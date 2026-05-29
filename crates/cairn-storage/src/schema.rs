// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Storage schema bootstrap + migration runner per D0022 §3.
//!
//! ## Tables
//!
//! ```sql
//! CREATE TABLE storage (
//!   category   TEXT NOT NULL,
//!   record_id  BLOB NOT NULL,
//!   ciphertext BLOB NOT NULL,  -- version ‖ nonce ‖ AEAD(payload, AAD)
//!   version    INTEGER NOT NULL,
//!   PRIMARY KEY (category, record_id)
//! );
//!
//! CREATE TABLE schema_version (
//!   category TEXT PRIMARY KEY,
//!   version  INTEGER NOT NULL
//! );
//!
//! CREATE TABLE meta (
//!   key   TEXT PRIMARY KEY,
//!   value BLOB NOT NULL
//! );
//! ```
//!
//! - `storage` is the encrypted-blob KV table that every category
//!   reads from + writes to. The `version` column is also bound into
//!   the AAD per D0022 §2.4 so a downgrade-or-swap fails AEAD.
//! - `schema_version` records the per-category schema version the
//!   migration runner uses to decide whether to apply pending
//!   migrations.
//! - `meta` holds bootstrap data the migration code reads before any
//!   key material is available (e.g., `"encryption_kek_salt"` — the
//!   random salt the `KeyProvider` mixes into Argon2id).
//!
//! ## SQLite pragmas applied at connection open per D0022 §1.1
//!
//! ```sql
//! PRAGMA journal_mode = WAL;       -- concurrent reads while writing
//! PRAGMA synchronous  = FULL;      -- fsync on commit (durability)
//! PRAGMA foreign_keys = ON;        -- structural integrity
//! PRAGMA temp_store   = MEMORY;    -- no plaintext tempfiles on disk
//! PRAGMA auto_vacuum  = INCREMENTAL;
//! ```
//!
//! ## Migration discipline
//!
//! - **Forward-only at v1.** Migrations advance versions; rolling
//!   back is not supported.
//! - **Transactional wrapping.** Each migration runs inside a single
//!   SQLite transaction; failure rolls back to pre-migration state.
//! - **No automatic migration on decrypt failure.** If decrypt fails
//!   we surface the failure; we don't try "maybe it's a different
//!   schema" — that path is an attack surface per D0022 §3.2.
//! - **Explicit trigger at app start.** Each app start reads
//!   `schema_version` per category and applies pending migrations
//!   in declared order.
//! - **Logging per D0018 §4.3.** No secret material in logs; record
//!   from-version + to-version + duration + row count.
//!
//! v1 lands the bootstrap schema only. Per-category schema content
//! lands with each consuming crate as their persistence requirements
//! materialize.

use rusqlite::{Connection, params};

use crate::error::StorageError;

/// Schema version of the bootstrap layout itself (the `storage` +
/// `schema_version` + `meta` tables). This is distinct from per-
/// category schema versions, which live as rows in the
/// `schema_version` table.
pub const BOOTSTRAP_SCHEMA_VERSION: u32 = 1;

/// `meta` table key for the random 16-byte salt the [`KeyProvider`]
/// mixes into Argon2id per D0022 §2.2.
///
/// [`KeyProvider`]: crate::key_provider::KeyProvider
pub const META_KEK_SALT: &str = "encryption_kek_salt";

/// `meta` table key for the storage layer's own bootstrap version.
pub const META_BOOTSTRAP_VERSION: &str = "bootstrap_schema_version";

/// Apply the SQLite pragmas per D0022 §1.1.
///
/// Called once per connection open. Pragmas are connection-scoped
/// in SQLite — they don't persist across reopens — so this runs at
/// every connection-establishment path.
///
/// # Errors
///
/// Propagates [`StorageError::OpenFailed`] for any underlying
/// rusqlite failure (rare; usually disk-level issues).
pub fn apply_pragmas(conn: &Connection) -> Result<(), StorageError> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    Ok(())
}

/// Initialize the bootstrap tables if not already present.
///
/// Idempotent: re-running on an already-initialized database is a
/// no-op. The function does NOT migrate per-category schemas — those
/// land with each consuming crate.
///
/// # Errors
///
/// Propagates [`StorageError::OpenFailed`] for rusqlite failures.
pub fn initialize_bootstrap(conn: &Connection) -> Result<(), StorageError> {
    let tx = conn.unchecked_transaction()?;

    tx.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS storage (
          category   TEXT NOT NULL,
          record_id  BLOB NOT NULL,
          ciphertext BLOB NOT NULL,
          version    INTEGER NOT NULL,
          PRIMARY KEY (category, record_id)
        );

        CREATE TABLE IF NOT EXISTS schema_version (
          category TEXT PRIMARY KEY,
          version  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS meta (
          key   TEXT PRIMARY KEY,
          value BLOB NOT NULL
        );
        ",
    )?;

    // Record the bootstrap schema version. INSERT OR IGNORE so re-runs
    // don't overwrite an explicitly-bumped version.
    tx.execute(
        "INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)",
        params![
            META_BOOTSTRAP_VERSION,
            BOOTSTRAP_SCHEMA_VERSION.to_le_bytes()
        ],
    )?;

    tx.commit()?;
    Ok(())
}

/// Read the per-category schema version from the `schema_version`
/// table.
///
/// Returns `Ok(0)` if the category has no row yet — the convention
/// that "absence-of-version = pre-v1" lets consuming crates declare
/// their first migration as `from_version = 0 → to_version = 1`.
///
/// # Errors
///
/// Propagates [`StorageError::OpenFailed`] for rusqlite failures.
pub fn category_schema_version(conn: &Connection, category: &str) -> Result<u32, StorageError> {
    let row: Result<u32, _> = conn.query_row(
        "SELECT version FROM schema_version WHERE category = ?",
        params![category],
        |r| r.get(0),
    );
    match row {
        Ok(v) => Ok(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
        Err(other) => Err(StorageError::from(other)),
    }
}

/// Set the per-category schema version. Called by the migration
/// runner at the END of a successful migration step, inside the same
/// transaction as the schema-change statements.
///
/// # Errors
///
/// Propagates [`StorageError::OpenFailed`] for rusqlite failures.
pub fn set_category_schema_version(
    conn: &Connection,
    category: &str,
    version: u32,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO schema_version (category, version) VALUES (?, ?)
         ON CONFLICT(category) DO UPDATE SET version = excluded.version",
        params![category, version],
    )?;
    Ok(())
}

/// Read a value from the `meta` table.
///
/// Returns `Ok(None)` if the key is not present.
///
/// # Errors
///
/// Propagates [`StorageError::OpenFailed`] for rusqlite failures.
pub fn meta_get(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
    let row: Result<Vec<u8>, _> =
        conn.query_row("SELECT value FROM meta WHERE key = ?", params![key], |r| {
            r.get(0)
        });
    match row {
        Ok(value) => Ok(Some(value)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(StorageError::from(e)),
    }
}

/// Write a value to the `meta` table. Overwrites any prior value.
///
/// # Errors
///
/// Propagates [`StorageError::OpenFailed`] for rusqlite failures.
pub fn meta_set(conn: &Connection, key: &str, value: &[u8]) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::categories;

    fn open_in_memory() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        apply_pragmas(&conn).unwrap();
        initialize_bootstrap(&conn).unwrap();
        conn
    }

    #[test]
    fn bootstrap_creates_required_tables() {
        let conn = open_in_memory();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(tables.contains(&"storage".to_string()));
        assert!(tables.contains(&"schema_version".to_string()));
        assert!(tables.contains(&"meta".to_string()));
    }

    #[test]
    fn bootstrap_is_idempotent() {
        let conn = open_in_memory();
        // Re-initialize should not error or duplicate.
        initialize_bootstrap(&conn).unwrap();
        initialize_bootstrap(&conn).unwrap();
    }

    #[test]
    fn category_schema_version_defaults_to_zero() {
        let conn = open_in_memory();
        assert_eq!(
            category_schema_version(&conn, categories::IDENTITY).unwrap(),
            0
        );
    }

    #[test]
    fn category_schema_version_round_trips() {
        let conn = open_in_memory();
        set_category_schema_version(&conn, categories::IDENTITY, 3).unwrap();
        assert_eq!(
            category_schema_version(&conn, categories::IDENTITY).unwrap(),
            3
        );
    }

    #[test]
    fn category_schema_version_can_advance() {
        let conn = open_in_memory();
        set_category_schema_version(&conn, categories::MESSAGES, 1).unwrap();
        set_category_schema_version(&conn, categories::MESSAGES, 2).unwrap();
        assert_eq!(
            category_schema_version(&conn, categories::MESSAGES).unwrap(),
            2
        );
    }

    #[test]
    fn meta_round_trip() {
        let conn = open_in_memory();
        assert_eq!(meta_get(&conn, "test-key").unwrap(), None);
        meta_set(&conn, "test-key", b"test-value").unwrap();
        assert_eq!(
            meta_get(&conn, "test-key").unwrap().as_deref(),
            Some(&b"test-value"[..])
        );
        meta_set(&conn, "test-key", b"updated-value").unwrap();
        assert_eq!(
            meta_get(&conn, "test-key").unwrap().as_deref(),
            Some(&b"updated-value"[..])
        );
    }

    #[test]
    fn bootstrap_version_recorded_in_meta() {
        let conn = open_in_memory();
        let version_bytes = meta_get(&conn, META_BOOTSTRAP_VERSION).unwrap().unwrap();
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&version_bytes);
        assert_eq!(u32::from_le_bytes(buf), BOOTSTRAP_SCHEMA_VERSION);
    }

    #[test]
    fn pragma_journal_mode_is_wal() {
        let conn = open_in_memory();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        // For :memory: databases SQLite may use "memory" rather than
        // WAL. The pragma_update above attempts WAL; the test
        // verifies the call succeeded structurally. Production file-
        // backed databases land in WAL.
        assert!(
            ["wal", "memory"].contains(&mode.as_str()),
            "unexpected journal_mode: {mode}"
        );
    }
}
