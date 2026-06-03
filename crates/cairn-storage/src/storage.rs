// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! The consumer-facing `Storage` handle per D0022 §4.
//!
//! ## Lifecycle
//!
//! ```text
//!     ┌────────────────────────────────────────────────────────────┐
//!     │  Storage::open(path, key_provider, passphrase)             │
//!     │    1. open / create the SQLite file                        │
//!     │    2. apply_pragmas (WAL + synchronous=FULL + …)           │
//!     │    3. initialize_bootstrap (storage / schema_version /     │
//!     │       meta tables)                                          │
//!     │    4. ensure the KEK salt exists in meta (generate if      │
//!     │       this is first-open; read if subsequent open)         │
//!     │    5. derive KEK from passphrase + salt via                │
//!     │       key_provider.derive_kek                              │
//!     │    6. fetch StrongBox material via                         │
//!     │       key_provider.strongbox_material                      │
//!     │    7. derive one DEK per category via HKDF                 │
//!     │    8. cache DEKs in Zeroizing memory; original KEK +       │
//!     │       passphrase + StrongBox material drop here            │
//!     └────────────────────────────────────────────────────────────┘
//! ```
//!
//! The Storage handle owns the SQLite connection (single-writer per
//! D0022 §1.3; the `Mutex` discipline is internal) and the per-
//! category DEK cache.
//!
//! ## Drop semantics
//!
//! `Storage::drop` wipes the cached DEKs via `Zeroizing`. The SQLite
//! connection's WAL is flushed by rusqlite's own Drop impl.
//!
//! ## Re-derive after lock
//!
//! Per D0022 §4 + the [`KeyProvider::unlock_state`] signal, when the
//! device locks the cached DEKs SHOULD be wiped and re-derived after
//! the next unlock. v1 ships without this lifecycle hook — the
//! cached DEKs persist for the Storage handle's lifetime. v1.5 adds
//! the wipe-on-lock surface.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

use crate::error::StorageError;
use crate::key_provider::{KeyProvider, derive_category_dek};
use crate::{DEK_LEN, categories, encryption, schema};

/// Length of the per-storage KEK salt in bytes. Generated once at
/// first-open and persisted in the `meta` table.
pub const KEK_SALT_LEN: usize = 16;

/// The consumer-facing storage handle per D0022 §4.
///
/// Wraps a rusqlite Connection + a cache of per-category DEKs
/// derived at open time. Operations route through the per-record
/// AEAD with AAD-binding per D0022 §2.3 + §2.4.
///
/// Single-writer discipline per D0022 §1.3: the Connection is held
/// inside a `Mutex`; concurrent `put`/`get`/`delete` calls from
/// multiple threads serialize through the Mutex. Read-heavy
/// workloads can benefit from opening additional read-only
/// Storage handles against the same file (a v1.5+ optimization
/// per D0022 §7.5).
pub struct Storage {
    /// SQLite connection. `Mutex` because rusqlite::Connection is
    /// `Send` but not `Sync`.
    conn: Mutex<Connection>,

    /// Per-category DEK cache. Lookup by category-tag string;
    /// `Zeroizing<[u8; DEK_LEN]>` wipes on Drop.
    deks: HashMap<&'static str, Zeroizing<[u8; DEK_LEN]>>,
}

impl Storage {
    /// Open or create the Storage at `path`, deriving all per-category
    /// DEKs per D0022 §2.2.
    ///
    /// On first open: generates a random `KEK_SALT_LEN`-byte salt,
    /// runs schema bootstrap, derives + caches all DEKs.
    /// On subsequent opens: reads the salt from meta, derives + caches
    /// all DEKs.
    ///
    /// # Errors
    ///
    /// - [`StorageError::OpenFailed`] for SQLite file / I/O failures
    /// - [`StorageError::KeyProvider`] for KEK / StrongBox derivation failures
    pub fn open(
        path: &Path,
        key_provider: &dyn KeyProvider,
        passphrase: &Zeroizing<Vec<u8>>,
    ) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        Self::bootstrap_and_derive(conn, key_provider, passphrase)
    }

    /// Open or create a Storage backed by an in-memory SQLite (no
    /// disk file). Intended for tests + transient workloads. The
    /// DEK derivation chain runs exactly as in [`Self::open`].
    ///
    /// # Errors
    ///
    /// Same as [`Self::open`] for the in-memory equivalent.
    pub fn open_in_memory(
        key_provider: &dyn KeyProvider,
        passphrase: &Zeroizing<Vec<u8>>,
    ) -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        Self::bootstrap_and_derive(conn, key_provider, passphrase)
    }

    /// Shared post-open setup: apply pragmas, initialize bootstrap,
    /// ensure salt, derive per-category DEKs.
    fn bootstrap_and_derive(
        conn: Connection,
        key_provider: &dyn KeyProvider,
        passphrase: &Zeroizing<Vec<u8>>,
    ) -> Result<Self, StorageError> {
        schema::apply_pragmas(&conn)?;
        schema::initialize_bootstrap(&conn)?;

        let salt = ensure_kek_salt(&conn)?;

        // Derive the KEK once, then per-category DEKs.
        // KEK + StrongBox material drop at the end of this function;
        // only the DEKs persist.
        let kek = key_provider.derive_kek(passphrase, &salt)?;
        let strongbox_material = key_provider.strongbox_material()?;

        let mut deks: HashMap<&'static str, Zeroizing<[u8; DEK_LEN]>> = HashMap::new();
        for category in ALL_CATEGORIES {
            let dek = derive_category_dek(&kek, &strongbox_material, category)?;
            deks.insert(category, dek);
        }

        Ok(Self {
            conn: Mutex::new(conn),
            deks,
        })
    }

    /// Insert or overwrite a record per D0022 §2.3.
    ///
    /// The payload is sealed with the per-category DEK + an AAD bound
    /// to `(category, record_id, version)`. Replacing an existing
    /// record produces a fresh random nonce, so the same `(category,
    /// record_id, payload)` written twice produces different
    /// ciphertext on each call — by design per D0022 §2.3.
    ///
    /// # Errors
    ///
    /// - [`StorageError::OpenFailed`] for SQLite I/O failures
    /// - [`StorageError::CanonicalEncode`] for AAD encoding (unreachable)
    /// - [`StorageError::MutexPoisoned`] if a prior call panicked
    ///   while holding the internal connection lock
    pub fn put(
        &self,
        category: &'static str,
        record_id: &[u8],
        payload: &[u8],
    ) -> Result<(), StorageError> {
        let dek = self.dek_for(category)?;
        let sealed = encryption::seal(dek, category, record_id, payload)?;
        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT INTO storage (category, record_id, ciphertext, version)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(category, record_id) DO UPDATE SET
               ciphertext = excluded.ciphertext,
               version = excluded.version",
            params![
                category,
                record_id,
                sealed,
                encryption::CURRENT_RECORD_VERSION
            ],
        )?;
        drop(conn);
        Ok(())
    }

    /// Fetch + decrypt a record. The returned plaintext lives in
    /// `Zeroizing` so it wipes when the caller drops it.
    ///
    /// # Errors
    ///
    /// - [`StorageError::RecordNotFound`] if the row is absent
    /// - [`StorageError::DecryptFailed`] for any AEAD failure
    ///   (wrong DEK, tampered ciphertext, AAD mismatch / slot-swap
    ///   attack) — uniform per D0018 §1.4
    /// - [`StorageError::CiphertextTruncated`] if the stored
    ///   ciphertext is shorter than [`encryption::MIN_CIPHERTEXT_LEN`]
    /// - [`StorageError::UnsupportedRecordVersion`] if the version
    ///   byte isn't recognized by this build
    /// - [`StorageError::MutexPoisoned`] if a prior call panicked
    ///   while holding the internal connection lock
    pub fn get(
        &self,
        category: &'static str,
        record_id: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let dek = self.dek_for(category)?;
        let sealed: Vec<u8> = {
            let conn = self.lock_conn()?;
            conn.query_row(
                "SELECT ciphertext FROM storage WHERE category = ? AND record_id = ?",
                params![category, record_id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(StorageError::RecordNotFound { category })?
        };
        encryption::open(dek, category, record_id, &sealed)
    }

    /// Delete a record. Returns `true` if a row was actually removed,
    /// `false` if no matching row existed.
    ///
    /// # Errors
    ///
    /// - [`StorageError::OpenFailed`] for SQLite failures
    /// - [`StorageError::MutexPoisoned`] if a prior call panicked
    ///   while holding the internal connection lock
    pub fn delete(&self, category: &'static str, record_id: &[u8]) -> Result<bool, StorageError> {
        let conn = self.lock_conn()?;
        let rows = conn.execute(
            "DELETE FROM storage WHERE category = ? AND record_id = ?",
            params![category, record_id],
        )?;
        drop(conn);
        Ok(rows > 0)
    }

    /// List the `record_id` values currently stored in a category.
    /// Returned in lexicographic order of `record_id` bytes.
    ///
    /// Intended for category-scan workloads (e.g., loading all
    /// trust-graph ops at startup; iterating recovery peer state).
    /// Returns just the IDs — fetch payloads via [`Self::get`].
    ///
    /// # Errors
    ///
    /// - [`StorageError::OpenFailed`] for SQLite failures
    /// - [`StorageError::MutexPoisoned`] if a prior call panicked
    ///   while holding the internal connection lock
    pub fn list_records(&self, category: &'static str) -> Result<Vec<Vec<u8>>, StorageError> {
        let conn = self.lock_conn()?;
        let mut ids = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT record_id FROM storage WHERE category = ? ORDER BY record_id ASC",
            )?;
            let rows = stmt.query_map(params![category], |r| r.get::<_, Vec<u8>>(0))?;
            for row in rows {
                ids.push(row?);
            }
        }
        drop(conn);
        Ok(ids)
    }

    /// Count records in a category. Convenience over
    /// [`Self::list_records`] for callers that only need the count.
    ///
    /// # Errors
    ///
    /// - [`StorageError::OpenFailed`] for SQLite failures
    /// - [`StorageError::MutexPoisoned`] if a prior call panicked
    ///   while holding the internal connection lock
    pub fn count_records(&self, category: &'static str) -> Result<u64, StorageError> {
        let conn = self.lock_conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM storage WHERE category = ?",
            params![category],
            |r| r.get(0),
        )?;
        drop(conn);
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Read the per-category schema version per D0022 §3.1.
    ///
    /// # Errors
    ///
    /// - [`StorageError::OpenFailed`] for SQLite failures
    /// - [`StorageError::MutexPoisoned`] if a prior call panicked
    pub fn category_schema_version(&self, category: &str) -> Result<u32, StorageError> {
        let conn = self.lock_conn()?;
        schema::category_schema_version(&conn, category)
    }

    /// Set the per-category schema version per D0022 §3.1.
    /// Called by consuming crates' migration runners.
    ///
    /// # Errors
    ///
    /// - [`StorageError::OpenFailed`] for SQLite failures
    /// - [`StorageError::MutexPoisoned`] if a prior call panicked
    pub fn set_category_schema_version(
        &self,
        category: &str,
        version: u32,
    ) -> Result<(), StorageError> {
        let conn = self.lock_conn()?;
        schema::set_category_schema_version(&conn, category, version)
    }

    /// Lock the internal connection mutex, mapping poison into a
    /// typed StorageError variant per D0018 §4.2 — no `expect`/`unwrap`
    /// on the lock guard.
    fn lock_conn(&self) -> Result<MutexGuard<'_, Connection>, StorageError> {
        self.conn.lock().map_err(|_| StorageError::MutexPoisoned)
    }

    /// Look up the cached DEK for a category. Errors if the category
    /// isn't one of the known [`ALL_CATEGORIES`] tags.
    fn dek_for(&self, category: &'static str) -> Result<&Zeroizing<[u8; DEK_LEN]>, StorageError> {
        self.deks
            .get(category)
            .ok_or(StorageError::RecordNotFound { category })
    }
}

/// Ensure the KEK salt is present in the `meta` table; generate a
/// fresh random salt on first open. The salt is non-secret (it's
/// just a salt), so it lives in the cleartext meta table per
/// D0022 §2.1.
fn ensure_kek_salt(conn: &Connection) -> Result<Vec<u8>, StorageError> {
    if let Some(existing) = schema::meta_get(conn, schema::META_KEK_SALT)? {
        if existing.len() != KEK_SALT_LEN {
            return Err(StorageError::UnexpectedRecordLength {
                got_bytes: existing.len(),
            });
        }
        return Ok(existing);
    }
    let mut fresh = [0u8; KEK_SALT_LEN];
    OsRng.fill_bytes(&mut fresh);
    schema::meta_set(conn, schema::META_KEK_SALT, &fresh)?;
    Ok(fresh.to_vec())
}

/// All per-category tags this build derives DEKs for at open time.
///
/// Per D0022 §2.2: adding a new category tag here (and to
/// [`crate::categories`]) extends the DEK set without touching
/// existing records — the HKDF `info` parameter differentiates
/// derivations, so previously-derived DEKs stay unchanged.
pub const ALL_CATEGORIES: &[&str] = &[
    categories::IDENTITY,
    categories::CAPABILITY_TOKENS,
    categories::MASTER_ATTESTATION,
    categories::TRUST_GRAPH,
    categories::QUARANTINE_STATE,
    categories::RECOVERY_PEERS,
    categories::RECOVERY_SHARES,
    categories::RATCHET_STATE,
    categories::MESSAGES,
    categories::SIGSUM_CACHE,
    categories::CONTACTS,
];

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used
)]
mod tests {
    use super::*;
    use crate::key_provider::testing::InMemoryKeyProvider;

    fn open_test_storage() -> Storage {
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"test passphrase".to_vec());
        Storage::open_in_memory(&provider, &passphrase).unwrap()
    }

    #[test]
    fn open_in_memory_succeeds() {
        let _storage = open_test_storage();
    }

    #[test]
    fn put_get_round_trip() {
        let storage = open_test_storage();
        let payload = b"trust-graph op canonical-CBOR bytes (notional)";
        storage
            .put(categories::TRUST_GRAPH, b"op-id-1", payload)
            .unwrap();
        let recovered = storage.get(categories::TRUST_GRAPH, b"op-id-1").unwrap();
        assert_eq!(recovered.as_slice(), payload);
    }

    #[test]
    fn put_overwrites_existing_record() {
        let storage = open_test_storage();
        storage
            .put(categories::IDENTITY, b"key-1", b"first value")
            .unwrap();
        storage
            .put(categories::IDENTITY, b"key-1", b"second value")
            .unwrap();
        let recovered = storage.get(categories::IDENTITY, b"key-1").unwrap();
        assert_eq!(recovered.as_slice(), b"second value");
    }

    #[test]
    fn get_missing_record_returns_not_found() {
        let storage = open_test_storage();
        let result = storage.get(categories::IDENTITY, b"nonexistent");
        assert!(matches!(
            result,
            Err(StorageError::RecordNotFound {
                category: categories::IDENTITY
            })
        ));
    }

    #[test]
    fn delete_returns_true_when_row_removed() {
        let storage = open_test_storage();
        storage
            .put(categories::MESSAGES, b"msg-1", b"payload")
            .unwrap();
        assert!(storage.delete(categories::MESSAGES, b"msg-1").unwrap());
        assert!(matches!(
            storage.get(categories::MESSAGES, b"msg-1"),
            Err(StorageError::RecordNotFound { .. })
        ));
    }

    #[test]
    fn delete_returns_false_when_no_matching_row() {
        let storage = open_test_storage();
        assert!(
            !storage
                .delete(categories::MESSAGES, b"nonexistent")
                .unwrap()
        );
    }

    #[test]
    fn list_records_returns_lexicographic_ids() {
        let storage = open_test_storage();
        storage
            .put(categories::TRUST_GRAPH, b"id-c", b"payload-c")
            .unwrap();
        storage
            .put(categories::TRUST_GRAPH, b"id-a", b"payload-a")
            .unwrap();
        storage
            .put(categories::TRUST_GRAPH, b"id-b", b"payload-b")
            .unwrap();
        let ids = storage.list_records(categories::TRUST_GRAPH).unwrap();
        assert_eq!(
            ids,
            vec![b"id-a".to_vec(), b"id-b".to_vec(), b"id-c".to_vec()]
        );
    }

    #[test]
    fn count_records_matches_list_len() {
        let storage = open_test_storage();
        for i in 0..7u8 {
            storage
                .put(categories::TRUST_GRAPH, &[i], &[i, i, i])
                .unwrap();
        }
        assert_eq!(storage.count_records(categories::TRUST_GRAPH).unwrap(), 7);
    }

    #[test]
    fn categories_are_isolated() {
        let storage = open_test_storage();
        storage
            .put(categories::IDENTITY, b"id-1", b"identity payload")
            .unwrap();
        storage
            .put(categories::MESSAGES, b"id-1", b"messages payload")
            .unwrap();
        assert_eq!(
            storage
                .get(categories::IDENTITY, b"id-1")
                .unwrap()
                .as_slice(),
            b"identity payload"
        );
        assert_eq!(
            storage
                .get(categories::MESSAGES, b"id-1")
                .unwrap()
                .as_slice(),
            b"messages payload"
        );
    }

    #[test]
    fn put_produces_fresh_nonces_so_storage_layer_ciphertext_differs() {
        let storage = open_test_storage();
        storage
            .put(categories::IDENTITY, b"id-1", b"same payload")
            .unwrap();
        let ct_a: Vec<u8> = {
            let conn = storage.conn.lock().unwrap();
            conn.query_row(
                "SELECT ciphertext FROM storage WHERE category = ? AND record_id = ?",
                params![categories::IDENTITY, b"id-1"],
                |r| r.get(0),
            )
            .unwrap()
        };
        storage
            .put(categories::IDENTITY, b"id-1", b"same payload")
            .unwrap();
        let ct_b: Vec<u8> = {
            let conn = storage.conn.lock().unwrap();
            conn.query_row(
                "SELECT ciphertext FROM storage WHERE category = ? AND record_id = ?",
                params![categories::IDENTITY, b"id-1"],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_ne!(ct_a, ct_b);
    }

    #[test]
    fn reopen_with_same_passphrase_recovers_records() {
        let tmpfile = tempfile_path();
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"the passphrase".to_vec());
        {
            let storage = Storage::open(&tmpfile, &provider, &passphrase).unwrap();
            storage
                .put(categories::IDENTITY, b"key-1", b"persisted payload")
                .unwrap();
        }
        let storage = Storage::open(&tmpfile, &provider, &passphrase).unwrap();
        let recovered = storage.get(categories::IDENTITY, b"key-1").unwrap();
        assert_eq!(recovered.as_slice(), b"persisted payload");
        drop(storage);
        std::fs::remove_file(&tmpfile).ok();
    }

    #[test]
    fn reopen_with_wrong_passphrase_fails_decrypt() {
        let tmpfile = tempfile_path();
        let provider = InMemoryKeyProvider::new();
        let passphrase_a = Zeroizing::new(b"correct passphrase".to_vec());
        let passphrase_b = Zeroizing::new(b"wrong passphrase".to_vec());
        {
            let storage = Storage::open(&tmpfile, &provider, &passphrase_a).unwrap();
            storage
                .put(categories::IDENTITY, b"key-1", b"secret payload")
                .unwrap();
        }
        let storage = Storage::open(&tmpfile, &provider, &passphrase_b).unwrap();
        let result = storage.get(categories::IDENTITY, b"key-1");
        assert!(matches!(result, Err(StorageError::DecryptFailed)));
        drop(storage);
        std::fs::remove_file(&tmpfile).ok();
    }

    #[test]
    fn category_schema_version_round_trip_through_storage() {
        let storage = open_test_storage();
        assert_eq!(
            storage
                .category_schema_version(categories::TRUST_GRAPH)
                .unwrap(),
            0
        );
        storage
            .set_category_schema_version(categories::TRUST_GRAPH, 2)
            .unwrap();
        assert_eq!(
            storage
                .category_schema_version(categories::TRUST_GRAPH)
                .unwrap(),
            2
        );
    }

    /// Generate a unique temporary file path under the system temp
    /// directory. Avoids pulling the `tempfile` crate (one fewer
    /// supply-chain item to vet).
    fn tempfile_path() -> std::path::PathBuf {
        use core::fmt::Write as _;
        let mut rng = OsRng;
        let mut suffix = [0u8; 8];
        rng.fill_bytes(&mut suffix);
        let mut hex = String::with_capacity(suffix.len().saturating_mul(2));
        for b in &suffix {
            write!(&mut hex, "{b:02x}").expect("hex format never fails");
        }
        let mut path = std::env::temp_dir();
        path.push(format!("cairn-storage-test-{hex}.sqlite"));
        path
    }
}
