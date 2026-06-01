// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// D0018 §8.1 + D0022 §6.4 grant cairn-storage an `unsafe_code =
// "deny"` exception (vs the workspace-default "forbid") for the
// future `mlock` wrapper that pins cached DEKs to non-swappable
// memory. The skeleton landed in this commit has NO `unsafe` blocks
// so it inherits the workspace `forbid` as a no-op. When the mlock
// wrapper lands, this crate's `[lints]` table in Cargo.toml stops
// inheriting from workspace and sets `unsafe_code = "deny"`
// directly; the `mlock` call site carries a documented
// `#[allow(unsafe_code)]` with safety argument per D0018 §8.1.

// `doc_markdown` is allowed crate-wide because this crate's docs
// reference many technical-term proper nouns (SQLite, SimpleX,
// StrongBox, UniFFI, KeyStore, Android, etc.) that would each need
// backticks. The crate-local convention matches cairn-cli's
// `clippy::print_*` allow and keeps the documentation readable.
#![allow(clippy::doc_markdown)]

//! # cairn-storage
//!
//! Persistent storage layer for Cairn per [D0022](../../docs/decisions/D0022-storage-layer.md).
//!
//! ## Architecture
//!
//! ```text
//!   Consuming crate                     │  cairn-storage              │  Underlying engine
//!   (cairn-trust-graph, cairn-recovery, │                             │  + AEAD
//!    cairn-simplex-adapter, …)          │                             │
//!  ─────────────────────────────────────┼─────────────────────────────┼──────────────────────
//!   put(category, record_id, payload)   │  encryption::seal()         │  XChaCha20-Poly1305
//!                                       │    ├─ AAD = canonical-CBOR  │  with 24-byte nonce
//!                                       │    │   of (category,        │
//!                                       │    │      record_id,        │
//!                                       │    │      version)          │
//!                                       │    └─ DEK_category from     │
//!                                       │       KeyProvider           │
//!                                       │  ↓                          │
//!                                       │  rusqlite: INSERT INTO      │  SQLite WAL +
//!                                       │  storage (category,         │  synchronous=FULL
//!                                       │     record_id, ciphertext,  │
//!                                       │     version) VALUES (…)     │
//! ```
//!
//! All bytes at rest are ciphertext from our own per-record AEAD;
//! SQLite sees only opaque blobs. This is the structural reason we
//! can treat SQLite as an audit trust root per D0011 + D0022 §6.3 —
//! the engine doesn't parse attacker-controlled bytes.
//!
//! ## Per-record format (D0022 §2.3)
//!
//! Each `ciphertext` column carries:
//!
//! ```text
//! version_byte (1) ‖ nonce (24) ‖ XChaCha20-Poly1305(DEK_category, payload, AAD)
//! ```
//!
//! The AEAD's 16-byte Poly1305 tag is appended by the encryptor
//! (chacha20poly1305 crate convention) and not separately framed.
//!
//! ## AAD construction (D0022 §2.4)
//!
//! ```text
//! AAD = canonical_cbor_encode([
//!   category_tag : tstr,
//!   record_id    : bstr,
//!   version      : uint,
//! ])
//! ```
//!
//! Slot-binding: an adversary with write access to the SQLite file
//! who swaps `(category, record_id_A)` ↔ `(category, record_id_B)`
//! invalidates the AEAD tag because the AAD reconstructed at read
//! time references the destination row's id, not the originating
//! row's id.
//!
//! ## Key provider trait (D0022 §4)
//!
//! [`KeyProvider`] is the only hardware-abstraction-layer surface
//! this crate exposes. Implementations:
//!
//! - [`key_provider::testing::InMemoryKeyProvider`] for unit + integration tests
//!   inside the workspace (Argon2id with reduced parameters; fixed
//!   in-memory StrongBox material).
//! - `cairn-uniffi::AndroidKeyProvider` (future crate per D0018 §8.6)
//!   wraps the UniFFI callback that calls into Kotlin for Argon2 +
//!   Android KeyStore per D0020 §3.4.
//!
//! ## What this crate does NOT do
//!
//! - **Schema construction for downstream categories.** This crate
//!   exposes the byte-level storage primitive; the trust-graph,
//!   recovery, and messaging categories define their own
//!   record_id derivation + payload schemas in their own crates.
//! - **Migrations beyond the bootstrap schema.** The migration
//!   runner is present but the migration *content* lands with each
//!   consuming crate as their schemas evolve.
//! - **Hardware key binding directly.** The [`KeyProvider`] trait
//!   abstracts this; the Android-specific implementation lives in
//!   `cairn-uniffi` per D0020 §3.
//! - **mlock of cached DEKs.** Deferred to a follow-up commit. The
//!   `unsafe_code = "deny"` exception per D0018 §8.1 is registered
//!   at the lint level so the mlock wrapper can land with a
//!   documented `#[allow(unsafe_code)]` at the specific call site.

pub mod encryption;
pub mod error;
pub mod key_provider;
pub mod schema;
pub mod storage;

pub use error::StorageError;
pub use key_provider::{KeyProvider, KeyProviderError, UnlockState};
pub use storage::{ALL_CATEGORIES, KEK_SALT_LEN, Storage};

/// Length of the per-record nonce in bytes (XChaCha20-Poly1305
/// 192-bit nonce per D0018 §1.4 + D0022 §2.3).
pub const NONCE_LEN: usize = 24;

/// Length of the AEAD tag in bytes (Poly1305 128-bit tag).
pub const TAG_LEN: usize = 16;

/// Length of a Data Encryption Key (XChaCha20-Poly1305 256-bit key).
pub const DEK_LEN: usize = 32;

/// Length of the Key-Encryption Key derived from the passphrase via
/// Argon2id per D0022 §2.2.
pub const KEK_LEN: usize = 32;

/// Length of the StrongBox-attested key material returned by
/// [`KeyProvider::strongbox_material`] per D0022 §2.2 + D0020 §3.4.
pub const STRONGBOX_MATERIAL_LEN: usize = 32;

/// HKDF salt for the storage DEK derivation per D0022 §2.2.
///
/// The salt is constant + protocol-version-bound; the per-category
/// derivation differentiation happens via the HKDF `info` parameter
/// (the category tag string).
pub const STORAGE_KDF_SALT: &[u8] = b"cairn-v1-storage-kdf";

/// Category tags per D0022 §2.2. These are the `info` parameters
/// fed into HKDF to derive per-category DEKs from the (KEK, StrongBox
/// material) combination.
///
/// A future revision can extend this list by adding new tags;
/// existing categories' DEKs are unchanged.
pub mod categories {
    /// Operational identity keys (small; rarely rotated).
    pub const IDENTITY: &str = "identity";
    /// Capability tokens (rotated hours-to-days per D0018 §5.1).
    pub const CAPABILITY_TOKENS: &str = "capability_tokens";
    /// Master attestations (rotated only at op-identity rotation).
    pub const MASTER_ATTESTATION: &str = "master_attestation";
    /// Trust-graph operations (issued + received).
    pub const TRUST_GRAPH: &str = "trust_graph";
    /// Computed cascade-quarantine state + soft-flag UI ack history.
    pub const QUARANTINE_STATE: &str = "quarantine_state";
    /// Recovery peer pubkeys + names + share commitments.
    pub const RECOVERY_PEERS: &str = "recovery_peers";
    /// Shares this user holds of OTHER users' masters.
    pub const RECOVERY_SHARES: &str = "recovery_shares";
    /// SimpleX per-conversation ratchet state.
    pub const RATCHET_STATE: &str = "ratchet_state";
    /// Per-conversation message history.
    pub const MESSAGES: &str = "messages";
    /// Sigsum log heads + witness cosignatures cache.
    pub const SIGSUM_CACHE: &str = "sigsum_cache";
}
