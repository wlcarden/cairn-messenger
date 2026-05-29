// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Error types for `cairn-storage`.
//!
//! Per D0018 §4.2: error variants carry indices, lengths, and type
//! tags only — never `Vec<u8>` or `&[u8]` payloads. Decrypt failures
//! are uniform per the no-error-oracle discipline (D0006 / D0018
//! §1.4); the storage layer surfaces `DecryptFailed` for every
//! AEAD verification failure mode without distinguishing wrong-key
//! from tampered-ciphertext from AAD-mismatch.

use thiserror::Error;

use crate::key_provider::KeyProviderError;

/// Top-level error type for `cairn-storage`, re-exported from the
/// crate root.
///
/// `#[non_exhaustive]` per D0018 §4.2.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StorageError {
    /// Failure opening or upgrading the SQLite database file.
    /// Surfaces rusqlite I/O failures (file permissions, disk full,
    /// corrupted journal, etc.).
    #[error("storage open / upgrade failed: {0}")]
    OpenFailed(#[from] rusqlite::Error),

    /// Failure from the [`crate::KeyProvider`] implementation when
    /// deriving the KEK or fetching StrongBox-attested material.
    #[error("key provider failure: {0}")]
    KeyProvider(#[from] KeyProviderError),

    /// Failure encoding the AAD or payload to canonical CBOR per
    /// D0022 §2.4. Unreachable for typed inputs; the variant exists
    /// so we never `unwrap` on the encoder result.
    #[error("storage canonical CBOR encoding failed: {0}")]
    CanonicalEncode(#[from] cairn_envelope::EnvelopeError),

    /// The record's stored `version` byte did not match any decoder
    /// this build of cairn-storage knows. Indicates either:
    ///   1. The database was written by a newer cairn-storage; the
    ///      caller should upgrade.
    ///   2. The version byte was tampered (AAD verification would
    ///      also catch this at decrypt time).
    #[error("storage record at version {got} is not supported by this build")]
    UnsupportedRecordVersion {
        /// The numeric version observed in the record header.
        got: u8,
    },

    /// The decrypted record was not the expected length for its
    /// category schema. Diagnostic only — the AEAD tag still
    /// validated, so this indicates schema drift the caller should
    /// surface as a clear "your local data is from a different
    /// version" message.
    #[error("storage record body has unexpected length: {got_bytes} bytes")]
    UnexpectedRecordLength {
        /// Length of the decrypted body.
        got_bytes: usize,
    },

    /// AEAD verification failed. Uniform across all crypto-layer
    /// failure modes per D0006 / D0018 §1.4: wrong DEK, ciphertext
    /// tamper, AAD mismatch (slot-swap attack), corrupted nonce —
    /// all surface as a single error variant.
    #[error("storage record AEAD verification failed")]
    DecryptFailed,

    /// The ciphertext column was shorter than `version_byte ‖ nonce ‖
    /// tag`. Surfaced separately from `DecryptFailed` because no
    /// AEAD invocation is possible — the structural error precedes
    /// the cryptographic check.
    #[error(
        "storage record ciphertext truncated: {got_bytes} bytes (expected at least {min_bytes})"
    )]
    CiphertextTruncated {
        /// Length of the ciphertext column observed.
        got_bytes: usize,
        /// Minimum length for a well-formed record (version + nonce
        /// + tag).
        min_bytes: usize,
    },

    /// The requested record was not found in the storage table.
    /// Surfaced as a distinct error variant (rather than `Option`)
    /// because callers often want to distinguish "missing" from
    /// "decrypt-failed" for diagnostic reasons (the latter indicates
    /// tamper; the former indicates the record was never written).
    #[error("storage record not found in category {category}")]
    RecordNotFound {
        /// The category tag the caller queried.
        category: &'static str,
    },

    /// Migration runner failure. Includes the from-version and
    /// to-version so the log discipline per D0018 §4.3 can record
    /// what the runner was attempting at failure time.
    #[error(
        "storage migration failed from v{from_version} to v{to_version} for category {category}"
    )]
    MigrationFailed {
        /// The category whose schema migration failed.
        category: &'static str,
        /// The schema_version row's pre-migration version.
        from_version: u32,
        /// The migration step's target version.
        to_version: u32,
    },

    /// The internal `Mutex` guarding the SQLite connection was
    /// poisoned. Happens iff a panic occurred while a thread held
    /// the lock; surfaces here so the caller can decide whether to
    /// re-open or fail the request. The storage handle should be
    /// considered unusable after this error.
    #[error("storage internal mutex was poisoned by a panicking thread")]
    MutexPoisoned,
}
