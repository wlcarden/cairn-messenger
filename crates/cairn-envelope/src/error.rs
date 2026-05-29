// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Error types for `cairn-envelope`.
//!
//! Per D0018 §4.2: error variants carry indices, lengths, and type tags
//! only — never `Vec<u8>` or `&[u8]` payloads. This prevents secret-leak
//! vectors through error-propagation logging and matches the discipline
//! established in `cairn-crypto::error`.

use thiserror::Error;

/// Top-level error type for `cairn-envelope`, re-exported from the crate
/// root.
///
/// `#[non_exhaustive]` per D0018 §4.2 so new variants do not require a
/// major version bump as surfaces land.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// A [`crate::canonical::Value::Map`] contained duplicate
    /// canonical-encoded keys.
    ///
    /// RFC 8949 §4.2 forbids duplicate keys in canonical CBOR. Two
    /// `Value` entries are considered duplicates when their canonical
    /// encodings are byte-identical, not when they are `PartialEq`-equal
    /// at the `Value` level — the encoder rejects, e.g., `{0i64: ...,
    /// 0i64: ...}` even though the duplicates are obvious at the type
    /// level.
    #[error("canonical CBOR map contains duplicate encoded keys ({entries} entries)")]
    CanonicalCborDuplicateMapKey {
        /// Number of entries in the input map (pre-deduplication). Carried
        /// for diagnostic clarity only; per the no-payload discipline
        /// (D0018 §4.2) no key bytes are included.
        entries: usize,
    },
    /// The Ed25519 signing operation underlying `COSE_Sign1` construction
    /// failed (typically because the canonical-CBOR `Sig_structure`
    /// exceeded `cairn-crypto`'s `MAX_PAYLOAD_BYTES` limit).
    #[error("`COSE_Sign1` signing failed")]
    CoseSign1SignFailed,
    /// `COSE_Sign1` signature verification failed.
    ///
    /// Uniform across all crypto-layer failure modes (wrong key,
    /// tampered payload, tampered headers, tampered signature, wrong
    /// external AAD) per the no-error-oracle discipline (D0006 / D0018
    /// §1.4).
    #[error("`COSE_Sign1` signature verification failed")]
    CoseSign1VerifyFailed,
    /// The signature field of a decoded `COSE_Sign1` envelope was not
    /// the expected Ed25519 signature length (64 bytes).
    #[error(
        "`COSE_Sign1` signature has invalid length: {got_bytes} bytes (expected {expected_bytes})"
    )]
    CoseSign1InvalidSignatureLength {
        /// Length observed in the envelope's signature field.
        got_bytes: usize,
        /// Expected Ed25519 signature length.
        expected_bytes: usize,
    },
    /// The envelope bytes were not well-formed CBOR or did not match
    /// the `COSE_Sign1` 4-tuple structure per RFC 9052 §4.4.
    #[error("`COSE_Sign1` envelope is malformed CBOR")]
    CoseSign1MalformedCbor,
    /// A header value contained an integer outside the `i64` range
    /// representable by the canonical [`crate::canonical::Value::Int`]
    /// variant. CBOR allows full-`u64` and arbitrary-precision integers;
    /// Cairn restricts to `i64` per D0018 §2.3.
    #[error("`COSE_Sign1` header contains integer outside i64 range")]
    CoseSign1IntegerOutOfRange,
    /// A header value used a CBOR type not representable in the
    /// canonical [`crate::canonical::Value`] AST (floats, tagged values
    /// other than the outer `COSE_Sign1` tag, etc.).
    #[error("`COSE_Sign1` header uses unsupported CBOR type")]
    CoseSign1UnsupportedCborType,
}
