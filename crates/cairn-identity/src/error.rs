// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Error types for `cairn-identity`.
//!
//! Per D0018 §4.2: error variants carry indices, lengths, and type tags
//! only — never `Vec<u8>` or `&[u8]` payloads. This prevents secret-leak
//! vectors through error-propagation logging and matches the discipline
//! established in `cairn-crypto::error`, `cairn-envelope::error`, and
//! `cairn-shamir::error`.

use thiserror::Error;

/// Top-level error type for `cairn-identity`, re-exported from the crate
/// root.
///
/// `#[non_exhaustive]` per D0018 §4.2 so new variants do not require a
/// major version bump as additional surfaces (capability-token renewal,
/// revocation tokens, etc. per D0006) land later.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// Failure while building the canonical-CBOR payload of a
    /// capability token — typically only happens if a scope string
    /// produces a duplicate canonical-encoded key, which the typed
    /// schema prevents at construction. Carried through so the variant
    /// is non-panicking at the API boundary.
    #[error("capability-token canonical CBOR encoding failed: {0}")]
    CanonicalEncode(#[from] cairn_envelope::EnvelopeError),
    /// The capability-token payload bytes were not well-formed CBOR or
    /// did not match the expected schema (map with integer keys 1..=5
    /// per D0006 §9).
    #[error("capability-token payload is malformed")]
    MalformedPayload,
    /// A pubkey field (issuer or subject) was not the expected 32-byte
    /// Ed25519 public key length.
    #[error(
        "capability-token public key has invalid length: {got_bytes} bytes (expected {expected_bytes})"
    )]
    InvalidPubkeyLength {
        /// Number of bytes observed in the field.
        got_bytes: usize,
        /// Expected Ed25519 public key length.
        expected_bytes: usize,
    },
    /// A pubkey field decoded to a length-correct byte string that
    /// `ed25519-dalek` rejected as not a valid curve point.
    #[error("capability-token public key is not a valid Ed25519 point")]
    InvalidPubkey,
    /// The `expiry` field's integer value did not fit in `i64` /
    /// `u64`. Practically unreachable for sane timestamps; surfaces if
    /// a peer encodes a negative or `> 2^63` expiry.
    #[error("capability-token expiry is out of representable range")]
    ExpiryOutOfRange,
    /// The token's `COSE_Sign1` signature did not verify against the
    /// expected issuer's public key.
    ///
    /// Uniform across all crypto-layer failure modes per the
    /// no-error-oracle discipline (D0006 / D0018 §1.4).
    #[error("capability-token signature verification failed")]
    SignatureVerifyFailed,
    /// The issuer pubkey embedded in the decoded payload did not
    /// match the expected issuer pubkey supplied by the caller.
    ///
    /// Defends against key-substitution: a verifier knows who they
    /// expect signed the token; if the payload claims a different
    /// issuer, the token is rejected before signature verification.
    #[error("capability-token issuer does not match expected issuer")]
    IssuerMismatch,
}
