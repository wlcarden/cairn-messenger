// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Error types for `cairn-recovery`.
//!
//! Per D0018 §4.2: error variants carry indices, lengths, and type tags
//! only — never `Vec<u8>` or `&[u8]` payloads.

use thiserror::Error;

/// Top-level error type for `cairn-recovery`, re-exported from the
/// crate root.
///
/// `#[non_exhaustive]` per D0018 §4.2.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RecoveryError {
    /// Shamir reconstruction failed (insufficient / tampered shares;
    /// uniform `CommitmentMismatch` per D0018 §3.4).
    #[error("Shamir reconstruction failed: {0}")]
    ShamirReconstruct(#[from] cairn_shamir::ShamirError),
    /// Failure while encoding the attestation payload to canonical
    /// CBOR.
    #[error("master attestation canonical CBOR encoding failed: {0}")]
    CanonicalEncode(#[from] cairn_envelope::EnvelopeError),
    /// Failure during the `COSE_Sign1` signing step (typically a
    /// payload-size-limit hit on the underlying Ed25519 sign).
    #[error("master attestation signing failed")]
    SignFailed,
    /// Attestation payload bytes were not well-formed CBOR or did not
    /// match the schema.
    #[error("master attestation payload is malformed")]
    MalformedPayload,
    /// A pubkey field decoded to non-32-byte or non-curve-point.
    #[error(
        "master attestation public key has invalid length: {got_bytes} bytes (expected {expected_bytes})"
    )]
    InvalidPubkeyLength {
        /// Bytes observed in the field.
        got_bytes: usize,
        /// Expected Ed25519 public-key length.
        expected_bytes: usize,
    },
    /// A pubkey field decoded to a length-correct byte string that
    /// `ed25519-dalek` rejected as not a valid curve point.
    #[error("master attestation public key is not a valid Ed25519 point")]
    InvalidPubkey,
    /// The `timestamp` integer did not fit in `i64` (or was negative
    /// in `u64` decoding).
    #[error("master attestation timestamp is out of representable range")]
    TimestampOutOfRange,
    /// The master attestation's `COSE_Sign1` signature did not verify
    /// against the expected master pubkey. Uniform across crypto-layer
    /// failure modes per the no-error-oracle discipline (D0006 / D0018
    /// §1.4).
    #[error("master attestation signature verification failed")]
    SignatureVerifyFailed,
    /// The master pubkey field in the decoded payload did not match
    /// the expected master pubkey supplied by the caller. Defends
    /// against key-substitution.
    #[error("master attestation master pubkey does not match expected master pubkey")]
    MasterPubkeyMismatch,
}
