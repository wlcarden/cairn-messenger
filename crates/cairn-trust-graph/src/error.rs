// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Error types for `cairn-trust-graph`.
//!
//! Per D0018 §4.2: error variants carry indices, lengths, and type tags
//! only — never `Vec<u8>` or `&[u8]` payloads.

use thiserror::Error;

/// Top-level error type for `cairn-trust-graph`, re-exported from the
/// crate root.
///
/// `#[non_exhaustive]` per D0018 §4.2.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TrustGraphError {
    /// Failure while encoding a trust-graph operation to canonical
    /// CBOR (unreachable for typed inputs but the variant exists so we
    /// never `unwrap` on the underlying encoder result).
    #[error("trust-graph op canonical CBOR encoding failed: {0}")]
    CanonicalEncode(#[from] cairn_envelope::EnvelopeError),
    /// The operation payload bytes were not well-formed CBOR or did
    /// not match the expected schema per D0006 §2.
    #[error("trust-graph op payload is malformed")]
    MalformedPayload,
    /// A pubkey field (issuer or subject) was not the expected 32-byte
    /// Ed25519 public-key length.
    #[error(
        "trust-graph op public key has invalid length: {got_bytes} bytes (expected {expected_bytes})"
    )]
    InvalidPubkeyLength {
        /// Bytes observed in the field.
        got_bytes: usize,
        /// Expected Ed25519 public-key length.
        expected_bytes: usize,
    },
    /// A pubkey field decoded to a length-correct byte string that
    /// `ed25519-dalek` rejected as not a valid curve point.
    #[error("trust-graph op public key is not a valid Ed25519 point")]
    InvalidPubkey,
    /// The `op_type` field carried a value not in the v1 enumeration
    /// (1..=4).
    #[error("trust-graph op_type {value} is not a v1 operation type")]
    UnknownOpType {
        /// The raw integer value observed.
        value: i64,
    },
    /// A type-required field is missing for the decoded operation
    /// variant (e.g. `revoked_as_of` missing for a `CompromiseRevoke`).
    #[error("trust-graph op missing type-required field for variant {variant}")]
    MissingRequiredField {
        /// The operation type name.
        variant: &'static str,
    },
    /// An integer field's value did not fit in `u64` (or `i64` for
    /// `op_type`).
    #[error("trust-graph op integer field out of representable range")]
    IntegerOutOfRange,
    /// The trust-graph operation's `COSE_Sign1` signature did not
    /// verify against the expected device public key (the token's
    /// subject). Uniform across all crypto-layer failure modes per
    /// the no-error-oracle discipline (D0006 / D0018 §1.4).
    #[error("trust-graph op signature verification failed")]
    SignatureVerifyFailed,
    /// The capability token's subject pubkey did not match the
    /// device pubkey extracted from the operation envelope verifier
    /// flow.
    #[error("trust-graph op device pubkey does not match token subject")]
    DeviceTokenMismatch,
    /// The capability token does not authorize the operation type
    /// (scope does not contain the required `trust-graph:*`
    /// capability).
    #[error("token does not authorize trust-graph op {op_type}: required capability {required}")]
    CapabilityNotAuthorized {
        /// The numeric op-type that was attempted.
        op_type: i64,
        /// The capability string the token would have needed.
        required: &'static str,
    },
    /// Wraps a capability-token verification failure (when verifying
    /// the bound token as part of the trust-graph op chain).
    #[error("capability token verification failed: {0}")]
    CapabilityTokenVerify(#[from] cairn_identity::IdentityError),
    /// Chain-walk: the first op in a chain claimed a non-empty
    /// `prior_hash` (only the genesis op may have an empty `prior_hash`).
    #[error("chain-walk: op at index {index} claimed to be genesis but has non-empty prior_hash")]
    ChainGenesisNotEmpty {
        /// Position of the offending op in the input slice.
        index: usize,
    },
    /// Chain-walk: a non-genesis op's `prior_hash` did not match the
    /// SHA-256 of the previous op's signature per D0006 §5.
    #[error(
        "chain-walk: op at index {index} prior_hash does not match SHA-256 of prior op signature"
    )]
    ChainPriorHashMismatch {
        /// Position of the offending op in the input slice.
        index: usize,
    },
    /// Chain-walk: ops in the chain disagree on the `(issuer, subject)`
    /// pair. A chain is per-(issuer, subject) per D0006 §5; cross-pair
    /// reordering is a structural error.
    #[error("chain-walk: op at index {index} has (issuer, subject) pair different from chain head")]
    ChainPairMismatch {
        /// Position of the offending op in the input slice.
        index: usize,
    },
    /// Chain-walk: timestamps must be non-decreasing along the chain
    /// (each op was issued at or after its predecessor). A regression
    /// indicates either a clock-rewind reuse attempt or a reordering
    /// attack.
    #[error("chain-walk: op at index {index} timestamp is earlier than its predecessor")]
    ChainTimestampRegression {
        /// Position of the offending op in the input slice.
        index: usize,
    },
    /// Chain-walk: caller passed an empty slice. A chain must have at
    /// least one op (the genesis).
    #[error("chain-walk: empty chain — must contain at least one op")]
    ChainEmpty,
}
