// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Trust-graph export surface (D0027 §2 — the `trust_graph` per-domain
//! module).
//!
//! This is the first per-domain export module to land behind the
//! build-validated UniFFI pipeline (D0028) per D0027 §8 step 4. It
//! exposes the cascade-quarantine classification the Android shell
//! needs to render trust badges (design brief §5.6 — the DEFERRED
//! "trust-badge rendering" row): given a contact's stored trust-graph
//! op chain + the capability token authorizing it + the expected
//! operational-identity pubkey, return the per-op
//! [`QuarantineStatusFfi`].
//!
//! ## Why a single fused `verify_and_classify`
//!
//! `cairn_trust_graph::compute_quarantine_state` documents a hard
//! precondition: *callers MUST verify the ops (via
//! [`cairn_trust_graph::verify_chain_links`]) before classifying* —
//! the cascade rule assumes cryptographically valid input. Across the
//! FFI boundary that "MUST" cannot be trusted to the Kotlin caller, so
//! [`trust_graph_verify_and_classify`] fuses verify-then-classify into
//! one call. The unsafe ordering (classify unverified ops) is not
//! merely discouraged — it is unrepresentable from Kotlin.
//!
//! ## Marshalling discipline
//!
//! Inputs cross as bytes (`Vec<Vec<u8>>` op chain, `Vec<u8>` token,
//! `Vec<u8>` pubkey) — Kotlin holds no Rust `SignedTrustGraphOp`
//! handle. Outputs carry only PUBLIC data: the revoking peer's pubkey
//! (32 public bytes) + Unix-seconds. No secret type appears in this
//! surface (enforced by [`crate::never_export_gate`]). Every typed
//! `TrustGraphError` is flattened to [`CairnFfiError`] via the existing
//! facade `From` mapping (D0027 §3) — no source `Display` string
//! crosses.

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, VerifyingKey};
use cairn_trust_graph::{SignedTrustGraphOp, compute_quarantine_state, verify_chain_links};

use crate::error::CairnFfiError;

/// FFI mirror of [`cairn_trust_graph::QuarantineStatus`] (D0027 §2.2).
///
/// The domain enum carries `VerifyingKey` fields; those are PUBLIC
/// keys, so they cross as 32-byte `Vec<u8>` (not secrets). Becomes a
/// `uniffi::Enum` under the `uniffi-bindings` feature; a plain Rust
/// enum otherwise so the mapping is testable without the proc-macro.
///
/// The domain `QuarantineStatus` is `#[non_exhaustive]`, so the `From`
/// mapping below carries a wildcard arm → [`Self::Unknown`]. This is
/// the fail-closed posture: a future domain variant this build does
/// not recognize renders as "unknown / treat as suspect", never
/// silently as [`Self::Active`]. (Same discipline as the error
/// facade's `UnmappedInternal`, D0027 §3.2.)
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
pub enum QuarantineStatusFfi {
    /// The op is a revocation, not an attestation — not classified.
    NotApplicable,
    /// No cascade revocation applies; the attestation is usable.
    Active,
    /// The issuer was withdrawn-from at or before this attestation's
    /// timestamp. Operationally usable but flagged.
    SoftFlaggedByWithdrawal {
        /// The PUBLIC key (32 bytes) of the peer who issued the
        /// `WithdrawRevoke`.
        revoked_by: Vec<u8>,
        /// The withdrawal op's Unix-seconds timestamp.
        withdrawal_at: u64,
    },
    /// The issuer was compromise-revoked, and this attestation was
    /// issued at or before the compromise window. Flagged but usable.
    SoftFlaggedPreCompromise {
        /// The PUBLIC key (32 bytes) of the peer who issued the
        /// `CompromiseRevoke`.
        revoked_by: Vec<u8>,
        /// The `revoked_as_of` Unix-seconds from the compromise revoke.
        revoked_as_of: u64,
    },
    /// The issuer was compromise-revoked, and this attestation was
    /// issued AFTER the compromise window. NOT operationally usable
    /// per D0006 §2's anti-laundering rule.
    HardSuspended {
        /// The PUBLIC key (32 bytes) of the peer who issued the
        /// `CompromiseRevoke`.
        revoked_by: Vec<u8>,
        /// The `revoked_as_of` Unix-seconds from the compromise revoke.
        revoked_as_of: u64,
    },
    /// Fail-closed catch-all for a future `#[non_exhaustive]` domain
    /// variant this build does not recognize. The shell renders this
    /// as the most-restrictive badge.
    Unknown,
}

impl From<cairn_trust_graph::QuarantineStatus> for QuarantineStatusFfi {
    fn from(status: cairn_trust_graph::QuarantineStatus) -> Self {
        use cairn_trust_graph::QuarantineStatus as Q;
        match status {
            Q::NotApplicable => Self::NotApplicable,
            Q::Active => Self::Active,
            Q::SoftFlaggedByWithdrawal {
                revoked_by,
                withdrawal_at,
            } => Self::SoftFlaggedByWithdrawal {
                revoked_by: revoked_by.to_bytes().to_vec(),
                withdrawal_at,
            },
            Q::SoftFlaggedPreCompromise {
                revoked_by,
                revoked_as_of,
            } => Self::SoftFlaggedPreCompromise {
                revoked_by: revoked_by.to_bytes().to_vec(),
                revoked_as_of,
            },
            Q::HardSuspended {
                revoked_by,
                revoked_as_of,
            } => Self::HardSuspended {
                revoked_by: revoked_by.to_bytes().to_vec(),
                revoked_as_of,
            },
            // The domain enum is #[non_exhaustive]; fail closed.
            _ => Self::Unknown,
        }
    }
}

/// Verify a single issuer's trust-graph op chain, then classify each
/// op's cascade-quarantine status (D0027 §2.2).
///
/// `op_chain` is the issuer's ordered ops, each as canonical
/// `COSE_Sign1` bytes (`cairn_trust_graph::SignedTrustGraphOp`
/// encoding). `capability_token` is the encoded
/// `SignedCapabilityToken` authorizing the issuing device.
/// `expected_operational_identity` is the issuer's 32-byte operational
/// pubkey. Returns one [`QuarantineStatusFfi`] per input op, in order
/// (`output[i]` classifies `op_chain[i]`).
///
/// Verification (three-hop chain per op + chain-link integrity per
/// D0006 §2/§5) happens BEFORE classification; an invalid chain
/// returns an error and never reaches the cascade rule.
///
/// # Errors
///
/// - [`CairnFfiError::MalformedData`] if `expected_operational_identity`
///   is not exactly [`PUBLIC_KEY_LEN`] bytes or is not a valid Ed25519
///   public key, or if any `op_chain` entry is not well-formed.
/// - [`CairnFfiError::ChainInvalid`] for any chain-integrity failure
///   (empty chain, genesis/prior-hash mismatch, pair mismatch,
///   timestamp regression).
/// - [`CairnFfiError::SignatureVerifyFailed`] /
///   [`CairnFfiError::CapabilityNotAuthorized`] from per-op
///   verification.
///
/// All variants are the flat facade mapping of the source
/// `TrustGraphError` (D0027 §3); no source `Display` string crosses.
#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
)]
pub fn trust_graph_verify_and_classify(
    op_chain: Vec<Vec<u8>>,
    capability_token: Vec<u8>,
    expected_operational_identity: Vec<u8>,
) -> Result<Vec<QuarantineStatusFfi>, CairnFfiError> {
    // Parse the expected operational-identity pubkey (32 public bytes).
    let pubkey_bytes: [u8; PUBLIC_KEY_LEN] = expected_operational_identity
        .as_slice()
        .try_into()
        .map_err(|_| CairnFfiError::MalformedData)?;
    let expected =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| CairnFfiError::MalformedData)?;

    // Decode each op (no verification yet); a malformed entry flattens
    // to MalformedData via the facade From mapping.
    let ops: Vec<SignedTrustGraphOp> = op_chain
        .iter()
        .map(|bytes| SignedTrustGraphOp::from_bytes(bytes))
        .collect::<Result<_, _>>()?;

    // Verify the chain BEFORE classifying. verify_chain_links returns
    // the verified inner ops, which compute_quarantine_state consumes.
    let verified = verify_chain_links(&ops, &capability_token, &expected)?;
    let statuses = compute_quarantine_state(&verified);

    Ok(statuses
        .into_iter()
        .map(QuarantineStatusFfi::from)
        .collect())
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests assert on known-shape fixtures; index/unwrap panics ARE the failure signal"
)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use cairn_identity::{CapabilityToken, capabilities};
    use cairn_trust_graph::TrustGraphOp;
    use rand_core::OsRng;

    /// Build `(expected_operational_identity_bytes, capability_token_bytes,
    /// genesis_attest_op_bytes)` for a single valid genesis attestation
    /// authorizing `device` under the attest scope. Mirrors the
    /// `cairn-trust-graph` signed-op test fixture.
    fn single_genesis_attest() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let op_identity_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();

        let token = CapabilityToken::new(
            op_identity_sk.verifying_key(),
            device_sk.verifying_key(),
            vec![capabilities::TRUST_GRAPH_ATTEST.to_string()],
            2_000_000_000,
            vec![],
        );
        let token_bytes = token.sign(&op_identity_sk).unwrap().encode(false).unwrap();

        // Genesis attest: empty prior_hash.
        let op = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![],
            vec![],
            cairn_trust_graph::Strength::InPerson,
        );
        let op_bytes = SignedTrustGraphOp::sign(op, &device_sk)
            .unwrap()
            .encode(false)
            .unwrap();

        (
            op_identity_sk.verifying_key().to_bytes().to_vec(),
            token_bytes,
            op_bytes,
        )
    }

    #[test]
    fn single_genesis_attest_classifies_active() {
        let (expected, token, op) = single_genesis_attest();
        let statuses = trust_graph_verify_and_classify(vec![op], token, expected).unwrap();
        assert_eq!(statuses, vec![QuarantineStatusFfi::Active]);
    }

    #[test]
    fn empty_chain_maps_to_chain_invalid() {
        // A syntactically valid pubkey, but no ops → ChainEmpty →
        // ChainInvalid (the facade flattening of the chain errors).
        let (expected, token, _op) = single_genesis_attest();
        let err = trust_graph_verify_and_classify(vec![], token, expected).unwrap_err();
        assert_eq!(err, CairnFfiError::ChainInvalid);
    }

    #[test]
    fn wrong_length_pubkey_maps_to_malformed_data() {
        let (_expected, token, op) = single_genesis_attest();
        let err = trust_graph_verify_and_classify(vec![op], token, vec![0u8; 31]).unwrap_err();
        assert_eq!(err, CairnFfiError::MalformedData);
    }

    #[test]
    fn malformed_op_bytes_map_to_malformed_data() {
        // Valid pubkey, but the op bytes are not COSE_Sign1 → decode
        // fails as MalformedPayload → MalformedData.
        let (expected, token, _op) = single_genesis_attest();
        let err =
            trust_graph_verify_and_classify(vec![vec![0xFFu8; 8]], token, expected).unwrap_err();
        assert_eq!(err, CairnFfiError::MalformedData);
    }

    #[test]
    fn tampered_token_rejected_as_signature_failure() {
        // Flip the last byte of the capability token (the signature
        // tail); verification must fail and never reach the cascade
        // rule. Every capability-token verify failure collapses to
        // SignatureVerifyFailed (D0027 §3.2) — a deterministic mapping,
        // NOT UnmappedInternal (regression-guarded in error.rs).
        let (expected, mut token, op) = single_genesis_attest();
        let last = token.len() - 1;
        token[last] ^= 0x01;
        let err = trust_graph_verify_and_classify(vec![op], token, expected).unwrap_err();
        assert_eq!(err, CairnFfiError::SignatureVerifyFailed);
    }
}
