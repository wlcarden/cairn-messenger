// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Stateless chain-link validation for trust-graph operations per
//! D0006 §2 + §5.
//!
//! ## What this module owns
//!
//! Given a sequence of [`SignedTrustGraphOp`]s for one
//! `(issuer, subject)` pair, [`verify_chain_links`] validates:
//!
//! 1. **Per-op three-hop verification.** Each op individually goes
//!    through [`SignedTrustGraphOp::verify_chain`] (hops #1 + #2) —
//!    same path the single-op verifier uses, so this surface inherits
//!    all the existing defenses.
//! 2. **Chain structure** per D0006 §5:
//!    - Genesis (`ops[0]`) has zero-length `prior_hash`.
//!    - Each non-genesis op's `prior_hash` equals
//!      `SHA-256( ops[i-1].COSE_Sign1.signature_bytes )`.
//!    - All ops share the same `(issuer, subject)` pair (the chain
//!      scope per D0006 §5).
//!    - Timestamps are non-decreasing along the chain (no clock
//!      regression / reordering).
//!
//! ## What this module does NOT own
//!
//! - **Cascade quarantine state tracking** per D0006 §2 (the time-
//!   based 90-day stale-flag escalation). That's a stateful surface
//!   requiring persistent storage decisions outside D0018's current
//!   scope; the `cairn-trust-graph-state` crate will own it once the
//!   storage architecture lands.
//! - **Re-attestation policy enforcement** (D0006 §2's "stricter
//!   re-attestation requirements" — fresh in-person verification or
//!   two independent unflagged paths). UI policy, not chain
//!   correctness.
//! - **Cross-(issuer, subject) chain detection.** A peer might issue
//!   chains for many subjects; this module validates one chain at a
//!   time. Aggregating chains across subjects is the higher-layer
//!   trust-graph state's job.

use cairn_crypto::ed25519::VerifyingKey;

use crate::error::TrustGraphError;
use crate::op::TrustGraphOp;
use crate::signed::SignedTrustGraphOp;

/// Verify a sequence of `SignedTrustGraphOp`s as a single chain per
/// D0006 §2 + §5.
///
/// On success returns the verified `TrustGraphOp` references in order,
/// so callers don't have to re-verify or re-decode to walk them.
///
/// # Errors
///
/// - [`TrustGraphError::ChainEmpty`] if `ops` is empty.
/// - Any [`TrustGraphError`] from the per-op
///   [`SignedTrustGraphOp::verify_chain`] (signature failure,
///   capability mismatch, token verification failure, etc.) is
///   propagated with no transformation.
/// - [`TrustGraphError::ChainGenesisNotEmpty`] if `ops[0]` has a
///   non-empty `prior_hash`.
/// - [`TrustGraphError::ChainPriorHashMismatch`] if any non-genesis
///   op's `prior_hash` does not match the SHA-256 of its predecessor's
///   signature per D0006 §5.
/// - [`TrustGraphError::ChainPairMismatch`] if any op in the chain
///   has an `(issuer, subject)` pair different from `ops[0]`.
/// - [`TrustGraphError::ChainTimestampRegression`] if any op's
///   timestamp is strictly earlier than its predecessor's.
pub fn verify_chain_links<'a>(
    ops: &'a [SignedTrustGraphOp],
    token_bytes: &[u8],
    expected_operational_identity: &VerifyingKey,
) -> Result<Vec<&'a TrustGraphOp>, TrustGraphError> {
    if ops.is_empty() {
        return Err(TrustGraphError::ChainEmpty);
    }

    let mut verified: Vec<&TrustGraphOp> = Vec::with_capacity(ops.len());
    let mut prior_hash_expected: Option<[u8; 32]> = None;
    let mut chain_pair: Option<(VerifyingKey, VerifyingKey)> = None;
    let mut last_timestamp: Option<u64> = None;

    for (index, signed_op) in ops.iter().enumerate() {
        // Per-op three-hop verification (hops #1 + #2).
        let op = signed_op.verify_chain(token_bytes, expected_operational_identity)?;

        // Chain pair scope: all ops share the same (issuer, subject).
        match chain_pair {
            None => {
                chain_pair = Some((op.issuer, op.subject));
            }
            Some((chain_issuer, chain_subject)) => {
                if op.issuer != chain_issuer || op.subject != chain_subject {
                    return Err(TrustGraphError::ChainPairMismatch { index });
                }
            }
        }

        // Genesis vs non-genesis prior_hash check.
        match prior_hash_expected {
            None => {
                // Genesis: prior_hash must be zero-length.
                if !op.prior_hash.is_empty() {
                    return Err(TrustGraphError::ChainGenesisNotEmpty { index });
                }
            }
            Some(expected) => {
                if op.prior_hash.as_slice() != expected.as_slice() {
                    return Err(TrustGraphError::ChainPriorHashMismatch { index });
                }
            }
        }

        // Timestamp non-decreasing (defends against clock-rewind reuse
        // and reordering attacks).
        if let Some(prev_ts) = last_timestamp
            && op.timestamp < prev_ts
        {
            return Err(TrustGraphError::ChainTimestampRegression { index });
        }
        last_timestamp = Some(op.timestamp);

        // Update the expected prior_hash for the next iteration.
        prior_hash_expected = Some(signed_op.prior_hash_bytes());
        verified.push(op);
    }

    Ok(verified)
}

#[cfg(test)]
// `indexing_slicing` allowed at the test-module level: shares,
// envelope bytes, and chain slots are produced by the test setup
// and have statically-known lengths.
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use cairn_envelope::cose_sign1::CoseSign1;
    use cairn_identity::{CapabilityToken, capabilities};
    use rand_core::OsRng;
    use sha2::{Digest as _, Sha256};

    /// Build a complete (operational identity, device, capability
    /// token) bundle authorizing the device for the requested scope.
    pub(super) fn make_token_bundle(scope: &[&str]) -> (SigningKey, SigningKey, Vec<u8>) {
        let mut rng = OsRng;
        let op_identity_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);

        let token = CapabilityToken::new(
            op_identity_sk.verifying_key(),
            device_sk.verifying_key(),
            scope.iter().map(|s| (*s).to_string()).collect(),
            2_000_000_000,
            vec![],
        );
        let signed_token = token.sign(&op_identity_sk).unwrap();
        let token_bytes = signed_token.encode(false).unwrap();
        (op_identity_sk, device_sk, token_bytes)
    }

    /// Helper: sign a genesis Attest op + N follow-up Attest ops, each
    /// chained via SHA-256(prior signature). Timestamps strictly
    /// increasing.
    pub(super) fn build_well_formed_chain(
        length: usize,
        cert_hash: &[u8],
    ) -> (
        SigningKey,
        SigningKey,
        VerifyingKey,
        Vec<u8>,
        Vec<SignedTrustGraphOp>,
    ) {
        assert!(length >= 1, "chain must have at least one op");
        let (op_identity_sk, device_sk, token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let mut rng = OsRng;
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();

        let mut chain = Vec::with_capacity(length);
        let mut prior_hash: Vec<u8> = vec![];
        let mut timestamp = 1_700_000_000u64;
        for _ in 0..length {
            let op = TrustGraphOp::new_attest(
                op_identity_sk.verifying_key(),
                peer_pubkey,
                timestamp,
                prior_hash.clone(),
                cert_hash.to_vec(),
                crate::Strength::InPerson,
            );
            let signed = SignedTrustGraphOp::sign(op, &device_sk).unwrap();
            prior_hash = signed.prior_hash_bytes().to_vec();
            timestamp = timestamp.saturating_add(100);
            chain.push(signed);
        }
        (op_identity_sk, device_sk, peer_pubkey, token_bytes, chain)
    }

    #[test]
    fn empty_chain_rejected() {
        let (op_identity_sk, _device_sk, token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let result = verify_chain_links(&[], &token_bytes, &op_identity_sk.verifying_key());
        assert!(matches!(result, Err(TrustGraphError::ChainEmpty)));
    }

    #[test]
    fn single_genesis_op_chain_verifies() {
        let (op_identity_sk, _device_sk, _peer, token_bytes, chain) =
            build_well_formed_chain(1, &[]);
        let verified =
            verify_chain_links(&chain, &token_bytes, &op_identity_sk.verifying_key()).unwrap();
        assert_eq!(verified.len(), 1);
        assert!(verified[0].prior_hash.is_empty());
    }

    #[test]
    fn three_op_well_formed_chain_verifies() {
        let (op_identity_sk, _device_sk, _peer, token_bytes, chain) =
            build_well_formed_chain(3, &[]);
        let verified =
            verify_chain_links(&chain, &token_bytes, &op_identity_sk.verifying_key()).unwrap();
        assert_eq!(verified.len(), 3);
        // Verify chain link bytes match SHA-256 of prior signatures.
        for i in 1..verified.len() {
            let prev_envelope_bytes = chain[i - 1].encode(false).unwrap();
            let prev_envelope = CoseSign1::from_bytes(&prev_envelope_bytes).unwrap();
            let expected = Sha256::digest(prev_envelope.signature());
            assert_eq!(verified[i].prior_hash.as_slice(), expected.as_slice());
        }
    }

    #[test]
    fn genesis_with_non_empty_prior_hash_rejected() {
        let (op_identity_sk, device_sk, token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let mut rng = OsRng;
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();

        // Construct a "genesis" op with non-empty prior_hash.
        let bogus_genesis = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![0u8; 32], // wrong: genesis should have empty prior_hash
            vec![],
            crate::Strength::InPerson,
        );
        let signed_genesis = SignedTrustGraphOp::sign(bogus_genesis, &device_sk).unwrap();
        let result = verify_chain_links(
            std::slice::from_ref(&signed_genesis),
            &token_bytes,
            &op_identity_sk.verifying_key(),
        );
        assert!(matches!(
            result,
            Err(TrustGraphError::ChainGenesisNotEmpty { index: 0 })
        ));
    }

    #[test]
    fn broken_prior_hash_link_rejected() {
        let (op_identity_sk, device_sk, token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let mut rng = OsRng;
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();

        // Build a 2-op chain where op[1]'s prior_hash is wrong.
        let op_genesis = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![],
            vec![],
            crate::Strength::InPerson,
        );
        let signed_genesis = SignedTrustGraphOp::sign(op_genesis, &device_sk).unwrap();

        let op_followup = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_100,
            vec![0xAAu8; 32], // wrong: not SHA-256 of signed_genesis.signature
            vec![],
            crate::Strength::InPerson,
        );
        let signed_followup = SignedTrustGraphOp::sign(op_followup, &device_sk).unwrap();

        let chain = vec![signed_genesis, signed_followup];
        let result = verify_chain_links(&chain, &token_bytes, &op_identity_sk.verifying_key());
        assert!(matches!(
            result,
            Err(TrustGraphError::ChainPriorHashMismatch { index: 1 })
        ));
    }

    #[test]
    fn pair_mismatch_rejected() {
        let (op_identity_sk, device_sk, token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let mut rng = OsRng;
        let peer_alpha_pubkey = SigningKey::generate(&mut rng).verifying_key();
        let peer_bravo_pubkey = SigningKey::generate(&mut rng).verifying_key();

        // Genesis op for peer alpha.
        let op_genesis = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer_alpha_pubkey,
            1_700_000_000,
            vec![],
            vec![],
            crate::Strength::InPerson,
        );
        let signed_genesis = SignedTrustGraphOp::sign(op_genesis, &device_sk).unwrap();

        // Follow-up op for peer bravo — wrong subject for this chain.
        let op_followup = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer_bravo_pubkey,
            1_700_000_100,
            signed_genesis.prior_hash_bytes().to_vec(),
            vec![],
            crate::Strength::InPerson,
        );
        let signed_followup = SignedTrustGraphOp::sign(op_followup, &device_sk).unwrap();

        let chain = vec![signed_genesis, signed_followup];
        let result = verify_chain_links(&chain, &token_bytes, &op_identity_sk.verifying_key());
        assert!(matches!(
            result,
            Err(TrustGraphError::ChainPairMismatch { index: 1 })
        ));
    }

    #[test]
    fn timestamp_regression_rejected() {
        let (op_identity_sk, device_sk, token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let mut rng = OsRng;
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();

        let op_genesis = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_500,
            vec![],
            vec![],
            crate::Strength::InPerson,
        );
        let signed_genesis = SignedTrustGraphOp::sign(op_genesis, &device_sk).unwrap();

        // Follow-up op with EARLIER timestamp.
        let op_followup = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000, // earlier than genesis
            signed_genesis.prior_hash_bytes().to_vec(),
            vec![],
            crate::Strength::InPerson,
        );
        let signed_followup = SignedTrustGraphOp::sign(op_followup, &device_sk).unwrap();

        let chain = vec![signed_genesis, signed_followup];
        let result = verify_chain_links(&chain, &token_bytes, &op_identity_sk.verifying_key());
        assert!(matches!(
            result,
            Err(TrustGraphError::ChainTimestampRegression { index: 1 })
        ));
    }

    #[test]
    fn per_op_verification_failure_propagated() {
        // Build a chain authorized under one operational identity, then
        // verify against a different expected operational identity.
        // The first verify_chain call inside should fail and surface as
        // a CapabilityTokenVerify error.
        let (op_identity_alpha, _device_sk, _peer, token_bytes_alpha, chain_alpha) =
            build_well_formed_chain(2, &[]);
        let mut rng = OsRng;
        let op_identity_bravo = SigningKey::generate(&mut rng);

        let result = verify_chain_links(
            &chain_alpha,
            &token_bytes_alpha,
            &op_identity_bravo.verifying_key(),
        );
        assert!(matches!(
            result,
            Err(TrustGraphError::CapabilityTokenVerify(_))
        ));
        // Sanity check: the chain DOES verify under the correct identity.
        assert!(
            verify_chain_links(
                &chain_alpha,
                &token_bytes_alpha,
                &op_identity_alpha.verifying_key()
            )
            .is_ok()
        );
    }

    #[test]
    fn long_chain_smoke_test() {
        // 16-op chain — well above typical depth; proves the prior_hash
        // chain composes correctly through many links.
        let (op_identity_sk, _device_sk, _peer, token_bytes, chain) =
            build_well_formed_chain(16, &[]);
        let verified =
            verify_chain_links(&chain, &token_bytes, &op_identity_sk.verifying_key()).unwrap();
        assert_eq!(verified.len(), 16);
        // First op is genesis; last op has the final prior_hash.
        assert!(verified[0].prior_hash.is_empty());
        assert!(!verified[15].prior_hash.is_empty());
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod proptests {
    use super::tests::{build_well_formed_chain, make_token_bundle};
    use super::*;
    use cairn_identity::capabilities;
    use proptest::prelude::*;

    proptest! {
        /// Property: any well-formed chain of length in [1, 8] verifies
        /// cleanly. The build_well_formed_chain helper produces a chain
        /// that satisfies all four invariants (genesis empty
        /// prior_hash, SHA-256 link, single pair, monotone timestamps).
        #[test]
        fn prop_well_formed_chain_verifies_for_any_length(length in 1usize..=8) {
            let (op_identity_sk, _device_sk, _peer, token_bytes, chain) =
                build_well_formed_chain(length, &[]);
            let result = verify_chain_links(
                &chain, &token_bytes, &op_identity_sk.verifying_key()
            );
            prop_assert!(result.is_ok(), "well-formed chain of length {length} should verify");
            let verified = result.unwrap();
            prop_assert_eq!(verified.len(), length);
        }

        /// Property: verifying the same chain twice yields identical
        /// results. Determinism guard for the verifier path.
        #[test]
        fn prop_verification_is_deterministic(length in 1usize..=4) {
            let (op_identity_sk, _device_sk, _peer, token_bytes, chain) =
                build_well_formed_chain(length, &[]);
            let a = verify_chain_links(&chain, &token_bytes, &op_identity_sk.verifying_key());
            let b = verify_chain_links(&chain, &token_bytes, &op_identity_sk.verifying_key());
            prop_assert_eq!(a.is_ok(), b.is_ok());
        }

        /// Property: a chain with the wrong expected operational
        /// identity always rejects. The mismatch is detected at the
        /// first per-op verify_chain call, so the chain-walk surfaces
        /// the same error path regardless of chain length.
        #[test]
        fn prop_wrong_expected_issuer_always_rejected(length in 1usize..=4) {
            let mut rng = rand_core::OsRng;
            let (_op_identity_sk, _device_sk, _peer, token_bytes, chain) =
                build_well_formed_chain(length, &[]);
            let bogus_issuer = cairn_crypto::ed25519::SigningKey::generate(&mut rng).verifying_key();
            let result = verify_chain_links(&chain, &token_bytes, &bogus_issuer);
            prop_assert!(result.is_err());
        }

        /// Property: empty chain always rejects with ChainEmpty.
        /// Length 0 has no genesis to anchor structural checks against.
        #[test]
        fn prop_empty_chain_rejected(_dummy in 0u8..1) {
            let (op_identity_sk, _device_sk, token_bytes) =
                make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
            let result = verify_chain_links(&[], &token_bytes, &op_identity_sk.verifying_key());
            let is_empty_error = matches!(result, Err(TrustGraphError::ChainEmpty));
            prop_assert!(is_empty_error);
        }
    }
}
