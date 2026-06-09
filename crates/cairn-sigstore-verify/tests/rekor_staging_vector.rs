// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Phase-2 "2a" (D0042 §7): prove the Rekor verifier against **real**
//! Sigstore staging data, not synthetic fixtures.
//!
//! The fixtures (`tests/vectors/rekor-staging/`) are a `hashedrekord`
//! entry + its inclusion proof + signed checkpoint, and the staging Rekor
//! public key, captured once from `rekor.sigstage.dev` (see that dir's
//! README). The checkpoint is signed by the **real** staging Rekor ECDSA
//! P-256 key; the inclusion proof is the **real** RFC 6962 audit path in a
//! frozen (inactive) shard. So a green `verify_rekor_inclusion` here means
//! the verifier accepts attacker-**unforgeable** log data — the first
//! non-synthetic verification in the release-pipeline stack, and the half
//! that delivers consumer-side forgery-resistance (D0041 §6.1).
//!
//! Pure offline: the proof + checkpoint are a frozen cryptographic fact,
//! so no network runs at test time (CI-safe, no `online-rekor` feature).

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use cairn_sigstore_verify::{SigstoreVerifyError, parse_rekor_log_entry, verify_rekor_inclusion};

/// The pinned Sigstore **staging** Rekor public key (ECDSA P-256 SPKI).
const STAGING_REKOR_PUBKEY_PEM: &str = include_str!("vectors/rekor-staging/log-publickey.pem");
/// A real staging `GET /api/v1/log/entries/{uuid}` response.
const STAGING_ENTRY_JSON: &str = include_str!("vectors/rekor-staging/entry-logindex1.json");

/// The frozen inactive-shard tree size + origin the captured entry proves
/// inclusion against (see the vectors README).
const EXPECTED_TREE_SIZE: u64 = 461;

#[test]
fn verifies_real_rekor_staging_inclusion_and_checkpoint() {
    // Parse the real Rekor response into a bundle (leaf hash = SHA-256(0x00
    // || body); proof nodes; the signed checkpoint split into note + DER
    // ECDSA sig), then verify it against the REAL pinned staging key.
    let bundle = parse_rekor_log_entry(STAGING_ENTRY_JSON)
        .expect("the real staging entry must parse into a RekorBundle");

    let checkpoint = verify_rekor_inclusion(&bundle, STAGING_REKOR_PUBKEY_PEM.as_bytes())
        .expect("the real staging inclusion proof + checkpoint must verify against the real key");

    // A green verify already proves: the checkpoint signature is valid
    // under the pinned staging key AND the RFC 6962 audit path reconstructs
    // to the checkpoint's signed root. Spot-check the surfaced facts.
    assert_eq!(checkpoint.tree_size, EXPECTED_TREE_SIZE);
    assert!(
        checkpoint.origin.starts_with("rekor.sigstage.dev"),
        "origin was {:?}",
        checkpoint.origin
    );
}

#[test]
fn rejects_real_staging_checkpoint_under_a_non_pinned_key() {
    // The pin's core defense: a checkpoint signed by the real staging key
    // must NOT verify against a different (attacker-controlled) pinned key.
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePublicKey as _, LineEnding};
    use rand_core::OsRng;

    let bundle = parse_rekor_log_entry(STAGING_ENTRY_JSON).unwrap();

    let attacker_key = SigningKey::random(&mut OsRng);
    let attacker_pem = p256::ecdsa::VerifyingKey::from(&attacker_key)
        .to_public_key_pem(LineEnding::LF)
        .unwrap();

    let result = verify_rekor_inclusion(&bundle, attacker_pem.as_bytes());
    assert!(
        matches!(
            result,
            Err(SigstoreVerifyError::RekorCheckpointVerifyFailed)
        ),
        "got {result:?}"
    );
}

#[test]
fn rejects_real_staging_proof_with_a_tampered_audit_node() {
    // Corrupt one real audit-path node: the reconstructed RFC 6962 root no
    // longer matches the (signature-verified) checkpoint root.
    let mut bundle = parse_rekor_log_entry(STAGING_ENTRY_JSON).unwrap();
    assert!(
        !bundle.proof_nodes.is_empty(),
        "the entry has an audit path"
    );
    bundle.proof_nodes[0][0] ^= 0xFF;

    let result = verify_rekor_inclusion(&bundle, STAGING_REKOR_PUBKEY_PEM.as_bytes());
    assert!(
        matches!(
            result,
            Err(SigstoreVerifyError::RekorInclusionProofVerifyFailed)
        ),
        "got {result:?}"
    );
}
