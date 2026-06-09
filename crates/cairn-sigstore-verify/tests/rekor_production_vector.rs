// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Phase-2 (D0042 §5/§7): prove the Rekor verifier against **real**
//! Sigstore **production** data — the production counterpart to
//! `rekor_staging_vector.rs`, completing the production Fulcio + CT + Rekor
//! anchor triple.
//!
//! The fixtures (`tests/vectors/rekor-production/`) are the real
//! `GET /api/v1/log/entries?logIndex=1767842880` response (the same GHA
//! signing event whose cert is `fulcio-gha/leaf-cert.pem`) — a
//! `hashedrekord` entry + its RFC 6962 inclusion proof + the C2SP signed
//! checkpoint — and the production Rekor ECDSA P-256 public key, captured
//! once from `rekor.sigstore.dev` (see that dir's README). A green
//! `verify_rekor_inclusion` here means the verifier accepts
//! attacker-**unforgeable** *production* log data.
//!
//! Unlike the staging vector (a frozen inactive shard), this proof is in an
//! active shard — but an inclusion proof against a captured `treeSize` is a
//! frozen cryptographic fact (the Merkle root at that size is immutable), so
//! it remains verifiable permanently with no network at test time.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use cairn_sigstore_verify::{SigstoreVerifyError, parse_rekor_log_entry, verify_rekor_inclusion};

/// The pinned Sigstore **production** Rekor public key (ECDSA P-256 SPKI).
const PROD_REKOR_PUBKEY_PEM: &str = include_str!("vectors/rekor-production/log-publickey.pem");
/// A real production `GET /api/v1/log/entries?logIndex=…` response.
const PROD_ENTRY_JSON: &str =
    include_str!("vectors/rekor-production/entry-logindex1767842880.json");

/// The tree size the captured entry proves inclusion against (the active
/// shard's size at capture; the root at that size is immutable — see the
/// vectors README).
const EXPECTED_TREE_SIZE: u64 = 1_648_242_788;

#[test]
fn verifies_real_rekor_production_inclusion_and_checkpoint() {
    // Parse the real Rekor response into a bundle (leaf hash = SHA-256(0x00
    // || body); proof nodes; the signed checkpoint split into note + DER
    // ECDSA sig), then verify it against the REAL pinned production key.
    let bundle = parse_rekor_log_entry(PROD_ENTRY_JSON)
        .expect("the real production entry must parse into a RekorBundle");

    let checkpoint = verify_rekor_inclusion(&bundle, PROD_REKOR_PUBKEY_PEM.as_bytes()).expect(
        "the real production inclusion proof + checkpoint must verify against the real key",
    );

    // A green verify already proves: the checkpoint signature is valid under
    // the pinned production key AND the RFC 6962 audit path reconstructs to
    // the checkpoint's signed root. Spot-check the surfaced facts.
    assert_eq!(checkpoint.tree_size, EXPECTED_TREE_SIZE);
    assert!(
        checkpoint.origin.starts_with("rekor.sigstore.dev"),
        "origin was {:?}",
        checkpoint.origin
    );
}

#[test]
fn rejects_real_production_checkpoint_under_a_non_pinned_key() {
    // The pin's core defense: a checkpoint signed by the real production key
    // must NOT verify against a different (attacker-controlled) pinned key.
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePublicKey as _, LineEnding};
    use rand_core::OsRng;

    let bundle = parse_rekor_log_entry(PROD_ENTRY_JSON).unwrap();

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
fn rejects_real_production_proof_with_a_tampered_audit_node() {
    // Corrupt one real audit-path node: the reconstructed RFC 6962 root no
    // longer matches the (signature-verified) checkpoint root.
    let mut bundle = parse_rekor_log_entry(PROD_ENTRY_JSON).unwrap();
    assert!(
        !bundle.proof_nodes.is_empty(),
        "the entry has an audit path"
    );
    bundle.proof_nodes[0][0] ^= 0xFF;

    let result = verify_rekor_inclusion(&bundle, PROD_REKOR_PUBKEY_PEM.as_bytes());
    assert!(
        matches!(
            result,
            Err(SigstoreVerifyError::RekorInclusionProofVerifyFailed)
        ),
        "got {result:?}"
    );
}
