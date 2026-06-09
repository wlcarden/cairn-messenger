// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Phase-2 (D0042 §6.6): prove the Rekor **entry-type binding** —
//! reconstruct a `hashedrekord` entry body from its components
//! (artifact hash + detached signature + signing certificate) **byte-for-
//! byte** against a real captured Rekor entry, so the verifier can bind a
//! Rekor inclusion proof to **this** signing event rather than trusting a
//! producer-supplied leaf hash.
//!
//! Fixture: `tests/vectors/fulcio-gha/rekor-hashedrekord-body.json` — the
//! exact canonical entry body of the real production Rekor entry
//! (logIndex 1767842880) whose cert is `leaf-cert.pem`. If
//! `build_hashedrekord_body`'s canonical-JSON + PEM + base64 reconstruction
//! is off by one byte, the byte-exact assertion (and the leaf-hash match)
//! fails — so a green test proves the reconstruction reproduces Rekor's
//! canonicalization on real data, not a guess.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use base64::Engine as _;
use cairn_sigstore_verify::{build_hashedrekord_body, hashedrekord_leaf_hash};
use sha2::{Digest, Sha256};
use x509_parser::pem::Pem;

/// The exact canonical body of the real Rekor `hashedrekord` entry.
const REKOR_BODY: &[u8] = include_bytes!("vectors/fulcio-gha/rekor-hashedrekord-body.json");
/// The signing leaf cert (byte-identical to the cert inside the body).
const LEAF_PEM: &str = include_str!("vectors/fulcio-gha/leaf-cert.pem");

fn leaf_der() -> Vec<u8> {
    Pem::iter_from_buffer(LEAF_PEM.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .contents
}

fn hex_decode_32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "sha256 hex is 64 chars");
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[test]
fn reconstructs_real_rekor_hashedrekord_body_byte_exact() {
    // Extract the entry's components from the real canonical body.
    let v: serde_json::Value = serde_json::from_slice(REKOR_BODY).unwrap();
    let artifact_hex = v["spec"]["data"]["hash"]["value"].as_str().unwrap();
    let sig_b64 = v["spec"]["signature"]["content"].as_str().unwrap();

    let artifact = hex_decode_32(artifact_hex);
    let sig_der = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .unwrap();
    let cert_der = leaf_der();

    // Reconstruct from components and demand byte-exact equality with the
    // real Rekor canonical body — proves the JSON canonicalization + PEM
    // re-encode + base64 all match Rekor's.
    let rebuilt = build_hashedrekord_body(&artifact, &sig_der, &cert_der);
    assert_eq!(
        rebuilt, REKOR_BODY,
        "reconstructed hashedrekord body must byte-match the real Rekor entry"
    );

    // And the leaf hash the verifier computes must equal SHA-256(0x00 ||
    // body) — the value a real inclusion proof proves is logged.
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(REKOR_BODY);
    let expected_leaf: [u8; 32] = h.finalize().into();
    assert_eq!(
        hashedrekord_leaf_hash(&artifact, &sig_der, &cert_der),
        expected_leaf,
        "reconstructed leaf hash must match the real entry's"
    );
}

#[test]
fn binding_changes_when_any_component_changes() {
    let v: serde_json::Value = serde_json::from_slice(REKOR_BODY).unwrap();
    let artifact = hex_decode_32(v["spec"]["data"]["hash"]["value"].as_str().unwrap());
    let sig_der = base64::engine::general_purpose::STANDARD
        .decode(v["spec"]["signature"]["content"].as_str().unwrap())
        .unwrap();
    let cert_der = leaf_der();
    let base = hashedrekord_leaf_hash(&artifact, &sig_der, &cert_der);

    // A different artifact hash (a tampered manifest) -> different leaf.
    let mut other_artifact = artifact;
    other_artifact[0] ^= 0xFF;
    assert_ne!(
        hashedrekord_leaf_hash(&other_artifact, &sig_der, &cert_der),
        base
    );

    // A different signature -> different leaf (fresh-decoded, then flipped).
    let mut other_sig = base64::engine::general_purpose::STANDARD
        .decode(v["spec"]["signature"]["content"].as_str().unwrap())
        .unwrap();
    other_sig[10] ^= 0xFF;
    assert_ne!(
        hashedrekord_leaf_hash(&artifact, &other_sig, &cert_der),
        base
    );

    // A different cert -> different leaf (binds the signing identity).
    let mut other_cert = leaf_der();
    let n = other_cert.len();
    other_cert[n - 50] ^= 0xFF;
    assert_ne!(
        hashedrekord_leaf_hash(&artifact, &sig_der, &other_cert),
        base
    );
}
