// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Phase-2 (D0042 §6.5): prove embedded **SCT** verification against the
//! **real** CT-log signature on a genuine production GitHub Actions Fulcio
//! certificate — the CT-log-inclusion half of full Sigstore verification.
//!
//! This is the strongest possible correctness check for the precert
//! reconstruction (RFC 6962 §3.2): the production CT log signed over the
//! leaf's TBSCertificate-minus-the-SCT-extension, so if
//! [`verify_embedded_sct`]'s byte-surgery were wrong by a single byte, the
//! reconstructed blob's `SHA-256` would differ and the **real** CT log's
//! ECDSA-P256 signature would not verify. A green
//! `verifies_real_gha_embedded_sct` therefore proves the reconstruction is
//! byte-exact against real, attacker-unforgeable data — not merely that it
//! parses.
//!
//! Fixtures: `tests/vectors/fulcio-gha/` — the captured production GHA leaf
//! (embeds one SCT, CT-log ID `dd3d306a…`), the production Fulcio chain
//! (the `sigstore-intermediate` is the precert issuer), and the matching
//! production CT-log public key. Pure offline (no network, no clock).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cairn_sigstore_verify::{SigstoreVerifyError, verify_embedded_sct};
use x509_parser::pem::Pem;

const LEAF_PEM: &str = include_str!("vectors/fulcio-gha/leaf-cert.pem");
const FULCIO_CHAIN_PEM: &str = include_str!("vectors/fulcio-gha/fulcio-chain.pem");
const CTLOG_PUBKEY_PEM: &str = include_str!("vectors/fulcio-gha/ctlog-pubkey.pem");
/// The SCT-less developer-email staging leaf (for the `SctMissing` case).
const STAGING_LEAF_PEM: &str = include_str!("vectors/fulcio-staging/leaf-cert.pem");

/// Decode the `n`-th PEM block's DER bytes.
fn nth_der(pem: &str, n: usize) -> Vec<u8> {
    Pem::iter_from_buffer(pem.as_bytes())
        .nth(n)
        .expect("pem block present")
        .expect("pem block parses")
        .contents
}

fn leaf_der() -> Vec<u8> {
    nth_der(LEAF_PEM, 0)
}
/// The leaf's issuing CA — the Fulcio intermediate (first cert in the
/// chain), which signs precertificates directly.
fn issuer_der() -> Vec<u8> {
    nth_der(FULCIO_CHAIN_PEM, 0)
}
fn ctlog_pubkey_der() -> Vec<u8> {
    nth_der(CTLOG_PUBKEY_PEM, 0)
}

#[test]
fn verifies_real_gha_embedded_sct() {
    // THE proof: the real production CT log's signature over the
    // reconstructed precert verifies under the pinned CT-log key.
    verify_embedded_sct(&leaf_der(), &issuer_der(), &ctlog_pubkey_der())
        .expect("a real GHA leaf's embedded SCT must verify against the real pinned CT-log key");
}

#[test]
fn rejects_sct_under_wrong_ctlog_key() {
    // A freshly-generated P-256 key is not the pinned CT log: its log ID
    // won't match the SCT's, so nothing verifies.
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey as _;
    use rand_core::OsRng;

    let wrong = *SigningKey::random(&mut OsRng).verifying_key();
    let wrong_der = wrong.to_public_key_der().unwrap();
    let result = verify_embedded_sct(&leaf_der(), &issuer_der(), wrong_der.as_bytes());
    assert!(
        matches!(result, Err(SigstoreVerifyError::SctVerifyFailed)),
        "got {result:?}"
    );
}

#[test]
fn rejects_sct_with_wrong_issuer() {
    // Passing the ROOT (not the precert's actual intermediate issuer) gives
    // the wrong issuer_key_hash, so the reconstructed signed blob differs
    // and the real signature no longer verifies — proving the issuer is
    // bound into what the CT log signed.
    let root_der = nth_der(FULCIO_CHAIN_PEM, 1);
    let result = verify_embedded_sct(&leaf_der(), &root_der, &ctlog_pubkey_der());
    assert!(
        matches!(result, Err(SigstoreVerifyError::SctVerifyFailed)),
        "got {result:?}"
    );
}

#[test]
fn reports_sct_missing_on_a_cert_without_one() {
    // The 2022 staging developer-email leaf embeds no SCT extension.
    let staging_leaf = nth_der(STAGING_LEAF_PEM, 0);
    let result = verify_embedded_sct(&staging_leaf, &issuer_der(), &ctlog_pubkey_der());
    assert!(
        matches!(result, Err(SigstoreVerifyError::SctMissing)),
        "got {result:?}"
    );
}

#[test]
fn malformed_inputs_fail_closed_without_panic() {
    // The SCT path parses an ATTACKER-CONTROLLED cert (the bundle's
    // `fulcio_cert_der`) with a hand-rolled DER walk, so every malformed
    // input must return an error, never panic and never spuriously accept.
    let leaf = leaf_der();
    let issuer = issuer_der();
    let ctlog = ctlog_pubkey_der();

    // Garbage / truncated / empty leaf DER.
    assert!(verify_embedded_sct(b"\xFF\x00not-a-cert", &issuer, &ctlog).is_err());
    let mut truncated = leaf.clone();
    truncated.truncate(40);
    assert!(verify_embedded_sct(&truncated, &issuer, &ctlog).is_err());
    assert!(verify_embedded_sct(&[], &[], &[]).is_err());

    // A real SCT-bearing leaf, but a garbage CT-log key (not a P-256 SPKI).
    assert!(verify_embedded_sct(&leaf, &issuer, b"not-a-key").is_err());
    // Real leaf + real CT key, but a garbage issuer cert (no SPKI to hash).
    assert!(verify_embedded_sct(&leaf, b"\x00garbage", &ctlog).is_err());
}
