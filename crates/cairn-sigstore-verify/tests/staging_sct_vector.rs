// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Phase-2 (D0042 §5/§6.5): prove embedded **SCT** verification against a
//! **real Sigstore *staging*** Fulcio certificate + the matching **staging**
//! CT-log key — the same-environment staging counterpart to the production
//! GHA proof in `sct_vector.rs`, closing the "no staging CT-log key" gap.
//!
//! Why this matters beyond `sct_vector.rs`: that test proves the RFC 6962
//! precert reconstruction against the *production* CT log. This one proves
//! the **staging** half — a real staging Fulcio leaf, its embedded SCT, and
//! the staging CT log's key, all from `sigstage` — so a staging-targeted
//! build (D0042 phase 2) has an attacker-unforgeable SCT proof in its own
//! environment, not a production stand-in.
//!
//! Fixtures (`tests/vectors/fulcio-staging-sct/`, captured 2026-06-09 from
//! public staging Rekor `rekor.sigstage.dev` global logIndex 54783963, a
//! `hashedrekord` whose cert is a genuine staging Fulcio leaf):
//! - `leaf-cert.pem` — a real staging Fulcio **leaf** (email SAN
//!   `sigstore-staging-prometheus-sa@…gserviceaccount.com`, OIDC issuer
//!   `accounts.google.com`), embedding **one SCT** whose CT-log id
//!   `3e607153…a6b6` is the staging CT log active from 2026-01-14.
//! - `ctlog-pubkey.pem` — that staging CT log's ECDSA-P256 key, extracted
//!   from the staging `trusted_root.json`; `SHA-256(SPKI)` equals the SCT's
//!   log id (verified at capture).
//!
//! The **issuer** is the staging Fulcio intermediate, reused from
//! `tests/vectors/fulcio-staging/root-chain.pem` (its SKI equals the leaf's
//! AKI — staging Fulcio has not rotated its intermediate since 2022). Pure
//! offline (no network, no clock): the staging CT log's real signature over
//! the reconstructed precert is a frozen cryptographic fact.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cairn_sigstore_verify::{SigstoreVerifyError, verify_embedded_sct};
use x509_parser::pem::Pem;

const LEAF_PEM: &str = include_str!("vectors/fulcio-staging-sct/leaf-cert.pem");
const CTLOG_PUBKEY_PEM: &str = include_str!("vectors/fulcio-staging-sct/ctlog-pubkey.pem");
/// The staging Fulcio chain (intermediate = block 0, root = block 1); the
/// intermediate is this leaf's issuer / SCT precert issuer.
const STAGING_CHAIN_PEM: &str = include_str!("vectors/fulcio-staging/root-chain.pem");
/// The PRODUCTION CT-log key (a different log) — used to prove the staging
/// proof is environment-specific (log-id mismatch must reject).
const PROD_CTLOG_PUBKEY_PEM: &str = include_str!("vectors/fulcio-gha/ctlog-pubkey.pem");

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
/// The staging Fulcio intermediate (chain block 0) — issues staging precerts.
fn issuer_der() -> Vec<u8> {
    nth_der(STAGING_CHAIN_PEM, 0)
}
fn ctlog_pubkey_der() -> Vec<u8> {
    nth_der(CTLOG_PUBKEY_PEM, 0)
}

#[test]
fn verifies_real_staging_embedded_sct() {
    // THE proof: the real staging CT log's signature over the reconstructed
    // precert verifies under the pinned staging CT-log key. Same-environment
    // (staging leaf + staging intermediate + staging CT key) — the staging
    // counterpart to `sct_vector.rs`'s production proof.
    verify_embedded_sct(&leaf_der(), &issuer_der(), &ctlog_pubkey_der()).expect(
        "a real staging Fulcio leaf's embedded SCT must verify against the staging CT-log key",
    );
}

#[test]
fn rejects_staging_sct_under_wrong_ctlog_key() {
    // A freshly-generated P-256 key is not the staging CT log: its log id
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
fn rejects_staging_sct_under_production_ctlog_key() {
    // Cross-environment guard: the PRODUCTION CT-log key is a different log
    // (different log id), so it must NOT verify the staging leaf's SCT —
    // proving the staging proof binds the staging log specifically, not "any
    // valid CT key".
    let result = verify_embedded_sct(
        &leaf_der(),
        &issuer_der(),
        &nth_der(PROD_CTLOG_PUBKEY_PEM, 0),
    );
    assert!(
        matches!(result, Err(SigstoreVerifyError::SctVerifyFailed)),
        "got {result:?}"
    );
}

#[test]
fn rejects_staging_sct_with_wrong_issuer() {
    // Passing the staging ROOT (chain block 1), not the precert's actual
    // intermediate issuer, gives the wrong issuer_key_hash, so the
    // reconstructed signed blob differs and the real signature no longer
    // verifies — proving the issuer is bound into what the CT log signed.
    let root_der = nth_der(STAGING_CHAIN_PEM, 1);
    let result = verify_embedded_sct(&leaf_der(), &root_der, &ctlog_pubkey_der());
    assert!(
        matches!(result, Err(SigstoreVerifyError::SctVerifyFailed)),
        "got {result:?}"
    );
}
