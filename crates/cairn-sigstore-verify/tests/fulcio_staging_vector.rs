// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Phase-2 "2a" (D0042 §7): prove the Fulcio path-validator + P-256 key
//! extraction against a **real** Sigstore staging leaf certificate, not a
//! synthetic rcgen fixture.
//!
//! The fixtures (`tests/vectors/fulcio-staging/`) are a real keyless
//! signing certificate captured from the Sigstore **staging** Fulcio CA
//! (see that dir's README for provenance), plus its issuing trust bundle:
//!
//! - `leaf-cert.pem` — a genuine Fulcio ephemeral leaf: an ECDSA **P-256**
//!   key, SAN `email:kleung@chainguard.dev`, the OIDC-issuer extension
//!   (`1.3.6.1.4.1.57264.1.1` = `google-sigstore-prod`), `digitalSignature`
//!   `KeyUsage` + `codeSigning` `ExtendedKeyUsage`, `CA:FALSE`, and a real
//!   ~10-minute validity window (2022-04-21 18:43:37Z .. 18:53:36Z).
//! - `root-chain.pem` — the staging Fulcio trust bundle the leaf chains to.
//!
//! A green [`validate_cert_chain`] here means the verifier accepts a
//! **real, attacker-unforgeable** Fulcio certificate end-to-end — the
//! chain signature (ring), the validity window, the OIDC issuer + email
//! pins, the RFC 5280 leaf constraints (D0041 §6.1), AND the B-model P-256
//! `SubjectPublicKeyInfo` extraction (D0042 §3) — and returns exactly the
//! leaf's own signing key. This is the producer-independent half of the
//! phase-2 proof: the synthetic `cairn-release` round-trip shows the
//! verifier accepts what the project's producer emits; this shows the same
//! validator accepts what the **real** Fulcio CA emits.
//!
//! Pure offline: the leaf is a frozen, already-expired certificate, so the
//! signing time is pinned inside its historical window — no network and no
//! wall-clock dependency (CI-safe).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cairn_sigstore_verify::{SigstoreVerifyError, validate_cert_chain};
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey as _;
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};

/// A real Sigstore **staging** Fulcio leaf (ECDSA P-256, keyless).
const LEAF_PEM: &str = include_str!("vectors/fulcio-staging/leaf-cert.pem");
/// The staging Fulcio trust bundle the leaf chains to.
const ROOT_CHAIN_PEM: &str = include_str!("vectors/fulcio-staging/root-chain.pem");

/// The real OIDC-issuer value the leaf's `1.3.6.1.4.1.57264.1.1`
/// extension carries.
const STAGING_ISSUER: &str = "google-sigstore-prod";
/// The real SAN `rfc822Name` the leaf carries.
const STAGING_EMAIL: &str = "kleung@chainguard.dev";
/// A signing time INSIDE the leaf's real validity window
/// (2022-04-21 18:43:37Z .. 18:53:36Z); the midpoint.
const SIGNING_TIME_IN_WINDOW: u64 = 1_650_566_916;

/// Decode the leaf PEM into the DER bytes `validate_cert_chain` consumes.
fn leaf_der() -> Vec<u8> {
    Pem::iter_from_buffer(LEAF_PEM.as_bytes())
        .next()
        .expect("leaf PEM has one block")
        .expect("leaf PEM parses")
        .contents
}

#[test]
fn extracts_p256_key_from_real_staging_fulcio_leaf() {
    let leaf_der = leaf_der();
    let key = validate_cert_chain(
        &leaf_der,
        ROOT_CHAIN_PEM.as_bytes(),
        STAGING_ISSUER,
        STAGING_EMAIL,
        SIGNING_TIME_IN_WINDOW,
    )
    .expect("the real staging Fulcio leaf must validate + extract its P-256 key");

    // The returned key must be EXACTLY the leaf's own `SubjectPublicKeyInfo`
    // key, parsed independently — proving `validate_cert_chain` surfaces the
    // real ephemeral signing key (which the detached manifest signature is
    // later checked against), not some placeholder.
    let (_, leaf) = X509Certificate::from_der(&leaf_der).unwrap();
    let direct = VerifyingKey::from_public_key_der(leaf.public_key().raw)
        .expect("leaf SPKI is a valid P-256 key");
    assert_eq!(key, direct, "extracted key must equal the leaf's SPKI key");
}

#[test]
fn rejects_real_leaf_under_wrong_email_pin() {
    // The cert is real and the chain is valid, but pinning a different
    // developer email must reject (the SAN binds kleung@chainguard.dev).
    let result = validate_cert_chain(
        &leaf_der(),
        ROOT_CHAIN_PEM.as_bytes(),
        STAGING_ISSUER,
        "attacker@evil.example",
        SIGNING_TIME_IN_WINDOW,
    );
    assert!(
        matches!(result, Err(SigstoreVerifyError::OidcEmailMismatch)),
        "got {result:?}"
    );
}

#[test]
fn rejects_real_leaf_under_wrong_issuer_pin() {
    // Pinning a different OIDC issuer than the cert's 1.1 extension carries
    // must reject.
    let result = validate_cert_chain(
        &leaf_der(),
        ROOT_CHAIN_PEM.as_bytes(),
        "https://evil.example.org",
        STAGING_EMAIL,
        SIGNING_TIME_IN_WINDOW,
    );
    assert!(
        matches!(result, Err(SigstoreVerifyError::OidcIssuerMismatch)),
        "got {result:?}"
    );
}

#[test]
fn rejects_real_leaf_signed_after_expiry() {
    // A signing time AFTER the leaf's real ~10-minute window (here: 2023,
    // long past the 2022 expiry) must reject — Fulcio leaves are short-
    // lived, so the Rekor-attested signing time, not "now", is what gates.
    let result = validate_cert_chain(
        &leaf_der(),
        ROOT_CHAIN_PEM.as_bytes(),
        STAGING_ISSUER,
        STAGING_EMAIL,
        1_700_000_000,
    );
    assert!(
        matches!(
            result,
            Err(SigstoreVerifyError::FulcioCertExpiredAtSigningTime)
        ),
        "got {result:?}"
    );
}

#[test]
fn rejects_real_leaf_signed_before_validity() {
    // A signing time BEFORE the leaf's notBefore (here: 2020) must reject.
    let result = validate_cert_chain(
        &leaf_der(),
        ROOT_CHAIN_PEM.as_bytes(),
        STAGING_ISSUER,
        STAGING_EMAIL,
        1_600_000_000,
    );
    assert!(
        matches!(
            result,
            Err(SigstoreVerifyError::FulcioCertExpiredAtSigningTime)
        ),
        "got {result:?}"
    );
}
