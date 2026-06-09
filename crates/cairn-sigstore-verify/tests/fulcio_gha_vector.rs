// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Phase-2 (D0042 §6.4): prove the Fulcio **SAN-URI** CI-workflow identity
//! match against a **real** GitHub Actions keyless certificate from the
//! production Sigstore log — the identity model Cairn's own CI releases
//! will use (D0042 §2), not the developer-email model.
//!
//! The fixtures (`tests/vectors/fulcio-gha/`) are a genuine keyless
//! certificate captured from the **production** Rekor transparency log
//! (`rekor.sigstore.dev`; see that dir's README for the log index +
//! provenance), plus the production Fulcio trust chain it was issued
//! under:
//!
//! - `leaf-cert.pem` — a real GitHub Actions keyless leaf: an ECDSA P-256
//!   key, **no email SAN**, instead a SAN
//!   `uniformResourceIdentifier` workflow identity
//!   (`https://github.com/chainguard-dev/mono/.github/workflows/…@REF`),
//!   the OIDC issuer `https://token.actions.githubusercontent.com`,
//!   `codeSigning` EKU, and an embedded SCT (proven separately).
//! - `fulcio-chain.pem` — the production Fulcio intermediate + root, so
//!   the leaf exercises the **3-level** chain walk
//!   (leaf → `sigstore-intermediate` → `sigstore` root), unlike the
//!   single-hop staging vector.
//!
//! A green [`validate_cert_chain_with_identity`] with
//! [`ExpectedIdentity::Uri`] here means the verifier accepts a real CI
//! keyless certificate end-to-end and pins the precise workflow + git ref;
//! the negatives confirm a mismatched URI, the email matcher (a URI cert
//! carries no `rfc822Name`), a mismatched issuer, and an out-of-window
//! signing time all reject. Pure offline: the leaf is a frozen, expired
//! 10-minute ephemeral, so the signing time is pinned inside its
//! historical window (no network, no wall-clock).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cairn_sigstore_verify::{
    ExpectedIdentity, SigstoreVerifyError, validate_cert_chain_with_identity,
};
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey as _;
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};

/// A real **production** GitHub Actions keyless leaf (ECDSA P-256).
const LEAF_PEM: &str = include_str!("vectors/fulcio-gha/leaf-cert.pem");
/// The production Fulcio intermediate + root the leaf chains to.
const FULCIO_CHAIN_PEM: &str = include_str!("vectors/fulcio-gha/fulcio-chain.pem");

/// The OIDC issuer the leaf's `1.3.6.1.4.1.57264.1.1` extension carries.
const GHA_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The real SAN `uniformResourceIdentifier` CI workflow identity.
const GHA_SAN_URI: &str =
    "https://github.com/chainguard-dev/mono/.github/workflows/.terraform.yaml@refs/tags/v0.2.278";
/// A signing time INSIDE the leaf's real validity window
/// (2026-06-09 15:49:05Z .. 15:59:05Z); the midpoint.
const SIGNING_TIME_IN_WINDOW: u64 = 1_781_020_445;

fn leaf_der() -> Vec<u8> {
    Pem::iter_from_buffer(LEAF_PEM.as_bytes())
        .next()
        .expect("leaf PEM has one block")
        .expect("leaf PEM parses")
        .contents
}

#[test]
fn accepts_real_gha_cert_with_uri_identity() {
    let leaf_der = leaf_der();
    let key = validate_cert_chain_with_identity(
        &leaf_der,
        FULCIO_CHAIN_PEM.as_bytes(),
        GHA_ISSUER,
        ExpectedIdentity::Uri(GHA_SAN_URI),
        SIGNING_TIME_IN_WINDOW,
    )
    .expect("a real GHA keyless cert with the pinned URI identity must validate");

    // The returned key must be EXACTLY the leaf's own SPKI key — the real
    // ephemeral signing key the detached manifest signature is checked
    // against. Confirms the 3-level chain walk surfaced the right leaf.
    let (_, leaf) = X509Certificate::from_der(&leaf_der).unwrap();
    let direct = VerifyingKey::from_public_key_der(leaf.public_key().raw)
        .expect("leaf SPKI is a valid P-256 key");
    assert_eq!(key, direct, "extracted key must equal the leaf's SPKI key");
}

#[test]
fn rejects_real_gha_cert_under_wrong_uri() {
    // The cert + chain are real and valid, but pinning a different workflow
    // URI must reject (the SAN binds the exact repo/workflow/ref).
    let result = validate_cert_chain_with_identity(
        &leaf_der(),
        FULCIO_CHAIN_PEM.as_bytes(),
        GHA_ISSUER,
        ExpectedIdentity::Uri(
            "https://github.com/attacker/evil/.github/workflows/x.yaml@refs/tags/v1",
        ),
        SIGNING_TIME_IN_WINDOW,
    );
    assert!(
        matches!(result, Err(SigstoreVerifyError::OidcIdentityMismatch)),
        "got {result:?}"
    );
}

#[test]
fn rejects_real_gha_cert_under_email_identity() {
    // A GHA workflow cert carries a SAN URI, NOT an rfc822Name. Pinning an
    // email identity (even one textually equal to the URI) must reject —
    // the email matcher must not spuriously match a URI SAN.
    let result = validate_cert_chain_with_identity(
        &leaf_der(),
        FULCIO_CHAIN_PEM.as_bytes(),
        GHA_ISSUER,
        ExpectedIdentity::Email(GHA_SAN_URI),
        SIGNING_TIME_IN_WINDOW,
    );
    assert!(
        matches!(result, Err(SigstoreVerifyError::OidcEmailMismatch)),
        "got {result:?}"
    );
}

#[test]
fn rejects_real_gha_cert_under_wrong_issuer() {
    let result = validate_cert_chain_with_identity(
        &leaf_der(),
        FULCIO_CHAIN_PEM.as_bytes(),
        "https://accounts.evil.example",
        ExpectedIdentity::Uri(GHA_SAN_URI),
        SIGNING_TIME_IN_WINDOW,
    );
    assert!(
        matches!(result, Err(SigstoreVerifyError::OidcIssuerMismatch)),
        "got {result:?}"
    );
}

#[test]
fn rejects_real_gha_cert_signed_after_expiry() {
    // A signing time after the leaf's real ~10-minute window must reject.
    let result = validate_cert_chain_with_identity(
        &leaf_der(),
        FULCIO_CHAIN_PEM.as_bytes(),
        GHA_ISSUER,
        ExpectedIdentity::Uri(GHA_SAN_URI),
        2_000_000_000,
    );
    assert!(
        matches!(
            result,
            Err(SigstoreVerifyError::FulcioCertExpiredAtSigningTime)
        ),
        "got {result:?}"
    );
}
