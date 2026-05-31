// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Fulcio CA trust-root validation per D0024 §2.
//!
//! [`validate_cert_chain`] validates a Fulcio-issued signing
//! certificate against a pinned Fulcio trust bundle and returns the
//! developer's Ed25519 public key for the manifest-signature check
//! (D0024 §4). It performs four checks:
//!
//! 1. **Chain to the pinned root.** Walk leaf → issuer → … → a
//!    self-signed root contained in the pinned bundle, verifying each
//!    link's signature. Signature verification uses `x509-parser`'s
//!    `verify` feature, which is backed by `ring` (see the crate-level
//!    note + D0024 §6.5 revision: this is a deliberate, documented
//!    departure from the workspace pure-Rust discipline, because the
//!    Fulcio root is ECDSA P-384 and hand-rolling X.509 verification is
//!    the riskier choice).
//! 2. **Validity window.** The certificate must have been valid at the
//!    Rekor-attested signing time (D0024 §2.1) — Fulcio certs are
//!    short-lived, so the signing time, not "now", is what matters.
//! 3. **OIDC issuer pin.** The Fulcio issuer extension
//!    (OID `1.3.6.1.4.1.57264.1.1`) must equal the pinned issuer.
//! 4. **OIDC email pin.** A SAN `rfc822Name` must equal the pinned
//!    developer email.
//!
//! The returned key is the certificate's Ed25519 SubjectPublicKeyInfo
//! key — the developer's Sigstore signing key, which Cairn requires to
//! be Ed25519 so the manifest `COSE_Sign1` (Ed25519-only per
//! `cairn_envelope`) verifies against it.
//!
//! ## v1 path-validation scope
//!
//! v1 enforces signature-chain validity to a pinned self-signed root +
//! the validity window + the OIDC pins. It does NOT yet enforce the
//! full RFC 5280 path-validation constraint set (BasicConstraints CA
//! flag + path-length, KeyUsage `keyCertSign`, ExtendedKeyUsage,
//! NameConstraints). For the pinned-root threat model (the root is a
//! coordinated release-bundled trust anchor, not a public web PKI), the
//! signature chain + the OIDC-identity pins are the load-bearing
//! checks; the remaining constraint enforcement is a hardening
//! follow-up tracked against D0024 §2.

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, VerifyingKey};
use x509_parser::der_parser::oid;
use x509_parser::oid_registry::OID_SIG_ED25519;
use x509_parser::prelude::{FromDer, GeneralName, Pem, X509Certificate};

use crate::error::SigstoreVerifyError;

/// Maximum certificate-chain depth (leaf + intermediates + root). Bounds
/// the chain walk so a malformed/cyclic bundle cannot loop forever.
const MAX_CHAIN_DEPTH: usize = 8;

/// Validate a Fulcio-issued signing certificate per D0024 §2 and return
/// the developer's Ed25519 signing key.
///
/// # Errors
///
/// - [`SigstoreVerifyError::FulcioChainInvalid`] — the cert or pinned
///   bundle did not parse, the chain did not build to a self-signed
///   root in the bundle, a link signature failed, or the leaf key is
///   not Ed25519.
/// - [`SigstoreVerifyError::FulcioCertExpiredAtSigningTime`] — the
///   Rekor-attested signing time falls outside the cert validity window.
/// - [`SigstoreVerifyError::OidcIssuerMismatch`] /
///   [`SigstoreVerifyError::OidcEmailMismatch`] — the cert's OIDC
///   claims do not match the pinned values.
pub fn validate_cert_chain(
    signing_cert_der: &[u8],
    pinned_root_pem: &[u8],
    expected_oidc_issuer: &str,
    expected_oidc_email: &str,
    rekor_signing_time_unix: u64,
) -> Result<VerifyingKey, SigstoreVerifyError> {
    let (_, leaf) = X509Certificate::from_der(signing_cert_der)
        .map_err(|_| SigstoreVerifyError::FulcioChainInvalid)?;

    // Parse the pinned trust bundle (root + any intermediates). Keep the
    // owned PEM blocks alive for the lifetime of the parsed certs.
    let pems: Vec<Pem> = Pem::iter_from_buffer(pinned_root_pem)
        .collect::<Result<_, _>>()
        .map_err(|_| SigstoreVerifyError::FulcioChainInvalid)?;
    let cas: Vec<X509Certificate> = pems
        .iter()
        .map(Pem::parse_x509)
        .collect::<Result<_, _>>()
        .map_err(|_| SigstoreVerifyError::FulcioChainInvalid)?;
    if cas.is_empty() {
        return Err(SigstoreVerifyError::FulcioChainInvalid);
    }

    // (1) Chain validation: walk leaf -> issuer -> ... -> self-signed
    // root in the bundle, verifying each link. The leaf is never
    // self-trusted; it must verify against a bundle CA.
    verify_chain_to_root(&leaf, &cas)?;

    // (2) Validity window: the cert must have been valid at the
    // Rekor-attested signing time.
    let signing_time = i64::try_from(rekor_signing_time_unix)
        .map_err(|_| SigstoreVerifyError::FulcioCertExpiredAtSigningTime)?;
    let not_before = leaf.validity().not_before.timestamp();
    let not_after = leaf.validity().not_after.timestamp();
    if signing_time < not_before || signing_time > not_after {
        return Err(SigstoreVerifyError::FulcioCertExpiredAtSigningTime);
    }

    // (3) OIDC issuer pin (Fulcio extension OID 1.3.6.1.4.1.57264.1.1,
    // whose value is the raw issuer URL string).
    let issuer_oid = oid!(1.3.6.1.4.1.57264.1.1);
    let issuer_ext = leaf
        .get_extension_unique(&issuer_oid)
        .map_err(|_| SigstoreVerifyError::FulcioChainInvalid)?
        .ok_or(SigstoreVerifyError::OidcIssuerMismatch)?;
    let cert_issuer = core::str::from_utf8(issuer_ext.value)
        .map_err(|_| SigstoreVerifyError::OidcIssuerMismatch)?;
    if cert_issuer != expected_oidc_issuer {
        return Err(SigstoreVerifyError::OidcIssuerMismatch);
    }

    // (4) OIDC email pin (SAN rfc822Name).
    if !san_has_email(&leaf, expected_oidc_email)? {
        return Err(SigstoreVerifyError::OidcEmailMismatch);
    }

    // Extract the Ed25519 signing key from the leaf SPKI.
    extract_ed25519_key(&leaf)
}

/// Walk the chain from `leaf` up to a self-signed root contained in
/// `cas`, verifying each link's signature. Returns `Ok(())` only if a
/// trusted self-signed root is reached.
fn verify_chain_to_root(
    leaf: &X509Certificate,
    cas: &[X509Certificate],
) -> Result<(), SigstoreVerifyError> {
    let mut current = leaf;
    for _ in 0..MAX_CHAIN_DEPTH {
        // Find the issuer cert in the pinned bundle.
        let issuer = cas
            .iter()
            .find(|ca| ca.subject() == current.issuer())
            .ok_or(SigstoreVerifyError::FulcioChainInvalid)?;
        // Verify the current cert's signature against the issuer's key
        // (ring-backed; handles the issuer's signature algorithm, e.g.
        // ECDSA P-384 for the Fulcio root).
        current
            .verify_signature(Some(issuer.public_key()))
            .map_err(|_| SigstoreVerifyError::FulcioChainInvalid)?;
        // The issuer is a pinned-bundle cert; if it is self-signed it is
        // the trust anchor and the chain is complete.
        if issuer.subject() == issuer.issuer() {
            return Ok(());
        }
        current = issuer;
    }
    Err(SigstoreVerifyError::FulcioChainInvalid)
}

/// Return `true` if the cert's SAN contains an `rfc822Name` equal to
/// `expected_email`.
fn san_has_email(
    cert: &X509Certificate,
    expected_email: &str,
) -> Result<bool, SigstoreVerifyError> {
    let san = cert
        .subject_alternative_name()
        .map_err(|_| SigstoreVerifyError::FulcioChainInvalid)?;
    let Some(san) = san else {
        return Ok(false);
    };
    for name in &san.value.general_names {
        if let GeneralName::RFC822Name(email) = name {
            if *email == expected_email {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Extract the Ed25519 public key from the cert's SubjectPublicKeyInfo.
fn extract_ed25519_key(cert: &X509Certificate) -> Result<VerifyingKey, SigstoreVerifyError> {
    let spki = cert.public_key();
    if spki.algorithm.algorithm != OID_SIG_ED25519 {
        return Err(SigstoreVerifyError::FulcioChainInvalid);
    }
    let key_bytes = spki.subject_public_key.data.as_ref();
    if key_bytes.len() != PUBLIC_KEY_LEN {
        return Err(SigstoreVerifyError::FulcioChainInvalid);
    }
    let mut arr = [0u8; PUBLIC_KEY_LEN];
    arr.copy_from_slice(key_bytes);
    VerifyingKey::from_bytes(&arr).map_err(|_| SigstoreVerifyError::FulcioChainInvalid)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, CustomExtension, DnType, IsCa, KeyPair,
        PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519, SanType, date_time_ymd,
    };

    const ISSUER: &str = "https://accounts.example.org";
    const EMAIL: &str = "maintainer@cairn-project.org";
    // A signing time inside the 2020-2030 leaf validity window used below.
    const SIGNING_TIME: u64 = 1_717_200_000; // ~2024-06

    /// A self-signed ECDSA P-384 CA (exercises ring's P-384 chain-sig
    /// verification — the Fulcio root is P-384).
    fn make_root() -> (Certificate, KeyPair) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "Test Fulcio Root");
        let cert = params.self_signed(&key).unwrap();
        (cert, key)
    }

    /// A leaf cert signed by `root`, carrying the Fulcio OIDC issuer
    /// extension + a SAN email, with the given key algorithm + validity.
    fn make_leaf(
        root: &Certificate,
        root_key: &KeyPair,
        issuer: &str,
        email: &str,
        alg: &'static rcgen::SignatureAlgorithm,
    ) -> Vec<u8> {
        let key = KeyPair::generate_for(alg).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2030, 1, 1);
        params
            .distinguished_name
            .push(DnType::CommonName, "sigstore");
        params.subject_alt_names = vec![SanType::Rfc822Name(email.try_into().unwrap())];
        // Fulcio OIDC issuer extension OID 1.3.6.1.4.1.57264.1.1; value
        // is the raw issuer URL string.
        params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 57264, 1, 1],
            issuer.as_bytes().to_vec(),
        )];
        let leaf = params.signed_by(&key, root, root_key).unwrap();
        leaf.der().as_ref().to_vec()
    }

    #[test]
    fn accepts_valid_chain_and_pins() {
        let (root, root_key) = make_root();
        let leaf = make_leaf(&root, &root_key, ISSUER, EMAIL, &PKCS_ED25519);
        let result = validate_cert_chain(&leaf, root.pem().as_bytes(), ISSUER, EMAIL, SIGNING_TIME);
        assert!(result.is_ok(), "valid chain must validate: {result:?}");
    }

    #[test]
    fn rejects_issuer_pin_mismatch() {
        let (root, root_key) = make_root();
        let leaf = make_leaf(&root, &root_key, ISSUER, EMAIL, &PKCS_ED25519);
        let result = validate_cert_chain(
            &leaf,
            root.pem().as_bytes(),
            "https://evil.example.org",
            EMAIL,
            SIGNING_TIME,
        );
        assert!(matches!(
            result,
            Err(SigstoreVerifyError::OidcIssuerMismatch)
        ));
    }

    #[test]
    fn rejects_email_pin_mismatch() {
        let (root, root_key) = make_root();
        let leaf = make_leaf(&root, &root_key, ISSUER, EMAIL, &PKCS_ED25519);
        let result = validate_cert_chain(
            &leaf,
            root.pem().as_bytes(),
            ISSUER,
            "attacker@evil.example.org",
            SIGNING_TIME,
        );
        assert!(matches!(
            result,
            Err(SigstoreVerifyError::OidcEmailMismatch)
        ));
    }

    #[test]
    fn rejects_signing_time_outside_validity() {
        let (root, root_key) = make_root();
        let leaf = make_leaf(&root, &root_key, ISSUER, EMAIL, &PKCS_ED25519);
        // ~2035, past the 2030 not_after.
        let result =
            validate_cert_chain(&leaf, root.pem().as_bytes(), ISSUER, EMAIL, 2_051_000_000);
        assert!(matches!(
            result,
            Err(SigstoreVerifyError::FulcioCertExpiredAtSigningTime)
        ));
    }

    #[test]
    fn rejects_leaf_signed_by_untrusted_root() {
        // Leaf signed by root A, but root B is pinned -> the leaf's issuer
        // is not in the trust bundle.
        let (root_a, key_a) = make_root();
        let (root_b, _key_b) = make_root();
        let leaf = make_leaf(&root_a, &key_a, ISSUER, EMAIL, &PKCS_ED25519);
        let result =
            validate_cert_chain(&leaf, root_b.pem().as_bytes(), ISSUER, EMAIL, SIGNING_TIME);
        assert!(matches!(
            result,
            Err(SigstoreVerifyError::FulcioChainInvalid)
        ));
    }

    #[test]
    fn rejects_non_ed25519_leaf_key() {
        // The chain + pins are valid, but the leaf binds a P-256 key,
        // which the Ed25519-only manifest path cannot use.
        let (root, root_key) = make_root();
        let leaf = make_leaf(&root, &root_key, ISSUER, EMAIL, &PKCS_ECDSA_P256_SHA256);
        let result = validate_cert_chain(&leaf, root.pem().as_bytes(), ISSUER, EMAIL, SIGNING_TIME);
        assert!(matches!(
            result,
            Err(SigstoreVerifyError::FulcioChainInvalid)
        ));
    }

    #[test]
    fn rejects_malformed_cert_der() {
        let (root, _root_key) = make_root();
        let result = validate_cert_chain(
            b"\xFF\x00not-a-cert",
            root.pem().as_bytes(),
            ISSUER,
            EMAIL,
            SIGNING_TIME,
        );
        assert!(matches!(
            result,
            Err(SigstoreVerifyError::FulcioChainInvalid)
        ));
    }
}
