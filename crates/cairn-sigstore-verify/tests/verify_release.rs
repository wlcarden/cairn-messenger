// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! End-to-end `verify_release` orchestration harness per D0024 §6.
//!
//! Builds a fully-valid offline [`ReleaseBundle`] — a Fulcio cert chain
//! (P-384 test root → Ed25519 leaf binding the developer key), a
//! `COSE_Sign1` manifest signed by that same developer key, and a valid
//! RFC 6962 + C2SP/ECDSA-P256 Rekor bundle — and drives
//! `SigstoreVerifier::verify_release` through the happy path plus
//! per-layer failure injections.
//!
//! The key trick: one Ed25519 key plays both roles. It is generated as
//! an rcgen `KeyPair` (so rcgen issues the Fulcio leaf binding it), and
//! its seed is lifted from the rcgen PKCS#8 into a cairn-crypto
//! `SigningKey` (so it signs the manifest). Both libraries derive the
//! same RFC 8032 public key from the seed, so the key the cert binds is
//! exactly the key that signs the manifest.
//!
//! The §5 Sigsum-anchored-release-log step is NOT exercised here: it is
//! gated on `cairn_sigsum_client::verify_inclusion` (still stubbed), and
//! `verify_release` intentionally does not invoke it yet.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;

use base64::Engine as _;
use cairn_crypto::ed25519::SigningKey;
use cairn_envelope::cose_sign1::Sign1Builder;
use cairn_sigstore_verify::manifest::RELEASE_MANIFEST_AAD;
use cairn_sigstore_verify::{
    ArtifactHash, RekorBundle, ReleaseBundle, ReleaseManifest, SigstoreVerifier,
    SigstoreVerifierConfig, SigstoreVerifyError,
};
use cairn_sigsum_client::{RetryBudget, SigsumClient, SigsumClientConfig, parse_witness_pool};
use cairn_storage::Storage;
use cairn_storage::key_provider::testing::InMemoryKeyProvider;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p256::pkcs8::{EncodePublicKey as _, LineEnding};
use rand_core::OsRng;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DnType, IsCa, KeyPair,
    PKCS_ECDSA_P384_SHA384, PKCS_ED25519, SanType, date_time_ymd,
};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

const ISSUER: &str = "https://accounts.example.org";
const EMAIL: &str = "maintainer@cairn-project.org";
const SIGNING_TIME: u64 = 1_717_200_000; // ~2024-06, inside the 2020-2030 leaf window
const PRIOR_HASH: [u8; 32] = [0x55u8; 32];

// ===================================================================
// RFC 6962 Merkle helpers (for the Rekor bundle)
// ===================================================================

fn sha256_prefixed(prefix: u8, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([prefix]);
    for p in parts {
        hasher.update(p);
    }
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn leaf_hash(data: &[u8]) -> [u8; 32] {
    sha256_prefixed(0x00, &[data])
}

fn hash_children(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    sha256_prefixed(0x01, &[l, r])
}

const fn largest_pow2_below(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => panic!("empty tree not used"),
        1 => leaves[0],
        n => {
            let k = largest_pow2_below(n);
            let (l, r) = leaves.split_at(k);
            hash_children(&mth(l), &mth(r))
        }
    }
}

fn audit_path(index: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return vec![];
    }
    let k = largest_pow2_below(leaves.len());
    let (l, r) = leaves.split_at(k);
    if index < k {
        let mut p = audit_path(index, l);
        p.push(mth(r));
        p
    } else {
        let mut p = audit_path(index - k, r);
        p.push(mth(l));
        p
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A valid Rekor bundle (5-leaf tree, target index 2) with a C2SP
/// checkpoint signed by a fresh P-256 key. Returns the bundle + the
/// pinned Rekor pubkey PEM.
fn make_rekor_bundle() -> (RekorBundle, Vec<u8>) {
    let sk = P256SigningKey::random(&mut OsRng);
    let leaves: Vec<[u8; 32]> = (0..5)
        .map(|i| leaf_hash(format!("rekor-leaf-{i}").as_bytes()))
        .collect();
    let root = mth(&leaves);
    let proof = audit_path(2, &leaves);
    let note = format!("rekor.example/test\n5\n{}\n", b64(&root));
    let sig: P256Signature = sk.sign(note.as_bytes());
    let pem = P256VerifyingKey::from(&sk)
        .to_public_key_pem(LineEnding::LF)
        .unwrap()
        .into_bytes();
    let bundle = RekorBundle {
        leaf_hash: leaves[2],
        leaf_index: 2,
        proof_nodes: proof,
        checkpoint_note: note.into_bytes(),
        checkpoint_signature: sig.to_der().as_bytes().to_vec(),
    };
    (bundle, pem)
}

// ===================================================================
// Fulcio cert helpers
// ===================================================================

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

/// Generate a developer Ed25519 key as both an rcgen `KeyPair` (to be
/// bound into the Fulcio leaf cert) and the matching cairn-crypto
/// `SigningKey` (to sign the manifest). The seed is lifted out of the
/// rcgen PKCS#8 via the standard Ed25519 privateKey marker
/// (`04 22 04 20 || seed[32]`); both libraries derive the same RFC 8032
/// public key from it (the happy-path test confirms the match).
fn make_dev_key() -> (KeyPair, SigningKey) {
    let kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let pkcs8 = kp.serialize_der();
    let marker = [0x04u8, 0x22, 0x04, 0x20];
    let pos = pkcs8
        .windows(4)
        .position(|w| w == marker)
        .expect("ed25519 pkcs8 privateKey marker");
    let seed: [u8; 32] = pkcs8[pos + 4..pos + 36].try_into().unwrap();
    let sk = SigningKey::from_seed(&Zeroizing::new(seed));
    (kp, sk)
}

/// A leaf cert binding `dev_kp`'s Ed25519 key, signed by `root`,
/// carrying the Fulcio OIDC issuer extension + SAN email.
fn make_leaf(
    root: &Certificate,
    root_key: &KeyPair,
    dev_kp: &KeyPair,
    issuer: &str,
    email: &str,
) -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::NoCa;
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2030, 1, 1);
    params
        .distinguished_name
        .push(DnType::CommonName, "sigstore");
    params.subject_alt_names = vec![SanType::Rfc822Name(email.try_into().unwrap())];
    params.custom_extensions = vec![CustomExtension::from_oid_content(
        &[1, 3, 6, 1, 4, 1, 57264, 1, 1],
        issuer.as_bytes().to_vec(),
    )];
    let leaf = params.signed_by(dev_kp, root, root_key).unwrap();
    leaf.der().as_ref().to_vec()
}

// ===================================================================
// Manifest + verifier construction
// ===================================================================

fn signed_manifest_envelope(dev_sk: &SigningKey, prior: Vec<u8>) -> (Vec<u8>, ReleaseManifest) {
    let manifest = ReleaseManifest {
        version: "1.0.0-pilot".to_string(),
        artifact_sha256: vec![ArtifactHash {
            name: "cairn-1.0.0.apk".to_string(),
            sha256: [0x01; 32],
        }],
        build_provenance_sha256: [0x02; 32],
        release_timestamp: SIGNING_TIME,
        prior_release_hash: prior,
    };
    let payload = manifest.to_canonical_cbor().unwrap();
    let envelope = Sign1Builder::new()
        .with_payload(payload)
        .with_external_aad(RELEASE_MANIFEST_AAD.to_vec())
        .finalize(dev_sk)
        .unwrap()
        .encode(false)
        .unwrap();
    (envelope, manifest)
}

fn make_witness_pool_toml(count: usize) -> String {
    let mut rng = OsRng;
    let mut out = String::new();
    for i in 0..count {
        let sk = SigningKey::generate(&mut rng);
        let pubkey_hex = sk
            .verifying_key()
            .to_bytes()
            .iter()
            .fold(String::new(), |mut acc, b| {
                use std::fmt::Write as _;
                let _ = write!(&mut acc, "{b:02x}");
                acc
            });
        out.push_str(&format!(
            "[[witness]]\nname = \"W{i}\"\npubkey_hex = \"{pubkey_hex}\"\nurl = \"https://w-{i}.example.org\"\n\n"
        ));
    }
    out
}

fn make_sigsum_client() -> SigsumClient {
    let provider = InMemoryKeyProvider::new();
    let passphrase = Zeroizing::new(b"test passphrase".to_vec());
    let storage = Arc::new(Storage::open_in_memory(&provider, &passphrase).unwrap());
    let pool = parse_witness_pool(&make_witness_pool_toml(3)).unwrap();
    let log_pubkey = SigningKey::generate(&mut OsRng).verifying_key();
    let config = SigsumClientConfig {
        log_url: Url::parse("https://log.example.org").unwrap(),
        log_pubkey,
        witness_pool: pool,
        default_retry_budget: RetryBudget::default(),
    };
    SigsumClient::new(config, storage).unwrap()
}

fn make_verifier(
    fulcio_root_pem: Vec<u8>,
    rekor_pubkey_pem: Vec<u8>,
    issuer: &str,
) -> SigstoreVerifier {
    let config = SigstoreVerifierConfig {
        fulcio_root_pem,
        rekor_pubkey_pem,
        expected_oidc_issuer: issuer.to_string(),
        expected_oidc_email: EMAIL.to_string(),
        sigsum_client: make_sigsum_client(),
        default_retry_budget: RetryBudget::default(),
    };
    SigstoreVerifier::new(config).unwrap()
}

/// Everything needed to drive `verify_release`, all mutually consistent.
struct Fixture {
    bundle: ReleaseBundle,
    fulcio_root_pem: Vec<u8>,
    rekor_pem: Vec<u8>,
}

/// Build a fully-valid release bundle: dev key → cert → manifest →
/// Rekor bundle, all consistent.
fn valid_fixture() -> Fixture {
    let (dev_kp, dev_sk) = make_dev_key();
    let (root, root_key) = make_root();
    let leaf_der = make_leaf(&root, &root_key, &dev_kp, ISSUER, EMAIL);
    let (envelope, _manifest) = signed_manifest_envelope(&dev_sk, PRIOR_HASH.to_vec());
    let (rekor_bundle, rekor_pem) = make_rekor_bundle();
    let bundle = ReleaseBundle {
        manifest_envelope_bytes: envelope,
        fulcio_cert_der: leaf_der,
        rekor_bundle,
        rekor_signing_time_unix: SIGNING_TIME,
    };
    Fixture {
        bundle,
        fulcio_root_pem: root.pem().into_bytes(),
        rekor_pem,
    }
}

// ===================================================================
// Tests
// ===================================================================

#[tokio::test]
async fn accepts_a_fully_valid_release() {
    let fx = valid_fixture();
    let verifier = make_verifier(fx.fulcio_root_pem, fx.rekor_pem, ISSUER);
    let outcome = verifier
        .verify_release(&fx.bundle, Some(PRIOR_HASH))
        .await
        .expect("a fully valid release must verify");
    assert_eq!(outcome.manifest.version, "1.0.0-pilot");
    assert_eq!(outcome.manifest.artifact_sha256.len(), 1);
}

#[tokio::test]
async fn accepts_with_no_expected_predecessor() {
    let fx = valid_fixture();
    let verifier = make_verifier(fx.fulcio_root_pem, fx.rekor_pem, ISSUER);
    // None skips the rollback check (e.g. the caller has no stored
    // predecessor yet).
    assert!(verifier.verify_release(&fx.bundle, None).await.is_ok());
}

#[tokio::test]
async fn rejects_prior_hash_mismatch() {
    let fx = valid_fixture();
    let verifier = make_verifier(fx.fulcio_root_pem, fx.rekor_pem, ISSUER);
    let wrong_predecessor = [0x66u8; 32];
    let err = verifier
        .verify_release(&fx.bundle, Some(wrong_predecessor))
        .await
        .unwrap_err();
    assert!(
        matches!(err, SigstoreVerifyError::ManifestPriorHashMismatch),
        "got {err:?}"
    );
}

#[tokio::test]
async fn rejects_manifest_signed_by_wrong_key() {
    // The cert binds the dev key, but the manifest is signed by a
    // DIFFERENT key -> the COSE_Sign1 signature fails against the
    // Fulcio-bound key.
    let (dev_kp, _dev_sk) = make_dev_key();
    let (root, root_key) = make_root();
    let leaf_der = make_leaf(&root, &root_key, &dev_kp, ISSUER, EMAIL);

    let imposter_sk = SigningKey::generate(&mut OsRng);
    let (envelope, _m) = signed_manifest_envelope(&imposter_sk, PRIOR_HASH.to_vec());
    let (rekor_bundle, rekor_pem) = make_rekor_bundle();
    let bundle = ReleaseBundle {
        manifest_envelope_bytes: envelope,
        fulcio_cert_der: leaf_der,
        rekor_bundle,
        rekor_signing_time_unix: SIGNING_TIME,
    };

    let verifier = make_verifier(root.pem().into_bytes(), rekor_pem, ISSUER);
    let err = verifier.verify_release(&bundle, None).await.unwrap_err();
    assert!(
        matches!(err, SigstoreVerifyError::ManifestSignatureVerifyFailed),
        "got {err:?}"
    );
}

#[tokio::test]
async fn rejects_oidc_issuer_pin_mismatch() {
    let fx = valid_fixture();
    // Verifier pins a different issuer than the cert carries.
    let verifier = make_verifier(fx.fulcio_root_pem, fx.rekor_pem, "https://evil.example.org");
    let err = verifier.verify_release(&fx.bundle, None).await.unwrap_err();
    assert!(
        matches!(err, SigstoreVerifyError::OidcIssuerMismatch),
        "got {err:?}"
    );
}

#[tokio::test]
async fn rejects_tampered_rekor_inclusion_proof() {
    let mut fx = valid_fixture();
    // Corrupt a Rekor proof node: Fulcio + manifest still pass, but the
    // Rekor inclusion proof no longer reconstructs the checkpoint root.
    fx.bundle.rekor_bundle.proof_nodes[0][0] ^= 0xFF;
    let verifier = make_verifier(fx.fulcio_root_pem, fx.rekor_pem, ISSUER);
    let err = verifier.verify_release(&fx.bundle, None).await.unwrap_err();
    assert!(
        matches!(err, SigstoreVerifyError::RekorInclusionProofVerifyFailed),
        "got {err:?}"
    );
}
