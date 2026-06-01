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
//! The §5 Sigsum-anchored-release-log step IS exercised: `valid_fixture`
//! builds a cosigned `get-tree-head` + `get-inclusion-proof` (via a
//! controlled witness pool whose keys also configure the verifier's
//! composed `SigsumClient`) bound to the manifest's `release_leaf_hash`,
//! and the tamper tests confirm `verify_release` enforces it offline.

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
use cairn_sigsum_client::witness::{
    build_cosignature_signed_message, build_tree_head_note, witness_key_hash,
};
use cairn_sigsum_client::{
    EmittedLeaf, LeafHash, RetryBudget, SigsumClient, SigsumClientConfig, SigsumError, WitnessPool,
    build_tree_leaf, leaf_hash_for_cose_sign1_bytes, parse_witness_pool,
};
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

// ===================================================================
// Sigsum-anchored release-log fixtures (D0024 §5)
// ===================================================================

/// A controlled Sigsum log: the log signing key + three witnesses + the
/// parsed pool, so the test can produce a valid cosigned head the
/// verifier's composed client accepts.
struct SigsumLog {
    log_sk: SigningKey,
    witnesses: Vec<(String, SigningKey)>,
    pool: WitnessPool,
}

fn make_sigsum_log() -> SigsumLog {
    let mut rng = OsRng;
    let log_sk = SigningKey::generate(&mut rng);
    let witnesses: Vec<(String, SigningKey)> = (0..3)
        .map(|i| (format!("W{i}"), SigningKey::generate(&mut rng)))
        .collect();
    let mut toml = String::new();
    for (i, (name, sk)) in witnesses.iter().enumerate() {
        out_witness(&mut toml, i, name, sk);
    }
    let pool = parse_witness_pool(&toml).unwrap();
    SigsumLog {
        log_sk,
        witnesses,
        pool,
    }
}

fn out_witness(toml: &mut String, i: usize, name: &str, sk: &SigningKey) {
    use std::fmt::Write as _;
    let _ = write!(
        toml,
        "[[witness]]\nname = \"{name}\"\npubkey_hex = \"{}\"\nurl = \"https://w-{i}.example.org\"\n\n",
        hex_str(&sk.verifying_key().to_bytes()),
    );
}

fn hex_str(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// A cosigned `get-tree-head` body: the log + the first `num_cosigners`
/// witnesses sign over the checkpoint note for `size`/`root`.
fn cosigned_tree_head(log: &SigsumLog, size: u64, root: &[u8; 32], num_cosigners: usize) -> String {
    let lkh = {
        let mut h = Sha256::new();
        h.update(log.log_sk.verifying_key().to_bytes());
        let o = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&o);
        a
    };
    let note = build_tree_head_note(&lkh, size, root);
    let log_sig = log.log_sk.sign(&note).unwrap();
    let mut body = String::new();
    body.push_str(&format!("size={size}\n"));
    body.push_str(&format!("root_hash={}\n", hex_str(root)));
    body.push_str(&format!("signature={}\n", hex_str(&log_sig.to_bytes())));
    for (i, (name, sk)) in log.witnesses.iter().take(num_cosigners).enumerate() {
        let ts = 1_700_000_100 + i as u64;
        let key_hash = witness_key_hash(name, &sk.verifying_key());
        let msg = build_cosignature_signed_message(ts, &note);
        let sig = sk.sign(&msg).unwrap().to_bytes();
        body.push_str(&format!(
            "cosignature={} {} {}\n",
            hex_str(&key_hash),
            ts,
            hex_str(&sig),
        ));
    }
    body
}

/// Build the bundle's three Sigsum-proof fields bound to
/// `release_leaf_hash`: a size-2 tree with the release leaf at index 0
/// and an opaque sibling, all three witnesses cosigning.
fn make_sigsum_proof(
    log: &SigsumLog,
    release_leaf_hash: &LeafHash,
) -> (EmittedLeaf, String, String) {
    let submitter_sk = SigningKey::generate(&mut OsRng);
    let tl = build_tree_leaf(release_leaf_hash.as_bytes(), &submitter_sk).unwrap();
    let emitted = EmittedLeaf {
        message: *release_leaf_hash.as_bytes(),
        signature: tl.signature,
        key_hash: tl.key_hash,
        observed_at: 0,
    };
    let sibling = [0x5Au8; 32];
    let root = hash_children(&tl.merkle_leaf_hash(), &sibling);
    let head = cosigned_tree_head(log, 2, &root, 3);
    let proof = format!("leaf_index=0\nnode_hash={}\n", hex_str(&sibling));
    (emitted, head, proof)
}

fn make_sigsum_client(log: &SigsumLog) -> SigsumClient {
    let provider = InMemoryKeyProvider::new();
    let passphrase = Zeroizing::new(b"test passphrase".to_vec());
    let storage = Arc::new(Storage::open_in_memory(&provider, &passphrase).unwrap());
    let config = SigsumClientConfig {
        log_url: Url::parse("https://log.example.org").unwrap(),
        log_pubkey: log.log_sk.verifying_key(),
        witness_pool: log.pool.clone(),
        default_retry_budget: RetryBudget::default(),
    };
    SigsumClient::new(config, storage).unwrap()
}

fn make_verifier(
    fulcio_root_pem: Vec<u8>,
    rekor_pubkey_pem: Vec<u8>,
    issuer: &str,
    sigsum_log: &SigsumLog,
) -> SigstoreVerifier {
    let config = SigstoreVerifierConfig {
        fulcio_root_pem,
        rekor_pubkey_pem,
        expected_oidc_issuer: issuer.to_string(),
        expected_oidc_email: EMAIL.to_string(),
        sigsum_client: make_sigsum_client(sigsum_log),
        default_retry_budget: RetryBudget::default(),
    };
    SigstoreVerifier::new(config).unwrap()
}

/// Everything needed to drive `verify_release`, all mutually consistent.
struct Fixture {
    bundle: ReleaseBundle,
    fulcio_root_pem: Vec<u8>,
    rekor_pem: Vec<u8>,
    sigsum_log: SigsumLog,
}

/// Build a fully-valid release bundle: dev key → cert → manifest →
/// Rekor bundle → Sigsum-anchored release-log proof, all consistent.
fn valid_fixture() -> Fixture {
    let (dev_kp, dev_sk) = make_dev_key();
    let (root, root_key) = make_root();
    let leaf_der = make_leaf(&root, &root_key, &dev_kp, ISSUER, EMAIL);
    let (envelope, _manifest) = signed_manifest_envelope(&dev_sk, PRIOR_HASH.to_vec());
    let (rekor_bundle, rekor_pem) = make_rekor_bundle();

    // Sigsum proof bound to THIS manifest's release leaf hash (the shared
    // SHA-256-of-signature-bytes primitive, D0024 §5.1).
    let sigsum_log = make_sigsum_log();
    let release_leaf_hash = leaf_hash_for_cose_sign1_bytes(&envelope).unwrap();
    let (sigsum_emitted_leaf, sigsum_tree_head_body, sigsum_inclusion_proof_body) =
        make_sigsum_proof(&sigsum_log, &release_leaf_hash);

    let bundle = ReleaseBundle {
        manifest_envelope_bytes: envelope,
        fulcio_cert_der: leaf_der,
        rekor_bundle,
        rekor_signing_time_unix: SIGNING_TIME,
        sigsum_emitted_leaf,
        sigsum_tree_head_body,
        sigsum_inclusion_proof_body,
    };
    Fixture {
        bundle,
        fulcio_root_pem: root.pem().into_bytes(),
        rekor_pem,
        sigsum_log,
    }
}

// ===================================================================
// Tests
// ===================================================================

#[tokio::test]
async fn accepts_a_fully_valid_release() {
    let fx = valid_fixture();
    let verifier = make_verifier(fx.fulcio_root_pem, fx.rekor_pem, ISSUER, &fx.sigsum_log);
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
    let verifier = make_verifier(fx.fulcio_root_pem, fx.rekor_pem, ISSUER, &fx.sigsum_log);
    // None skips the rollback check (e.g. the caller has no stored
    // predecessor yet).
    assert!(verifier.verify_release(&fx.bundle, None).await.is_ok());
}

#[tokio::test]
async fn rejects_prior_hash_mismatch() {
    let fx = valid_fixture();
    let verifier = make_verifier(fx.fulcio_root_pem, fx.rekor_pem, ISSUER, &fx.sigsum_log);
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
    let sigsum_log = make_sigsum_log();
    let bundle = ReleaseBundle {
        manifest_envelope_bytes: envelope,
        fulcio_cert_der: leaf_der,
        rekor_bundle,
        rekor_signing_time_unix: SIGNING_TIME,
        // Fails at step (3) (manifest signature) before the Sigsum step,
        // so a placeholder proof suffices.
        sigsum_emitted_leaf: EmittedLeaf {
            message: [0; 32],
            signature: [0; 64],
            key_hash: [0; 32],
            observed_at: 0,
        },
        sigsum_tree_head_body: String::new(),
        sigsum_inclusion_proof_body: String::new(),
    };

    let verifier = make_verifier(root.pem().into_bytes(), rekor_pem, ISSUER, &sigsum_log);
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
    let verifier = make_verifier(
        fx.fulcio_root_pem,
        fx.rekor_pem,
        "https://evil.example.org",
        &fx.sigsum_log,
    );
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
    let verifier = make_verifier(fx.fulcio_root_pem, fx.rekor_pem, ISSUER, &fx.sigsum_log);
    let err = verifier.verify_release(&fx.bundle, None).await.unwrap_err();
    assert!(
        matches!(err, SigstoreVerifyError::RekorInclusionProofVerifyFailed),
        "got {err:?}"
    );
}

#[tokio::test]
async fn rejects_tampered_sigsum_inclusion_proof() {
    // Fulcio + manifest + Rekor + rollback all pass, but the Sigsum
    // inclusion proof's audit node is corrupted, so the reconstructed
    // RFC 6962 root no longer matches the cosigned head. Proves step (6)
    // is actually enforced (not skipped).
    let mut fx = valid_fixture();
    fx.bundle.sigsum_inclusion_proof_body =
        format!("leaf_index=0\nnode_hash={}\n", "00".repeat(32));
    let verifier = make_verifier(fx.fulcio_root_pem, fx.rekor_pem, ISSUER, &fx.sigsum_log);
    let err = verifier.verify_release(&fx.bundle, None).await.unwrap_err();
    assert!(
        matches!(
            err,
            SigstoreVerifyError::SigsumReleaseLog(SigsumError::InclusionProofVerifyFailed)
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn rejects_sigsum_leaf_binding_mismatch() {
    // The bundled emitted-leaf is for a different leaf than the manifest's
    // release_leaf_hash — a valid proof bundled against the wrong
    // artifact. The binding check in verify_bundled_inclusion must reject.
    let mut fx = valid_fixture();
    fx.bundle.sigsum_emitted_leaf.message = [0x99u8; 32];
    let verifier = make_verifier(fx.fulcio_root_pem, fx.rekor_pem, ISSUER, &fx.sigsum_log);
    let err = verifier.verify_release(&fx.bundle, None).await.unwrap_err();
    assert!(
        matches!(
            err,
            SigstoreVerifyError::SigsumReleaseLog(SigsumError::InclusionProofVerifyFailed)
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn rejects_sigsum_head_from_wrong_log_key() {
    // The verifier's composed client pins log key A, but the bundled head
    // is cosigned for a DIFFERENT log B. The pinned log tree-head
    // signature fails -> MalformedResponse, surfaced as SigsumReleaseLog.
    let fx = valid_fixture();
    let other_log = make_sigsum_log();
    // Build a verifier whose composed client pins `other_log`, while the
    // bundle's head was signed by `fx.sigsum_log`.
    let verifier = make_verifier(fx.fulcio_root_pem, fx.rekor_pem, ISSUER, &other_log);
    let err = verifier.verify_release(&fx.bundle, None).await.unwrap_err();
    assert!(
        matches!(
            err,
            SigstoreVerifyError::SigsumReleaseLog(SigsumError::MalformedResponse)
        ),
        "got {err:?}"
    );
}
