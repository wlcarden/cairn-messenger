// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! The release producer: assemble a fully-valid [`ReleaseBundle`] over
//! real artifact digests, plus the [`ReleaseRoots`] that pin it.
//!
//! This is the D0024 §6 verifier's counterpart — it emits exactly the
//! bytes `verify_release` consumes. The six obligations it satisfies map
//! 1:1 onto the six verify steps:
//!
//! 1. build the [`ReleaseManifest`] (version, artifact digests,
//!    build-provenance digest, timestamp, `prior_release_hash`);
//! 2. mint a Fulcio cert chain binding the developer key + OIDC pins;
//! 3. `COSE_Sign1` the manifest under [`RELEASE_MANIFEST_AAD`] with that
//!    same developer key;
//! 4. anchor a Rekor inclusion proof + signed C2SP checkpoint;
//! 5. chain `prior_release_hash` to the predecessor manifest;
//! 6. emit a Sigsum tree leaf bound to the manifest's release-leaf hash +
//!    a witness-cosigned tree head + inclusion proof.
//!
//! ## Self-minted roots (D0041 phase 1)
//!
//! The Fulcio root, Rekor key, and Sigsum log + witnesses are generated
//! here, per `build`, and emitted in [`ReleaseRoots`] so the verifier can
//! pin them. This proves the pipeline MECHANICS end-to-end with zero
//! external services. It is NOT a real Sigstore signing event — the
//! keyless OIDC + real Fulcio/Rekor + recruited-witness path is D0041
//! phase 2, and is a verifier-config swap plus the producer's network
//! legs, not a schema change. The synthetic-minting helpers below mirror
//! the reviewed fixtures in `cairn-sigstore-verify/tests/verify_release.rs`.

// The RFC 6962 Merkle helpers + the PKCS#8 seed-lift are index- and
// arithmetic-heavy; they mirror the reviewed test fixtures. This is a
// host producer tool (never shipped to a device, never in the verify
// trust path), so the indexing/arithmetic lints are allowed here with
// the same pragmatism as the fixtures they port.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "RFC 6962 Merkle math + PKCS#8 seed-lift, ported from the reviewed verify_release fixtures; host-only producer"
)]

use std::fmt::Write as _;

use anyhow::{Context, Result};
use base64::Engine as _;
use cairn_crypto::ed25519::SigningKey;
use cairn_envelope::cose_sign1::Sign1Builder;
use cairn_sigstore_verify::manifest::RELEASE_MANIFEST_AAD;
use cairn_sigstore_verify::{
    ArtifactHash, RekorBundle, ReleaseBundle, ReleaseManifest, SHA256_LEN,
};
use cairn_sigsum_client::witness::{
    build_cosignature_signed_message, build_tree_head_note, witness_key_hash,
};
use cairn_sigsum_client::{EmittedLeaf, LeafHash, build_tree_leaf, leaf_hash_for_cose_sign1_bytes};
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
use zeroize::Zeroizing;

use crate::roots::{ReleaseRoots, to_hex};

/// The self-minted OIDC identity the synthetic Fulcio leaf carries. In
/// D0041 phase 2 these become the project's pinned real OIDC issuer +
/// developer email (D0024 §1.1).
const SELF_MINTED_ISSUER: &str = "https://accounts.google.com";
/// The self-minted developer email (SAN) the synthetic leaf carries.
const SELF_MINTED_EMAIL: &str = "releases@cairn-project.org";
/// Fulcio leaf validity window (inclusive of any plausible build time
/// through 2030). The Rekor-attested signing time must fall inside it.
const LEAF_NOT_BEFORE: (i32, u8, u8) = (2020, 1, 1);
const LEAF_NOT_AFTER: (i32, u8, u8) = (2030, 1, 1);

/// One artifact's name + raw bytes, as handed to [`produce`]. The
/// producer computes the SHA-256 itself so the manifest digest is bound
/// to the exact bytes on disk.
pub struct ArtifactInput {
    /// Human-readable artifact identifier, e.g. `"cairn-1.0.0.apk"`.
    pub name: String,
    /// The artifact's raw bytes (the producer hashes these).
    pub bytes: Vec<u8>,
}

/// Everything `build` writes out: the bundle, the roots that pin it, the
/// raw manifest CBOR (for the NEXT release's `prior_release_hash`), and
/// the build-provenance attestation that ships as a release artifact.
pub struct ProducedRelease {
    /// The canonical-CBOR `ReleaseBundle` (`release-bundle.cbor`).
    pub bundle: ReleaseBundle,
    /// The trust-root sidecar (`release-roots.json`).
    pub roots: ReleaseRoots,
    /// The signed manifest's payload — canonical-CBOR of the
    /// [`ReleaseManifest`] (`manifest.cbor`). SHA-256 of these bytes is
    /// the value the next release pins as `prior_release_hash`.
    pub manifest_cbor: Vec<u8>,
    /// SHA-256 of `manifest_cbor`; surfaced so `build` can print the
    /// chain link the next release must reference.
    pub manifest_self_hash: [u8; SHA256_LEN],
    /// The build-provenance attestation bytes (`build-provenance.json`),
    /// whose SHA-256 the manifest commits to.
    pub build_provenance_json: Vec<u8>,
    /// SHA-256 of `build_provenance_json` (the value the manifest's
    /// `build_provenance_sha256` field carries); surfaced for the summary.
    pub build_provenance_sha256: [u8; SHA256_LEN],
    /// The artifact name + digest set, surfaced for the `build` summary.
    pub artifacts: Vec<ArtifactHash>,
    /// The Sigsum release-leaf hash the bundle is bound to; surfaced for
    /// the `build` summary.
    pub release_leaf_hash: [u8; 32],
}

/// Produce a fully-valid, self-minted release bundle.
///
/// `prior_release_hash` is empty for the genesis release, or the SHA-256
/// of the predecessor's `manifest.cbor` for every subsequent release.
/// `release_timestamp` is Unix-seconds and MUST fall inside the synthetic
/// Fulcio leaf window ([`LEAF_NOT_BEFORE`]..[`LEAF_NOT_AFTER`]).
///
/// # Errors
///
/// Returns an error if any minting, signing, or canonical-CBOR step
/// fails (cert generation, COSE signing, Sigsum leaf construction, or the
/// bundle encode).
pub fn produce(
    artifacts: &[ArtifactInput],
    version: &str,
    prior_release_hash: Vec<u8>,
    release_timestamp: u64,
) -> Result<ProducedRelease> {
    anyhow::ensure!(!artifacts.is_empty(), "at least one artifact is required");

    // (1) Artifact digests + the build-provenance attestation.
    let artifact_hashes: Vec<ArtifactHash> = artifacts
        .iter()
        .map(|a| ArtifactHash {
            name: a.name.clone(),
            sha256: sha256(&a.bytes),
        })
        .collect();
    let build_provenance_json = build_provenance(version, &artifact_hashes, release_timestamp);
    let build_provenance_sha256 = sha256(&build_provenance_json);

    let manifest = ReleaseManifest {
        version: version.to_string(),
        artifact_sha256: artifact_hashes.clone(),
        build_provenance_sha256,
        release_timestamp,
        prior_release_hash,
    };
    let manifest_cbor = manifest
        .to_canonical_cbor()
        .map_err(|e| anyhow::anyhow!("encode manifest: {e}"))?;
    let manifest_self_hash = manifest
        .canonical_self_hash()
        .map_err(|e| anyhow::anyhow!("hash manifest: {e}"))?;

    // (2) Developer key + Fulcio cert chain binding it.
    let (dev_kp, dev_sk) = mint_dev_key()?;
    let (root_cert, root_key) = mint_root()?;
    let fulcio_cert_der = mint_leaf(&root_cert, &root_key, &dev_kp)?;
    let fulcio_root_pem = root_cert.pem();

    // (3) COSE_Sign1 the manifest under the release AAD with the dev key.
    let manifest_envelope_bytes = sign_manifest_envelope(&dev_sk, &manifest)?;

    // (4) Rekor inclusion proof + signed checkpoint.
    let (rekor_bundle, rekor_pubkey_pem) = mint_rekor_bundle(&manifest_envelope_bytes)?;

    // (6) Sigsum tree leaf bound to the manifest's release-leaf hash + a
    // witness-cosigned head + inclusion proof.
    let release_leaf_hash = leaf_hash_for_cose_sign1_bytes(&manifest_envelope_bytes)
        .map_err(|e| anyhow::anyhow!("compute release leaf hash: {e}"))?;
    let log = mint_sigsum_log();
    let (sigsum_emitted_leaf, sigsum_tree_head_body, sigsum_inclusion_proof_body) =
        mint_sigsum_proof(&log, &release_leaf_hash, release_timestamp)?;

    let bundle = ReleaseBundle {
        manifest_envelope_bytes,
        fulcio_cert_der,
        rekor_bundle,
        rekor_signing_time_unix: release_timestamp,
        sigsum_emitted_leaf,
        sigsum_tree_head_body,
        sigsum_inclusion_proof_body,
    };

    let roots = ReleaseRoots {
        fulcio_root_pem,
        rekor_pubkey_pem,
        oidc_issuer: SELF_MINTED_ISSUER.to_string(),
        oidc_email: SELF_MINTED_EMAIL.to_string(),
        sigsum_log_pubkey_hex: to_hex(&log.log_sk.verifying_key().to_bytes()),
        witnesses_toml: log.toml,
    };

    Ok(ProducedRelease {
        bundle,
        roots,
        manifest_cbor,
        manifest_self_hash,
        build_provenance_json,
        build_provenance_sha256,
        artifacts: artifact_hashes,
        release_leaf_hash: *release_leaf_hash.as_bytes(),
    })
}

/// SHA-256 helper returning the fixed-width digest.
fn sha256(bytes: &[u8]) -> [u8; SHA256_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; SHA256_LEN];
    arr.copy_from_slice(&out);
    arr
}

/// A minimal SLSA-style in-toto provenance statement. v1 ships this as a
/// release artifact for independent inspection; the manifest commits to
/// its SHA-256. The `buildType` names this the self-minted producer so a
/// reader is not misled into thinking a hermetic/reproducible build
/// produced it (D0004 defers reproducible builds to v1.5).
fn build_provenance(version: &str, artifacts: &[ArtifactHash], release_timestamp: u64) -> Vec<u8> {
    let subjects: Vec<serde_json::Value> = artifacts
        .iter()
        .map(|a| {
            serde_json::json!({
                "name": a.name,
                "digest": { "sha256": to_hex(&a.sha256) },
            })
        })
        .collect();
    let statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": subjects,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://cairn-project.org/release/v0-self-minted",
                "externalParameters": { "version": version },
            },
            "runDetails": {
                "builder": { "id": "https://cairn-project.org/cairn-release" },
                "metadata": { "finishedOn": release_timestamp },
            },
        },
    });
    let mut bytes = serde_json::to_vec_pretty(&statement).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

// ===================================================================
// Synthetic Fulcio cert helpers (mirror tests/verify_release.rs)
// ===================================================================

/// Generate the developer Ed25519 key as both an rcgen `KeyPair` (bound
/// into the Fulcio leaf) and the matching cairn-crypto `SigningKey` (signs
/// the manifest). The seed is lifted from the rcgen PKCS#8 via the RFC
/// 8410 Ed25519 privateKey marker (`04 22 04 20 || seed[32]`); both
/// libraries derive the same RFC 8032 public key from it.
fn mint_dev_key() -> Result<(KeyPair, SigningKey)> {
    let kp = KeyPair::generate_for(&PKCS_ED25519).context("generate dev keypair")?;
    let pkcs8 = kp.serialize_der();
    let marker = [0x04u8, 0x22, 0x04, 0x20];
    let pos = pkcs8
        .windows(4)
        .position(|w| w == marker)
        .context("locate ed25519 pkcs8 privateKey marker")?;
    let seed: [u8; 32] = pkcs8
        .get(pos + 4..pos + 36)
        .context("ed25519 seed slice out of range")?
        .try_into()
        .context("ed25519 seed not 32 bytes")?;
    let sk = SigningKey::from_seed(&Zeroizing::new(seed));
    Ok((kp, sk))
}

/// A self-signed synthetic Fulcio root (ECDSA P-384).
fn mint_root() -> Result<(Certificate, KeyPair)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).context("generate root keypair")?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Cairn self-minted release root");
    let cert = params.self_signed(&key).context("self-sign root")?;
    Ok((cert, key))
}

/// A leaf cert binding `dev_kp`'s Ed25519 key, signed by `root`, carrying
/// the Fulcio OIDC issuer extension + SAN email (D0024 §2).
fn mint_leaf(root: &Certificate, root_key: &KeyPair, dev_kp: &KeyPair) -> Result<Vec<u8>> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::NoCa;
    params.not_before = date_time_ymd(LEAF_NOT_BEFORE.0, LEAF_NOT_BEFORE.1, LEAF_NOT_BEFORE.2);
    params.not_after = date_time_ymd(LEAF_NOT_AFTER.0, LEAF_NOT_AFTER.1, LEAF_NOT_AFTER.2);
    params
        .distinguished_name
        .push(DnType::CommonName, "sigstore");
    params.subject_alt_names = vec![SanType::Rfc822Name(
        SELF_MINTED_EMAIL
            .try_into()
            .context("email into SAN Rfc822Name")?,
    )];
    // Fulcio OIDC issuer extension OID 1.3.6.1.4.1.57264.1.1.
    params.custom_extensions = vec![CustomExtension::from_oid_content(
        &[1, 3, 6, 1, 4, 1, 57264, 1, 1],
        SELF_MINTED_ISSUER.as_bytes().to_vec(),
    )];
    let leaf = params
        .signed_by(dev_kp, root, root_key)
        .context("sign leaf by root")?;
    Ok(leaf.der().as_ref().to_vec())
}

/// `COSE_Sign1` the canonical-CBOR manifest under [`RELEASE_MANIFEST_AAD`].
fn sign_manifest_envelope(dev_sk: &SigningKey, manifest: &ReleaseManifest) -> Result<Vec<u8>> {
    let payload = manifest
        .to_canonical_cbor()
        .map_err(|e| anyhow::anyhow!("encode manifest payload: {e}"))?;
    Sign1Builder::new()
        .with_payload(payload)
        .with_external_aad(RELEASE_MANIFEST_AAD.to_vec())
        .finalize(dev_sk)
        .map_err(|e| anyhow::anyhow!("finalize COSE_Sign1: {e}"))?
        .encode(false)
        .map_err(|e| anyhow::anyhow!("encode COSE_Sign1: {e}"))
}

// ===================================================================
// Synthetic Rekor bundle (RFC 6962 tree + C2SP/ECDSA-P256 checkpoint)
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

fn rfc6962_leaf(data: &[u8]) -> [u8; 32] {
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
        0 | 1 => leaves.first().copied().unwrap_or([0u8; 32]),
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

/// A valid synthetic Rekor bundle: a 5-leaf tree with the signing-event
/// leaf at index 2 (the RFC 6962 leaf hash of the manifest envelope), a
/// C2SP checkpoint signed by a fresh P-256 key. Returns the bundle + the
/// pinned Rekor pubkey PEM.
fn mint_rekor_bundle(manifest_envelope: &[u8]) -> Result<(RekorBundle, String)> {
    let sk = P256SigningKey::random(&mut OsRng);
    let mut leaves: Vec<[u8; 32]> = (0..5)
        .map(|i| rfc6962_leaf(format!("cairn-rekor-pad-{i}").as_bytes()))
        .collect();
    // The index-2 leaf is the real signing-event entry.
    leaves[2] = rfc6962_leaf(manifest_envelope);
    let root = mth(&leaves);
    let proof = audit_path(2, &leaves);
    let note = format!("rekor.cairn.invalid/self-minted\n5\n{}\n", b64(&root));
    let sig: P256Signature = sk.sign(note.as_bytes());
    let pem = P256VerifyingKey::from(&sk)
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("encode rekor pubkey PEM: {e}"))?;
    let bundle = RekorBundle {
        leaf_hash: leaves[2],
        leaf_index: 2,
        proof_nodes: proof,
        checkpoint_note: note.into_bytes(),
        checkpoint_signature: sig.to_der().as_bytes().to_vec(),
    };
    Ok((bundle, pem))
}

// ===================================================================
// Synthetic Sigsum log + witness pool (mirror the verify fixtures)
// ===================================================================

/// A controlled synthetic Sigsum log: the log signing key + three
/// witnesses + the witness-pool TOML the roots carry.
struct SigsumLog {
    log_sk: SigningKey,
    witnesses: Vec<(String, SigningKey)>,
    toml: String,
}

fn mint_sigsum_log() -> SigsumLog {
    let mut rng = OsRng;
    let log_sk = SigningKey::generate(&mut rng);
    let witnesses: Vec<(String, SigningKey)> = (0..3)
        .map(|i| (format!("cairn-witness-{i}"), SigningKey::generate(&mut rng)))
        .collect();
    let mut toml = String::new();
    for (i, (name, sk)) in witnesses.iter().enumerate() {
        let _ = write!(
            toml,
            "[[witness]]\nname = \"{name}\"\npubkey_hex = \"{}\"\nurl = \"https://witness-{i}.cairn.invalid\"\n\n",
            to_hex(&sk.verifying_key().to_bytes()),
        );
    }
    SigsumLog {
        log_sk,
        witnesses,
        toml,
    }
}

/// A cosigned `get-tree-head` body: the log + all witnesses sign over the
/// checkpoint note for `size`/`root` (the 2-of-3 threshold is satisfied
/// by signing with all three).
fn cosigned_tree_head(
    log: &SigsumLog,
    size: u64,
    root: &[u8; 32],
    base_timestamp: u64,
) -> Result<String> {
    let lkh = {
        let mut h = Sha256::new();
        h.update(log.log_sk.verifying_key().to_bytes());
        let o = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&o);
        a
    };
    let note = build_tree_head_note(&lkh, size, root);
    let log_sig = log
        .log_sk
        .sign(&note)
        .map_err(|e| anyhow::anyhow!("log sign tree head: {e}"))?;
    let mut body = String::new();
    let _ = writeln!(body, "size={size}");
    let _ = writeln!(body, "root_hash={}", to_hex(root));
    let _ = writeln!(body, "signature={}", to_hex(&log_sig.to_bytes()));
    for (i, (name, sk)) in log.witnesses.iter().enumerate() {
        let ts = base_timestamp.saturating_add(i as u64);
        let key_hash = witness_key_hash(name, &sk.verifying_key());
        let msg = build_cosignature_signed_message(ts, &note);
        let sig = sk
            .sign(&msg)
            .map_err(|e| anyhow::anyhow!("witness cosign: {e}"))?
            .to_bytes();
        let _ = writeln!(
            body,
            "cosignature={} {} {}",
            to_hex(&key_hash),
            ts,
            to_hex(&sig)
        );
    }
    Ok(body)
}

/// Build the bundle's three Sigsum-proof fields bound to
/// `release_leaf_hash`: a size-2 tree with the release leaf at index 0
/// and an opaque sibling, all witnesses cosigning.
fn mint_sigsum_proof(
    log: &SigsumLog,
    release_leaf_hash: &LeafHash,
    release_timestamp: u64,
) -> Result<(EmittedLeaf, String, String)> {
    let submitter_sk = SigningKey::generate(&mut OsRng);
    let tl = build_tree_leaf(release_leaf_hash.as_bytes(), &submitter_sk)
        .map_err(|e| anyhow::anyhow!("build tree leaf: {e}"))?;
    let emitted = EmittedLeaf {
        message: *release_leaf_hash.as_bytes(),
        signature: tl.signature,
        key_hash: tl.key_hash,
        observed_at: release_timestamp,
    };
    let sibling = [0x5Au8; 32];
    let root = hash_children(&tl.merkle_leaf_hash(), &sibling);
    let head = cosigned_tree_head(log, 2, &root, release_timestamp)?;
    let proof = format!("leaf_index=0\nnode_hash={}\n", to_hex(&sibling));
    Ok((emitted, head, proof))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn one_apk() -> Vec<ArtifactInput> {
        vec![ArtifactInput {
            name: "cairn-1.0.0.apk".to_string(),
            bytes: b"fake apk bytes for the host round-trip".to_vec(),
        }]
    }

    #[test]
    fn produced_bundle_round_trips_through_canonical_cbor() {
        let produced = produce(&one_apk(), "1.0.0-test", vec![], 1_717_200_000)
            .expect("produce a self-minted bundle");
        let bytes = produced
            .bundle
            .to_canonical_cbor()
            .expect("encode produced bundle");
        let recovered = ReleaseBundle::from_canonical_cbor(&bytes).expect("decode produced bundle");
        assert_eq!(
            recovered.manifest_envelope_bytes,
            produced.bundle.manifest_envelope_bytes
        );
        assert_eq!(recovered.rekor_bundle.leaf_index, 2);
    }

    #[tokio::test]
    async fn produced_bundle_verifies_against_its_own_roots() {
        // The end-to-end host proof: producer -> serialize -> the REAL
        // verify_release accepts it against the emitted roots. Genesis
        // release (no predecessor), so verify with expected_prior = None.
        let produced =
            produce(&one_apk(), "1.0.0-test", vec![], 1_717_200_000).expect("produce bundle");
        let verifier = produced.roots.build_verifier().expect("build verifier");
        let outcome = verifier
            .verify_release(&produced.bundle, None)
            .await
            .expect("a self-minted bundle must verify against its own roots");
        assert_eq!(outcome.manifest.version, "1.0.0-test");
        assert_eq!(outcome.manifest.artifact_sha256.len(), 1);
    }

    #[tokio::test]
    async fn rollback_chain_links_predecessor_to_successor() {
        // Genesis -> N+1: the successor pins SHA-256(predecessor manifest
        // cbor) as prior_release_hash, and verify_release enforces it.
        let genesis =
            produce(&one_apk(), "1.0.0-test", vec![], 1_717_200_000).expect("produce genesis");
        let successor = produce(
            &one_apk(),
            "1.0.1-test",
            genesis.manifest_self_hash.to_vec(),
            1_717_300_000,
        )
        .expect("produce successor");
        let verifier = successor.roots.build_verifier().expect("build verifier");
        // Correct predecessor -> accepts.
        verifier
            .verify_release(&successor.bundle, Some(genesis.manifest_self_hash))
            .await
            .expect("successor verifies against the genesis chain link");
        // Wrong predecessor -> rejected (rollback resistance).
        let wrong = [0x99u8; 32];
        assert!(
            verifier
                .verify_release(&successor.bundle, Some(wrong))
                .await
                .is_err(),
            "a mismatched predecessor must be rejected"
        );
    }
}
