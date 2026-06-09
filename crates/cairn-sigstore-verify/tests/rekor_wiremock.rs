// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Hermetic integration harness for the online Rekor fetch path per
//! D0024 §6.4 / §10.
//!
//! ## What this validates
//!
//! [`SigstoreVerifier::fetch_and_verify_rekor`] issues a real
//! `GET /api/v1/log/entries/{uuid}` against a [`wiremock`] mock Rekor,
//! parses the v1 JSON response (`body`, `verification.inclusionProof`)
//! into a `RekorBundle`, and verifies it against the pinned Rekor
//! public key. The mock response is built with the crate's expected
//! formats — an RFC 6962 Merkle tree + a C2SP signed-note checkpoint
//! signed by a freshly-generated **ECDSA P-256** key — so the test
//! asserts the fetch+parse+verify pipeline agrees with the producer
//! side. No external network, no real Rekor, no checked-in keys.
//!
//! ## Coverage
//!
//! - Accept: a valid signed response verifies end-to-end.
//! - Inclusion tamper: a corrupted proof hash → inclusion failure.
//! - Checkpoint key mismatch: a checkpoint signed by a non-pinned key
//!   → checkpoint failure.
//! - Malformed response: non-JSON body → parse failure.
//! - Transport: repeated 5xx exhausts the retry budget → network error.

// This harness exercises the online `fetch_*` path, which only exists
// under the `online-rekor` feature (D0041 §6.1). Compiled out otherwise,
// so the default `cargo test` sees no online surface to test.
#![cfg(feature = "online-rekor")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use cairn_crypto::ed25519::SigningKey as EdSigningKey;
use cairn_sigstore_verify::{SigstoreVerifier, SigstoreVerifierConfig, SigstoreVerifyError};
use cairn_sigsum_client::{RetryBudget, SigsumClient, SigsumClientConfig, parse_witness_pool};
use cairn_storage::Storage;
use cairn_storage::key_provider::testing::InMemoryKeyProvider;
use p256::ecdsa::Signature;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::{EncodePublicKey as _, LineEnding};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zeroize::Zeroizing;

const ENTRY_UUID: &str = "deadbeefcafef00d";

// ===================================================================
// RFC 6962 reference tree (mirrors rekor.rs's private helpers; the
// harness is a separate crate and cannot reach them)
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

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ===================================================================
// Canned Rekor v1 response builder
// ===================================================================

/// Build a Rekor v1 `GET /api/v1/log/entries/{uuid}` JSON response for a
/// 5-leaf tree with the target entry at index 2, with a C2SP
/// signed-note checkpoint signed by `checkpoint_sk`.
fn build_response(checkpoint_sk: &P256SigningKey) -> serde_json::Value {
    let num_leaves = 5usize;
    let target_index = 2usize;
    let body = b"rekor-entry-body-bytes".to_vec();
    let target_leaf = leaf_hash(&body);

    let leaves: Vec<[u8; 32]> = (0..num_leaves)
        .map(|i| {
            if i == target_index {
                target_leaf
            } else {
                leaf_hash(format!("other-leaf-{i}").as_bytes())
            }
        })
        .collect();

    let root = mth(&leaves);
    let proof = audit_path(target_index, &leaves);

    // C2SP signed-note checkpoint. Signed body = origin\n size\n
    // base64(root)\n (ends in \n). The signature line follows a blank
    // line.
    let note = format!("rekor.example/test\n{num_leaves}\n{}\n", b64(&root));
    let sig: Signature = checkpoint_sk.sign(note.as_bytes());
    let der = sig.to_der();
    // C2SP signed note: base64(4-byte key id || signature).
    let mut keyed_sig = vec![0x12u8, 0x34, 0x56, 0x78];
    keyed_sig.extend_from_slice(der.as_bytes());
    let checkpoint = format!("{note}\n\u{2014} rekor.example/test {}\n", b64(&keyed_sig));

    serde_json::json!({
        ENTRY_UUID: {
            "body": b64(&body),
            "logIndex": 987_654,
            "integratedTime": 1_700_000_000u64,
            "verification": {
                "inclusionProof": {
                    "logIndex": target_index,
                    "rootHash": lower_hex(&root),
                    "treeSize": num_leaves,
                    "hashes": proof.iter().map(|h| lower_hex(h)).collect::<Vec<_>>(),
                    "checkpoint": checkpoint,
                }
            }
        }
    })
}

// ===================================================================
// Verifier construction (mirrors the client-module test helpers)
// ===================================================================

fn make_witness_pool_toml(count: usize) -> String {
    let mut rng = OsRng;
    let mut out = String::new();
    for i in 0..count {
        let sk = EdSigningKey::generate(&mut rng);
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
    let log_pubkey = EdSigningKey::generate(&mut OsRng).verifying_key();
    let config = SigsumClientConfig {
        log_url: Url::parse("https://log.example.org").unwrap(),
        log_pubkey,
        witness_pool: pool,
        default_retry_budget: RetryBudget::default(),
    };
    SigsumClient::new(config, storage).unwrap()
}

fn make_verifier(rekor_pubkey_pem: Vec<u8>, budget: RetryBudget) -> SigstoreVerifier {
    let config = SigstoreVerifierConfig {
        fulcio_root_pem: b"-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----"
            .to_vec(),
        rekor_pubkey_pem,
        expected_oidc_issuer: "https://accounts.example.org".to_string(),
        expected_oidc_email: "maintainer@cairn-project.org".to_string(),
        sigsum_client: make_sigsum_client(),
        default_retry_budget: budget,
    };
    SigstoreVerifier::new(config).unwrap()
}

fn pubkey_pem(sk: &P256SigningKey) -> Vec<u8> {
    p256::ecdsa::VerifyingKey::from(sk)
        .to_public_key_pem(LineEnding::LF)
        .unwrap()
        .into_bytes()
}

fn base_url(server: &MockServer) -> Url {
    Url::parse(&format!("{}/", server.uri())).unwrap()
}

async fn mount_json(server: &MockServer, value: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/log/entries/{ENTRY_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(value.to_string()))
        .mount(server)
        .await;
}

// ===================================================================
// Tests
// ===================================================================

#[tokio::test]
async fn fetch_and_verify_accepts_valid_response() {
    let sk = P256SigningKey::random(&mut OsRng);
    let server = MockServer::start().await;
    mount_json(&server, build_response(&sk)).await;

    let verifier = make_verifier(pubkey_pem(&sk), RetryBudget::default());
    let checkpoint = verifier
        .fetch_and_verify_rekor(&base_url(&server), ENTRY_UUID)
        .await
        .expect("valid fetched response must verify");

    assert_eq!(checkpoint.tree_size, 5);
    assert_eq!(checkpoint.origin, "rekor.example/test");
}

#[tokio::test]
async fn fetch_rekor_bundle_parses_expected_shape() {
    // Exercise the parse path in isolation: the bundle's leaf_index +
    // proof length must match what was served.
    let sk = P256SigningKey::random(&mut OsRng);
    let server = MockServer::start().await;
    mount_json(&server, build_response(&sk)).await;

    let verifier = make_verifier(pubkey_pem(&sk), RetryBudget::default());
    let bundle = verifier
        .fetch_rekor_bundle(&base_url(&server), ENTRY_UUID)
        .await
        .expect("valid response must parse");

    assert_eq!(bundle.leaf_index, 2);
    // A 5-leaf tree yields a 3-node audit path for index 2.
    assert_eq!(bundle.proof_nodes.len(), 3);
    assert!(!bundle.checkpoint_note.is_empty());
}

#[tokio::test]
async fn rejects_tampered_inclusion_proof() {
    let sk = P256SigningKey::random(&mut OsRng);
    let server = MockServer::start().await;
    let mut value = build_response(&sk);
    // Corrupt the first proof hash: checkpoint signature still verifies
    // (note untouched), but the reconstructed root no longer matches.
    value[ENTRY_UUID]["verification"]["inclusionProof"]["hashes"][0] =
        serde_json::Value::String(lower_hex(&[0u8; 32]));
    mount_json(&server, value).await;

    let verifier = make_verifier(pubkey_pem(&sk), RetryBudget::default());
    let err = verifier
        .fetch_and_verify_rekor(&base_url(&server), ENTRY_UUID)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SigstoreVerifyError::RekorInclusionProofVerifyFailed),
        "got {err:?}"
    );
}

#[tokio::test]
async fn rejects_checkpoint_signed_by_non_pinned_key() {
    // Response checkpoint is signed by `signer`, but the verifier pins a
    // different key -> the checkpoint signature fails.
    let signer = P256SigningKey::random(&mut OsRng);
    let pinned = P256SigningKey::random(&mut OsRng);
    let server = MockServer::start().await;
    mount_json(&server, build_response(&signer)).await;

    let verifier = make_verifier(pubkey_pem(&pinned), RetryBudget::default());
    let err = verifier
        .fetch_and_verify_rekor(&base_url(&server), ENTRY_UUID)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SigstoreVerifyError::RekorCheckpointVerifyFailed),
        "got {err:?}"
    );
}

#[tokio::test]
async fn rejects_malformed_response_body() {
    let sk = P256SigningKey::random(&mut OsRng);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/log/entries/{ENTRY_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_string("this is not json"))
        .mount(&server)
        .await;

    let verifier = make_verifier(pubkey_pem(&sk), RetryBudget::default());
    let err = verifier
        .fetch_rekor_bundle(&base_url(&server), ENTRY_UUID)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SigstoreVerifyError::RekorResponseMalformed),
        "got {err:?}"
    );
}

#[tokio::test]
async fn network_failure_surfaces_after_retry_budget() {
    let sk = P256SigningKey::random(&mut OsRng);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/log/entries/{ENTRY_UUID}")))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let budget = RetryBudget {
        max_retries: 1,
        initial_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
    };
    let verifier = make_verifier(pubkey_pem(&sk), budget);
    let err = verifier
        .fetch_rekor_bundle(&base_url(&server), ENTRY_UUID)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            SigstoreVerifyError::Network {
                retry_budget_used: 1
            }
        ),
        "got {err:?}"
    );
}
