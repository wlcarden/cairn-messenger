// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Hermetic integration harness for [`SigsumClient::verify_inclusion`]
//! per D0023 §10.
//!
//! ## What this validates
//!
//! `verify_inclusion` is the third (and last) network-bound surface to
//! leave the v1 skeleton. End-to-end it:
//!
//! 1. recomputes Cairn's leaf hash from the signed op,
//! 2. loads the emit-time [`cairn_sigsum_client::EmittedLeaf`] from the
//!    cache and reconstructs the Sigsum `tree_leaf` → its RFC 6962
//!    Merkle leaf hash (`H(0x00 ‖ tree_leaf)`),
//! 3. fetches a fresh, cosigned, split-view-checked accepted head via
//!    `refresh_tree_head`,
//! 4. for a size-1 tree checks inclusion locally (`leaf_hash ==
//!    root_hash`); otherwise fetches `get-inclusion-proof`, reconstructs
//!    the RFC 6962 root, and requires it to equal the accepted head's
//!    root,
//! 5. caches + returns the verified [`InclusionProof`].
//!
//! ## Producer/verifier symmetry (why the fixtures are trustworthy)
//!
//! The cache is seeded by a real [`SigsumClient::emit_leaf`] call
//! against a mock `add-leaf` (so this is a genuine emit→verify
//! composition test, not a hand-stuffed cache). The Merkle leaf hash
//! the proof fixtures are built around is recomputed with the crate's
//! OWN [`build_tree_leaf`] + [`cairn_sigsum_client::TreeLeaf::merkle_-
//! leaf_hash`]. Because Ed25519 (RFC 8032) is deterministic, that hash
//! is byte-identical to the one `verify_inclusion` reconstructs from the
//! cached record — so the test never maintains a divergent second
//! implementation of the leaf model. The only Merkle math the test adds
//! is a 3-line RFC 6962 interior-node hash (`H(0x01 ‖ left ‖ right)`)
//! used to assemble a minimal tree of opaque sibling hashes around the
//! real target leaf.
//!
//! The cosigned `get-tree-head` fixtures reuse the same
//! [`build_tree_head_note`] / [`build_cosignature_signed_message`] /
//! [`witness_key_hash`] producer helpers as
//! `tests/refresh_tree_head_wiremock.rs`. No external network, no real
//! Sigsum log, no checked-in key material.
//!
//! ## Coverage map (D0023 §3.2 + §5 + verify.rs branches)
//!
//! - Acceptance: size-1 local check; multi-leaf (size 3) RFC 6962 proof
//!   reconstructed to the accepted root.
//! - Rejection: size-1 root mismatch; tampered proof node (size 2); the
//!   empty (size 0) log includes nothing.
//! - Transport: `get-inclusion-proof` 404 ("not included") exhausts the
//!   retry budget → `Network`.
//! - Parse: a proof body missing `leaf_index` → `MalformedResponse`.
//! - Precondition: verifying a leaf that was never emitted is a cache
//!   miss → `Storage`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;
use std::time::Duration;

use cairn_crypto::ed25519::SigningKey;
use cairn_sigsum_client::witness::{
    build_cosignature_signed_message, build_tree_head_note, witness_key_hash,
};
use cairn_sigsum_client::{
    RetryBudget, SigsumClient, SigsumClientConfig, SigsumError, WitnessPool, build_tree_leaf,
    leaf_hash_for, parse_witness_pool,
};
use cairn_storage::Storage;
use cairn_storage::key_provider::testing::InMemoryKeyProvider;
use cairn_trust_graph::{SignedTrustGraphOp, TrustGraphOp};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zeroize::Zeroizing;

// ===================================================================
// Fixtures — log + witness pool (mirrors refresh_tree_head_wiremock.rs)
// ===================================================================

/// A test witness: its display name (as it appears in `witnesses.toml`,
/// the name fed into the C2SP key-id derivation) and its Ed25519 key.
struct TestWitness {
    name: String,
    sk: SigningKey,
}

/// A fully-controlled test Sigsum log: the log's own signing key, the
/// three witnesses, and the parsed pool the client is configured with.
struct TestLog {
    log_sk: SigningKey,
    witnesses: Vec<TestWitness>,
    pool: WitnessPool,
}

/// One cosignature line emitted into a `get-tree-head` body.
struct CosignEntry<'a> {
    name: &'a str,
    sk: &'a SigningKey,
    ts: u64,
}

/// Generate a log key + three witnesses and parse the matching pool.
fn make_test_log() -> TestLog {
    let mut rng = OsRng;
    let log_sk = SigningKey::generate(&mut rng);
    let witnesses: Vec<TestWitness> = (0..3)
        .map(|i| TestWitness {
            name: format!("W{i}"),
            sk: SigningKey::generate(&mut rng),
        })
        .collect();

    let mut toml = String::new();
    for (i, w) in witnesses.iter().enumerate() {
        toml.push_str(&format!(
            "[[witness]]\nname = \"{}\"\npubkey_hex = \"{}\"\nurl = \"https://w-{i}.example.org\"\n\n",
            w.name,
            lower_hex(&w.sk.verifying_key().to_bytes()),
        ));
    }
    let pool = parse_witness_pool(&toml).unwrap();
    TestLog {
        log_sk,
        witnesses,
        pool,
    }
}

/// The three configured witnesses, all signing honestly, with distinct
/// ascending timestamps.
fn three_valid(log: &TestLog) -> Vec<CosignEntry<'_>> {
    vec![
        CosignEntry {
            name: &log.witnesses[0].name,
            sk: &log.witnesses[0].sk,
            ts: 1_700_000_100,
        },
        CosignEntry {
            name: &log.witnesses[1].name,
            sk: &log.witnesses[1].sk,
            ts: 1_700_000_200,
        },
        CosignEntry {
            name: &log.witnesses[2].name,
            sk: &log.witnesses[2].sk,
            ts: 1_700_000_300,
        },
    ]
}

/// Build a spec-correct, honestly-cosigned `get-tree-head` ASCII body.
/// The log + every witness sign over the checkpoint note for
/// (`tree_size`, `root`); three valid cosignatures satisfy the 2-of-3
/// acceptance threshold so `refresh_tree_head` accepts the head.
fn honest_tree_head_body(log: &TestLog, tree_size: u64, root: &[u8; 32]) -> String {
    let log_pubkey = log.log_sk.verifying_key();
    let log_key_hash = sha256(&log_pubkey.to_bytes());
    let note = build_tree_head_note(&log_key_hash, tree_size, root);
    let log_sig = log.log_sk.sign(&note).unwrap();

    let mut body = String::new();
    body.push_str(&format!("size={tree_size}\n"));
    body.push_str(&format!("root_hash={}\n", lower_hex(root)));
    body.push_str(&format!("signature={}\n", lower_hex(&log_sig.to_bytes())));
    for c in three_valid(log) {
        let key_hash = witness_key_hash(c.name, &c.sk.verifying_key());
        let msg = build_cosignature_signed_message(c.ts, &note);
        let sig = c.sk.sign(&msg).unwrap().to_bytes();
        body.push_str(&format!(
            "cosignature={} {} {}\n",
            lower_hex(&key_hash),
            c.ts,
            lower_hex(&sig),
        ));
    }
    body
}

// ===================================================================
// Fixtures — the leaf under test + RFC 6962 tree math
// ===================================================================

/// Build a structurally-valid signed trust-graph op plus an independent
/// submitter key (the operational identity acting as the Sigsum
/// submitter per D0023 §3). `verify_inclusion` does not re-verify the
/// chain, so no capability token is needed here.
fn make_op_and_submitter() -> (SignedTrustGraphOp, SigningKey) {
    let mut rng = OsRng;
    let op_identity_sk = SigningKey::generate(&mut rng);
    let device_sk = SigningKey::generate(&mut rng);
    let peer = SigningKey::generate(&mut rng).verifying_key();
    let op = TrustGraphOp::new_attest(
        op_identity_sk.verifying_key(),
        peer,
        1_700_000_000,
        vec![],
        vec![],
        cairn_trust_graph::Strength::InPerson,
    );
    let signed = SignedTrustGraphOp::sign(op, &device_sk).unwrap();
    let submitter_sk = SigningKey::generate(&mut rng);
    (signed, submitter_sk)
}

/// Recompute the Sigsum Merkle leaf hash for `signed_op` under
/// `submitter_sk` using the crate's own leaf model — byte-identical to
/// what `verify_inclusion` reconstructs from the cached `EmittedLeaf`.
fn merkle_leaf_hash_for(signed_op: &SignedTrustGraphOp, submitter_sk: &SigningKey) -> [u8; 32] {
    let leaf_hash = leaf_hash_for(signed_op).unwrap();
    let tree_leaf = build_tree_leaf(leaf_hash.as_bytes(), submitter_sk).unwrap();
    tree_leaf.merkle_leaf_hash()
}

/// RFC 6962 interior-node hash: `SHA-256(0x01 ‖ left ‖ right)`. The sole
/// Merkle primitive the test owns; everything else comes from the crate.
fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01u8]);
    hasher.update(left);
    hasher.update(right);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

// ===================================================================
// Client + mock-server wiring
// ===================================================================

/// Construct a `SigsumClient` pointed at the mock server with fresh
/// in-memory storage and the supplied retry budget. Trailing slash so
/// `Url::join` resolves against the authority root.
fn make_client(server: &MockServer, log: &TestLog, budget: RetryBudget) -> SigsumClient {
    let provider = InMemoryKeyProvider::new();
    let passphrase = Zeroizing::new(b"test passphrase".to_vec());
    let storage = Arc::new(Storage::open_in_memory(&provider, &passphrase).unwrap());
    let log_url = Url::parse(&format!("{}/", server.uri())).unwrap();
    let config = SigsumClientConfig {
        log_url,
        log_pubkey: log.log_sk.verifying_key(),
        witness_pool: log.pool.clone(),
        default_retry_budget: budget,
    };
    SigsumClient::new(config, storage).unwrap()
}

/// Mount `POST /add-leaf` → 200 so a real `emit_leaf` call seeds the
/// `EmittedLeaf` cache record that `verify_inclusion` consumes.
async fn mount_add_leaf_committed(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/add-leaf"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

/// Mount `GET /get-tree-head` → 200 + `body`.
async fn mount_tree_head(server: &MockServer, body: String) {
    Mock::given(method("GET"))
        .and(path("/get-tree-head"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(server)
        .await;
}

/// Mount `GET /get-inclusion-proof/<size>/<hex>` → `status` + `body`.
async fn mount_inclusion_proof(
    server: &MockServer,
    size: u64,
    merkle_leaf_hash: &[u8; 32],
    status: u16,
    body: String,
) {
    let p = format!(
        "/get-inclusion-proof/{size}/{}",
        lower_hex(merkle_leaf_hash)
    );
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(server)
        .await;
}

/// Emit `signed_op` against the mock `add-leaf` so its `EmittedLeaf`
/// lands in the cache, returning the recomputed Merkle leaf hash the
/// proof fixtures are built around.
async fn emit_and_leaf_hash(
    client: &SigsumClient,
    signed_op: &SignedTrustGraphOp,
    submitter_sk: &SigningKey,
) -> [u8; 32] {
    client
        .emit_leaf(signed_op, submitter_sk)
        .await
        .expect("emit_leaf against a 200 add-leaf must succeed");
    merkle_leaf_hash_for(signed_op, submitter_sk)
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

// ===================================================================
// Acceptance
// ===================================================================

#[tokio::test]
async fn included_in_size_one_tree_uses_local_check() {
    // A size-1 tree includes a leaf iff the leaf hash equals the root
    // (Sigsum spec §3.2) — no get-inclusion-proof is fetched. We
    // advertise a cosigned head whose root IS the leaf's Merkle hash.
    let log = make_test_log();
    let server = MockServer::start().await;
    mount_add_leaf_committed(&server).await;
    let client = make_client(&server, &log, RetryBudget::default());
    let (signed_op, submitter_sk) = make_op_and_submitter();

    let mlh = emit_and_leaf_hash(&client, &signed_op, &submitter_sk).await;
    mount_tree_head(&server, honest_tree_head_body(&log, 1, &mlh)).await;

    let proof = client
        .verify_inclusion(&signed_op)
        .await
        .expect("size-1 root == leaf hash is an inclusion");

    assert_eq!(proof.tree_size, 1);
    assert_eq!(proof.leaf_index, 0);
    assert!(
        proof.proof_nodes.is_empty(),
        "the size-1 local check fetches no audit path"
    );
    // A successful return implies step 5's proof cache write (storage.put)
    // did not error; the InclusionProof CBOR round-trip itself is unit-
    // tested in cache.rs.
}

#[tokio::test]
async fn included_in_multi_leaf_tree_via_rfc6962_proof() {
    // Size-3 tree, target leaf at index 0. RFC 6962 root:
    //   root = H(0x01 ‖ H(0x01 ‖ L0 ‖ L1) ‖ L2)
    // The audit path (leaf→root) is [L1, L2]; L1/L2 are opaque sibling
    // hashes to the verifier, so any 32-byte values serve.
    let log = make_test_log();
    let server = MockServer::start().await;
    mount_add_leaf_committed(&server).await;
    let client = make_client(&server, &log, RetryBudget::default());
    let (signed_op, submitter_sk) = make_op_and_submitter();

    let l0 = emit_and_leaf_hash(&client, &signed_op, &submitter_sk).await;
    let l1 = [0x71u8; 32];
    let l2 = [0x72u8; 32];
    let root = hash_children(&hash_children(&l0, &l1), &l2);

    mount_tree_head(&server, honest_tree_head_body(&log, 3, &root)).await;
    let proof_body = format!(
        "leaf_index=0\nnode_hash={}\nnode_hash={}\n",
        lower_hex(&l1),
        lower_hex(&l2),
    );
    mount_inclusion_proof(&server, 3, &l0, 200, proof_body).await;

    let proof = client
        .verify_inclusion(&signed_op)
        .await
        .expect("a proof reconstructing to the accepted root verifies");

    assert_eq!(proof.tree_size, 3);
    assert_eq!(proof.leaf_index, 0);
    assert_eq!(proof.proof_nodes, vec![l1, l2]);
}

// ===================================================================
// Rejection: inclusion-verify failures
// ===================================================================

#[tokio::test]
async fn size_one_root_mismatch_fails_inclusion() {
    // Size-1 head whose root is NOT the leaf's Merkle hash: the local
    // check must reject without fetching any proof.
    let log = make_test_log();
    let server = MockServer::start().await;
    mount_add_leaf_committed(&server).await;
    let client = make_client(&server, &log, RetryBudget::default());
    let (signed_op, submitter_sk) = make_op_and_submitter();

    let _mlh = emit_and_leaf_hash(&client, &signed_op, &submitter_sk).await;
    // A different root, honestly cosigned (a valid head, wrong leaf).
    mount_tree_head(&server, honest_tree_head_body(&log, 1, &[0xFFu8; 32])).await;

    let err = client.verify_inclusion(&signed_op).await.unwrap_err();
    assert!(
        matches!(err, SigsumError::InclusionProofVerifyFailed),
        "got {err:?}"
    );
}

#[tokio::test]
async fn tampered_proof_node_fails_inclusion() {
    // Size-2 tree, target at index 0; audit path = [sibling]. We
    // advertise the CORRECT root but serve a corrupted sibling so the
    // reconstructed root diverges from the accepted head's root.
    let log = make_test_log();
    let server = MockServer::start().await;
    mount_add_leaf_committed(&server).await;
    let client = make_client(&server, &log, RetryBudget::default());
    let (signed_op, submitter_sk) = make_op_and_submitter();

    let l0 = emit_and_leaf_hash(&client, &signed_op, &submitter_sk).await;
    let sibling = [0x81u8; 32];
    let root = hash_children(&l0, &sibling);

    mount_tree_head(&server, honest_tree_head_body(&log, 2, &root)).await;
    let mut corrupt = sibling;
    corrupt[0] ^= 0xFF;
    let proof_body = format!("leaf_index=0\nnode_hash={}\n", lower_hex(&corrupt));
    mount_inclusion_proof(&server, 2, &l0, 200, proof_body).await;

    let err = client.verify_inclusion(&signed_op).await.unwrap_err();
    assert!(
        matches!(err, SigsumError::InclusionProofVerifyFailed),
        "got {err:?}"
    );
}

#[tokio::test]
async fn empty_log_includes_nothing() {
    // A cosigned size-0 head is structurally accepted by
    // refresh_tree_head (no cached head to split-view against), but an
    // empty tree includes nothing → InclusionProofVerifyFailed.
    let log = make_test_log();
    let server = MockServer::start().await;
    mount_add_leaf_committed(&server).await;
    let client = make_client(&server, &log, RetryBudget::default());
    let (signed_op, submitter_sk) = make_op_and_submitter();

    let _mlh = emit_and_leaf_hash(&client, &signed_op, &submitter_sk).await;
    mount_tree_head(&server, honest_tree_head_body(&log, 0, &[0x00u8; 32])).await;

    let err = client.verify_inclusion(&signed_op).await.unwrap_err();
    assert!(
        matches!(err, SigsumError::InclusionProofVerifyFailed),
        "got {err:?}"
    );
}

// ===================================================================
// Transport + parse failure
// ===================================================================

#[tokio::test]
async fn not_included_proof_404_surfaces_network() {
    // The head is healthy (size 2) so verify_inclusion proceeds to fetch
    // the proof, but get-inclusion-proof 404s ("not included"). With a
    // 1-retry budget the fetch exhausts the budget → Network.
    let log = make_test_log();
    let server = MockServer::start().await;
    mount_add_leaf_committed(&server).await;
    let budget = RetryBudget {
        max_retries: 1,
        initial_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
    };
    let client = make_client(&server, &log, budget);
    let (signed_op, submitter_sk) = make_op_and_submitter();

    let l0 = emit_and_leaf_hash(&client, &signed_op, &submitter_sk).await;
    let root = hash_children(&l0, &[0x91u8; 32]);
    mount_tree_head(&server, honest_tree_head_body(&log, 2, &root)).await;
    mount_inclusion_proof(&server, 2, &l0, 404, String::new()).await;

    let err = client.verify_inclusion(&signed_op).await.unwrap_err();
    assert!(
        matches!(
            err,
            SigsumError::Network {
                retry_budget_used: 1
            }
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn malformed_proof_missing_leaf_index_is_malformed() {
    // A proof body with node_hash lines but no leaf_index is
    // unparseable → MalformedResponse.
    let log = make_test_log();
    let server = MockServer::start().await;
    mount_add_leaf_committed(&server).await;
    let client = make_client(&server, &log, RetryBudget::default());
    let (signed_op, submitter_sk) = make_op_and_submitter();

    let l0 = emit_and_leaf_hash(&client, &signed_op, &submitter_sk).await;
    let root = hash_children(&l0, &[0xA1u8; 32]);
    mount_tree_head(&server, honest_tree_head_body(&log, 2, &root)).await;
    let proof_body = format!("node_hash={}\n", lower_hex(&[0xA1u8; 32]));
    mount_inclusion_proof(&server, 2, &l0, 200, proof_body).await;

    let err = client.verify_inclusion(&signed_op).await.unwrap_err();
    assert!(matches!(err, SigsumError::MalformedResponse), "got {err:?}");
}

// ===================================================================
// Precondition: leaf was never emitted
// ===================================================================

#[tokio::test]
async fn verify_without_emit_is_storage_cache_miss() {
    // verify_inclusion requires the emit-time EmittedLeaf (a recipient
    // cannot recompute the submitter's tree-leaf signature, D0023 §1.4).
    // With nothing emitted, the cache load fails before any network call.
    let log = make_test_log();
    let server = MockServer::start().await;
    let client = make_client(&server, &log, RetryBudget::default());
    let (signed_op, _submitter_sk) = make_op_and_submitter();

    // No get-tree-head / get-inclusion-proof mocks are mounted: the
    // cache miss short-circuits before any network call, so reaching the
    // network would surface a different error than Storage.
    let err = client.verify_inclusion(&signed_op).await.unwrap_err();
    assert!(matches!(err, SigsumError::Storage(_)), "got {err:?}");
}
