// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Offline harness for [`SigsumClient::verify_bundled_inclusion`] per
//! D0023 §5 + D0024 §6.4.
//!
//! ## What this validates
//!
//! `verify_bundled_inclusion` is the air-gapped, third-party-proof
//! counterpart to `verify_inclusion`: a party that never emitted the
//! leaf verifies a transmitted proof bundle (the emit-time
//! [`EmittedLeaf`] tree-leaf components + the raw `get-tree-head` and
//! `get-inclusion-proof` bodies) against the pinned log key + witness
//! pool, with NO network and NO cache. These tests therefore need no
//! `wiremock` server — they call the sync verify method directly.
//!
//! Fixtures are produced with the crate's OWN `build_tree_leaf` +
//! `build_tree_head_note` / `build_cosignature_signed_message` /
//! `witness_key_hash` producers and freshly-generated keys, so the test
//! asserts the verifier agrees byte-for-byte with the producer side.
//!
//! ## Coverage map
//!
//! - Acceptance: size-1 local check; multi-leaf (size 3) RFC 6962 proof.
//! - Rejection: leaf-hash binding mismatch; tampered log root (log-sig
//!   failure); below-threshold cosignatures; tampered proof node; the
//!   empty (size-0) log.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;

use cairn_crypto::ed25519::SigningKey;
use cairn_sigsum_client::witness::{
    build_cosignature_signed_message, build_tree_head_note, witness_key_hash,
};
use cairn_sigsum_client::{
    EmittedLeaf, LeafHash, RetryBudget, SigsumClient, SigsumClientConfig, SigsumError, WitnessPool,
    build_tree_leaf, parse_witness_pool,
};
use cairn_storage::Storage;
use cairn_storage::key_provider::testing::InMemoryKeyProvider;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

// ===================================================================
// Fixtures
// ===================================================================

struct TestWitness {
    name: String,
    sk: SigningKey,
}

struct TestLog {
    log_sk: SigningKey,
    witnesses: Vec<TestWitness>,
    pool: WitnessPool,
}

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

/// Build a `get-tree-head` body where the log + the first `num_cosigners`
/// witnesses sign over `signed_root`, while the body advertises
/// `advertised_root`. In the honest case the two roots are equal; the
/// log-signature-failure test diverges them.
fn tree_head_body(
    log: &TestLog,
    size: u64,
    advertised_root: &[u8; 32],
    signed_root: &[u8; 32],
    num_cosigners: usize,
) -> String {
    let log_key_hash = sha256(&log.log_sk.verifying_key().to_bytes());
    let note = build_tree_head_note(&log_key_hash, size, signed_root);
    let log_sig = log.log_sk.sign(&note).unwrap();

    let mut body = String::new();
    body.push_str(&format!("size={size}\n"));
    body.push_str(&format!("root_hash={}\n", lower_hex(advertised_root)));
    body.push_str(&format!("signature={}\n", lower_hex(&log_sig.to_bytes())));
    for (i, w) in log.witnesses.iter().take(num_cosigners).enumerate() {
        let ts = 1_700_000_100 + i as u64;
        let key_hash = witness_key_hash(&w.name, &w.sk.verifying_key());
        let msg = build_cosignature_signed_message(ts, &note);
        let sig = w.sk.sign(&msg).unwrap().to_bytes();
        body.push_str(&format!(
            "cosignature={} {} {}\n",
            lower_hex(&key_hash),
            ts,
            lower_hex(&sig),
        ));
    }
    body
}

/// Honest body: advertised == signed, all three witnesses cosign.
fn honest_body(log: &TestLog, size: u64, root: &[u8; 32]) -> String {
    tree_head_body(log, size, root, root, 3)
}

/// Construct an offline client (in-memory storage, dummy log URL — never
/// dialed because `verify_bundled_inclusion` makes no network calls).
fn make_client(log: &TestLog) -> SigsumClient {
    let provider = InMemoryKeyProvider::new();
    let passphrase = Zeroizing::new(b"test passphrase".to_vec());
    let storage = Arc::new(Storage::open_in_memory(&provider, &passphrase).unwrap());
    let config = SigsumClientConfig {
        log_url: Url::parse("https://offline.invalid/").unwrap(),
        log_pubkey: log.log_sk.verifying_key(),
        witness_pool: log.pool.clone(),
        default_retry_budget: RetryBudget::default(),
    };
    SigsumClient::new(config, storage).unwrap()
}

/// Build the transmitted [`EmittedLeaf`] for `message` under a fresh
/// submitter key, returning it + its Merkle leaf hash + the bound
/// [`LeafHash`].
fn make_emitted(message: [u8; 32]) -> (EmittedLeaf, [u8; 32], LeafHash) {
    let submitter_sk = SigningKey::generate(&mut OsRng);
    let tl = build_tree_leaf(&message, &submitter_sk).unwrap();
    let emitted = EmittedLeaf {
        message,
        signature: tl.signature,
        key_hash: tl.key_hash,
        observed_at: 0,
    };
    (
        emitted,
        tl.merkle_leaf_hash(),
        LeafHash::from_bytes(message),
    )
}

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

#[test]
fn included_size_one_local_check() {
    let log = make_test_log();
    let client = make_client(&log);
    let (emitted, mlh, leaf_hash) = make_emitted([0x42u8; 32]);

    let head = honest_body(&log, 1, &mlh);
    let verified = client
        .verify_bundled_inclusion(&leaf_hash, &emitted, &head, "")
        .expect("size-1 root == leaf hash is an inclusion");
    assert_eq!(verified.tree_size, 1);
    assert_eq!(verified.cosignatures.len(), 3);
}

#[test]
fn included_multi_leaf_rfc6962_proof() {
    let log = make_test_log();
    let client = make_client(&log);
    let (emitted, l0, leaf_hash) = make_emitted([0x01u8; 32]);
    let l1 = [0x71u8; 32];
    let l2 = [0x72u8; 32];
    let root = hash_children(&hash_children(&l0, &l1), &l2);

    let head = honest_body(&log, 3, &root);
    let proof = format!(
        "leaf_index=0\nnode_hash={}\nnode_hash={}\n",
        lower_hex(&l1),
        lower_hex(&l2),
    );

    let verified = client
        .verify_bundled_inclusion(&leaf_hash, &emitted, &head, &proof)
        .expect("a proof reconstructing to the cosigned root verifies");
    assert_eq!(verified.tree_size, 3);
    assert_eq!(verified.root_hash, root);
}

// ===================================================================
// Rejection
// ===================================================================

#[test]
fn binding_mismatch_fails_before_head() {
    // The transmitted emitted-leaf is for message A, but the caller binds
    // against message B (e.g. a different release manifest). Must reject.
    let log = make_test_log();
    let client = make_client(&log);
    let (emitted, mlh, _real_leaf_hash) = make_emitted([0x11u8; 32]);
    let wrong_leaf_hash = LeafHash::from_bytes([0x22u8; 32]);

    let head = honest_body(&log, 1, &mlh);
    let err = client
        .verify_bundled_inclusion(&wrong_leaf_hash, &emitted, &head, "")
        .unwrap_err();
    assert!(
        matches!(err, SigsumError::InclusionProofVerifyFailed),
        "got {err:?}"
    );
}

#[test]
fn tampered_log_root_fails_log_signature() {
    // The log signs over root A; the body advertises root B. The rebuilt
    // note (from B) makes the pinned log key's signature (over A) fail.
    let log = make_test_log();
    let client = make_client(&log);
    let (emitted, _mlh, leaf_hash) = make_emitted([0x33u8; 32]);

    let signed_root = [0xAAu8; 32];
    let advertised_root = [0xBBu8; 32];
    let head = tree_head_body(&log, 5, &advertised_root, &signed_root, 3);
    let err = client
        .verify_bundled_inclusion(&leaf_hash, &emitted, &head, "leaf_index=0\n")
        .unwrap_err();
    assert!(matches!(err, SigsumError::MalformedResponse), "got {err:?}");
}

#[test]
fn below_threshold_cosignatures_rejected() {
    // Only one witness cosigns — below the 2-of-3 acceptance threshold.
    let log = make_test_log();
    let client = make_client(&log);
    let (emitted, mlh, leaf_hash) = make_emitted([0x44u8; 32]);

    let head = tree_head_body(&log, 1, &mlh, &mlh, 1);
    let err = client
        .verify_bundled_inclusion(&leaf_hash, &emitted, &head, "")
        .unwrap_err();
    assert!(
        matches!(
            err,
            SigsumError::InsufficientWitnessCosignatures {
                valid: 1,
                required: 2,
                pool_size: 3,
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn tampered_proof_node_fails_inclusion() {
    // Size-2 tree, target at index 0; advertise the correct root but
    // serve a corrupted sibling so reconstruction diverges.
    let log = make_test_log();
    let client = make_client(&log);
    let (emitted, l0, leaf_hash) = make_emitted([0x55u8; 32]);
    let sibling = [0x81u8; 32];
    let root = hash_children(&l0, &sibling);

    let head = honest_body(&log, 2, &root);
    let mut corrupt = sibling;
    corrupt[0] ^= 0xFF;
    let proof = format!("leaf_index=0\nnode_hash={}\n", lower_hex(&corrupt));
    let err = client
        .verify_bundled_inclusion(&leaf_hash, &emitted, &head, &proof)
        .unwrap_err();
    assert!(
        matches!(err, SigsumError::InclusionProofVerifyFailed),
        "got {err:?}"
    );
}

#[test]
fn empty_log_includes_nothing() {
    let log = make_test_log();
    let client = make_client(&log);
    let (emitted, _mlh, leaf_hash) = make_emitted([0x66u8; 32]);

    let head = honest_body(&log, 0, &[0x00u8; 32]);
    let err = client
        .verify_bundled_inclusion(&leaf_hash, &emitted, &head, "")
        .unwrap_err();
    assert!(
        matches!(err, SigsumError::InclusionProofVerifyFailed),
        "got {err:?}"
    );
}
