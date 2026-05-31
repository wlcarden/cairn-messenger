// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Hermetic integration harness for [`SigsumClient::refresh_tree_head`]
//! per D0023 §10.
//!
//! ## What this validates
//!
//! `refresh_tree_head` is the first network-bound surface to leave the
//! v1 skeleton. It performs a real `GET /get-tree-head`, parses the
//! Sigsum v1 ASCII response, verifies the log's tree-head signature,
//! verifies witness cosignatures against the C2SP
//! `tlog-cosignature/v1` signed message, applies the 2-of-3 acceptance
//! threshold (D0023 §3.4), runs split-view detection against the cached
//! head, and caches the accepted head.
//!
//! These tests serve a canned `get-tree-head` body from a [`wiremock`]
//! mock server. The fixtures are produced with the crate's OWN
//! [`build_tree_head_note`] / [`build_cosignature_signed_message`] /
//! [`witness_key_hash`] helpers and freshly-generated keys, so the test
//! asserts that the verifier agrees byte-for-byte with the producer
//! side of the same canonical format. No external network, no real
//! Sigsum log, no checked-in key material.
//!
//! ## Coverage map (D0023 §3.4 + §4.1 + §5)
//!
//! - Acceptance: 3-of-3 and the 2-of-3 threshold boundary.
//! - Rejection: 1 valid cosignature is below threshold.
//! - Router correctness: a cosignature from a key NOT in the pool is
//!   silently ignored (its 4-byte key id matches no configured
//!   witness) rather than counted-and-failed.
//! - Partial failure: a corrupted cosignature drops out of the count
//!   while the others still satisfy the threshold.
//! - Log-signature integrity: a tampered `root_hash` makes the pinned
//!   log key's tree-head signature fail → `MalformedResponse`.
//! - Split-view: same `tree_size`, different `root_hash` vs the cached
//!   head → halt. Regression: a smaller `tree_size` → halt. Monotonic
//!   growth is the positive control.
//! - Transport: repeated 5xx exhausts the retry budget → `Network`.
//! - Parse: a missing required field → `MalformedResponse`.

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
    RetryBudget, SigsumClient, SigsumClientConfig, SigsumError, WitnessPool, parse_witness_pool,
};
use cairn_storage::Storage;
use cairn_storage::key_provider::testing::InMemoryKeyProvider;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zeroize::Zeroizing;

// ===================================================================
// Fixtures
// ===================================================================

/// A test witness: its display name (as it appears in `witnesses.toml`,
/// which is the name fed into the C2SP key-id derivation) and its
/// Ed25519 signing key.
struct TestWitness {
    name: String,
    sk: SigningKey,
}

/// A fully-controlled test Sigsum log: the log's own signing key, the
/// three witnesses, and the parsed pool the client will be configured
/// with. The pool's witness names/pubkeys are exactly those in
/// `witnesses` so `witness_key_hash` lines up on both sides.
struct TestLog {
    log_sk: SigningKey,
    witnesses: Vec<TestWitness>,
    pool: WitnessPool,
}

/// One cosignature line to emit into a `get-tree-head` body.
struct CosignEntry<'a> {
    /// Witness display name used for the C2SP key-id derivation.
    name: &'a str,
    /// Key that signs the C2SP message. May be an out-of-pool key to
    /// model an unknown witness.
    sk: &'a SigningKey,
    /// POSIX timestamp written into the `time <ts>` line.
    ts: u64,
    /// When true, flip a byte of the produced signature so it fails to
    /// verify (models a corrupted cosignature).
    corrupt: bool,
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
/// ascending timestamps (so the cached `TreeHead.timestamp` — the max —
/// is deterministic).
fn three_valid(log: &TestLog) -> Vec<CosignEntry<'_>> {
    vec![
        CosignEntry {
            name: &log.witnesses[0].name,
            sk: &log.witnesses[0].sk,
            ts: 1_700_000_100,
            corrupt: false,
        },
        CosignEntry {
            name: &log.witnesses[1].name,
            sk: &log.witnesses[1].sk,
            ts: 1_700_000_200,
            corrupt: false,
        },
        CosignEntry {
            name: &log.witnesses[2].name,
            sk: &log.witnesses[2].sk,
            ts: 1_700_000_300,
            corrupt: false,
        },
    ]
}

/// Build a spec-correct `get-tree-head` ASCII body.
///
/// `advertised_root` is what goes on the `root_hash=` line; `signed_root`
/// is what the log + witnesses actually sign over. They are equal in the
/// honest case; the tamper test deliberately diverges them so the log's
/// tree-head signature fails against the rebuilt note.
fn build_body(
    log: &TestLog,
    tree_size: u64,
    advertised_root: &[u8; 32],
    signed_root: &[u8; 32],
    cosigns: &[CosignEntry<'_>],
) -> String {
    let log_pubkey = log.log_sk.verifying_key();
    let log_key_hash = sha256(&log_pubkey.to_bytes());
    // The bytes the log + each witness sign over: the checkpoint note.
    let signed_note = build_tree_head_note(&log_key_hash, tree_size, signed_root);
    let log_sig = log.log_sk.sign(&signed_note).unwrap();

    let mut body = String::new();
    body.push_str(&format!("size={tree_size}\n"));
    body.push_str(&format!("root_hash={}\n", lower_hex(advertised_root)));
    body.push_str(&format!("signature={}\n", lower_hex(&log_sig.to_bytes())));
    for c in cosigns {
        let key_hash = witness_key_hash(c.name, &c.sk.verifying_key());
        let msg = build_cosignature_signed_message(c.ts, &signed_note);
        let mut sig = c.sk.sign(&msg).unwrap().to_bytes();
        if c.corrupt {
            sig[0] ^= 0xFF;
        }
        body.push_str(&format!(
            "cosignature={} {} {}\n",
            lower_hex(&key_hash),
            c.ts,
            lower_hex(&sig),
        ));
    }
    body
}

/// Honest body: the log + witnesses sign over the same root they
/// advertise.
fn honest_body(
    log: &TestLog,
    tree_size: u64,
    root: &[u8; 32],
    cosigns: &[CosignEntry<'_>],
) -> String {
    build_body(log, tree_size, root, root, cosigns)
}

/// Construct a `SigsumClient` pointed at the mock server, with a fresh
/// in-memory storage and the supplied retry budget.
fn make_client(server: &MockServer, log: &TestLog, budget: RetryBudget) -> SigsumClient {
    let provider = InMemoryKeyProvider::new();
    let passphrase = Zeroizing::new(b"test passphrase".to_vec());
    let storage = Arc::new(Storage::open_in_memory(&provider, &passphrase).unwrap());
    // Trailing slash so `Url::join("get-tree-head")` resolves against
    // the authority root rather than replacing a path segment.
    let log_url = Url::parse(&format!("{}/", server.uri())).unwrap();
    let config = SigsumClientConfig {
        log_url,
        log_pubkey: log.log_sk.verifying_key(),
        witness_pool: log.pool.clone(),
        default_retry_budget: budget,
    };
    SigsumClient::new(config, storage).unwrap()
}

/// Mount a single `GET /get-tree-head` → 200 + `body` mock.
async fn mount_ok(server: &MockServer, body: String) {
    Mock::given(method("GET"))
        .and(path("/get-tree-head"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(server)
        .await;
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

/// Collect the accepted witness indices in sorted order for assertions.
fn sorted_indices(head: &cairn_sigsum_client::TreeHead) -> Vec<u8> {
    let mut idxs: Vec<u8> = head.cosignatures.iter().map(|c| c.witness_index).collect();
    idxs.sort_unstable();
    idxs
}

// ===================================================================
// Acceptance
// ===================================================================

#[tokio::test]
async fn accept_three_valid_cosignatures() {
    let log = make_test_log();
    let server = MockServer::start().await;
    let root = [0x11u8; 32];
    let cosigns = three_valid(&log);
    mount_ok(&server, honest_body(&log, 5, &root, &cosigns)).await;

    let client = make_client(&server, &log, RetryBudget::default());
    let head = client
        .refresh_tree_head()
        .await
        .expect("3-of-3 cosignatures must be accepted");

    assert_eq!(head.tree_size, 5);
    assert_eq!(head.root_hash, root);
    assert_eq!(head.cosignatures.len(), 3);
    assert_eq!(sorted_indices(&head), vec![0, 1, 2]);
    // The cached head's timestamp is the freshest cosignature time.
    assert_eq!(head.timestamp, 1_700_000_300);
}

#[tokio::test]
async fn accept_exactly_two_cosignatures_at_threshold() {
    let log = make_test_log();
    let server = MockServer::start().await;
    let root = [0x22u8; 32];
    // Only W0 + W1 cosign — exactly the 2-of-3 threshold.
    let cosigns = vec![
        CosignEntry {
            name: &log.witnesses[0].name,
            sk: &log.witnesses[0].sk,
            ts: 1_700_000_100,
            corrupt: false,
        },
        CosignEntry {
            name: &log.witnesses[1].name,
            sk: &log.witnesses[1].sk,
            ts: 1_700_000_200,
            corrupt: false,
        },
    ];
    mount_ok(&server, honest_body(&log, 8, &root, &cosigns)).await;

    let client = make_client(&server, &log, RetryBudget::default());
    let head = client
        .refresh_tree_head()
        .await
        .expect("2-of-3 meets the acceptance threshold");

    assert_eq!(head.cosignatures.len(), 2);
    assert_eq!(sorted_indices(&head), vec![0, 1]);
}

// ===================================================================
// Rejection: threshold + verification failures
// ===================================================================

#[tokio::test]
async fn reject_single_cosignature_below_threshold() {
    let log = make_test_log();
    let server = MockServer::start().await;
    let root = [0x33u8; 32];
    let cosigns = vec![CosignEntry {
        name: &log.witnesses[0].name,
        sk: &log.witnesses[0].sk,
        ts: 1_700_000_100,
        corrupt: false,
    }];
    mount_ok(&server, honest_body(&log, 3, &root, &cosigns)).await;

    let client = make_client(&server, &log, RetryBudget::default());
    let err = client.refresh_tree_head().await.unwrap_err();

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

#[tokio::test]
async fn unknown_witness_cosignature_is_ignored() {
    let log = make_test_log();
    let server = MockServer::start().await;
    let root = [0x44u8; 32];
    // A stranger key that is NOT in the configured pool. Its 4-byte
    // key id will match no configured witness, so it is skipped — it
    // must NOT push the valid count to 3.
    let stranger = SigningKey::generate(&mut OsRng);
    let cosigns = vec![
        CosignEntry {
            name: &log.witnesses[0].name,
            sk: &log.witnesses[0].sk,
            ts: 1_700_000_100,
            corrupt: false,
        },
        CosignEntry {
            name: &log.witnesses[1].name,
            sk: &log.witnesses[1].sk,
            ts: 1_700_000_200,
            corrupt: false,
        },
        CosignEntry {
            name: "Stranger",
            sk: &stranger,
            ts: 1_700_000_900,
            corrupt: false,
        },
    ];
    mount_ok(&server, honest_body(&log, 9, &root, &cosigns)).await;

    let client = make_client(&server, &log, RetryBudget::default());
    let head = client
        .refresh_tree_head()
        .await
        .expect("two in-pool cosignatures still satisfy threshold");

    // Exactly the two in-pool witnesses count; the stranger is dropped.
    assert_eq!(head.cosignatures.len(), 2);
    assert_eq!(sorted_indices(&head), vec![0, 1]);
    // The stranger's fresher timestamp must not leak into the head.
    assert_eq!(head.timestamp, 1_700_000_200);
}

#[tokio::test]
async fn corrupt_cosignature_is_not_counted() {
    let log = make_test_log();
    let server = MockServer::start().await;
    let root = [0x55u8; 32];
    // W1's signature is corrupted; W0 + W2 remain valid → still 2.
    let cosigns = vec![
        CosignEntry {
            name: &log.witnesses[0].name,
            sk: &log.witnesses[0].sk,
            ts: 1_700_000_100,
            corrupt: false,
        },
        CosignEntry {
            name: &log.witnesses[1].name,
            sk: &log.witnesses[1].sk,
            ts: 1_700_000_200,
            corrupt: true,
        },
        CosignEntry {
            name: &log.witnesses[2].name,
            sk: &log.witnesses[2].sk,
            ts: 1_700_000_300,
            corrupt: false,
        },
    ];
    mount_ok(&server, honest_body(&log, 6, &root, &cosigns)).await;

    let client = make_client(&server, &log, RetryBudget::default());
    let head = client
        .refresh_tree_head()
        .await
        .expect("the two intact cosignatures satisfy threshold");

    assert_eq!(head.cosignatures.len(), 2);
    // W1 (index 1) is dropped; W0 + W2 survive.
    assert_eq!(sorted_indices(&head), vec![0, 2]);
}

#[tokio::test]
async fn tampered_root_hash_fails_log_signature() {
    let log = make_test_log();
    let server = MockServer::start().await;
    // The log signs over root A but the body advertises root B. The
    // client rebuilds the note from B and the pinned log key's
    // signature (over A) fails → MalformedResponse, before any
    // cosignature is even examined.
    let signed_root = [0x11u8; 32];
    let advertised_root = [0x22u8; 32];
    let cosigns = three_valid(&log);
    let body = build_body(&log, 5, &advertised_root, &signed_root, &cosigns);
    mount_ok(&server, body).await;

    let client = make_client(&server, &log, RetryBudget::default());
    let err = client.refresh_tree_head().await.unwrap_err();

    assert!(matches!(err, SigsumError::MalformedResponse), "got {err:?}");
}

// ===================================================================
// Split-view detection (requires a cached head from a first refresh)
// ===================================================================

#[tokio::test]
async fn split_view_same_size_different_root_halts() {
    let log = make_test_log();
    let server = MockServer::start().await;
    let client = make_client(&server, &log, RetryBudget::default());

    // First refresh: size 10, root A — accepted + cached.
    let root_a = [0xA1u8; 32];
    let cosigns = three_valid(&log);
    mount_ok(&server, honest_body(&log, 10, &root_a, &cosigns)).await;
    let head1 = client
        .refresh_tree_head()
        .await
        .expect("first head accepted");
    assert_eq!(head1.tree_size, 10);
    assert_eq!(head1.root_hash, root_a);

    // Conflicting head at the SAME size with a DIFFERENT root — a pure
    // split-view indicator. Must halt.
    server.reset().await;
    let root_b = [0xB2u8; 32];
    mount_ok(&server, honest_body(&log, 10, &root_b, &cosigns)).await;
    let err = client.refresh_tree_head().await.unwrap_err();

    assert!(
        matches!(err, SigsumError::LogSplitView { tree_size: 10 }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn tree_size_regression_halts() {
    let log = make_test_log();
    let server = MockServer::start().await;
    let client = make_client(&server, &log, RetryBudget::default());

    let cosigns = three_valid(&log);
    mount_ok(&server, honest_body(&log, 10, &[0xC1u8; 32], &cosigns)).await;
    client
        .refresh_tree_head()
        .await
        .expect("first head accepted");

    // A smaller tree_size on the next fetch indicates split-view or
    // corruption. Must halt with the cached vs fetched sizes.
    server.reset().await;
    mount_ok(&server, honest_body(&log, 7, &[0xC2u8; 32], &cosigns)).await;
    let err = client.refresh_tree_head().await.unwrap_err();

    assert!(
        matches!(
            err,
            SigsumError::LogTreeSizeRegression {
                cached_tree_size: 10,
                fetched_tree_size: 7,
            }
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn monotonic_growth_is_accepted() {
    // Positive control for the split-view path: an honest log that
    // grows (size up, new root) must be accepted, not flagged.
    let log = make_test_log();
    let server = MockServer::start().await;
    let client = make_client(&server, &log, RetryBudget::default());

    let cosigns = three_valid(&log);
    mount_ok(&server, honest_body(&log, 5, &[0xD1u8; 32], &cosigns)).await;
    client
        .refresh_tree_head()
        .await
        .expect("first head accepted");

    server.reset().await;
    let root2 = [0xD2u8; 32];
    mount_ok(&server, honest_body(&log, 9, &root2, &cosigns)).await;
    let head2 = client
        .refresh_tree_head()
        .await
        .expect("monotonic growth must be accepted");

    assert_eq!(head2.tree_size, 9);
    assert_eq!(head2.root_hash, root2);
}

// ===================================================================
// Parse + transport failure
// ===================================================================

#[tokio::test]
async fn missing_signature_field_is_malformed() {
    let log = make_test_log();
    let server = MockServer::start().await;
    let cosigns = three_valid(&log);
    // Strip the `signature=` line so the parser cannot find the log
    // tree-head signature.
    let full = honest_body(&log, 5, &[0xEEu8; 32], &cosigns);
    let mut stripped = String::new();
    for l in full.lines() {
        if !l.starts_with("signature=") {
            stripped.push_str(l);
            stripped.push('\n');
        }
    }
    mount_ok(&server, stripped).await;

    let client = make_client(&server, &log, RetryBudget::default());
    let err = client.refresh_tree_head().await.unwrap_err();

    assert!(matches!(err, SigsumError::MalformedResponse), "got {err:?}");
}

#[tokio::test]
async fn network_failure_surfaces_after_retry_budget() {
    let log = make_test_log();
    let server = MockServer::start().await;
    // Always 503. With a 1-retry budget the client tries attempt 0,
    // sleeps, retries as attempt 1, then surfaces Network.
    Mock::given(method("GET"))
        .and(path("/get-tree-head"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let budget = RetryBudget {
        max_retries: 1,
        initial_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
    };
    let client = make_client(&server, &log, budget);
    let err = client.refresh_tree_head().await.unwrap_err();

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
