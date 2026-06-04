// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Hermetic integration harness for [`SigsumClient::emit_leaf`] per
//! D0023 §5 + the Sigsum v1 `add-leaf` spec (§3.5).
//!
//! `emit_leaf` builds the Sigsum `tree_leaf` (`checksum` + submitter
//! `signature` + `key_hash`), POSTs `add-leaf` to the log, and caches an
//! [`EmittedLeaf`] record. These tests serve a mock Sigsum `add-leaf`
//! endpoint via [`wiremock`] and assert:
//!
//! - `200 OK` → emit succeeds, returns Cairn's leaf hash, and the
//!   `EmittedLeaf` cache record is written + round-trips (message =
//!   leaf hash).
//! - persistent `202 Accepted` (never committed) → after the retry
//!   budget, `Network` (the caller defers per §6.1).
//! - persistent `503` → after the retry budget, `Network`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::time::Duration;

use cairn_crypto::ed25519::SigningKey;
use cairn_sigsum_client::{
    EmittedLeaf, RetryBudget, SigsumClient, SigsumClientConfig, SigsumError,
    cache_record_id_for_leaf, parse_witness_pool,
};
use cairn_storage::key_provider::testing::InMemoryKeyProvider;
use cairn_storage::{Storage, categories};
use cairn_trust_graph::{SignedTrustGraphOp, TrustGraphOp};
use rand_core::OsRng;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zeroize::Zeroizing;

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

fn open_storage() -> Arc<Storage> {
    let provider = InMemoryKeyProvider::new();
    let passphrase = Zeroizing::new(b"test passphrase".to_vec());
    Arc::new(Storage::open_in_memory(&provider, &passphrase).unwrap())
}

fn make_client(server: &MockServer, storage: Arc<Storage>, budget: RetryBudget) -> SigsumClient {
    let pool = parse_witness_pool(&make_witness_pool_toml(3)).unwrap();
    let log_pubkey = SigningKey::generate(&mut OsRng).verifying_key();
    let log_url = Url::parse(&format!("{}/", server.uri())).unwrap();
    let config = SigsumClientConfig {
        log_url,
        log_pubkey,
        witness_pool: pool,
        default_retry_budget: budget,
    };
    SigsumClient::new(config, storage).unwrap()
}

/// A signed op + the operational-identity key acting as Sigsum
/// submitter.
fn make_signed_op() -> (SignedTrustGraphOp, SigningKey) {
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
    (signed, op_identity_sk)
}

const fn tiny_budget() -> RetryBudget {
    RetryBudget {
        max_retries: 1,
        initial_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
    }
}

async fn mount_add_leaf(server: &MockServer, status: u16) {
    Mock::given(method("POST"))
        .and(path("/add-leaf"))
        .respond_with(ResponseTemplate::new(status))
        .mount(server)
        .await;
}

#[tokio::test]
async fn emit_leaf_accepts_200_and_caches_the_emitted_leaf() {
    let server = MockServer::start().await;
    mount_add_leaf(&server, 200).await;
    let storage = open_storage();
    let client = make_client(&server, Arc::clone(&storage), RetryBudget::default());
    let (signed_op, submitter_sk) = make_signed_op();

    let leaf = client
        .emit_leaf(&signed_op, &submitter_sk)
        .await
        .expect("a 200 add-leaf response must succeed");

    // The EmittedLeaf cache record was written and round-trips.
    let record_id = cache_record_id_for_leaf(client.log_url(), &leaf);
    let bytes = storage
        .get(categories::SIGSUM_CACHE, &record_id)
        .expect("emitted-leaf cache record must exist");
    let record = EmittedLeaf::from_canonical_cbor(&bytes).unwrap();
    // The cached message is exactly Cairn's leaf hash (the submitted
    // message); its tree_leaf checksum is SHA-256(message).
    assert_eq!(&record.message, leaf.as_bytes());
    assert_eq!(record.tree_leaf().merkle_leaf_hash().len(), 32);
}

#[tokio::test]
async fn emit_leaf_defers_on_persistent_202() {
    // 202 Accepted means "received, not yet committed"; if the log never
    // returns 200, emit exhausts the budget and surfaces Network so the
    // caller defers per §6.1.
    let server = MockServer::start().await;
    mount_add_leaf(&server, 202).await;
    let storage = open_storage();
    let client = make_client(&server, storage, tiny_budget());
    let (signed_op, submitter_sk) = make_signed_op();

    let err = client
        .emit_leaf(&signed_op, &submitter_sk)
        .await
        .unwrap_err();
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
async fn emit_leaf_surfaces_network_after_5xx_budget() {
    let server = MockServer::start().await;
    mount_add_leaf(&server, 503).await;
    let storage = open_storage();
    let client = make_client(&server, storage, tiny_budget());
    let (signed_op, submitter_sk) = make_signed_op();

    let err = client
        .emit_leaf(&signed_op, &submitter_sk)
        .await
        .unwrap_err();
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
