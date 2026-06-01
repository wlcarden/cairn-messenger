// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Live two-party integration test against running `simplex-chat` CLI daemons
//! (D0026 §12 step 7 — the live-validation gate).
//!
//! This is the end-to-end proof that `SimplexAdapter<SimploxideTransport>`
//! drives a real Cairn envelope over real SimpleX/XFTP: build → sign → pad →
//! `CryptoFile` upload on send, and XFTP download → verify → unpad → chain
//! check on recv. It complements the hermetic `sidecar::mock_ws_tests` (which
//! pin the connection/RPC/event machinery) by exercising the actual
//! simplex-chat v6.5.2 wire protocol.
//!
//! **Gated twice**: behind the `integration-tests` cargo feature (so it is
//! never compiled into the default build / CI per D0026 §12) AND `#[ignore]`
//! (so even `--features integration-tests` skips it unless `--ignored` is
//! passed) — it requires external daemons + relay access.
//!
//! ## Running
//!
//! ```bash
//! # 1. Fetch the CLI (per-ABI native asset; see D0020 §1.1):
//! #    github.com/simplex-chat/simplex-chat releases -> simplex-chat-<os>-<arch>
//! # 2. Create two profiles + start two WS-server daemons:
//! printf 'alice\n' | simplex-chat -d ./alice -y -e /user
//! printf 'bob\n'   | simplex-chat -d ./bob   -y -e /user
//! simplex-chat -d ./alice -p 5225 -y &
//! simplex-chat -d ./bob   -p 5226 -y &
//! # 3. Run (allow a minute+ for the relay handshake + XFTP transfer):
//! cargo test -p cairn-simplex-adapter --features integration-tests \
//!     -- --ignored --nocapture live_two_party_envelope_round_trip
//! ```

#![cfg(feature = "integration-tests")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "an integration test: expect/panic ARE the failure signal"
)]

use std::sync::Arc;
use std::time::Duration;

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, SigningKey, VerifyingKey};
use cairn_simplex_adapter::{
    EnvelopeSigner, LocalIdentity, RetryBudget, SidecarEndpoint, SimplexAdapter,
    SimplexAdapterConfig, SimploxideTransport,
};
use cairn_storage::Storage;
use cairn_storage::key_provider::testing::InMemoryKeyProvider;
use tokio::time::timeout;
use zeroize::Zeroizing;

/// One party: its adapter over a live daemon, its operational pubkey, and its
/// device verifying key (the peer needs both to `recv`).
fn party(
    port: u16,
    seed: u8,
) -> (
    SimplexAdapter<SimploxideTransport>,
    [u8; PUBLIC_KEY_LEN],
    VerifyingKey,
) {
    let device = SigningKey::from_seed(&Zeroizing::new([seed; 32]));
    let device_vk = device.verifying_key();
    let operational_pubkey = [seed ^ 0xAA; PUBLIC_KEY_LEN];
    let device_signer: Arc<dyn EnvelopeSigner> = Arc::new(device);

    let provider = InMemoryKeyProvider::new();
    let passphrase = Zeroizing::new(b"cairn-live-it".to_vec());
    let storage = Arc::new(Storage::open_in_memory(&provider, &passphrase).expect("storage"));

    let config = SimplexAdapterConfig {
        identity: LocalIdentity {
            device_signer,
            operational_pubkey,
        },
        storage,
        default_retry_budget: RetryBudget::default(),
    };
    let transport = SimploxideTransport::new(SidecarEndpoint {
        host: "127.0.0.1".to_string(),
        port,
    });
    let adapter = SimplexAdapter::new(transport, config).expect("adapter");
    (adapter, operational_pubkey, device_vk)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires two running simplex-chat daemons (5225/5226) + relay access"]
async fn live_two_party_envelope_round_trip() {
    let (alice, alice_op, alice_vk) = party(5225, 0x11);
    let (bob, bob_op, _bob_vk) = party(5226, 0x22);

    // 1. Establish the connection (relay-mediated; allow a generous handshake).
    let invitation = alice.create_invitation().await.expect("create_invitation");
    let bob_conn = timeout(Duration::from_secs(90), bob.accept_invitation(invitation))
        .await
        .expect("accept_invitation timed out")
        .expect("accept_invitation");
    let alice_conn = timeout(Duration::from_secs(90), alice.await_connection())
        .await
        .expect("await_connection timed out")
        .expect("await_connection");

    // 2. Send a Cairn envelope alice -> bob (signed + padded, CryptoFile/XFTP).
    let payload = b"cairn live envelope round-trip over real SimpleX + XFTP";
    timeout(
        Duration::from_secs(60),
        alice.send(&alice_conn, &bob_op, payload),
    )
    .await
    .expect("send timed out")
    .expect("send");

    // 3. Receive + verify on bob (waits for the XFTP download to complete).
    let received = timeout(
        Duration::from_secs(150),
        bob.recv(&bob_conn, &alice_op, &alice_vk),
    )
    .await
    .expect("recv timed out")
    .expect("recv");

    assert_eq!(
        received.payload, payload,
        "payload must survive the round-trip"
    );
    assert_eq!(
        received.sender_operational_pubkey, alice_op,
        "recv must bind the envelope to alice's operational identity"
    );
}
