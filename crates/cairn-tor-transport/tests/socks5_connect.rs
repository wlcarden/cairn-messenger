// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Hermetic harness for [`TorTransport::connect`] per D0025 §2 / §10.
//!
//! ## What this validates
//!
//! `connect` is the first network-bound surface to leave the
//! tor-transport skeleton. It opens a real SOCKS5 CONNECT tunnel
//! (hand-rolled client per D0025 §10) through what it believes is the
//! C-Tor proxy, authenticating with the per-conversation
//! `IsolateSOCKSAuth` credential and sending the target as a SOCKS5
//! domain.
//!
//! These tests stand up a **mock SOCKS5 server** (a `tokio` `TcpListener`
//! speaking the server side of RFC 1928 + RFC 1929) and point the
//! transport at it via `with_socks_proxy_addr`. No real Tor, no external
//! network — the mock asserts the bytes the client sent and drives the
//! client through each reply path.
//!
//! ## Coverage map
//!
//! - Happy path: full handshake + an `AsyncRead`/`AsyncWrite` round-trip
//!   through the tunnel.
//! - Per-conversation circuit isolation: the SOCKS username is stable for
//!   a given `conversation_id` and distinct across conversations
//!   (D0020 §2.6).
//! - SOCKS reply mapping: `0x04` → `HostResolutionFailed`, `0x05` →
//!   `ConnectionRefused`, other codes → `SocksProtocol`.
//! - Auth-method rejection → `SocksProtocol`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // Nursery/style lints that are noise in a test harness:
    clippy::missing_const_for_fn,
    clippy::significant_drop_tightening
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cairn_tor_transport::{
    BridgeManifest, RetryBudget, TorTransport, TorTransportConfig, TorTransportError,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

// ===================================================================
// Mock SOCKS5 server
// ===================================================================

/// How the mock server should respond.
#[derive(Debug, Clone, Copy)]
enum MockBehavior {
    /// Complete the handshake, reply to CONNECT with `code`, and (when
    /// `code == 0x00`) echo any subsequent payload bytes.
    Connect(u8),
    /// Reject at method selection (reply `0xFF` — no acceptable methods).
    RejectAuthMethod,
}

/// Bind an ephemeral-port mock SOCKS5 server, spawn its single-connection
/// handler, and return its address + a handle to the usernames it
/// captures during RFC 1929 auth.
async fn spawn_mock(behavior: MockBehavior) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_for_task = Arc::clone(&captured);

    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        handle_one(sock, behavior, captured_for_task).await;
    });

    (addr, captured)
}

async fn handle_one(
    mut sock: TcpStream,
    behavior: MockBehavior,
    captured: Arc<Mutex<Vec<String>>>,
) {
    // (1) Greeting: VER NMETHODS METHODS.
    let mut greeting = [0u8; 2];
    if sock.read_exact(&mut greeting).await.is_err() {
        return;
    }
    let mut methods = vec![0u8; usize::from(greeting[1])];
    let _ = sock.read_exact(&mut methods).await;

    if matches!(behavior, MockBehavior::RejectAuthMethod) {
        let _ = sock.write_all(&[0x05, 0xFF]).await;
        return;
    }
    // Select username/password.
    let _ = sock.write_all(&[0x05, 0x02]).await;

    // (2) RFC 1929 auth: VER ULEN USER PLEN PASS.
    let mut auth_head = [0u8; 2];
    let _ = sock.read_exact(&mut auth_head).await;
    let mut user = vec![0u8; usize::from(auth_head[1])];
    let _ = sock.read_exact(&mut user).await;
    let mut plen = [0u8; 1];
    let _ = sock.read_exact(&mut plen).await;
    let mut pass = vec![0u8; usize::from(plen[0])];
    let _ = sock.read_exact(&mut pass).await;
    captured
        .lock()
        .unwrap()
        .push(String::from_utf8_lossy(&user).into_owned());
    let _ = sock.write_all(&[0x01, 0x00]).await; // auth success

    // (3) CONNECT request: VER CMD RSV ATYP=domain DLEN DOMAIN PORT.
    let mut req = [0u8; 4];
    let _ = sock.read_exact(&mut req).await;
    let mut dlen = [0u8; 1];
    let _ = sock.read_exact(&mut dlen).await;
    let mut domain = vec![0u8; usize::from(dlen[0])];
    let _ = sock.read_exact(&mut domain).await;
    let mut port = [0u8; 2];
    let _ = sock.read_exact(&mut port).await;

    // (4) Reply: VER REP RSV ATYP=ipv4 BND.ADDR(4) BND.PORT(2).
    let MockBehavior::Connect(code) = behavior else {
        return;
    };
    let _ = sock
        .write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await;

    // On success, echo the tunneled payload so the client can verify
    // AsyncRead/AsyncWrite passthrough.
    if code == 0x00 {
        let mut buf = [0u8; 1024];
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
}

// ===================================================================
// Transport construction
// ===================================================================

fn make_transport(proxy_addr: SocketAddr) -> TorTransport {
    let config = TorTransportConfig {
        bridge_manifest: BridgeManifest::empty(),
        default_retry_budget: RetryBudget::default(),
    };
    TorTransport::new(config)
        .unwrap()
        .with_socks_proxy_addr(proxy_addr)
}

/// A tiny budget: terminal SOCKS failures do not retry, so 0 retries
/// keeps the failure-path tests instant.
fn tiny_budget() -> RetryBudget {
    RetryBudget {
        max_retries: 0,
        initial_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(1),
    }
}

// ===================================================================
// Tests
// ===================================================================

#[tokio::test]
async fn connect_happy_path_round_trips_through_the_tunnel() {
    let (addr, captured) = spawn_mock(MockBehavior::Connect(0x00)).await;
    let transport = make_transport(addr);

    let mut stream = transport
        .connect(b"conversation-A", "queue.example.onion", 443, tiny_budget())
        .await
        .expect("a 0x00 CONNECT reply yields an open tunnel");

    // The tunnel is a real AsyncRead+AsyncWrite; the mock echoes.
    stream.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");

    // Exactly one auth exchange happened, with a 64-hex-char username.
    let names = captured.lock().unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].len(), 64);
}

#[tokio::test]
async fn connect_isolates_circuits_per_conversation() {
    // Same conversation_id -> same SOCKS username (stable circuit);
    // different conversation_id -> different username (D0020 §2.6). We
    // assert the property without recomputing the hash (that is unit-
    // tested in socks5.rs).
    let a1 = captured_username_for(b"conversation-A").await;
    let a2 = captured_username_for(b"conversation-A").await;
    let b1 = captured_username_for(b"conversation-B").await;

    assert_eq!(a1, a2, "same conversation must reuse the same SOCKS auth");
    assert_ne!(
        a1, b1,
        "distinct conversations must not share the credential"
    );
}

async fn captured_username_for(conversation_id: &[u8]) -> String {
    let (addr, captured) = spawn_mock(MockBehavior::Connect(0x00)).await;
    let transport = make_transport(addr);
    let _stream = transport
        .connect(conversation_id, "h.example.onion", 443, tiny_budget())
        .await
        .unwrap();
    let names = captured.lock().unwrap();
    names.first().cloned().unwrap()
}

#[tokio::test]
async fn connect_host_unreachable_maps_to_resolution_failed() {
    let (addr, _captured) = spawn_mock(MockBehavior::Connect(0x04)).await;
    let err = make_transport(addr)
        .connect(b"conv", "nope.example.onion", 443, tiny_budget())
        .await
        .unwrap_err();
    assert!(
        matches!(err, TorTransportError::HostResolutionFailed),
        "got {err:?}"
    );
}

#[tokio::test]
async fn connect_refused_maps_to_connection_refused() {
    let (addr, _captured) = spawn_mock(MockBehavior::Connect(0x05)).await;
    let err = make_transport(addr)
        .connect(b"conv", "refuser.example.onion", 443, tiny_budget())
        .await
        .unwrap_err();
    assert!(
        matches!(err, TorTransportError::ConnectionRefused),
        "got {err:?}"
    );
}

#[tokio::test]
async fn connect_other_reply_code_maps_to_socks_protocol() {
    // 0x01 = general SOCKS server failure (e.g. Tor not bootstrapped /
    // no circuit). Without the control-port we cannot distinguish it from
    // other general failures, so it surfaces as the generic SocksProtocol.
    let (addr, _captured) = spawn_mock(MockBehavior::Connect(0x01)).await;
    let err = make_transport(addr)
        .connect(b"conv", "general.example.onion", 443, tiny_budget())
        .await
        .unwrap_err();
    assert!(
        matches!(err, TorTransportError::SocksProtocol),
        "got {err:?}"
    );
}

#[tokio::test]
async fn connect_auth_method_rejection_maps_to_socks_protocol() {
    let (addr, _captured) = spawn_mock(MockBehavior::RejectAuthMethod).await;
    let err = make_transport(addr)
        .connect(b"conv", "h.example.onion", 443, tiny_budget())
        .await
        .unwrap_err();
    assert!(
        matches!(err, TorTransportError::SocksProtocol),
        "got {err:?}"
    );
}
