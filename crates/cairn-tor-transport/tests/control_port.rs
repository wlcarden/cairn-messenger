// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Hermetic harness for the control-port client per D0025 §1.1 / §4.
//!
//! ## What this validates
//!
//! `signal_newnym`, `bootstrap_phase`, and `observe_network_state`'s
//! `Offline → Online` NEWNYM side effect speak the Tor control protocol
//! (SAFECOOKIE auth + `SIGNAL NEWNYM` / `GETINFO status/bootstrap-phase`)
//! against a **mock control-port server** (a `tokio` `TcpListener`
//! speaking the server side). The mock computes the SAFECOOKIE hashes the
//! same way the client does (HMAC-SHA256 via `hkdf::Hkdf::<Sha256>::
//! extract`), so a wrong client hash, a wrong server hash, or an auth
//! rejection each exercise the real failure paths. No real Tor, no
//! external network.
//!
//! ## Coverage map
//!
//! - `signal_newnym` happy path (full SAFECOOKIE handshake + `250 OK`).
//! - `bootstrap_phase` parses `PROGRESS=`.
//! - `observe_network_state` issues NEWNYM on `Offline → Online` and NOT
//!   on a same-state (no-edge) call.
//! - Server-hash mismatch + auth rejection → `ControlPortProtocol`.
//! - Control-port unreachable → `Network`.
//! - No cookie path configured → NEWNYM skipped (`Ok`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_const_for_fn,
    clippy::significant_drop_tightening,
    // hex digits are 0–15, so the u32→u8 cast in from_hex_32 cannot truncate.
    clippy::cast_possible_truncation
)]

use std::net::SocketAddr;
use std::path::PathBuf;

use cairn_tor_transport::{
    BridgeManifest, NetworkState, RetryBudget, TorTransport, TorTransportConfig, TorTransportError,
};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

const SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const CLIENT_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";
const SERVER_NONCE: [u8; 32] = [0x99u8; 32];

// ===================================================================
// Crypto + hex helpers (mirror the client side)
// ===================================================================

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let (prk, _hkdf) = Hkdf::<Sha256>::extract(Some(key), msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn from_hex_32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64);
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16).unwrap() as u8;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16).unwrap() as u8;
        *slot = (hi << 4) | lo;
    }
    out
}

// ===================================================================
// Mock control-port server
// ===================================================================

#[derive(Debug, Clone, Copy)]
enum Behavior {
    /// Authenticate, then reply `250 OK` to the command (SIGNAL NEWNYM).
    Newnym,
    /// Authenticate, then reply with a `GETINFO` bootstrap line at `progress`.
    Bootstrap(u8),
    /// Reply `515` to AUTHENTICATE (auth rejected).
    AuthReject,
    /// Send a bogus SERVERHASH so the client's verification fails.
    WrongServerHash,
}

async fn spawn_mock(cookie: [u8; 32], behavior: Behavior) -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        handle(sock, cookie, behavior).await;
    });
    addr
}

async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> String {
    let mut buf = Vec::new();
    reader.read_until(b'\n', &mut buf).await.unwrap();
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
    String::from_utf8(buf).unwrap()
}

async fn handle(mut sock: TcpStream, cookie: [u8; 32], behavior: Behavior) {
    let (read_half, mut write_half) = sock.split();
    let mut reader = BufReader::new(read_half);

    // (1) AUTHCHALLENGE SAFECOOKIE <hex(client_nonce)>.
    let challenge = read_line(&mut reader).await;
    let client_nonce = from_hex_32(challenge.rsplit(' ').next().unwrap());

    let mut msg = Vec::new();
    msg.extend_from_slice(&cookie);
    msg.extend_from_slice(&client_nonce);
    msg.extend_from_slice(&SERVER_NONCE);

    let server_hash = if matches!(behavior, Behavior::WrongServerHash) {
        [0u8; 32]
    } else {
        hmac_sha256(SERVER_KEY, &msg)
    };
    write_half
        .write_all(
            format!(
                "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                to_hex(&server_hash),
                to_hex(&SERVER_NONCE),
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    if matches!(behavior, Behavior::WrongServerHash) {
        return; // the client rejects + never sends AUTHENTICATE
    }

    // (2) AUTHENTICATE <hex(client_hash)>.
    let auth = read_line(&mut reader).await;
    let client_hash = from_hex_32(auth.rsplit(' ').next().unwrap());
    let expected = hmac_sha256(CLIENT_KEY, &msg);
    if matches!(behavior, Behavior::AuthReject) || client_hash != expected {
        let _ = write_half.write_all(b"515 Bad authentication\r\n").await;
        return;
    }
    write_half.write_all(b"250 OK\r\n").await.unwrap();

    // (3) The command.
    let _cmd = read_line(&mut reader).await;
    let reply = match behavior {
        Behavior::Bootstrap(progress) => format!(
            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS={progress} TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n"
        ),
        _ => "250 OK\r\n".to_string(),
    };
    write_half.write_all(reply.as_bytes()).await.unwrap();
}

// ===================================================================
// Cookie + transport construction
// ===================================================================

/// Write a fresh 32-byte cookie to a unique temp file; return its path +
/// the bytes (shared with the mock).
fn write_cookie() -> (PathBuf, [u8; 32]) {
    let mut cookie = [0u8; 32];
    getrandom::getrandom(&mut cookie).unwrap();
    let mut suffix = [0u8; 8];
    getrandom::getrandom(&mut suffix).unwrap();
    let path = std::env::temp_dir().join(format!("cairn-ctrl-cookie-{}.bin", to_hex(&suffix)));
    std::fs::write(&path, cookie).unwrap();
    (path, cookie)
}

fn make_transport(control_addr: SocketAddr, cookie_path: PathBuf) -> TorTransport {
    let config = TorTransportConfig {
        bridge_manifest: BridgeManifest::empty(),
        default_retry_budget: RetryBudget::default(),
    };
    TorTransport::new(config)
        .unwrap()
        .with_control_port_addr(control_addr)
        .with_control_cookie_path(cookie_path)
}

// ===================================================================
// Tests
// ===================================================================

#[tokio::test]
async fn signal_newnym_completes_safecookie_handshake() {
    let (cookie_path, cookie) = write_cookie();
    let addr = spawn_mock(cookie, Behavior::Newnym).await;
    let transport = make_transport(addr, cookie_path);
    transport
        .signal_newnym()
        .await
        .expect("SAFECOOKIE auth + SIGNAL NEWNYM must succeed");
}

#[tokio::test]
async fn bootstrap_phase_parses_progress() {
    let (cookie_path, cookie) = write_cookie();
    let addr = spawn_mock(cookie, Behavior::Bootstrap(100)).await;
    let transport = make_transport(addr, cookie_path);
    let phase = transport.bootstrap_phase().await.unwrap();
    assert_eq!(phase, 100);
}

#[tokio::test]
async fn observe_offline_to_online_issues_newnym() {
    let (cookie_path, cookie) = write_cookie();
    let addr = spawn_mock(cookie, Behavior::Newnym).await;
    let transport = make_transport(addr, cookie_path);

    // Online -> Offline is NOT the NEWNYM edge (no control call); the mock
    // accepts exactly one connection, used by the Offline -> Online edge.
    transport
        .observe_network_state(NetworkState::Offline)
        .await
        .unwrap();
    transport
        .observe_network_state(NetworkState::Online)
        .await
        .expect("Offline -> Online must issue NEWNYM and succeed");
    assert_eq!(
        transport.current_network_state().unwrap(),
        NetworkState::Online
    );
}

#[tokio::test]
async fn observe_same_state_makes_no_control_call() {
    // Cookie path is set but the control addr points at a closed port. A
    // no-edge transition (Online -> Online) must NOT touch the control
    // port, so this succeeds despite the unreachable address.
    let (cookie_path, _cookie) = write_cookie();
    let dead = SocketAddr::from(([127, 0, 0, 1], 1));
    let transport = make_transport(dead, cookie_path);
    transport
        .observe_network_state(NetworkState::Online)
        .await
        .expect("a no-edge transition must not dial the control port");
}

#[tokio::test]
async fn server_hash_mismatch_is_control_port_protocol() {
    let (cookie_path, cookie) = write_cookie();
    let addr = spawn_mock(cookie, Behavior::WrongServerHash).await;
    let transport = make_transport(addr, cookie_path);
    let err = transport.signal_newnym().await.unwrap_err();
    assert!(
        matches!(err, TorTransportError::ControlPortProtocol),
        "got {err:?}"
    );
}

#[tokio::test]
async fn auth_rejection_is_control_port_protocol() {
    let (cookie_path, cookie) = write_cookie();
    let addr = spawn_mock(cookie, Behavior::AuthReject).await;
    let transport = make_transport(addr, cookie_path);
    let err = transport.signal_newnym().await.unwrap_err();
    assert!(
        matches!(err, TorTransportError::ControlPortProtocol),
        "got {err:?}"
    );
}

#[tokio::test]
async fn unreachable_control_port_is_network() {
    // Cookie file is readable, but no control port is listening at :1.
    let (cookie_path, _cookie) = write_cookie();
    let dead = SocketAddr::from(([127, 0, 0, 1], 1));
    let transport = make_transport(dead, cookie_path);
    let err = transport.signal_newnym().await.unwrap_err();
    assert!(
        matches!(err, TorTransportError::Network { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn signal_newnym_without_cookie_path_is_skipped() {
    // No cookie path configured -> NEWNYM is a no-op even with a dead
    // control address (it is never dialed).
    let config = TorTransportConfig {
        bridge_manifest: BridgeManifest::empty(),
        default_retry_budget: RetryBudget::default(),
    };
    let transport = TorTransport::new(config)
        .unwrap()
        .with_control_port_addr(SocketAddr::from(([127, 0, 0, 1], 1)));
    transport
        .signal_newnym()
        .await
        .expect("no cookie path -> NEWNYM skipped");
}
