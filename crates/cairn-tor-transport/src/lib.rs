// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// Same crate-wide allow as cairn-storage + cairn-sigsum-client +
// cairn-sigstore-verify: many proper-noun technical terms (Tor,
// Arti, OIDC, SOCKS5, DPI, Briar, etc.) that would each need
// backticks.
#![allow(clippy::doc_markdown)]

//! # cairn-tor-transport
//!
//! Tor transport per [D0025](../../docs/decisions/D0025-cairn-tor-transport.md),
//! re-anchored under [D0020](../../docs/decisions/D0020-integration-architecture.md)
//! §2: the Rust-side SOCKS5 + control-port client of the C-Tor
//! `ForegroundService`. This crate does NOT embed a Tor
//! implementation — C-Tor via `guardianproject/tor-android` is the
//! D0020 §2 decision; Arti is deferred per D0020 §2.7's gating events.
//!
//! ## Architectural commitments this crate implements
//!
//! - **SOCKS5 + control-port client of the C-Tor `ForegroundService`**
//!   per D0025 §1 / D0020 §2. SOCKS5 to `127.0.0.1:9050` for
//!   messaging; control-port `127.0.0.1:9051` (cookie auth) for
//!   circuit management. No `unsafe_code`; the `libtor.so` JNI
//!   wrapper is Android-shell code, not this crate.
//! - **Per-conversation circuit isolation** per D0025 §2 / D0020 §2.6.
//!   `connect(conversation_id, ...)` sets the SOCKS5 username to
//!   `hash(conversation_id)` with `IsolateSOCKSAuth`.
//! - **Bridge manifest** per D0025 §3 / D0020 §2.4. Parses the
//!   already-verified remote-updateable signed manifest (Lyrebird
//!   bundle: obfs4 + WebTunnel + Snowflake + meek). Manifest fetch,
//!   signature verification, and witness-cosignature checks compose
//!   D0024 + D0023 (out of crate scope).
//! - **Network-state observation cascade** per D0025 §4 / D0020 §2.9.
//!   Android shell signals `observe_network_state(Online | Offline |
//!   Constrained)`; `Offline → Online` issues `SIGNAL NEWNYM`.
//! - **`RetryBudget` reuse from `cairn-sigsum-client`** per
//!   D0025 §5.1 + D0023 §5.3.
//! - **Typed errors** per D0018 §4.2 + D0025 §6. No `Vec<u8>`
//!   payloads, no peer-supplied strings, no bridge lines or
//!   control-port cookie bytes in error bodies.
//!
//! ## Crate structure
//!
//! - [`config`] — `BridgeManifest` + TOML parser per D0025 §3.
//! - [`transport`] — `TorTransport` async handle per D0025 §1 + §5.
//! - [`error`] — typed error enum per D0018 §4.2 + D0025 §6.
//!
//! ## Implementation status
//!
//! [`transport::TorTransport::connect`] is **implemented**: a real SOCKS5
//! CONNECT tunnel through the C-Tor proxy via a hand-rolled, pure-safe-
//! Rust SOCKS5 client (RFC 1928 + RFC 1929; NO third-party SOCKS pin —
//! D0025 §10 revised 2026-05-31), carrying the per-conversation
//! `IsolateSOCKSAuth` credential (`hex(SHA-256(conversation_id))`) and
//! sending the target as a SOCKS5 domain so it resolves over Tor. The
//! returned `TorStream` is `AsyncRead + AsyncWrite` over the tunnel.
//! Validated by `tests/socks5_connect.rs` against a hermetic mock SOCKS5
//! server.
//!
//! Also implemented + tested:
//!
//! - `BridgeManifest` TOML round-trip per D0025 §3.
//! - `TorTransport::new` wiring the manifest + retry budget + the SOCKS
//!   proxy address + observed network state.
//! - `TorTransport::observe_network_state` +
//!   `TorTransport::current_network_state` per D0025 §4.
//! - Typed `TorTransportError` surface per D0025 §6.
//!
//! Remaining follow-ups: the control-port client (`127.0.0.1:9051`,
//! cookie auth) for `SIGNAL NEWNYM` on `Offline → Online` + bootstrap-
//! status queries, and onion-service hosting
//! ([`transport::TorTransport::host_onion_service`], a v1.5 slot per
//! D0025 §7). The `integration-tests` cargo feature flag still gates the
//! eventual real-C-Tor network tests.

pub mod config;
pub mod error;
pub mod transport;

/// Internal hand-rolled SOCKS5 CONNECT client (D0025 §2 / §10).
/// Crate-visible (`pub(crate)`) so [`transport`] can call it, but not part
/// of the public surface — the public entry point is
/// [`transport::TorTransport::connect`].
pub(crate) mod socks5;

pub use cairn_sigsum_client::RetryBudget;

pub use config::{BridgeEntry, BridgeManifest, parse_bridge_manifest};
pub use error::{StreamCloseReason, TorTransportError};
pub use transport::{
    NetworkState, OnionServiceConfig, OnionServiceHandle, TorStream, TorTransport,
    TorTransportConfig,
};
