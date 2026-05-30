// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// Same crate-wide allow as cairn-storage + cairn-sigsum-client +
// cairn-sigstore-verify: many proper-noun technical terms (Tor,
// Arti, OIDC, SOCKS5, DPI, Briar, etc.) that would each need
// backticks.
#![allow(clippy::doc_markdown)]

//! # cairn-tor-transport
//!
//! Tor transport per [D0025](../../docs/decisions/D0025-cairn-tor-transport.md).
//!
//! ## Architectural commitments this crate implements
//!
//! - **Arti embedded as a pure-Rust in-process library** per
//!   D0025 §1. No subprocess; no FFI; no C Tor binary. Same audit
//!   boundary as the rest of the workspace.
//! - **Outbound circuit construction at v1** per D0025 §2. Client
//!   connects to (hostname | .onion v3 address) and returns a
//!   `TorStream`. Onion-service hosting is the v1.5 Briar
//!   architectural slot per D0025 §7.
//! - **Pluggable transports via release-bundled `pluggable_-
//!   transports.toml`** per D0025 §3. Same release-coordinated
//!   rotation posture as the witness pool per D0023 §3.3.
//! - **Network-state observation cascade** per D0025 §4. Android
//!   shell signals `observe_network_state(Online | Offline |
//!   Constrained)` to drive bootstrap + circuit lifecycle.
//! - **`RetryBudget` reuse from `cairn-sigsum-client`** per
//!   D0025 §5.1 + D0023 §5.3. Same type, same defaults, same
//!   caller-scoping discipline across the workspace's async I/O
//!   surface.
//! - **Typed errors** per D0018 §4.2 + D0025 §6. No `Vec<u8>`
//!   payloads, no peer-supplied strings, no bridge lines or
//!   certificates in error bodies. Arti's upstream errors are
//!   converted via internal `From` impls that discard the original
//!   payload (per D0025 §6.2's no-error-oracle posture).
//!
//! ## Crate structure
//!
//! - [`config`] — `PluggableTransportConfig` + TOML parser per
//!   D0025 §3.
//! - [`transport`] — `TorTransport` async handle per D0025 §1 + §5.
//! - [`error`] — typed error enum per D0018 §4.2 + D0025 §6.
//!
//! ## Implementation status (v1 skeleton)
//!
//! The load-bearing primitives are implemented + tested:
//!
//! - `PluggableTransportConfig` TOML round-trip per D0025 §3
//! - `TorTransport::new` constructor wiring the config + retry
//!   budget + the observed network state
//! - `TorTransport::observe_network_state` real state tracking per
//!   D0025 §4
//! - `TorTransport::current_network_state` + accessor methods
//! - Typed `TorTransportError` surface per D0025 §6
//!
//! The network-bound surfaces ([`transport::TorTransport::connect`],
//! [`transport::TorTransport::host_onion_service`]) are present as
//! async method signatures but their bodies return their typed
//! deferral errors pending the Arti integration body landing per
//! D0025 §10 step 5. The `integration-tests` cargo feature flag
//! gates the eventual network-exercising tests; v1 skeleton ships
//! without them. The Arti workspace pin is similarly deferred per
//! D0025 §1.4 + §10 step 4 so the skeleton's dep surface stays
//! minimal.

pub mod config;
pub mod error;
pub mod transport;

pub use cairn_sigsum_client::RetryBudget;

pub use config::{
    PluggableTransportConfig, PluggableTransportEntry, parse_pluggable_transport_config,
};
pub use error::{StreamCloseReason, TorTransportError};
pub use transport::{
    NetworkState, OnionServiceConfig, OnionServiceHandle, TorStream, TorTransport,
    TorTransportConfig,
};
