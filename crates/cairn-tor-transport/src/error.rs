// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Typed error surface per D0025 §6 + D0018 §4.2.
//!
//! Discipline: every variant carries indices, lengths, type tags, or
//! small numeric values only. No `Vec<u8>` payloads. No peer-supplied
//! strings. No bridge lines, no peer hostnames, no control-port
//! cookie bytes in error bodies.
//!
//! Per D0025 (re-anchored under D0020 §2), this crate is the Rust-side
//! SOCKS5 + control-port client of the C-Tor `ForegroundService`. The
//! error surface reflects that boundary: loopback connection failures,
//! C-Tor bootstrap state, bridge-manifest bootstrap failures, and
//! control-port protocol errors — NOT an embedded-Tor-implementation
//! surface.

use thiserror::Error;

/// Top-level error type for `cairn-tor-transport`, re-exported from
/// the crate root.
///
/// `#[non_exhaustive]` per D0018 §4.2.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TorTransportError {
    /// Loopback connection to the C-Tor SOCKS proxy (`127.0.0.1:9050`)
    /// or control-port (`127.0.0.1:9051`) failed after the retry
    /// budget was exhausted.
    #[error("tor-transport: loopback connection failure after {retry_budget_used} retries")]
    Network {
        /// Number of retries consumed before the error surfaced.
        retry_budget_used: u8,
    },

    /// Placeholder for the network-bound surfaces that aren't
    /// implemented yet. v1 skeleton ships with the testable load-
    /// bearing primitives + this stub; the SOCKS5 + control-port
    /// client body lands per D0025 §10.
    #[error("tor-transport: network surface not yet implemented (v1 skeleton)")]
    NetworkUnreached,

    /// The C-Tor `ForegroundService` is reachable but Tor bootstrap
    /// has not completed; outbound circuits are not yet available.
    /// The caller should wait for bootstrap or surface a "connecting"
    /// state to the user.
    #[error("tor-transport: C-Tor bootstrap not complete; circuits unavailable")]
    BootstrapIncomplete,

    /// All configured bridges in the manifest failed to bootstrap.
    /// `bridges_attempted` names how many entries in the
    /// release's bridge manifest were tried per D0020 §2.4.
    #[error("tor-transport: all {bridges_attempted} configured bridges failed to bootstrap")]
    AllBridgesFailed {
        /// Number of configured bridges tried.
        bridges_attempted: u8,
    },

    /// A specific bridge in the manifest failed to bootstrap.
    /// `bridge_index` is the 0-based index into the
    /// [`crate::config::BridgeManifest`] so the caller can correlate
    /// to the entry's name without the bridge line itself being in
    /// the error payload.
    #[error("tor-transport: bridge at index {bridge_index} failed to bootstrap")]
    BridgeBootstrapFailed {
        /// 0-based index into [`crate::config::BridgeManifest`].
        bridge_index: u8,
    },

    /// The bridge manifest could not be parsed. Indicates malformed
    /// TOML, a missing required field, or an invalid bridge-line
    /// entry. (Signature + witness verification of the manifest
    /// happens upstream via D0023 + D0024; this variant is the
    /// structural parse failure of an already-verified manifest.)
    #[error("tor-transport: bridge manifest parse failed")]
    BridgeManifestParse,

    /// The control-port returned an error reply or an unexpected
    /// reply shape (`SIGNAL NEWNYM`, bootstrap-status query, or — at
    /// v1.5 — `ADD_ONION`).
    #[error("tor-transport: control-port protocol error")]
    ControlPortProtocol,

    /// The SOCKS5 proxy handshake failed in a way that indicates a
    /// protocol or proxy-configuration problem rather than a target
    /// failure: the proxy rejected username/password auth, returned a
    /// non-zero RFC 1929 auth status, sent malformed/short framing, or
    /// returned a CONNECT reply code other than the recognized
    /// host-unreachable (→ [`Self::HostResolutionFailed`]) / connection-
    /// refused (→ [`Self::ConnectionRefused`]) ones. Distinct from
    /// [`Self::Network`] (a loopback transport failure) and
    /// [`Self::BootstrapIncomplete`] (which the control-port bootstrap-
    /// status query reports precisely; the SOCKS layer cannot).
    #[error("tor-transport: SOCKS5 proxy handshake/protocol error")]
    SocksProtocol,

    /// The supplied `target_host` did not resolve over Tor.
    #[error("tor-transport: target host did not resolve over Tor")]
    HostResolutionFailed,

    /// The Tor connection was refused or reset by the target.
    #[error("tor-transport: target refused the connection")]
    ConnectionRefused,

    /// An open stream was closed mid-operation. `reason` names why
    /// the stream closed so the caller can decide retry policy.
    #[error("tor-transport: stream closed: {reason}")]
    StreamClosed {
        /// The structured close-reason.
        reason: StreamCloseReason,
    },

    /// Onion-service hosting is deferred to v1.5 per D0025 §7 / D0020
    /// §2.8 (C-Tor `ADD_ONION` via control-port). The
    /// `host_onion_service()` method returns this variant in v1 so
    /// consuming code compiles against the eventual API surface
    /// without behavioral surprises.
    #[error("tor-transport: onion-service hosting deferred to v1.5 (D0025 §7 / D0020 §2.8)")]
    OnionServiceHostingDeferred,
}

/// Why an in-flight stream closed.
///
/// `#[non_exhaustive]` per D0018 §4.2. The variants distinguish
/// caller-initiated close from network-driven close from circuit
/// failure so the caller's retry policy can branch appropriately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StreamCloseReason {
    /// Caller explicitly closed the stream.
    #[error("caller close")]
    CallerClose,
    /// Underlying Tor circuit failed (intermediate relay dropped,
    /// circuit timeout, etc.).
    #[error("circuit failure")]
    CircuitFailure,
    /// Network state transitioned to offline mid-stream.
    #[error("network transitioned offline")]
    NetworkTransition,
    /// The remote peer reset the connection.
    #[error("peer reset")]
    PeerReset,
}
