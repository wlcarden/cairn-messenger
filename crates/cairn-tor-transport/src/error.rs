// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Typed error surface per D0025 §6 + D0018 §4.2.
//!
//! Discipline: every variant carries indices, lengths, type tags, or
//! small numeric values only. No `Vec<u8>` payloads. No peer-supplied
//! strings. No bridge lines, no peer hostnames, no certificate bytes
//! in error bodies.
//!
//! Upstream Arti errors are NOT directly wrapped. Per D0025 §6.2,
//! the conversion is intentional: Arti's `Display` output may
//! include peer-controlled metadata that the no-error-oracle
//! discipline forbids. Each Arti error variant maps to a typed
//! [`TorTransportError`] variant via an internal `From` impl that
//! discards the original payload.

use thiserror::Error;

/// Top-level error type for `cairn-tor-transport`, re-exported from
/// the crate root.
///
/// `#[non_exhaustive]` per D0018 §4.2.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TorTransportError {
    /// Underlying network failure (timeout, no-route-to-host) after
    /// the retry budget was exhausted. `retry_budget_used` names how
    /// many retries were consumed before giving up.
    #[error("tor-transport: network failure after {retry_budget_used} retries")]
    Network {
        /// Number of retries consumed before the error surfaced.
        retry_budget_used: u8,
    },

    /// Placeholder for the network-bound surfaces that aren't
    /// implemented yet. v1 skeleton ships with the testable load-
    /// bearing primitives + this stub; the actual Arti exercise
    /// lands when CI grows the integration harness per D0025 §10.
    #[error("tor-transport: network surface not yet implemented (v1 skeleton)")]
    NetworkUnreached,

    /// The Arti client bootstrap did not complete within the
    /// budget. `retry_budget_used` names how many bootstrap retries
    /// were consumed before giving up.
    #[error("tor-transport: bootstrap did not complete after {retry_budget_used} retries")]
    BootstrapFailed {
        /// Number of bootstrap retries consumed.
        retry_budget_used: u8,
    },

    /// All configured pluggable transports failed to bootstrap.
    /// `transports_attempted` names how many entries in the
    /// release's `pluggable_transports.toml` were tried.
    #[error(
        "tor-transport: all {transports_attempted} configured pluggable transports failed to bootstrap"
    )]
    AllPluggableTransportsFailed {
        /// Number of configured transports tried.
        transports_attempted: u8,
    },

    /// A specific named pluggable transport failed to bootstrap.
    /// `transport_index` is the 0-based index into the configured
    /// list so the caller can correlate to the entry's name without
    /// the bridge line itself being in the error payload.
    #[error("tor-transport: pluggable transport at index {transport_index} failed to bootstrap")]
    PluggableTransportBootstrapFailed {
        /// 0-based index into [`crate::config::PluggableTransportConfig`].
        transport_index: u8,
    },

    /// The `pluggable_transports.toml` config could not be parsed.
    /// Indicates malformed TOML, missing required fields, or invalid
    /// bridge-line syntax.
    #[error("tor-transport: pluggable_transports.toml parse failed")]
    PluggableTransportConfigParse,

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

    /// Onion-service hosting is deferred to v1.5 per D0025 §7.
    /// The `host_onion_service()` method returns this variant in v1
    /// so consuming code compiles against the eventual API surface
    /// without behavioral surprises.
    #[error("tor-transport: onion-service hosting deferred to v1.5 (D0025 §7)")]
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
