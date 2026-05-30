// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Typed error surface per D0026 §9 + D0018 §4.2 (re-anchored under
//! D0020 §1: the SimplOxide-sidecar model).
//!
//! Discipline per the no-error-oracle principle (D0018 §1.4): every
//! variant carries indices, lengths, type tags, or small numeric
//! values only. No ciphertext bytes, key bytes, plaintext bytes, or
//! peer-supplied strings appear in error payloads. Bounded counters
//! from the envelope chain (message numbers) appear in the diagnostic
//! `EnvelopeChainGap` variant.
//!
//! Variants split by failure layer per D0026 §9.2:
//!
//! - **Sidecar-layer** (talking to SimplOxide / the CLI sidecar):
//!   `Network`, `SidecarUnavailable`, `SidecarProtocol`,
//!   `ConnectionNotFound`
//! - **Envelope-layer** (Cairn's application envelope):
//!   `EnvelopeSignatureVerifyFailed`, `EnvelopeDecodeFailed`,
//!   `EnvelopeDomainTagMismatch`, `EnvelopeChainGap`
//! - **Padding-layer**: `PaddingMalformed`
//! - **Storage-layer**: `Storage`
//!
//! ## What changed vs. the original (project-owned SMP) error surface
//!
//! Removed: `RatchetOutOfSync`, `SmpProtocolViolation`,
//! `QueueNotFound`, and `TransportError(TorTransportError)` — those
//! were artifacts of Cairn owning the SMP wire + ratchet + a direct
//! Tor connection. In the corrected model SimpleX/SimplOxide owns the
//! ratchet + the SMP wire, and the CLI sidecar owns its own Tor
//! routing per D0020 §1-§2. Added: `SidecarUnavailable`,
//! `SidecarProtocol`, `ConnectionNotFound` — the failure modes of
//! talking to SimplOxide over loopback WebSocket.

use thiserror::Error;

/// Top-level error type for `cairn-simplex-adapter`, re-exported from
/// the crate root.
///
/// `#[non_exhaustive]` per D0018 §4.2.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SimplexAdapterError {
    /// Loopback WebSocket to the SimpleX Chat CLI sidecar failed
    /// after the retry budget was exhausted.
    #[error("simplex-adapter: sidecar WebSocket failure after {retry_budget_used} retries")]
    Network {
        /// Number of retries consumed before the error surfaced.
        retry_budget_used: u8,
    },

    /// Placeholder for the network-bound surfaces that aren't
    /// implemented yet. v1 skeleton stubs to this; the SimplOxide-
    /// client body lands when CI grows a local SimpleX Chat CLI
    /// harness per D0026 §12.
    #[error("simplex-adapter: network surface not yet implemented (v1 skeleton)")]
    NetworkUnreached,

    /// The SimpleX Chat CLI sidecar is not reachable on
    /// `127.0.0.1:5225` (the `ForegroundService` is not started, or
    /// the child process died). Distinct from `Network` so the caller
    /// can prompt the Android shell to restart the
    /// `ForegroundService` per D0020 §1.6.
    #[error("simplex-adapter: CLI sidecar unavailable on 127.0.0.1:5225")]
    SidecarUnavailable,

    /// SimplOxide returned an error reply or an unexpected reply
    /// shape from the CLI sidecar.
    #[error("simplex-adapter: SimplOxide / CLI sidecar protocol error")]
    SidecarProtocol,

    /// The named connection was not found by the sidecar (the queue
    /// was deleted, never established, or the ConnectionId is stale).
    #[error("simplex-adapter: connection not found by the sidecar")]
    ConnectionNotFound,

    /// The Cairn envelope's signature did not verify against the
    /// peer's operational identity. Indicates either tamper or the
    /// peer's device-key rotation Cairn has not yet observed.
    #[error("simplex-adapter: envelope signature did not verify")]
    EnvelopeSignatureVerifyFailed,

    /// The Cairn envelope's canonical-CBOR decode failed.
    #[error("simplex-adapter: envelope canonical-CBOR decode failed")]
    EnvelopeDecodeFailed,

    /// The Cairn envelope's AAD domain tag was not
    /// `cairn-v1-message-envelope` per D0006 §8 — cross-protocol
    /// substitution attempt rejected.
    #[error("simplex-adapter: envelope AAD domain tag did not match cairn-v1-message-envelope")]
    EnvelopeDomainTagMismatch,

    /// The peer's `prior_envelope_hash` chain has a gap — an envelope
    /// is missing between the last-observed and the current one.
    /// Indicates either a delivery failure (the missing envelope will
    /// arrive later) or chain-tampering.
    #[error(
        "simplex-adapter: envelope chain gap: last observed msg #{last_observed_message_number}, current #{observed_message_number}"
    )]
    EnvelopeChainGap {
        /// The last in-order message number this client observed.
        last_observed_message_number: u64,
        /// The message number the just-received envelope claims.
        observed_message_number: u64,
    },

    /// Padding was malformed — the wire payload was smaller than the
    /// bucket-size or the bucket-size was unknown.
    #[error("simplex-adapter: padding malformed")]
    PaddingMalformed,

    /// Storage failure for Cairn message history.
    #[error("simplex-adapter: storage failure: {0}")]
    Storage(#[from] cairn_storage::StorageError),

    /// Trust-graph envelope encode/decode failure — surfaced for the
    /// device key + capability token verification path.
    #[error("simplex-adapter: trust-graph envelope failure: {0}")]
    Envelope(#[from] cairn_trust_graph::TrustGraphError),
}
