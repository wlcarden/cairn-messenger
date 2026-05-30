// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Typed error surface per D0026 §9 + D0018 §4.2.
//!
//! Discipline per the no-error-oracle principle (D0018 §1.4):
//! every variant carries indices, lengths, type tags, or small
//! numeric values only. Bounded counters from the SMP spec
//! (message numbers) appear in diagnostic variants but NO ciphertext
//! bytes, key bytes, plaintext bytes, or peer-supplied strings
//! appear in error payloads.
//!
//! Variants split by failure layer per D0026 §9.2:
//!
//! - **Transport-layer**: `TransportError`, `Network`
//! - **Protocol-layer**: `SmpProtocolViolation`, `QueueNotFound`
//! - **Ratchet-layer**: `RatchetOutOfSync`
//! - **Envelope-layer**: `EnvelopeSignatureVerifyFailed`,
//!   `EnvelopeDecodeFailed`, `EnvelopeDomainTagMismatch`,
//!   `EnvelopeChainGap`
//! - **Storage-layer**: `Storage`
//! - **Padding-layer**: `PaddingMalformed`
//!
//! This mirrors D0024 §7's split-by-layer discipline.

use thiserror::Error;

/// Top-level error type for `cairn-simplex-adapter`, re-exported
/// from the crate root.
///
/// `#[non_exhaustive]` per D0018 §4.2.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SimplexAdapterError {
    /// Underlying network failure after the retry budget was
    /// exhausted.
    #[error("simplex-adapter: network failure after {retry_budget_used} retries")]
    Network {
        /// Number of retries consumed before the error surfaced.
        retry_budget_used: u8,
    },

    /// Placeholder for the network-bound surfaces that aren't
    /// implemented yet. v1 skeleton stubs to this; the SMP body
    /// lands when CI grows a local-SMP-server harness per D0026
    /// §12.
    #[error("simplex-adapter: network surface not yet implemented (v1 skeleton)")]
    NetworkUnreached,

    /// The named SMP queue was not found on the server.
    #[error("simplex-adapter: SMP queue not found on server")]
    QueueNotFound,

    /// The ratchet state could not advance. Indicates either a
    /// wire-protocol error (the ciphertext was not the next-expected
    /// message number) OR a decryption failure under the chain key.
    /// Recovery: out-of-band re-key with the peer per the SimpleX
    /// double-ratchet derivative spec.
    #[error(
        "simplex-adapter: ratchet out of sync: expected msg #{expected_message_number}, observed #{observed_message_number}"
    )]
    RatchetOutOfSync {
        /// The next-expected message number per the local ratchet
        /// state.
        expected_message_number: u64,
        /// The message number the wire ciphertext claimed.
        observed_message_number: u64,
    },

    /// The peer's `prior_envelope_hash` chain has a gap — an
    /// envelope is missing between the last-observed and the
    /// current one. Indicates either a delivery failure (the
    /// missing envelope will arrive later) or chain-tampering.
    #[error(
        "simplex-adapter: envelope chain gap: last observed msg #{last_observed_message_number}, current #{observed_message_number}"
    )]
    EnvelopeChainGap {
        /// The last in-order message number this client observed.
        last_observed_message_number: u64,
        /// The message number the just-received envelope claims.
        observed_message_number: u64,
    },

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

    /// Padding was malformed — the wire payload was smaller than
    /// the bucket-size or the bucket-size was unknown.
    #[error("simplex-adapter: padding malformed")]
    PaddingMalformed,

    /// The SMP server returned an unexpected response shape.
    #[error("simplex-adapter: SMP protocol violation")]
    SmpProtocolViolation,

    /// Storage failure for ratchet state or message history.
    #[error("simplex-adapter: storage failure: {0}")]
    Storage(#[from] cairn_storage::StorageError),

    /// Trust-graph envelope encode/decode failure — surfaced for
    /// the device key + capability token verification path.
    #[error("simplex-adapter: trust-graph envelope failure: {0}")]
    Envelope(#[from] cairn_trust_graph::TrustGraphError),

    /// Underlying Tor transport failure. Carries the wrapped Tor
    /// error so the caller can distinguish bootstrap / connection /
    /// stream-close failure modes.
    #[error("simplex-adapter: tor transport failure: {0}")]
    TransportError(#[from] cairn_tor_transport::TorTransportError),
}
