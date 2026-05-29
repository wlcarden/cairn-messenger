// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Typed error surface per D0023 §7 + D0018 §4.2.
//!
//! Discipline: every variant carries indices, lengths, type tags, or
//! small numeric values only. No `Vec<u8>`, no `&[u8]`, no peer-
//! supplied strings in error bodies.

use thiserror::Error;

/// Top-level error type for `cairn-sigsum-client`, re-exported from
/// the crate root.
///
/// `#[non_exhaustive]` per D0018 §4.2.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SigsumError {
    /// Underlying network failure (timeout, connection-reset, HTTP
    /// 5xx) after the retry budget was exhausted. `retry_budget_used`
    /// names how many retries were consumed before giving up.
    #[error("sigsum: network failure after {retry_budget_used} retries")]
    Network {
        /// Number of retries consumed before the error surfaced.
        retry_budget_used: u8,
    },

    /// Placeholder for the network-bound surfaces that aren't
    /// implemented yet. v1 skeleton ships with the testable load-
    /// bearing primitives + this stub; the actual HTTP exercise lands
    /// when CI grows a wiremock harness OR an opt-in integration-test
    /// flag against a real Sigsum log per D0023 §10.
    #[error("sigsum: network surface not yet implemented (v1 skeleton)")]
    NetworkUnreached,

    /// Witness pool config has fewer than 3 entries — D0015 + D0023
    /// §3.4 require a minimum of 3 witnesses for any verification to
    /// proceed.
    #[error("sigsum: witness pool too small: {configured} configured (minimum {minimum})")]
    WitnessPoolTooSmall {
        /// Number of witnesses currently configured.
        configured: u8,
        /// Minimum required per D0023 §3.4.
        minimum: u8,
    },

    /// Witness pool has the right count but fewer than the required
    /// threshold returned valid cosignatures for this tree head.
    #[error(
        "sigsum: insufficient witness cosignatures: {valid} valid (required {required} of {pool_size})"
    )]
    InsufficientWitnessCosignatures {
        /// Cosignatures that verified successfully.
        valid: u8,
        /// Required threshold per D0023 §3.4 (2 of 3).
        required: u8,
        /// Witness pool size.
        pool_size: u8,
    },

    /// A specific witness's cosignature failed Ed25519 verify. The
    /// `witness_index` is the 0-based index into the pool config so
    /// the caller can correlate to the witness's display name without
    /// the witness's pubkey or signature material being in the error
    /// payload.
    #[error("sigsum: cosignature verify failed for witness index {witness_index}")]
    CosignatureVerifyFailed {
        /// Index of the witness in the pool config.
        witness_index: u8,
    },

    /// A fresh tree head's `tree_size` is smaller than the cached
    /// one. Indicates either log split-view or log corruption — halt.
    #[error(
        "sigsum: log tree_size regression: cached {cached_tree_size} > fetched {fetched_tree_size}"
    )]
    LogTreeSizeRegression {
        /// `tree_size` from the cache.
        cached_tree_size: u64,
        /// `tree_size` from the fresh fetch.
        fetched_tree_size: u64,
    },

    /// Two log heads with the same `tree_size` but different
    /// `root_hash`. Pure split-view indicator. Halt.
    #[error("sigsum: log split-view detected at tree_size {tree_size}")]
    LogSplitView {
        /// `tree_size` at which the split-view was detected.
        tree_size: u64,
    },

    /// An inclusion proof does not verify against the accepted tree
    /// head.
    #[error("sigsum: inclusion proof verify failed")]
    InclusionProofVerifyFailed,

    /// A consistency proof from `old_size` to `new_size` does not
    /// verify.
    #[error("sigsum: consistency proof verify failed from tree_size {old_size} to {new_size}")]
    ConsistencyProofVerifyFailed {
        /// Old tree_size.
        old_size: u64,
        /// New tree_size.
        new_size: u64,
    },

    /// Failure from the underlying [`cairn_storage::Storage`] handle.
    #[error("sigsum: storage failure: {0}")]
    Storage(#[from] cairn_storage::StorageError),

    /// Failure encoding a trust-graph op to its on-the-wire form.
    /// Unreachable for envelopes constructed via the public API; the
    /// variant exists so we never `unwrap` on the encode path.
    #[error("sigsum: trust-graph encode failure: {0}")]
    Encode(#[from] cairn_trust_graph::TrustGraphError),

    /// A [`cairn_trust_graph::StoreError`] variant landed that this
    /// build's mapping logic doesn't explicitly cover.
    ///
    /// The trust-graph crate marks `StoreError` `#[non_exhaustive]`
    /// per D0018 §4.2 — a future variant will compile against this
    /// wildcard until an explicit mapping is added in
    /// [`crate::emit`]. The error is intentionally minimal: no
    /// `Vec<u8>` payload, no peer-controlled string — only the type
    /// tag, so the no-error-oracle discipline holds.
    #[error("sigsum: unmapped cairn-trust-graph store error variant")]
    TrustGraphStoreUnknown,

    /// Witness pool config parse failure (malformed TOML, missing
    /// required fields, invalid pubkey hex, invalid URL).
    #[error("sigsum: witness pool config parse failed")]
    WitnessConfigParse,

    /// Sigsum protocol response parse failure (malformed JSON,
    /// malformed cosignature shape, malformed inclusion proof shape).
    #[error("sigsum: malformed response from log endpoint")]
    MalformedResponse,

    /// The cache record didn't deserialize per the schema. Indicates
    /// either schema drift or storage corruption past the AEAD check.
    #[error("sigsum: malformed cache record")]
    MalformedCacheRecord,
}
