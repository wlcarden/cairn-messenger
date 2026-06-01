// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// Same crate-wide allow as cairn-storage: many proper-noun technical
// terms (Sigsum, Ed25519, JSON, TOML, etc.) that would each need
// backticks.
#![allow(clippy::doc_markdown)]

//! # cairn-sigsum-client
//!
//! Sigsum integration per [D0023](../../docs/decisions/D0023-sigsum-integration.md).
//!
//! ## Architectural commitments this crate implements
//!
//! - **Commitment-only logging** (design brief §3.3 + D0006 §3.3):
//!   Sigsum stores SHA-256 hashes of trust-graph operations only;
//!   issuer/subject/context never appear in the public log.
//! - **Leaf hash schema** (D0023 §1):
//!   `leaf_hash = SHA-256(COSE_Sign1.signature_bytes(signed_op))`.
//!   Byte-identical to D0006 §5's `prior_hash` byte input — the same
//!   hash anchors the trust-graph chain integrity AND the Sigsum
//!   commitment.
//! - **Project-owned witness cosignature verification** (D0023 §3):
//!   Ed25519 `verify_strict` against a static `witnesses.toml`
//!   shipped per release. No `sigsum-go` shim; no Go runtime in the
//!   trust path.
//! - **2-of-3 witness acceptance threshold** per D0015 + D0023 §3.4.
//! - **Storage-layer caching** in
//!   [`cairn_storage::categories::SIGSUM_CACHE`] for log heads +
//!   inclusion proofs per D0023 §4.
//! - **Typed errors** per D0018 §4.2 + D0023 §7 — every failure mode
//!   surfaces a typed [`SigsumError`] variant; no `Vec<u8>` payloads
//!   in error bodies.
//!
//! ## Crate structure
//!
//! - [`leaf`] — leaf hash computation per D0023 §1.
//! - [`witness`] — witness pool config + cosignature verification per
//!   D0023 §3.
//! - [`cache`] — log-head + inclusion-proof cache types per D0023 §4.
//! - [`client`] — the `SigsumClient` async surface per D0023 §5.
//! - [`emit`] — combined persist + Sigsum-emit wrapper per D0023 §6.1
//!   (hosted here instead of in `cairn-trust-graph` to avoid the
//!   dependency cycle the literal §6.1 placement would create).
//! - [`verify`] — chain-link + Sigsum-inclusion composed verifier per
//!   D0023 §6.2 (same dependency-direction rationale as `emit`).
//! - [`error`] — typed error enum per D0018 §4.2 + D0023 §7.
//!
//! ## Implementation status
//!
//! The load-bearing primitives are implemented + tested:
//!
//! - Leaf hash composition (pure SHA-256 of envelope signature bytes)
//! - Witness pool parsing + Ed25519 cosignature verification against
//!   the C2SP `tlog-cosignature/v1` signed message (per the corrected
//!   D0023 §3.1 wire format; revision 2026-05-30)
//! - Cache state schema (canonical-CBOR per D0022 §2.4 storage
//!   semantics)
//! - Threshold check (2-of-3 acceptance) per D0023 §3.4
//! - Typed error surface per D0023 §7
//!
//! All three network-bound surfaces are implemented end-to-end and
//! validated by hermetic wiremock harnesses (no `NetworkUnreached`
//! stub remains in the crate):
//!
//! - [`SigsumClient::refresh_tree_head`] — `get-tree-head` fetch,
//!   log-signature verification, the 2-of-3 cosignature threshold,
//!   split-view detection, and a cache write
//!   (`tests/refresh_tree_head_wiremock.rs`).
//! - [`SigsumClient::emit_leaf`] — builds the Sigsum `tree_leaf`, POSTs
//!   `add-leaf` (retrying `202` until `200`), and caches an
//!   [`EmittedLeaf`] (`tests/emit_leaf_wiremock.rs`).
//! - [`SigsumClient::verify_inclusion`] — reconstructs the Merkle leaf
//!   hash from the cached [`EmittedLeaf`], fetches a fresh accepted
//!   head plus `get-inclusion-proof`, verifies the RFC 6962 inclusion
//!   against the head's root, and caches the [`InclusionProof`]
//!   (`tests/verify_inclusion_wiremock.rs`).
//!
//! The `integration-tests` cargo feature flag gates the eventual
//! real-Sigsum network-exercising tests (the wiremock harnesses above
//! run without it).

pub mod cache;
pub mod client;
pub mod emit;
pub mod error;
pub mod leaf;
pub mod verify;
pub mod witness;

pub use cache::{
    EmittedLeaf, InclusionProof, TreeHead, cache_record_id_for_inclusion_proof,
    cache_record_id_for_leaf, cache_record_id_for_log,
};
pub use client::{RetryBudget, SigsumClient, SigsumClientConfig};
pub use emit::{EmissionStatus, EmitOutcome, sigsum_emit};
pub use error::SigsumError;
pub use leaf::{
    LEAF_HASH_LEN, LeafHash, TREE_LEAF_NAMESPACE, TreeLeaf, build_tree_leaf, leaf_hash_for,
};
pub use verify::{VerifyChainWithSigsumError, verify_chain_links_with_sigsum};
pub use witness::{
    MIN_WITNESS_COUNT, REQUIRED_COSIGNATURE_COUNT, Witness, WitnessPool, parse_witness_pool,
    verify_cosignature,
};
