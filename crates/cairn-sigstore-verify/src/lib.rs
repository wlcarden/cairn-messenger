// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// Same crate-wide allow as cairn-storage + cairn-sigsum-client:
// many proper-noun technical terms (Sigstore, Fulcio, Rekor, OIDC,
// SLSA, etc.) that would each need backticks.
#![allow(clippy::doc_markdown)]

//! # cairn-sigstore-verify
//!
//! Release-artifact identity verification per
//! [D0024](../../docs/decisions/D0024-sigstore-release-verification.md).
//!
//! ## Architectural commitments this crate implements
//!
//! - **Pinned OIDC identity model** per D0024 §1: the verifier
//!   checks the Fulcio-issued signing certificate's embedded
//!   `iss` + `email` claims against per-release pinned values
//!   bundled in the release config.
//! - **Pinned Fulcio CA root** per D0024 §2: no runtime fetch of
//!   the Fulcio trust bundle. Coordinated root rotation across
//!   releases, same posture as the witness pool per D0023 §3.3.
//! - **Project-owned Rekor verifier** per D0024 §3: inclusion
//!   proof + signed checkpoint verify against a pinned Rekor
//!   public key, no `sigstore-rs` shim in the security-critical
//!   path.
//! - **Canonical-CBOR `ReleaseManifest` per D0024 §4 +
//!   D0018 §2.3**: version, per-artifact sha256, build-provenance
//!   sha256, release timestamp, `prior_release_hash` for rollback
//!   resistance.
//! - **Sigstore + Sigsum composition per D0024 §5**:
//!   `release_leaf_hash = SHA-256(COSE_Sign1.signature_bytes(signed_manifest))` —
//!   byte-identical to D0023 §1's trust-graph leaf hash schema.
//!   Cross-log cross-checkability between Rekor + Sigsum.
//! - **Typed errors** per D0018 §4.2 + D0024 §7 — every failure
//!   surfaces a typed [`SigstoreVerifyError`] variant; no
//!   `Vec<u8>` cert / signature material in error bodies.
//!
//! ## Crate structure
//!
//! - [`manifest`] — `ReleaseManifest` schema + canonical-CBOR
//!   round-trip per D0024 §4.
//! - [`fulcio`] — Fulcio cert-chain validation per D0024 §2.
//! - [`rekor`] — Rekor inclusion-proof + signed-checkpoint verifier
//!   per D0024 §3.
//! - [`compose`] — release-leaf-hash composition with
//!   `cairn-sigsum-client` per D0024 §5.
//! - [`client`] — the `SigstoreVerifier` async surface per D0024 §6.
//! - [`error`] — typed error enum per D0018 §4.2 + D0024 §7.
//!
//! ## Implementation status (v1 skeleton)
//!
//! The load-bearing primitives are implemented + tested:
//!
//! - `ReleaseManifest` canonical-CBOR round-trip per D0024 §4
//! - `canonical_self_hash` per D0024 §4.2 (rollback-resistance
//!   input)
//! - `release_leaf_hash_for_envelope_bytes` per D0024 §5
//! - `SigstoreVerifier` constructor + config + retry-budget
//!   accessor
//! - Typed `SigstoreVerifyError` surface per D0024 §7
//!
//! The network-bound surfaces ([`fulcio::validate_cert_chain`],
//! [`rekor::verify_rekor_inclusion`],
//! [`client::SigstoreVerifier::verify_release`]) are present as
//! function / method signatures but their bodies return
//! [`SigstoreVerifyError::NetworkUnreached`] pending integration
//! testing per D0024 §10. The `integration-tests` cargo feature
//! flag gates the eventual network-exercising tests; v1 skeleton
//! ships without them.

pub mod client;
pub mod compose;
pub mod error;
pub mod fulcio;
pub mod rekor;

pub mod manifest;

pub use client::{ReleaseBundle, SigstoreVerifier, SigstoreVerifierConfig, VerifiedRelease};
pub use compose::release_leaf_hash_for_envelope_bytes;
pub use error::SigstoreVerifyError;
pub use fulcio::validate_cert_chain;
pub use manifest::{ArtifactHash, ReleaseManifest, SHA256_LEN};
pub use rekor::{RekorBundle, verify_rekor_inclusion};
