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
//! ## Implementation status
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
//! - [`rekor::verify_rekor_inclusion`]: the full offline Rekor
//!   verifier — RFC 6962 inclusion proof + C2SP signed-checkpoint
//!   ECDSA P-256 verify against the pinned Rekor key per D0024 §3
//!   (revised 2026-05-30: ECDSA, not Ed25519). Pure crypto, no
//!   network; exhaustively unit-tested. The online fetch
//!   ([`client::SigstoreVerifier::fetch_rekor_bundle`]) + its wiremock
//!   harness landed alongside.
//! - [`fulcio::validate_cert_chain`]: Fulcio cert-chain validation per
//!   D0024 §2 — verifies the signing cert chains to the pinned root
//!   (ECDSA P-384 chain sig via the `ring`-backed x509-parser `verify`
//!   feature; see D0024 §6.5 revision), checks the validity window vs
//!   the Rekor-attested signing time, pins the OIDC `iss` + `email`,
//!   and returns the developer's Ed25519 key for the manifest check.
//! - [`client::SigstoreVerifier::verify_release`]: the end-to-end
//!   offline orchestration (D0024 §6) — manifest decode → Fulcio +
//!   OIDC → manifest `COSE_Sign1` verify → Rekor inclusion + checkpoint
//!   → `prior_release_hash` rollback check. Validated end-to-end in
//!   `tests/verify_release.rs`.
//!
//! **One composition gap remains (D0024 §5):** `verify_release` does
//! NOT yet perform the witness-cosigned Sigsum-anchored-release-log
//! step — it depends on `cairn_sigsum_client::verify_inclusion`, still
//! a `NetworkUnreached` stub. The composed `SigsumClient` is held for
//! that step. The `integration-tests` cargo feature flag gates the
//! eventual real-Rekor / real-Fulcio network-exercising tests.

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
pub use rekor::{RekorBundle, RekorCheckpoint, parse_rekor_log_entry, verify_rekor_inclusion};
