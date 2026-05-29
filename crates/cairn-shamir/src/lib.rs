// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! # cairn-shamir
//!
//! Shamir Secret Sharing for the 32-byte Ed25519 seed per D0006 §9 + D0018
//! §3. Splits a [`cairn_crypto::ed25519::SigningKey`]'s seed bytes into
//! `n` shares such that any `k` shares reconstruct the seed, but any
//! `< k` shares leak nothing about it (information-theoretic security in
//! the sharing layer itself; identity confidentiality at the application
//! layer depends on the trust-graph + recovery-peer authentication per
//! D0006).
//!
//! ## Why seed-not-scalar
//!
//! Cairn splits the 32-byte Ed25519 **seed** (RFC 8032 §5.1.5), NOT the
//! derived scalar or signing key directly. This preserves Ed25519's
//! deterministic-nonce contract per RFC 8032 §5.1.6: reconstructing a
//! scalar in one location and signing there must produce identical
//! signatures to reconstructing a seed elsewhere and signing the same
//! payload. Splitting at the seed layer makes this trivially true; any
//! other split point requires careful coordination of nonce derivation
//! state across reconstruction sites.
//!
//! ## BLAKE3 commit-of-secret (D0018 §3.4)
//!
//! Every share carries a 32-byte BLAKE3 commitment of the original seed:
//! `commit = BLAKE3(domain_separator || seed)`. At reconstruction time,
//! the reconstructed candidate is hashed and compared against the
//! commitment before being used. This defends against:
//!
//! 1. **Corrupted shares.** A passive bit-flip in stored share material
//!    would otherwise reconstruct a different seed silently; the
//!    commitment makes the corruption detectable.
//! 2. **Malicious reconstruction shares.** A peer who delivers a
//!    deliberately-wrong share would otherwise contribute a wrong
//!    polynomial point and shift the reconstructed seed; the commitment
//!    rejects the result. Note: this does not identify *which* peer
//!    contributed the bad share — Cairn's trust-graph layer surfaces
//!    that information separately.
//! 3. **Implementation drift.** A peer running a different Shamir
//!    implementation that produces subtly-different shares (different
//!    field, different polynomial encoding) is caught at the commitment
//!    check rather than producing a silently-wrong seed.
//!
//! The commitment is NOT a secret. It travels alongside the shares.
//!
//! ## Constant-time discipline
//!
//! Per D0018 §3.5: the Shamir reconstruction polynomial evaluation must
//! be constant-time across the secret-bearing intermediates. The
//! `vsss-rs` 4.3.8 implementation provides this; this crate's CI pipeline
//! includes a `dudect-bencher` constant-time gate per D0018 §5.3
//! (forthcoming surface).
//!
//! ## Module organization (incremental — surfaces land per
//! `metrics.md`)
//!
//! - [`error`] — error types for the crate
//! - `share` (forthcoming) — `Share` type + split / reconstruct API
//! - `commit` (forthcoming) — BLAKE3 commitment construction +
//!   verification

pub mod error;

pub use error::ShamirError;
