// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! # cairn-shamir
//!
//! Shamir Secret Sharing for the 32-byte Ed25519 seed per D0006 §9 + D0018
//! §3. Wraps `vsss-rs` 5.4.0's `Gf256` byte-level GF(2⁸) implementation
//! (Cure53 PVY-01-003 reference per D0018 §3.1 line 316) in Cairn's
//! Share / Commitment discipline.
//!
//! Any `k` shares reconstruct the seed; any `< k` shares leak nothing
//! about it (information-theoretic security in the sharing layer
//! itself; identity confidentiality at the application layer depends
//! on the trust-graph + recovery-peer authentication per D0006).
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
//!    implementation that produces subtly-different shares is caught
//!    at the commitment check rather than producing a silently-wrong
//!    seed.
//!
//! `vsss-rs` does NOT provide a commit-of-secret primitive; this is
//! the value-add of `cairn-shamir::commit` on top of the audited
//! `Gf256` arithmetic.
//!
//! ## Constant-time discipline
//!
//! The field arithmetic comes from `vsss-rs::Gf256` which explicitly
//! disclaims lookup tables (see `vsss-rs-5.4.0/src/gf256.rs:1-9`).
//! Cairn adds the `dudect-bencher` constant-time gate per D0018 §5.3
//! as the operational check (forthcoming surface).
//!
//! ## Module organization
//!
//! - [`error`] — error types for the crate
//! - [`share`] — `Share` type + `split` / `reconstruct` API over
//!   `vsss-rs::Gf256`
//! - [`commit`] — BLAKE3 commit-of-secret construction + verification

pub mod commit;
pub mod error;
pub mod share;

pub use commit::{COMMITMENT_LEN, Commitment};
pub use error::ShamirError;
pub use share::{SECRET_LEN, SHARE_LEN, Share, reconstruct, split};
