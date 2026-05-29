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
//! ## Implementation strategy: byte-level GF(2⁸), not vsss-rs
//!
//! D0018 §3.1 originally pinned `vsss-rs` 4.3.8 for Shamir Secret
//! Sharing. Investigation revealed `vsss-rs::shamir::split_secret`
//! requires `F: PrimeField` (cryptographic-curve scalar field). Cairn's
//! seed-not-scalar requirement means the secret is 32 *bytes*, not a
//! scalar — byte-level GF(2⁸) Shamir is required, which `vsss-rs` does
//! not implement at v4.3.8.
//!
//! The byte-level GF(2⁸) Shamir algorithm is small (~150 `LoC` core),
//! well-known, and more auditable than wrapping a generic library. This
//! crate implements it directly with documented constant-time intent
//! across all secret-bearing intermediates. A future D-doc will record
//! the D0018 §3.1 revision.
//!
//! ## Constant-time discipline
//!
//! All field-arithmetic primitives ([`gf256`]) operate without
//! data-dependent branches or table lookups indexed by secret values.
//! The shift-and-conditional-XOR multiplication idiom uses bitmask
//! arithmetic (`(b & 1).wrapping_neg()` to produce the all-ones or
//! all-zeros mask) rather than a conditional branch. Reconstruction
//! Lagrange interpolation evaluates over a fixed loop bound determined
//! by the share count (not the secret bytes). The `dudect-bencher`
//! constant-time gate per D0018 §5.3 is a separate surface that
//! empirically validates this property.
//!
//! ## Module organization (incremental — surfaces land per
//! `metrics.md`)
//!
//! - [`error`] — error types for the crate
//! - [`gf256`] — GF(2⁸) field arithmetic (constant-time)
//! - [`share`] — `Share` type + `split` / `reconstruct` API
//! - [`commit`] — BLAKE3 commit-of-secret construction + verification

pub mod commit;
pub mod error;
pub mod gf256;
pub mod share;

pub use commit::{COMMITMENT_LEN, Commitment};
pub use error::ShamirError;
pub use share::{SECRET_LEN, Share, reconstruct, split};
