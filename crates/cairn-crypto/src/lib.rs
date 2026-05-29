// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! # cairn-crypto
//!
//! Foundational cryptographic primitives for Cairn. Thin, typed wrappers over the
//! `RustCrypto` stack with strict memory-hygiene discipline.
//!
//! ## Threat model context
//!
//! Cairn targets users facing state-actor adversaries: mercenary spyware,
//! forensic-extraction tooling, and traditional state intelligence. The threat
//! model is documented in `docs/design-brief.md` §3. This crate's discipline is
//! calibrated against forensic memory extraction from seized devices.
//!
//! ## Memory hygiene — honest limitations
//!
//! Per `docs/design-brief.md` §5.1 (post-Sprint 1 update), `zeroize` does NOT
//! defeat all forensic-extraction scenarios. Specifically:
//!
//! - LLVM may spill secret bytes to caller-save registers or stack slots that
//!   `zeroize` cannot reach (stack-spill copies and intermediate registers).
//! - Rust executes `Drop` only on the location where a value resides at scope
//!   exit; values that moved leave the source slot stale.
//! - `mlock`/`mlockall` can fail silently on Android with `RLIMIT_MEMLOCK`.
//! - Hardware-level cache lines containing the secret are not reached.
//! - Compiler-introduced copies elsewhere in memory are not reached by `zeroize`'s
//!   single-address `volatile_write`.
//!
//! The discipline accepts these limitations and bounds them through time
//! (sub-second reconstruction windows), space (recovery on fresh device), and
//! process boundaries (`panic = "abort"` in release per workspace `Cargo.toml`).
//! Memory hygiene is **defense-in-depth**, not a guarantee.
//!
//! ## Discipline framework
//!
//! 1. Every type holding key/seed bytes uses `secrecy::SecretBox` wrapping and
//!    derives or has `ZeroizeOnDrop` semantics.
//! 2. Every comparison on secret bytes uses `subtle::ConstantTimeEq`.
//! 3. Every key-generation function takes an explicit `&mut impl CryptoRng + RngCore`
//!    or calls `OsRng` directly — never `thread_rng` or `SmallRng`.
//! 4. Public values (signatures, public keys, fingerprints) cross the API as
//!    plain bytes; secret-bearing types implement [`NeverExport`] and are
//!    prevented from crossing the `UniFFI` boundary (per D0020 §3.7).
//! 5. Errors carry indices, lengths, and type tags only — never `Vec<u8>` or
//!    `&[u8]` payloads (per D0018 §4.2).
//! 6. After every X25519 ECDH, `was_contributory()` is called and the agreement
//!    is rejected if false (per D0018 §1.2; vodozemac 2026 audit reference).
//!
//! ## Module organization
//!
//! - [`never_export`] — sealed marker trait preventing secret types from crossing
//!   the `UniFFI` boundary
//! - [`ed25519`] — Ed25519 signing key wrappers
//! - [`x25519`] — X25519 ECDH (forthcoming as integration crates land)
//! - [`hkdf`] — HKDF-SHA256 derivation (forthcoming)
//! - [`error`] — error types for the crate

pub mod ed25519;
pub mod error;
pub mod never_export;

pub use error::{CryptoError, SignError, VerifyError};
