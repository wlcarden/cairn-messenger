// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! # cairn-envelope
//!
//! Canonical CBOR + `COSE_Sign1` envelope construction for Cairn. Implements
//! the byte-level wire form per D0006 (cryptographic envelope completion)
//! and D0018 §2 (CBOR + COSE engineering foundation).
//!
//! ## Wire-form principles
//!
//! Cairn's envelope is the byte-level format every cooperating
//! implementation must produce identically for trust-graph signatures and
//! verifications to interop. The byte form is constrained by three
//! requirements:
//!
//! 1. **Determinism.** Two implementations must produce the exact same
//!    byte string from the same logical inputs. Achieved via canonical
//!    CBOR encoding (RFC 8949 §4.2 deterministic encoding rules) plus
//!    project-owned encoder discipline per D0018 §2.3 (because no
//!    Rust-side CBOR crate currently enforces deterministic encoding
//!    end-to-end).
//! 2. **Authenticated provenance.** Every envelope carries a `COSE_Sign1`
//!    signature (RFC 9052 §4) by the sender's long-term Ed25519 key,
//!    binding the outer header to the inner payload via the COSE
//!    `Sig_structure`.
//! 3. **Confidentiality.** The inner payload is XChaCha20-Poly1305 AEAD
//!    ciphertext per [`cairn_crypto::aead`]; the outer header is
//!    authenticated but not encrypted, allowing per-recipient routing
//!    without payload disclosure.
//!
//! ## Module organization (incremental — surfaces land per
//! `metrics.md`)
//!
//! - [`canonical`] — canonical CBOR encoding per RFC 8949 §4.2 +
//!   D0018 §2.3 (project-owned because `ciborium` does not enforce
//!   deterministic encoding alone)
//! - [`cose_sign1`] — ``COSE_Sign1`` construction + verification
//!   (forthcoming; per RFC 9052 §4.4 `Sig_structure`)
//! - [`error`] — error types for the crate
//!
//! ## Interop validation strategy
//!
//! Per D0018 §2.2 + §2.5: `COSE_Sign1` byte forms produced by this crate
//! MUST validate against an independent implementation. Cairn targets
//! `veraison/go-cose` as the cross-implementation oracle: the Go test
//! harness in `interop/go-cose/` parses and re-verifies the pinned
//! `tests/vectors/*.json` envelopes (run via the `go-cose-interop` CI
//! job). Discrepancies indicate either a Cairn bug or a `coset`
//! regression; the gate is mandatory before declaring the envelope
//! module audit-ready.
//!
//! ## Stability commitment
//!
//! Once Cairn ships v1, the byte-level envelope form is frozen. Future
//! schema changes happen via a versioning header (`alg = ...` plus a
//! `kid` namespace per D0006 §5.3), never via silent re-encoding. The
//! deterministic-encoding discipline is the load-bearing invariant for
//! this stability promise.

// Module declarations land here as surfaces are implemented. The
// progression per metrics.md is: canonical CBOR → ``COSE_Sign1`` →
// envelope assembly → cross-implementation interop.

pub mod canonical;
pub mod cose_sign1;
pub mod error;

pub use error::EnvelopeError;
