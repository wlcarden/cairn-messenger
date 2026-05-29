// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! # cairn-identity
//!
//! Capability-token construction for Cairn's authority model per D0006 §9.
//! Tokens are ``COSE_Sign1`` envelopes signed by the operational identity,
//! authorizing a named device-key subject to perform operations within a
//! specific scope until an expiry.
//!
//! ## Three-hop verification chain (D0006 §9)
//!
//! ```text
//!     device-key signs an operation envelope
//!       ↓ verified against
//!     capability token (signed by operational identity)
//!       ↓ scope-check against operation type
//!       ↓ chain-to-master link
//!     operational-identity master attestation
//!       ↓ trust-graph trace to known master
//! ```
//!
//! This crate owns hop #2 — token construction + token-level signature
//! verification. The other hops live in higher-level crates:
//!
//! - **Hop #1** (operation envelope verification against device key) is
//!   the responsibility of the operation-issuing crate (e.g.,
//!   `cairn-trust-graph` for attestation operations).
//! - **Hop #3** (chain-to-master link verification) is the responsibility
//!   of `cairn-recovery` / `cairn-trust-graph` and runs the master-
//!   attestation verification path.
//!
//! ## Token payload schema
//!
//! Per D0006 §9, the token payload is a canonical-CBOR map with
//! integer keys following COSE conventions:
//!
//! | Key | Field | CBOR type | Notes |
//! |-----|-------|-----------|-------|
//! | 1 | `issuer` | bstr(32) | Operational-identity Ed25519 public key |
//! | 2 | `subject` | bstr(32) | Device Ed25519 public key |
//! | 3 | `scope` | array of text | Capability strings (see [`capabilities`]) |
//! | 4 | `expiry` | uint | Unix seconds; verifier-side staleness check is the caller's job |
//! | 5 | `chain` | bstr | Opaque signature-chain-to-master bytes; verified by higher layer |
//!
//! The `COSE_Sign1` protected header carries `alg = EdDSA` (`-8`); the
//! `EdDSA` algorithm is per RFC 9053 §2.2; the COSE labels are per RFC
//! 9052 §3.1.
//! unprotected header may carry a `kid` (operational-identity key
//! identifier) for routing.
//!
//! ## What this crate does NOT do
//!
//! - **Hardware-element integration.** Device-key generation lives in
//!   `StrongBox` / TEE per D0020 §3.7; this crate operates on
//!   already-extracted public keys + already-available signing keys.
//! - **Chain-to-master validation.** The `signature_chain_to_master`
//!   field is carried opaquely; higher layers verify it against the
//!   master they trust.
//! - **Expiry enforcement.** Tokens carry an `expiry` field; callers
//!   decide policy (reject expired vs accept-then-renew) per operation
//!   type.
//! - **Scope-against-operation matching.** Callers compare
//!   [`CapabilityToken::has_capability`] against the operation type
//!   they're issuing.

pub mod capabilities;
pub mod error;
pub mod token;

pub use error::IdentityError;
pub use token::{CapabilityToken, SignedCapabilityToken};
