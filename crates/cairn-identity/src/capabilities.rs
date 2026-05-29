// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Capability string identifiers for v1 token scopes.
//!
//! D0006 §9 specifies the token's `scope` field as "enumerated capability
//! strings" — opaque text identifiers. This module exposes the v1
//! identifiers as `const &str` so call sites can be checked at
//! compile-time:
//!
//! ```
//! use cairn_identity::capabilities;
//!
//! let messaging = capabilities::MESSAGING_SEND;
//! assert_eq!(messaging, "messaging:send");
//! ```
//!
//! Tokens are stored as [`Vec<String>`] on the [`crate::CapabilityToken`]
//! to preserve forward-compatibility — a peer issuing a token with a
//! v1.1+ capability we don't yet recognize should still round-trip
//! through the type cleanly. [`crate::CapabilityToken::has_capability`]
//! is the runtime check; the constants here are the typed labels for
//! the v1 set.
//!
//! ## v1 capabilities
//!
//! - [`MESSAGING_SEND`]: send Cairn-protocol messages on the
//!   operational identity's behalf
//! - [`TRUST_GRAPH_ATTEST`]: issue trust-graph attestation operations
//!   per D0006 §2
//! - [`TRUST_GRAPH_REVOKE_WITHDRAW`]: issue a withdrawal-style
//!   revocation per D0006 §2 + D0021 cross-references (renamed from
//!   the F4 finding)
//! - [`TRUST_GRAPH_REVOKE_COMPROMISE`]: issue a compromise-style
//!   revocation per D0006 §2 (triggers the cascade per D0006 §2's
//!   "Cascade quarantine on revocation" paragraph)
//! - [`RECOVERY_PARTICIPATE`]: act as a recovery peer per D0006 §6 +
//!   `cairn-recovery`'s atomic-re-split orchestration
//!
//! ## Forward-compatibility
//!
//! D0006 §6.4 specifies that operation types unknown to a client are
//! retained but ignored. The same principle applies here: unknown
//! capability strings on a token must round-trip through the type
//! cleanly. [`crate::CapabilityToken`] stores [`String`] rather than an
//! enum specifically so unknown values are not rejected at decode.

/// Send Cairn-protocol messages on the operational identity's behalf.
pub const MESSAGING_SEND: &str = "messaging:send";

/// Issue trust-graph attestation operations per D0006 §2.
pub const TRUST_GRAPH_ATTEST: &str = "trust-graph:attest";

/// Issue a withdrawal-style revocation per D0006 §2.
///
/// Withdrawal is the legitimate user-initiated revocation path:
/// "I no longer wish to maintain trust with this peer." Does NOT
/// trigger the cascade.
pub const TRUST_GRAPH_REVOKE_WITHDRAW: &str = "trust-graph:revoke-withdraw";

/// Issue a compromise-style revocation per D0006 §2.
///
/// Compromise is the security-incident revocation path: "this peer's
/// key was extracted under coercion / forensic action." Triggers the
/// cascade quarantine on revocation per D0006 §2.
pub const TRUST_GRAPH_REVOKE_COMPROMISE: &str = "trust-graph:revoke-compromise";

/// Act as a recovery peer per D0006 §6 + `cairn-recovery`'s atomic
/// re-split orchestration.
pub const RECOVERY_PARTICIPATE: &str = "recovery:participate";
