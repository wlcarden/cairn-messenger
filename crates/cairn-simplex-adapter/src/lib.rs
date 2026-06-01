// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// Same crate-wide allow as cairn-storage + cairn-sigsum-client +
// cairn-sigstore-verify + cairn-tor-transport: many proper-noun
// technical terms (SimpleX, SMP, Cairn, OIDC, SimplOxide, Briar, etc.)
// that would each need backticks.
#![allow(clippy::doc_markdown)]

//! # cairn-simplex-adapter
//!
//! SimplOxide-sidecar transport + Cairn message envelope per
//! [D0026](../../docs/decisions/D0026-cairn-simplex-adapter.md),
//! re-anchored under
//! [D0020](../../docs/decisions/D0020-integration-architecture.md)
//! §1: a SimplOxide client over a loopback WebSocket to the SimpleX
//! Chat CLI sidecar. This crate does NOT implement the SMP wire
//! protocol or the double-ratchet — SimpleX / SimplOxide owns those
//! (the clean-room SMP path was rejected per D0020 §1.8).
//!
//! ## Architectural commitments this crate implements
//!
//! - **SimplOxide client over the CLI sidecar** per D0026 §1 /
//!   D0020 §1. The adapter is a WebSocket client of the sidecar +
//!   an envelope-construction/parse layer — not a protocol
//!   implementation. SimpleX owns the SMP wire + the PQ double-
//!   ratchet (FS + post-compromise security).
//! - **The D0020 §1.10 `Transport` seam.** [`SimplexAdapter`] exposes
//!   `create_invitation` / `accept_invitation` / `send` / `recv`; the
//!   v1.5 Briar adapter joins behind the same seam without disturbing
//!   the crypto / envelope / trust-graph / recovery crates.
//! - **Cairn message envelope** per D0026 §2: canonical-CBOR per
//!   D0018 §2.3, `COSE_Sign1` per D0018 §2.1, signed under D0006 §9's
//!   three-hop chain, AAD domain tag [`envelope::DOMAIN_TAG`] =
//!   `cairn-v1-message-envelope` per D0006 §8. The signed envelope
//!   rides as the opaque `send` payload INSIDE SimpleX's transport.
//! - **Per-sender-per-recipient envelope chain** via
//!   `prior_envelope_hash` per D0026 §2.3 (mirrors D0006 §5's trust-
//!   graph chain discipline at the messaging layer).
//! - **Size-bin padding** per D0026 §4: power-of-2 buckets
//!   `{256, 1024, 4096, 16384, 65536}` applied to the Cairn envelope
//!   BEFORE handing to SimplOxide's send. The SimpleX ratchet then
//!   wraps the padded envelope; the wire size leaks bucket size, not
//!   message size.
//! - **Cairn message history** in
//!   [`cairn_storage::categories::MESSAGES`] (record-ids per D0026
//!   §3.2). SimpleX ratchet state is NOT Cairn-stored — the CLI
//!   sidecar persists it.
//! - **Group-membership minimization architectural property** per
//!   D0026 §5: single-pubkey recipient even at v1 (1:1) preserves the
//!   v1.5 group-fan-out lift without schema restructuring.
//! - **Typed errors** per D0018 §4.2 + D0026 §9: variants split by
//!   failure layer (sidecar / envelope / padding / storage). No
//!   `Vec<u8>` ciphertext, no key bytes, no peer-supplied strings in
//!   error bodies.
//!
//! ## Crate structure
//!
//! - [`envelope`] — Cairn message envelope schema + canonical-CBOR
//!   round-trip + sign / verify with the AAD domain tag per D0026 §2.
//! - [`padding`] — size-bin bucket policy + padding-byte generation
//!   per D0026 §4.
//! - [`storage`] — record-id derivation for the `MESSAGES` category
//!   per D0026 §3.2 (`RATCHET_STATE` reserved-not-used; see §4.1).
//! - [`adapter`] — async `SimplexAdapter` per D0026 §7, the SimplOxide
//!   client implementing the D0020 §1.10 `Transport` seam.
//! - [`error`] — typed error enum per D0018 §4.2 + D0026 §9.
//!
//! ## Implementation status
//!
//! The adapter's security-critical envelope flow is **implemented +
//! tested** over the [`sidecar::SidecarTransport`] seam (the dependency
//! inversion of D0026 §1.2): `SimplexAdapter<T>` is generic over the
//! transport, so `send` (build → sign → pad → persist → advance chain)
//! and `recv` (verify → bind-to-sender → chain-check → unpad → persist)
//! are exercised end-to-end over an in-memory
//! `sidecar::MockSidecarTransport` — a two-party message round-trip,
//! `prior_envelope_hash` chain-linking, signature/AAD verification,
//! sender binding, and chain-gap rejection. Plus the load-bearing
//! primitives:
//!
//! - `envelope::MessageEnvelope` canonical-CBOR round-trip + sign/verify
//!   with AAD domain tag per D0026 §2 / D0006 §8.
//! - `envelope::next_prior_envelope_hash` per D0026 §2.3.
//! - `padding::select_bucket` + `padding::generate_padding` per D0026 §4.
//! - `storage::message_record_id_for` per D0026 §3.2.
//! - Typed `SimplexAdapterError` surface per D0026 §9.
//!
//! The concrete [`sidecar::SimploxideTransport`] is now a real
//! `simploxide-ws-core` WebSocket client of the SimpleX Chat CLI sidecar
//! (D0026 §1.3 / §12): it lazily dials `ws://host:port`, runs the `/user`
//! handshake, issues simplex-chat commands (the crate-internal `protocol`
//! layer), and drains events for incoming `CryptoFile`s. Its connection +
//! command-RPC + event-drain + error-mapping machinery is hermetically
//! tested against a localhost mock WS server (`sidecar::mock_ws_tests`); the
//! simplex-chat **wire fidelity** against a live daemon — especially the
//! `CryptoFile`/XFTP recv lifecycle — is the `integration-tests` gate
//! (D0026 §12), NOT asserted in unit tests. ws-core (the low-level raw WS
//! client) was chosen over the high-level `simploxide-client` Bot SDK
//! because it compiles on the pinned rust 1.85 and keeps Cairn off the
//! subprocess path (D0026 §12 probe matrix).
//!
//! The per-`(sender, recipient)` chain cursor is cached in memory and
//! **rehydrated lazily from the `MESSAGES` history** on the first chain
//! access after a restart (D0026 §3.2), so the `prior_envelope_hash`
//! chain survives process restarts.
//!
//! ## What was removed in the D0020 re-anchor (2026-05-30)
//!
//! The original skeleton's `ratchet.rs` (a project-owned double-
//! ratchet reimplementation) was DELETED. SimpleX / SimplOxide owns
//! the PQ double-ratchet; reimplementing it solo was the security
//! risk the revert eliminated (see D0026's revision note).

pub mod adapter;
pub mod envelope;
pub mod error;
pub mod padding;
/// The simplex-chat command/response/event JSON layer (D0026 §1.3) —
/// crate-internal, consumed by [`sidecar::SimploxideTransport`]. Pure
/// command builders + defensive parsers; see the module docs for the
/// verified-vs-live-gated boundary.
mod protocol;
/// The sidecar-transport seam (D0020 §1.10 / D0026 §1.2).
///
/// The raw byte transport below the Cairn envelope, with the deferred
/// SimplOxide-backed [`sidecar::SimploxideTransport`] + (test-only) mock.
pub mod sidecar;
pub mod storage;

pub use cairn_sigsum_client::RetryBudget;

pub use adapter::{
    ConnectionId, Invitation, LocalIdentity, MessageSent, ReceivedMessage, SidecarEndpoint,
    SimplexAdapter, SimplexAdapterConfig,
};
pub use envelope::{
    DOMAIN_TAG, ENVELOPE_SCHEMA_VERSION, EnvelopeSigner, MessageEnvelope, next_prior_envelope_hash,
    verify_envelope,
};
pub use error::SimplexAdapterError;
pub use padding::{
    LARGEST_BUCKET, SIZE_BUCKETS, generate_padding, padding_bytes_required, select_bucket,
};
pub use sidecar::{SidecarTransport, SimploxideTransport};
pub use storage::{RECORD_ID_LEN, message_record_id_for, ratchet_record_id_for};
