// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// Same crate-wide allow as cairn-storage + cairn-sigsum-client +
// cairn-sigstore-verify + cairn-tor-transport: many proper-noun
// technical terms (SimpleX, SMP, Cairn, OIDC, X3DH, Briar, etc.)
// that would each need backticks.
#![allow(clippy::doc_markdown)]

//! # cairn-simplex-adapter
//!
//! Project-owned Rust SMP client + Cairn message envelope per
//! [D0026](../../docs/decisions/D0026-cairn-simplex-adapter.md).
//!
//! ## Architectural commitments this crate implements
//!
//! - **Project-owned Rust SMP client** per D0026 §1. Same pure-Rust
//!   audit-scope-ownership discipline as D0023 §3 (Sigsum witness
//!   verification) and D0024 §3 (Rekor verifier).
//! - **Cairn message envelope** per D0026 §2: canonical-CBOR per
//!   D0018 §2.3, wrapped in `COSE_Sign1` per D0018 §2.1, signed
//!   under D0006 §9's three-hop chain. AAD domain tag
//!   [`envelope::DOMAIN_TAG`] = `cairn-v1-message-envelope` per
//!   D0006 §8 prevents cross-protocol signature substitution.
//! - **Per-sender-per-recipient envelope chain** via
//!   `prior_envelope_hash` per D0026 §2.3 (mirrors D0006 §5's
//!   trust-graph chain discipline at the messaging layer).
//! - **Size-bin padding** per D0026 §4: power-of-2 buckets
//!   `{256, 1024, 4096, 16384, 65536}` BEFORE SMP wrapping. Wire
//!   ciphertext leaks bucket size, not message size.
//! - **Per-conversation ratchet state** in
//!   [`cairn_storage::categories::RATCHET_STATE`]; per-message
//!   history in `MESSAGES`. Record-ids deterministic per
//!   `(local, peer)` and `(sender, recipient, message_number)` per
//!   D0026 §3.2.
//! - **Group-membership minimization architectural property** per
//!   D0026 §5: single-pubkey recipient field even at v1 (1:1)
//!   preserves the v1.5 group-fan-out lift without schema
//!   restructuring.
//! - **Tor composition** per D0026 §8: every outbound SMP
//!   connection routes through `cairn_tor_transport::TorTransport`.
//!   No raw sockets.
//! - **Typed errors** per D0018 §4.2 + D0026 §9: 13 variants split
//!   by failure layer (transport / protocol / ratchet / envelope /
//!   storage / padding). No `Vec<u8>` ciphertext, no key bytes, no
//!   peer-supplied strings in error bodies.
//!
//! ## Crate structure
//!
//! - [`envelope`] — Cairn message envelope schema + canonical-CBOR
//!   round-trip + sign / verify path with AAD domain tag per D0026
//!   §2.
//! - [`padding`] — size-bin bucket policy + padding-byte generation
//!   per D0026 §4.
//! - [`storage`] — record-id derivation for `RATCHET_STATE` +
//!   `MESSAGES` categories per D0026 §3.2.
//! - [`ratchet`] — double-ratchet derivative state per D0026 §3.
//!   v1 skeleton stubs encrypt/decrypt; the body lands with the
//!   SimpleX upstream cross-validation per D0026 §1.4.
//! - [`client`] — async `SimplexClient` per D0026 §7 composing the
//!   layers above + `TorTransport` per D0026 §8.
//! - [`error`] — typed error enum per D0018 §4.2 + D0026 §9.
//!
//! ## Implementation status (v1 skeleton)
//!
//! The load-bearing primitives are implemented + tested:
//!
//! - `envelope::MessageEnvelope` canonical-CBOR round-trip per
//!   D0026 §2
//! - `envelope` sign + verify with AAD domain tag per D0006 §8
//!   (tamper / wrong-key / wrong-AAD rejection covered)
//! - `envelope::next_prior_envelope_hash` per D0026 §2.3 (same
//!   composition as D0023 §1 + D0024 §5)
//! - `padding::select_bucket` + `padding::generate_padding` per
//!   D0026 §4
//! - `storage::ratchet_record_id_for` +
//!   `storage::message_record_id_for` per D0026 §3.2
//! - `client::SimplexClient` constructor + accessors
//! - Typed `SimplexAdapterError` surface per D0026 §9
//!
//! The network-bound surfaces ([`client::SimplexClient::send_message`],
//! [`client::SimplexClient::poll_inbox`],
//! [`client::SimplexClient::rotate_queue`], and the double-ratchet
//! encrypt / decrypt paths in [`ratchet`]) are present as method
//! signatures but return [`SimplexAdapterError::NetworkUnreached`]
//! pending the SMP wire-protocol body + the double-ratchet
//! derivative body per D0026 §12. The `integration-tests` cargo
//! feature flag gates the eventual network-exercising tests;
//! v1 skeleton ships without them.

pub mod client;
pub mod envelope;
pub mod error;
pub mod padding;
pub mod ratchet;
pub mod storage;

pub use cairn_sigsum_client::RetryBudget;

pub use client::{
    MessageSent, ReceivedMessage, SimplexClient, SimplexClientConfig, SimplexServer,
    SimplexServerConfig,
};
pub use envelope::{
    DOMAIN_TAG, ENVELOPE_SCHEMA_VERSION, MessageEnvelope, next_prior_envelope_hash, verify_envelope,
};
pub use error::SimplexAdapterError;
pub use padding::{
    LARGEST_BUCKET, SIZE_BUCKETS, generate_padding, padding_bytes_required, select_bucket,
};
pub use ratchet::RatchetState;
pub use storage::{RECORD_ID_LEN, message_record_id_for, ratchet_record_id_for};
