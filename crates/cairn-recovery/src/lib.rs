// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! # cairn-recovery
//!
//! v1 recovery primitive: from a 3-of-5 (or k-of-n) Shamir share set
//! plus a commitment, reconstruct the master seed transiently and
//! sign a master-attestation of a new operational identity per D0005
//! and D0006 §6. The reconstructed master is held in `Zeroizing` for
//! the function lifetime and wiped on exit.
//!
//! ## Three-hop verification chain (top of the chain)
//!
//! ```text
//!   operation envelope signed by device key  (hop #1)
//!     verified against device pubkey
//!   capability token signed by operational identity  (hop #2)
//!     verified against operational identity pubkey
//!   master attestation signed by master  (hop #3) ← this crate
//!     verified against known master pubkey
//! ```
//!
//! cairn-recovery owns the construction + verification of hop #3 —
//! the master attestation. The master pubkey itself is bootstrapped
//! out-of-band (printed on the user's paper backup card, registered
//! with the recovery peers at provisioning).
//!
//! ## What this crate does at v1
//!
//! - [`MasterAttestation`] data structure + canonical CBOR encoding
//!   per D0018 §2.3
//! - [`SignedMasterAttestation`] `COSE_Sign1` envelope (signed by
//!   master directly — NOT by a device key under a capability token;
//!   the master is its own root of trust)
//! - [`reconstruct_and_attest`] — composes
//!   `cairn-shamir::reconstruct` + `MasterAttestation::sign`,
//!   keeping the master in `Zeroizing` end-to-end
//!
//! ## What this crate does NOT do (deferred)
//!
//! - **Atomic-or-non-leaking re-split per D0018 §3.5**: distributing
//!   new shares to N peers with two-phase commit, rollback on partial
//!   ack failure. That's a peer-protocol layer (depends on
//!   network/messaging) — this crate provides the cryptographic
//!   primitives. Future: `cairn-recovery-orchestrator`.
//! - **Recovery-peer authentication per D0005**: the trust-graph
//!   layer establishes which peers are authorized to hold shares.
//!   This crate operates on share bytes the caller has already
//!   collected through that flow.

pub mod attestation;
pub mod card;
pub mod error;
pub mod peer_store;

pub use attestation::{
    DOMAIN_TAG, ISSUER_CERT_HASH_LEN, MasterAttestation, SignedMasterAttestation,
    reconstruct_and_attest,
};
pub use card::{MASTER_PUBKEY_LEN, RecoveryCard, decode_card, encode_card};
pub use error::RecoveryError;
pub use peer_store::{
    HeldShare, PeerRecord, PeerStoreError, RECORD_ID_LEN as PEER_STORE_RECORD_ID_LEN,
    RECOVERY_PEERS_SCHEMA_VERSION, RECOVERY_SHARES_SCHEMA_VERSION, delete_held_share, delete_peer,
    initialize_schema as initialize_peer_schema, load_all_peers, load_held_share, load_peer,
    peer_record_id, share_record_id, store_held_share, store_peer,
};
