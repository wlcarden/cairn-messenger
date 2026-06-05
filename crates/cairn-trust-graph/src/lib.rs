// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! # cairn-trust-graph
//!
//! Trust-graph operation envelopes per D0006 §2: the four signed
//! operation types that compose the social layer Cairn distinguishes
//! itself by (vs other E2EE messengers that only express user-to-user
//! key trust).
//!
//! ## Operation types
//!
//! | Type | Purpose | Required capability |
//! |------|---------|---------------------|
//! | `Attest` | Issuer claims relationship with subject peer | `trust-graph:attest` |
//! | `WithdrawRevoke` | Clean break — user-initiated; no cascade | `trust-graph:revoke-withdraw` |
//! | `CompromiseRevoke` | Security incident — triggers cascade quarantine per D0006 §2 | `trust-graph:revoke-compromise` |
//! | `ReAttest` | Post-revocation healing — re-establishes trust with stricter verification | `trust-graph:attest` |
//!
//! ## Three-hop verification chain (per D0006 §9, same as message envelopes)
//!
//! ```text
//!   device-key signs the operation envelope
//!     ↓ verified against device pubkey
//!   capability token names device-key as subject + authorizes the op-type capability
//!     ↓ token signed by operational identity
//!   operational-identity master attestation
//!     ↓ trust-graph trace to known master
//! ```
//!
//! This crate owns the per-operation level: sign + verify a single
//! trust-graph operation envelope. Higher layers own:
//!
//! - **State tracking** — maintaining the prior-hash chain of operations
//!   each peer has issued, detecting omissions / replay
//! - **Cascade quarantine** — D0006 §2's "Cascade quarantine on
//!   revocation" semantics: when a `CompromiseRevoke(X)` lands with
//!   `revoked_as_of = t`, attestations issued by X *after* `t` are
//!   quarantined (90-day stale-flag escalation); user is prompted to
//!   re-attest the affected peers
//! - **Re-attestation policy** — D0006 §2's "stricter re-attestation
//!   requirements" decision (out-of-band verification etc.)
//!
//! ## Operation payload schema (per D0006 §2 + canonical CBOR per D0018 §2.3)
//!
//! Integer-keyed canonical-CBOR map:
//!
//! | Key | Field | CBOR type | Notes |
//! |-----|-------|-----------|-------|
//! | 1 | `op_type` | uint | 1=Attest, 2=WithdrawRevoke, 3=CompromiseRevoke, 4=ReAttest |
//! | 2 | `issuer_pubkey` | bstr(32) | Operational-identity public key issuing the op |
//! | 3 | `subject_pubkey` | bstr(32) | Peer being attested / revoked / re-attested |
//! | 4 | `timestamp` | uint | Unix-seconds when the op was issued |
//! | 5 | `prior_hash` | bstr | Chain link to the previous op this issuer signed (zero-length for genesis) |
//! | 6 | `issuer_cert_hash` | bstr | Hash of the capability token authorizing this op |
//! | 7 | `revoked_as_of` | uint | (`CompromiseRevoke` only) Unix-seconds prior-to-this-time considered compromised |
//! | 8 | `prior_revocation_ref` | bstr | (`ReAttest` only) reference to the revocation being healed |
//! | 9 | `strength` | uint | (attestation op-types only) 1=in-person, 2=channel-verified, 3=asserted (D0006 §4 / D0035 §3) |
//!
//! All fields are canonical-CBOR-encoded per D0018 §2.3 so two
//! implementations sign byte-identical inputs.

pub mod cascade;
pub mod chain;
pub mod error;
pub mod op;
pub mod self_token;
pub mod signed;
pub mod store;
pub mod vouch;

pub use cascade::{QuarantineStatus, compute_quarantine_state};
pub use chain::verify_chain_links;
pub use error::TrustGraphError;
pub use op::{OpType, Strength, TrustGraphOp};
pub use self_token::{self_issued_scopes, self_issued_token};
pub use signed::{DOMAIN_TAG, PRIOR_HASH_LEN, SignedTrustGraphOp};
pub use store::{
    RECORD_ID_LEN as STORE_RECORD_ID_LEN, StoreError, TRUST_GRAPH_SCHEMA_VERSION, delete_op,
    initialize_schema, load_all_ops_chronological, load_chain_for_pair, load_signed_op,
    record_id_for, store_signed_op,
};
pub use vouch::{decode_vouch, encode_vouch};
