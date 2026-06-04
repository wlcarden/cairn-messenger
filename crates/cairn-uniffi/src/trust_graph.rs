// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Trust-graph export surface (D0027 §2 — the `trust_graph` per-domain
//! module).
//!
//! This is the first per-domain export module to land behind the
//! build-validated UniFFI pipeline (D0028) per D0027 §8 step 4. It
//! exposes the cascade-quarantine classification the Android shell
//! needs to render trust badges (design brief §5.6 — the DEFERRED
//! "trust-badge rendering" row): given a contact's stored trust-graph
//! op chain + the capability token authorizing it + the expected
//! operational-identity pubkey, return the per-op
//! [`QuarantineStatusFfi`].
//!
//! ## Why a single fused `verify_and_classify`
//!
//! `cairn_trust_graph::compute_quarantine_state` documents a hard
//! precondition: *callers MUST verify the ops (via
//! [`cairn_trust_graph::verify_chain_links`]) before classifying* —
//! the cascade rule assumes cryptographically valid input. Across the
//! FFI boundary that "MUST" cannot be trusted to the Kotlin caller, so
//! [`trust_graph_verify_and_classify`] fuses verify-then-classify into
//! one call. The unsafe ordering (classify unverified ops) is not
//! merely discouraged — it is unrepresentable from Kotlin.
//!
//! ## Marshalling discipline
//!
//! Inputs cross as bytes (`Vec<Vec<u8>>` op chain, `Vec<u8>` token,
//! `Vec<u8>` pubkey) — Kotlin holds no Rust `SignedTrustGraphOp`
//! handle. Outputs carry only PUBLIC data: the revoking peer's pubkey
//! (32 public bytes) + Unix-seconds. No secret type appears in this
//! surface (enforced by [`crate::never_export_gate`]). Every typed
//! `TrustGraphError` is flattened to [`CairnFfiError`] via the existing
//! facade `From` mapping (D0027 §3) — no source `Display` string
//! crosses.

use std::sync::{Arc, Mutex, PoisonError};

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, VerifyingKey};
use cairn_identity::IdentityError;
use cairn_storage::Storage;
use cairn_trust_graph::{
    SignedTrustGraphOp, Strength, TrustGraphError, TrustGraphOp, compute_quarantine_state,
    initialize_schema, load_chain_for_pair, self_issued_token, store_signed_op, verify_chain_links,
};

use crate::error::CairnFfiError;
use crate::hardware::HardwareKeySigner;
use crate::storage::StorageHandle;

/// FFI mirror of [`cairn_trust_graph::QuarantineStatus`] (D0027 §2.2).
///
/// The domain enum carries `VerifyingKey` fields; those are PUBLIC
/// keys, so they cross as 32-byte `Vec<u8>` (not secrets). Becomes a
/// `uniffi::Enum` under the `uniffi-bindings` feature; a plain Rust
/// enum otherwise so the mapping is testable without the proc-macro.
///
/// The domain `QuarantineStatus` is `#[non_exhaustive]`, so the `From`
/// mapping below carries a wildcard arm → [`Self::Unknown`]. This is
/// the fail-closed posture: a future domain variant this build does
/// not recognize renders as "unknown / treat as suspect", never
/// silently as [`Self::Active`]. (Same discipline as the error
/// facade's `UnmappedInternal`, D0027 §3.2.)
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
pub enum QuarantineStatusFfi {
    /// The op is a revocation, not an attestation — not classified.
    NotApplicable,
    /// No cascade revocation applies; the attestation is usable.
    Active,
    /// The issuer was withdrawn-from at or before this attestation's
    /// timestamp. Operationally usable but flagged.
    SoftFlaggedByWithdrawal {
        /// The PUBLIC key (32 bytes) of the peer who issued the
        /// `WithdrawRevoke`.
        revoked_by: Vec<u8>,
        /// The withdrawal op's Unix-seconds timestamp.
        withdrawal_at: u64,
    },
    /// The issuer was compromise-revoked, and this attestation was
    /// issued at or before the compromise window. Flagged but usable.
    SoftFlaggedPreCompromise {
        /// The PUBLIC key (32 bytes) of the peer who issued the
        /// `CompromiseRevoke`.
        revoked_by: Vec<u8>,
        /// The `revoked_as_of` Unix-seconds from the compromise revoke.
        revoked_as_of: u64,
    },
    /// The issuer was compromise-revoked, and this attestation was
    /// issued AFTER the compromise window. NOT operationally usable
    /// per D0006 §2's anti-laundering rule.
    HardSuspended {
        /// The PUBLIC key (32 bytes) of the peer who issued the
        /// `CompromiseRevoke`.
        revoked_by: Vec<u8>,
        /// The `revoked_as_of` Unix-seconds from the compromise revoke.
        revoked_as_of: u64,
    },
    /// Fail-closed catch-all for a future `#[non_exhaustive]` domain
    /// variant this build does not recognize. The shell renders this
    /// as the most-restrictive badge.
    Unknown,
}

impl From<cairn_trust_graph::QuarantineStatus> for QuarantineStatusFfi {
    fn from(status: cairn_trust_graph::QuarantineStatus) -> Self {
        use cairn_trust_graph::QuarantineStatus as Q;
        match status {
            Q::NotApplicable => Self::NotApplicable,
            Q::Active => Self::Active,
            Q::SoftFlaggedByWithdrawal {
                revoked_by,
                withdrawal_at,
            } => Self::SoftFlaggedByWithdrawal {
                revoked_by: revoked_by.to_bytes().to_vec(),
                withdrawal_at,
            },
            Q::SoftFlaggedPreCompromise {
                revoked_by,
                revoked_as_of,
            } => Self::SoftFlaggedPreCompromise {
                revoked_by: revoked_by.to_bytes().to_vec(),
                revoked_as_of,
            },
            Q::HardSuspended {
                revoked_by,
                revoked_as_of,
            } => Self::HardSuspended {
                revoked_by: revoked_by.to_bytes().to_vec(),
                revoked_as_of,
            },
            // The domain enum is #[non_exhaustive]; fail closed.
            _ => Self::Unknown,
        }
    }
}

/// Verify a single issuer's trust-graph op chain, then classify each
/// op's cascade-quarantine status (D0027 §2.2).
///
/// `op_chain` is the issuer's ordered ops, each as canonical
/// `COSE_Sign1` bytes (`cairn_trust_graph::SignedTrustGraphOp`
/// encoding). `capability_token` is the encoded
/// `SignedCapabilityToken` authorizing the issuing device.
/// `expected_operational_identity` is the issuer's 32-byte operational
/// pubkey. Returns one [`QuarantineStatusFfi`] per input op, in order
/// (`output[i]` classifies `op_chain[i]`).
///
/// Verification (three-hop chain per op + chain-link integrity per
/// D0006 §2/§5) happens BEFORE classification; an invalid chain
/// returns an error and never reaches the cascade rule.
///
/// # Errors
///
/// - [`CairnFfiError::MalformedData`] if `expected_operational_identity`
///   is not exactly [`PUBLIC_KEY_LEN`] bytes or is not a valid Ed25519
///   public key, or if any `op_chain` entry is not well-formed.
/// - [`CairnFfiError::ChainInvalid`] for any chain-integrity failure
///   (empty chain, genesis/prior-hash mismatch, pair mismatch,
///   timestamp regression).
/// - [`CairnFfiError::SignatureVerifyFailed`] /
///   [`CairnFfiError::CapabilityNotAuthorized`] from per-op
///   verification.
///
/// All variants are the flat facade mapping of the source
/// `TrustGraphError` (D0027 §3); no source `Display` string crosses.
#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
)]
pub fn trust_graph_verify_and_classify(
    op_chain: Vec<Vec<u8>>,
    capability_token: Vec<u8>,
    expected_operational_identity: Vec<u8>,
) -> Result<Vec<QuarantineStatusFfi>, CairnFfiError> {
    // Parse the expected operational-identity pubkey (32 public bytes).
    let pubkey_bytes: [u8; PUBLIC_KEY_LEN] = expected_operational_identity
        .as_slice()
        .try_into()
        .map_err(|_| CairnFfiError::MalformedData)?;
    let expected =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| CairnFfiError::MalformedData)?;

    // Decode each op (no verification yet); a malformed entry flattens
    // to MalformedData via the facade From mapping.
    let ops: Vec<SignedTrustGraphOp> = op_chain
        .iter()
        .map(|bytes| SignedTrustGraphOp::from_bytes(bytes))
        .collect::<Result<_, _>>()?;

    // Verify the chain BEFORE classifying. verify_chain_links returns
    // the verified inner ops, which compute_quarantine_state consumes.
    let verified = verify_chain_links(&ops, &capability_token, &expected)?;
    let statuses = compute_quarantine_state(&verified);

    Ok(statuses
        .into_iter()
        .map(QuarantineStatusFfi::from)
        .collect())
}

/// FFI mirror of [`cairn_trust_graph::Strength`] (D0035 §3) — the
/// verification provenance the shell records when the user verifies a
/// contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
pub enum StrengthFfi {
    /// Confirmed face-to-face (QR safety-number scan in person).
    InPerson,
    /// Confirmed over a separate channel (e.g. number read over a call).
    ChannelVerified,
    /// Asserted from first contact (TOFU); renders as unverified.
    Asserted,
}

impl StrengthFfi {
    const fn to_domain(self) -> Strength {
        match self {
            Self::InPerson => Strength::InPerson,
            Self::ChannelVerified => Strength::ChannelVerified,
            Self::Asserted => Strength::Asserted,
        }
    }
}

impl From<Strength> for StrengthFfi {
    fn from(strength: Strength) -> Self {
        match strength {
            Strength::InPerson => Self::InPerson,
            Strength::ChannelVerified => Self::ChannelVerified,
            // `Asserted` + any future #[non_exhaustive] domain variant map
            // to the WEAKEST strength — the fail-safe never over-claims trust.
            _ => Self::Asserted,
        }
    }
}

/// The outcome of minting a trust-graph op (D0035 §4): the storage record
/// id it was persisted under + the signed op bytes (so the shell can
/// re-classify or display the op without a reload).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct TrustGraphOpRecord {
    /// The trust-graph store record id the op was persisted under.
    pub record_id: Vec<u8>,
    /// The canonical `COSE_Sign1` bytes of the signed op.
    pub op_bytes: Vec<u8>,
}

/// v1 self-issued capability tokens carry no explicit expiry (D0035 §4):
/// the collapsed single key is its own authority, rotated only when the
/// master hierarchy lands (§7).
const SELF_TOKEN_NO_EXPIRY: u64 = 0;

/// The write surface for the trust graph (D0035 §4).
///
/// Mints signed, persisted, cascade-revocable attestations + revocations
/// on the v1 collapsed single-key identity, and classifies a contact's
/// stored chain for the trust badge.
///
/// Holds the StrongBox [`HardwareKeySigner`] callback (the device key
/// never crosses), the operational pubkey (== device key in v1, D0035
/// §1), and the shared `Arc<Storage>`. The self-issued capability token
/// (D0035 §1) is minted lazily on first use and cached in-memory —
/// re-minting is deterministic (Ed25519), so it is an optimization, not a
/// correctness requirement.
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct TrustGraphHandle {
    storage: Arc<Storage>,
    signer: Box<dyn HardwareKeySigner>,
    device_key_alias: String,
    operational_pubkey: VerifyingKey,
    self_token: Mutex<Option<Vec<u8>>>,
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "UniFFI exports/constructors take owned arguments by value; the FFI layer owns the lowered buffers"
)]
impl TrustGraphHandle {
    /// Construct the trust-graph write handle over `storage`'s shared
    /// store, with op + self-token signing mediated by the StrongBox
    /// `signer` callback (the key never crosses; D0035 §4).
    ///
    /// `device_key_alias` names the StrongBox key; `operational_pubkey` is
    /// this identity's 32-byte operational pubkey (== the device key in
    /// the v1 collapsed identity, D0035 §1).
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `operational_pubkey` is not a
    ///   valid 32-byte Ed25519 public key.
    /// - [`CairnFfiError::StorageFailure`] if the trust-graph category
    ///   schema cannot be initialized.
    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    pub fn new(
        storage: Arc<StorageHandle>,
        signer: Box<dyn HardwareKeySigner>,
        device_key_alias: String,
        operational_pubkey: Vec<u8>,
    ) -> Result<Arc<Self>, CairnFfiError> {
        let operational_pubkey = parse_pubkey(&operational_pubkey)?;
        Self::assemble(
            storage.storage_arc(),
            signer,
            device_key_alias,
            operational_pubkey,
        )
    }

    /// Mint + persist an `Attest` op for `subject_operational_pubkey` with
    /// the given verification `strength` (D0035 §3). Chains on this
    /// identity's prior op for the pair; genesis when none exists.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] for a non-32-byte subject key.
    /// - The original signer error if the StrongBox sign fails.
    /// - [`CairnFfiError::StorageFailure`] for a persistence failure.
    pub fn attest(
        &self,
        subject_operational_pubkey: Vec<u8>,
        strength: StrengthFfi,
        now_unix: u64,
    ) -> Result<TrustGraphOpRecord, CairnFfiError> {
        let subject = parse_pubkey(&subject_operational_pubkey)?;
        let (prior_hash, floor_ts) = self.prior_for(&subject)?;
        let op = TrustGraphOp::new_attest(
            self.operational_pubkey,
            subject,
            now_unix.max(floor_ts),
            prior_hash,
            Vec::new(),
            strength.to_domain(),
        );
        self.mint_op(op)
    }

    /// Mint + persist a `WithdrawRevoke` op for `subject_operational_pubkey`
    /// (a clean retraction; no cascade — D0035 §6).
    ///
    /// # Errors
    ///
    /// As [`Self::attest`].
    pub fn withdraw_revoke(
        &self,
        subject_operational_pubkey: Vec<u8>,
        now_unix: u64,
    ) -> Result<TrustGraphOpRecord, CairnFfiError> {
        let subject = parse_pubkey(&subject_operational_pubkey)?;
        let (prior_hash, floor_ts) = self.prior_for(&subject)?;
        let op = TrustGraphOp::new_withdraw_revoke(
            self.operational_pubkey,
            subject,
            now_unix.max(floor_ts),
            prior_hash,
            Vec::new(),
        );
        self.mint_op(op)
    }

    /// Mint + persist a `CompromiseRevoke` op for
    /// `subject_operational_pubkey` (triggers the cascade quarantine for
    /// attestations after `revoked_as_of` — D0035 §6).
    ///
    /// # Errors
    ///
    /// As [`Self::attest`].
    pub fn compromise_revoke(
        &self,
        subject_operational_pubkey: Vec<u8>,
        revoked_as_of: u64,
        now_unix: u64,
    ) -> Result<TrustGraphOpRecord, CairnFfiError> {
        let subject = parse_pubkey(&subject_operational_pubkey)?;
        let (prior_hash, floor_ts) = self.prior_for(&subject)?;
        let op = TrustGraphOp::new_compromise_revoke(
            self.operational_pubkey,
            subject,
            now_unix.max(floor_ts),
            prior_hash,
            Vec::new(),
            revoked_as_of,
        );
        self.mint_op(op)
    }

    /// Load this identity's stored op chain for `subject_operational_pubkey`,
    /// verify it, and return the per-op cascade-quarantine status (D0035 §5
    /// — the input the trust badge interprets). Empty when no ops exist.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] for a non-32-byte subject key.
    /// - [`CairnFfiError::ChainInvalid`] / `SignatureVerifyFailed` if the
    ///   stored chain fails verification.
    /// - The original signer error if minting the self-token fails.
    pub fn load_and_classify(
        &self,
        subject_operational_pubkey: Vec<u8>,
    ) -> Result<Vec<QuarantineStatusFfi>, CairnFfiError> {
        let subject = parse_pubkey(&subject_operational_pubkey)?;
        let chain = load_chain_for_pair(&self.storage, &self.operational_pubkey, &subject)?;
        if chain.is_empty() {
            return Ok(Vec::new());
        }
        let token = self.ensure_self_token()?;
        let verified = verify_chain_links(&chain, &token, &self.operational_pubkey)?;
        Ok(compute_quarantine_state(&verified)
            .into_iter()
            .map(QuarantineStatusFfi::from)
            .collect())
    }
}

impl TrustGraphHandle {
    /// Shared construction over an already-shared `Arc<Storage>` (the
    /// path the `new` constructor + tests both take). Initializes the
    /// trust-graph category schema (idempotent).
    fn assemble(
        storage: Arc<Storage>,
        signer: Box<dyn HardwareKeySigner>,
        device_key_alias: String,
        operational_pubkey: VerifyingKey,
    ) -> Result<Arc<Self>, CairnFfiError> {
        initialize_schema(&storage)?;
        Ok(Arc::new(Self {
            storage,
            signer,
            device_key_alias,
            operational_pubkey,
            self_token: Mutex::new(None),
        }))
    }

    /// The `(prior_hash, floor_timestamp)` for a new op in this identity's
    /// chain with `subject`: the SHA-256 of the latest op's signature (or
    /// empty for genesis) + the latest op's timestamp (or 0), so the new
    /// op's timestamp can be clamped non-decreasing (D0006 §5).
    fn prior_for(&self, subject: &VerifyingKey) -> Result<(Vec<u8>, u64), CairnFfiError> {
        let chain = load_chain_for_pair(&self.storage, &self.operational_pubkey, subject)?;
        Ok(chain.last().map_or_else(
            || (Vec::new(), 0),
            |last| (last.prior_hash_bytes().to_vec(), last.op().timestamp),
        ))
    }

    /// Sign `op` with the StrongBox device key + persist it. Preserves the
    /// signer's original [`CairnFfiError`] on a hardware-signing failure
    /// (rather than collapsing it through the trust-graph facade).
    fn mint_op(&self, op: TrustGraphOp) -> Result<TrustGraphOpRecord, CairnFfiError> {
        let mut signer_err: Option<CairnFfiError> = None;
        let signed = SignedTrustGraphOp::sign_external(op, |signing_input| {
            match self
                .signer
                .sign(self.device_key_alias.clone(), signing_input.to_vec())
            {
                Ok(sig) => Ok(sig),
                Err(err) => {
                    signer_err = Some(err);
                    Err(TrustGraphError::ExternalSignerFailed)
                }
            }
        });
        let signed = match signed {
            Ok(signed) => signed,
            Err(TrustGraphError::ExternalSignerFailed) => {
                return Err(signer_err.unwrap_or(CairnFfiError::UnmappedInternal));
            }
            Err(err) => return Err(err.into()),
        };
        let record_id = store_signed_op(&self.storage, &signed)?;
        let op_bytes = signed.encode(false).map_err(CairnFfiError::from)?;
        Ok(TrustGraphOpRecord {
            record_id: record_id.to_vec(),
            op_bytes,
        })
    }

    /// Load-or-mint the v1 self-issued capability token (D0035 §1),
    /// caching it in-memory. The collapsed key signs a token naming
    /// itself, authorizing all trust-graph op types.
    fn ensure_self_token(&self) -> Result<Vec<u8>, CairnFfiError> {
        // Fast path: return the cached token. The guard is scoped to this
        // block so the StrongBox sign below does NOT hold the lock.
        {
            let guard = self
                .self_token
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(bytes) = guard.as_ref() {
                return Ok(bytes.clone());
            }
        }
        // Mint the self-token (a StrongBox sign) OUTSIDE the lock. A benign
        // race (two threads both mint) yields byte-identical tokens —
        // Ed25519 is deterministic — and last write wins.
        let token = self_issued_token(self.operational_pubkey, SELF_TOKEN_NO_EXPIRY);
        let mut signer_err: Option<CairnFfiError> = None;
        let signed = token.sign_external(|signing_input| {
            match self
                .signer
                .sign(self.device_key_alias.clone(), signing_input.to_vec())
            {
                Ok(sig) => Ok(sig),
                Err(err) => {
                    signer_err = Some(err);
                    Err(IdentityError::ExternalSignerFailed)
                }
            }
        });
        let signed = match signed {
            Ok(signed) => signed,
            Err(IdentityError::ExternalSignerFailed) => {
                return Err(signer_err.unwrap_or(CairnFfiError::UnmappedInternal));
            }
            Err(err) => return Err(err.into()),
        };
        let bytes = signed.encode(false).map_err(CairnFfiError::from)?;
        // Re-acquire briefly to cache the minted token.
        self.self_token
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(bytes.clone());
        Ok(bytes)
    }
}

/// Parse a 32-byte Ed25519 operational/subject public key, mapping any
/// length or curve-point error to [`CairnFfiError::MalformedData`].
fn parse_pubkey(bytes: &[u8]) -> Result<VerifyingKey, CairnFfiError> {
    let arr: [u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| CairnFfiError::MalformedData)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| CairnFfiError::MalformedData)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests assert on known-shape fixtures; index/unwrap panics ARE the failure signal"
)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use cairn_identity::{CapabilityToken, capabilities};
    use cairn_trust_graph::TrustGraphOp;
    use rand_core::OsRng;

    /// Build `(expected_operational_identity_bytes, capability_token_bytes,
    /// genesis_attest_op_bytes)` for a single valid genesis attestation
    /// authorizing `device` under the attest scope. Mirrors the
    /// `cairn-trust-graph` signed-op test fixture.
    fn single_genesis_attest() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let op_identity_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();

        let token = CapabilityToken::new(
            op_identity_sk.verifying_key(),
            device_sk.verifying_key(),
            vec![capabilities::TRUST_GRAPH_ATTEST.to_string()],
            2_000_000_000,
            vec![],
        );
        let token_bytes = token.sign(&op_identity_sk).unwrap().encode(false).unwrap();

        // Genesis attest: empty prior_hash.
        let op = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![],
            vec![],
            cairn_trust_graph::Strength::InPerson,
        );
        let op_bytes = SignedTrustGraphOp::sign(op, &device_sk)
            .unwrap()
            .encode(false)
            .unwrap();

        (
            op_identity_sk.verifying_key().to_bytes().to_vec(),
            token_bytes,
            op_bytes,
        )
    }

    #[test]
    fn single_genesis_attest_classifies_active() {
        let (expected, token, op) = single_genesis_attest();
        let statuses = trust_graph_verify_and_classify(vec![op], token, expected).unwrap();
        assert_eq!(statuses, vec![QuarantineStatusFfi::Active]);
    }

    #[test]
    fn empty_chain_maps_to_chain_invalid() {
        // A syntactically valid pubkey, but no ops → ChainEmpty →
        // ChainInvalid (the facade flattening of the chain errors).
        let (expected, token, _op) = single_genesis_attest();
        let err = trust_graph_verify_and_classify(vec![], token, expected).unwrap_err();
        assert_eq!(err, CairnFfiError::ChainInvalid);
    }

    #[test]
    fn wrong_length_pubkey_maps_to_malformed_data() {
        let (_expected, token, op) = single_genesis_attest();
        let err = trust_graph_verify_and_classify(vec![op], token, vec![0u8; 31]).unwrap_err();
        assert_eq!(err, CairnFfiError::MalformedData);
    }

    #[test]
    fn malformed_op_bytes_map_to_malformed_data() {
        // Valid pubkey, but the op bytes are not COSE_Sign1 → decode
        // fails as MalformedPayload → MalformedData.
        let (expected, token, _op) = single_genesis_attest();
        let err =
            trust_graph_verify_and_classify(vec![vec![0xFFu8; 8]], token, expected).unwrap_err();
        assert_eq!(err, CairnFfiError::MalformedData);
    }

    #[test]
    fn tampered_token_rejected_as_signature_failure() {
        // Flip the last byte of the capability token (the signature
        // tail); verification must fail and never reach the cascade
        // rule. Every capability-token verify failure collapses to
        // SignatureVerifyFailed (D0027 §3.2) — a deterministic mapping,
        // NOT UnmappedInternal (regression-guarded in error.rs).
        let (expected, mut token, op) = single_genesis_attest();
        let last = token.len() - 1;
        token[last] ^= 0x01;
        let err = trust_graph_verify_and_classify(vec![op], token, expected).unwrap_err();
        assert_eq!(err, CairnFfiError::SignatureVerifyFailed);
    }

    // === TrustGraphHandle mint surface (D0035 §4) ===

    /// A `HardwareKeySigner` backed by a real in-memory Ed25519 key, so
    /// minted ops + the self-token actually verify (the production
    /// `StrongBox` key is replaced by this software key in the host test).
    struct RealKeySigner {
        key: SigningKey,
    }

    impl HardwareKeySigner for RealKeySigner {
        fn sign(&self, _key_alias: String, payload: Vec<u8>) -> Result<Vec<u8>, CairnFfiError> {
            self.key
                .sign(&payload)
                .map(|sig| sig.to_bytes().to_vec())
                .map_err(|_| CairnFfiError::UnmappedInternal)
        }

        fn generate_key(
            &self,
            _key_alias: String,
            _spec: crate::hardware::KeyGenSpec,
        ) -> Result<crate::hardware::HardwarePublicKey, CairnFfiError> {
            Err(CairnFfiError::MalformedData)
        }

        fn attestation_chain(
            &self,
            _key_alias: String,
        ) -> Result<Vec<crate::hardware::AttestationCertificate>, CairnFfiError> {
            Err(CairnFfiError::MalformedData)
        }
    }

    fn in_memory_storage() -> Arc<Storage> {
        use cairn_storage::key_provider::testing::InMemoryKeyProvider;
        use zeroize::Zeroizing;
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"trust-graph-test".to_vec());
        Arc::new(Storage::open_in_memory(&provider, &passphrase).unwrap())
    }

    /// Build a handle over a fresh in-memory store whose device +
    /// operational identity is the single key `key` (D0035 §1 collapse).
    /// Takes `key` by value (`SigningKey` is intentionally non-`Clone`).
    fn handle_for(key: SigningKey) -> Arc<TrustGraphHandle> {
        let operational_pubkey = key.verifying_key();
        TrustGraphHandle::assemble(
            in_memory_storage(),
            Box::new(RealKeySigner { key }),
            "device-key".to_string(),
            operational_pubkey,
        )
        .unwrap()
    }

    #[test]
    fn mint_attest_persists_and_classifies_active() {
        let mut rng = OsRng;
        let me = SigningKey::generate(&mut rng);
        let peer = SigningKey::generate(&mut rng).verifying_key();
        let handle = handle_for(me);
        let peer_bytes = peer.to_bytes().to_vec();

        let record = handle
            .attest(peer_bytes.clone(), StrengthFfi::InPerson, 1_700_000_000)
            .unwrap();
        assert!(!record.record_id.is_empty());

        // The persisted op decodes with the strength we minted.
        let decoded = SignedTrustGraphOp::from_bytes(&record.op_bytes).unwrap();
        assert_eq!(decoded.op().strength, Some(Strength::InPerson));

        // The stored chain verifies (self-token + collapsed identity) and
        // classifies Active — the full mint→persist→verify→classify loop.
        let statuses = handle.load_and_classify(peer_bytes).unwrap();
        assert_eq!(statuses, vec![QuarantineStatusFfi::Active]);
    }

    #[test]
    fn second_attest_chains_on_the_first() {
        let mut rng = OsRng;
        let me = SigningKey::generate(&mut rng);
        let peer = SigningKey::generate(&mut rng).verifying_key();
        let handle = handle_for(me);
        let peer_bytes = peer.to_bytes().to_vec();

        handle
            .attest(peer_bytes.clone(), StrengthFfi::Asserted, 1_700_000_000)
            .unwrap();
        handle
            .attest(peer_bytes.clone(), StrengthFfi::InPerson, 1_700_000_100)
            .unwrap();

        // Genesis + chained op verify as one chain → two Active statuses.
        let statuses = handle.load_and_classify(peer_bytes).unwrap();
        assert_eq!(
            statuses,
            vec![QuarantineStatusFfi::Active, QuarantineStatusFfi::Active]
        );
    }

    #[test]
    fn compromise_revoke_is_minted_and_classifiable() {
        let mut rng = OsRng;
        let me = SigningKey::generate(&mut rng);
        let peer = SigningKey::generate(&mut rng).verifying_key();
        let handle = handle_for(me);
        let peer_bytes = peer.to_bytes().to_vec();

        handle
            .attest(peer_bytes.clone(), StrengthFfi::InPerson, 1_700_000_000)
            .unwrap();
        handle
            .compromise_revoke(peer_bytes.clone(), 1_700_000_050, 1_700_000_100)
            .unwrap();

        // Two ops in the chain; the cascade classifier runs without error.
        let statuses = handle.load_and_classify(peer_bytes).unwrap();
        assert_eq!(statuses.len(), 2);
    }

    #[test]
    fn classify_unknown_subject_is_empty() {
        let mut rng = OsRng;
        let me = SigningKey::generate(&mut rng);
        let stranger = SigningKey::generate(&mut rng).verifying_key();
        let handle = handle_for(me);
        let statuses = handle
            .load_and_classify(stranger.to_bytes().to_vec())
            .unwrap();
        assert!(statuses.is_empty());
    }

    #[test]
    fn attest_rejects_malformed_subject_key() {
        let mut rng = OsRng;
        let me = SigningKey::generate(&mut rng);
        let handle = handle_for(me);
        let err = handle
            .attest(vec![0u8; 31], StrengthFfi::InPerson, 1_700_000_000)
            .unwrap_err();
        assert_eq!(err, CairnFfiError::MalformedData);
    }
}
