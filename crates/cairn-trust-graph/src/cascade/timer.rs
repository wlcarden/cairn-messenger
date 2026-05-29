// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! 90-day stale-flag escalation per D0006 §2.
//!
//! D0006 §2:
//!
//! > Stale-flag escalation. A soft-flagged attestation that remains
//! > flagged for 90 days without the user taking explicit action
//! > (re-attest, accept-with-acknowledgment, or quarantine) auto-
//! > quarantines. The 90-day clock is per-attestation and resets if
//! > the user touches it.
//!
//! This module implements the per-attestation timer baselines + UI
//! acknowledgment history through [`cairn_storage::Storage`] in the
//! [`cairn_storage::categories::QUARANTINE_STATE`] category.
//!
//! ## Record format
//!
//! Each attestation that the cascade-quarantine layer flags as
//! `SoftFlaggedByWithdrawal` or `SoftFlaggedPreCompromise` (per
//! [`crate::QuarantineStatus`]) gets a `TimerState` record keyed by
//! `record_id = SHA-256(issuer ‖ subject ‖ timestamp_be_bytes)`. The
//! payload schema:
//!
//! | Field | Type | Notes |
//! | --- | --- | --- |
//! | `first_observed_at` | uint Unix-seconds | When the storage layer first saw the flag |
//! | `last_acknowledged_at` | Option<uint Unix-seconds> | Most recent user touch, if any |
//!
//! The 90-day clock is measured from `last_acknowledged_at` if set,
//! else from `first_observed_at`. Escalation fires when `now -
//! anchor >= STALE_FLAG_ESCALATION_SECONDS`.
//!
//! ## Composition with the cascade primitive
//!
//! [`escalate_quarantine_status`] consumes a base
//! [`crate::QuarantineStatus`] from [`crate::compute_quarantine_state`]
//! and upgrades it from `SoftFlagged*` to a virtual `HardSuspended`
//! once the 90-day window elapses without acknowledgment. The
//! original cascade-rule result is unmodified; the timer-aware
//! decoration is the caller's choice at display time.
//!
//! ## What this module does NOT do
//!
//! - **Re-attestation policy enforcement** per D0006 §2's stricter
//!   re-attestation requirements (fresh in-person verification or
//!   two independent unflagged paths). That's UI-layer policy + a
//!   future surface in `cairn-trust-graph::policy`.
//! - **Quarantine *event* logging**: the user-visible "this got
//!   auto-quarantined because you didn't touch it for 90 days" event
//!   stream is a UI concern. This module surfaces the boolean
//!   `is_stale` + the timer state; the UI consumes them.

use cairn_crypto::ed25519::VerifyingKey;
use cairn_envelope::canonical::Value;
use cairn_storage::{Storage, StorageError, categories};
use ciborium::Value as CiboriumValue;
use sha2::{Digest, Sha256};

use crate::QuarantineStatus;

/// 90 days in seconds per D0006 §2's stale-flag escalation rule.
pub const STALE_FLAG_ESCALATION_SECONDS: u64 = 90 * 24 * 60 * 60;

/// Per-category schema version for the `QUARANTINE_STATE` storage
/// records per D0022 §3.1. Bumped when the record payload schema
/// changes.
pub const QUARANTINE_TIMER_SCHEMA_VERSION: u32 = 1;

/// Canonical-CBOR map key for `first_observed_at`.
const KEY_FIRST_OBSERVED: i64 = 1;
/// Canonical-CBOR map key for `last_acknowledged_at`.
const KEY_LAST_ACKNOWLEDGED: i64 = 2;

/// The persisted timer state for one soft-flagged attestation per
/// D0006 §2's 90-day clock.
///
/// `first_observed_at` is set once when the storage layer first sees
/// the flag for this attestation. `last_acknowledged_at` is updated
/// every time the user performs an explicit action that "touches"
/// the flag (re-attest, accept-with-acknowledgment, etc.).
///
/// The escalation anchor is `last_acknowledged_at.unwrap_or(first_observed_at)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerState {
    /// Unix-seconds when the storage layer first observed the flag
    /// for this attestation.
    pub first_observed_at: u64,
    /// Most recent user-touch Unix-seconds, if any.
    pub last_acknowledged_at: Option<u64>,
}

impl TimerState {
    /// Construct a `TimerState` for a freshly-observed flag (no prior
    /// acknowledgment).
    #[must_use]
    pub const fn freshly_observed(now: u64) -> Self {
        Self {
            first_observed_at: now,
            last_acknowledged_at: None,
        }
    }

    /// Update the timer to record a user acknowledgment at `now`.
    /// Subsequent staleness checks anchor against this timestamp.
    #[must_use]
    pub const fn with_acknowledgment(mut self, now: u64) -> Self {
        self.last_acknowledged_at = Some(now);
        self
    }

    /// Compute the escalation anchor — the timestamp the 90-day
    /// clock counts from. `last_acknowledged_at` if set, else
    /// `first_observed_at`.
    #[must_use]
    pub const fn escalation_anchor(&self) -> u64 {
        match self.last_acknowledged_at {
            Some(t) => t,
            None => self.first_observed_at,
        }
    }

    /// Has the 90-day window elapsed since the escalation anchor?
    #[must_use]
    pub const fn is_stale(&self, now: u64) -> bool {
        let anchor = self.escalation_anchor();
        now.saturating_sub(anchor) >= STALE_FLAG_ESCALATION_SECONDS
    }

    /// Encode as canonical-CBOR for storage. Bound into the AAD
    /// per D0022 §2.4 via the storage layer's slot-binding.
    ///
    /// # Errors
    ///
    /// Propagates the canonical encoder failure (unreachable for the
    /// typed input).
    fn to_canonical_cbor(self) -> Result<Vec<u8>, TimerError> {
        let first =
            i64::try_from(self.first_observed_at).map_err(|_| TimerError::TimestampOutOfRange)?;
        let mut entries: Vec<(Value, Value)> =
            vec![(Value::Int(KEY_FIRST_OBSERVED), Value::Int(first))];
        if let Some(ack) = self.last_acknowledged_at {
            let ack_i64 = i64::try_from(ack).map_err(|_| TimerError::TimestampOutOfRange)?;
            entries.push((Value::Int(KEY_LAST_ACKNOWLEDGED), Value::Int(ack_i64)));
        }
        Value::Map(entries)
            .encode()
            .map_err(|e| TimerError::Storage(StorageError::CanonicalEncode(e)))
    }

    /// Decode from canonical-CBOR bytes produced by `to_canonical_cbor`.
    ///
    /// # Errors
    ///
    /// - [`TimerError::MalformedPayload`] for any CBOR / schema
    ///   structural error
    /// - [`TimerError::TimestampOutOfRange`] for negative or
    ///   `> 2^63` timestamps
    fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, TimerError> {
        let parsed: CiboriumValue =
            ciborium::de::from_reader(bytes).map_err(|_| TimerError::MalformedPayload)?;
        let CiboriumValue::Map(entries) = parsed else {
            return Err(TimerError::MalformedPayload);
        };
        let mut first_observed_at: Option<u64> = None;
        let mut last_acknowledged_at: Option<u64> = None;
        for (key, value) in entries {
            let CiboriumValue::Integer(key_int_ciborium) = key else {
                return Err(TimerError::MalformedPayload);
            };
            let key_int = i64::try_from(i128::from(key_int_ciborium))
                .map_err(|_| TimerError::MalformedPayload)?;
            match key_int {
                KEY_FIRST_OBSERVED => {
                    let CiboriumValue::Integer(v) = value else {
                        return Err(TimerError::MalformedPayload);
                    };
                    first_observed_at = Some(
                        u64::try_from(i128::from(v))
                            .map_err(|_| TimerError::TimestampOutOfRange)?,
                    );
                }
                KEY_LAST_ACKNOWLEDGED => {
                    let CiboriumValue::Integer(v) = value else {
                        return Err(TimerError::MalformedPayload);
                    };
                    last_acknowledged_at = Some(
                        u64::try_from(i128::from(v))
                            .map_err(|_| TimerError::TimestampOutOfRange)?,
                    );
                }
                _ => {} // forward-compat per D0006 §6.4
            }
        }
        let first_observed_at = first_observed_at.ok_or(TimerError::MalformedPayload)?;
        Ok(Self {
            first_observed_at,
            last_acknowledged_at,
        })
    }
}

/// Errors specific to the cascade timer state layer.
///
/// `#[non_exhaustive]` per D0018 §4.2.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TimerError {
    /// Failure from the underlying [`Storage`] handle.
    #[error("cascade timer: storage failure: {0}")]
    Storage(#[from] StorageError),
    /// The persisted timer payload was not well-formed canonical CBOR
    /// or did not match the schema.
    #[error("cascade timer: malformed payload")]
    MalformedPayload,
    /// A timestamp didn't fit in `i64` for canonical-CBOR encoding,
    /// or was negative when decoding to `u64`.
    #[error("cascade timer: timestamp out of representable range")]
    TimestampOutOfRange,
}

/// Compute the on-disk record id for the timer state of an
/// attestation identified by `(issuer, subject, timestamp)`.
///
/// SHA-256 of the concatenation; deterministic across runs.
#[must_use]
pub fn timer_record_id(issuer: &VerifyingKey, subject: &VerifyingKey, timestamp: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(issuer.to_bytes());
    hasher.update(subject.to_bytes());
    hasher.update(timestamp.to_be_bytes());
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Observe a flag for an attestation: set the timer baseline if not
/// already present.
///
/// Idempotent if a timer record already exists for this attestation
/// — the existing `first_observed_at` is preserved, the existing
/// `last_acknowledged_at` is preserved. The 90-day clock thus
/// anchors at the first-observation time per D0006 §2 spec ("The
/// 90-day clock is per-attestation and resets if the user touches
/// it" — the clock STARTS at first observation; it RESETS on
/// acknowledgment via [`acknowledge_flag`]).
///
/// # Errors
///
/// - [`TimerError::Storage`] for storage failures
/// - [`TimerError::MalformedPayload`] if an existing record is
///   corrupted past the AEAD check
pub fn observe_flag(
    storage: &Storage,
    issuer: &VerifyingKey,
    subject: &VerifyingKey,
    attestation_timestamp: u64,
    now: u64,
) -> Result<TimerState, TimerError> {
    let id = timer_record_id(issuer, subject, attestation_timestamp);
    match storage.get(categories::QUARANTINE_STATE, &id) {
        Ok(bytes) => {
            // Existing record: parse + return without modification.
            TimerState::from_canonical_cbor(&bytes)
        }
        Err(StorageError::RecordNotFound { .. }) => {
            // First observation: write a fresh baseline.
            let state = TimerState::freshly_observed(now);
            let bytes = state.to_canonical_cbor()?;
            storage.put(categories::QUARANTINE_STATE, &id, &bytes)?;
            Ok(state)
        }
        Err(e) => Err(TimerError::from(e)),
    }
}

/// Record a user acknowledgment for a flagged attestation. Resets
/// the 90-day clock to `now`.
///
/// If no timer record exists yet (the flag wasn't previously
/// observed), this also creates the record — `first_observed_at` is
/// set to `now` and `last_acknowledged_at` is also `now`. The combined
/// effect is equivalent to "the flag was observed and immediately
/// acknowledged."
///
/// # Errors
///
/// - [`TimerError::Storage`] for storage failures
pub fn acknowledge_flag(
    storage: &Storage,
    issuer: &VerifyingKey,
    subject: &VerifyingKey,
    attestation_timestamp: u64,
    now: u64,
) -> Result<TimerState, TimerError> {
    let id = timer_record_id(issuer, subject, attestation_timestamp);
    let mut state = match storage.get(categories::QUARANTINE_STATE, &id) {
        Ok(bytes) => TimerState::from_canonical_cbor(&bytes)?,
        Err(StorageError::RecordNotFound { .. }) => TimerState::freshly_observed(now),
        Err(e) => return Err(TimerError::from(e)),
    };
    state = state.with_acknowledgment(now);
    let bytes = state.to_canonical_cbor()?;
    storage.put(categories::QUARANTINE_STATE, &id, &bytes)?;
    Ok(state)
}

/// Load the current timer state for an attestation, if one exists.
///
/// Returns `Ok(None)` if the attestation has not been flagged yet
/// (no timer record).
///
/// # Errors
///
/// - [`TimerError::Storage`] for storage failures
/// - [`TimerError::MalformedPayload`] for corrupted records past
///   the AEAD check
pub fn load_timer_state(
    storage: &Storage,
    issuer: &VerifyingKey,
    subject: &VerifyingKey,
    attestation_timestamp: u64,
) -> Result<Option<TimerState>, TimerError> {
    let id = timer_record_id(issuer, subject, attestation_timestamp);
    match storage.get(categories::QUARANTINE_STATE, &id) {
        Ok(bytes) => Ok(Some(TimerState::from_canonical_cbor(&bytes)?)),
        Err(StorageError::RecordNotFound { .. }) => Ok(None),
        Err(e) => Err(TimerError::from(e)),
    }
}

/// Upgrade a base `QuarantineStatus` to `HardSuspended` if the
/// associated timer has elapsed without acknowledgment.
///
/// Composition contract:
///
/// 1. Base status from [`crate::compute_quarantine_state`] is the
///    static-set cascade rule per D0006 §2.
/// 2. If the base status is one of the `SoftFlagged*` variants AND
///    a stored timer is stale at `now`, upgrade to a virtual
///    `HardSuspended` with the original revoker pubkey + anchor.
/// 3. Other statuses pass through unchanged.
///
/// The base cascade rule's `HardSuspended` always passes through
/// — once compromise-revoked post-revoke, no acknowledgment-window
/// argument applies.
#[must_use]
pub fn escalate_quarantine_status(
    base: QuarantineStatus,
    timer: Option<TimerState>,
    now: u64,
) -> QuarantineStatus {
    let is_stale = timer.is_some_and(|t| t.is_stale(now));
    match base {
        QuarantineStatus::SoftFlaggedByWithdrawal {
            revoked_by,
            withdrawal_at,
        } if is_stale => QuarantineStatus::HardSuspended {
            revoked_by,
            revoked_as_of: withdrawal_at,
        },
        QuarantineStatus::SoftFlaggedPreCompromise {
            revoked_by,
            revoked_as_of,
        } if is_stale => QuarantineStatus::HardSuspended {
            revoked_by,
            revoked_as_of,
        },
        other => other,
    }
}

/// Initialize / migrate the `QUARANTINE_STATE` category's schema per
/// D0022 §3.2.
///
/// v1 lands the bootstrap schema only. Idempotent.
///
/// # Errors
///
/// - [`TimerError::Storage`] for storage failures
pub fn initialize_schema(storage: &Storage) -> Result<(), TimerError> {
    let current = storage
        .category_schema_version(categories::QUARANTINE_STATE)
        .map_err(TimerError::from)?;
    if current >= QUARANTINE_TIMER_SCHEMA_VERSION {
        return Ok(());
    }
    storage
        .set_category_schema_version(
            categories::QUARANTINE_STATE,
            QUARANTINE_TIMER_SCHEMA_VERSION,
        )
        .map_err(TimerError::from)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use cairn_storage::key_provider::testing::InMemoryKeyProvider;
    use rand_core::OsRng;
    use zeroize::Zeroizing;

    fn open_storage() -> Storage {
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"test passphrase".to_vec());
        Storage::open_in_memory(&provider, &passphrase).unwrap()
    }

    fn make_keys() -> (VerifyingKey, VerifyingKey) {
        let mut rng = OsRng;
        let issuer = SigningKey::generate(&mut rng).verifying_key();
        let subject = SigningKey::generate(&mut rng).verifying_key();
        (issuer, subject)
    }

    #[test]
    fn timer_record_id_is_deterministic() {
        let (issuer, subject) = make_keys();
        let id_a = timer_record_id(&issuer, &subject, 1_700_000_000);
        let id_b = timer_record_id(&issuer, &subject, 1_700_000_000);
        assert_eq!(id_a, id_b);
    }

    #[test]
    fn timer_record_id_differs_across_attestations() {
        let (issuer, subject) = make_keys();
        let (other_issuer, _) = make_keys();
        // Different timestamps → different ids.
        assert_ne!(
            timer_record_id(&issuer, &subject, 100),
            timer_record_id(&issuer, &subject, 200)
        );
        // Different issuers → different ids.
        assert_ne!(
            timer_record_id(&issuer, &subject, 100),
            timer_record_id(&other_issuer, &subject, 100)
        );
    }

    #[test]
    fn observe_flag_sets_baseline_on_first_observation() {
        let storage = open_storage();
        let (issuer, subject) = make_keys();
        let state =
            observe_flag(&storage, &issuer, &subject, 1_700_000_000, 1_705_000_000).unwrap();
        assert_eq!(state.first_observed_at, 1_705_000_000);
        assert_eq!(state.last_acknowledged_at, None);
    }

    #[test]
    fn observe_flag_is_idempotent() {
        let storage = open_storage();
        let (issuer, subject) = make_keys();
        let state_a =
            observe_flag(&storage, &issuer, &subject, 1_700_000_000, 1_705_000_000).unwrap();
        // Second observe at a different `now` preserves the original
        // baseline — the timer doesn't reset on re-observation.
        let state_b =
            observe_flag(&storage, &issuer, &subject, 1_700_000_000, 1_710_000_000).unwrap();
        assert_eq!(state_a, state_b);
        assert_eq!(state_b.first_observed_at, 1_705_000_000);
    }

    #[test]
    fn acknowledge_flag_resets_clock_anchor() {
        let storage = open_storage();
        let (issuer, subject) = make_keys();
        observe_flag(&storage, &issuer, &subject, 1_700_000_000, 1_705_000_000).unwrap();
        let acked =
            acknowledge_flag(&storage, &issuer, &subject, 1_700_000_000, 1_708_000_000).unwrap();
        assert_eq!(acked.first_observed_at, 1_705_000_000);
        assert_eq!(acked.last_acknowledged_at, Some(1_708_000_000));
        assert_eq!(acked.escalation_anchor(), 1_708_000_000);
    }

    #[test]
    fn acknowledge_flag_without_prior_observe_creates_record() {
        let storage = open_storage();
        let (issuer, subject) = make_keys();
        let state =
            acknowledge_flag(&storage, &issuer, &subject, 1_700_000_000, 1_705_000_000).unwrap();
        assert_eq!(state.first_observed_at, 1_705_000_000);
        assert_eq!(state.last_acknowledged_at, Some(1_705_000_000));
    }

    #[test]
    fn is_stale_returns_false_within_window() {
        let state = TimerState::freshly_observed(1_705_000_000);
        // 89 days later.
        let almost_window = 1_705_000_000 + (89 * 24 * 60 * 60);
        assert!(!state.is_stale(almost_window));
    }

    #[test]
    fn is_stale_returns_true_at_exactly_90_days() {
        let state = TimerState::freshly_observed(1_705_000_000);
        let exactly_window = 1_705_000_000 + STALE_FLAG_ESCALATION_SECONDS;
        assert!(state.is_stale(exactly_window));
    }

    #[test]
    fn is_stale_returns_true_well_past_window() {
        let state = TimerState::freshly_observed(1_705_000_000);
        let way_past = 1_705_000_000 + (180 * 24 * 60 * 60);
        assert!(state.is_stale(way_past));
    }

    #[test]
    fn acknowledge_resets_staleness_check() {
        // Observe at t=0; 80 days pass; acknowledge; another 80 days
        // pass. is_stale at +160d should be false because the
        // acknowledgment reset the clock at +80d.
        let state = TimerState::freshly_observed(1_705_000_000)
            .with_acknowledgment(1_705_000_000 + 80 * 24 * 60 * 60);
        let later = 1_705_000_000 + 160 * 24 * 60 * 60;
        assert!(!state.is_stale(later));
    }

    #[test]
    fn timer_state_round_trips_through_canonical_cbor() {
        let original = TimerState {
            first_observed_at: 1_705_000_000,
            last_acknowledged_at: Some(1_708_000_000),
        };
        let bytes = original.to_canonical_cbor().unwrap();
        let recovered = TimerState::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(original, recovered);

        // Without ack.
        let original = TimerState::freshly_observed(1_705_000_000);
        let bytes = original.to_canonical_cbor().unwrap();
        let recovered = TimerState::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn load_timer_state_returns_none_for_unobserved() {
        let storage = open_storage();
        let (issuer, subject) = make_keys();
        assert_eq!(
            load_timer_state(&storage, &issuer, &subject, 1_700_000_000).unwrap(),
            None
        );
    }

    #[test]
    fn load_timer_state_returns_persisted_state() {
        let storage = open_storage();
        let (issuer, subject) = make_keys();
        observe_flag(&storage, &issuer, &subject, 1_700_000_000, 1_705_000_000).unwrap();
        let loaded = load_timer_state(&storage, &issuer, &subject, 1_700_000_000)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.first_observed_at, 1_705_000_000);
        assert_eq!(loaded.last_acknowledged_at, None);
    }

    #[test]
    fn escalate_passes_through_active_unchanged() {
        let now = 1_900_000_000;
        let result = escalate_quarantine_status(QuarantineStatus::Active, None, now);
        assert_eq!(result, QuarantineStatus::Active);
    }

    #[test]
    fn escalate_passes_through_hard_suspended_unchanged() {
        let (revoker, _) = make_keys();
        let now = 1_900_000_000;
        let base = QuarantineStatus::HardSuspended {
            revoked_by: revoker,
            revoked_as_of: 1_700_000_000,
        };
        let timer = Some(
            TimerState::freshly_observed(1_700_000_000), // stale
        );
        let result = escalate_quarantine_status(base, timer, now);
        assert_eq!(result, base);
    }

    #[test]
    fn escalate_promotes_soft_flagged_pre_compromise_after_window() {
        let (revoker, _) = make_keys();
        let now = 1_900_000_000;
        let base = QuarantineStatus::SoftFlaggedPreCompromise {
            revoked_by: revoker,
            revoked_as_of: 1_650_000_000,
        };
        let timer = Some(TimerState::freshly_observed(now - 91 * 24 * 60 * 60));
        let result = escalate_quarantine_status(base, timer, now);
        match result {
            QuarantineStatus::HardSuspended {
                revoked_by,
                revoked_as_of,
            } => {
                assert_eq!(revoked_by, revoker);
                assert_eq!(revoked_as_of, 1_650_000_000);
            }
            other => panic!("expected HardSuspended, got {other:?}"),
        }
    }

    #[test]
    fn escalate_promotes_soft_flagged_by_withdrawal_after_window() {
        let (revoker, _) = make_keys();
        let now = 1_900_000_000;
        let base = QuarantineStatus::SoftFlaggedByWithdrawal {
            revoked_by: revoker,
            withdrawal_at: 1_650_000_000,
        };
        let timer = Some(TimerState::freshly_observed(now - 100 * 24 * 60 * 60));
        let result = escalate_quarantine_status(base, timer, now);
        match result {
            QuarantineStatus::HardSuspended {
                revoked_by,
                revoked_as_of,
            } => {
                assert_eq!(revoked_by, revoker);
                assert_eq!(revoked_as_of, 1_650_000_000);
            }
            other => panic!("expected HardSuspended, got {other:?}"),
        }
    }

    #[test]
    fn escalate_within_window_leaves_soft_flagged_unchanged() {
        let (revoker, _) = make_keys();
        let now = 1_900_000_000;
        let base = QuarantineStatus::SoftFlaggedPreCompromise {
            revoked_by: revoker,
            revoked_as_of: 1_650_000_000,
        };
        // Timer observed only 30 days ago — within the window.
        let timer = Some(TimerState::freshly_observed(now - 30 * 24 * 60 * 60));
        let result = escalate_quarantine_status(base, timer, now);
        assert_eq!(result, base);
    }

    #[test]
    fn escalate_acknowledged_within_window_leaves_soft_flagged_unchanged() {
        let (revoker, _) = make_keys();
        let now = 1_900_000_000;
        let base = QuarantineStatus::SoftFlaggedPreCompromise {
            revoked_by: revoker,
            revoked_as_of: 1_650_000_000,
        };
        // Observed 100 days ago (stale by first-observation anchor)
        // but acknowledged 30 days ago — within window from ack.
        let timer = Some(
            TimerState::freshly_observed(now - 100 * 24 * 60 * 60)
                .with_acknowledgment(now - 30 * 24 * 60 * 60),
        );
        let result = escalate_quarantine_status(base, timer, now);
        assert_eq!(result, base);
    }

    #[test]
    fn escalate_with_no_timer_leaves_soft_flagged_unchanged() {
        // No timer record yet (e.g., the flag was just computed
        // by compute_quarantine_state but observe_flag hasn't been
        // called yet). Without a timer the staleness check can't
        // fire.
        let (revoker, _) = make_keys();
        let base = QuarantineStatus::SoftFlaggedByWithdrawal {
            revoked_by: revoker,
            withdrawal_at: 1_650_000_000,
        };
        let result = escalate_quarantine_status(base, None, 1_900_000_000);
        assert_eq!(result, base);
    }

    #[test]
    fn initialize_schema_is_idempotent() {
        let storage = open_storage();
        initialize_schema(&storage).unwrap();
        initialize_schema(&storage).unwrap();
        assert_eq!(
            storage
                .category_schema_version(categories::QUARANTINE_STATE)
                .unwrap(),
            QUARANTINE_TIMER_SCHEMA_VERSION
        );
    }
}
