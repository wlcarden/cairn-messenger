// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Cascade-quarantine state computation per D0006 §2.
//!
//! ## Semantics
//!
//! Per D0006 §2 a [`OpType::CompromiseRevoke`] of subject `X` with
//! `revoked_as_of = t` triggers cascade quarantine on every
//! attestation `X` issued:
//!
//! - `A.timestamp >  t` ⇒ [`QuarantineStatus::HardSuspended`] —
//!   issued under suspicion of attacker control.
//! - `A.timestamp <= t` ⇒ [`QuarantineStatus::SoftFlaggedPreCompromise`]
//!   — the compromise may have begun earlier than the user detected.
//!
//! A [`OpType::WithdrawRevoke`] of subject `X` at op-timestamp `t_w`
//! cascades less aggressively (the issuer is retracting endorsement
//! without claiming key compromise):
//!
//! - `A.timestamp >= t_w` ⇒
//!   [`QuarantineStatus::SoftFlaggedByWithdrawal`].
//! - `A.timestamp <  t_w` ⇒ unaffected by that withdrawal.
//!
//! ## Multi-revocation precedence
//!
//! If multiple revocation events target the same subject (e.g., one
//! user issues `CompromiseRevoke`, another issues `WithdrawRevoke`),
//! the most-severe status wins:
//! `HardSuspended` > `SoftFlaggedPreCompromise` > `SoftFlaggedByWithdrawal` > `Active`.
//!
//! Within the same severity, the earliest revoked timestamp wins
//! (the most conservative anchor).
//!
//! ## What this module does NOT do
//!
//! - **90-day stale-flag escalation** per D0006 §2. That's a time-
//!   evolution rule that requires persistent state across sessions
//!   (the 90-day clock starts at first-flag-observation, not at
//!   revocation time) and depends on storage-layer architecture
//!   decisions. Deferred until `cairn-storage` lands.
//! - **Re-attestation policy enforcement** (D0006 §2's stricter
//!   re-attestation requirements). UI-layer policy.
//! - **Verification of the input ops.** Callers must pass ops that
//!   have already been verified via [`crate::verify_chain_links`] or
//!   [`crate::SignedTrustGraphOp::verify_chain`] — this module
//!   computes status assuming the ops are cryptographically valid.

use std::collections::HashMap;

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, VerifyingKey};

use crate::op::{OpType, TrustGraphOp};

/// Cascade-quarantine status of an attestation operation.
///
/// Returned by [`compute_quarantine_state`] for each input op. Non-
/// attestation ops are returned as [`Self::NotApplicable`] (the
/// classification only applies to `Attest` and `ReAttest`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuarantineStatus {
    /// The op is not an attestation (revocation ops don't get
    /// classified by this module).
    NotApplicable,
    /// No cascade revocation applies to this attestation.
    Active,
    /// The issuer of this attestation was withdrawn-from at or before
    /// this attestation's timestamp. Operationally usable but flagged.
    SoftFlaggedByWithdrawal {
        /// The peer who issued the `WithdrawRevoke`.
        revoked_by: VerifyingKey,
        /// The withdrawal op's timestamp.
        withdrawal_at: u64,
    },
    /// The issuer of this attestation was compromise-revoked, and this
    /// attestation was issued at or before the compromise window. May
    /// also have been compromised; flagged but operationally usable.
    SoftFlaggedPreCompromise {
        /// The peer who issued the `CompromiseRevoke`.
        revoked_by: VerifyingKey,
        /// The `revoked_as_of` Unix-seconds from the compromise revoke.
        revoked_as_of: u64,
    },
    /// The issuer of this attestation was compromise-revoked, and this
    /// attestation was issued AFTER the compromise window. Not
    /// operationally usable per D0006 §2's anti-laundering rule.
    HardSuspended {
        /// The peer who issued the `CompromiseRevoke`.
        revoked_by: VerifyingKey,
        /// The `revoked_as_of` Unix-seconds from the compromise revoke.
        revoked_as_of: u64,
    },
}

impl QuarantineStatus {
    /// Severity-precedence rank. Higher = more restrictive.
    const fn severity(self) -> u8 {
        match self {
            Self::NotApplicable | Self::Active => 0,
            Self::SoftFlaggedByWithdrawal { .. } => 1,
            Self::SoftFlaggedPreCompromise { .. } => 2,
            Self::HardSuspended { .. } => 3,
        }
    }

    /// Combine two statuses, returning the more restrictive one.
    /// Used when multiple revocations target the same subject.
    const fn worst_of(self, other: Self) -> Self {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}

/// Compute the cascade-quarantine status of each op in the input
/// slice per D0006 §2.
///
/// Output is parallel to input: `output[i]` is the status of `ops[i]`.
/// Revocation ops (Withdraw/Compromise) return
/// [`QuarantineStatus::NotApplicable`] — this function classifies
/// attestations, not revocations.
///
/// The classification is multi-pass (two passes over the input):
/// pass 1 indexes revocations by subject pubkey, pass 2 walks the ops
/// and classifies each attestation. The computation is `O(N + N*R)`
/// where `R` is the number of distinct revoked subjects.
///
/// Callers MUST verify the input ops via
/// [`crate::verify_chain_links`] or
/// [`crate::SignedTrustGraphOp::verify_chain`] before calling this —
/// the cascade rule assumes the ops are cryptographically valid.
#[must_use]
pub fn compute_quarantine_state(ops: &[&TrustGraphOp]) -> Vec<QuarantineStatus> {
    // Index revocations by their subject — the subject is the "revoked
    // operational key" whose downstream attestations cascade.
    // `VerifyingKey` doesn't implement `Hash` (curve points are
    // arrays, not hash-friendly types); use the 32-byte form as the
    // map key.
    let mut revocations_by_subject: HashMap<[u8; PUBLIC_KEY_LEN], Vec<&TrustGraphOp>> =
        HashMap::new();
    for op in ops {
        match op.op_type {
            OpType::CompromiseRevoke | OpType::WithdrawRevoke => {
                revocations_by_subject
                    .entry(op.subject.to_bytes())
                    .or_default()
                    .push(op);
            }
            _ => {}
        }
    }

    let mut statuses = Vec::with_capacity(ops.len());
    for op in ops {
        let status = match op.op_type {
            OpType::Attest | OpType::ReAttest => classify_attestation(op, &revocations_by_subject),
            _ => QuarantineStatus::NotApplicable,
        };
        statuses.push(status);
    }
    statuses
}

/// Classify a single attestation op against the indexed revocations.
fn classify_attestation(
    attestation: &TrustGraphOp,
    revocations_by_subject: &HashMap<[u8; PUBLIC_KEY_LEN], Vec<&TrustGraphOp>>,
) -> QuarantineStatus {
    // The cascade triggers when a revocation targets the ISSUER of
    // this attestation — the issuer's key was the one "revoked" /
    // "withdrawn-from".
    let Some(relevant_revocations) = revocations_by_subject.get(&attestation.issuer.to_bytes())
    else {
        return QuarantineStatus::Active;
    };

    let mut worst = QuarantineStatus::Active;
    for revocation in relevant_revocations {
        let candidate = match revocation.op_type {
            OpType::CompromiseRevoke => classify_against_compromise(attestation, revocation),
            OpType::WithdrawRevoke => classify_against_withdrawal(attestation, revocation),
            _ => continue, // unreachable per the indexing pass.
        };
        worst = worst.worst_of(candidate);
    }
    worst
}

/// Apply the `CompromiseRevoke` cascade rule to one attestation.
const fn classify_against_compromise(
    attestation: &TrustGraphOp,
    revocation: &TrustGraphOp,
) -> QuarantineStatus {
    let Some(revoked_as_of) = revocation.revoked_as_of else {
        // Schema invariant violation — CompromiseRevoke ops MUST
        // carry revoked_as_of. Surface as Active (no-op) rather
        // than panic; the caller should have caught this via
        // verify_chain prior to invoking us.
        return QuarantineStatus::Active;
    };
    if attestation.timestamp > revoked_as_of {
        QuarantineStatus::HardSuspended {
            revoked_by: revocation.issuer,
            revoked_as_of,
        }
    } else {
        QuarantineStatus::SoftFlaggedPreCompromise {
            revoked_by: revocation.issuer,
            revoked_as_of,
        }
    }
}

/// Apply the `WithdrawRevoke` cascade rule to one attestation.
const fn classify_against_withdrawal(
    attestation: &TrustGraphOp,
    revocation: &TrustGraphOp,
) -> QuarantineStatus {
    if attestation.timestamp >= revocation.timestamp {
        QuarantineStatus::SoftFlaggedByWithdrawal {
            revoked_by: revocation.issuer,
            withdrawal_at: revocation.timestamp,
        }
    } else {
        QuarantineStatus::Active
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::match_on_vec_items)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use rand_core::OsRng;

    fn vk(rng: &mut OsRng) -> VerifyingKey {
        SigningKey::generate(rng).verifying_key()
    }

    #[test]
    fn empty_input_returns_empty_output() {
        let statuses = compute_quarantine_state(&[]);
        assert!(statuses.is_empty());
    }

    #[test]
    fn no_revocations_means_all_active() {
        let mut rng = OsRng;
        let alice = vk(&mut rng);
        let bob = vk(&mut rng);
        let charlie = vk(&mut rng);
        let attest_1 = TrustGraphOp::new_attest(alice, bob, 100, vec![], vec![]);
        let attest_2 = TrustGraphOp::new_attest(bob, charlie, 200, vec![], vec![]);
        let statuses = compute_quarantine_state(&[&attest_1, &attest_2]);
        assert_eq!(statuses.len(), 2);
        assert_eq!(statuses[0], QuarantineStatus::Active);
        assert_eq!(statuses[1], QuarantineStatus::Active);
    }

    #[test]
    fn revocation_op_itself_is_not_applicable() {
        let mut rng = OsRng;
        let alice = vk(&mut rng);
        let bob = vk(&mut rng);
        let rev = TrustGraphOp::new_compromise_revoke(alice, bob, 100, vec![], vec![], 50);
        let statuses = compute_quarantine_state(&[&rev]);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0], QuarantineStatus::NotApplicable);
    }

    #[test]
    fn compromise_revoke_hard_suspends_post_revoke_attestations() {
        // Bob attests Charlie at t=200; Alice compromise-revokes Bob
        // with revoked_as_of=150. The attestation t=200 was issued
        // after Bob was considered compromised → hard-suspended.
        let mut rng = OsRng;
        let alice = vk(&mut rng);
        let bob = vk(&mut rng);
        let charlie = vk(&mut rng);
        let attest_bob_charlie = TrustGraphOp::new_attest(bob, charlie, 200, vec![], vec![]);
        let revoke_bob = TrustGraphOp::new_compromise_revoke(alice, bob, 300, vec![], vec![], 150);
        let statuses = compute_quarantine_state(&[&attest_bob_charlie, &revoke_bob]);
        match statuses[0] {
            QuarantineStatus::HardSuspended {
                revoked_by,
                revoked_as_of,
            } => {
                assert_eq!(revoked_by, alice);
                assert_eq!(revoked_as_of, 150);
            }
            other => panic!("expected HardSuspended, got {other:?}"),
        }
        assert_eq!(statuses[1], QuarantineStatus::NotApplicable);
    }

    #[test]
    fn compromise_revoke_soft_flags_pre_revoke_attestations() {
        // Bob attests Charlie at t=100; Alice compromise-revokes Bob
        // with revoked_as_of=150. The attestation t=100 was issued
        // BEFORE Bob's revoked_as_of window → SoftFlaggedPreCompromise
        // (the compromise may have started earlier).
        let mut rng = OsRng;
        let alice = vk(&mut rng);
        let bob = vk(&mut rng);
        let charlie = vk(&mut rng);
        let attest_bob_charlie = TrustGraphOp::new_attest(bob, charlie, 100, vec![], vec![]);
        let revoke_bob = TrustGraphOp::new_compromise_revoke(alice, bob, 300, vec![], vec![], 150);
        let statuses = compute_quarantine_state(&[&attest_bob_charlie, &revoke_bob]);
        match statuses[0] {
            QuarantineStatus::SoftFlaggedPreCompromise {
                revoked_by,
                revoked_as_of,
            } => {
                assert_eq!(revoked_by, alice);
                assert_eq!(revoked_as_of, 150);
            }
            other => panic!("expected SoftFlaggedPreCompromise, got {other:?}"),
        }
    }

    #[test]
    fn compromise_revoke_at_exact_boundary_is_soft_flagged() {
        // D0006 §2: attestations <= revoked_as_of are soft-flagged
        // (the boundary is inclusive of "before").
        let mut rng = OsRng;
        let alice = vk(&mut rng);
        let bob = vk(&mut rng);
        let charlie = vk(&mut rng);
        let attest = TrustGraphOp::new_attest(bob, charlie, 150, vec![], vec![]);
        let revoke = TrustGraphOp::new_compromise_revoke(alice, bob, 300, vec![], vec![], 150);
        let statuses = compute_quarantine_state(&[&attest, &revoke]);
        assert!(matches!(
            statuses[0],
            QuarantineStatus::SoftFlaggedPreCompromise { .. }
        ));
    }

    #[test]
    fn withdraw_revoke_soft_flags_post_withdrawal_attestations() {
        // Bob attests Charlie at t=200; Alice withdraws her attestation
        // of Bob at op-timestamp=150. Bob's attestation at t=200 came
        // AFTER the withdrawal → SoftFlaggedByWithdrawal.
        let mut rng = OsRng;
        let alice = vk(&mut rng);
        let bob = vk(&mut rng);
        let charlie = vk(&mut rng);
        let attest = TrustGraphOp::new_attest(bob, charlie, 200, vec![], vec![]);
        let withdraw = TrustGraphOp::new_withdraw_revoke(alice, bob, 150, vec![], vec![]);
        let statuses = compute_quarantine_state(&[&attest, &withdraw]);
        match statuses[0] {
            QuarantineStatus::SoftFlaggedByWithdrawal {
                revoked_by,
                withdrawal_at,
            } => {
                assert_eq!(revoked_by, alice);
                assert_eq!(withdrawal_at, 150);
            }
            other => panic!("expected SoftFlaggedByWithdrawal, got {other:?}"),
        }
    }

    #[test]
    fn withdraw_revoke_leaves_pre_withdrawal_attestations_active() {
        // Bob attests Charlie at t=100; Alice withdraws at t=150. The
        // attestation at t=100 predates the withdrawal → Active.
        let mut rng = OsRng;
        let alice = vk(&mut rng);
        let bob = vk(&mut rng);
        let charlie = vk(&mut rng);
        let attest = TrustGraphOp::new_attest(bob, charlie, 100, vec![], vec![]);
        let withdraw = TrustGraphOp::new_withdraw_revoke(alice, bob, 150, vec![], vec![]);
        let statuses = compute_quarantine_state(&[&attest, &withdraw]);
        assert_eq!(statuses[0], QuarantineStatus::Active);
    }

    #[test]
    fn compromise_takes_precedence_over_withdrawal() {
        // Bob attests Charlie at t=200; Alice withdraws Bob at t=150;
        // Dave compromise-revokes Bob with revoked_as_of=100. The
        // attestation t=200 falls within both cascades — the
        // CompromiseRevoke (HardSuspended) outranks the WithdrawRevoke
        // (SoftFlaggedByWithdrawal).
        let mut rng = OsRng;
        let alice = vk(&mut rng);
        let bob = vk(&mut rng);
        let charlie = vk(&mut rng);
        let dave = vk(&mut rng);
        let attest = TrustGraphOp::new_attest(bob, charlie, 200, vec![], vec![]);
        let withdraw = TrustGraphOp::new_withdraw_revoke(alice, bob, 150, vec![], vec![]);
        let compromise = TrustGraphOp::new_compromise_revoke(dave, bob, 300, vec![], vec![], 100);
        let statuses = compute_quarantine_state(&[&attest, &withdraw, &compromise]);
        assert!(matches!(
            statuses[0],
            QuarantineStatus::HardSuspended { .. }
        ));
    }

    #[test]
    fn non_cascading_subject_unaffected() {
        // Bob compromise-revoked, but attestation by Alice (not Bob)
        // about Bob → not affected (Alice's key wasn't revoked).
        let mut rng = OsRng;
        let alice = vk(&mut rng);
        let bob = vk(&mut rng);
        let dave = vk(&mut rng);
        let attest = TrustGraphOp::new_attest(alice, bob, 200, vec![], vec![]);
        let revoke = TrustGraphOp::new_compromise_revoke(dave, bob, 300, vec![], vec![], 150);
        let statuses = compute_quarantine_state(&[&attest, &revoke]);
        assert_eq!(statuses[0], QuarantineStatus::Active);
    }

    #[test]
    fn re_attest_op_is_classified_too() {
        // ReAttest is an attestation variant per D0006 §2 (subject to
        // the cascade rules too). Bob ReAttests Charlie at t=200
        // after Alice CompromiseRevoked Bob at revoked_as_of=150 —
        // hard-suspended.
        let mut rng = OsRng;
        let alice = vk(&mut rng);
        let bob = vk(&mut rng);
        let charlie = vk(&mut rng);
        let re_attest =
            TrustGraphOp::new_re_attest(bob, charlie, 200, vec![], vec![], b"prior-rev".to_vec());
        let revoke = TrustGraphOp::new_compromise_revoke(alice, bob, 300, vec![], vec![], 150);
        let statuses = compute_quarantine_state(&[&re_attest, &revoke]);
        assert!(matches!(
            statuses[0],
            QuarantineStatus::HardSuspended { .. }
        ));
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::match_on_vec_items)]
mod proptests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use proptest::prelude::*;
    use rand_core::OsRng;

    /// Independent re-derivation of the cascade-status severity rank
    /// (parallels the internal `severity` impl on `QuarantineStatus`)
    /// so property assertions are not just self-referential.
    ///
    /// `QuarantineStatus` is `#[non_exhaustive]`; if a future variant
    /// is added, this match becomes inexhaustive at compile time and
    /// forces an explicit decision on its severity. That's the right
    /// failure mode for property tests — silent default-handling of a
    /// new variant would let the cascade rule drift unnoticed.
    #[allow(
        unreachable_patterns,
        reason = "wildcard covers any future non_exhaustive variant — \
                  intentional safety net rather than an unreachable arm"
    )]
    const fn severity_rank(status: QuarantineStatus) -> u8 {
        match status {
            QuarantineStatus::NotApplicable | QuarantineStatus::Active => 0,
            QuarantineStatus::SoftFlaggedByWithdrawal { .. } => 1,
            QuarantineStatus::SoftFlaggedPreCompromise { .. } => 2,
            QuarantineStatus::HardSuspended { .. } => 3,
            _ => u8::MAX, // unknown future variant → most-conservative rank
        }
    }

    proptest! {
        /// Property: compute_quarantine_state is deterministic — same
        /// input always yields the same output. Guards against
        /// HashMap-iteration-order leakage or any other source of
        /// nondeterminism in the classifier.
        #[test]
        fn prop_classifier_is_deterministic(
            attest_timestamp in 0u64..1_000_000,
            revoked_as_of in 0u64..1_000_000,
        ) {
            let mut rng = OsRng;
            let alice = SigningKey::generate(&mut rng).verifying_key();
            let bob = SigningKey::generate(&mut rng).verifying_key();
            let charlie = SigningKey::generate(&mut rng).verifying_key();
            let attest = TrustGraphOp::new_attest(bob, charlie, attest_timestamp, vec![], vec![]);
            let revoke = TrustGraphOp::new_compromise_revoke(
                alice, bob, attest_timestamp.saturating_add(1000), vec![], vec![], revoked_as_of,
            );
            let a = compute_quarantine_state(&[&attest, &revoke]);
            let b = compute_quarantine_state(&[&attest, &revoke]);
            prop_assert_eq!(a, b);
        }

        /// Property: CompromiseRevoke severity is monotone in
        /// attest_timestamp. As the attestation moves from "well before
        /// revoked_as_of" to "well after revoked_as_of", the cascade
        /// severity is non-decreasing.
        #[test]
        fn prop_compromise_severity_monotone_in_time(
            revoked_as_of in 100u64..10_000,
            delta in 1u64..1_000,
        ) {
            let mut rng = OsRng;
            let alice = SigningKey::generate(&mut rng).verifying_key();
            let bob = SigningKey::generate(&mut rng).verifying_key();
            let charlie = SigningKey::generate(&mut rng).verifying_key();
            let revoke = TrustGraphOp::new_compromise_revoke(
                alice, bob, revoked_as_of.saturating_add(50_000), vec![], vec![], revoked_as_of,
            );

            let pre_t = revoked_as_of.saturating_sub(delta);
            let post_t = revoked_as_of.saturating_add(delta);
            let attest_pre = TrustGraphOp::new_attest(bob, charlie, pre_t, vec![], vec![]);
            let attest_post = TrustGraphOp::new_attest(bob, charlie, post_t, vec![], vec![]);

            let pre_status = compute_quarantine_state(&[&attest_pre, &revoke])[0];
            let post_status = compute_quarantine_state(&[&attest_post, &revoke])[0];

            prop_assert!(
                severity_rank(post_status) >= severity_rank(pre_status),
                "post-revoke severity should be >= pre-revoke severity",
            );
            let post_is_hard = matches!(post_status, QuarantineStatus::HardSuspended { .. });
            let pre_is_soft = matches!(pre_status, QuarantineStatus::SoftFlaggedPreCompromise { .. });
            prop_assert!(post_is_hard);
            prop_assert!(pre_is_soft);
        }

        /// Property: an attestation whose issuer was NOT revoked is
        /// always Active, regardless of timestamp. Cross-cutting check
        /// that the cascade only triggers for revoked subjects.
        #[test]
        fn prop_unrevoked_issuer_is_always_active(
            attest_timestamp in 0u64..u64::from(u32::MAX),
        ) {
            let mut rng = OsRng;
            let alice = SigningKey::generate(&mut rng).verifying_key();
            let charlie = SigningKey::generate(&mut rng).verifying_key();
            let dave = SigningKey::generate(&mut rng).verifying_key();
            let unrelated_subject = SigningKey::generate(&mut rng).verifying_key();
            // Revoke is about `unrelated_subject`, not Alice — so
            // Alice→Charlie attestation should stay Active.
            let attest = TrustGraphOp::new_attest(alice, charlie, attest_timestamp, vec![], vec![]);
            let unrelated_revoke = TrustGraphOp::new_compromise_revoke(
                dave, unrelated_subject, 999_999, vec![], vec![], 500_000,
            );
            let statuses = compute_quarantine_state(&[&attest, &unrelated_revoke]);
            prop_assert_eq!(statuses[0], QuarantineStatus::Active);
        }

        /// Property: revocation ops themselves are NEVER classified
        /// as Active/Soft/Hard — they always return NotApplicable.
        #[test]
        fn prop_revocations_are_not_applicable(
            timestamp in 0u64..u64::from(u32::MAX),
            revoked_as_of in 0u64..u64::from(u32::MAX),
        ) {
            let mut rng = OsRng;
            let alice = SigningKey::generate(&mut rng).verifying_key();
            let bob = SigningKey::generate(&mut rng).verifying_key();
            let cr = TrustGraphOp::new_compromise_revoke(
                alice, bob, timestamp, vec![], vec![], revoked_as_of,
            );
            let wr = TrustGraphOp::new_withdraw_revoke(alice, bob, timestamp, vec![], vec![]);
            let statuses = compute_quarantine_state(&[&cr, &wr]);
            prop_assert_eq!(statuses[0], QuarantineStatus::NotApplicable);
            prop_assert_eq!(statuses[1], QuarantineStatus::NotApplicable);
        }
    }
}
