// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Byte-level Shamir Secret Sharing wrapping `vsss-rs::Gf256`.
//!
//! Per D0018 §3.1: `vsss-rs` 5.4.0's `Gf256` module implements
//! byte-level GF(2⁸) Shamir with explicitly constant-time arithmetic
//! (no lookup tables; documented at `vsss-rs-5.4.0/src/gf256.rs:1-9`).
//! That construction is the Cure53 PVY-01-003 reference per D0018 §3.1
//! line 316.
//!
//! This module wraps `Gf256::split_array` / `combine_array` in Cairn's
//! `Share` + `Commitment` discipline:
//!
//! - [`Share`] carries `(id, value_bytes)` with `Zeroizing` discipline
//!   on the value bytes. Internal representation mirrors our prior
//!   API; conversion to/from the `vsss-rs` `Vec<u8>` wire format
//!   (`[id, value_bytes...]` of length `SECRET_LEN + 1`) happens at
//!   the API boundary.
//! - [`split`] returns shares + a [`Commitment`] (BLAKE3 commit-of-
//!   secret per D0018 §3.4 — `vsss-rs` does not provide one).
//! - [`reconstruct`] verifies the commitment after recombination;
//!   commitment mismatch is uniform across corrupted shares /
//!   insufficient shares / tampered commitment per D0018 §3.4.
//!
//! ## Parameter constraints
//!
//! - `threshold ∈ [2, 255]`. `threshold = 1` is mathematically valid
//!   but provides zero security (every share equals the secret); it is
//!   rejected to make the security contract explicit.
//! - `num_shares ∈ [threshold, 255]`. The `u8` typing already prevents
//!   `num_shares > 255`.
//!
//! ## What this module does NOT verify
//!
//! - **Share authenticity** (was this share actually issued by the
//!   trusted dealer?). The [`Commitment`] catches *modified* shares
//!   but not *forged* shares paired with a forged commitment. Cairn's
//!   recovery model assumes shares are stored with peer-bound
//!   authentication wrappers (e.g., a `COSE_Sign1` envelope from the
//!   share-holder, per D0006 §6.3); the bare share / commitment pair
//!   from this module is not safe to accept from untrusted sources
//!   without that outer wrapping.

use rand_core::{CryptoRng, RngCore};
use vsss_rs::Gf256;
use zeroize::Zeroizing;

use crate::commit::Commitment;
use crate::error::ShamirError;

/// Length of the Shamir secret in bytes (= 32 = Ed25519 seed length per
/// RFC 8032 §5.1.5).
pub const SECRET_LEN: usize = 32;

/// Length of a single share's wire representation in bytes.
///
/// `vsss-rs::Gf256` shares are `[id_byte, value_byte_per_secret_position...]`
/// of length `secret.len() + 1`. For Cairn's 32-byte seed, shares are
/// `SECRET_LEN + 1 = 33` bytes.
pub const SHARE_LEN: usize = SECRET_LEN + 1;

/// A single Shamir share.
///
/// Carries a public 1-byte identifier (`1..=255`, the polynomial
/// evaluation point) and a 32-byte secret-bearing payload (the
/// polynomial value at that point, for each of the 32 byte positions
/// independently).
///
/// The payload is wrapped in [`Zeroizing`] so it zeroes on drop.
#[derive(Clone)]
pub struct Share {
    id: u8,
    bytes: Zeroizing<[u8; SECRET_LEN]>,
}

impl Share {
    /// Construct a share from its components (e.g., when loading from
    /// storage).
    ///
    /// # Errors
    ///
    /// Returns [`ShamirError::InvalidShareId`] if `id == 0`. The
    /// identifier `0` is reserved for the secret-recovery evaluation
    /// point and cannot be a valid share.
    pub fn try_from_parts(id: u8, bytes: Zeroizing<[u8; SECRET_LEN]>) -> Result<Self, ShamirError> {
        if id == 0 {
            return Err(ShamirError::InvalidShareId);
        }
        Ok(Self { id, bytes })
    }

    /// Return the share's public identifier (`1..=255`).
    #[must_use]
    pub const fn id(&self) -> u8 {
        self.id
    }

    /// Return the share's 32-byte payload.
    ///
    /// The returned reference is bound to the lifetime of `&self`; do
    /// not retain copies beyond the immediate use.
    #[must_use]
    pub fn bytes(&self) -> &[u8; SECRET_LEN] {
        &self.bytes
    }

    /// Encode to the `vsss-rs` share wire format (`[id, value...]`).
    ///
    /// Used by [`reconstruct`] when calling `Gf256::combine_array`. Not
    /// public — callers who need the wire format should serialize
    /// `id() ++ bytes()` themselves.
    fn to_vsss_format(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SHARE_LEN);
        v.push(self.id);
        v.extend_from_slice(self.bytes.as_ref());
        v
    }

    /// Decode from the `vsss-rs` share wire format.
    ///
    /// Used by [`split`] to convert `Gf256::split_array`'s output into
    /// Cairn's typed `Share` representation.
    ///
    /// `indexing_slicing` allowed: the early `raw.len() != SHARE_LEN`
    /// check proves `raw[0]` and `raw[1..]` are statically in-range.
    #[allow(clippy::indexing_slicing)]
    fn from_vsss_format(raw: &[u8]) -> Result<Self, ShamirError> {
        if raw.len() != SHARE_LEN {
            return Err(ShamirError::VsssSplitFailed);
        }
        let id = raw[0];
        if id == 0 {
            return Err(ShamirError::InvalidShareId);
        }
        let mut bytes = [0u8; SECRET_LEN];
        bytes.copy_from_slice(&raw[1..]);
        Ok(Self {
            id,
            bytes: Zeroizing::new(bytes),
        })
    }
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Redact the secret-bearing bytes.
        write!(f, "ShamirShare(id={}, bytes=<redacted>)", self.id)
    }
}

/// Split a 32-byte secret into `num_shares` Shamir shares with a
/// recovery `threshold`.
///
/// Delegates the GF(2⁸) Shamir arithmetic to `vsss-rs::Gf256::split_array`
/// (Cure53-cited construction). Returns the typed shares + a BLAKE3
/// commit-of-secret per [`Commitment::for_secret`] that [`reconstruct`]
/// uses to verify the recovered seed.
///
/// # Errors
///
/// - [`ShamirError::InvalidParameters`] if `threshold == 0`,
///   `threshold > num_shares`, or `num_shares == 0`.
/// - [`ShamirError::ThresholdTooLow`] if `threshold == 1` (provides
///   zero security; `threshold >= 2` is required).
/// - [`ShamirError::VsssSplitFailed`] if the underlying `vsss-rs`
///   split operation fails (practically unreachable for inputs that
///   pass Cairn's pre-validation).
pub fn split<R: CryptoRng + RngCore>(
    secret: &Zeroizing<[u8; SECRET_LEN]>,
    threshold: u8,
    num_shares: u8,
    rng: &mut R,
) -> Result<(Vec<Share>, Commitment), ShamirError> {
    if threshold == 0 || num_shares == 0 || threshold > num_shares {
        return Err(ShamirError::InvalidParameters {
            threshold,
            num_shares,
        });
    }
    if threshold == 1 {
        return Err(ShamirError::ThresholdTooLow { threshold });
    }

    let commitment = Commitment::for_secret(secret.as_ref());

    let raw_shares = Gf256::split_array(
        threshold as usize,
        num_shares as usize,
        secret.as_ref(),
        rng,
    )
    .map_err(|_| ShamirError::VsssSplitFailed)?;

    raw_shares
        .iter()
        .map(|raw| Share::from_vsss_format(raw))
        .collect::<Result<Vec<_>, _>>()
        .map(|shares| (shares, commitment))
}

/// Reconstruct the secret from `shares`, gated on the commitment check.
///
/// Delegates to `vsss-rs::Gf256::combine_array` for the GF(2⁸) Lagrange
/// interpolation. Requires at least `threshold` shares (the threshold
/// used at [`split`] time); supplying fewer produces a candidate that
/// fails the commitment check.
///
/// # Errors
///
/// - [`ShamirError::InsufficientShares`] if `shares.is_empty()`.
/// - [`ShamirError::InvalidShareId`] if any share has `id == 0`.
/// - [`ShamirError::DuplicateShareId`] if two shares carry the same
///   identifier.
/// - [`ShamirError::CommitmentMismatch`] if the reconstructed candidate
///   does not match the stored commitment (corrupted shares, malicious
///   reconstruction shares, insufficient share count, or `vsss-rs`
///   combine returning an unexpected error).
pub fn reconstruct(
    shares: &[Share],
    commitment: &Commitment,
) -> Result<Zeroizing<[u8; SECRET_LEN]>, ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::InsufficientShares { got: 0 });
    }

    // Reject id == 0 and duplicate ids in one pass.
    // `indexing_slicing` allowed: `share.id` is a `u8 ∈ [1, 255]` (the
    // `== 0` branch returns early), `seen_ids` has length 256, so
    // `seen_ids[id_idx]` is statically in-range.
    let mut seen_ids = [false; 256];
    for share in shares {
        if share.id == 0 {
            return Err(ShamirError::InvalidShareId);
        }
        let id_idx = share.id as usize;
        #[allow(clippy::indexing_slicing)]
        if seen_ids[id_idx] {
            return Err(ShamirError::DuplicateShareId { id: share.id });
        }
        #[allow(clippy::indexing_slicing)]
        {
            seen_ids[id_idx] = true;
        }
    }

    let raw_shares: Vec<Vec<u8>> = shares.iter().map(Share::to_vsss_format).collect();
    let secret_bytes =
        Gf256::combine_array(&raw_shares).map_err(|_| ShamirError::CommitmentMismatch)?;

    if secret_bytes.len() != SECRET_LEN {
        return Err(ShamirError::CommitmentMismatch);
    }

    let mut secret_arr = [0u8; SECRET_LEN];
    secret_arr.copy_from_slice(&secret_bytes);
    let secret: Zeroizing<[u8; SECRET_LEN]> = Zeroizing::new(secret_arr);

    let computed = Commitment::for_secret(secret.as_ref());
    if !computed.ct_eq(commitment) {
        return Err(ShamirError::CommitmentMismatch);
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    // Tests routinely index into shares-of-known-length and assert at
    // specific positions. The indices are constants under the test's
    // own control; clippy's panic-prone-indexing concern applies to
    // production code, not these tests.
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use rand_core::OsRng;

    fn random_secret<R: CryptoRng + RngCore>(rng: &mut R) -> Zeroizing<[u8; SECRET_LEN]> {
        let mut bytes = [0u8; SECRET_LEN];
        rng.fill_bytes(&mut bytes);
        Zeroizing::new(bytes)
    }

    #[test]
    fn split_reconstruct_round_trip_3_of_5() {
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (shares, commitment) = split(&secret, 3, 5, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);

        // Reconstruct from the first 3 shares.
        let recovered = reconstruct(&shares[..3], &commitment).unwrap();
        assert_eq!(recovered.as_ref(), secret.as_ref());
    }

    #[test]
    fn split_reconstruct_round_trip_2_of_2() {
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (shares, commitment) = split(&secret, 2, 2, &mut rng).unwrap();
        assert_eq!(shares.len(), 2);

        let recovered = reconstruct(&shares, &commitment).unwrap();
        assert_eq!(recovered.as_ref(), secret.as_ref());
    }

    #[test]
    fn split_reconstruct_round_trip_5_of_5() {
        // n-of-n: all shares required.
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (shares, commitment) = split(&secret, 5, 5, &mut rng).unwrap();
        let recovered = reconstruct(&shares, &commitment).unwrap();
        assert_eq!(recovered.as_ref(), secret.as_ref());
    }

    #[test]
    fn reconstruct_any_subset_of_threshold_shares() {
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (shares, commitment) = split(&secret, 3, 5, &mut rng).unwrap();

        let subset_a = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let subset_b = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
        let subset_c = vec![shares[2].clone(), shares[3].clone(), shares[0].clone()];

        assert_eq!(
            reconstruct(&subset_a, &commitment).unwrap().as_ref(),
            secret.as_ref()
        );
        assert_eq!(
            reconstruct(&subset_b, &commitment).unwrap().as_ref(),
            secret.as_ref()
        );
        assert_eq!(
            reconstruct(&subset_c, &commitment).unwrap().as_ref(),
            secret.as_ref()
        );
    }

    #[test]
    fn reconstruct_fewer_than_threshold_fails_commitment() {
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (shares, commitment) = split(&secret, 3, 5, &mut rng).unwrap();

        let too_few = vec![shares[0].clone(), shares[1].clone()];
        let result = reconstruct(&too_few, &commitment);
        assert!(matches!(result, Err(ShamirError::CommitmentMismatch)));
    }

    #[test]
    fn tampered_share_byte_fails_commitment() {
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (mut shares, commitment) = split(&secret, 3, 5, &mut rng).unwrap();

        let mut tampered_bytes = *shares[0].bytes();
        tampered_bytes[0] ^= 0xFF;
        shares[0] = Share::try_from_parts(shares[0].id(), Zeroizing::new(tampered_bytes)).unwrap();

        let result = reconstruct(&shares[..3], &commitment);
        assert!(matches!(result, Err(ShamirError::CommitmentMismatch)));
    }

    #[test]
    fn tampered_commitment_rejects_correct_shares() {
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (shares, commitment) = split(&secret, 3, 5, &mut rng).unwrap();

        let other_commitment = Commitment::for_secret(b"different seed");
        let result = reconstruct(&shares[..3], &other_commitment);
        assert!(matches!(result, Err(ShamirError::CommitmentMismatch)));
        assert!(!commitment.ct_eq(&other_commitment));
    }

    #[test]
    fn split_rejects_invalid_threshold() {
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        assert!(matches!(
            split(&secret, 0, 5, &mut rng),
            Err(ShamirError::InvalidParameters {
                threshold: 0,
                num_shares: 5
            })
        ));
        assert!(matches!(
            split(&secret, 6, 5, &mut rng),
            Err(ShamirError::InvalidParameters {
                threshold: 6,
                num_shares: 5
            })
        ));
        assert!(matches!(
            split(&secret, 1, 0, &mut rng),
            Err(ShamirError::InvalidParameters {
                threshold: 1,
                num_shares: 0
            })
        ));
    }

    #[test]
    fn split_rejects_threshold_one() {
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        assert!(matches!(
            split(&secret, 1, 3, &mut rng),
            Err(ShamirError::ThresholdTooLow { threshold: 1 })
        ));
    }

    #[test]
    fn try_from_parts_rejects_zero_id() {
        let bytes = Zeroizing::new([0u8; SECRET_LEN]);
        assert!(matches!(
            Share::try_from_parts(0, bytes),
            Err(ShamirError::InvalidShareId)
        ));
    }

    #[test]
    fn reconstruct_rejects_empty_share_set() {
        let commitment = Commitment::for_secret(b"any");
        let result = reconstruct(&[], &commitment);
        assert!(matches!(
            result,
            Err(ShamirError::InsufficientShares { got: 0 })
        ));
    }

    #[test]
    fn reconstruct_rejects_duplicate_ids() {
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (shares, commitment) = split(&secret, 2, 3, &mut rng).unwrap();
        let dup = vec![shares[0].clone(), shares[0].clone()];
        let result = reconstruct(&dup, &commitment);
        assert!(matches!(
            result,
            Err(ShamirError::DuplicateShareId { id: _ })
        ));
    }

    #[test]
    fn share_debug_redacts_bytes() {
        let bytes = Zeroizing::new([0xAB_u8; SECRET_LEN]);
        let share = Share::try_from_parts(7, bytes).unwrap();
        let debug_str = format!("{share:?}");
        assert!(debug_str.contains("id=7"));
        assert!(debug_str.contains("redacted"));
        assert!(!debug_str.contains("ab"));
    }

    /// Exhaustive over C(n, k): split with k-of-n, verify every
    /// possible k-subset reconstructs correctly.
    #[test]
    fn exhaustive_3_of_4_subset_reconstruction() {
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (shares, commitment) = split(&secret, 3, 4, &mut rng).unwrap();

        for skip in 0..4 {
            let subset: Vec<Share> = shares
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .map(|(_, s)| s.clone())
                .collect();
            assert_eq!(subset.len(), 3);
            let recovered = reconstruct(&subset, &commitment).unwrap();
            assert_eq!(
                recovered.as_ref(),
                secret.as_ref(),
                "skip={skip} subset should reconstruct"
            );
        }
    }
}

#[cfg(test)]
mod proptests {
    // `arithmetic_side_effects` / `indexing_slicing` allowed at module
    // scope: the proptest strategies bound the inputs so all arithmetic
    // and indexing is well-defined by construction.
    #![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

    use super::*;
    use proptest::prelude::*;
    use rand_core::OsRng;

    proptest! {
        /// Property: for any valid (threshold, num_shares) parameters
        /// and any 32-byte secret, the first `threshold` shares always
        /// reconstruct the original secret.
        #[test]
        fn prop_split_reconstruct_round_trip(
            secret_bytes in any::<[u8; SECRET_LEN]>(),
            threshold in 2u8..=10,
            extra in 0u8..=5,
        ) {
            let mut rng = OsRng;
            let num_shares = threshold + extra;

            let secret = Zeroizing::new(secret_bytes);
            let (shares, commitment) = split(&secret, threshold, num_shares, &mut rng).unwrap();
            let subset: Vec<Share> = shares.iter().take(threshold as usize).cloned().collect();
            let recovered = reconstruct(&subset, &commitment).unwrap();
            prop_assert_eq!(recovered.as_ref(), secret.as_ref());
        }

        /// Property: any single-bit tamper of any share byte causes
        /// reconstruction to fail the commitment check.
        #[test]
        fn prop_single_bit_tamper_fails(
            secret_bytes in any::<[u8; SECRET_LEN]>(),
            share_index in 0usize..3,
            byte_index in 0usize..SECRET_LEN,
            bit_index in 0u8..8,
        ) {
            let mut rng = OsRng;
            let secret = Zeroizing::new(secret_bytes);
            let (mut shares, commitment) = split(&secret, 3, 3, &mut rng).unwrap();

            let target_idx = share_index % shares.len();
            let mut tampered = *shares[target_idx].bytes();
            tampered[byte_index] ^= 1 << bit_index;
            shares[target_idx] = Share::try_from_parts(
                shares[target_idx].id(),
                Zeroizing::new(tampered)
            ).unwrap();

            let result = reconstruct(&shares, &commitment);
            prop_assert!(matches!(result, Err(ShamirError::CommitmentMismatch)));
        }
    }
}
