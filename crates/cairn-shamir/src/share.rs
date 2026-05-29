// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Byte-level Shamir Secret Sharing for the 32-byte Ed25519 seed.
//!
//! The algorithm runs independently on each of the `SECRET_LEN` (= 32)
//! byte positions: for each position a random `GF(2⁸)` polynomial of
//! degree `threshold - 1` is drawn, with the secret byte as the
//! constant term. Each share's byte at that position is the polynomial
//! evaluated at the share's identifier. Reconstruction recovers the
//! constant term by Lagrange interpolation at `x = 0` over any
//! `threshold` shares.
//!
//! ## Public API
//!
//! - [`split`]: produce `num_shares` shares + a [`Commitment`] from a
//!   secret seed.
//! - [`reconstruct`]: recover the seed from any `threshold` shares,
//!   gated on commitment verification.
//! - [`Share`]: opaque wrapper around `(id, bytes)` with [`Zeroize`]
//!   discipline on the byte material.
//!
//! ## Parameter constraints
//!
//! - `threshold ∈ [2, 255]`. `threshold = 1` is mathematically valid
//!   but provides zero security (every share equals the secret); it is
//!   rejected to make the security contract explicit.
//! - `num_shares ∈ [threshold, 255]`. `num_shares > 255` is impossible
//!   because share identifiers are `u8 ∈ [1, 255]` (`0` is reserved for
//!   the secret evaluation point).
//!
//! ## Constant-time discipline
//!
//! All loops bound on public quantities (`SECRET_LEN`, `threshold`,
//! `num_shares`) — never on secret bytes. Field operations come from
//! [`crate::gf256`], which is constant-time by construction.
//! Reconstruction's Lagrange formula reads share bytes at public loop
//! indices; the share identifiers (`u8`) are public values.
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
use zeroize::Zeroizing;

use crate::commit::Commitment;
use crate::error::ShamirError;
use crate::gf256;

/// Length of the Shamir secret in bytes (= 32 = Ed25519 seed length per
/// RFC 8032 §5.1.5).
pub const SECRET_LEN: usize = 32;

/// A single Shamir share.
///
/// Carries a public 1-byte identifier (`1..=255`, the polynomial
/// evaluation point) and a 32-byte secret-bearing payload (the
/// polynomial value at that point, for each of the 32 byte positions
/// independently).
///
/// The payload is wrapped in [`Zeroizing`] so it zeroes on drop. The
/// `Share` itself implements [`Zeroize`]-on-drop transitively.
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
/// Returns the share vector and a BLAKE3 commit-of-secret (per
/// [`Commitment::for_secret`]) that [`reconstruct`] uses to verify the
/// recovered seed.
///
/// # Errors
///
/// - [`ShamirError::InvalidParameters`] if `threshold == 0`,
///   `threshold > num_shares`, or `num_shares == 0`.
/// - [`ShamirError::ThresholdTooLow`] if `threshold == 1` (provides
///   zero security; `threshold >= 2` is required).
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
    // `num_shares > 255` cannot occur because the parameter is `u8`.

    let commitment = Commitment::for_secret(secret.as_ref());

    // Pre-allocate the share storage with zero payloads.
    let mut shares: Vec<Share> = (1..=num_shares)
        .map(|id| Share {
            id,
            bytes: Zeroizing::new([0u8; SECRET_LEN]),
        })
        .collect();

    // For each byte position, generate a random polynomial of degree
    // (threshold - 1) and evaluate it at each share's identifier.
    let mut coeffs: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; threshold as usize]);
    for pos in 0..SECRET_LEN {
        // `pos` is a fixed public index, not a secret-dependent one.
        // The index reads below operate at compile-known offsets.
        let coeffs_slice = coeffs.as_mut_slice();
        // Constant term = the secret byte at this position.
        #[allow(clippy::indexing_slicing)]
        {
            coeffs_slice[0] = secret.as_ref()[pos];
        }
        // Random higher-order coefficients. `threshold >= 2` is
        // guaranteed by the early-error check, so `coeffs_slice[1..]`
        // is a non-empty slice.
        #[allow(clippy::indexing_slicing)]
        rng.fill_bytes(&mut coeffs_slice[1..]);

        for share in &mut shares {
            let y = gf256::poly_eval(coeffs_slice, share.id);
            #[allow(clippy::indexing_slicing)]
            {
                share.bytes.as_mut_slice()[pos] = y;
            }
        }
    }

    Ok((shares, commitment))
}

/// Reconstruct the secret from `shares`, gated on the commitment check.
///
/// Requires at least `threshold` shares (the threshold used at
/// [`split`] time). The caller is responsible for delivering exactly
/// the share count that matches their chosen `threshold`; this function
/// performs Lagrange interpolation over however many shares are
/// supplied. Supplying fewer than `threshold` shares produces a
/// candidate that fails the commitment check (rejected).
///
/// # Errors
///
/// - [`ShamirError::InsufficientShares`] if `shares.is_empty()`.
/// - [`ShamirError::InvalidShareId`] if any share has `id == 0`.
/// - [`ShamirError::DuplicateShareId`] if two shares carry the same
///   identifier.
/// - [`ShamirError::CommitmentMismatch`] if the reconstructed candidate
///   does not match the stored commitment (corrupted shares, malicious
///   reconstruction shares, or insufficient share count).
pub fn reconstruct(
    shares: &[Share],
    commitment: &Commitment,
) -> Result<Zeroizing<[u8; SECRET_LEN]>, ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::InsufficientShares { got: 0 });
    }

    // Reject id == 0 and duplicate ids in one pass.
    let mut seen_ids = [false; 256];
    for share in shares {
        if share.id == 0 {
            return Err(ShamirError::InvalidShareId);
        }
        let id_idx = share.id as usize;
        // `id_idx ∈ 1..=255`, well within the `[bool; 256]` bound.
        #[allow(clippy::indexing_slicing)]
        {
            if seen_ids[id_idx] {
                return Err(ShamirError::DuplicateShareId { id: share.id });
            }
            seen_ids[id_idx] = true;
        }
    }

    let mut secret: Zeroizing<[u8; SECRET_LEN]> = Zeroizing::new([0u8; SECRET_LEN]);
    // Allocate once outside the byte-position loop.
    let mut points: Vec<(u8, u8)> = Vec::with_capacity(shares.len());

    for pos in 0..SECRET_LEN {
        points.clear();
        for share in shares {
            // `pos` is a fixed public index; bytes access is constant
            // for the byte under consideration.
            #[allow(clippy::indexing_slicing)]
            points.push((share.id, share.bytes.as_slice()[pos]));
        }
        #[allow(clippy::indexing_slicing)]
        {
            secret.as_mut_slice()[pos] = lagrange_at_zero(&points);
        }
    }

    // Verify commitment in constant time.
    let computed = Commitment::for_secret(secret.as_ref());
    if !computed.ct_eq(commitment) {
        return Err(ShamirError::CommitmentMismatch);
    }

    Ok(secret)
}

/// Lagrange interpolation of a polynomial through `points` evaluated at
/// `x = 0`, in `GF(2⁸)`.
///
/// Returns the constant term of the unique polynomial of degree
/// `points.len() - 1` passing through the supplied points. Used by
/// [`reconstruct`] to recover each byte of the secret.
///
/// In `GF(2⁸)` (characteristic 2), subtraction equals addition (XOR),
/// so the standard Lagrange formula
///
/// ```text
/// P(0) = Σᵢ yᵢ · Πⱼ≠ᵢ (-xⱼ) / (xᵢ - xⱼ)
/// ```
///
/// simplifies to
///
/// ```text
/// P(0) = Σᵢ yᵢ · Πⱼ≠ᵢ xⱼ / (xᵢ + xⱼ)
/// ```
///
/// The denominators `xᵢ + xⱼ` are guaranteed non-zero by the caller
/// (which rejects duplicate share identifiers before this function is
/// reached).
fn lagrange_at_zero(points: &[(u8, u8)]) -> u8 {
    let mut result: u8 = 0;
    let n = points.len();
    for i in 0..n {
        // `i < n == points.len()`, so the index is always in-range.
        #[allow(clippy::indexing_slicing)]
        let (xi, yi) = points[i];
        let mut num: u8 = 1;
        let mut den: u8 = 1;
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            num = gf256::mul(num, xj);
            den = gf256::mul(den, gf256::add(xi, xj));
        }
        // `den != 0` because all xⱼ are distinct (duplicate-id rejected
        // by caller) → `xᵢ + xⱼ != 0` for every `j != i`.
        let term = gf256::mul(yi, gf256::mul(num, gf256::inv(den)));
        result = gf256::add(result, term);
    }
    result
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
        // The shares must be reconstructable from ANY threshold-many
        // subset, not just the first `threshold` shares.
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (shares, commitment) = split(&secret, 3, 5, &mut rng).unwrap();

        // Try several different 3-share subsets.
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
        // With threshold=3 but only 2 shares, Lagrange interpolation
        // produces some arbitrary value that does not equal the secret.
        // The commitment check catches this and returns the proper
        // error variant.
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (shares, commitment) = split(&secret, 3, 5, &mut rng).unwrap();

        let too_few = vec![shares[0].clone(), shares[1].clone()];
        let result = reconstruct(&too_few, &commitment);
        assert!(matches!(result, Err(ShamirError::CommitmentMismatch)));
    }

    #[test]
    fn tampered_share_byte_fails_commitment() {
        // Flipping a bit in one share's payload causes reconstruction
        // to produce a different candidate seed; the commitment check
        // rejects it.
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (mut shares, commitment) = split(&secret, 3, 5, &mut rng).unwrap();

        // Tamper with share[0]'s first byte.
        let mut tampered_bytes = *shares[0].bytes();
        tampered_bytes[0] ^= 0xFF;
        shares[0] = Share::try_from_parts(shares[0].id(), Zeroizing::new(tampered_bytes)).unwrap();

        let result = reconstruct(&shares[..3], &commitment);
        assert!(matches!(result, Err(ShamirError::CommitmentMismatch)));
    }

    #[test]
    fn tampered_commitment_rejects_correct_shares() {
        // Even with valid shares, a tampered commitment causes the
        // reconstruction to be rejected.
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (shares, commitment) = split(&secret, 3, 5, &mut rng).unwrap();

        // Construct a different commitment.
        let other_commitment = Commitment::for_secret(b"different seed");
        let result = reconstruct(&shares[..3], &other_commitment);
        assert!(matches!(result, Err(ShamirError::CommitmentMismatch)));
        // Confirm the commitments are actually different.
        assert!(!commitment.ct_eq(&other_commitment));
    }

    #[test]
    fn split_rejects_invalid_threshold() {
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        // threshold == 0
        assert!(matches!(
            split(&secret, 0, 5, &mut rng),
            Err(ShamirError::InvalidParameters {
                threshold: 0,
                num_shares: 5
            })
        ));
        // threshold > num_shares
        assert!(matches!(
            split(&secret, 6, 5, &mut rng),
            Err(ShamirError::InvalidParameters {
                threshold: 6,
                num_shares: 5
            })
        ));
        // num_shares == 0
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
        // threshold=1 provides zero security and is rejected by design.
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
        // Use share[0] twice — duplicate id.
        let dup = vec![shares[0].clone(), shares[0].clone()];
        let result = reconstruct(&dup, &commitment);
        assert!(matches!(
            result,
            Err(ShamirError::DuplicateShareId { id: 1 })
        ));
    }

    #[test]
    fn share_debug_redacts_bytes() {
        let bytes = Zeroizing::new([0xAB_u8; SECRET_LEN]);
        let share = Share::try_from_parts(7, bytes).unwrap();
        let debug_str = format!("{share:?}");
        assert!(debug_str.contains("id=7"));
        assert!(debug_str.contains("redacted"));
        // The byte value `AB` must NOT leak into the Debug output.
        assert!(!debug_str.contains("ab"));
    }

    /// Cross-check: split with k-of-n, gather all n shares, verify each
    /// possible k-subset reconstructs correctly. Exhaustive over
    /// `C(n, k)` combinations for a small n.
    #[test]
    fn exhaustive_3_of_4_subset_reconstruction() {
        let mut rng = OsRng;
        let secret = random_secret(&mut rng);

        let (shares, commitment) = split(&secret, 3, 4, &mut rng).unwrap();

        // C(4, 3) = 4 subsets.
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
    // scope: the proptest strategies bound the inputs (`threshold ∈
    // [2, 10]`, `extra ∈ [0, 5]`), so `threshold + extra` is well
    // under `u8::MAX` and all indices are bounded by proptest-supplied
    // moduli.
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
        ///
        /// `arithmetic_side_effects` / `indexing_slicing` allowed: the
        /// tamper indices are bounded by the proptest strategy, and the
        /// modulo operations are well-defined because the divisors are
        /// strictly positive.
        #[test]
        #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
        fn prop_single_bit_tamper_fails(
            secret_bytes in any::<[u8; SECRET_LEN]>(),
            share_index in 0usize..3,
            byte_index in 0usize..SECRET_LEN,
            bit_index in 0u8..8,
        ) {
            let mut rng = OsRng;
            let secret = Zeroizing::new(secret_bytes);
            let (mut shares, commitment) = split(&secret, 3, 3, &mut rng).unwrap();

            // Tamper the chosen share's chosen byte at the chosen bit.
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
