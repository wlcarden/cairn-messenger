// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Error types for `cairn-shamir`.
//!
//! Per D0018 §4.2: error variants carry indices, lengths, and type tags
//! only — never `Vec<u8>` or `&[u8]` payloads. This prevents secret-leak
//! vectors through error-propagation logging and matches the discipline
//! established in `cairn-crypto::error` and `cairn-envelope::error`.

use thiserror::Error;

/// Top-level error type for `cairn-shamir`, re-exported from the crate
/// root.
///
/// `#[non_exhaustive]` per D0018 §4.2 so new variants do not require a
/// major version bump as additional surfaces (e.g., verifiable secret
/// sharing for trust-graph attestations per D0006 §6) land later.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ShamirError {
    /// Invalid `threshold` / `num_shares` combination passed to
    /// [`crate::share::split`].
    ///
    /// Valid combinations require `threshold >= 1`, `num_shares >= 1`,
    /// and `threshold <= num_shares`. The `u8` typing already prevents
    /// `num_shares > 255`; the `> 255` case is unreachable.
    #[error("invalid Shamir parameters: threshold={threshold} num_shares={num_shares}")]
    InvalidParameters {
        /// Threshold requested.
        threshold: u8,
        /// Number of shares requested.
        num_shares: u8,
    },
    /// Threshold of 1 was requested. Rejected because it provides zero
    /// security (every share equals the secret).
    #[error("Shamir threshold too low: {threshold} (must be >= 2)")]
    ThresholdTooLow {
        /// Threshold requested (always `1` at present).
        threshold: u8,
    },
    /// Share identifier `0` is reserved for the secret-recovery
    /// evaluation point and cannot be carried by a [`crate::share::Share`].
    #[error("invalid Shamir share identifier 0 (must be in 1..=255)")]
    InvalidShareId,
    /// Two shares in a reconstruction set carried the same identifier.
    #[error("duplicate Shamir share identifier: {id}")]
    DuplicateShareId {
        /// The duplicated share identifier.
        id: u8,
    },
    /// Reconstruction was attempted with an empty share set.
    #[error("insufficient Shamir shares: {got} provided")]
    InsufficientShares {
        /// Number of shares supplied to reconstruction.
        got: usize,
    },
    /// The reconstructed candidate seed did not match the stored
    /// commitment.
    ///
    /// Indicates either:
    /// 1. fewer than `threshold` shares were supplied (Lagrange
    ///    interpolation produced an arbitrary value);
    /// 2. one or more shares were corrupted in storage;
    /// 3. one or more shares were deliberately tampered with by a
    ///    malicious reconstruction-time peer; or
    /// 4. the commitment itself was tampered with.
    ///
    /// Per D0018 §3.4 the variant is uniform across these causes;
    /// distinguishing them is the application layer's responsibility.
    #[error("Shamir commitment verification failed")]
    CommitmentMismatch,
    /// The underlying `vsss-rs::Gf256` split operation returned an
    /// error. Practically unreachable for inputs that pass Cairn's
    /// pre-validation (`threshold` / `num_shares` / secret length), but
    /// the variant exists so we never `unwrap` on the library's
    /// `Result`.
    #[error("vsss-rs split operation failed")]
    VsssSplitFailed,
}
