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
/// major version bump as the split / reconstruct / commit surfaces land.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ShamirError {
    /// Placeholder variant. Removed when the first real variant lands
    /// with the `share` module; kept here so the empty enum compiles
    /// cleanly under `#[non_exhaustive]`.
    ///
    /// Marked `#[doc(hidden)]` so it does not appear in published docs.
    #[doc(hidden)]
    #[error("placeholder — surface not yet implemented")]
    Placeholder,
}
