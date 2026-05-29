// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Error types for `cairn-envelope`.
//!
//! Per D0018 §4.2: error variants carry indices, lengths, and type tags
//! only — never `Vec<u8>` or `&[u8]` payloads. This prevents secret-leak
//! vectors through error-propagation logging and matches the discipline
//! established in `cairn-crypto::error`.
//!
//! Variants are added incrementally as the surfaces land:
//!
//! - canonical-CBOR encoding errors will land with the `canonical` module
//! - `COSE_Sign1` construction / verification errors will land with the
//!   `cose_sign1` module
//! - envelope-assembly errors will land with the top-level encrypt /
//!   verify entry points

use thiserror::Error;

/// Top-level error type for `cairn-envelope`, re-exported from the crate
/// root.
///
/// Currently a placeholder until the first concrete surface (canonical
/// CBOR helper, per task 44) defines its variants. The `#[non_exhaustive]`
/// attribute is the discipline default per D0018 §4.2 so new variants do
/// not require a major version bump.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// Placeholder variant. Removed when the first real variant lands;
    /// kept here so the empty enum compiles cleanly under
    /// `#[non_exhaustive]`.
    ///
    /// Marked `#[doc(hidden)]` so it does not appear in published docs.
    #[doc(hidden)]
    #[error("placeholder — surface not yet implemented")]
    Placeholder,
}
