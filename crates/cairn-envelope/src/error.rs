// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Error types for `cairn-envelope`.
//!
//! Per D0018 §4.2: error variants carry indices, lengths, and type tags
//! only — never `Vec<u8>` or `&[u8]` payloads. This prevents secret-leak
//! vectors through error-propagation logging and matches the discipline
//! established in `cairn-crypto::error`.

use thiserror::Error;

/// Top-level error type for `cairn-envelope`, re-exported from the crate
/// root.
///
/// `#[non_exhaustive]` per D0018 §4.2 so new variants do not require a
/// major version bump as surfaces land.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// A [`crate::canonical::Value::Map`] contained duplicate
    /// canonical-encoded keys.
    ///
    /// RFC 8949 §4.2 forbids duplicate keys in canonical CBOR. Two
    /// `Value` entries are considered duplicates when their canonical
    /// encodings are byte-identical, not when they are `PartialEq`-equal
    /// at the `Value` level — the encoder rejects, e.g., `{0i64: ...,
    /// 0i64: ...}` even though the duplicates are obvious at the type
    /// level.
    #[error("canonical CBOR map contains duplicate encoded keys ({entries} entries)")]
    CanonicalCborDuplicateMapKey {
        /// Number of entries in the input map (pre-deduplication). Carried
        /// for diagnostic clarity only; per the no-payload discipline
        /// (D0018 §4.2) no key bytes are included.
        entries: usize,
    },
}
