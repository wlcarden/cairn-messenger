// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Shared canonical-CBOR decode helpers for the offline release-bundle
//! wire format (D0024 §6.4).
//!
//! [`crate::RekorBundle`] and [`crate::ReleaseBundle`] both decode
//! integer-keyed canonical-CBOR maps per D0018 §2.3; these helpers
//! convert the loosely-typed [`ciborium::Value`] tree into the bundle's
//! fixed-width fields, mapping every structural mismatch to
//! [`SigstoreVerifyError::ReleaseBundleDecodeFailed`]. The manifest
//! payload (`crate::manifest`) keeps its own helpers because its decode
//! failures route to [`SigstoreVerifyError::ManifestDecodeFailed`]
//! instead — a deliberate layer split per the error-orthogonality
//! discipline in `crate::error`.

// These helpers are `pub(crate)` so the sibling `rekor` + `client`
// modules can call them; `pub` would trip the workspace `unreachable_pub`
// lint (they are not public API). clippy's `redundant_pub_crate` and
// `unreachable_pub` are mutually exclusive for that visibility class —
// same resolution as cairn-tor-transport/src/control.rs.
#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) needed for sibling rekor/client modules; `pub` would trip unreachable_pub"
)]

use std::io::Cursor;

use ciborium::Value as CiboriumValue;

use crate::error::SigstoreVerifyError;

/// Decode the top-level canonical integer-keyed CBOR map with the two
/// strictness checks that are safe under the forward-compatibility
/// discipline (D0006 §6.4): reject **trailing bytes** after the map (the
/// wire form is exactly one CBOR item) and reject **duplicate integer
/// keys** (the canonical encoder forbids both, D0018 §2.3). Unknown
/// integer keys are PRESERVED — the caller's `match` skips them via its
/// `_` arm, so a newer producer adding keys is still tolerated.
///
/// Returns `None` (the caller maps it to its own decode-failure variant)
/// on any structural problem: not valid CBOR, trailing bytes, a non-map
/// top level, a non-integer key, an out-of-`i64` key, or a duplicate key.
///
/// Deliberately does NOT reject non-minimal integer heads or
/// indefinite-length items (D0041 §6.3): that needs a raw canonical-form
/// validator and conflicts with `ciborium`'s decode model, and the
/// residual is contained — the manifest payload is byte-pinned by its
/// `COSE_Sign1` signature (a non-minimal manifest fails the signature
/// check), the rollback chain hashes the canonical RE-encoding
/// (`canonical_self_hash`), and every nested proof is independently
/// re-verified. Trailing-bytes + duplicate-keys are the malleability
/// vectors closeable without breaking forward-compat.
pub(crate) fn decode_canonical_map(bytes: &[u8]) -> Option<Vec<(i64, CiboriumValue)>> {
    let mut cursor = Cursor::new(bytes);
    let value: CiboriumValue = ciborium::de::from_reader(&mut cursor).ok()?;
    // The canonical wire form is exactly one item — reject trailing bytes.
    if cursor.position() != u64::try_from(bytes.len()).ok()? {
        return None;
    }
    let CiboriumValue::Map(entries) = value else {
        return None;
    };
    let mut out = Vec::with_capacity(entries.len());
    let mut seen: Vec<i64> = Vec::with_capacity(entries.len());
    for (key, val) in entries {
        let CiboriumValue::Integer(ki) = key else {
            return None;
        };
        let ki = i64::try_from(i128::from(ki)).ok()?;
        if seen.contains(&ki) {
            return None; // duplicate key — non-canonical, parser-differential footgun
        }
        seen.push(ki);
        out.push((ki, val));
    }
    Some(out)
}

/// Coerce a CBOR byte string to a fixed 32-byte array.
pub(crate) fn bytes_to_array_32(value: CiboriumValue) -> Result<[u8; 32], SigstoreVerifyError> {
    let CiboriumValue::Bytes(b) = value else {
        return Err(SigstoreVerifyError::ReleaseBundleDecodeFailed);
    };
    let arr: [u8; 32] = b
        .as_slice()
        .try_into()
        .map_err(|_| SigstoreVerifyError::ReleaseBundleDecodeFailed)?;
    Ok(arr)
}

/// Take ownership of a CBOR byte string as a `Vec<u8>`.
pub(crate) fn into_bytes(value: CiboriumValue) -> Result<Vec<u8>, SigstoreVerifyError> {
    let CiboriumValue::Bytes(b) = value else {
        return Err(SigstoreVerifyError::ReleaseBundleDecodeFailed);
    };
    Ok(b)
}

/// Take ownership of a CBOR text string as a `String`.
pub(crate) fn into_text(value: CiboriumValue) -> Result<String, SigstoreVerifyError> {
    let CiboriumValue::Text(s) = value else {
        return Err(SigstoreVerifyError::ReleaseBundleDecodeFailed);
    };
    Ok(s)
}

/// Coerce a CBOR (unsigned) integer to `u64`.
pub(crate) fn int_to_u64(value: &CiboriumValue) -> Result<u64, SigstoreVerifyError> {
    let CiboriumValue::Integer(v) = value else {
        return Err(SigstoreVerifyError::ReleaseBundleDecodeFailed);
    };
    u64::try_from(i128::from(*v)).map_err(|_| SigstoreVerifyError::ReleaseBundleDecodeFailed)
}

/// Coerce a CBOR array of byte strings to a `Vec<[u8; 32]>` (the Rekor
/// inclusion-proof audit path).
pub(crate) fn array_of_array_32(
    value: CiboriumValue,
) -> Result<Vec<[u8; 32]>, SigstoreVerifyError> {
    let CiboriumValue::Array(items) = value else {
        return Err(SigstoreVerifyError::ReleaseBundleDecodeFailed);
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(bytes_to_array_32(item)?);
    }
    Ok(out)
}
