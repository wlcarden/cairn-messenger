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

use ciborium::Value as CiboriumValue;

use crate::error::SigstoreVerifyError;

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

/// Coerce a CBOR map key to `i64` (the integer-keyed-map discipline).
pub(crate) fn key_to_i64(key: &CiboriumValue) -> Result<i64, SigstoreVerifyError> {
    let CiboriumValue::Integer(k) = key else {
        return Err(SigstoreVerifyError::ReleaseBundleDecodeFailed);
    };
    i64::try_from(i128::from(*k)).map_err(|_| SigstoreVerifyError::ReleaseBundleDecodeFailed)
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
