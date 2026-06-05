// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Provenance-vouch wire codec per D0036 §2.
//!
//! A **vouch** packages a contact's shared `Attest` op chain (so the
//! receiver can verify it) + the voucher's capability token (so the
//! three-hop [`crate::verify_chain_links`] passes) into one canonical-CBOR
//! blob carried by the message-envelope key-9 `vouch` field. This module
//! is only the byte structure — verification + storage live at the FFI
//! handle (D0036 §5); authentication of the *sender* is the transport's
//! `COSE_Sign1` envelope (D0036 §3).
//!
//! Integer-keyed canonical-CBOR map:
//!
//! | Key | Field      | CBOR type      | Notes |
//! |-----|------------|----------------|-------|
//! | 1   | `op_chain` | array of bstr  | the voucher's `Attest` op chain, each a `COSE_Sign1` op |
//! | 2   | `token`    | bstr           | the voucher's signed capability token |

use cairn_envelope::canonical::Value;
use ciborium::Value as CiboriumValue;

use crate::error::TrustGraphError;

/// Canonical-CBOR map key for the op chain.
const KEY_OP_CHAIN: i64 = 1;
/// Canonical-CBOR map key for the voucher's capability token.
const KEY_TOKEN: i64 = 2;

/// Encode a vouch blob from the voucher's `op_chain` (each entry a signed
/// `COSE_Sign1` op) + their `token` bytes, per D0036 §2.
///
/// # Errors
///
/// [`TrustGraphError::CanonicalEncode`] from the canonical encoder
/// (unreachable for the byte inputs here).
pub fn encode_vouch(op_chain: &[Vec<u8>], token: &[u8]) -> Result<Vec<u8>, TrustGraphError> {
    let ops = Value::Array(op_chain.iter().map(|op| Value::Bytes(op.clone())).collect());
    let entries = vec![
        (Value::Int(KEY_OP_CHAIN), ops),
        (Value::Int(KEY_TOKEN), Value::Bytes(token.to_vec())),
    ];
    Value::Map(entries).encode().map_err(TrustGraphError::from)
}

/// Decode a vouch blob into `(op_chain, token)`, the inverse of
/// [`encode_vouch`].
///
/// # Errors
///
/// [`TrustGraphError::MalformedPayload`] for any CBOR / schema structural
/// error (not a map, missing/mistyped key, non-bstr op entry).
pub fn decode_vouch(bytes: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<u8>), TrustGraphError> {
    let parsed: CiboriumValue =
        ciborium::de::from_reader(bytes).map_err(|_| TrustGraphError::MalformedPayload)?;
    let CiboriumValue::Map(entries) = parsed else {
        return Err(TrustGraphError::MalformedPayload);
    };

    let mut op_chain: Option<Vec<Vec<u8>>> = None;
    let mut token: Option<Vec<u8>> = None;

    for (key, value) in entries {
        let CiboriumValue::Integer(key_int) = key else {
            return Err(TrustGraphError::MalformedPayload);
        };
        match i64::try_from(i128::from(key_int)) {
            Ok(KEY_OP_CHAIN) => {
                let CiboriumValue::Array(items) = value else {
                    return Err(TrustGraphError::MalformedPayload);
                };
                let mut ops = Vec::with_capacity(items.len());
                for item in items {
                    let CiboriumValue::Bytes(b) = item else {
                        return Err(TrustGraphError::MalformedPayload);
                    };
                    ops.push(b);
                }
                op_chain = Some(ops);
            }
            Ok(KEY_TOKEN) => {
                let CiboriumValue::Bytes(b) = value else {
                    return Err(TrustGraphError::MalformedPayload);
                };
                token = Some(b);
            }
            _ => {} // forward-compat per D0006 §6.4
        }
    }

    Ok((
        op_chain.ok_or(TrustGraphError::MalformedPayload)?,
        token.ok_or(TrustGraphError::MalformedPayload)?,
    ))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests unwrap known-good fixtures; an unwrap panic IS the failure signal"
)]
mod tests {
    use super::*;

    #[test]
    fn vouch_round_trips() {
        let op_chain = vec![b"op-one".to_vec(), b"op-two".to_vec()];
        let token = b"capability-token".to_vec();
        let bytes = encode_vouch(&op_chain, &token).unwrap();
        let (ops, tok) = decode_vouch(&bytes).unwrap();
        assert_eq!(ops, op_chain);
        assert_eq!(tok, token);
    }

    #[test]
    fn single_op_vouch_round_trips() {
        let op_chain = vec![b"genesis-attest".to_vec()];
        let token = b"tok".to_vec();
        let (ops, tok) = decode_vouch(&encode_vouch(&op_chain, &token).unwrap()).unwrap();
        assert_eq!(ops, op_chain);
        assert_eq!(tok, token);
    }

    #[test]
    fn malformed_vouch_rejected() {
        assert!(matches!(
            decode_vouch(&[0xFF, 0xFF, 0xFF]),
            Err(TrustGraphError::MalformedPayload)
        ));
    }
}
