// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Canonical CBOR encoder per RFC 8949 §4.2.
//!
//! Project-owned per D0018 §2.3: `ciborium` 0.2 does not enforce
//! deterministic encoding alone. This module provides a minimal typed
//! [`Value`] AST plus an encoder that produces byte-identical output for
//! semantically equivalent inputs. Two cooperating Cairn implementations
//! using this module must produce the exact same envelope bytes from the
//! same logical inputs — the load-bearing invariant for trust-graph
//! signature interop.
//!
//! ## Deterministic encoding rules (RFC 8949 §4.2)
//!
//! 1. **Smallest head encoding**: every length / integer head uses the
//!    smallest possible additional-information field (e.g., integer `0`
//!    encodes as `0x00`, not `0x18 0x00`).
//! 2. **Definite-length only**: no indefinite-length arrays / maps /
//!    strings / byte strings.
//! 3. **Canonical map-key order**: map entries are encoded with keys
//!    sorted by the bytewise lexicographic order of their canonical
//!    encoded forms. Duplicate keys are forbidden (encoder returns an
//!    error).
//! 4. **No floating-point**: floats and the `NaN` / `±inf` simple values
//!    are excluded from the type system. Cairn envelopes carry only
//!    integers, byte strings, text strings, arrays, maps, and the three
//!    simple values `null` / `true` / `false`.
//! 5. **No tags in v0.1**: CBOR tags (major type 6) are not yet
//!    represented in [`Value`]. The `COSE_Sign1` layer constructs its own
//!    tag wrapping at the byte level via the `coset` crate; the canonical
//!    encoder is currently only used for the bodies inside that wrapping.
//!
//! ## Type scope
//!
//! Deliberately minimal. The omitted variants (floats, indefinite-length
//! containers, tagged values, big integers beyond the `i64` range) all
//! either lack deterministic encodings or are unused by Cairn's envelope
//! schema (per D0006 §3). Adding a variant requires an explicit decision
//! and a corresponding update to the canonical encoding rules above.
//!
//! ## Decode strategy (deferred to next surface)
//!
//! Decoding to [`Value`] uses `ciborium` then strictness-checks by
//! re-encoding and comparing bytes. This is implemented in a separate
//! pass alongside the `COSE_Sign1` module. The v0.1 canonical helper is
//! encode-only.

use crate::error::EnvelopeError;

/// CBOR major type 0 — unsigned integers.
const MAJOR_UINT: u8 = 0;
/// CBOR major type 1 — negative integers.
const MAJOR_NINT: u8 = 1;
/// CBOR major type 2 — byte strings.
const MAJOR_BYTES: u8 = 2;
/// CBOR major type 3 — text strings.
const MAJOR_TEXT: u8 = 3;
/// CBOR major type 4 — arrays.
const MAJOR_ARRAY: u8 = 4;
/// CBOR major type 5 — maps.
const MAJOR_MAP: u8 = 5;
/// CBOR major type 7 — simple values (the three we allow: false/true/null).
const MAJOR_SIMPLE: u8 = 7;

/// A canonical-CBOR value.
///
/// Constructed via the typed variants below. The [`Value::encode`]
/// method produces canonical bytes per the rules in the module-level
/// docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// CBOR `null` (major 7, value 22 — `0xf6`).
    Null,
    /// CBOR boolean (major 7, value 20 / 21 — `0xf4` / `0xf5`).
    Bool(bool),
    /// CBOR signed integer in the `i64` range. Encodes as major 0 (when
    /// non-negative) or major 1 (when negative) with the smallest head.
    Int(i64),
    /// CBOR byte string.
    Bytes(Vec<u8>),
    /// CBOR text string (must be valid UTF-8 by the `String` type).
    Text(String),
    /// CBOR array.
    Array(Vec<Value>),
    /// CBOR map. The encoder sorts entries by canonical-key byte order
    /// per RFC 8949 §4.2 rule 3. Duplicate keys cause
    /// [`EnvelopeError::CanonicalCborDuplicateMapKey`].
    Map(Vec<(Value, Value)>),
}

impl Value {
    /// Encode this value to canonical CBOR bytes per RFC 8949 §4.2.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::CanonicalCborDuplicateMapKey`] if any
    /// [`Value::Map`] within `self` (recursively) contains duplicate
    /// canonical-encoded keys.
    pub fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        let mut buf = Vec::with_capacity(64);
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// Recursive encoding helper. Writes the canonical CBOR encoding of
    /// `self` into `buf`.
    fn encode_into(&self, buf: &mut Vec<u8>) -> Result<(), EnvelopeError> {
        match self {
            // Simple values (major 7) are encoded with their argument in
            // the low 5 bits of the head byte: `null` = 22, `false` = 20,
            // `true` = 21 (RFC 8949 §3.3 + §3.2.1).
            Self::Null => buf.push((MAJOR_SIMPLE << 5) | 22),
            Self::Bool(false) => buf.push((MAJOR_SIMPLE << 5) | 20),
            Self::Bool(true) => buf.push((MAJOR_SIMPLE << 5) | 21),
            Self::Int(n) => encode_int(buf, *n),
            Self::Bytes(b) => {
                encode_head(buf, MAJOR_BYTES, b.len() as u64);
                buf.extend_from_slice(b);
            }
            Self::Text(t) => {
                let bytes = t.as_bytes();
                encode_head(buf, MAJOR_TEXT, bytes.len() as u64);
                buf.extend_from_slice(bytes);
            }
            Self::Array(items) => {
                encode_head(buf, MAJOR_ARRAY, items.len() as u64);
                for item in items {
                    item.encode_into(buf)?;
                }
            }
            Self::Map(entries) => {
                encode_canonical_map(buf, entries)?;
            }
        }
        Ok(())
    }
}

/// Encode the head byte(s) for a major type + numeric argument per RFC
/// 8949 §3 using the smallest possible additional-information field.
///
/// This is the determinism load-bearing function: every length / integer
/// argument flows through here, so a single audit of this function
/// proves rule 1 (smallest head encoding) for the entire encoder. The
/// `try_from` cascade replaces an earlier explicit-comparison
/// formulation; using `try_from` lets the `Ok` arm produce the
/// already-narrowed value, eliminating inner truncating casts.
fn encode_head(buf: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    if value <= 23 {
        // Argument fits in the low 5 bits of the head. The `as u8` cast
        // is bounded by `<= 23` so truncation is impossible.
        #[allow(clippy::cast_possible_truncation)]
        buf.push(prefix | (value as u8));
    } else if let Ok(small) = u8::try_from(value) {
        // 1-byte argument follows.
        buf.push(prefix | 24);
        buf.push(small);
    } else if let Ok(short) = u16::try_from(value) {
        // 2-byte argument follows, big-endian.
        buf.push(prefix | 25);
        buf.extend_from_slice(&short.to_be_bytes());
    } else if let Ok(long) = u32::try_from(value) {
        // 4-byte argument follows, big-endian.
        buf.push(prefix | 26);
        buf.extend_from_slice(&long.to_be_bytes());
    } else {
        // 8-byte argument follows, big-endian.
        buf.push(prefix | 27);
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

/// Encode a signed `i64` per CBOR major 0 / major 1 with smallest head.
///
/// For `n >= 0`: encode as major 0 with argument `n as u64` (via
/// `u64::try_from`, never fails for non-negative `i64`).
///
/// For `n < 0`: encode as major 1 with argument `-1 - n`, which is
/// non-negative for the entire `i64` negative range including `i64::MIN`
/// (where `-1 - i64::MIN = i64::MAX`, still within `i64`). The expression
/// `n.wrapping_add(1).unsigned_abs()` computes this without any signed
/// overflow:
///
/// - `n.wrapping_add(1)` for `n` in `[i64::MIN, -1]` lands in
///   `[i64::MIN + 1, 0]`, all non-positive, no panic.
/// - `unsigned_abs()` on a non-positive `i64` returns the magnitude as
///   `u64`, no sign-loss cast required.
fn encode_int(buf: &mut Vec<u8>, n: i64) {
    if let Ok(non_negative) = u64::try_from(n) {
        encode_head(buf, MAJOR_UINT, non_negative);
    } else {
        // n < 0 (otherwise the `try_from` branch would have matched).
        let arg = n.wrapping_add(1).unsigned_abs();
        encode_head(buf, MAJOR_NINT, arg);
    }
}

/// Encode a CBOR map with canonical-key ordering and duplicate detection.
///
/// Per RFC 8949 §4.2 rule 3: map entries are emitted in ascending order
/// of the bytewise lexicographic comparison of their canonical encoded
/// keys. Duplicate canonical keys cause [`EnvelopeError::CanonicalCborDuplicateMapKey`].
fn encode_canonical_map(
    buf: &mut Vec<u8>,
    entries: &[(Value, Value)],
) -> Result<(), EnvelopeError> {
    // Pre-encode every key so we can sort by encoded-bytes order.
    let mut keyed: Vec<(Vec<u8>, &Value)> = Vec::with_capacity(entries.len());
    for (k, v) in entries {
        let encoded_key = k.encode()?;
        keyed.push((encoded_key, v));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));

    // Duplicate-key detection in a single pass over the sorted list.
    for window in keyed.windows(2) {
        // `windows(2)` always yields slices of length 2 for non-empty
        // inputs; this index is statically safe.
        #[allow(clippy::indexing_slicing)]
        if window[0].0 == window[1].0 {
            return Err(EnvelopeError::CanonicalCborDuplicateMapKey {
                entries: entries.len(),
            });
        }
    }

    encode_head(buf, MAJOR_MAP, entries.len() as u64);
    for (encoded_key, val) in &keyed {
        buf.extend_from_slice(encoded_key);
        val.encode_into(buf)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encoding `Int(0)` must use the single-byte head form `0x00`.
    #[test]
    fn int_zero_smallest_head() {
        let bytes = Value::Int(0).encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("00"));
    }

    /// Encoding `Int(23)` (boundary of low-5-bit argument) — single byte.
    #[test]
    fn int_23_single_byte() {
        let bytes = Value::Int(23).encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("17"));
    }

    /// Encoding `Int(24)` (first value needing 1-byte follower).
    #[test]
    fn int_24_two_byte() {
        let bytes = Value::Int(24).encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("1818"));
    }

    /// Encoding `Int(255)` (max 1-byte-follower value).
    #[test]
    fn int_255_two_byte() {
        let bytes = Value::Int(255).encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("18ff"));
    }

    /// Encoding `Int(256)` (first value needing 2-byte follower).
    #[test]
    fn int_256_three_byte() {
        let bytes = Value::Int(256).encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("190100"));
    }

    /// Encoding `Int(65535)` (max 2-byte-follower value).
    #[test]
    fn int_65535_three_byte() {
        let bytes = Value::Int(65535).encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("19ffff"));
    }

    /// Encoding `Int(65536)` (first value needing 4-byte follower).
    #[test]
    fn int_65536_five_byte() {
        let bytes = Value::Int(65536).encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("1a00010000"));
    }

    /// Encoding `Int(-1)` — major 1, argument 0 (smallest head).
    #[test]
    fn int_negative_one() {
        let bytes = Value::Int(-1).encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("20"));
    }

    /// Encoding `Int(-24)` — major 1, argument 23 (still single byte).
    #[test]
    fn int_negative_24_single_byte() {
        let bytes = Value::Int(-24).encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("37"));
    }

    /// Encoding `Int(-25)` — major 1, argument 24 (1-byte follower).
    #[test]
    fn int_negative_25_two_byte() {
        let bytes = Value::Int(-25).encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("3818"));
    }

    /// Encoding `Int(i64::MIN)` — the largest negative integer
    /// representable. The CBOR argument is `i64::MAX` as `u64` (`0x7FFF...`).
    #[test]
    fn int_min_does_not_overflow() {
        let bytes = Value::Int(i64::MIN).encode().unwrap();
        // Major 1 (`0x20`) | additional-info 27 (`0x1b`) = `0x3b`, then 8
        // bytes of `i64::MAX = 0x7FFFFFFFFFFFFFFF`.
        assert_eq!(bytes, hex_literal::hex!("3b7fffffffffffffff"));
    }

    #[test]
    fn null_encodes_as_f6() {
        assert_eq!(Value::Null.encode().unwrap(), hex_literal::hex!("f6"));
    }

    #[test]
    fn bool_false_encodes_as_f4() {
        assert_eq!(
            Value::Bool(false).encode().unwrap(),
            hex_literal::hex!("f4")
        );
    }

    #[test]
    fn bool_true_encodes_as_f5() {
        assert_eq!(Value::Bool(true).encode().unwrap(), hex_literal::hex!("f5"));
    }

    /// Empty byte string: major 2, argument 0 — `0x40`.
    #[test]
    fn bytes_empty() {
        assert_eq!(
            Value::Bytes(vec![]).encode().unwrap(),
            hex_literal::hex!("40")
        );
    }

    /// 4-byte byte string `[0x01, 0x02, 0x03, 0x04]` — `0x44 01 02 03 04`.
    #[test]
    fn bytes_short() {
        let bytes = Value::Bytes(vec![1, 2, 3, 4]).encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("4401020304"));
    }

    /// Empty text string: major 3, argument 0 — `0x60`.
    #[test]
    fn text_empty() {
        assert_eq!(
            Value::Text(String::new()).encode().unwrap(),
            hex_literal::hex!("60")
        );
    }

    /// Text string `"a"` — `0x61 0x61`.
    #[test]
    fn text_single_char() {
        let bytes = Value::Text("a".to_string()).encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("6161"));
    }

    /// Text string `"IETF"` — RFC 8949 §A example.
    #[test]
    fn text_ietf() {
        let bytes = Value::Text("IETF".to_string()).encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("6449455446"));
    }

    /// Empty array — `0x80`.
    #[test]
    fn array_empty() {
        assert_eq!(
            Value::Array(vec![]).encode().unwrap(),
            hex_literal::hex!("80")
        );
    }

    /// Array `[1, 2, 3]` — `0x83 01 02 03`.
    #[test]
    fn array_three_ints() {
        let bytes = Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)])
            .encode()
            .unwrap();
        assert_eq!(bytes, hex_literal::hex!("83010203"));
    }

    /// Empty map — `0xa0`.
    #[test]
    fn map_empty() {
        assert_eq!(
            Value::Map(vec![]).encode().unwrap(),
            hex_literal::hex!("a0")
        );
    }

    /// Single-entry map `{1: 2}` — `0xa1 01 02`.
    #[test]
    fn map_single_entry() {
        let v = Value::Map(vec![(Value::Int(1), Value::Int(2))]);
        assert_eq!(v.encode().unwrap(), hex_literal::hex!("a1 01 02"));
    }

    /// Map keys must be sorted by encoded-byte order. Input `{2: "b", 1: "a"}`
    /// must encode the same as `{1: "a", 2: "b"}`.
    #[test]
    fn map_keys_sorted() {
        let unsorted = Value::Map(vec![
            (Value::Int(2), Value::Text("b".to_string())),
            (Value::Int(1), Value::Text("a".to_string())),
        ]);
        let sorted = Value::Map(vec![
            (Value::Int(1), Value::Text("a".to_string())),
            (Value::Int(2), Value::Text("b".to_string())),
        ]);
        // Both inputs MUST produce the same canonical encoding.
        assert_eq!(unsorted.encode().unwrap(), sorted.encode().unwrap());
        // And both must equal the expected `{1: "a", 2: "b"}` bytes.
        assert_eq!(
            sorted.encode().unwrap(),
            hex_literal::hex!("a2 01 6161 02 6162")
        );
    }

    /// Map with mixed-type keys: the canonical order is by encoded-key
    /// bytewise comparison, which for `{1, "a"}` puts `1` (encoded
    /// `0x01`) before `"a"` (encoded `0x61 0x61`).
    #[test]
    fn map_keys_sort_across_types() {
        let v = Value::Map(vec![
            (Value::Text("a".to_string()), Value::Int(2)),
            (Value::Int(1), Value::Int(1)),
        ]);
        // Expected order: int key first (encoded byte 0x01 < text key
        // first byte 0x61).
        let bytes = v.encode().unwrap();
        assert_eq!(bytes, hex_literal::hex!("a2 01 01 6161 02"));
    }

    /// Duplicate canonical keys cause an error.
    #[test]
    fn map_duplicate_keys_error() {
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(1), Value::Int(2)),
        ]);
        let result = v.encode();
        assert!(matches!(
            result,
            Err(EnvelopeError::CanonicalCborDuplicateMapKey { entries: 2 })
        ));
    }

    /// Distinct values encoding to the same canonical key bytes are also
    /// duplicates. Both `Int(0)` and `Int(0)` encode to `0x00`; this is
    /// the same as the prior test logically but verifies via
    /// distinct-Value-but-same-encoded-bytes pathway.
    #[test]
    fn map_distinct_int_keys_with_same_encoding_error() {
        // Two `Int(0)` values are PartialEq-equal but the duplicate test
        // checks encoded-byte equality, which is what canonical CBOR
        // requires.
        let v = Value::Map(vec![
            (Value::Int(0), Value::Int(1)),
            (Value::Int(0), Value::Int(2)),
        ]);
        assert!(matches!(
            v.encode(),
            Err(EnvelopeError::CanonicalCborDuplicateMapKey { .. })
        ));
    }

    /// Nested arrays / maps encode correctly. `[[1, 2], {1: 2}]`.
    #[test]
    fn nested_array_and_map() {
        let v = Value::Array(vec![
            Value::Array(vec![Value::Int(1), Value::Int(2)]),
            Value::Map(vec![(Value::Int(1), Value::Int(2))]),
        ]);
        // Expected: array(2) | array(2) | 1 | 2 | map(1) | 1 | 2
        //         = 0x82      0x82      0x01 0x02 0xa1   0x01 0x02
        assert_eq!(v.encode().unwrap(), hex_literal::hex!("8282 0102 a1 0102"));
    }

    /// Determinism: encoding the same `Value` twice produces identical
    /// bytes.
    #[test]
    fn determinism_repeated_encode() {
        let v = Value::Map(vec![
            (Value::Int(5), Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef])),
            (Value::Int(2), Value::Text("hello".to_string())),
            (Value::Int(9), Value::Bool(true)),
        ]);
        let bytes1 = v.encode().unwrap();
        let bytes2 = v.encode().unwrap();
        assert_eq!(bytes1, bytes2);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Bounded `Value` strategy for round-trip testing. Excludes recursive
    /// generation depth to keep test runtime tractable.
    fn small_value_strategy() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(Value::Int),
            proptest::collection::vec(any::<u8>(), 0..32).prop_map(Value::Bytes),
            "[a-z]{0,16}".prop_map(Value::Text),
        ];
        leaf
    }

    proptest! {
        /// Property: encoding any leaf [`Value`] produces a non-empty
        /// canonical byte string (sanity check — all leaf encodings are
        /// at least 1 byte).
        #[test]
        fn prop_leaf_encode_non_empty(v in small_value_strategy()) {
            let bytes = v.encode().unwrap();
            prop_assert!(!bytes.is_empty());
        }

        /// Property: encoding the same value twice yields identical bytes
        /// (determinism — the contract this entire module exists to
        /// uphold).
        #[test]
        fn prop_determinism(v in small_value_strategy()) {
            let a = v.encode().unwrap();
            let b = v.encode().unwrap();
            prop_assert_eq!(a, b);
        }

        /// Property: map encoding is order-invariant in the input.
        /// Permuting the entry list of a map (without changing the
        /// entries themselves) does not change the encoded bytes.
        #[test]
        fn prop_map_order_invariance(
            keys in proptest::collection::vec(any::<i64>(), 0..8)
        ) {
            // Build a map from distinct keys.
            use std::collections::BTreeSet;
            let unique_keys: BTreeSet<i64> = keys.into_iter().collect();
            let entries: Vec<(Value, Value)> = unique_keys
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    // Cast safety: `i` is a `Vec` index bounded by the
                    // map size (well under `i64::MAX`).
                    #[allow(clippy::cast_possible_wrap)]
                    let value = Value::Int(i as i64);
                    (Value::Int(*k), value)
                })
                .collect();

            // Two orderings: as-iterated, and reversed.
            let map_forward = Value::Map(entries.clone());
            let mut reversed = entries;
            reversed.reverse();
            let map_reverse = Value::Map(reversed);

            prop_assert_eq!(
                map_forward.encode().unwrap(),
                map_reverse.encode().unwrap()
            );
        }
    }
}
