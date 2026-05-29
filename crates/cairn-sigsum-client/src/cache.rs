// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Cache state schema per D0023 §4.
//!
//! Two record types live in
//! [`cairn_storage::categories::SIGSUM_CACHE`]:
//!
//! - [`TreeHead`] — one per log endpoint; holds the latest accepted
//!   signed tree head + the cosignatures that backed acceptance.
//! - [`InclusionProof`] — one per emitted op; holds the leaf hash,
//!   the inclusion proof at `tree_size` when first observed, and the
//!   `observed_at` Unix-seconds timestamp.
//!
//! ## Record id derivation
//!
//! - Log-head record id: `SHA-256(log_url_bytes)` — addresses one
//!   row per log endpoint.
//! - Inclusion-proof record id:
//!   `SHA-256(log_url_bytes ‖ leaf_hash_bytes)` — addresses one row
//!   per (log, op) pair.
//!
//! Both ids are 32 bytes; the storage layer's AAD-binding per
//! D0022 §2.4 binds them to their categories so cross-category swap
//! fails AEAD.
//!
//! ## Cancel safety on cache write
//!
//! Cache writes use the same single-writer Storage::put path the rest
//! of the codebase uses. A cancelled future at any point during a
//! `put` either commits the row (SQLite COMMIT happened before the
//! drop) or doesn't (no partial state); the AEAD-sealed row is
//! self-contained.

use cairn_envelope::canonical::Value;
use ciborium::Value as CiboriumValue;
use sha2::{Digest, Sha256};

use crate::error::SigsumError;
use crate::leaf::LeafHash;

/// Length of the record id (storage-addressing key). 32 bytes
/// (SHA-256 output length).
pub const CACHE_RECORD_ID_LEN: usize = 32;

// === Canonical-CBOR map keys for the TreeHead payload schema ===
const KEY_TREE_HEAD_TREE_SIZE: i64 = 1;
const KEY_TREE_HEAD_ROOT_HASH: i64 = 2;
const KEY_TREE_HEAD_TIMESTAMP: i64 = 3;
const KEY_TREE_HEAD_COSIGNATURES: i64 = 4;
const KEY_TREE_HEAD_OBSERVED_AT: i64 = 5;

// === Canonical-CBOR map keys for the InclusionProof payload schema ===
const KEY_INCLUSION_LEAF_HASH: i64 = 1;
const KEY_INCLUSION_TREE_SIZE: i64 = 2;
const KEY_INCLUSION_PROOF_NODES: i64 = 3;
const KEY_INCLUSION_LEAF_INDEX: i64 = 4;
const KEY_INCLUSION_OBSERVED_AT: i64 = 5;

/// Signed Sigsum tree head, cached after successful witness-cosignature
/// verification per D0023 §4.1.
///
/// One witness produces one [`Cosignature`]; the cached `cosignatures`
/// vector holds the at-least-2-of-3 that verified per D0023 §3.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHead {
    /// Total number of leaves in the Sigsum log at this head.
    pub tree_size: u64,
    /// Root hash of the Merkle tree at `tree_size`.
    pub root_hash: [u8; 32],
    /// Log timestamp at signing (Unix-seconds; provided by the log).
    pub timestamp: u64,
    /// Witness cosignatures that backed acceptance per D0023 §3.4.
    pub cosignatures: Vec<Cosignature>,
    /// Unix-seconds when the cache observed this head.
    pub observed_at: u64,
}

/// A single witness cosignature, as cached.
///
/// The `witness_index` is the index into the configured
/// [`crate::WitnessPool`] so the cache can correlate the cosignature
/// back to its source witness without storing the witness's display
/// name redundantly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cosignature {
    /// 0-based index into the witness pool.
    pub witness_index: u8,
    /// 64-byte Ed25519 signature.
    pub signature: [u8; 64],
}

/// Inclusion proof for a single leaf at a specific `tree_size`, as
/// cached per D0023 §4.2.
///
/// The proof bytes are the Merkle-tree intermediate node hashes
/// returned by the Sigsum `get-inclusion-proof` endpoint. Verification
/// against the cached [`TreeHead`] is implemented at the
/// [`crate::client`] layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Leaf hash this proof witnesses inclusion of.
    pub leaf_hash: LeafHash,
    /// `tree_size` at which the proof was originally fetched.
    pub tree_size: u64,
    /// Merkle proof node hashes (32 bytes each).
    pub proof_nodes: Vec<[u8; 32]>,
    /// Leaf index within the Merkle tree.
    pub leaf_index: u64,
    /// Unix-seconds when the cache observed this proof.
    pub observed_at: u64,
}

impl TreeHead {
    /// Encode as canonical-CBOR for storage.
    ///
    /// # Errors
    ///
    /// Propagates the canonical encoder failure (unreachable for
    /// typed inputs).
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SigsumError> {
        let timestamp_i64 =
            i64::try_from(self.timestamp).map_err(|_| SigsumError::MalformedCacheRecord)?;
        let tree_size_i64 =
            i64::try_from(self.tree_size).map_err(|_| SigsumError::MalformedCacheRecord)?;
        let observed_at_i64 =
            i64::try_from(self.observed_at).map_err(|_| SigsumError::MalformedCacheRecord)?;

        let cosigs_array = self
            .cosignatures
            .iter()
            .map(|c| {
                Value::Array(vec![
                    Value::Int(i64::from(c.witness_index)),
                    Value::Bytes(c.signature.to_vec()),
                ])
            })
            .collect::<Vec<_>>();

        let map = Value::Map(vec![
            (
                Value::Int(KEY_TREE_HEAD_TREE_SIZE),
                Value::Int(tree_size_i64),
            ),
            (
                Value::Int(KEY_TREE_HEAD_ROOT_HASH),
                Value::Bytes(self.root_hash.to_vec()),
            ),
            (
                Value::Int(KEY_TREE_HEAD_TIMESTAMP),
                Value::Int(timestamp_i64),
            ),
            (
                Value::Int(KEY_TREE_HEAD_COSIGNATURES),
                Value::Array(cosigs_array),
            ),
            (
                Value::Int(KEY_TREE_HEAD_OBSERVED_AT),
                Value::Int(observed_at_i64),
            ),
        ]);
        map.encode().map_err(|_| SigsumError::MalformedCacheRecord)
    }

    /// Decode from canonical-CBOR bytes.
    ///
    /// # Errors
    ///
    /// [`SigsumError::MalformedCacheRecord`] for any CBOR / schema
    /// structural error.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SigsumError> {
        let parsed: CiboriumValue =
            ciborium::de::from_reader(bytes).map_err(|_| SigsumError::MalformedCacheRecord)?;
        let CiboriumValue::Map(entries) = parsed else {
            return Err(SigsumError::MalformedCacheRecord);
        };

        let mut tree_size: Option<u64> = None;
        let mut root_hash: Option<[u8; 32]> = None;
        let mut timestamp: Option<u64> = None;
        let mut cosignatures: Option<Vec<Cosignature>> = None;
        let mut observed_at: Option<u64> = None;

        for (key, value) in entries {
            let CiboriumValue::Integer(key_int_ciborium) = key else {
                return Err(SigsumError::MalformedCacheRecord);
            };
            let key_int = i64::try_from(i128::from(key_int_ciborium))
                .map_err(|_| SigsumError::MalformedCacheRecord)?;
            match key_int {
                KEY_TREE_HEAD_TREE_SIZE => {
                    tree_size = Some(int_to_u64(&value)?);
                }
                KEY_TREE_HEAD_ROOT_HASH => {
                    root_hash = Some(bytes_to_array_32(value)?);
                }
                KEY_TREE_HEAD_TIMESTAMP => {
                    timestamp = Some(int_to_u64(&value)?);
                }
                KEY_TREE_HEAD_COSIGNATURES => {
                    cosignatures = Some(decode_cosignatures(value)?);
                }
                KEY_TREE_HEAD_OBSERVED_AT => {
                    observed_at = Some(int_to_u64(&value)?);
                }
                _ => {} // forward-compat per D0006 §6.4
            }
        }

        Ok(Self {
            tree_size: tree_size.ok_or(SigsumError::MalformedCacheRecord)?,
            root_hash: root_hash.ok_or(SigsumError::MalformedCacheRecord)?,
            timestamp: timestamp.ok_or(SigsumError::MalformedCacheRecord)?,
            cosignatures: cosignatures.ok_or(SigsumError::MalformedCacheRecord)?,
            observed_at: observed_at.ok_or(SigsumError::MalformedCacheRecord)?,
        })
    }
}

impl InclusionProof {
    /// Encode as canonical-CBOR for storage.
    ///
    /// # Errors
    ///
    /// Propagates the canonical encoder failure (unreachable for
    /// typed inputs).
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SigsumError> {
        let tree_size_i64 =
            i64::try_from(self.tree_size).map_err(|_| SigsumError::MalformedCacheRecord)?;
        let leaf_index_i64 =
            i64::try_from(self.leaf_index).map_err(|_| SigsumError::MalformedCacheRecord)?;
        let observed_at_i64 =
            i64::try_from(self.observed_at).map_err(|_| SigsumError::MalformedCacheRecord)?;

        let proof_array = self
            .proof_nodes
            .iter()
            .map(|n| Value::Bytes(n.to_vec()))
            .collect::<Vec<_>>();

        let map = Value::Map(vec![
            (
                Value::Int(KEY_INCLUSION_LEAF_HASH),
                Value::Bytes(self.leaf_hash.as_bytes().to_vec()),
            ),
            (
                Value::Int(KEY_INCLUSION_TREE_SIZE),
                Value::Int(tree_size_i64),
            ),
            (
                Value::Int(KEY_INCLUSION_PROOF_NODES),
                Value::Array(proof_array),
            ),
            (
                Value::Int(KEY_INCLUSION_LEAF_INDEX),
                Value::Int(leaf_index_i64),
            ),
            (
                Value::Int(KEY_INCLUSION_OBSERVED_AT),
                Value::Int(observed_at_i64),
            ),
        ]);
        map.encode().map_err(|_| SigsumError::MalformedCacheRecord)
    }

    /// Decode from canonical-CBOR bytes.
    ///
    /// # Errors
    ///
    /// [`SigsumError::MalformedCacheRecord`] for any CBOR / schema
    /// structural error.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SigsumError> {
        let parsed: CiboriumValue =
            ciborium::de::from_reader(bytes).map_err(|_| SigsumError::MalformedCacheRecord)?;
        let CiboriumValue::Map(entries) = parsed else {
            return Err(SigsumError::MalformedCacheRecord);
        };

        let mut leaf_hash: Option<LeafHash> = None;
        let mut tree_size: Option<u64> = None;
        let mut proof_nodes: Option<Vec<[u8; 32]>> = None;
        let mut leaf_index: Option<u64> = None;
        let mut observed_at: Option<u64> = None;

        for (key, value) in entries {
            let CiboriumValue::Integer(key_int_ciborium) = key else {
                return Err(SigsumError::MalformedCacheRecord);
            };
            let key_int = i64::try_from(i128::from(key_int_ciborium))
                .map_err(|_| SigsumError::MalformedCacheRecord)?;
            match key_int {
                KEY_INCLUSION_LEAF_HASH => {
                    leaf_hash = Some(LeafHash::from_bytes(bytes_to_array_32(value)?));
                }
                KEY_INCLUSION_TREE_SIZE => {
                    tree_size = Some(int_to_u64(&value)?);
                }
                KEY_INCLUSION_PROOF_NODES => {
                    proof_nodes = Some(decode_proof_nodes(value)?);
                }
                KEY_INCLUSION_LEAF_INDEX => {
                    leaf_index = Some(int_to_u64(&value)?);
                }
                KEY_INCLUSION_OBSERVED_AT => {
                    observed_at = Some(int_to_u64(&value)?);
                }
                _ => {} // forward-compat per D0006 §6.4
            }
        }

        Ok(Self {
            leaf_hash: leaf_hash.ok_or(SigsumError::MalformedCacheRecord)?,
            tree_size: tree_size.ok_or(SigsumError::MalformedCacheRecord)?,
            proof_nodes: proof_nodes.ok_or(SigsumError::MalformedCacheRecord)?,
            leaf_index: leaf_index.ok_or(SigsumError::MalformedCacheRecord)?,
            observed_at: observed_at.ok_or(SigsumError::MalformedCacheRecord)?,
        })
    }
}

/// Compute the SIGSUM_CACHE record id for a log endpoint per
/// D0023 §4.1.
#[must_use]
pub fn cache_record_id_for_log(log_url: &url::Url) -> [u8; CACHE_RECORD_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(log_url.as_str().as_bytes());
    let out = hasher.finalize();
    let mut arr = [0u8; CACHE_RECORD_ID_LEN];
    arr.copy_from_slice(&out);
    arr
}

/// Compute the SIGSUM_CACHE record id for one (log, leaf) inclusion
/// proof per D0023 §4.2.
#[must_use]
pub fn cache_record_id_for_leaf(
    log_url: &url::Url,
    leaf_hash: &LeafHash,
) -> [u8; CACHE_RECORD_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(log_url.as_str().as_bytes());
    hasher.update(leaf_hash.as_bytes());
    let out = hasher.finalize();
    let mut arr = [0u8; CACHE_RECORD_ID_LEN];
    arr.copy_from_slice(&out);
    arr
}

// === Internal decode helpers ===

fn int_to_u64(value: &CiboriumValue) -> Result<u64, SigsumError> {
    let CiboriumValue::Integer(v) = value else {
        return Err(SigsumError::MalformedCacheRecord);
    };
    u64::try_from(i128::from(*v)).map_err(|_| SigsumError::MalformedCacheRecord)
}

fn bytes_to_array_32(value: CiboriumValue) -> Result<[u8; 32], SigsumError> {
    let CiboriumValue::Bytes(b) = value else {
        return Err(SigsumError::MalformedCacheRecord);
    };
    if b.len() != 32 {
        return Err(SigsumError::MalformedCacheRecord);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    Ok(arr)
}

fn decode_cosignatures(value: CiboriumValue) -> Result<Vec<Cosignature>, SigsumError> {
    let CiboriumValue::Array(entries) = value else {
        return Err(SigsumError::MalformedCacheRecord);
    };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let CiboriumValue::Array(pair) = entry else {
            return Err(SigsumError::MalformedCacheRecord);
        };
        if pair.len() != 2 {
            return Err(SigsumError::MalformedCacheRecord);
        }
        let mut iter = pair.into_iter();
        let witness_index_ciborium = iter.next().ok_or(SigsumError::MalformedCacheRecord)?;
        let signature_value = iter.next().ok_or(SigsumError::MalformedCacheRecord)?;
        let CiboriumValue::Integer(wi) = witness_index_ciborium else {
            return Err(SigsumError::MalformedCacheRecord);
        };
        let witness_index =
            u8::try_from(i128::from(wi)).map_err(|_| SigsumError::MalformedCacheRecord)?;
        let CiboriumValue::Bytes(sig_bytes) = signature_value else {
            return Err(SigsumError::MalformedCacheRecord);
        };
        if sig_bytes.len() != 64 {
            return Err(SigsumError::MalformedCacheRecord);
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        out.push(Cosignature {
            witness_index,
            signature: sig_arr,
        });
    }
    Ok(out)
}

fn decode_proof_nodes(value: CiboriumValue) -> Result<Vec<[u8; 32]>, SigsumError> {
    let CiboriumValue::Array(entries) = value else {
        return Err(SigsumError::MalformedCacheRecord);
    };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        out.push(bytes_to_array_32(entry)?);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_tree_head() -> TreeHead {
        TreeHead {
            tree_size: 1234,
            root_hash: [0xABu8; 32],
            timestamp: 1_700_000_000,
            cosignatures: vec![
                Cosignature {
                    witness_index: 0,
                    signature: [0xCCu8; 64],
                },
                Cosignature {
                    witness_index: 2,
                    signature: [0xDDu8; 64],
                },
            ],
            observed_at: 1_705_000_000,
        }
    }

    fn make_inclusion_proof() -> InclusionProof {
        InclusionProof {
            leaf_hash: LeafHash::from_bytes([0xEEu8; 32]),
            tree_size: 1234,
            proof_nodes: vec![[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]],
            leaf_index: 100,
            observed_at: 1_705_000_000,
        }
    }

    #[test]
    fn tree_head_round_trip_canonical_cbor() {
        let original = make_tree_head();
        let bytes = original.to_canonical_cbor().unwrap();
        let recovered = TreeHead::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn inclusion_proof_round_trip_canonical_cbor() {
        let original = make_inclusion_proof();
        let bytes = original.to_canonical_cbor().unwrap();
        let recovered = InclusionProof::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn tree_head_with_empty_cosignatures_round_trips() {
        let mut original = make_tree_head();
        original.cosignatures.clear();
        let bytes = original.to_canonical_cbor().unwrap();
        let recovered = TreeHead::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn malformed_bytes_fail_tree_head_decode() {
        let result = TreeHead::from_canonical_cbor(b"\xFF\x00\x01");
        assert!(matches!(result, Err(SigsumError::MalformedCacheRecord)));
    }

    #[test]
    fn malformed_bytes_fail_inclusion_proof_decode() {
        let result = InclusionProof::from_canonical_cbor(b"\xFF\x00\x01");
        assert!(matches!(result, Err(SigsumError::MalformedCacheRecord)));
    }

    #[test]
    fn cache_record_ids_are_deterministic() {
        let log_url = url::Url::parse("https://log.example.org").unwrap();
        let leaf = LeafHash::from_bytes([0xAAu8; 32]);
        assert_eq!(
            cache_record_id_for_log(&log_url),
            cache_record_id_for_log(&log_url)
        );
        assert_eq!(
            cache_record_id_for_leaf(&log_url, &leaf),
            cache_record_id_for_leaf(&log_url, &leaf)
        );
    }

    #[test]
    fn cache_record_ids_differ_across_distinct_inputs() {
        let log_a = url::Url::parse("https://log-a.example.org").unwrap();
        let log_b = url::Url::parse("https://log-b.example.org").unwrap();
        let leaf_a = LeafHash::from_bytes([0xAAu8; 32]);
        let leaf_b = LeafHash::from_bytes([0xBBu8; 32]);

        assert_ne!(
            cache_record_id_for_log(&log_a),
            cache_record_id_for_log(&log_b)
        );
        assert_ne!(
            cache_record_id_for_leaf(&log_a, &leaf_a),
            cache_record_id_for_leaf(&log_a, &leaf_b)
        );
        assert_ne!(
            cache_record_id_for_leaf(&log_a, &leaf_a),
            cache_record_id_for_leaf(&log_b, &leaf_a)
        );
    }
}
