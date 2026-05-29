// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Recovery peer + share persistence per D0005 + D0022.
//!
//! Cairn's social recovery (D0005) has two storage-layer roles per
//! user that this module addresses:
//!
//! ## Role 1: acting AS the master (recovery-needing user)
//!
//! The user designates ~5 recovery peers. For each peer the user
//! persists: pubkey, display name, and the BLAKE3 commitment-of-
//! secret per D0018 §3.4 that the peer holds against the user's own
//! master. The commitment lets the peer detect a tampered share at
//! reconstruction time per D0005.
//!
//! Storage: [`cairn_storage::categories::RECOVERY_PEERS`]. Record id
//! per peer is SHA-256 of the peer's pubkey.
//!
//! ## Role 2: acting as a recovery peer for ANOTHER user
//!
//! When this user accepts a recovery-peer role for someone else, they
//! hold one Shamir share of that other user's master + the matching
//! commitment. The share is sensitive material — the storage layer's
//! per-record AEAD per D0022 §2.3 + the StrongBox-bound DEK
//! derivation per D0022 §2.2 are the at-rest defense.
//!
//! Storage: [`cairn_storage::categories::RECOVERY_SHARES`]. Record id
//! per share is SHA-256 of the master-pubkey-being-protected.
//!
//! ## What this module does NOT do
//!
//! - **Atomic re-split coordination per D0018 §3.5**: two-phase
//!   commit across N peers when the user re-shards. That needs the
//!   peer-protocol layer (D0025) + recovery-orchestrator (deferred
//!   until D0025 lands).
//! - **Peer-authentication per D0005**: the trust-graph layer
//!   establishes which peers are authorized to hold shares. This
//!   module operates on records the trust-graph layer has authorized.
//! - **Share distribution at provisioning**: the actual peer-to-peer
//!   transport of a share to its holder happens via the messaging
//!   layer + protocol (D0025).

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, VerifyingKey};
use cairn_envelope::canonical::Value;
use cairn_shamir::{COMMITMENT_LEN, Commitment, SECRET_LEN, Share};
use cairn_storage::{Storage, StorageError, categories};
use ciborium::Value as CiboriumValue;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Per-category schema version for `RECOVERY_PEERS` per D0022 §3.1.
pub const RECOVERY_PEERS_SCHEMA_VERSION: u32 = 1;

/// Per-category schema version for `RECOVERY_SHARES` per D0022 §3.1.
pub const RECOVERY_SHARES_SCHEMA_VERSION: u32 = 1;

/// Length of the SHA-256-based record id (storage addressing key).
pub const RECORD_ID_LEN: usize = 32;

// === Payload schema keys per D0006 §6.4 forward-compat discipline ===

/// `PeerRecord`: peer pubkey (bstr 32).
const KEY_PEER_PUBKEY: i64 = 1;
/// `PeerRecord`: display name (tstr).
const KEY_PEER_NAME: i64 = 2;
/// `PeerRecord`: 32-byte BLAKE3 commitment the peer holds.
const KEY_PEER_COMMITMENT: i64 = 3;

/// `HeldShare`: master pubkey being protected (bstr 32).
const KEY_SHARE_MASTER: i64 = 1;
/// `HeldShare`: share id byte.
const KEY_SHARE_ID: i64 = 2;
/// `HeldShare`: share value bytes (32).
const KEY_SHARE_VALUE: i64 = 3;
/// `HeldShare`: matching commitment (32 bytes).
const KEY_SHARE_COMMITMENT: i64 = 4;

/// A recovery peer the user (acting as master) has designated.
///
/// Per D0005 the user holds the peer's pubkey + display name + the
/// commitment-of-secret the peer holds against the user's master.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// Peer's Ed25519 public key. Verifies peer's signatures + binds
    /// the trust-graph attestation between user and peer.
    pub peer_pubkey: VerifyingKey,
    /// Display name (user-supplied, UTF-8). Operational UI affordance.
    pub display_name: String,
    /// 32-byte BLAKE3 commitment-of-secret the peer holds. Per D0018
    /// §3.4 + D0005 this is what the peer (or anyone reconstructing
    /// through them) checks the recovered candidate against.
    pub commitment: Commitment,
}

impl PeerRecord {
    /// Encode as canonical-CBOR for storage.
    fn to_canonical_cbor(&self) -> Result<Vec<u8>, PeerStoreError> {
        let map = Value::Map(vec![
            (
                Value::Int(KEY_PEER_PUBKEY),
                Value::Bytes(self.peer_pubkey.to_bytes().to_vec()),
            ),
            (
                Value::Int(KEY_PEER_NAME),
                Value::Text(self.display_name.clone()),
            ),
            (
                Value::Int(KEY_PEER_COMMITMENT),
                Value::Bytes(self.commitment.to_bytes().to_vec()),
            ),
        ]);
        map.encode()
            .map_err(|e| PeerStoreError::Storage(StorageError::CanonicalEncode(e)))
    }

    /// Decode from canonical-CBOR bytes.
    fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, PeerStoreError> {
        let parsed: CiboriumValue =
            ciborium::de::from_reader(bytes).map_err(|_| PeerStoreError::MalformedPayload)?;
        let CiboriumValue::Map(entries) = parsed else {
            return Err(PeerStoreError::MalformedPayload);
        };
        let mut peer_pubkey_bytes: Option<Vec<u8>> = None;
        let mut display_name: Option<String> = None;
        let mut commitment_bytes: Option<Vec<u8>> = None;
        for (key, value) in entries {
            let CiboriumValue::Integer(key_int_ciborium) = key else {
                return Err(PeerStoreError::MalformedPayload);
            };
            let key_int = i64::try_from(i128::from(key_int_ciborium))
                .map_err(|_| PeerStoreError::MalformedPayload)?;
            match key_int {
                KEY_PEER_PUBKEY => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(PeerStoreError::MalformedPayload);
                    };
                    peer_pubkey_bytes = Some(b);
                }
                KEY_PEER_NAME => {
                    let CiboriumValue::Text(t) = value else {
                        return Err(PeerStoreError::MalformedPayload);
                    };
                    display_name = Some(t);
                }
                KEY_PEER_COMMITMENT => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(PeerStoreError::MalformedPayload);
                    };
                    commitment_bytes = Some(b);
                }
                _ => {} // forward-compat per D0006 §6.4
            }
        }
        let peer_pubkey_bytes = peer_pubkey_bytes.ok_or(PeerStoreError::MalformedPayload)?;
        let display_name = display_name.ok_or(PeerStoreError::MalformedPayload)?;
        let commitment_bytes = commitment_bytes.ok_or(PeerStoreError::MalformedPayload)?;

        if peer_pubkey_bytes.len() != PUBLIC_KEY_LEN {
            return Err(PeerStoreError::MalformedPayload);
        }
        if commitment_bytes.len() != COMMITMENT_LEN {
            return Err(PeerStoreError::MalformedPayload);
        }
        let mut pubkey_arr = [0u8; PUBLIC_KEY_LEN];
        pubkey_arr.copy_from_slice(&peer_pubkey_bytes);
        let peer_pubkey =
            VerifyingKey::from_bytes(&pubkey_arr).map_err(|_| PeerStoreError::MalformedPayload)?;
        let mut commitment_arr = [0u8; COMMITMENT_LEN];
        commitment_arr.copy_from_slice(&commitment_bytes);
        let commitment = Commitment::from_bytes(commitment_arr);
        Ok(Self {
            peer_pubkey,
            display_name,
            commitment,
        })
    }
}

/// A Shamir share THIS user holds of ANOTHER user's master, with the
/// matching commitment for verification at recovery time.
///
/// The share's `value` bytes are sensitive — at rest they're sealed
/// by the storage layer's per-record AEAD per D0022 §2.3 + bound to
/// the StrongBox-derived DEK per D0022 §2.2. In memory they live in
/// `Zeroizing` via the `cairn_shamir::Share` type.
#[derive(Debug)]
pub struct HeldShare {
    /// The master public key this share protects. Used as the
    /// storage record id (after SHA-256 hashing).
    pub master_pubkey: VerifyingKey,
    /// The Shamir share itself.
    pub share: Share,
    /// The matching 32-byte BLAKE3 commitment of the master's seed
    /// per D0018 §3.4 — what the peer checks the recovered candidate
    /// against.
    pub commitment: Commitment,
}

impl HeldShare {
    /// Encode as canonical-CBOR for storage.
    fn to_canonical_cbor(&self) -> Result<Vec<u8>, PeerStoreError> {
        let map = Value::Map(vec![
            (
                Value::Int(KEY_SHARE_MASTER),
                Value::Bytes(self.master_pubkey.to_bytes().to_vec()),
            ),
            (
                Value::Int(KEY_SHARE_ID),
                Value::Int(i64::from(self.share.id())),
            ),
            (
                Value::Int(KEY_SHARE_VALUE),
                Value::Bytes(self.share.bytes().to_vec()),
            ),
            (
                Value::Int(KEY_SHARE_COMMITMENT),
                Value::Bytes(self.commitment.to_bytes().to_vec()),
            ),
        ]);
        map.encode()
            .map_err(|e| PeerStoreError::Storage(StorageError::CanonicalEncode(e)))
    }

    /// Decode from canonical-CBOR bytes.
    fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, PeerStoreError> {
        let parsed: CiboriumValue =
            ciborium::de::from_reader(bytes).map_err(|_| PeerStoreError::MalformedPayload)?;
        let CiboriumValue::Map(entries) = parsed else {
            return Err(PeerStoreError::MalformedPayload);
        };
        let mut master_bytes: Option<Vec<u8>> = None;
        let mut share_id: Option<u8> = None;
        let mut share_value: Option<Vec<u8>> = None;
        let mut commitment_bytes: Option<Vec<u8>> = None;
        for (key, value) in entries {
            let CiboriumValue::Integer(key_int_ciborium) = key else {
                return Err(PeerStoreError::MalformedPayload);
            };
            let key_int = i64::try_from(i128::from(key_int_ciborium))
                .map_err(|_| PeerStoreError::MalformedPayload)?;
            match key_int {
                KEY_SHARE_MASTER => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(PeerStoreError::MalformedPayload);
                    };
                    master_bytes = Some(b);
                }
                KEY_SHARE_ID => {
                    let CiboriumValue::Integer(v) = value else {
                        return Err(PeerStoreError::MalformedPayload);
                    };
                    let id_i64 = i64::try_from(i128::from(v))
                        .map_err(|_| PeerStoreError::MalformedPayload)?;
                    let id_u8 =
                        u8::try_from(id_i64).map_err(|_| PeerStoreError::MalformedPayload)?;
                    share_id = Some(id_u8);
                }
                KEY_SHARE_VALUE => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(PeerStoreError::MalformedPayload);
                    };
                    share_value = Some(b);
                }
                KEY_SHARE_COMMITMENT => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(PeerStoreError::MalformedPayload);
                    };
                    commitment_bytes = Some(b);
                }
                _ => {} // forward-compat
            }
        }
        let master_bytes = master_bytes.ok_or(PeerStoreError::MalformedPayload)?;
        let share_id = share_id.ok_or(PeerStoreError::MalformedPayload)?;
        let share_value = share_value.ok_or(PeerStoreError::MalformedPayload)?;
        let commitment_bytes = commitment_bytes.ok_or(PeerStoreError::MalformedPayload)?;

        if master_bytes.len() != PUBLIC_KEY_LEN {
            return Err(PeerStoreError::MalformedPayload);
        }
        if share_value.len() != SECRET_LEN {
            return Err(PeerStoreError::MalformedPayload);
        }
        if commitment_bytes.len() != COMMITMENT_LEN {
            return Err(PeerStoreError::MalformedPayload);
        }
        let mut master_arr = [0u8; PUBLIC_KEY_LEN];
        master_arr.copy_from_slice(&master_bytes);
        let master_pubkey =
            VerifyingKey::from_bytes(&master_arr).map_err(|_| PeerStoreError::MalformedPayload)?;
        let mut share_value_arr = [0u8; SECRET_LEN];
        share_value_arr.copy_from_slice(&share_value);
        let share = Share::try_from_parts(share_id, Zeroizing::new(share_value_arr))
            .map_err(|_| PeerStoreError::MalformedPayload)?;
        let mut commitment_arr = [0u8; COMMITMENT_LEN];
        commitment_arr.copy_from_slice(&commitment_bytes);
        let commitment = Commitment::from_bytes(commitment_arr);
        Ok(Self {
            master_pubkey,
            share,
            commitment,
        })
    }
}

/// Errors specific to the peer-store layer.
///
/// `#[non_exhaustive]` per D0018 §4.2.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PeerStoreError {
    /// Underlying storage failure.
    #[error("peer store: storage failure: {0}")]
    Storage(#[from] StorageError),
    /// Persisted payload was not well-formed canonical CBOR or did
    /// not match the schema.
    #[error("peer store: malformed payload")]
    MalformedPayload,
}

/// Compute the storage record id for a `PeerRecord` keyed by the
/// peer's pubkey: SHA-256 of the 32-byte pubkey.
#[must_use]
pub fn peer_record_id(peer_pubkey: &VerifyingKey) -> [u8; RECORD_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(peer_pubkey.to_bytes());
    let out = hasher.finalize();
    let mut arr = [0u8; RECORD_ID_LEN];
    arr.copy_from_slice(&out);
    arr
}

/// Compute the storage record id for a `HeldShare` keyed by the
/// master pubkey it protects: SHA-256 of the 32-byte master pubkey.
#[must_use]
pub fn share_record_id(master_pubkey: &VerifyingKey) -> [u8; RECORD_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(master_pubkey.to_bytes());
    let out = hasher.finalize();
    let mut arr = [0u8; RECORD_ID_LEN];
    arr.copy_from_slice(&out);
    arr
}

/// Store a recovery peer record. Idempotent: re-storing the same peer
/// overwrites with the supplied content (e.g., the user updated the
/// display name).
///
/// # Errors
///
/// Propagates [`PeerStoreError::Storage`] for storage failures and
/// AAD-encode failures (unreachable for typed inputs).
pub fn store_peer(
    storage: &Storage,
    record: &PeerRecord,
) -> Result<[u8; RECORD_ID_LEN], PeerStoreError> {
    let id = peer_record_id(&record.peer_pubkey);
    let bytes = record.to_canonical_cbor()?;
    storage.put(categories::RECOVERY_PEERS, &id, &bytes)?;
    Ok(id)
}

/// Load a recovery peer record by the peer's pubkey.
///
/// # Errors
///
/// - [`PeerStoreError::Storage`] with [`StorageError::RecordNotFound`]
///   if no peer with this pubkey is stored
/// - [`PeerStoreError::Storage`] with [`StorageError::DecryptFailed`]
///   for AEAD failures
/// - [`PeerStoreError::MalformedPayload`] if the persisted bytes
///   don't deserialize per the schema (storage corruption past the
///   AEAD check)
pub fn load_peer(
    storage: &Storage,
    peer_pubkey: &VerifyingKey,
) -> Result<PeerRecord, PeerStoreError> {
    let id = peer_record_id(peer_pubkey);
    let bytes = storage.get(categories::RECOVERY_PEERS, &id)?;
    PeerRecord::from_canonical_cbor(&bytes)
}

/// Load all designated recovery peers, sorted by pubkey bytes.
///
/// # Errors
///
/// Same as [`load_peer`].
pub fn load_all_peers(storage: &Storage) -> Result<Vec<PeerRecord>, PeerStoreError> {
    let ids = storage.list_records(categories::RECOVERY_PEERS)?;
    let mut peers = Vec::with_capacity(ids.len());
    for id in ids {
        let bytes = storage.get(categories::RECOVERY_PEERS, &id)?;
        peers.push(PeerRecord::from_canonical_cbor(&bytes)?);
    }
    peers.sort_by(|a, b| a.peer_pubkey.to_bytes().cmp(&b.peer_pubkey.to_bytes()));
    Ok(peers)
}

/// Delete a recovery peer record. Returns `true` if a row was
/// actually removed.
///
/// # Errors
///
/// Propagates [`PeerStoreError::Storage`] for storage failures.
pub fn delete_peer(storage: &Storage, peer_pubkey: &VerifyingKey) -> Result<bool, PeerStoreError> {
    let id = peer_record_id(peer_pubkey);
    storage
        .delete(categories::RECOVERY_PEERS, &id)
        .map_err(PeerStoreError::from)
}

/// Store a held share (this user is acting as a recovery peer for
/// another user). Idempotent.
///
/// # Errors
///
/// Propagates [`PeerStoreError::Storage`] for storage failures.
pub fn store_held_share(
    storage: &Storage,
    record: &HeldShare,
) -> Result<[u8; RECORD_ID_LEN], PeerStoreError> {
    let id = share_record_id(&record.master_pubkey);
    let bytes = record.to_canonical_cbor()?;
    storage.put(categories::RECOVERY_SHARES, &id, &bytes)?;
    Ok(id)
}

/// Load the share THIS user holds of the supplied master's secret.
///
/// # Errors
///
/// Same surface as [`load_peer`].
pub fn load_held_share(
    storage: &Storage,
    master_pubkey: &VerifyingKey,
) -> Result<HeldShare, PeerStoreError> {
    let id = share_record_id(master_pubkey);
    let bytes = storage.get(categories::RECOVERY_SHARES, &id)?;
    HeldShare::from_canonical_cbor(&bytes)
}

/// Delete a held share record. Returns `true` if a row was actually
/// removed.
///
/// # Errors
///
/// Propagates [`PeerStoreError::Storage`] for storage failures.
pub fn delete_held_share(
    storage: &Storage,
    master_pubkey: &VerifyingKey,
) -> Result<bool, PeerStoreError> {
    let id = share_record_id(master_pubkey);
    storage
        .delete(categories::RECOVERY_SHARES, &id)
        .map_err(PeerStoreError::from)
}

/// Initialize / migrate the recovery-peer category schemas per
/// D0022 §3.2. Idempotent.
///
/// # Errors
///
/// Propagates [`PeerStoreError::Storage`] for storage failures.
pub fn initialize_schema(storage: &Storage) -> Result<(), PeerStoreError> {
    let peers_v = storage.category_schema_version(categories::RECOVERY_PEERS)?;
    if peers_v < RECOVERY_PEERS_SCHEMA_VERSION {
        storage.set_category_schema_version(
            categories::RECOVERY_PEERS,
            RECOVERY_PEERS_SCHEMA_VERSION,
        )?;
    }
    let shares_v = storage.category_schema_version(categories::RECOVERY_SHARES)?;
    if shares_v < RECOVERY_SHARES_SCHEMA_VERSION {
        storage.set_category_schema_version(
            categories::RECOVERY_SHARES,
            RECOVERY_SHARES_SCHEMA_VERSION,
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use cairn_shamir::split;
    use cairn_storage::key_provider::testing::InMemoryKeyProvider;
    use rand_core::OsRng;
    use zeroize::Zeroizing;

    fn open_storage() -> Storage {
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"test passphrase".to_vec());
        Storage::open_in_memory(&provider, &passphrase).unwrap()
    }

    fn make_peer_record() -> PeerRecord {
        let mut rng = OsRng;
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();
        // Notional commitment — for storage tests, the byte content
        // doesn't matter; the round-trip property does.
        let commitment = Commitment::from_bytes([0x5Au8; COMMITMENT_LEN]);
        PeerRecord {
            peer_pubkey,
            display_name: "Alice".to_string(),
            commitment,
        }
    }

    fn make_held_share() -> HeldShare {
        let mut rng = OsRng;
        let master_pubkey = SigningKey::generate(&mut rng).verifying_key();
        let secret = Zeroizing::new([0x77u8; SECRET_LEN]);
        let (shares, commitment) = split(&secret, 3, 5, &mut rng).unwrap();
        let share = shares.into_iter().next().unwrap();
        HeldShare {
            master_pubkey,
            share,
            commitment,
        }
    }

    #[test]
    fn peer_record_id_is_deterministic() {
        let record = make_peer_record();
        let a = peer_record_id(&record.peer_pubkey);
        let b = peer_record_id(&record.peer_pubkey);
        assert_eq!(a, b);
    }

    #[test]
    fn peer_record_round_trip_canonical_cbor() {
        let record = make_peer_record();
        let bytes = record.to_canonical_cbor().unwrap();
        let recovered = PeerRecord::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(record, recovered);
    }

    #[test]
    fn store_load_peer_round_trip() {
        let storage = open_storage();
        let record = make_peer_record();
        store_peer(&storage, &record).unwrap();
        let loaded = load_peer(&storage, &record.peer_pubkey).unwrap();
        assert_eq!(loaded, record);
    }

    #[test]
    fn store_peer_is_idempotent_and_updatable() {
        let storage = open_storage();
        let mut record = make_peer_record();
        store_peer(&storage, &record).unwrap();
        record.display_name = "Alice (updated)".to_string();
        store_peer(&storage, &record).unwrap();
        let loaded = load_peer(&storage, &record.peer_pubkey).unwrap();
        assert_eq!(loaded.display_name, "Alice (updated)");
        assert_eq!(
            storage.count_records(categories::RECOVERY_PEERS).unwrap(),
            1
        );
    }

    #[test]
    fn load_all_peers_sorted_by_pubkey_bytes() {
        let storage = open_storage();
        let mut rng = OsRng;
        let mut records = (0u8..5)
            .map(|i| PeerRecord {
                peer_pubkey: SigningKey::generate(&mut rng).verifying_key(),
                display_name: format!("peer-{i}"),
                commitment: Commitment::from_bytes([i; COMMITMENT_LEN]),
            })
            .collect::<Vec<_>>();
        for r in &records {
            store_peer(&storage, r).unwrap();
        }
        records.sort_by(|a, b| a.peer_pubkey.to_bytes().cmp(&b.peer_pubkey.to_bytes()));
        let loaded = load_all_peers(&storage).unwrap();
        assert_eq!(loaded, records);
    }

    #[test]
    fn delete_peer_removes_record() {
        let storage = open_storage();
        let record = make_peer_record();
        store_peer(&storage, &record).unwrap();
        assert!(delete_peer(&storage, &record.peer_pubkey).unwrap());
        assert!(matches!(
            load_peer(&storage, &record.peer_pubkey),
            Err(PeerStoreError::Storage(StorageError::RecordNotFound { .. }))
        ));
        assert!(!delete_peer(&storage, &record.peer_pubkey).unwrap());
    }

    #[test]
    fn held_share_round_trip_canonical_cbor() {
        let record = make_held_share();
        let bytes = record.to_canonical_cbor().unwrap();
        let recovered = HeldShare::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(recovered.master_pubkey, record.master_pubkey);
        assert_eq!(recovered.share.id(), record.share.id());
        assert_eq!(recovered.share.bytes(), record.share.bytes());
        assert_eq!(
            recovered.commitment.to_bytes(),
            record.commitment.to_bytes()
        );
    }

    #[test]
    fn store_load_held_share_round_trip() {
        let storage = open_storage();
        let record = make_held_share();
        store_held_share(&storage, &record).unwrap();
        let loaded = load_held_share(&storage, &record.master_pubkey).unwrap();
        assert_eq!(loaded.master_pubkey, record.master_pubkey);
        assert_eq!(loaded.share.id(), record.share.id());
        assert_eq!(loaded.share.bytes(), record.share.bytes());
    }

    #[test]
    fn delete_held_share_removes_record() {
        let storage = open_storage();
        let record = make_held_share();
        store_held_share(&storage, &record).unwrap();
        assert!(delete_held_share(&storage, &record.master_pubkey).unwrap());
        assert!(matches!(
            load_held_share(&storage, &record.master_pubkey),
            Err(PeerStoreError::Storage(StorageError::RecordNotFound { .. }))
        ));
    }

    #[test]
    fn peer_and_held_share_categories_are_isolated() {
        // Same pubkey used as both a peer pubkey and as a master
        // pubkey for a held share. The record ids collide AT THE
        // HASH LEVEL but the per-category DEKs + AAD-binding to the
        // category keep them isolated.
        let storage = open_storage();
        let mut rng = OsRng;
        let shared_pubkey = SigningKey::generate(&mut rng).verifying_key();
        let peer = PeerRecord {
            peer_pubkey: shared_pubkey,
            display_name: "Alice".to_string(),
            commitment: Commitment::from_bytes([0x42u8; COMMITMENT_LEN]),
        };
        let secret = Zeroizing::new([0x77u8; SECRET_LEN]);
        let (shares, commitment) = split(&secret, 3, 5, &mut rng).unwrap();
        let share = HeldShare {
            master_pubkey: shared_pubkey,
            share: shares.into_iter().next().unwrap(),
            commitment,
        };
        store_peer(&storage, &peer).unwrap();
        store_held_share(&storage, &share).unwrap();
        // Both load independently.
        let loaded_peer = load_peer(&storage, &shared_pubkey).unwrap();
        let loaded_share = load_held_share(&storage, &shared_pubkey).unwrap();
        assert_eq!(loaded_peer.display_name, "Alice");
        assert_eq!(loaded_share.master_pubkey, shared_pubkey);
    }

    #[test]
    fn initialize_schema_sets_both_versions() {
        let storage = open_storage();
        initialize_schema(&storage).unwrap();
        assert_eq!(
            storage
                .category_schema_version(categories::RECOVERY_PEERS)
                .unwrap(),
            RECOVERY_PEERS_SCHEMA_VERSION
        );
        assert_eq!(
            storage
                .category_schema_version(categories::RECOVERY_SHARES)
                .unwrap(),
            RECOVERY_SHARES_SCHEMA_VERSION
        );
        // Idempotent.
        initialize_schema(&storage).unwrap();
    }
}
