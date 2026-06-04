// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Trust-graph history persistence per D0022 + D0006 §2 / §5.
//!
//! Wraps [`cairn_storage::Storage`] with trust-graph-specific
//! semantics:
//!
//! - **Category**: [`cairn_storage::categories::TRUST_GRAPH`]
//! - **Record id**: SHA-256 of the signed envelope bytes
//!   (`crate::SignedTrustGraphOp::encode(false)`). The 32-byte digest
//!   is the on-disk key; the AAD-binding per D0022 §2.4 binds the
//!   record to that key so slot-swap attacks fail the AEAD tag.
//! - **Payload**: the canonical encoded envelope bytes themselves —
//!   the same wire format the rest of the protocol layer consumes
//!   via `SignedTrustGraphOp::from_bytes`.
//!
//! The store-layer is thin on purpose: it doesn't re-encode, doesn't
//! recompute hashes, doesn't validate the chain. Callers do all of
//! that via `verify_chain_links` against the loaded slice. The store
//! is just durable storage + lookup.
//!
//! ## Recovering chains
//!
//! [`load_chain_for_pair`] reads every op whose `(issuer, subject)`
//! matches the supplied pair and returns them ordered by `timestamp`.
//! The returned slice is suitable input to
//! [`crate::verify_chain_links`].
//!
//! v1's implementation does a linear scan over the trust-graph
//! category (per-record decode + filter). At pilot scale (~hundreds
//! of ops total per user per the [implementation-status doc][1]) the
//! linear scan is fine. v1.5 adds a secondary index if profiling
//! shows the scan becomes a bottleneck — the per-(issuer, subject)
//! index would live in a sibling `quarantine_state` or new
//! `trust_graph_index` category.
//!
//! [1]: ../../../docs/implementation-status.md

use cairn_crypto::ed25519::VerifyingKey;
use cairn_storage::{Storage, StorageError, categories};
use sha2::{Digest, Sha256};

use crate::{SignedTrustGraphOp, TrustGraphError};

/// Per-category schema version this build emits + understands per
/// D0022 §3.1. Bumped when the on-disk payload schema changes.
pub const TRUST_GRAPH_SCHEMA_VERSION: u32 = 1;

/// Length of the on-disk record id (SHA-256 digest of the signed
/// envelope bytes). 32 bytes.
pub const RECORD_ID_LEN: usize = 32;

/// Errors specific to the trust-graph store layer.
///
/// `#[non_exhaustive]` per D0018 §4.2.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// Failure from the underlying [`Storage`] handle (rusqlite I/O,
    /// AEAD verify failure, mutex poison, etc.).
    #[error("trust-graph store: storage failure: {0}")]
    Storage(#[from] StorageError),
    /// Failure decoding a loaded record back into a
    /// [`SignedTrustGraphOp`]. Indicates either schema drift or
    /// storage corruption beyond what the AEAD tag caught.
    #[error("trust-graph store: failed to decode stored op: {0}")]
    Decode(#[from] TrustGraphError),
    /// Failure encoding a [`SignedTrustGraphOp`] for storage.
    /// Unreachable for envelopes the caller constructed via
    /// [`crate::SignedTrustGraphOp::sign`]; the variant exists so we
    /// never `unwrap` on the encode path.
    #[error("trust-graph store: failed to encode op for storage: {0}")]
    Encode(TrustGraphError),
}

/// Compute the on-disk record id for a signed op per the
/// module-level schema: SHA-256 of the canonical envelope bytes.
///
/// Stable across runs + implementations: same op → same id. This is
/// the property that lets `store_signed_op` deduplicate idempotently.
///
/// # Errors
///
/// Propagates [`TrustGraphError`] from the envelope encoder
/// (unreachable for envelopes constructed via the public API).
pub fn record_id_for(op: &SignedTrustGraphOp) -> Result<[u8; RECORD_ID_LEN], StoreError> {
    let bytes = op.encode(false).map_err(StoreError::Encode)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; RECORD_ID_LEN];
    arr.copy_from_slice(&out);
    Ok(arr)
}

/// Persist a signed trust-graph op to durable storage.
///
/// Idempotent: storing the same op twice overwrites with the same
/// content (the `record_id` is deterministic). The store-layer does NOT
/// validate the op against a chain or capability token — callers must
/// have verified the op via [`SignedTrustGraphOp::verify_chain`]
/// before calling this.
///
/// # Errors
///
/// - [`StoreError::Encode`] if the envelope encode step fails
///   (unreachable)
/// - [`StoreError::Storage`] for any underlying storage failure
pub fn store_signed_op(
    storage: &Storage,
    op: &SignedTrustGraphOp,
) -> Result<[u8; RECORD_ID_LEN], StoreError> {
    let id = record_id_for(op)?;
    let bytes = op.encode(false).map_err(StoreError::Encode)?;
    storage.put(categories::TRUST_GRAPH, &id, &bytes)?;
    Ok(id)
}

/// Load a signed trust-graph op by its record id.
///
/// # Errors
///
/// - [`StoreError::Storage`] with [`StorageError::RecordNotFound`]
///   if no op with this id is stored
/// - [`StoreError::Storage`] with [`StorageError::DecryptFailed`] if
///   the AEAD verification fails (storage tamper or wrong DEK —
///   uniform per D0018 §1.4)
/// - [`StoreError::Decode`] if the decrypted bytes don't deserialize
///   as a `SignedTrustGraphOp` (schema drift or corruption past the
///   AEAD check)
pub fn load_signed_op(
    storage: &Storage,
    id: &[u8; RECORD_ID_LEN],
) -> Result<SignedTrustGraphOp, StoreError> {
    let bytes = storage.get(categories::TRUST_GRAPH, id.as_slice())?;
    let op = SignedTrustGraphOp::from_bytes(&bytes)?;
    Ok(op)
}

/// Load all signed ops whose `(issuer, subject)` pair matches the
/// supplied keys, sorted by `timestamp` ascending.
///
/// Suitable input to [`crate::verify_chain_links`]. The store-layer
/// does NOT verify the ops — callers must run chain validation
/// against the returned slice.
///
/// Implementation: linear scan over the trust-graph category. At v1
/// pilot scale (~hundreds of ops) the scan is fine; v1.5+ adds a
/// secondary index if profiling shows otherwise.
///
/// # Errors
///
/// - [`StoreError::Storage`] for `SQLite` / AEAD failures
/// - [`StoreError::Decode`] if any stored record fails to decode
///   (storage corruption past the AEAD check)
pub fn load_chain_for_pair(
    storage: &Storage,
    issuer: &VerifyingKey,
    subject: &VerifyingKey,
) -> Result<Vec<SignedTrustGraphOp>, StoreError> {
    let ids = storage.list_records(categories::TRUST_GRAPH)?;
    let mut chain = Vec::new();
    for id in ids {
        let bytes = storage.get(categories::TRUST_GRAPH, &id)?;
        let op = SignedTrustGraphOp::from_bytes(&bytes)?;
        if op.op().issuer == *issuer && op.op().subject == *subject {
            chain.push(op);
        }
    }
    chain.sort_by_key(|op| op.op().timestamp);
    Ok(chain)
}

/// Load all signed ops in the trust-graph category, sorted by
/// `timestamp` ascending. Intended for the cascade-quarantine
/// computation path which needs the cross-chain set per D0006 §2.
///
/// # Errors
///
/// Same as [`load_chain_for_pair`].
pub fn load_all_ops_chronological(
    storage: &Storage,
) -> Result<Vec<SignedTrustGraphOp>, StoreError> {
    let ids = storage.list_records(categories::TRUST_GRAPH)?;
    let mut all = Vec::new();
    for id in ids {
        let bytes = storage.get(categories::TRUST_GRAPH, &id)?;
        let op = SignedTrustGraphOp::from_bytes(&bytes)?;
        all.push(op);
    }
    all.sort_by_key(|op| op.op().timestamp);
    Ok(all)
}

/// Delete a stored op by record id.
///
/// Used by maintenance flows (manual cleanup; post-rotation pruning).
/// The cryptographic chain invariants are not enforced here — callers
/// must reason about whether deleting an op leaves dependent ops
/// dangling.
///
/// # Errors
///
/// - [`StoreError::Storage`] for `SQLite` failures
pub fn delete_op(storage: &Storage, id: &[u8; RECORD_ID_LEN]) -> Result<bool, StoreError> {
    storage
        .delete(categories::TRUST_GRAPH, id.as_slice())
        .map_err(StoreError::from)
}

/// Initialize / migrate the trust-graph category's schema per
/// D0022 §3.2.
///
/// v1 lands the bootstrap schema only — there's no per-record content
/// to migrate yet (the payload is the canonical-CBOR envelope which
/// has its own forward-compat discipline per D0006 §6.4). The
/// function exists so consuming-app code can call it idempotently at
/// app start, in anticipation of v1.5+ migrations.
///
/// # Errors
///
/// - [`StoreError::Storage`] for `SQLite` failures
pub fn initialize_schema(storage: &Storage) -> Result<(), StoreError> {
    let current = storage.category_schema_version(categories::TRUST_GRAPH)?;
    if current >= TRUST_GRAPH_SCHEMA_VERSION {
        return Ok(());
    }
    storage.set_category_schema_version(categories::TRUST_GRAPH, TRUST_GRAPH_SCHEMA_VERSION)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{OpType, TrustGraphOp};
    use cairn_crypto::ed25519::SigningKey;
    use cairn_identity::{CapabilityToken, capabilities};
    use cairn_storage::key_provider::testing::InMemoryKeyProvider;
    use rand_core::OsRng;
    use zeroize::Zeroizing;

    fn open_storage() -> Storage {
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"test passphrase".to_vec());
        Storage::open_in_memory(&provider, &passphrase).unwrap()
    }

    /// Build a (operational identity, device, signed op) triple. The
    /// op is an Attest from the operational identity about a random
    /// peer at the supplied timestamp.
    fn make_attest_op(
        op_identity_sk: &SigningKey,
        device_sk: &SigningKey,
        peer: VerifyingKey,
        timestamp: u64,
    ) -> SignedTrustGraphOp {
        let op = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer,
            timestamp,
            vec![],
            vec![],
            crate::Strength::InPerson,
        );
        SignedTrustGraphOp::sign(op, device_sk).unwrap()
    }

    /// Build a fresh (op identity, device, token bytes) bundle so
    /// callers can verify ops loaded back through the store.
    fn make_token_bundle(scope: &[&str]) -> (SigningKey, SigningKey, Vec<u8>) {
        let mut rng = OsRng;
        let op_identity_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);
        let token = CapabilityToken::new(
            op_identity_sk.verifying_key(),
            device_sk.verifying_key(),
            scope.iter().map(|s| (*s).to_string()).collect(),
            2_000_000_000,
            vec![],
        );
        let signed_token = token.sign(&op_identity_sk).unwrap();
        let token_bytes = signed_token.encode(false).unwrap();
        (op_identity_sk, device_sk, token_bytes)
    }

    #[test]
    fn record_id_is_deterministic_for_same_op() {
        let mut rng = OsRng;
        let op_identity_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);
        let peer = SigningKey::generate(&mut rng).verifying_key();
        let op = make_attest_op(&op_identity_sk, &device_sk, peer, 1_700_000_000);
        let id_a = record_id_for(&op).unwrap();
        let id_b = record_id_for(&op).unwrap();
        assert_eq!(id_a, id_b);
        assert_eq!(id_a.len(), RECORD_ID_LEN);
    }

    #[test]
    fn round_trip_store_then_load() {
        let storage = open_storage();
        let mut rng = OsRng;
        let op_identity_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);
        let peer = SigningKey::generate(&mut rng).verifying_key();
        let op = make_attest_op(&op_identity_sk, &device_sk, peer, 1_700_000_000);

        let id = store_signed_op(&storage, &op).unwrap();
        let loaded = load_signed_op(&storage, &id).unwrap();

        assert_eq!(loaded.op(), op.op());
        // Encoded envelopes should be byte-identical.
        assert_eq!(loaded.encode(false).unwrap(), op.encode(false).unwrap());
    }

    #[test]
    fn store_is_idempotent_for_same_op() {
        let storage = open_storage();
        let mut rng = OsRng;
        let op_identity_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);
        let peer = SigningKey::generate(&mut rng).verifying_key();
        let op = make_attest_op(&op_identity_sk, &device_sk, peer, 1_700_000_000);

        let id_a = store_signed_op(&storage, &op).unwrap();
        let id_b = store_signed_op(&storage, &op).unwrap();
        assert_eq!(id_a, id_b);
        // After two stores, count is still 1.
        assert_eq!(storage.count_records(categories::TRUST_GRAPH).unwrap(), 1);
    }

    #[test]
    fn load_chain_for_pair_filters_correctly() {
        let storage = open_storage();
        let mut rng = OsRng;
        let alice_sk = SigningKey::generate(&mut rng);
        let alice_device = SigningKey::generate(&mut rng);
        let bob_sk = SigningKey::generate(&mut rng);
        let bob_device = SigningKey::generate(&mut rng);
        let charlie = SigningKey::generate(&mut rng).verifying_key();
        let dave = SigningKey::generate(&mut rng).verifying_key();

        // Three ops in mixed order:
        // - Alice → Charlie at t=200
        // - Alice → Dave at t=100
        // - Bob → Charlie at t=150
        let op_alice_charlie = make_attest_op(&alice_sk, &alice_device, charlie, 200);
        let op_alice_dave = make_attest_op(&alice_sk, &alice_device, dave, 100);
        let op_bob_charlie = make_attest_op(&bob_sk, &bob_device, charlie, 150);

        store_signed_op(&storage, &op_alice_charlie).unwrap();
        store_signed_op(&storage, &op_alice_dave).unwrap();
        store_signed_op(&storage, &op_bob_charlie).unwrap();

        // Filter on (Alice, Charlie): should yield one op.
        let chain = load_chain_for_pair(&storage, &alice_sk.verifying_key(), &charlie).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].op().timestamp, 200);

        // Filter on (Alice, Dave): should yield one op.
        let chain = load_chain_for_pair(&storage, &alice_sk.verifying_key(), &dave).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].op().timestamp, 100);

        // Filter on (Bob, Charlie): should yield one op.
        let chain = load_chain_for_pair(&storage, &bob_sk.verifying_key(), &charlie).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].op().timestamp, 150);

        // Filter on a non-existent pair: empty.
        let chain = load_chain_for_pair(&storage, &alice_sk.verifying_key(), &charlie)
            .and_then(|_| load_chain_for_pair(&storage, &bob_sk.verifying_key(), &dave))
            .unwrap();
        assert!(chain.is_empty());
    }

    #[test]
    fn load_chain_for_pair_returns_chronological_order() {
        let storage = open_storage();
        let mut rng = OsRng;
        let alice_sk = SigningKey::generate(&mut rng);
        let alice_device = SigningKey::generate(&mut rng);
        let peer = SigningKey::generate(&mut rng).verifying_key();

        // Store in reverse-chronological order.
        let op_a = make_attest_op(&alice_sk, &alice_device, peer, 300);
        let op_b = make_attest_op(&alice_sk, &alice_device, peer, 100);
        let op_c = make_attest_op(&alice_sk, &alice_device, peer, 200);

        store_signed_op(&storage, &op_a).unwrap();
        store_signed_op(&storage, &op_b).unwrap();
        store_signed_op(&storage, &op_c).unwrap();

        let chain = load_chain_for_pair(&storage, &alice_sk.verifying_key(), &peer).unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].op().timestamp, 100);
        assert_eq!(chain[1].op().timestamp, 200);
        assert_eq!(chain[2].op().timestamp, 300);
    }

    #[test]
    fn load_all_ops_chronological_orders_across_pairs() {
        let storage = open_storage();
        let mut rng = OsRng;
        let alice_sk = SigningKey::generate(&mut rng);
        let alice_device = SigningKey::generate(&mut rng);
        let bob_sk = SigningKey::generate(&mut rng);
        let bob_device = SigningKey::generate(&mut rng);
        let peer = SigningKey::generate(&mut rng).verifying_key();

        let op_alice_t200 = make_attest_op(&alice_sk, &alice_device, peer, 200);
        let op_bob_t100 = make_attest_op(&bob_sk, &bob_device, peer, 100);
        let op_alice_t150 = make_attest_op(&alice_sk, &alice_device, peer, 150);

        store_signed_op(&storage, &op_alice_t200).unwrap();
        store_signed_op(&storage, &op_bob_t100).unwrap();
        store_signed_op(&storage, &op_alice_t150).unwrap();

        let all = load_all_ops_chronological(&storage).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].op().timestamp, 100);
        assert_eq!(all[1].op().timestamp, 150);
        assert_eq!(all[2].op().timestamp, 200);
    }

    #[test]
    fn loaded_op_verifies_against_original_token() {
        // End-to-end: persist an op, load it, verify the loaded
        // envelope against a capability token. The store-layer
        // preserves byte equivalence so verify_chain succeeds.
        let storage = open_storage();
        let (op_identity_sk, device_sk, token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let mut rng = OsRng;
        let peer = SigningKey::generate(&mut rng).verifying_key();
        let op = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer,
            1_700_000_000,
            vec![],
            vec![],
            crate::Strength::InPerson,
        );
        let signed = SignedTrustGraphOp::sign(op, &device_sk).unwrap();

        let id = store_signed_op(&storage, &signed).unwrap();
        let loaded = load_signed_op(&storage, &id).unwrap();

        let verified = loaded
            .verify_chain(&token_bytes, &op_identity_sk.verifying_key())
            .unwrap();
        assert_eq!(verified.op_type, OpType::Attest);
    }

    #[test]
    fn delete_op_removes_record() {
        let storage = open_storage();
        let mut rng = OsRng;
        let op_identity_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);
        let peer = SigningKey::generate(&mut rng).verifying_key();
        let op = make_attest_op(&op_identity_sk, &device_sk, peer, 1_700_000_000);

        let id = store_signed_op(&storage, &op).unwrap();
        assert!(delete_op(&storage, &id).unwrap());
        // Subsequent load returns RecordNotFound.
        assert!(matches!(
            load_signed_op(&storage, &id),
            Err(StoreError::Storage(StorageError::RecordNotFound { .. }))
        ));
        // Second delete returns false (already gone).
        assert!(!delete_op(&storage, &id).unwrap());
    }

    #[test]
    fn initialize_schema_sets_version() {
        let storage = open_storage();
        assert_eq!(
            storage
                .category_schema_version(categories::TRUST_GRAPH)
                .unwrap(),
            0
        );
        initialize_schema(&storage).unwrap();
        assert_eq!(
            storage
                .category_schema_version(categories::TRUST_GRAPH)
                .unwrap(),
            TRUST_GRAPH_SCHEMA_VERSION
        );
        // Idempotent.
        initialize_schema(&storage).unwrap();
        assert_eq!(
            storage
                .category_schema_version(categories::TRUST_GRAPH)
                .unwrap(),
            TRUST_GRAPH_SCHEMA_VERSION
        );
    }
}
