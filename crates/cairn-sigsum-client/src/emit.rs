// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Combined persist + Sigsum-emit wrapper per D0023 §6.1.
//!
//! ## Module location vs. D0023 §6.1's prose
//!
//! D0023 §6.1 nominates `cairn-trust-graph::sigsum_emit` as the
//! module name. This v1 implementation hosts the wrapper in
//! `cairn-sigsum-client::emit` instead because the literal placement
//! would create a dependency cycle: this crate already depends on
//! `cairn-trust-graph` (for [`SignedTrustGraphOp`] in
//! [`crate::leaf::leaf_hash_for`]), so the reverse edge cannot land
//! without breaking the workspace DAG. The architectural intent of
//! D0023 §6.1 — a single call that persists locally AND emits to
//! Sigsum — is preserved unchanged.
//!
//! ## Best-effort emission discipline (D0023 §6.1)
//!
//! Persistence is fatal-error: if the trust-graph store fails, the
//! wrapper returns an error and the op is NOT logged. Sigsum
//! emission is best-effort: if persistence succeeds but emission
//! fails, the wrapper returns `Ok(EmitOutcome { emission_status:
//! Deferred, .. })` so the caller knows to retry the emission on a
//! subsequent sweep (typically at app start).
//!
//! ## v1 skeleton status
//!
//! The wrapper composes against the v1 skeleton's stubbed
//! [`crate::client::SigsumClient::emit_leaf`] which returns
//! [`SigsumError::NetworkUnreached`] unconditionally. Every wrapper
//! invocation in v1 therefore returns [`EmissionStatus::Deferred`].
//! Once the network surface lands (a follow-up commit gated on
//! integration testing per D0023 §10), successful emissions return
//! [`EmissionStatus::Logged`].

use cairn_storage::Storage;
use cairn_trust_graph::{
    STORE_RECORD_ID_LEN, SignedTrustGraphOp, StoreError as TrustGraphStoreError, store_signed_op,
};

use crate::client::SigsumClient;
use crate::error::SigsumError;
use crate::leaf::{LeafHash, leaf_hash_for};

/// Outcome of a combined persist + Sigsum-emit invocation per
/// D0023 §6.1.
///
/// `record_id` and `leaf_hash` are populated for every returned
/// outcome (the only `Ok` path is one where persistence succeeded).
/// `emission_status` separately tracks the Sigsum-side outcome so
/// callers can distinguish "logged" from "deferred for retry sweep".
#[derive(Debug, Clone)]
pub struct EmitOutcome {
    /// Record id under which the op was persisted in the trust-graph
    /// store per D0022 + cairn-trust-graph::store.
    pub record_id: [u8; STORE_RECORD_ID_LEN],
    /// Leaf hash computed for the op per D0023 §1. Byte-identical to
    /// D0006 §5's `prior_hash` byte input.
    pub leaf_hash: LeafHash,
    /// Whether the Sigsum emission half completed or was deferred.
    pub emission_status: EmissionStatus,
}

/// Outcome of the Sigsum-emission half of [`sigsum_emit`].
///
/// In the v1 skeleton, [`EmissionStatus::Logged`] is unreachable
/// because [`crate::client::SigsumClient::emit_leaf`] is stubbed to
/// return [`SigsumError::NetworkUnreached`]. Once the network
/// surface lands, [`EmissionStatus::Logged`] becomes the success
/// path and [`EmissionStatus::Deferred`] is reserved for transient
/// post-retry-budget failures the caller should sweep later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmissionStatus {
    /// Successfully emitted to the configured log and cached in
    /// [`cairn_storage::categories::SIGSUM_CACHE`].
    Logged,
    /// Sigsum emission deferred per §6.1's best-effort discipline.
    /// The caller (typically an app-start sweep) retries
    /// [`sigsum_emit`] for the same op later; deduplication is
    /// idempotent on `record_id`.
    Deferred,
}

/// Persist a signed trust-graph op AND emit a leaf to the configured
/// Sigsum log per D0023 §6.1.
///
/// Order of operations:
///
/// 1. **Persist** via [`store_signed_op`]. Fatal-error fall-through:
///    a failure here returns [`SigsumError::Storage`] or
///    [`SigsumError::Encode`] and the op is NOT logged.
/// 2. **Compute** the leaf hash via [`leaf_hash_for`] (pure SHA-256;
///    no I/O). Fatal-error: an envelope-encode failure here is
///    unreachable for envelopes constructed via the public API but
///    surfaces as [`SigsumError::Encode`] if it occurs.
/// 3. **Emit** via [`crate::client::SigsumClient::emit_leaf`].
///    Best-effort per §6.1: failure here is NOT fatal — the op stays
///    persisted; the returned [`EmissionStatus::Deferred`] signals
///    the caller to retry the emission half on a later sweep.
///
/// # Errors
///
/// - [`SigsumError::Storage`] if the trust-graph persistence step
///   fails (fatal — the op was not stored)
/// - [`SigsumError::Encode`] for the leaf-hash precompute or
///   trust-graph encode path (unreachable for envelopes built via
///   the public API)
pub async fn sigsum_emit(
    storage: &Storage,
    client: &SigsumClient,
    op: &SignedTrustGraphOp,
) -> Result<EmitOutcome, SigsumError> {
    // Step 1: persist. Fatal-error fall-through; the persistence half
    // is the source of truth per §6.1.
    let record_id = store_signed_op(storage, op).map_err(map_store_error)?;

    // Step 2: compute the leaf hash. Pure SHA-256; no I/O.
    let leaf_hash = leaf_hash_for(op)?;

    // Step 3: best-effort Sigsum emission per §6.1. v1 skeleton
    // returns Deferred unconditionally because emit_leaf is stubbed
    // to NetworkUnreached. Once the network surface lands, the Ok
    // arm is the cache-write + Logged path.
    let emission_status = match client.emit_leaf(op).await {
        Ok(_) => EmissionStatus::Logged,
        Err(_) => EmissionStatus::Deferred,
    };

    Ok(EmitOutcome {
        record_id,
        leaf_hash,
        emission_status,
    })
}

/// Map a [`TrustGraphStoreError`] into the local [`SigsumError`]
/// surface.
///
/// The trust-graph store-layer surfaces three documented variants:
///
/// - `Storage(StorageError)` — maps to [`SigsumError::Storage`]
/// - `Encode(TrustGraphError)` — maps to [`SigsumError::Encode`]
/// - `Decode(TrustGraphError)` — maps to [`SigsumError::Encode`]
///   (unreachable from `store_signed_op`, which never deserializes,
///   but listed here so the match arm is documented if the surface
///   evolves to also surface decode failures from this entry point)
///
/// `StoreError` is `#[non_exhaustive]` per D0018 §4.2. The wildcard
/// arm maps any future variant to
/// [`SigsumError::TrustGraphStoreUnknown`] — a typed sentinel that
/// surfaces the gap rather than silently coercing into one of the
/// existing variants.
fn map_store_error(err: TrustGraphStoreError) -> SigsumError {
    match err {
        TrustGraphStoreError::Storage(se) => SigsumError::Storage(se),
        TrustGraphStoreError::Decode(e) | TrustGraphStoreError::Encode(e) => SigsumError::Encode(e),
        _ => SigsumError::TrustGraphStoreUnknown,
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::client::{SigsumClient, SigsumClientConfig};
    use crate::witness::parse_witness_pool;
    use cairn_crypto::ed25519::SigningKey;
    use cairn_storage::key_provider::testing::InMemoryKeyProvider;
    use cairn_storage::{Storage, categories};
    use cairn_trust_graph::{TrustGraphOp, load_signed_op, record_id_for};
    use rand_core::OsRng;
    use std::sync::Arc;
    use url::Url;
    use zeroize::Zeroizing;

    fn make_witness_pool_toml(count: usize) -> String {
        let mut rng = OsRng;
        let mut out = String::new();
        for i in 0..count {
            let sk = SigningKey::generate(&mut rng);
            let pubkey_hex =
                sk.verifying_key()
                    .to_bytes()
                    .iter()
                    .fold(String::new(), |mut acc, b| {
                        use core::fmt::Write as _;
                        let _ = write!(&mut acc, "{b:02x}");
                        acc
                    });
            out.push_str(&format!(
                "[[witness]]\nname = \"W{i}\"\npubkey_hex = \"{pubkey_hex}\"\nurl = \"https://w-{i}.example.org\"\n\n"
            ));
        }
        out
    }

    fn open_storage() -> Arc<Storage> {
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"test passphrase".to_vec());
        Arc::new(Storage::open_in_memory(&provider, &passphrase).unwrap())
    }

    fn make_client(storage: Arc<Storage>) -> SigsumClient {
        let toml = make_witness_pool_toml(3);
        let pool = parse_witness_pool(&toml).unwrap();
        let log_pubkey = SigningKey::generate(&mut OsRng).verifying_key();
        let config = SigsumClientConfig {
            log_url: Url::parse("https://log.example.org").unwrap(),
            log_pubkey,
            witness_pool: pool,
            default_retry_budget: crate::RetryBudget::default(),
        };
        SigsumClient::new(config, storage).unwrap()
    }

    fn make_signed_op(rng: &mut OsRng, timestamp: u64) -> SignedTrustGraphOp {
        let op_identity_sk = SigningKey::generate(rng);
        let device_sk = SigningKey::generate(rng);
        let peer = SigningKey::generate(rng).verifying_key();
        let op = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer,
            timestamp,
            vec![],
            vec![],
        );
        SignedTrustGraphOp::sign(op, &device_sk).unwrap()
    }

    #[tokio::test]
    async fn sigsum_emit_persists_op_in_v1_skeleton() {
        // Per §6.1: persistence is the source of truth, emission is
        // best-effort. v1 skeleton's emit_leaf returns NetworkUnreached
        // so we expect EmissionStatus::Deferred AND a populated
        // record_id pointing at a real row in the trust-graph
        // category.
        let storage = open_storage();
        let client = make_client(Arc::clone(&storage));
        let mut rng = OsRng;
        let signed_op = make_signed_op(&mut rng, 1_700_000_000);

        let outcome = sigsum_emit(&storage, &client, &signed_op).await.unwrap();

        // Persistence half succeeded.
        let loaded = load_signed_op(&storage, &outcome.record_id).unwrap();
        assert_eq!(loaded.op(), signed_op.op());

        // Emission half deferred in the v1 skeleton.
        assert_eq!(outcome.emission_status, EmissionStatus::Deferred);
    }

    #[tokio::test]
    async fn sigsum_emit_returns_record_id_matching_store_layer() {
        // The wrapper's record_id MUST match cairn-trust-graph's
        // own record_id_for(op) so a v1.5 sweep can dedupe across
        // both code paths.
        let storage = open_storage();
        let client = make_client(Arc::clone(&storage));
        let mut rng = OsRng;
        let signed_op = make_signed_op(&mut rng, 1_700_000_000);

        let outcome = sigsum_emit(&storage, &client, &signed_op).await.unwrap();
        let direct_id = record_id_for(&signed_op).unwrap();
        assert_eq!(outcome.record_id, direct_id);
    }

    #[tokio::test]
    async fn sigsum_emit_leaf_hash_matches_d0006_prior_hash_byte_input() {
        // The wrapper's leaf_hash MUST be byte-identical to
        // D0006 §5's prior_hash byte input per D0023 §1. This pins
        // the cross-D-doc invariant at the integration boundary.
        let storage = open_storage();
        let client = make_client(Arc::clone(&storage));
        let mut rng = OsRng;
        let signed_op = make_signed_op(&mut rng, 1_700_000_000);

        let outcome = sigsum_emit(&storage, &client, &signed_op).await.unwrap();
        assert_eq!(outcome.leaf_hash.as_bytes(), &signed_op.prior_hash_bytes());
    }

    #[tokio::test]
    async fn sigsum_emit_is_idempotent_across_retries() {
        // §6.1: "A subsequent call to emit_leaf (e.g., on app start
        // sweep) catches up missed emissions." Idempotence is the
        // property that makes the sweep safe — the same op twice
        // produces the same record_id + leaf_hash, and the storage
        // row count stays at 1.
        let storage = open_storage();
        let client = make_client(Arc::clone(&storage));
        let mut rng = OsRng;
        let signed_op = make_signed_op(&mut rng, 1_700_000_000);

        let first = sigsum_emit(&storage, &client, &signed_op).await.unwrap();
        let second = sigsum_emit(&storage, &client, &signed_op).await.unwrap();

        assert_eq!(first.record_id, second.record_id);
        assert_eq!(first.leaf_hash, second.leaf_hash);
        assert_eq!(
            storage.count_records(categories::TRUST_GRAPH).unwrap(),
            1,
            "double emit should not duplicate trust-graph rows"
        );
    }

    #[tokio::test]
    async fn distinct_ops_produce_distinct_record_ids() {
        let storage = open_storage();
        let client = make_client(Arc::clone(&storage));
        let mut rng = OsRng;
        let op_a = make_signed_op(&mut rng, 1_700_000_000);
        let op_b = make_signed_op(&mut rng, 1_700_000_001);

        let outcome_a = sigsum_emit(&storage, &client, &op_a).await.unwrap();
        let outcome_b = sigsum_emit(&storage, &client, &op_b).await.unwrap();

        assert_ne!(outcome_a.record_id, outcome_b.record_id);
        assert_ne!(outcome_a.leaf_hash, outcome_b.leaf_hash);
        assert_eq!(
            storage.count_records(categories::TRUST_GRAPH).unwrap(),
            2,
            "distinct ops should produce distinct rows"
        );
    }

    #[tokio::test]
    async fn sigsum_emit_persists_even_when_emit_leaf_fails() {
        // §6.1's "errors at step 2 do NOT roll back step 1" property.
        // In v1 skeleton, emit_leaf always errors; we verify the row
        // is still there + readable.
        let storage = open_storage();
        let client = make_client(Arc::clone(&storage));
        let mut rng = OsRng;
        let signed_op = make_signed_op(&mut rng, 1_700_000_000);

        let outcome = sigsum_emit(&storage, &client, &signed_op).await.unwrap();
        assert_eq!(outcome.emission_status, EmissionStatus::Deferred);

        // The trust-graph row must exist after the call even though
        // emission deferred.
        let loaded = load_signed_op(&storage, &outcome.record_id).unwrap();
        assert_eq!(
            loaded.encode(false).unwrap(),
            signed_op.encode(false).unwrap()
        );
    }
}
