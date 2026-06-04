// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Async `SigsumClient` surface per D0023 §5.
//!
//! ## Implementation status
//!
//! [`SigsumClient::refresh_tree_head`] is **implemented**: it performs
//! the real `GET /get-tree-head`, parses the Sigsum v1 ASCII response,
//! verifies the log's tree-head signature against the pinned log key,
//! verifies the embedded C2SP `tlog-cosignature/v1` cosignatures
//! against the configured witness pool (2-of-3 threshold per
//! D0023 §3.4), runs split-view detection against the cached head, and
//! caches the accepted head. It is validated end-to-end by the
//! hermetic wiremock harness in `tests/refresh_tree_head_wiremock.rs`.
//!
//! [`SigsumClient::emit_leaf`] is **implemented**: it builds the Sigsum
//! `tree_leaf` (D0023 §1 revised + Sigsum spec §2.2.4), POSTs it to
//! `add-leaf` (retrying `202` until `200`), and caches an
//! [`crate::cache::EmittedLeaf`] record so `verify_inclusion` can later
//! reconstruct the Merkle leaf hash. Validated by the hermetic wiremock
//! harness in `tests/emit_leaf_wiremock.rs`.
//!
//! [`SigsumClient::verify_inclusion`] is **implemented**: it loads the
//! emit-time [`crate::cache::EmittedLeaf`] to recompute the Sigsum
//! Merkle leaf hash, fetches a fresh accepted head, fetches
//! `get-inclusion-proof`, verifies the RFC 6962 inclusion against the
//! head's root, and caches the [`crate::cache::InclusionProof`].
//! Validated by the hermetic wiremock harness in
//! `tests/verify_inclusion_wiremock.rs`.
//!
//! All three network surfaces (`emit_leaf`, `refresh_tree_head`,
//! `verify_inclusion`) are now implemented; no `NetworkUnreached` stub
//! remains in this crate.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cairn_crypto::ed25519::{Signature, SigningKey, VerifyingKey};
use cairn_storage::{Storage, categories};
use cairn_trust_graph::SignedTrustGraphOp;
use sha2::{Digest, Sha256};
use url::Url;

use crate::cache::{
    Cosignature, EmittedLeaf, InclusionProof, TreeHead, cache_record_id_for_inclusion_proof,
    cache_record_id_for_leaf, cache_record_id_for_log,
};
use crate::error::SigsumError;
use crate::leaf::LeafHash;
use crate::witness::{
    REQUIRED_COSIGNATURE_COUNT, WitnessPool, build_cosignature_signed_message,
    build_tree_head_note, witness_key_hash,
};

/// Retry budget per D0023 §5.3.
///
/// Default: 5 retries with 250ms initial backoff capped at 60s. Caller-
/// scoped so a single-op-blocking flow (e.g., a user-visible verify)
/// can shrink the budget for snappier failure surfacing.
#[derive(Debug, Clone, Copy)]
pub struct RetryBudget {
    /// Maximum number of retry attempts before surfacing
    /// [`SigsumError::Network`].
    pub max_retries: u8,
    /// Initial backoff delay (doubled on each retry up to `max_delay`).
    pub initial_delay: Duration,
    /// Maximum backoff delay (cap on the exponential growth).
    pub max_delay: Duration,
}

impl Default for RetryBudget {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(60),
        }
    }
}

/// Configuration bundle for constructing a [`SigsumClient`].
///
/// Builder-pattern is intentional: `SigsumClient::new` takes one
/// `SigsumClientConfig` argument so callers can construct the config
/// in stages without a long positional argument list.
#[derive(Debug, Clone)]
pub struct SigsumClientConfig {
    /// HTTPS endpoint of the Sigsum log.
    pub log_url: Url,
    /// The log's Ed25519 public key, pinned per release. Required to
    /// verify the log's tree-head signature + to compute the log key
    /// hash (`SHA-256(pubkey)`) that forms the checkpoint origin line
    /// (`sigsum.org/v1/tree/<hex>`) per the Sigsum v1 log spec.
    pub log_pubkey: VerifyingKey,
    /// Witness pool parsed from the release's `witnesses.toml`.
    pub witness_pool: WitnessPool,
    /// Default retry budget for network operations.
    pub default_retry_budget: RetryBudget,
}

/// The async Sigsum integration handle per D0023 §5.
///
/// Wraps the `reqwest::Client`, the `cairn_storage::Storage` for
/// cache state, the configured witness pool, and the log URL. Each
/// async method routes through the cache + retry logic per D0023 §5.
pub struct SigsumClient {
    /// HTTPS client per D0023 §2. Used by the network surfaces
    /// (`get-tree-head`, `add-leaf`).
    http: reqwest::Client,
    /// Storage handle for cache state per D0023 §4 (tree-head + emitted
    /// leaf records).
    storage: Arc<Storage>,
    /// Configured witness pool per D0023 §3.
    witness_pool: WitnessPool,
    /// HTTPS endpoint of the Sigsum log.
    log_url: Url,
    /// The log's pinned Ed25519 public key per D0023 §3.
    log_pubkey: VerifyingKey,
    /// Default retry budget per D0023 §5.3.
    default_retry_budget: RetryBudget,
}

impl SigsumClient {
    /// Construct a new `SigsumClient` from its config bundle.
    ///
    /// The `reqwest::Client` is constructed with `rustls-tls` per
    /// D0023 §2.1; `default-features = false` strips native-tls,
    /// cookies, and compression at the workspace pin level.
    ///
    /// # Errors
    ///
    /// Returns [`SigsumError::Network`] if the reqwest client
    /// construction fails (extremely unusual — typically only on
    /// platform-specific TLS configuration issues).
    pub fn new(config: SigsumClientConfig, storage: Arc<Storage>) -> Result<Self, SigsumError> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|_| SigsumError::Network {
                retry_budget_used: 0,
            })?;
        Ok(Self {
            http,
            storage,
            witness_pool: config.witness_pool,
            log_url: config.log_url,
            log_pubkey: config.log_pubkey,
            default_retry_budget: config.default_retry_budget,
        })
    }

    /// Return the configured log URL.
    #[must_use]
    pub const fn log_url(&self) -> &Url {
        &self.log_url
    }

    /// Return the configured log public key.
    #[must_use]
    pub const fn log_pubkey(&self) -> &VerifyingKey {
        &self.log_pubkey
    }

    /// Return the configured witness pool.
    #[must_use]
    pub const fn witness_pool(&self) -> &WitnessPool {
        &self.witness_pool
    }

    /// Return the default retry budget.
    #[must_use]
    pub const fn default_retry_budget(&self) -> RetryBudget {
        self.default_retry_budget
    }

    /// Emit a leaf for `signed_op` to the configured Sigsum log per
    /// D0023 §5.
    ///
    /// Implemented per D0023 §5 + the Sigsum v1 `add-leaf` spec (§3.5).
    /// Flow:
    ///
    /// 1. Compute Cairn's leaf hash via [`crate::leaf::leaf_hash_for`]
    ///    (the 32-byte `message` submitted to the log).
    /// 2. Build the Sigsum [`crate::leaf::TreeLeaf`]
    ///    ([`crate::leaf::build_tree_leaf`]): `checksum = SHA-256(message)`,
    ///    the submitter's tree-leaf signature (signed by `submitter_sk`,
    ///    the operational identity per D0023 §3), and
    ///    `key_hash = SHA-256(submitter pubkey)`.
    /// 3. `POST {log_url}/add-leaf` with `message` / `signature` /
    ///    `public_key` hex fields, retrying `202 Accepted` (not yet
    ///    committed) until `200 OK` per the spec, within the retry
    ///    budget.
    /// 4. Cache an [`EmittedLeaf`] record so
    ///    [`SigsumClient::verify_inclusion`] can later reconstruct the
    ///    `tree_leaf` + its Merkle leaf hash without re-signing.
    ///
    /// `submitter_sk` is the operational-identity Ed25519 key that acts
    /// as the Sigsum submitter (D0023 §3). Returns Cairn's [`LeafHash`]
    /// (the submitted message).
    ///
    /// # Errors
    ///
    /// - [`SigsumError::Network`] — transport failed (or the log never
    ///   returned `200`) after the retry budget was exhausted.
    /// - [`SigsumError::Encode`] — trust-graph envelope encode failure
    ///   (unreachable for envelopes constructed via the public API).
    /// - [`SigsumError::LeafSignFailed`] — tree-leaf signing failed
    ///   (effectively unreachable for a valid key).
    /// - [`SigsumError::Storage`] — cache write failure.
    pub async fn emit_leaf(
        &self,
        signed_op: &SignedTrustGraphOp,
        submitter_sk: &SigningKey,
    ) -> Result<LeafHash, SigsumError> {
        self.emit_leaf_with_signer(
            signed_op,
            &crate::leaf::SoftwareTreeLeafSigner(submitter_sk),
        )
        .await
    }

    /// Emit `signed_op`'s leaf, signing the tree-leaf via a
    /// [`crate::leaf::TreeLeafSigner`] rather than a local `SigningKey`.
    ///
    /// Identical flow to [`Self::emit_leaf`] (build tree-leaf → POST
    /// `add-leaf` → cache the `EmittedLeaf`), but the submitter signature
    /// comes from the `signer` — so the operational key can sign in
    /// hardware (StrongBox per D0020 §3.4) without the raw key entering
    /// this crate. The FFI boundary (cairn-uniffi) uses this to bridge a
    /// `HardwareKeySigner` callback. `emit_leaf` is the software-key
    /// special case (it wraps a `SigningKey` in the same path).
    ///
    /// # Errors
    ///
    /// Same as [`Self::emit_leaf`], plus any [`SigsumError::LeafSignFailed`]
    /// the `signer` returns.
    pub async fn emit_leaf_with_signer(
        &self,
        signed_op: &SignedTrustGraphOp,
        signer: &dyn crate::leaf::TreeLeafSigner,
    ) -> Result<LeafHash, SigsumError> {
        let leaf_hash = crate::leaf::leaf_hash_for(signed_op)?;
        let tree_leaf = crate::leaf::build_tree_leaf_with_signer(leaf_hash.as_bytes(), signer)?;
        let submitter_pubkey = signer.submitter_public_key();

        self.http_post_add_leaf(
            leaf_hash.as_bytes(),
            &tree_leaf.signature,
            &submitter_pubkey,
        )
        .await?;

        let record = EmittedLeaf {
            message: *leaf_hash.as_bytes(),
            signature: tree_leaf.signature,
            key_hash: tree_leaf.key_hash,
            observed_at: now_unix(),
        };
        let record_id = cache_record_id_for_leaf(&self.log_url, &leaf_hash);
        self.storage.put(
            categories::SIGSUM_CACHE,
            &record_id,
            &record.to_canonical_cbor()?,
        )?;

        Ok(leaf_hash)
    }

    /// `POST {log_url}/add-leaf` with the Sigsum v1 ASCII body, retrying
    /// `202 Accepted` (received but not yet committed) until `200 OK`,
    /// and transient transport / 5xx failures, up to the retry budget.
    async fn http_post_add_leaf(
        &self,
        message: &[u8; 32],
        signature: &[u8; 64],
        public_key: &[u8; 32],
    ) -> Result<(), SigsumError> {
        let url = self
            .log_url
            .join("add-leaf")
            .map_err(|_| SigsumError::MalformedResponse)?;
        let body = format!(
            "message={}\nsignature={}\npublic_key={}\n",
            lower_hex(message),
            lower_hex(signature),
            lower_hex(public_key),
        );
        let budget = self.default_retry_budget;
        let mut delay = budget.initial_delay;
        let mut attempt: u8 = 0;
        loop {
            match self.http.post(url.clone()).body(body.clone()).send().await {
                // 200 OK = the log is committed to publishing the leaf.
                Ok(resp) if resp.status().as_u16() == 200 => return Ok(()),
                // Any other status (202 Accepted = received but not yet
                // committed, per the spec resend until 200; or 4xx/5xx)
                // and transport errors retry within the budget, then
                // surface Network so the caller defers.
                Ok(_) | Err(_) if attempt < budget.max_retries => {}
                Ok(_) | Err(_) => {
                    return Err(SigsumError::Network {
                        retry_budget_used: attempt,
                    });
                }
            }
            tokio::time::sleep(delay).await;
            delay = delay.saturating_mul(2).min(budget.max_delay);
            attempt = attempt.saturating_add(1);
        }
    }

    /// Verify that `signed_op` is included in the latest accepted log
    /// head per D0023 §5 + §6.2, against the real Sigsum v1
    /// `get-inclusion-proof` endpoint.
    ///
    /// Flow:
    /// 1. Compute Cairn's leaf hash (the submitted `message`).
    /// 2. Load the emit-time [`EmittedLeaf`] for this leaf from the
    ///    cache and reconstruct the Sigsum `tree_leaf` → its Merkle leaf
    ///    hash `H(0x00 ‖ tree_leaf)` (the value the log addresses). This
    ///    requires the leaf to have been emitted ([`Self::emit_leaf`])
    ///    or its `EmittedLeaf` transmitted + cached — a verifying
    ///    recipient cannot recompute the submitter's tree-leaf signature
    ///    (D0023 §1.4).
    /// 3. Fetch + verify a fresh accepted head via
    ///    [`Self::refresh_tree_head`] (cosigned + split-view-checked).
    /// 4. For a tree of size 1, check inclusion locally (`leaf_hash ==
    ///    root_hash` per the Sigsum spec §3.2); otherwise
    ///    `GET get-inclusion-proof/<size>/<merkle_leaf_hash>`, parse the
    ///    `leaf_index` + `node_hash` lines, and reconstruct the RFC 6962
    ///    root, which must equal the accepted head's root.
    /// 5. Cache the verified [`InclusionProof`] (under a key
    ///    domain-separated from the [`EmittedLeaf`] record) and return
    ///    it.
    ///
    /// # Errors
    ///
    /// - [`SigsumError::Storage`] — the `EmittedLeaf` is not cached (the
    ///   leaf was never emitted / its record was not transmitted), or a
    ///   cache read/write failed.
    /// - any error from [`Self::refresh_tree_head`] (network /
    ///   cosignature / split-view).
    /// - [`SigsumError::Network`] — the `get-inclusion-proof` fetch
    ///   failed (incl. 404 "not included") after the retry budget.
    /// - [`SigsumError::MalformedResponse`] — unparseable
    ///   `get-inclusion-proof` response.
    /// - [`SigsumError::InclusionProofVerifyFailed`] — the proof's
    ///   reconstructed root did not match the accepted head's root.
    pub async fn verify_inclusion(
        &self,
        signed_op: &SignedTrustGraphOp,
    ) -> Result<InclusionProof, SigsumError> {
        // (1) Cairn leaf hash (the submitted message).
        let leaf_hash = crate::leaf::leaf_hash_for(signed_op)?;

        // (2) Load the emit-time tree_leaf -> Sigsum Merkle leaf hash.
        let emitted_id = cache_record_id_for_leaf(&self.log_url, &leaf_hash);
        let emitted = self.load_emitted_leaf(&emitted_id)?;
        let merkle_leaf_hash = emitted.tree_leaf().merkle_leaf_hash();

        // (3) Fresh, cosigned, split-view-checked accepted head.
        let head = self.refresh_tree_head().await?;

        // (4) Verify inclusion against the accepted head.
        let (leaf_index, proof_nodes) = if head.tree_size == 0 {
            return Err(SigsumError::InclusionProofVerifyFailed);
        } else if head.tree_size == 1 {
            // Sigsum spec §3.2: in a size-1 tree a leaf is included iff
            // its hash equals the root hash; no proof is fetched.
            if merkle_leaf_hash != head.root_hash {
                return Err(SigsumError::InclusionProofVerifyFailed);
            }
            (0u64, Vec::new())
        } else {
            let body = self
                .http_get_inclusion_proof(head.tree_size, &merkle_leaf_hash)
                .await?;
            let (leaf_index, proof_nodes) = parse_get_inclusion_proof(&body)?;
            let computed = rfc6962_root_from_inclusion_proof(
                leaf_index,
                head.tree_size,
                &merkle_leaf_hash,
                &proof_nodes,
            )
            .ok_or(SigsumError::InclusionProofVerifyFailed)?;
            if computed != head.root_hash {
                return Err(SigsumError::InclusionProofVerifyFailed);
            }
            (leaf_index, proof_nodes)
        };

        // (5) Cache + return the verified inclusion proof. The proof is
        // cached under a key domain-separated from the EmittedLeaf
        // record so the two per-leaf records do not collide.
        let proof = InclusionProof {
            leaf_hash,
            tree_size: head.tree_size,
            proof_nodes,
            leaf_index,
            observed_at: now_unix(),
        };
        let proof_id = cache_record_id_for_inclusion_proof(&self.log_url, &leaf_hash);
        self.storage.put(
            categories::SIGSUM_CACHE,
            &proof_id,
            &proof.to_canonical_cbor()?,
        )?;
        Ok(proof)
    }

    /// Load + decode the cached [`EmittedLeaf`] for this leaf. A cache
    /// miss surfaces as [`SigsumError::Storage`].
    fn load_emitted_leaf(&self, record_id: &[u8]) -> Result<EmittedLeaf, SigsumError> {
        let bytes = self.storage.get(categories::SIGSUM_CACHE, record_id)?;
        EmittedLeaf::from_canonical_cbor(&bytes)
    }

    /// Verify a *bundled* Sigsum inclusion proof **offline** — no
    /// network, no cache — against this client's pinned log key + witness
    /// pool.
    ///
    /// This is the third-party-proof counterpart to
    /// [`Self::verify_inclusion`]. Where `verify_inclusion` serves the
    /// self-emit-then-verify flow (the same node emitted the leaf, so its
    /// [`EmittedLeaf`] is in the local cache and a fresh head is fetched
    /// from the network), `verify_bundled_inclusion` serves the
    /// air-gapped flow (D0024 §6.4): the party that emitted the leaf
    /// (e.g. the release signer) transmits the proof material, and a
    /// recipient who never emitted the leaf verifies it without any I/O.
    /// It is the Sigsum analogue of
    /// `cairn_sigstore_verify::verify_rekor_inclusion`.
    ///
    /// Inputs (all transmitted alongside the artifact):
    /// - `expected_leaf_hash` — the leaf hash the caller independently
    ///   recomputed from the artifact (e.g. the release manifest's
    ///   `release_leaf_hash` per D0024 §5.1). Binds the bundled proof to
    ///   the artifact under verification.
    /// - `emitted` — the emit-time [`EmittedLeaf`] (the submitter's
    ///   tree-leaf signature + `key_hash`); a recipient cannot recompute
    ///   the submitter signature (D0023 §1.4), so it must be transmitted.
    /// - `tree_head_body` — the raw `get-tree-head` ASCII the proof was
    ///   captured against (cosigned accepted head).
    /// - `inclusion_proof_body` — the raw `get-inclusion-proof` ASCII
    ///   (`leaf_index` + `node_hash` lines); ignored for a size-1 tree.
    ///
    /// Returns the verified accepted [`TreeHead`] on success.
    ///
    /// # Errors
    ///
    /// - [`SigsumError::InclusionProofVerifyFailed`] — the `emitted` leaf
    ///   does not match `expected_leaf_hash` (binding failure), the tree
    ///   is empty, the size-1 local check fails, or the reconstructed
    ///   RFC 6962 root does not equal the accepted head's root.
    /// - [`SigsumError::MalformedResponse`] — unparseable head/proof body,
    ///   or the log tree-head signature did not verify.
    /// - [`SigsumError::InsufficientWitnessCosignatures`] — fewer than the
    ///   threshold of configured witnesses cosigned the head.
    pub fn verify_bundled_inclusion(
        &self,
        expected_leaf_hash: &LeafHash,
        emitted: &EmittedLeaf,
        tree_head_body: &str,
        inclusion_proof_body: &str,
    ) -> Result<TreeHead, SigsumError> {
        // (1) Bind the transmitted leaf to the artifact under
        // verification. Without this, a valid proof for an unrelated leaf
        // could be bundled against this artifact.
        if &emitted.message != expected_leaf_hash.as_bytes() {
            return Err(SigsumError::InclusionProofVerifyFailed);
        }

        // (2) Verify the cosigned accepted head offline (log signature +
        // 2-of-3 cosignature threshold), exactly as the online path does.
        let parsed = parse_get_tree_head(tree_head_body)?;
        let head = self.verify_parsed_tree_head(&parsed)?;

        // (3) Reconstruct the Sigsum Merkle leaf hash from the transmitted
        // tree-leaf components.
        let merkle_leaf_hash = emitted.tree_leaf().merkle_leaf_hash();

        // (4) Verify inclusion against the accepted head's root.
        if head.tree_size == 0 {
            return Err(SigsumError::InclusionProofVerifyFailed);
        } else if head.tree_size == 1 {
            // Sigsum spec §3.2: in a size-1 tree a leaf is included iff its
            // hash equals the root hash; no proof body is consulted.
            if merkle_leaf_hash != head.root_hash {
                return Err(SigsumError::InclusionProofVerifyFailed);
            }
        } else {
            let (leaf_index, proof_nodes) = parse_get_inclusion_proof(inclusion_proof_body)?;
            let computed = rfc6962_root_from_inclusion_proof(
                leaf_index,
                head.tree_size,
                &merkle_leaf_hash,
                &proof_nodes,
            )
            .ok_or(SigsumError::InclusionProofVerifyFailed)?;
            if computed != head.root_hash {
                return Err(SigsumError::InclusionProofVerifyFailed);
            }
        }

        Ok(head)
    }

    /// `GET {log_url}/get-inclusion-proof/{size}/{hex(merkle_leaf_hash)}`,
    /// retrying transient transport / 5xx failures up to the retry
    /// budget. A 404 ("not included") surfaces as the terminal
    /// [`SigsumError::Network`] after the budget.
    async fn http_get_inclusion_proof(
        &self,
        size: u64,
        merkle_leaf_hash: &[u8; 32],
    ) -> Result<String, SigsumError> {
        let path = format!("get-inclusion-proof/{size}/{}", lower_hex(merkle_leaf_hash));
        let url = self
            .log_url
            .join(&path)
            .map_err(|_| SigsumError::MalformedResponse)?;
        let budget = self.default_retry_budget;
        let mut delay = budget.initial_delay;
        let mut attempt: u8 = 0;
        loop {
            match self.http.get(url.clone()).send().await {
                Ok(resp) => match resp.error_for_status() {
                    Ok(ok) => {
                        return ok.text().await.map_err(|_| SigsumError::MalformedResponse);
                    }
                    Err(_) if attempt < budget.max_retries => {}
                    Err(_) => {
                        return Err(SigsumError::Network {
                            retry_budget_used: attempt,
                        });
                    }
                },
                Err(_) if attempt < budget.max_retries => {}
                Err(_) => {
                    return Err(SigsumError::Network {
                        retry_budget_used: attempt,
                    });
                }
            }
            tokio::time::sleep(delay).await;
            delay = delay.saturating_mul(2).min(budget.max_delay);
            attempt = attempt.saturating_add(1);
        }
    }

    /// Refresh the latest accepted tree head per D0023 §4.1 +
    /// §5.
    ///
    /// Fetch + verify the latest accepted tree head per D0023 §4.1 +
    /// §5, against the real Sigsum v1 `get-tree-head` endpoint +
    /// C2SP `tlog-cosignature/v1` cosignature format.
    ///
    /// Flow:
    /// 1. `GET {log_url}/get-tree-head` (retried per the default
    ///    retry budget on transient transport errors).
    /// 2. Parse the ASCII response (`size=` / `root_hash=`hex /
    ///    `signature=`hex / repeated `cosignature=<keyhash> <ts>
    ///    <sig>`).
    /// 3. Verify the log's tree-head signature over the checkpoint
    ///    note via the pinned log pubkey.
    /// 4. Verify each cosignature: match its 4-byte key id to a
    ///    configured witness, rebuild the C2SP signed message with the
    ///    cosignature's timestamp, Ed25519-verify. Require at least
    ///    [`REQUIRED_COSIGNATURE_COUNT`] valid per D0023 §3.4.
    /// 5. Split-view check against the cached head (tree-size
    ///    regression / same-size-different-root → halt).
    /// 6. Cache the accepted head in
    ///    [`cairn_storage::categories::SIGSUM_CACHE`].
    ///
    /// # Errors
    ///
    /// - [`SigsumError::Network`] — transport failed after the retry
    ///   budget was exhausted.
    /// - [`SigsumError::MalformedResponse`] — unparseable response, or
    ///   the log tree-head signature did not verify against the pinned
    ///   log key.
    /// - [`SigsumError::InsufficientWitnessCosignatures`] — fewer than
    ///   the threshold of configured witnesses cosigned.
    /// - [`SigsumError::LogTreeSizeRegression`] /
    ///   [`SigsumError::LogSplitView`] — split-view indicators; halt.
    /// - [`SigsumError::Storage`] — cache read/write failure.
    pub async fn refresh_tree_head(&self) -> Result<TreeHead, SigsumError> {
        let body = self.http_get_tree_head().await?;
        let parsed = parse_get_tree_head(&body)?;

        // Verify the log tree-head signature + 2-of-3 cosignature
        // threshold (shared with the offline bundled path).
        let head = self.verify_parsed_tree_head(&parsed)?;

        // Split-view detection against any cached head.
        let record_id = cache_record_id_for_log(&self.log_url);
        if let Some(cached) = self.load_cached_head(&record_id)? {
            if head.tree_size < cached.tree_size {
                return Err(SigsumError::LogTreeSizeRegression {
                    cached_tree_size: cached.tree_size,
                    fetched_tree_size: head.tree_size,
                });
            }
            if head.tree_size == cached.tree_size && head.root_hash != cached.root_hash {
                return Err(SigsumError::LogSplitView {
                    tree_size: head.tree_size,
                });
            }
        }

        // Cache the accepted head.
        let encoded = head.to_canonical_cbor()?;
        self.storage
            .put(categories::SIGSUM_CACHE, &record_id, &encoded)?;
        Ok(head)
    }

    /// Verify a parsed `get-tree-head` against the pinned log key + the
    /// configured witness pool, and assemble the accepted [`TreeHead`].
    ///
    /// Performs the log tree-head signature verification (over the C2SP
    /// checkpoint note) + the 2-of-3 witness-cosignature threshold per
    /// D0023 §3.4. Does NOT touch the network, the cache, or split-view
    /// state — those are [`Self::refresh_tree_head`]'s concern. Shared
    /// by `refresh_tree_head` and the offline
    /// [`Self::verify_bundled_inclusion`].
    fn verify_parsed_tree_head(&self, parsed: &ParsedTreeHead) -> Result<TreeHead, SigsumError> {
        let log_key_hash = sha256_of(&self.log_pubkey.to_bytes());
        let note = build_tree_head_note(&log_key_hash, parsed.tree_size, &parsed.root_hash);
        let log_sig = Signature::from_bytes(parsed.log_signature);
        self.log_pubkey
            .verify(&note, &log_sig)
            .map_err(|_| SigsumError::MalformedResponse)?;

        let accepted = self.verify_cosignatures(&note, &parsed.cosignatures);
        let valid = u8::try_from(accepted.len()).unwrap_or(u8::MAX);
        if valid < REQUIRED_COSIGNATURE_COUNT {
            return Err(SigsumError::InsufficientWitnessCosignatures {
                valid,
                required: REQUIRED_COSIGNATURE_COUNT,
                pool_size: self.witness_pool.len(),
            });
        }

        // `timestamp` records the freshest cosignature time; `observed_at`
        // is wall-clock now.
        let freshest = accepted.iter().map(|c| c.timestamp).max().unwrap_or(0);
        Ok(TreeHead {
            tree_size: parsed.tree_size,
            root_hash: parsed.root_hash,
            timestamp: freshest,
            cosignatures: accepted,
            observed_at: now_unix(),
        })
    }

    /// `GET {log_url}/get-tree-head`, retrying transient transport
    /// failures up to the default retry budget.
    async fn http_get_tree_head(&self) -> Result<String, SigsumError> {
        let url = self
            .log_url
            .join("get-tree-head")
            .map_err(|_| SigsumError::MalformedResponse)?;
        let budget = self.default_retry_budget;
        let mut delay = budget.initial_delay;
        let mut attempt: u8 = 0;
        loop {
            match self.http.get(url.clone()).send().await {
                Ok(resp) => match resp.error_for_status() {
                    Ok(ok) => {
                        return ok.text().await.map_err(|_| SigsumError::MalformedResponse);
                    }
                    Err(_) if attempt < budget.max_retries => {}
                    Err(_) => {
                        return Err(SigsumError::Network {
                            retry_budget_used: attempt,
                        });
                    }
                },
                Err(_) if attempt < budget.max_retries => {}
                Err(_) => {
                    return Err(SigsumError::Network {
                        retry_budget_used: attempt,
                    });
                }
            }
            tokio::time::sleep(delay).await;
            delay = delay.saturating_mul(2).min(budget.max_delay);
            attempt = attempt.saturating_add(1);
        }
    }

    /// Verify each parsed cosignature against the configured witness
    /// pool, returning the accepted [`Cosignature`]s (one per witness
    /// whose key id matched + whose Ed25519 cosignature verified over
    /// the C2SP signed message built with that cosignature's
    /// timestamp).
    fn verify_cosignatures(&self, note: &[u8], parsed: &[ParsedCosignature]) -> Vec<Cosignature> {
        // No `Result`: this routine filters to the cosignatures that
        // verified. A cosignature that fails to verify (or comes from a
        // key not in our pool) is simply not counted — it is NOT a fatal
        // error. The acceptance threshold check downstream in
        // `refresh_tree_head` owns the accept/reject decision per
        // D0023 §3.4.
        let witnesses = self.witness_pool.witnesses();
        let mut accepted = Vec::new();
        for pc in parsed {
            // Find the configured witness whose 4-byte C2SP key id
            // matches this cosignature. A cosignature whose key id maps
            // to no configured witness is skipped.
            let Some((idx, witness)) = witnesses
                .iter()
                .enumerate()
                .find(|(_, w)| witness_key_hash(&w.name, &w.pubkey) == pc.witness_key_hash)
            else {
                continue;
            };
            let witness_index = u8::try_from(idx).unwrap_or(u8::MAX);
            let signed_message = build_cosignature_signed_message(pc.timestamp, note);
            if crate::witness::verify_cosignature(
                &witness.pubkey,
                witness_index,
                &signed_message,
                &pc.signature,
            )
            .is_ok()
            {
                accepted.push(Cosignature {
                    witness_index,
                    timestamp: pc.timestamp,
                    signature: pc.signature,
                });
            }
        }
        accepted
    }

    /// Load + decode the cached tree head for this log, if present.
    fn load_cached_head(&self, record_id: &[u8]) -> Result<Option<TreeHead>, SigsumError> {
        match self.storage.get(categories::SIGSUM_CACHE, record_id) {
            Ok(bytes) => Ok(Some(TreeHead::from_canonical_cbor(&bytes)?)),
            Err(cairn_storage::StorageError::RecordNotFound { .. }) => Ok(None),
            Err(e) => Err(SigsumError::Storage(e)),
        }
    }
}

/// One cosignature parsed from a `get-tree-head` response, before
/// witness-pool matching.
struct ParsedCosignature {
    witness_key_hash: [u8; 4],
    timestamp: u64,
    signature: [u8; 64],
}

/// The structurally-parsed (not yet verified) `get-tree-head` body.
struct ParsedTreeHead {
    tree_size: u64,
    root_hash: [u8; 32],
    log_signature: [u8; 64],
    cosignatures: Vec<ParsedCosignature>,
}

/// Parse the Sigsum v1 `get-tree-head` ASCII response per the log
/// spec: `size=<dec>`, `root_hash=<hex64>`, `signature=<hex128>`, and
/// zero or more `cosignature=<keyhash_hex8> <ts_dec> <sig_hex128>`.
fn parse_get_tree_head(body: &str) -> Result<ParsedTreeHead, SigsumError> {
    let mut tree_size: Option<u64> = None;
    let mut root_hash: Option<[u8; 32]> = None;
    let mut log_signature: Option<[u8; 64]> = None;
    let mut cosignatures = Vec::new();

    for line in body.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(SigsumError::MalformedResponse)?;
        match key {
            "size" => {
                tree_size = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| SigsumError::MalformedResponse)?,
                );
            }
            "root_hash" => root_hash = Some(parse_hex_array::<32>(value)?),
            "signature" => log_signature = Some(parse_hex_array::<64>(value)?),
            "cosignature" => {
                let mut parts = value.split(' ');
                let kh = parts.next().ok_or(SigsumError::MalformedResponse)?;
                let ts = parts.next().ok_or(SigsumError::MalformedResponse)?;
                let sig = parts.next().ok_or(SigsumError::MalformedResponse)?;
                if parts.next().is_some() {
                    return Err(SigsumError::MalformedResponse);
                }
                cosignatures.push(ParsedCosignature {
                    witness_key_hash: parse_hex_array::<4>(kh)?,
                    timestamp: ts
                        .parse::<u64>()
                        .map_err(|_| SigsumError::MalformedResponse)?,
                    signature: parse_hex_array::<64>(sig)?,
                });
            }
            _ => {} // forward-compat: ignore unknown keys
        }
    }

    Ok(ParsedTreeHead {
        tree_size: tree_size.ok_or(SigsumError::MalformedResponse)?,
        root_hash: root_hash.ok_or(SigsumError::MalformedResponse)?,
        log_signature: log_signature.ok_or(SigsumError::MalformedResponse)?,
        cosignatures,
    })
}

/// Decode a lowercase/uppercase hex string into a fixed `[u8; N]`,
/// erroring on wrong length or non-hex input.
fn parse_hex_array<const N: usize>(s: &str) -> Result<[u8; N], SigsumError> {
    if s.len() != N.saturating_mul(2) {
        return Err(SigsumError::MalformedResponse);
    }
    let mut out = [0u8; N];
    let bytes = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(
            *bytes
                .get(i.saturating_mul(2))
                .ok_or(SigsumError::MalformedResponse)?,
        )?;
        let lo = hex_nibble(
            *bytes
                .get(i.saturating_mul(2).saturating_add(1))
                .ok_or(SigsumError::MalformedResponse)?,
        )?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

const fn hex_nibble(c: u8) -> Result<u8, SigsumError> {
    match c {
        b'0'..=b'9' => Ok(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Ok(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => Err(SigsumError::MalformedResponse),
    }
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Lowercase-hex-encode a byte slice (no `0x` prefix) for the Sigsum
/// `add-leaf` ASCII body fields.
fn lower_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Parse a Sigsum v1 `get-inclusion-proof` response (spec §3.2): a
/// `leaf_index=<dec>` line followed by one or more `node_hash=<hex>`
/// lines in RFC 6962 leaf→root order.
fn parse_get_inclusion_proof(body: &str) -> Result<(u64, Vec<[u8; 32]>), SigsumError> {
    let mut leaf_index: Option<u64> = None;
    let mut nodes = Vec::new();
    for line in body.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(SigsumError::MalformedResponse)?;
        match key {
            "leaf_index" => {
                if leaf_index.is_some() {
                    return Err(SigsumError::MalformedResponse);
                }
                leaf_index = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| SigsumError::MalformedResponse)?,
                );
            }
            "node_hash" => nodes.push(parse_hex_array::<32>(value)?),
            _ => {} // forward-compat: ignore unknown keys
        }
    }
    Ok((leaf_index.ok_or(SigsumError::MalformedResponse)?, nodes))
}

/// Reconstruct the RFC 6962 Merkle root from an inclusion proof
/// (transparency-dev `inner`/`border` decomposition). Returns `None` if
/// the index is out of range or the proof length is wrong.
fn rfc6962_root_from_inclusion_proof(
    index: u64,
    size: u64,
    leaf_hash: &[u8; 32],
    proof: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if index >= size {
        return None;
    }
    let size_minus_one = size.wrapping_sub(1);
    let inner: u32 = u64::BITS.saturating_sub((index ^ size_minus_one).leading_zeros());
    let border = index.checked_shr(inner).map_or(0, u64::count_ones);
    let inner_len = inner as usize;
    if proof.len() != inner_len.saturating_add(border as usize) {
        return None;
    }
    let (inner_nodes, border_nodes) = proof.split_at(inner_len);
    let mut res = *leaf_hash;
    for (i, node) in (0u32..).zip(inner_nodes.iter()) {
        let bit = index.checked_shr(i).unwrap_or(0) & 1;
        res = if bit == 0 {
            hash_children(&res, node)
        } else {
            hash_children(node, &res)
        };
    }
    for node in border_nodes {
        res = hash_children(node, &res);
    }
    Some(res)
}

/// RFC 6962 interior-node hash: `SHA-256(0x01 ‖ left ‖ right)`.
fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01u8]);
    hasher.update(left);
    hasher.update(right);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::witness::parse_witness_pool;
    use cairn_crypto::ed25519::SigningKey;
    use cairn_storage::key_provider::testing::InMemoryKeyProvider;
    use cairn_trust_graph::TrustGraphOp;
    use rand_core::OsRng;
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

    fn make_test_client() -> SigsumClient {
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"test passphrase".to_vec());
        let storage = Arc::new(Storage::open_in_memory(&provider, &passphrase).unwrap());
        let toml = make_witness_pool_toml(3);
        let pool = parse_witness_pool(&toml).unwrap();
        let log_pubkey = SigningKey::generate(&mut OsRng).verifying_key();
        let config = SigsumClientConfig {
            log_url: Url::parse("https://log.example.org").unwrap(),
            log_pubkey,
            witness_pool: pool,
            default_retry_budget: RetryBudget::default(),
        };
        SigsumClient::new(config, storage).unwrap()
    }

    fn make_signed_op(rng: &mut OsRng) -> SignedTrustGraphOp {
        let op_identity_sk = SigningKey::generate(rng);
        let device_sk = SigningKey::generate(rng);
        let peer = SigningKey::generate(rng).verifying_key();
        let op = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer,
            1_700_000_000,
            vec![],
            vec![],
            cairn_trust_graph::Strength::InPerson,
        );
        SignedTrustGraphOp::sign(op, &device_sk).unwrap()
    }

    #[test]
    fn retry_budget_defaults_match_d0023() {
        let b = RetryBudget::default();
        assert_eq!(b.max_retries, 5);
        assert_eq!(b.initial_delay, Duration::from_millis(250));
        assert_eq!(b.max_delay, Duration::from_secs(60));
    }

    #[test]
    fn client_construction_succeeds() {
        let _client = make_test_client();
    }

    #[test]
    fn client_exposes_log_url_and_witness_pool() {
        let client = make_test_client();
        assert_eq!(client.log_url().as_str(), "https://log.example.org/");
        assert_eq!(client.witness_pool().len(), 3);
    }

    // `emit_leaf` is no longer a stub — it builds the Sigsum tree_leaf,
    // POSTs add-leaf, and caches an EmittedLeaf. Its behavior is
    // validated end-to-end against a hermetic mock Sigsum log in
    // `tests/emit_leaf_wiremock.rs`.

    #[tokio::test]
    async fn verify_inclusion_without_emitted_leaf_is_storage_error() {
        // verify_inclusion needs the emit-time EmittedLeaf cached (to
        // rebuild the Sigsum Merkle leaf hash). For an op that was never
        // emitted, the cache lookup misses and surfaces a Storage error
        // before any network call. The full accept path is validated in
        // `tests/verify_inclusion_wiremock.rs`.
        let client = make_test_client();
        let mut rng = OsRng;
        let signed_op = make_signed_op(&mut rng);
        let result = client.verify_inclusion(&signed_op).await;
        assert!(
            matches!(result, Err(SigsumError::Storage(_))),
            "got {result:?}"
        );
    }

    // `emit_leaf` + `refresh_tree_head` are no longer stubs — both
    // perform real network work, validated end-to-end against hermetic
    // wiremock Sigsum logs in `tests/emit_leaf_wiremock.rs` +
    // `tests/refresh_tree_head_wiremock.rs`.
}
