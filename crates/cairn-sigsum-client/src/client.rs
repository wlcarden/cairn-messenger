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
//! [`SigsumClient::emit_leaf`] + [`SigsumClient::verify_inclusion`]
//! still return [`SigsumError::NetworkUnreached`] pending their
//! `add-leaf` POST + inclusion-proof bodies per D0023 §10. When those
//! land they follow the D0023 §5 spec: `add-leaf` POST to the log,
//! then read the cosignatures back from the (single) `get-tree-head`
//! response — NOT a separate per-witness fetch — and the inclusion
//! proof from `get-inclusion-proof`, with the cache updated on success.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cairn_crypto::ed25519::{Signature, VerifyingKey};
use cairn_storage::{Storage, categories};
use cairn_trust_graph::SignedTrustGraphOp;
use sha2::{Digest, Sha256};
use url::Url;

use crate::cache::{Cosignature, InclusionProof, TreeHead, cache_record_id_for_log};
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
    /// HTTPS client per D0023 §2.
    #[allow(
        dead_code,
        reason = "wired in v1 skeleton; populated for the network surface"
    )]
    http: reqwest::Client,
    /// Storage handle for cache state per D0023 §4.
    #[allow(dead_code, reason = "v1 skeleton; populated for the cache writes")]
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
    /// v1 skeleton: returns [`SigsumError::NetworkUnreached`] pending
    /// integration testing. When the network body lands, the flow is:
    ///
    /// 1. Compute the leaf hash via [`crate::leaf::leaf_hash_for`].
    /// 2. POST to `{log_url}/add-leaf` with the rfc6962-formatted
    ///    leaf body.
    /// 3. On success, the log returns the new tree head + inclusion
    ///    proof — store both in the cache.
    /// 4. Retry on transient HTTP failures per
    ///    [`SigsumClient::default_retry_budget`].
    ///
    /// # Errors
    ///
    /// - [`SigsumError::NetworkUnreached`] (skeleton only; replaced
    ///   by [`SigsumError::Network`] once the body lands)
    /// - [`SigsumError::Encode`] for envelope encode failures
    ///   (unreachable for envelopes constructed via the public API)
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; network body lands with the integration-tests gate per D0023 §10"
    )]
    pub async fn emit_leaf(&self, signed_op: &SignedTrustGraphOp) -> Result<LeafHash, SigsumError> {
        // Compute the leaf hash now so the structural error surfaces
        // even before the network body lands.
        let _hash = crate::leaf::leaf_hash_for(signed_op)?;
        Err(SigsumError::NetworkUnreached)
    }

    /// Verify that `signed_op` is included in the latest accepted
    /// log head per D0023 §5 + §6.2.
    ///
    /// v1 skeleton: returns [`SigsumError::NetworkUnreached`].
    ///
    /// # Errors
    ///
    /// - [`SigsumError::NetworkUnreached`] (skeleton only)
    /// - When the body lands:
    ///   [`SigsumError::InclusionProofVerifyFailed`],
    ///   [`SigsumError::InsufficientWitnessCosignatures`],
    ///   [`SigsumError::LogSplitView`],
    ///   [`SigsumError::Storage`] for cache I/O failures.
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; network body lands with the integration-tests gate per D0023 §10"
    )]
    pub async fn verify_inclusion(
        &self,
        signed_op: &SignedTrustGraphOp,
    ) -> Result<InclusionProof, SigsumError> {
        let _hash = crate::leaf::leaf_hash_for(signed_op)?;
        Err(SigsumError::NetworkUnreached)
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

        // (3) Verify the log's own tree-head signature over the
        // checkpoint note, using the pinned log key + its key hash.
        let log_key_hash = sha256_of(&self.log_pubkey.to_bytes());
        let note = build_tree_head_note(&log_key_hash, parsed.tree_size, &parsed.root_hash);
        let log_sig = Signature::from_bytes(parsed.log_signature);
        self.log_pubkey
            .verify(&note, &log_sig)
            .map_err(|_| SigsumError::MalformedResponse)?;

        // (4) Verify witness cosignatures against the configured pool.
        let accepted = self.verify_cosignatures(&note, &parsed.cosignatures);
        let valid = u8::try_from(accepted.len()).unwrap_or(u8::MAX);
        if valid < REQUIRED_COSIGNATURE_COUNT {
            return Err(SigsumError::InsufficientWitnessCosignatures {
                valid,
                required: REQUIRED_COSIGNATURE_COUNT,
                pool_size: self.witness_pool.len(),
            });
        }

        // (5) Split-view detection against any cached head.
        let record_id = cache_record_id_for_log(&self.log_url);
        if let Some(cached) = self.load_cached_head(&record_id)? {
            if parsed.tree_size < cached.tree_size {
                return Err(SigsumError::LogTreeSizeRegression {
                    cached_tree_size: cached.tree_size,
                    fetched_tree_size: parsed.tree_size,
                });
            }
            if parsed.tree_size == cached.tree_size && parsed.root_hash != cached.root_hash {
                return Err(SigsumError::LogSplitView {
                    tree_size: parsed.tree_size,
                });
            }
        }

        // (6) Build + cache the accepted head. `timestamp` records the
        // freshest cosignature time; `observed_at` is wall-clock now.
        let freshest = accepted.iter().map(|c| c.timestamp).max().unwrap_or(0);
        let head = TreeHead {
            tree_size: parsed.tree_size,
            root_hash: parsed.root_hash,
            timestamp: freshest,
            cosignatures: accepted,
            observed_at: now_unix(),
        };
        let encoded = head.to_canonical_cbor()?;
        self.storage
            .put(categories::SIGSUM_CACHE, &record_id, &encoded)?;
        Ok(head)
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

    #[tokio::test]
    async fn emit_leaf_returns_network_unreached_in_skeleton() {
        let client = make_test_client();
        let mut rng = OsRng;
        let signed_op = make_signed_op(&mut rng);
        let result = client.emit_leaf(&signed_op).await;
        assert!(matches!(result, Err(SigsumError::NetworkUnreached)));
    }

    #[tokio::test]
    async fn verify_inclusion_returns_network_unreached_in_skeleton() {
        let client = make_test_client();
        let mut rng = OsRng;
        let signed_op = make_signed_op(&mut rng);
        let result = client.verify_inclusion(&signed_op).await;
        assert!(matches!(result, Err(SigsumError::NetworkUnreached)));
    }

    // `refresh_tree_head` is no longer a stub — it performs a real
    // get-tree-head fetch + C2SP cosignature verification. Its
    // behavior is validated end-to-end against a hermetic wiremock
    // Sigsum log in `tests/refresh_tree_head_wiremock.rs`.
}
