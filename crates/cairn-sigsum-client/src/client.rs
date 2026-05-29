// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Async `SigsumClient` surface per D0023 §5.
//!
//! ## v1 skeleton status
//!
//! The struct + method signatures are defined per the D0023 §5.1 API.
//! The network-bound bodies (`emit_leaf`, `verify_inclusion`,
//! `refresh_tree_head`) return [`SigsumError::NetworkUnreached`]
//! pending integration testing against a real Sigsum log endpoint or
//! a wiremock-based mock per D0023 §10.
//!
//! What IS implemented + tested in the skeleton:
//!
//! - `SigsumClient::new` constructor wiring the `reqwest::Client`,
//!   the `Arc<Storage>`, the `WitnessPool`, and the log URL.
//! - `RetryBudget` type + default per D0023 §5.3.
//! - `SigsumClientConfig` builder pattern.
//!
//! When the network surface lands (a follow-up commit gated on
//! wiremock or real-Sigsum integration testing), the method bodies
//! follow the D0023 §5 spec exactly: `add-leaf` POST to the log,
//! cosignature fetch from each witness in parallel, threshold check
//! per D0023 §3.4, cache update on success.

use std::sync::Arc;
use std::time::Duration;

use cairn_storage::Storage;
use cairn_trust_graph::SignedTrustGraphOp;
use url::Url;

use crate::cache::{InclusionProof, TreeHead};
use crate::error::SigsumError;
use crate::leaf::LeafHash;
use crate::witness::WitnessPool;

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
            default_retry_budget: config.default_retry_budget,
        })
    }

    /// Return the configured log URL.
    #[must_use]
    pub const fn log_url(&self) -> &Url {
        &self.log_url
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
    /// v1 skeleton: returns [`SigsumError::NetworkUnreached`].
    ///
    /// # Errors
    ///
    /// - [`SigsumError::NetworkUnreached`] (skeleton only)
    /// - When the body lands: every variant of `SigsumError` that the
    ///   refresh path can surface (monotonic-check failures, witness-
    ///   threshold failures, etc.).
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; network body lands with the integration-tests gate per D0023 §10"
    )]
    pub async fn refresh_tree_head(&self) -> Result<TreeHead, SigsumError> {
        Err(SigsumError::NetworkUnreached)
    }
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
        let config = SigsumClientConfig {
            log_url: Url::parse("https://log.example.org").unwrap(),
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

    #[tokio::test]
    async fn refresh_tree_head_returns_network_unreached_in_skeleton() {
        let client = make_test_client();
        let result = client.refresh_tree_head().await;
        assert!(matches!(result, Err(SigsumError::NetworkUnreached)));
    }
}
