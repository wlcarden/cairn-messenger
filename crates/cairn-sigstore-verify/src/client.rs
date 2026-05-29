// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Async `SigstoreVerifier` surface per D0024 §6.
//!
//! ## v1 skeleton status
//!
//! The struct + method signatures are defined per the D0024 §6 API.
//! The orchestration body (`verify_release`) returns
//! [`SigstoreVerifyError::NetworkUnreached`] pending the Fulcio +
//! Rekor + composition bodies landing per D0024 §10. The
//! constructor + configuration surface are real + tested.
//!
//! What IS implemented + tested in the skeleton:
//!
//! - `SigstoreVerifier::new` constructor wiring the `reqwest::Client`,
//!   the pinned Fulcio root + Rekor pubkey + OIDC identity config,
//!   and the composed `cairn_sigsum_client::SigsumClient` per D0024
//!   §5.
//! - `SigstoreVerifierConfig` builder pattern.
//! - `RetryBudget` re-export from `cairn_sigsum_client` per
//!   D0024 §6.3 ("same RetryBudget type as D0023 §5.3").
//!
//! When the verify body lands, the flow is:
//!
//! 1. Decode the `ReleaseManifest` from the bundle's manifest bytes.
//! 2. Validate the Fulcio cert chain + OIDC claims per D0024 §1-§2.
//! 3. Verify the Rekor inclusion proof + signed checkpoint per
//!    D0024 §3.
//! 4. Verify the `COSE_Sign1` manifest signature against the
//!    Fulcio-issued public key per D0024 §4.
//! 5. Compose with `cairn-sigsum-client` to verify the Sigsum
//!    witness-cosigned release-log entry per D0024 §5.
//! 6. Check `prior_release_hash` against the caller-supplied
//!    expected predecessor per D0024 §4.2.

use cairn_sigsum_client::{RetryBudget, SigsumClient};

use crate::error::SigstoreVerifyError;
use crate::manifest::ReleaseManifest;
use crate::rekor::RekorBundle;

/// Configuration bundle for constructing a [`SigstoreVerifier`].
///
/// Builder-pattern is intentional, mirroring D0023 §5's
/// [`cairn_sigsum_client::SigsumClientConfig`]: a single config
/// argument so callers can construct in stages without a long
/// positional argument list.
///
/// Note: this type does NOT derive `Debug` because the composed
/// [`SigsumClient`] does not derive `Debug` either (it owns a
/// `reqwest::Client` whose `Debug` surface upstream chose not to
/// expose). The config's contents are operational pins, not
/// secrets, so a future `Debug` impl is tractable if a caller
/// surfaces a need; v1 callers do not.
pub struct SigstoreVerifierConfig {
    /// Pinned Fulcio root certificate in PEM bytes per D0024 §2.
    pub fulcio_root_pem: Vec<u8>,
    /// Pinned Rekor public key in PEM bytes per D0024 §3.
    pub rekor_pubkey_pem: Vec<u8>,
    /// Expected OIDC issuer URL per D0024 §1.1.
    pub expected_oidc_issuer: String,
    /// Expected developer identity email per D0024 §1.1.
    pub expected_oidc_email: String,
    /// Sigsum client for the witness-cosigned release log per
    /// D0024 §5.
    pub sigsum_client: SigsumClient,
    /// Default retry budget for Rekor / Fulcio network operations.
    /// Re-uses the D0023 §5.3 type.
    pub default_retry_budget: RetryBudget,
}

/// A self-contained release bundle the verifier consumes per
/// D0024 §6.4 (offline mode) or freshly fetched (online mode).
///
/// Carries:
///
/// - the canonical-CBOR encoded `COSE_Sign1` of the manifest;
/// - the Fulcio-issued signing certificate in DER bytes;
/// - the Rekor inclusion + checkpoint bundle.
///
/// The Sigsum witness-cosigned release-log entry is fetched via the
/// composed [`SigsumClient`] rather than carried inline; that path
/// reuses the D0023 substrate without duplication.
#[derive(Debug, Clone)]
pub struct ReleaseBundle {
    /// `COSE_Sign1` envelope bytes over the canonical-CBOR
    /// encoded [`ReleaseManifest`].
    pub manifest_envelope_bytes: Vec<u8>,
    /// Fulcio-issued signing certificate in DER bytes.
    pub fulcio_cert_der: Vec<u8>,
    /// Rekor inclusion + checkpoint bundle per D0024 §3.
    pub rekor_bundle: RekorBundle,
    /// Unix-seconds the Rekor entry attests as the signing time.
    /// Compared against the Fulcio cert's validity window per
    /// D0024 §2.1.
    pub rekor_signing_time_unix: u64,
}

/// Outcome of a successful [`SigstoreVerifier::verify_release`]
/// invocation per D0024 §6.
///
/// In the v1 skeleton this type is constructed only by the
/// orchestration body that does not yet land; the type exists so
/// the public API is stable from skeleton through implementation.
#[derive(Debug, Clone)]
pub struct VerifiedRelease {
    /// The decoded + signature-verified manifest.
    pub manifest: ReleaseManifest,
}

/// The async Sigstore release verifier per D0024 §6.
///
/// Wraps the pinned trust roots + the OIDC identity pins + the
/// composed [`SigsumClient`]. Each async call routes through the
/// retry logic per D0024 §6.3.
pub struct SigstoreVerifier {
    /// HTTPS client per D0024 §6 (same workspace pin as D0023).
    #[allow(
        dead_code,
        reason = "wired in v1 skeleton; populated for the network surface"
    )]
    http: reqwest::Client,
    /// Pinned Fulcio root in PEM bytes per D0024 §2.
    #[allow(dead_code, reason = "v1 skeleton; populated for the Fulcio body")]
    fulcio_root_pem: Vec<u8>,
    /// Pinned Rekor public key in PEM bytes per D0024 §3.
    #[allow(dead_code, reason = "v1 skeleton; populated for the Rekor body")]
    rekor_pubkey_pem: Vec<u8>,
    /// Expected OIDC issuer URL per D0024 §1.1.
    expected_oidc_issuer: String,
    /// Expected developer identity email per D0024 §1.1.
    expected_oidc_email: String,
    /// Composed Sigsum client for the witness-cosigned release log
    /// per D0024 §5.
    #[allow(dead_code, reason = "v1 skeleton; populated for the compose body")]
    sigsum_client: SigsumClient,
    /// Default retry budget per D0024 §6.3 / D0023 §5.3.
    default_retry_budget: RetryBudget,
}

impl SigstoreVerifier {
    /// Construct a new `SigstoreVerifier` from its config bundle.
    ///
    /// The `reqwest::Client` is constructed with `rustls-tls` per
    /// D0023 §2.1 + D0024 §6 (same workspace pin); `default-features
    /// = false` strips native-tls, cookies, and compression at the
    /// workspace pin level.
    ///
    /// # Errors
    ///
    /// Returns [`SigstoreVerifyError::Network`] if the reqwest
    /// client construction fails (extremely unusual; typically only
    /// on platform-specific TLS configuration issues).
    pub fn new(config: SigstoreVerifierConfig) -> Result<Self, SigstoreVerifyError> {
        let http =
            reqwest::Client::builder()
                .build()
                .map_err(|_| SigstoreVerifyError::Network {
                    retry_budget_used: 0,
                })?;
        Ok(Self {
            http,
            fulcio_root_pem: config.fulcio_root_pem,
            rekor_pubkey_pem: config.rekor_pubkey_pem,
            expected_oidc_issuer: config.expected_oidc_issuer,
            expected_oidc_email: config.expected_oidc_email,
            sigsum_client: config.sigsum_client,
            default_retry_budget: config.default_retry_budget,
        })
    }

    /// Return the pinned OIDC issuer URL.
    #[must_use]
    pub fn expected_oidc_issuer(&self) -> &str {
        &self.expected_oidc_issuer
    }

    /// Return the pinned developer identity email.
    #[must_use]
    pub fn expected_oidc_email(&self) -> &str {
        &self.expected_oidc_email
    }

    /// Return the default retry budget.
    #[must_use]
    pub const fn default_retry_budget(&self) -> RetryBudget {
        self.default_retry_budget
    }

    /// Verify a release bundle end-to-end per D0024 §6.
    ///
    /// v1 skeleton: returns [`SigstoreVerifyError::NetworkUnreached`]
    /// pending Fulcio + Rekor + composition bodies landing.
    ///
    /// # Errors
    ///
    /// - [`SigstoreVerifyError::NetworkUnreached`] (skeleton only)
    /// - When the body lands: any
    ///   [`SigstoreVerifyError`] variant the layered verification
    ///   can surface (Fulcio chain failure, OIDC claim mismatch,
    ///   Rekor proof failure, manifest decode failure, Sigsum
    ///   release-log failure, predecessor mismatch).
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; orchestration body lands with the integration-tests gate per D0024 §10"
    )]
    pub async fn verify_release(
        &self,
        _bundle: &ReleaseBundle,
        _expected_predecessor_hash: Option<[u8; 32]>,
    ) -> Result<VerifiedRelease, SigstoreVerifyError> {
        Err(SigstoreVerifyError::NetworkUnreached)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use cairn_sigsum_client::{SigsumClientConfig, parse_witness_pool};
    use cairn_storage::Storage;
    use cairn_storage::key_provider::testing::InMemoryKeyProvider;
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

    fn make_sigsum_client() -> SigsumClient {
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

    fn make_verifier() -> SigstoreVerifier {
        let config = SigstoreVerifierConfig {
            fulcio_root_pem: b"-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----"
                .to_vec(),
            rekor_pubkey_pem: b"-----BEGIN PUBLIC KEY-----\nplaceholder\n-----END PUBLIC KEY-----"
                .to_vec(),
            expected_oidc_issuer: "https://accounts.example.org".to_string(),
            expected_oidc_email: "maintainer@cairn-project.org".to_string(),
            sigsum_client: make_sigsum_client(),
            default_retry_budget: RetryBudget::default(),
        };
        SigstoreVerifier::new(config).unwrap()
    }

    fn make_release_bundle() -> ReleaseBundle {
        ReleaseBundle {
            manifest_envelope_bytes: vec![0xAA; 64],
            fulcio_cert_der: vec![0xBB; 128],
            rekor_bundle: RekorBundle {
                leaf_hash: [0xCC; 32],
                leaf_index: 100,
                tree_size: 1024,
                checkpoint_root_hash: [0xDD; 32],
                proof_nodes: vec![[0x11; 32]],
                checkpoint_signature: vec![0xEE; 64],
            },
            rekor_signing_time_unix: 1_700_000_000,
        }
    }

    #[test]
    fn verifier_construction_succeeds() {
        let _verifier = make_verifier();
    }

    #[test]
    fn verifier_exposes_pinned_oidc_identity() {
        let verifier = make_verifier();
        assert_eq!(
            verifier.expected_oidc_issuer(),
            "https://accounts.example.org"
        );
        assert_eq!(
            verifier.expected_oidc_email(),
            "maintainer@cairn-project.org"
        );
    }

    #[test]
    fn verifier_exposes_default_retry_budget() {
        let verifier = make_verifier();
        let budget = verifier.default_retry_budget();
        // The default retry budget comes from cairn-sigsum-client
        // per D0024 §6.3; pinning its presence here keeps the
        // composition explicit.
        assert_eq!(budget.max_retries, RetryBudget::default().max_retries);
    }

    #[tokio::test]
    async fn verify_release_returns_network_unreached_in_skeleton() {
        let verifier = make_verifier();
        let bundle = make_release_bundle();
        let result = verifier.verify_release(&bundle, None).await;
        assert!(matches!(result, Err(SigstoreVerifyError::NetworkUnreached)));
    }

    #[tokio::test]
    async fn verify_release_with_expected_predecessor_returns_network_unreached_in_skeleton() {
        let verifier = make_verifier();
        let bundle = make_release_bundle();
        let predecessor = [0xFFu8; 32];
        let result = verifier.verify_release(&bundle, Some(predecessor)).await;
        assert!(matches!(result, Err(SigstoreVerifyError::NetworkUnreached)));
    }
}
