// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Async `SigstoreVerifier` surface per D0024 §6.
//!
//! ## Status
//!
//! [`SigstoreVerifier::verify_release`] is **implemented** as the
//! offline end-to-end orchestration (D0024 §6.4 bundle mode):
//!
//! 1. Decode the `ReleaseManifest` from the bundle's `COSE_Sign1`
//!    envelope payload (D0024 §4).
//! 2. Validate the Fulcio cert chain + OIDC `iss`/`email` pins
//!    ([`crate::fulcio::validate_cert_chain`]) → developer Ed25519 key
//!    (D0024 §1-§2).
//! 3. Verify the manifest `COSE_Sign1` signature against that key
//!    (D0024 §4).
//! 4. Verify the Rekor inclusion proof + signed checkpoint
//!    ([`crate::rekor::verify_rekor_inclusion`]) against the pinned
//!    Rekor key (D0024 §3).
//! 5. Enforce `prior_release_hash` rollback resistance (D0024 §4.2).
//!
//! The online Rekor fetch ([`SigstoreVerifier::fetch_rekor_bundle`] /
//! [`SigstoreVerifier::fetch_and_verify_rekor`]) is also implemented.
//!
//! **One gap remains (D0024 §5):** the witness-cosigned
//! Sigsum-anchored-release-log composition step is NOT wired into
//! `verify_release`. Its dependency,
//! `cairn_sigsum_client::SigsumClient::verify_inclusion`, is now fully
//! implemented (2026-05-31) — so this step is unblocked, but wiring it
//! is its own follow-up: a release manifest is not itself a
//! `SignedTrustGraphOp`, so composing the release log onto Sigsum needs
//! the release-leaf representation settled first (D0024 §5). The
//! composed [`SigsumClient`] is held in the verifier for that step.

use cairn_envelope::cose_sign1::CoseSign1;
use cairn_sigsum_client::{RetryBudget, SigsumClient};
use url::Url;

use crate::error::SigstoreVerifyError;
use crate::fulcio::validate_cert_chain;
use crate::manifest::{RELEASE_MANIFEST_AAD, ReleaseManifest};
use crate::rekor::{RekorBundle, RekorCheckpoint, parse_rekor_log_entry, verify_rekor_inclusion};

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
    /// HTTPS client per D0024 §6 (same workspace pin as D0023). Used by
    /// the online Rekor fetch path.
    http: reqwest::Client,
    /// Pinned Fulcio root in PEM bytes per D0024 §2.
    #[allow(dead_code, reason = "v1 skeleton; populated for the Fulcio body")]
    fulcio_root_pem: Vec<u8>,
    /// Pinned Rekor public key (PEM/SPKI, ECDSA P-256) per D0024 §3.
    /// Consumed by [`SigstoreVerifier::fetch_and_verify_rekor`].
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
    /// Composes the layered verification over a self-contained
    /// [`ReleaseBundle`] (offline mode, D0024 §6.4):
    ///
    /// 1. Decode the [`ReleaseManifest`] from the bundle's `COSE_Sign1`
    ///    envelope payload.
    /// 2. Validate the Fulcio cert chain + OIDC pins
    ///    ([`validate_cert_chain`]), yielding the developer's Ed25519
    ///    signing key.
    /// 3. Verify the manifest `COSE_Sign1` signature against that key
    ///    (external AAD [`RELEASE_MANIFEST_AAD`]).
    /// 4. Verify the Rekor inclusion proof + signed checkpoint
    ///    ([`verify_rekor_inclusion`]) against the pinned Rekor key.
    /// 5. Enforce rollback resistance: the manifest's
    ///    `prior_release_hash` must equal `expected_predecessor_hash`
    ///    when supplied (D0024 §4.2).
    ///
    /// # Sigsum composition gap (D0024 §5)
    ///
    /// The witness-cosigned Sigsum-anchored-release-log step (§5) is
    /// NOT performed here. Its dependency,
    /// `cairn_sigsum_client::SigsumClient::verify_inclusion`, is now
    /// implemented, so the step is unblocked — but it stays unwired
    /// (not faked) pending the release-leaf representation it needs (a
    /// release manifest is not a `SignedTrustGraphOp`, which is what
    /// `verify_inclusion` consumes). The composed [`SigsumClient`] is
    /// held in the verifier for that step.
    ///
    /// # Errors
    ///
    /// Any [`SigstoreVerifyError`] the layers surface:
    /// [`SigstoreVerifyError::ManifestDecodeFailed`],
    /// [`SigstoreVerifyError::FulcioChainInvalid`] /
    /// [`SigstoreVerifyError::FulcioCertExpiredAtSigningTime`] /
    /// [`SigstoreVerifyError::OidcIssuerMismatch`] /
    /// [`SigstoreVerifyError::OidcEmailMismatch`],
    /// [`SigstoreVerifyError::ManifestSignatureVerifyFailed`],
    /// [`SigstoreVerifyError::RekorInclusionProofVerifyFailed`] /
    /// [`SigstoreVerifyError::RekorCheckpointVerifyFailed`],
    /// [`SigstoreVerifyError::ManifestPriorHashMismatch`].
    #[allow(
        clippy::unused_async,
        reason = "offline-bundle verification is synchronous; async is retained per the D0024 §6 surface for the online-fetch composition + the gated Sigsum step"
    )]
    pub async fn verify_release(
        &self,
        bundle: &ReleaseBundle,
        expected_predecessor_hash: Option<[u8; 32]>,
    ) -> Result<VerifiedRelease, SigstoreVerifyError> {
        // (1) Decode the manifest from the COSE_Sign1 envelope payload.
        let envelope = CoseSign1::from_bytes(&bundle.manifest_envelope_bytes)
            .map_err(|_| SigstoreVerifyError::ManifestDecodeFailed)?;
        let payload = envelope
            .payload()
            .ok_or(SigstoreVerifyError::ManifestDecodeFailed)?;
        let manifest = ReleaseManifest::from_canonical_cbor(payload)?;

        // (2) Fulcio cert chain + OIDC pins -> developer Ed25519 key.
        let dev_key = validate_cert_chain(
            &bundle.fulcio_cert_der,
            &self.fulcio_root_pem,
            &self.expected_oidc_issuer,
            &self.expected_oidc_email,
            bundle.rekor_signing_time_unix,
        )?;

        // (3) Manifest signature against the Fulcio-bound developer key.
        envelope
            .verify(&dev_key, RELEASE_MANIFEST_AAD)
            .map_err(|_| SigstoreVerifyError::ManifestSignatureVerifyFailed)?;

        // (4) Rekor inclusion proof + signed checkpoint (offline, against
        // the pinned Rekor key).
        verify_rekor_inclusion(&bundle.rekor_bundle, &self.rekor_pubkey_pem)?;

        // (5) Rollback resistance (D0024 §4.2).
        if let Some(expected) = expected_predecessor_hash {
            if manifest.prior_release_hash.as_slice() != expected.as_slice() {
                return Err(SigstoreVerifyError::ManifestPriorHashMismatch);
            }
        }

        // (§5) Sigsum-anchored-release-log composition is intentionally
        // NOT performed — see the doc comment's "Sigsum composition gap".

        Ok(VerifiedRelease { manifest })
    }

    /// Fetch a Rekor log entry (online mode per D0024 §6.4) and parse it
    /// into a [`RekorBundle`].
    ///
    /// Issues `GET {rekor_base_url}/api/v1/log/entries/{entry_uuid}`,
    /// retried per the default retry budget on transient transport
    /// failures, then parses the response via
    /// [`parse_rekor_log_entry`]. _[Revised 2026-05-30]_ D0024 §6.4
    /// referenced `/api/v2/`; the JSON endpoint that returns an
    /// inclusion-proof-with-checkpoint in one response is the stable
    /// Rekor `/api/v1/log/entries/{uuid}` (the v2 tile-backed API uses a
    /// different retrieval model, deferrable).
    ///
    /// This performs NO cryptographic verification — the returned bundle
    /// must be passed to [`verify_rekor_inclusion`] (or use
    /// [`Self::fetch_and_verify_rekor`]).
    ///
    /// # Errors
    ///
    /// - [`SigstoreVerifyError::Network`] if the transport fails after
    ///   the retry budget is exhausted.
    /// - [`SigstoreVerifyError::RekorResponseMalformed`] if the URL join
    ///   fails or the response body does not parse.
    pub async fn fetch_rekor_bundle(
        &self,
        rekor_base_url: &Url,
        entry_uuid: &str,
    ) -> Result<RekorBundle, SigstoreVerifyError> {
        let url = rekor_base_url
            .join(&format!("api/v1/log/entries/{entry_uuid}"))
            .map_err(|_| SigstoreVerifyError::RekorResponseMalformed)?;
        let body = self.http_get_text(url).await?;
        parse_rekor_log_entry(&body)
    }

    /// Fetch + verify a Rekor entry online: fetches the bundle via
    /// [`Self::fetch_rekor_bundle`], then verifies it against the pinned
    /// Rekor public key via [`verify_rekor_inclusion`]. Returns the
    /// verified [`RekorCheckpoint`] (whose root hash is surfaced per
    /// D0024 §3.3).
    ///
    /// # Errors
    ///
    /// Any error from the fetch ([`SigstoreVerifyError::Network`] /
    /// [`SigstoreVerifyError::RekorResponseMalformed`]) or the verify
    /// ([`SigstoreVerifyError::RekorInclusionProofVerifyFailed`] /
    /// [`SigstoreVerifyError::RekorCheckpointVerifyFailed`]).
    pub async fn fetch_and_verify_rekor(
        &self,
        rekor_base_url: &Url,
        entry_uuid: &str,
    ) -> Result<RekorCheckpoint, SigstoreVerifyError> {
        let bundle = self.fetch_rekor_bundle(rekor_base_url, entry_uuid).await?;
        verify_rekor_inclusion(&bundle, &self.rekor_pubkey_pem)
    }

    /// `GET url`, retrying transient transport failures up to the default
    /// retry budget. Returns the response body text. Mirrors
    /// `cairn_sigsum_client`'s `http_get_tree_head` retry shape per
    /// D0024 §6.3 (shared `RetryBudget`).
    async fn http_get_text(&self, url: Url) -> Result<String, SigstoreVerifyError> {
        let budget = self.default_retry_budget;
        let mut delay = budget.initial_delay;
        let mut attempt: u8 = 0;
        loop {
            match self.http.get(url.clone()).send().await {
                Ok(resp) => match resp.error_for_status() {
                    Ok(ok) => {
                        return ok
                            .text()
                            .await
                            .map_err(|_| SigstoreVerifyError::RekorResponseMalformed);
                    }
                    Err(_) if attempt < budget.max_retries => {}
                    Err(_) => {
                        return Err(SigstoreVerifyError::Network {
                            retry_budget_used: attempt,
                        });
                    }
                },
                Err(_) if attempt < budget.max_retries => {}
                Err(_) => {
                    return Err(SigstoreVerifyError::Network {
                        retry_budget_used: attempt,
                    });
                }
            }
            tokio::time::sleep(delay).await;
            delay = delay.saturating_mul(2).min(budget.max_delay);
            attempt = attempt.saturating_add(1);
        }
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
        let log_pubkey = SigningKey::generate(&mut OsRng).verifying_key();
        let config = SigsumClientConfig {
            log_url: Url::parse("https://log.example.org").unwrap(),
            log_pubkey,
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
                proof_nodes: vec![[0x11; 32]],
                checkpoint_note: b"rekor.example/test\n1024\nAAAA\n".to_vec(),
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
    async fn verify_release_rejects_malformed_manifest_envelope() {
        // The placeholder bundle's manifest bytes are not a valid
        // COSE_Sign1, so verify_release fails at the first (decode) gate.
        // The full happy-path + per-layer failure composition is covered
        // end-to-end in tests/verify_release.rs (it needs rcgen certs +
        // a cairn-crypto-signed manifest + a valid Rekor bundle).
        let verifier = make_verifier();
        let bundle = make_release_bundle();
        let result = verifier.verify_release(&bundle, None).await;
        assert!(matches!(
            result,
            Err(SigstoreVerifyError::ManifestDecodeFailed)
        ));
    }
}
