// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Async `SigstoreVerifier` surface per D0024 §6.
//!
//! ## Status
//!
//! [`SigstoreVerifier::verify_release`] is **implemented** as the
//! offline end-to-end orchestration (D0024 §6.4 bundle mode):
//!
//! 1. Decode the `ReleaseManifest` from the bundle's canonical-CBOR
//!    `manifest_bytes` — the exact blob the detached signature covers
//!    (D0042 §3; no `COSE_Sign1` wrapper).
//! 2. Validate the Fulcio cert chain + OIDC `iss`/`email` pins
//!    ([`crate::fulcio::validate_cert_chain`]) → developer ECDSA P-256
//!    key (D0024 §1-§2 / D0042 §3).
//! 3. Verify the detached ECDSA P-256 `manifest_signature` over
//!    `manifest_bytes` against that key (the cosign sign-blob model;
//!    D0042 §3).
//! 4. Verify the Rekor inclusion proof + signed checkpoint
//!    ([`crate::rekor::verify_rekor_inclusion`]) against the pinned
//!    Rekor key (D0024 §3), then **bind** the proven-included entry to
//!    this signing event: the reconstructed `hashedrekord` leaf hash
//!    ([`crate::rekor::hashedrekord_leaf_hash`] over the manifest's
//!    artifact hash + detached signature + Fulcio cert) must equal the
//!    bundle's leaf (D0042 §6.6).
//! 5. Enforce `prior_release_hash` rollback resistance (D0024 §4.2).
//! 6. Verify the witness-cosigned Sigsum-anchored release-log inclusion
//!    (D0024 §5) offline via
//!    [`cairn_sigsum_client::SigsumClient::verify_bundled_inclusion`]:
//!    bind the bundled proof to this release's `release_leaf_hash`
//!    (`SHA-256(detached_signature_bytes)`, the shared D0023 §1 / D0042
//!    §3 primitive), re-verify the cosigned head + 2-of-3 witness
//!    threshold, and reconstruct the RFC 6962 root.
//!
//! All six steps are offline; the optional `online-rekor` feature's
//! Rekor fetch path (`fetch_rekor_bundle` / `fetch_and_verify_rekor`)
//! merely pre-populates the bundle, after which the identical offline
//! verify runs. That path is feature-gated OFF by default (D0024 §6.4 /
//! D0041 §6.1) so the shipped verifier is offline **by construction** —
//! the network methods do not exist in the default build, not merely "by
//! calling convention."
//!
//! The Sigsum step uses the offline `verify_bundled_inclusion`, NOT the
//! self-emit `verify_inclusion`: a release verifier never emitted the
//! release leaf, so the release signer transmits the tree-leaf
//! components + raw proof bodies in the [`ReleaseBundle`] (D0023 §1.4),
//! exactly as the Rekor proof is carried inline.

use cairn_envelope::canonical::Value;
use cairn_sigsum_client::{EmittedLeaf, RetryBudget, SigsumClient};
use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier as _;
use sha2::{Digest, Sha256};
use x509_parser::pem::Pem;
// `Url` is used only by the online `fetch_*` path (gated below).
#[cfg(feature = "online-rekor")]
use url::Url;

use crate::compose::release_leaf_hash_for_signature;
use crate::decode::{decode_canonical_map, int_to_u64, into_bytes, into_text};
use crate::error::SigstoreVerifyError;
use crate::fulcio::validate_cert_chain;
use crate::manifest::ReleaseManifest;
use crate::rekor::{RekorBundle, hashedrekord_leaf_hash, verify_rekor_inclusion};
// `RekorCheckpoint` + `parse_rekor_log_entry` are used only by the
// online `fetch_*` path (gated below); importing them unconditionally
// would be an unused import in the default offline build.
#[cfg(feature = "online-rekor")]
use crate::rekor::{RekorCheckpoint, parse_rekor_log_entry};

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
    /// Optional pinned CT-log public key (PEM/SPKI) for embedded-SCT
    /// verification (D0042 §6.5/§6.6). `Some` makes `verify_release`
    /// **enforce** the Fulcio leaf's embedded SCT against this key (real
    /// Sigstore roots, where every leaf is CT-logged); `None` skips SCT
    /// verification (synthetic roots / the phase-1 producer, whose rcgen
    /// leaves carry no SCT).
    pub ctlog_pubkey_pem: Option<Vec<u8>>,
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

/// A self-contained release bundle the verifier consumes per D0024 §6.4.
///
/// Every proof in the bundle is verified **offline** against the pinned
/// trust roots; "online mode" merely pre-populates these same fields by
/// fetching them first, then runs the identical offline verify.
///
/// Carries:
///
/// - the canonical-CBOR `ReleaseManifest` bytes + the detached ECDSA
///   P-256 signature over them (D0042 §3);
/// - the Fulcio-issued signing certificate in DER bytes;
/// - the Rekor inclusion + checkpoint bundle;
/// - the Sigsum witness-cosigned release-log proof (D0024 §5).
///
/// The Sigsum proof is carried **inline** (not fetched at verify time)
/// for the same reason the Rekor proof is: the air-gapped install path
/// (§6.4) must verify without network access. A verifier cannot
/// recompute the submitter's tree-leaf signature (D0023 §1.4), so the
/// emit-time [`EmittedLeaf`] is transmitted alongside the raw
/// `get-tree-head` + `get-inclusion-proof` bodies the release signer
/// captured.
#[derive(Debug, Clone)]
pub struct ReleaseBundle {
    /// The canonical-CBOR encoded [`ReleaseManifest`] bytes — the blob the
    /// release was signed over (D0042 §3; no `COSE_Sign1` wrapper, so a
    /// third party can `cosign verify-blob` it).
    pub manifest_bytes: Vec<u8>,
    /// The detached ECDSA **P-256** signature (ASN.1 DER) over
    /// [`Self::manifest_bytes`] — `cosign sign-blob`'s output under the
    /// Fulcio ephemeral key (D0042 §3/§4).
    pub manifest_signature: Vec<u8>,
    /// Fulcio-issued signing certificate in DER bytes.
    pub fulcio_cert_der: Vec<u8>,
    /// Rekor inclusion + checkpoint bundle per D0024 §3.
    pub rekor_bundle: RekorBundle,
    /// Unix-seconds the Rekor entry attests as the signing time.
    /// Compared against the Fulcio cert's validity window per
    /// D0024 §2.1.
    pub rekor_signing_time_unix: u64,
    /// The release signer's emit-time Sigsum tree-leaf components for
    /// the release leaf (D0024 §5.1 + D0023 §1.4). Required to
    /// reconstruct the Merkle leaf hash; the verifier cannot recompute
    /// the submitter signature.
    pub sigsum_emitted_leaf: EmittedLeaf,
    /// Raw `get-tree-head` ASCII the Sigsum inclusion proof was captured
    /// against — the cosigned accepted head, re-verified offline against
    /// the pinned log key + witness pool.
    pub sigsum_tree_head_body: String,
    /// Raw `get-inclusion-proof` ASCII for the release leaf (ignored for
    /// a size-1 tree, whose inclusion is checked locally).
    pub sigsum_inclusion_proof_body: String,
}

// === Canonical-CBOR map keys for the ReleaseBundle wire format ===
// Integer-keyed map per D0018 §2.3. This is the single-file offline-
// install artifact (D0024 §6.4): the release producer writes it, the
// client reads it, and `verify_release` consumes the decoded struct.
// The nested `RekorBundle` + Sigsum `EmittedLeaf` are carried as byte
// strings holding their own canonical-CBOR (each owns its schema).
const KEY_BUNDLE_MANIFEST_BYTES: i64 = 1;
const KEY_BUNDLE_FULCIO_CERT_DER: i64 = 2;
const KEY_BUNDLE_REKOR: i64 = 3;
const KEY_BUNDLE_REKOR_SIGNING_TIME: i64 = 4;
const KEY_BUNDLE_SIGSUM_EMITTED_LEAF: i64 = 5;
const KEY_BUNDLE_SIGSUM_TREE_HEAD: i64 = 6;
const KEY_BUNDLE_SIGSUM_INCLUSION_PROOF: i64 = 7;
const KEY_BUNDLE_MANIFEST_SIGNATURE: i64 = 8;

impl ReleaseBundle {
    /// Encode as canonical-CBOR per D0018 §2.3 — the offline-install
    /// wire format (D0024 §6.4) the release producer writes alongside
    /// the APK.
    ///
    /// # Errors
    ///
    /// [`SigstoreVerifyError::ReleaseBundleDecodeFailed`] if a nested
    /// component fails to encode or `rekor_signing_time_unix` exceeds
    /// `i64::MAX` (unreachable for real Unix timestamps).
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SigstoreVerifyError> {
        let rekor_cbor = self.rekor_bundle.to_canonical_cbor()?;
        let leaf_cbor = self
            .sigsum_emitted_leaf
            .to_canonical_cbor()
            .map_err(|_| SigstoreVerifyError::ReleaseBundleDecodeFailed)?;
        let signing_time_i64 = i64::try_from(self.rekor_signing_time_unix)
            .map_err(|_| SigstoreVerifyError::ReleaseBundleDecodeFailed)?;
        let map = Value::Map(vec![
            (
                Value::Int(KEY_BUNDLE_MANIFEST_BYTES),
                Value::Bytes(self.manifest_bytes.clone()),
            ),
            (
                Value::Int(KEY_BUNDLE_FULCIO_CERT_DER),
                Value::Bytes(self.fulcio_cert_der.clone()),
            ),
            (Value::Int(KEY_BUNDLE_REKOR), Value::Bytes(rekor_cbor)),
            (
                Value::Int(KEY_BUNDLE_REKOR_SIGNING_TIME),
                Value::Int(signing_time_i64),
            ),
            (
                Value::Int(KEY_BUNDLE_SIGSUM_EMITTED_LEAF),
                Value::Bytes(leaf_cbor),
            ),
            (
                Value::Int(KEY_BUNDLE_SIGSUM_TREE_HEAD),
                Value::Text(self.sigsum_tree_head_body.clone()),
            ),
            (
                Value::Int(KEY_BUNDLE_SIGSUM_INCLUSION_PROOF),
                Value::Text(self.sigsum_inclusion_proof_body.clone()),
            ),
            (
                Value::Int(KEY_BUNDLE_MANIFEST_SIGNATURE),
                Value::Bytes(self.manifest_signature.clone()),
            ),
        ]);
        map.encode()
            .map_err(|_| SigstoreVerifyError::ReleaseBundleDecodeFailed)
    }

    /// Decode from canonical-CBOR bytes. Unknown integer keys are
    /// tolerated per D0006 §6.4's forward-compatibility discipline.
    ///
    /// This is a structural decode only — it does NOT verify any proof.
    /// The decoded bundle MUST be passed to
    /// [`SigstoreVerifier::verify_release`] before any field is trusted.
    ///
    /// # Errors
    ///
    /// [`SigstoreVerifyError::ReleaseBundleDecodeFailed`] for any CBOR or
    /// schema structural error, including a malformed nested
    /// `RekorBundle` / Sigsum `EmittedLeaf`.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SigstoreVerifyError> {
        let entries =
            decode_canonical_map(bytes).ok_or(SigstoreVerifyError::ReleaseBundleDecodeFailed)?;
        let mut manifest_bytes: Option<Vec<u8>> = None;
        let mut manifest_signature: Option<Vec<u8>> = None;
        let mut fulcio_cert_der: Option<Vec<u8>> = None;
        let mut rekor_bundle: Option<RekorBundle> = None;
        let mut rekor_signing_time_unix: Option<u64> = None;
        let mut sigsum_emitted_leaf: Option<EmittedLeaf> = None;
        let mut sigsum_tree_head_body: Option<String> = None;
        let mut sigsum_inclusion_proof_body: Option<String> = None;
        for (key, value) in entries {
            match key {
                KEY_BUNDLE_MANIFEST_BYTES => manifest_bytes = Some(into_bytes(value)?),
                KEY_BUNDLE_MANIFEST_SIGNATURE => manifest_signature = Some(into_bytes(value)?),
                KEY_BUNDLE_FULCIO_CERT_DER => fulcio_cert_der = Some(into_bytes(value)?),
                KEY_BUNDLE_REKOR => {
                    rekor_bundle = Some(RekorBundle::from_canonical_cbor(&into_bytes(value)?)?);
                }
                KEY_BUNDLE_REKOR_SIGNING_TIME => {
                    rekor_signing_time_unix = Some(int_to_u64(&value)?);
                }
                KEY_BUNDLE_SIGSUM_EMITTED_LEAF => {
                    sigsum_emitted_leaf = Some(
                        EmittedLeaf::from_canonical_cbor(&into_bytes(value)?)
                            .map_err(|_| SigstoreVerifyError::ReleaseBundleDecodeFailed)?,
                    );
                }
                KEY_BUNDLE_SIGSUM_TREE_HEAD => sigsum_tree_head_body = Some(into_text(value)?),
                KEY_BUNDLE_SIGSUM_INCLUSION_PROOF => {
                    sigsum_inclusion_proof_body = Some(into_text(value)?);
                }
                _ => {} // forward-compat per D0006 §6.4
            }
        }
        Ok(Self {
            manifest_bytes: manifest_bytes.ok_or(SigstoreVerifyError::ReleaseBundleDecodeFailed)?,
            manifest_signature: manifest_signature
                .ok_or(SigstoreVerifyError::ReleaseBundleDecodeFailed)?,
            fulcio_cert_der: fulcio_cert_der
                .ok_or(SigstoreVerifyError::ReleaseBundleDecodeFailed)?,
            rekor_bundle: rekor_bundle.ok_or(SigstoreVerifyError::ReleaseBundleDecodeFailed)?,
            rekor_signing_time_unix: rekor_signing_time_unix
                .ok_or(SigstoreVerifyError::ReleaseBundleDecodeFailed)?,
            sigsum_emitted_leaf: sigsum_emitted_leaf
                .ok_or(SigstoreVerifyError::ReleaseBundleDecodeFailed)?,
            sigsum_tree_head_body: sigsum_tree_head_body
                .ok_or(SigstoreVerifyError::ReleaseBundleDecodeFailed)?,
            sigsum_inclusion_proof_body: sigsum_inclusion_proof_body
                .ok_or(SigstoreVerifyError::ReleaseBundleDecodeFailed)?,
        })
    }
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
    /// the online Rekor fetch path only — gated off by default so the
    /// offline verifier compiles no network surface (D0041 §6.1).
    #[cfg(feature = "online-rekor")]
    http: reqwest::Client,
    /// Pinned Fulcio root in PEM bytes per D0024 §2.
    #[allow(dead_code, reason = "v1 skeleton; populated for the Fulcio body")]
    fulcio_root_pem: Vec<u8>,
    /// Pinned Rekor public key (PEM/SPKI, ECDSA P-256) per D0024 §3. Used
    /// by the offline `verify_release` Rekor check (and, under the
    /// `online-rekor` feature, by `fetch_and_verify_rekor`).
    rekor_pubkey_pem: Vec<u8>,
    /// Optional pinned CT-log public key (PEM/SPKI) — `Some` enforces the
    /// embedded SCT in `verify_release` (D0042 §6.5); `None` skips it
    /// (synthetic roots, no CT transparency).
    ctlog_pubkey_pem: Option<Vec<u8>>,
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
    #[cfg_attr(
        not(feature = "online-rekor"),
        allow(
            clippy::unnecessary_wraps,
            reason = "Result kept for API stability + the online-rekor variant, which is fallible"
        )
    )]
    pub fn new(config: SigstoreVerifierConfig) -> Result<Self, SigstoreVerifyError> {
        #[cfg(feature = "online-rekor")]
        let http =
            reqwest::Client::builder()
                .build()
                .map_err(|_| SigstoreVerifyError::Network {
                    retry_budget_used: 0,
                })?;
        Ok(Self {
            #[cfg(feature = "online-rekor")]
            http,
            fulcio_root_pem: config.fulcio_root_pem,
            rekor_pubkey_pem: config.rekor_pubkey_pem,
            ctlog_pubkey_pem: config.ctlog_pubkey_pem,
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
    /// 1. Decode the [`ReleaseManifest`] from the bundle's canonical-CBOR
    ///    `manifest_bytes` — the exact blob the detached signature covers
    ///    (D0042 §3; no COSE wrapper).
    /// 2. Validate the Fulcio cert chain + OIDC pins
    ///    ([`validate_cert_chain`]), yielding the developer's ECDSA P-256
    ///    signing key.
    /// 3. Verify the detached ECDSA P-256 `manifest_signature` over
    ///    `manifest_bytes` against that key (the cosign sign-blob model;
    ///    D0042 §3 — third parties can `cosign verify-blob` the same pair).
    /// 4. Verify the Rekor inclusion proof + signed checkpoint
    ///    ([`verify_rekor_inclusion`]) against the pinned Rekor key, then
    ///    bind the proven-included entry to this signing event via
    ///    [`hashedrekord_leaf_hash`] (D0042 §6.6).
    /// 5. Enforce rollback resistance: the manifest's
    ///    `prior_release_hash` must equal `expected_predecessor_hash`
    ///    when supplied (D0024 §4.2).
    /// 6. Verify the witness-cosigned Sigsum-anchored release-log
    ///    inclusion (D0024 §5) **offline** via
    ///    [`SigsumClient::verify_bundled_inclusion`]: bind the bundled
    ///    proof to this release's leaf hash (SHA-256 of the detached
    ///    signature; D0042 §3), re-verify the
    ///    cosigned head + 2-of-3 threshold, and reconstruct the RFC 6962
    ///    root.
    ///
    /// All six steps are offline: the bundle is self-contained, so a
    /// verifier with the pinned trust roots makes no network calls.
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
    /// [`SigstoreVerifyError::RekorCheckpointVerifyFailed`] /
    /// [`SigstoreVerifyError::RekorEntryBindingFailed`],
    /// [`SigstoreVerifyError::ManifestPriorHashMismatch`],
    /// [`SigstoreVerifyError::SigsumReleaseLog`] (the wrapped Sigsum
    /// failure pinpoints the cause).
    #[allow(
        clippy::unused_async,
        reason = "offline-bundle verification is synchronous (incl. the Sigsum step); async is retained per the D0024 §6 surface for the online-fetch composition"
    )]
    pub async fn verify_release(
        &self,
        bundle: &ReleaseBundle,
        expected_predecessor_hash: Option<[u8; 32]>,
    ) -> Result<VerifiedRelease, SigstoreVerifyError> {
        // (1) Decode the manifest directly from its canonical-CBOR bytes —
        // the blob the detached signature covers (D0042 §3; no COSE wrapper,
        // so a third party can `cosign verify-blob` the same artifact).
        let manifest = ReleaseManifest::from_canonical_cbor(&bundle.manifest_bytes)?;

        // (2) Fulcio cert chain + OIDC pins -> developer ECDSA P-256 key.
        let dev_key = validate_cert_chain(
            &bundle.fulcio_cert_der,
            &self.fulcio_root_pem,
            &self.expected_oidc_issuer,
            &self.expected_oidc_email,
            bundle.rekor_signing_time_unix,
        )?;

        // (3) Detached ECDSA P-256 signature over the manifest bytes,
        // against the Fulcio-bound key (the cosign sign-blob model; D0042
        // §3). No external AAD: the blob is the canonical-CBOR manifest,
        // signed exactly as stock cosign would.
        let signature = Signature::from_der(&bundle.manifest_signature)
            .map_err(|_| SigstoreVerifyError::ManifestSignatureVerifyFailed)?;
        dev_key
            .verify(&bundle.manifest_bytes, &signature)
            .map_err(|_| SigstoreVerifyError::ManifestSignatureVerifyFailed)?;

        // (3b) Embedded SCT (D0042 §6.5): when a CT-log key is pinned (real
        // Sigstore roots, where every Fulcio leaf is CT-logged), enforce
        // that the leaf carries a valid Signed Certificate Timestamp from
        // that log — proving the cert is publicly transparency-logged. The
        // precert issuer is the Fulcio intermediate from the pinned chain.
        // Skipped entirely when no CT-log key is configured (synthetic
        // roots / the phase-1 producer, whose rcgen leaves carry no SCT).
        if let Some(ctlog_pubkey_pem) = self.ctlog_pubkey_pem.as_deref() {
            let ctlog_der = Pem::iter_from_buffer(ctlog_pubkey_pem)
                .next()
                .and_then(Result::ok)
                .map(|p| p.contents)
                .ok_or(SigstoreVerifyError::SctVerifyFailed)?;
            let issuer_der =
                crate::fulcio::issuer_cert_der_for(&bundle.fulcio_cert_der, &self.fulcio_root_pem)
                    .ok_or(SigstoreVerifyError::SctVerifyFailed)?;
            crate::sct::verify_embedded_sct(&bundle.fulcio_cert_der, &issuer_der, &ctlog_der)?;
        }

        // (4) Rekor inclusion proof + signed checkpoint (offline, against
        // the pinned Rekor key).
        verify_rekor_inclusion(&bundle.rekor_bundle, &self.rekor_pubkey_pem)?;

        // (4b) Entry-type binding (D0042 §6.6): the inclusion proof above
        // only proves "an entry with this leaf hash is in Rekor". Bind it to
        // THIS signing event by reconstructing the `hashedrekord` leaf hash
        // from the manifest's artifact hash + the detached signature + the
        // Fulcio cert (the cosign sign-blob entry commits to all three), and
        // requiring it to equal the proven-included leaf. Without this, a
        // valid inclusion proof for an unrelated logged entry would pass.
        let artifact_sha256: [u8; 32] = Sha256::digest(&bundle.manifest_bytes).into();
        let expected_rekor_leaf = hashedrekord_leaf_hash(
            &artifact_sha256,
            &bundle.manifest_signature,
            &bundle.fulcio_cert_der,
        );
        if expected_rekor_leaf != bundle.rekor_bundle.leaf_hash {
            return Err(SigstoreVerifyError::RekorEntryBindingFailed);
        }

        // (5) Rollback resistance (D0024 §4.2).
        if let Some(expected) = expected_predecessor_hash
            && manifest.prior_release_hash.as_slice() != expected.as_slice()
        {
            return Err(SigstoreVerifyError::ManifestPriorHashMismatch);
        }

        // (6) Sigsum-anchored release log (D0024 §5): bind the bundled,
        // offline inclusion proof to THIS release's leaf hash and
        // re-verify it (cosigned head + 2-of-3 threshold + RFC 6962 root)
        // against the composed client's pinned log key + witness pool. The
        // release leaf hash is recomputed from the detached signature
        // (SHA-256 of the verified `manifest_signature`; D0042 §3), so a
        // proof for any other leaf fails the binding check.
        let release_leaf_hash = release_leaf_hash_for_signature(&bundle.manifest_signature);
        self.sigsum_client.verify_bundled_inclusion(
            &release_leaf_hash,
            &bundle.sigsum_emitted_leaf,
            &bundle.sigsum_tree_head_body,
            &bundle.sigsum_inclusion_proof_body,
        )?;

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
    #[cfg(feature = "online-rekor")]
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
    #[cfg(feature = "online-rekor")]
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
    #[cfg(feature = "online-rekor")]
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
            ctlog_pubkey_pem: None,
            expected_oidc_issuer: "https://accounts.example.org".to_string(),
            expected_oidc_email: "maintainer@cairn-project.org".to_string(),
            sigsum_client: make_sigsum_client(),
            default_retry_budget: RetryBudget::default(),
        };
        SigstoreVerifier::new(config).unwrap()
    }

    fn make_release_bundle() -> ReleaseBundle {
        ReleaseBundle {
            // Not valid canonical-CBOR for a ReleaseManifest, so
            // verify_release fails at the first (manifest-decode) gate
            // before the detached-signature check is reached.
            manifest_bytes: vec![0xAA; 64],
            manifest_signature: vec![0x55; 72],
            fulcio_cert_der: vec![0xBB; 128],
            rekor_bundle: RekorBundle {
                leaf_hash: [0xCC; 32],
                leaf_index: 100,
                proof_nodes: vec![[0x11; 32]],
                checkpoint_note: b"rekor.example/test\n1024\nAAAA\n".to_vec(),
                checkpoint_signature: vec![0xEE; 64],
            },
            rekor_signing_time_unix: 1_700_000_000,
            // Placeholder Sigsum proof: this bundle is only used to assert
            // verify_release fails at the first (manifest-decode) gate, so
            // step (6) is never reached. The full valid + tampered Sigsum
            // paths are covered in tests/verify_release.rs.
            sigsum_emitted_leaf: EmittedLeaf {
                message: [0; 32],
                signature: [0; 64],
                key_hash: [0; 32],
                observed_at: 0,
            },
            sigsum_tree_head_body: String::new(),
            sigsum_inclusion_proof_body: String::new(),
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
    async fn verify_release_rejects_malformed_manifest_bytes() {
        // The placeholder bundle's manifest bytes are not valid
        // canonical-CBOR for a ReleaseManifest, so verify_release fails at
        // the first (decode) gate before the detached-P-256 signature
        // check. The full happy-path + per-layer failure composition is
        // covered end-to-end in tests/verify_release.rs (it needs rcgen
        // certs + a P-256-signed manifest + a valid Rekor bundle).
        let verifier = make_verifier();
        let bundle = make_release_bundle();
        let result = verifier.verify_release(&bundle, None).await;
        assert!(matches!(
            result,
            Err(SigstoreVerifyError::ManifestDecodeFailed)
        ));
    }

    #[test]
    fn release_bundle_round_trips_through_canonical_cbor() {
        let original = make_release_bundle();
        let bytes = original.to_canonical_cbor().unwrap();
        let recovered = ReleaseBundle::from_canonical_cbor(&bytes).unwrap();
        // ReleaseBundle / RekorBundle don't derive PartialEq (the verifier
        // path owns a non-Eq SigsumClient), so assert canonical-byte
        // identity on re-encode + spot-check representative fields across
        // all three nesting layers (top-level bytes, nested RekorBundle,
        // nested Sigsum EmittedLeaf).
        assert_eq!(recovered.to_canonical_cbor().unwrap(), bytes);
        assert_eq!(recovered.manifest_bytes, original.manifest_bytes);
        assert_eq!(recovered.manifest_signature, original.manifest_signature);
        assert_eq!(recovered.fulcio_cert_der, original.fulcio_cert_der);
        assert_eq!(
            recovered.rekor_signing_time_unix,
            original.rekor_signing_time_unix
        );
        assert_eq!(
            recovered.rekor_bundle.leaf_index,
            original.rekor_bundle.leaf_index
        );
        assert_eq!(
            recovered.rekor_bundle.leaf_hash,
            original.rekor_bundle.leaf_hash
        );
        assert_eq!(recovered.sigsum_emitted_leaf, original.sigsum_emitted_leaf);
        assert_eq!(
            recovered.sigsum_tree_head_body,
            original.sigsum_tree_head_body
        );
    }

    #[test]
    fn release_bundle_decode_rejects_malformed_cbor() {
        let result = ReleaseBundle::from_canonical_cbor(b"\xFF\x00\x01");
        assert!(matches!(
            result,
            Err(SigstoreVerifyError::ReleaseBundleDecodeFailed)
        ));
    }

    #[test]
    fn rekor_bundle_round_trips_with_multiple_proof_nodes() {
        // Exercises the array_of_array_32 audit-path decode with a
        // realistic multi-node proof + a DER-length checkpoint signature.
        let original = RekorBundle {
            leaf_hash: [0x42; 32],
            leaf_index: 7,
            proof_nodes: vec![[0x11; 32], [0x22; 32], [0x33; 32]],
            checkpoint_note: b"rekor.example/test\n8\nAAAA\n".to_vec(),
            checkpoint_signature: vec![0xAB; 70],
        };
        let bytes = original.to_canonical_cbor().unwrap();
        let recovered = RekorBundle::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(recovered.leaf_hash, original.leaf_hash);
        assert_eq!(recovered.leaf_index, original.leaf_index);
        assert_eq!(recovered.proof_nodes, original.proof_nodes);
        assert_eq!(recovered.checkpoint_note, original.checkpoint_note);
        assert_eq!(
            recovered.checkpoint_signature,
            original.checkpoint_signature
        );
    }

    /// Re-encode `valid` canonical-CBOR map bytes with the first `(key,
    /// value)` entry duplicated, so the first integer key appears twice.
    /// Exercises the duplicate-key strictness gate (D0041 §6.3) without
    /// hand-assembling CBOR.
    fn duplicate_first_map_key(valid: &[u8]) -> Vec<u8> {
        let value: ciborium::Value = ciborium::de::from_reader(valid).unwrap();
        let ciborium::Value::Map(mut entries) = value else {
            panic!("expected a top-level CBOR map");
        };
        let first = entries[0].clone();
        entries.push(first);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Map(entries), &mut out).unwrap();
        out
    }

    #[test]
    fn release_bundle_rejects_trailing_bytes() {
        // The canonical wire form is exactly one CBOR item; a trailing byte
        // is a malleability vector the strict decoder must reject (D0041 §6.3).
        let mut bytes = make_release_bundle().to_canonical_cbor().unwrap();
        bytes.push(0x00);
        assert!(matches!(
            ReleaseBundle::from_canonical_cbor(&bytes),
            Err(SigstoreVerifyError::ReleaseBundleDecodeFailed)
        ));
    }

    #[test]
    fn release_bundle_rejects_duplicate_key() {
        // Duplicate integer keys are non-canonical (D0018 §2.3) and a
        // parser-differential footgun; the strict decoder must reject them.
        let valid = make_release_bundle().to_canonical_cbor().unwrap();
        let dup = duplicate_first_map_key(&valid);
        assert!(matches!(
            ReleaseBundle::from_canonical_cbor(&dup),
            Err(SigstoreVerifyError::ReleaseBundleDecodeFailed)
        ));
    }
}
