// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Release-verification export surface (D0024 §6 client side / D0041).
//!
//! The Kotlin-facing counterpart to `cairn-release`: given a pinned set
//! of release trust roots and a producer-emitted `release-bundle.cbor`,
//! [`ReleaseVerifierHandle::verify`] replays the full offline
//! `cairn_sigstore_verify::SigstoreVerifier::verify_release` orchestration
//! on-device — Fulcio chain + OIDC pins, manifest `COSE_Sign1` signature,
//! Rekor inclusion, `prior_release_hash` rollback resistance, and the
//! witness-cosigned Sigsum release-log inclusion — and surfaces only the
//! decoded manifest on success (no proof bytes cross to Kotlin).
//!
//! ## Shared storage
//!
//! Like [`crate::transparency::SigsumClientHandle`], the composed
//! `SigsumClient` is constructed over the app's unlocked
//! [`StorageHandle`] `Arc<Storage>`. The offline `verify_bundled_inclusion`
//! path does not persist, but the client constructor requires a store, so
//! reusing the app's avoids a second connection / DEK derivation.
//!
//! ## Trust-root posture (D0041 §6.1)
//!
//! [`ReleaseRootsRecord`] is the typed form of `cairn-release`'s
//! `release-roots.json`. Two constructors enforce the phase boundary so
//! phase 1's caller-supplied shape cannot silently reach production:
//!
//! - [`ReleaseVerifierHandle::new`] takes caller-supplied roots, but only
//!   *functions* under the `synthetic-release-roots` cargo feature (the
//!   per-build self-minted-roots proof, which the DEBUG driver builds
//!   with). A shipped build without that feature REFUSES them
//!   ([`CairnFfiError::ReleaseRootsNotProvisioned`]).
//! - [`ReleaseVerifierHandle::new_pinned`] is the production path: it uses
//!   the compiled-in [`PRODUCTION_ROOTS`] (the real Fulcio root, Rekor
//!   key, project OIDC identity, recruited Sigsum log + witness pool) and
//!   accepts nothing from the caller.
//!
//! `PRODUCTION_ROOTS` is `None` until phase 2/3 mints + bakes the real
//! anchors, so the production path is a tripwire: a shipped build can
//! neither accept caller roots (`new`) nor build from absent baked roots
//! (`new_pinned`), forcing phase 2 to provision real roots rather than
//! inherit the phase-1 shape.

use std::sync::Arc;

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, VerifyingKey};
use cairn_sigstore_verify::{ReleaseBundle, SigstoreVerifier, SigstoreVerifierConfig};
use cairn_sigsum_client::{RetryBudget, SigsumClient, SigsumClientConfig, parse_witness_pool};
use cairn_storage::Storage;
use url::Url;

use crate::error::CairnFfiError;
use crate::storage::StorageHandle;

/// Length of a release manifest's `prior_release_hash` / artifact SHA-256.
const SHA256_LEN: usize = 32;

/// Compiled-in production release trust roots (D0041 §6.1 phase 2/3).
/// `None` until the real Fulcio root / Rekor key / project OIDC identity
/// / recruited Sigsum log + witness pool are minted and baked into the
/// shipping binary. While `None`, [`ReleaseVerifierHandle::new_pinned`]
/// returns [`CairnFfiError::ReleaseRootsNotProvisioned`] — the tripwire
/// that forces phase 2 to provision real roots rather than inherit phase
/// 1's caller-supplied shape. (`None` of a non-`const`-constructible type
/// is itself a valid `const`.)
///
/// **When provisioning this, set [`ReleaseRootsRecord::ctlog_pubkey_pem`]**
/// to the matching CT-log key (a real Fulcio root without it silently
/// disables the embedded-SCT / CT-transparency defense — see that field's
/// docs and `SigstoreVerifierConfig::ctlog_pubkey_pem`). The proven
/// Fulcio+CT+Rekor anchor triples live in `cairn_sigstore_verify::anchors`.
const PRODUCTION_ROOTS: Option<ReleaseRootsRecord> = None;

/// The pinned release trust roots (the typed form of `cairn-release`'s
/// `release-roots.json`). All public values. Becomes a `uniffi::Record`
/// under the feature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct ReleaseRootsRecord {
    /// Pinned Fulcio root certificate, PEM (D0024 §2).
    pub fulcio_root_pem: String,
    /// Pinned Rekor public key, PEM/SPKI (D0024 §3).
    pub rekor_pubkey_pem: String,
    /// Pinned CT-log public key, PEM/SPKI (RFC 6962), or `None` to skip
    /// embedded-SCT enforcement (D0042 §6.5). Synthetic rcgen leaves carry
    /// no SCT extension, so the `synthetic-release-roots` path leaves this
    /// `None`; real keyless roots set it to the CT log that countersigns
    /// Fulcio precertificates, making `verify_release` reject any leaf whose
    /// embedded SCT does not verify under this key. Defaulted to `None` so
    /// existing Kotlin callers (which omit it) compile unchanged.
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default = None))]
    pub ctlog_pubkey_pem: Option<String>,
    /// Expected OIDC issuer URL (D0024 §1.1).
    pub oidc_issuer: String,
    /// Expected developer identity email (D0024 §1.1) — used iff
    /// `oidc_san_uri` is `None`.
    pub oidc_email: String,
    /// Expected CI workflow SAN URI (keyless cosign, D0042 §2). `Some`
    /// pins this URI identity instead of the email; defaulted `None` so
    /// existing Kotlin callers (which omit it) compile unchanged.
    #[cfg_attr(feature = "uniffi-bindings", uniffi(default = None))]
    pub oidc_san_uri: Option<String>,
    /// The Sigsum log's pinned Ed25519 public key (32 bytes).
    pub sigsum_log_pubkey: Vec<u8>,
    /// The release's `witnesses.toml` text (2-of-3 cosignature threshold
    /// per D0023 §3.4), parsed Rust-side.
    pub witnesses_toml: String,
}

/// One verified artifact's name + SHA-256 (D0024 §4.1 key 2). Becomes a
/// `uniffi::Record` under the feature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct ReleaseArtifactRecord {
    /// Human-readable artifact identifier, e.g. `"cairn-1.0.0.apk"`.
    pub name: String,
    /// SHA-256 digest of the artifact bytes (32 bytes).
    pub sha256: Vec<u8>,
}

/// The decoded + fully-verified release manifest surfaced on success.
/// Becomes a `uniffi::Record` under the feature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct VerifiedReleaseRecord {
    /// Semver string identifying the verified release.
    pub version: String,
    /// The verified artifact digest set.
    pub artifacts: Vec<ReleaseArtifactRecord>,
    /// Unix-seconds the manifest was signed.
    pub release_timestamp: u64,
}

/// An opaque handle wrapping a configured
/// `cairn_sigstore_verify::SigstoreVerifier` (D0027 §2 / D0024 §6).
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct ReleaseVerifierHandle {
    verifier: SigstoreVerifier,
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
impl ReleaseVerifierHandle {
    /// Construct a release verifier pinned to `roots`, composing a
    /// `SigsumClient` over `storage`'s shared store.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if the Sigsum log pubkey is not
    ///   32 bytes / not a valid key, or `witnesses.toml` fails to parse.
    /// - [`CairnFfiError::Network`] / [`CairnFfiError::UnmappedInternal`]
    ///   if the HTTPS client cannot be constructed.
    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI constructors take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub fn new(
        storage: Arc<StorageHandle>,
        roots: ReleaseRootsRecord,
    ) -> Result<Arc<Self>, CairnFfiError> {
        // Tripwire (D0041 §6.1): a shipped build does NOT accept release
        // trust roots from the caller. Only the `synthetic-release-roots`
        // dev feature (the phase-1 proof, which the DEBUG driver builds
        // with) admits them; without it this refuses, forcing phase 2 to
        // provision real roots + use `new_pinned`. `cfg!` (not `#[cfg]`)
        // keeps `build_verifier` referenced in both builds — no dead-code
        // split, and the FFI binding surface is identical either way (the
        // Kotlin driver's `new(...)` call compiles unchanged).
        if cfg!(not(feature = "synthetic-release-roots")) {
            return Err(CairnFfiError::ReleaseRootsNotProvisioned);
        }
        let verifier = build_verifier(&roots, storage.storage_arc())?;
        Ok(Arc::new(Self { verifier }))
    }

    /// Construct a release verifier from the **compiled-in production
    /// trust roots** (D0041 §6.1). Unlike [`Self::new`], this accepts
    /// nothing from the caller — it is the only release path a shipped
    /// (non-`synthetic-release-roots`) build can use.
    ///
    /// # Errors
    ///
    /// [`CairnFfiError::ReleaseRootsNotProvisioned`] while
    /// [`PRODUCTION_ROOTS`] is `None` (phase 2/3 has not yet minted +
    /// baked the real anchors). Once provisioned, the same errors as
    /// [`Self::new`]'s `build_verifier` path.
    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI constructors take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub fn new_pinned(storage: Arc<StorageHandle>) -> Result<Arc<Self>, CairnFfiError> {
        if let Some(roots) = PRODUCTION_ROOTS {
            let verifier = build_verifier(&roots, storage.storage_arc())?;
            return Ok(Arc::new(Self { verifier }));
        }
        Err(CairnFfiError::ReleaseRootsNotProvisioned)
    }
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export(async_runtime = "tokio"))]
impl ReleaseVerifierHandle {
    /// Verify a producer-emitted `release-bundle.cbor` against the pinned
    /// roots. `expected_prior` is the predecessor manifest's SHA-256 (32
    /// bytes) for the rollback-resistance check, or `None` to skip it
    /// (e.g. a first install with no stored predecessor).
    ///
    /// Returns the verified manifest on success; every proof byte stays
    /// Rust-side per the no-error-oracle discipline (D0027 §3.2).
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `bundle_cbor` or
    ///   `expected_prior` is malformed.
    /// - [`CairnFfiError::SigstoreIdentityMismatch`] /
    ///   [`CairnFfiError::SigstoreChainInvalid`] /
    ///   [`CairnFfiError::SigstoreVerifyFailed`] /
    ///   [`CairnFfiError::SigsumVerifyFailed`] for the respective
    ///   verification-layer failures (D0024 §1-§5), including a
    ///   `prior_release_hash` rollback mismatch.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn verify(
        &self,
        bundle_cbor: Vec<u8>,
        expected_prior: Option<Vec<u8>>,
    ) -> Result<VerifiedReleaseRecord, CairnFfiError> {
        let bundle =
            ReleaseBundle::from_canonical_cbor(&bundle_cbor).map_err(CairnFfiError::from)?;
        let expected = match expected_prior {
            Some(bytes) => {
                let arr: [u8; SHA256_LEN] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| CairnFfiError::MalformedData)?;
                Some(arr)
            }
            None => None,
        };
        let verified = self
            .verifier
            .verify_release(&bundle, expected)
            .await
            .map_err(CairnFfiError::from)?;
        let artifacts = verified
            .manifest
            .artifact_sha256
            .into_iter()
            .map(|a| ReleaseArtifactRecord {
                name: a.name,
                sha256: a.sha256.to_vec(),
            })
            .collect();
        Ok(VerifiedReleaseRecord {
            version: verified.manifest.version,
            artifacts,
            release_timestamp: verified.manifest.release_timestamp,
        })
    }
}

/// Build a `SigstoreVerifier` from the pinned roots + a shared store.
fn build_verifier(
    roots: &ReleaseRootsRecord,
    storage: Arc<Storage>,
) -> Result<SigstoreVerifier, CairnFfiError> {
    let pubkey_bytes: [u8; PUBLIC_KEY_LEN] = roots
        .sigsum_log_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| CairnFfiError::MalformedData)?;
    let log_pubkey =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| CairnFfiError::MalformedData)?;
    let witness_pool =
        parse_witness_pool(&roots.witnesses_toml).map_err(|_| CairnFfiError::MalformedData)?;
    let sigsum_client = SigsumClient::new(
        SigsumClientConfig {
            // Offline bundled verify never fetches; the URL is only used by
            // the online fetch path the release client does not take.
            log_url: Url::parse("https://sigsum.invalid/")
                .map_err(|_| CairnFfiError::MalformedData)?,
            log_pubkey,
            witness_pool,
            default_retry_budget: RetryBudget::default(),
        },
        storage,
    )
    .map_err(CairnFfiError::from)?;
    SigstoreVerifier::new(SigstoreVerifierConfig {
        fulcio_root_pem: roots.fulcio_root_pem.clone().into_bytes(),
        rekor_pubkey_pem: roots.rekor_pubkey_pem.clone().into_bytes(),
        // `None` skips embedded-SCT enforcement (synthetic leaves carry no
        // SCT); a pinned CT-log key makes it mandatory (D0042 §6.5).
        ctlog_pubkey_pem: roots.ctlog_pubkey_pem.clone().map(String::into_bytes),
        expected_oidc_issuer: roots.oidc_issuer.clone(),
        expected_oidc_email: roots.oidc_email.clone(),
        expected_oidc_san_uri: roots.oidc_san_uri.clone(),
        sigsum_client,
        default_retry_budget: RetryBudget::default(),
    })
    .map_err(CairnFfiError::from)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests assert on known-shape fixtures; index/unwrap panics ARE the failure signal"
)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use rand_core::OsRng;
    use zeroize::Zeroizing;

    /// A shared in-memory store for the FFI-layer tests.
    fn test_storage() -> Arc<Storage> {
        use cairn_storage::key_provider::testing::InMemoryKeyProvider;
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"test-passphrase".to_vec());
        Arc::new(Storage::open_in_memory(&provider, &passphrase).unwrap())
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    fn witnesses_toml() -> String {
        let mut rng = OsRng;
        let mut toml = String::new();
        for i in 0..3 {
            let pk = SigningKey::generate(&mut rng).verifying_key().to_bytes();
            toml.push_str(&format!(
                "[[witness]]\nname = \"w{i}\"\npubkey_hex = \"{}\"\nurl = \"https://w{i}.example\"\n",
                hex(&pk)
            ));
        }
        toml
    }

    fn valid_roots() -> ReleaseRootsRecord {
        let log_pubkey = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        ReleaseRootsRecord {
            fulcio_root_pem: "-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----"
                .to_string(),
            rekor_pubkey_pem: "-----BEGIN PUBLIC KEY-----\nplaceholder\n-----END PUBLIC KEY-----"
                .to_string(),
            ctlog_pubkey_pem: None,
            oidc_issuer: "https://accounts.example.org".to_string(),
            oidc_email: "maintainer@cairn-project.org".to_string(),
            oidc_san_uri: None,
            sigsum_log_pubkey: log_pubkey.to_vec(),
            witnesses_toml: witnesses_toml(),
        }
    }

    #[test]
    fn build_verifier_accepts_valid_roots() {
        assert!(build_verifier(&valid_roots(), test_storage()).is_ok());
    }

    #[test]
    fn build_verifier_rejects_wrong_length_sigsum_pubkey() {
        let mut roots = valid_roots();
        roots.sigsum_log_pubkey = vec![0u8; 31];
        // SigstoreVerifier has no Debug impl, so match rather than unwrap_err.
        assert!(matches!(
            build_verifier(&roots, test_storage()),
            Err(CairnFfiError::MalformedData)
        ));
    }

    #[test]
    fn build_verifier_rejects_malformed_witness_pool() {
        let mut roots = valid_roots();
        roots.witnesses_toml = "this is not valid toml [[".to_string();
        // SigstoreVerifier has no Debug impl, so match rather than unwrap_err.
        assert!(matches!(
            build_verifier(&roots, test_storage()),
            Err(CairnFfiError::MalformedData)
        ));
    }

    #[tokio::test]
    async fn verify_rejects_malformed_bundle_bytes() {
        // Exercises the async export end-to-end (tokio runtime + await +
        // error mapping): a non-CBOR bundle fails at the decode gate and
        // surfaces as MalformedData, not a panic. The full happy-path +
        // per-layer failures are proven in cairn-release + verify_release.rs.
        let handle = ReleaseVerifierHandle {
            verifier: build_verifier(&valid_roots(), test_storage()).unwrap(),
        };
        let err = handle
            .verify(vec![0xff, 0x00, 0x01], None)
            .await
            .unwrap_err();
        assert_eq!(err, CairnFfiError::MalformedData);
    }

    // === D0041 §6.1 compiled-in-roots tripwire ===

    fn test_handle() -> Arc<StorageHandle> {
        StorageHandle::from_storage_arc_for_test(test_storage())
    }

    #[test]
    fn new_pinned_errors_until_roots_provisioned() {
        // The production path carries no compiled-in roots yet
        // (PRODUCTION_ROOTS is None), so it refuses — the tripwire that
        // forces phase 2 to bake real anchors. (No Debug on the handle, so
        // match rather than unwrap_err.)
        assert!(matches!(
            ReleaseVerifierHandle::new_pinned(test_handle()),
            Err(CairnFfiError::ReleaseRootsNotProvisioned)
        ));
    }

    #[cfg(not(feature = "synthetic-release-roots"))]
    #[test]
    fn new_refuses_caller_roots_without_synthetic_feature() {
        // A shipped build (no `synthetic-release-roots`) must NOT accept
        // caller-supplied roots — even structurally valid ones (D0041 §6.1).
        assert!(matches!(
            ReleaseVerifierHandle::new(test_handle(), valid_roots()),
            Err(CairnFfiError::ReleaseRootsNotProvisioned)
        ));
    }

    #[cfg(feature = "synthetic-release-roots")]
    #[test]
    fn new_accepts_caller_roots_under_synthetic_feature() {
        // The dev feature (the phase-1 self-minted-roots proof) admits
        // caller-supplied roots.
        assert!(ReleaseVerifierHandle::new(test_handle(), valid_roots()).is_ok());
    }
}
