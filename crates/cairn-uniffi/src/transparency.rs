// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Transparency export surface (D0027 §2 — the `transparency` module).
//!
//! The **first async** opaque `uniffi::Object`: [`SigsumClientHandle`]
//! over `cairn_sigsum_client::SigsumClient`. Its network methods export
//! as Kotlin `suspend fun`s via `#[uniffi::export(async_runtime =
//! "tokio")]` (D0027 §5); cairn-uniffi owns the single tokio runtime the
//! attribute registers.
//!
//! ## Shared storage
//!
//! `SigsumClient::new` takes an `Arc<Storage>`. The handle is
//! constructed from a [`crate::storage::StorageHandle`] and shares its
//! `Arc<Storage>` (via the crate-internal `storage_arc` accessor) so the
//! Sigsum cache lives in the same unlocked store as the rest of the app —
//! no second connection, no second DEK derivation.
//!
//! ## Hardware-signed emit (the security boundary)
//!
//! `emit_op` submits a trust-graph op's leaf to the log. The Sigsum
//! tree-leaf is signed by the operational identity, whose key lives in
//! StrongBox (the StrongBox-only decision, D0027 §2.2). So emit does NOT
//! take a software signing key — it takes the
//! [`crate::hardware::HardwareKeySigner`] callback, bridged into
//! `cairn_sigsum_client::TreeLeafSigner` by a crate-internal adapter.
//! The key signs in hardware; only the resulting signature bytes cross.
//! The
//! read methods (`refresh_tree_head`, `verify_inclusion`) need no key.

use std::sync::Arc;

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, VerifyingKey};
use cairn_sigsum_client::{
    RetryBudget, SigsumClient, SigsumClientConfig, SigsumError, TreeLeafSigner, parse_witness_pool,
};
use cairn_trust_graph::SignedTrustGraphOp;
use url::Url;

use crate::error::CairnFfiError;
use crate::hardware::HardwareKeySigner;
use crate::storage::StorageHandle;

/// Pinned configuration for a Sigsum log (D0027 §2.2).
///
/// All public values: the log URL, the log's 32-byte Ed25519 pubkey,
/// the witness pool as `witnesses.toml` text (parsed Rust-side), and a
/// retry-attempt cap. Becomes a `uniffi::Record` under the feature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct SigsumLogConfig {
    /// HTTPS endpoint of the Sigsum log.
    pub log_url: String,
    /// The log's pinned Ed25519 public key (32 bytes).
    pub log_pubkey: Vec<u8>,
    /// The release's `witnesses.toml` text; parsed into the witness
    /// pool (2-of-3 cosignature threshold per D0023 §3.4).
    pub witnesses_toml: String,
    /// Maximum network retry attempts (the backoff delays use the
    /// D0023 §5.3 defaults).
    pub max_retries: u8,
}

/// Convert the FFI config into a `cairn_sigsum_client::SigsumClientConfig`,
/// parsing the URL, pubkey, and witness pool. Ordered so the
/// cheap/structural failures surface before witness parsing.
fn to_client_config(config: &SigsumLogConfig) -> Result<SigsumClientConfig, CairnFfiError> {
    let log_url = Url::parse(&config.log_url).map_err(|_| CairnFfiError::MalformedData)?;
    let pubkey_bytes: [u8; PUBLIC_KEY_LEN] = config
        .log_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| CairnFfiError::MalformedData)?;
    let log_pubkey =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| CairnFfiError::MalformedData)?;
    let witness_pool =
        parse_witness_pool(&config.witnesses_toml).map_err(|_| CairnFfiError::MalformedData)?;
    Ok(SigsumClientConfig {
        log_url,
        log_pubkey,
        witness_pool,
        default_retry_budget: RetryBudget {
            max_retries: config.max_retries,
            ..RetryBudget::default()
        },
    })
}

/// Bridges a [`HardwareKeySigner`] callback into the
/// `cairn_sigsum_client::TreeLeafSigner` the emit path consumes. The
/// operational key signs in StrongBox; only the signature bytes cross.
struct FfiTreeLeafSigner {
    signer: Box<dyn HardwareKeySigner>,
    key_alias: String,
    public_key: [u8; PUBLIC_KEY_LEN],
}

impl TreeLeafSigner for FfiTreeLeafSigner {
    fn sign_tree_leaf(&self, signing_input: &[u8]) -> Result<[u8; 64], SigsumError> {
        let signature = self
            .signer
            .sign(self.key_alias.clone(), signing_input.to_vec())
            .map_err(|_| SigsumError::LeafSignFailed)?;
        signature
            .as_slice()
            .try_into()
            .map_err(|_| SigsumError::LeafSignFailed)
    }

    fn submitter_public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public_key
    }
}

/// Public fields of a Sigsum tree head (D0027 §2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct TreeHeadRecord {
    /// Number of leaves in the log at this head.
    pub tree_size: u64,
    /// Root hash of the Merkle tree at `tree_size` (32 bytes).
    pub root_hash: Vec<u8>,
    /// Log-provided Unix-seconds timestamp at signing.
    pub timestamp: u64,
}

/// An opaque async handle to a Sigsum log (D0027 §2.2). Holds the
/// `cairn_sigsum_client::SigsumClient`, sharing the `StorageHandle`'s
/// `Arc<Storage>` for cache state.
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct SigsumClientHandle {
    client: SigsumClient,
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
impl SigsumClientHandle {
    /// Construct a Sigsum client over `storage`'s shared store and the
    /// pinned `config`.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if the URL, pubkey, or
    ///   `witnesses.toml` is malformed.
    /// - [`CairnFfiError::Network`] / [`CairnFfiError::UnmappedInternal`]
    ///   if the HTTPS client cannot be constructed.
    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI constructors take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub fn new(
        storage: Arc<StorageHandle>,
        config: SigsumLogConfig,
    ) -> Result<Arc<Self>, CairnFfiError> {
        let client_config = to_client_config(&config)?;
        let client =
            SigsumClient::new(client_config, storage.storage_arc()).map_err(CairnFfiError::from)?;
        Ok(Arc::new(Self { client }))
    }
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export(async_runtime = "tokio"))]
impl SigsumClientHandle {
    /// Refresh + verify the log's tree head (fetch `get-tree-head`,
    /// verify the log signature + the 2-of-3 witness cosignatures,
    /// split-view-check, cache). Returns the accepted head.
    ///
    /// # Errors
    ///
    /// The facade mapping of `SigsumError` (D0027 §3): witness-threshold,
    /// split-view, network, etc.
    pub async fn refresh_tree_head(&self) -> Result<TreeHeadRecord, CairnFfiError> {
        let head = self
            .client
            .refresh_tree_head()
            .await
            .map_err(CairnFfiError::from)?;
        Ok(TreeHeadRecord {
            tree_size: head.tree_size,
            root_hash: head.root_hash.to_vec(),
            timestamp: head.timestamp,
        })
    }

    /// Verify that `signed_op`'s leaf is included in the log (loads the
    /// emit-time leaf, fetches a fresh head + inclusion proof, checks the
    /// RFC 6962 reconstruction). `Ok(())` means verified-included.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `signed_op` is not
    ///   well-formed.
    /// - [`CairnFfiError::SigsumVerifyFailed`] if the op is not included
    ///   or the proof does not verify.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn verify_inclusion(&self, signed_op: Vec<u8>) -> Result<(), CairnFfiError> {
        let op =
            SignedTrustGraphOp::from_bytes(&signed_op).map_err(|_| CairnFfiError::MalformedData)?;
        self.client
            .verify_inclusion(&op)
            .await
            .map(|_proof| ())
            .map_err(CairnFfiError::from)
    }

    /// Emit `signed_op`'s leaf to the log, signing the Sigsum tree-leaf
    /// via the StrongBox `signer` callback (the key never crosses).
    /// Returns the emitted leaf hash.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `signed_op` or
    ///   `submitter_pubkey` is malformed.
    /// - [`CairnFfiError::SignatureVerifyFailed`] if the StrongBox signer
    ///   fails (mapped from `LeafSignFailed`).
    /// - [`CairnFfiError::Network`] if the `add-leaf` POST never commits.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn emit_op(
        &self,
        signed_op: Vec<u8>,
        signer: Box<dyn HardwareKeySigner>,
        key_alias: String,
        submitter_pubkey: Vec<u8>,
    ) -> Result<Vec<u8>, CairnFfiError> {
        let op =
            SignedTrustGraphOp::from_bytes(&signed_op).map_err(|_| CairnFfiError::MalformedData)?;
        let public_key: [u8; PUBLIC_KEY_LEN] = submitter_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        let ffi_signer = FfiTreeLeafSigner {
            signer,
            key_alias,
            public_key,
        };
        let leaf_hash = self
            .client
            .emit_leaf_with_signer(&op, &ffi_signer)
            .await
            .map_err(CairnFfiError::from)?;
        Ok(leaf_hash.as_bytes().to_vec())
    }
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

    use crate::hardware::{AttestationCertificate, HardwarePublicKey, KeyGenSpec};

    /// A mock HardwareKeySigner returning a fixed 64-byte signature.
    struct MockSigner;
    impl HardwareKeySigner for MockSigner {
        fn sign(&self, _key_alias: String, _payload: Vec<u8>) -> Result<Vec<u8>, CairnFfiError> {
            Ok(vec![0x42u8; 64])
        }
        fn generate_key(
            &self,
            _key_alias: String,
            _spec: KeyGenSpec,
        ) -> Result<HardwarePublicKey, CairnFfiError> {
            Ok(HardwarePublicKey { encoded: vec![] })
        }
        fn attestation_chain(
            &self,
            _key_alias: String,
        ) -> Result<Vec<AttestationCertificate>, CairnFfiError> {
            Ok(vec![])
        }
    }

    /// Hex-encode bytes (no hex dep) for the witnesses.toml fixture.
    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// A minimal valid `witnesses.toml` with three witnesses.
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

    #[test]
    fn ffi_tree_leaf_signer_bridges_callback() {
        let pubkey = [0xCDu8; PUBLIC_KEY_LEN];
        let bridge = FfiTreeLeafSigner {
            signer: Box::new(MockSigner),
            key_alias: "op-identity".to_string(),
            public_key: pubkey,
        };
        // The bridge returns the callback's signature + the configured pubkey.
        assert_eq!(
            bridge.sign_tree_leaf(b"signing-input").unwrap(),
            [0x42u8; 64]
        );
        assert_eq!(bridge.submitter_public_key(), pubkey);
    }

    #[test]
    fn config_rejects_bad_url_and_pubkey() {
        let mut rng = OsRng;
        let good_pubkey = SigningKey::generate(&mut rng)
            .verifying_key()
            .to_bytes()
            .to_vec();

        // Bad URL → MalformedData (fails before witness parsing).
        let bad_url = SigsumLogConfig {
            log_url: "not a url".to_string(),
            log_pubkey: good_pubkey,
            witnesses_toml: String::new(),
            max_retries: 3,
        };
        assert_eq!(
            to_client_config(&bad_url).unwrap_err(),
            CairnFfiError::MalformedData
        );

        // Wrong-length pubkey → MalformedData.
        let bad_pubkey = SigsumLogConfig {
            log_url: "https://log.example".to_string(),
            log_pubkey: vec![0u8; 31],
            witnesses_toml: witnesses_toml(),
            max_retries: 3,
        };
        assert_eq!(
            to_client_config(&bad_pubkey).unwrap_err(),
            CairnFfiError::MalformedData
        );
    }

    #[tokio::test]
    async fn refresh_against_unreachable_log_errors() {
        // A well-formed config pointed at an unreachable port exercises
        // the async export end-to-end (tokio runtime + await + error
        // mapping); the network failure must surface as an error, not a
        // panic. The real network ops are wiremock-tested in
        // cairn-sigsum-client.
        let mut rng = OsRng;
        let log_pubkey = SigningKey::generate(&mut rng)
            .verifying_key()
            .to_bytes()
            .to_vec();
        let config = SigsumLogConfig {
            log_url: "http://127.0.0.1:1".to_string(),
            log_pubkey,
            witnesses_toml: witnesses_toml(),
            max_retries: 0,
        };
        let client = SigsumClient::new(to_client_config(&config).unwrap(), test_storage()).unwrap();
        let handle = SigsumClientHandle { client };
        assert!(handle.refresh_tree_head().await.is_err());
    }

    /// A shared in-memory Storage for the async test (production Argon2
    /// once).
    fn test_storage() -> Arc<cairn_storage::Storage> {
        use cairn_storage::key_provider::testing::InMemoryKeyProvider;
        use zeroize::Zeroizing;
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"test-passphrase".to_vec());
        Arc::new(cairn_storage::Storage::open_in_memory(&provider, &passphrase).unwrap())
    }
}
