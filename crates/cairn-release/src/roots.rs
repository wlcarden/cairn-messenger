// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! The trust-root sidecar (`release-roots.json`) the producer emits next
//! to the bundle, and the verifier-construction it drives.
//!
//! In the v1 self-minted-roots producer (D0041 phase 1) every field here
//! is generated per `build` invocation, so the bundle + its roots are
//! mutually consistent by construction. In the real-Sigstore path
//! (D0041 phase 2) these fields become the PINNED public trust roots
//! (Fulcio root, Rekor key, project OIDC identity, the recruited Sigsum
//! log + witness pool) baked into the shipping client — at which point
//! this sidecar is no longer transmitted, it is compiled in.
//!
//! The split matters for the proof's honesty: pinning roots that ship
//! alongside the artifact proves the verify MECHANICS, not the external
//! trust anchor. The on-device run is the oracle for "the producer emits
//! exactly what `verify_release` consumes"; it is explicitly NOT a claim
//! that a real Sigstore identity signed anything.

use std::sync::Arc;

use anyhow::{Context, Result};
use cairn_crypto::ed25519::VerifyingKey;
use cairn_sigstore_verify::{SigstoreVerifier, SigstoreVerifierConfig};
use cairn_sigsum_client::{RetryBudget, SigsumClient, SigsumClientConfig, parse_witness_pool};
use cairn_storage::Storage;
use cairn_storage::key_provider::testing::InMemoryKeyProvider;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

/// The trust-root sidecar serialized as `release-roots.json`.
///
/// PEMs are stored as UTF-8 strings (they already are PEM text); the
/// Sigsum log key is lower-hex of the 32-byte Ed25519 verifying key; the
/// witness pool is the same TOML `parse_witness_pool` consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseRoots {
    /// Pinned Fulcio root certificate, PEM.
    pub fulcio_root_pem: String,
    /// Pinned Rekor public key, PEM/SPKI.
    pub rekor_pubkey_pem: String,
    /// Expected OIDC issuer URL (D0024 §1.1).
    pub oidc_issuer: String,
    /// Expected developer identity email (D0024 §1.1).
    pub oidc_email: String,
    /// Sigsum log public key, lower-hex of the 32-byte Ed25519 key.
    pub sigsum_log_pubkey_hex: String,
    /// Witness pool TOML (D0023 §3.3), consumed by `parse_witness_pool`.
    pub witnesses_toml: String,
}

impl ReleaseRoots {
    /// Serialize to pretty JSON bytes for the `release-roots.json` sidecar.
    ///
    /// # Errors
    ///
    /// Propagates `serde_json` serialization failure (unreachable for
    /// this all-string struct).
    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self).context("serialize release roots")?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Parse from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or missing fields.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).context("parse release roots json")
    }

    /// Construct the [`SigstoreVerifier`] these roots pin.
    ///
    /// Backs the composed [`SigsumClient`] with a throwaway in-memory
    /// store (the offline `verify_bundled_inclusion` path never persists)
    /// and a placeholder log URL (only the online fetch path would use
    /// it). The Sigsum log key + witness pool ARE load-bearing: they pin
    /// the cosigned tree head the bundle must re-verify against.
    ///
    /// # Errors
    ///
    /// Returns an error if the log-key hex is malformed, the witness pool
    /// TOML fails to parse, the in-memory store fails to open, or the
    /// verifier rejects its config.
    pub fn build_verifier(&self) -> Result<SigstoreVerifier> {
        let log_pubkey = parse_log_pubkey(&self.sigsum_log_pubkey_hex)?;
        let witness_pool = parse_witness_pool(&self.witnesses_toml)
            .map_err(|e| anyhow::anyhow!("parse witness pool: {e}"))?;

        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"cairn-release-verify".to_vec());
        let storage = Arc::new(
            Storage::open_in_memory(&provider, &passphrase)
                .context("open in-memory store for verify")?,
        );
        let sigsum_client = SigsumClient::new(
            SigsumClientConfig {
                log_url: Url::parse("https://sigsum.invalid/")
                    .context("placeholder sigsum log url")?,
                log_pubkey,
                witness_pool,
                default_retry_budget: RetryBudget::default(),
            },
            storage,
        )
        .map_err(|e| anyhow::anyhow!("construct sigsum client: {e}"))?;

        SigstoreVerifier::new(SigstoreVerifierConfig {
            fulcio_root_pem: self.fulcio_root_pem.clone().into_bytes(),
            rekor_pubkey_pem: self.rekor_pubkey_pem.clone().into_bytes(),
            expected_oidc_issuer: self.oidc_issuer.clone(),
            expected_oidc_email: self.oidc_email.clone(),
            sigsum_client,
            default_retry_budget: RetryBudget::default(),
        })
        .map_err(|e| anyhow::anyhow!("construct sigstore verifier: {e}"))
    }
}

/// Parse a 64-char lower-hex string into a 32-byte Ed25519 verifying key.
fn parse_log_pubkey(hex: &str) -> Result<VerifyingKey> {
    let bytes = decode_hex_32(hex).context("decode sigsum log pubkey hex")?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("invalid sigsum log pubkey: {e}"))
}

/// Decode exactly 64 lower/upper-hex chars to a `[u8; 32]`. Shared by the
/// `verify` subcommand's `--expected-prior` parsing.
///
/// # Errors
///
/// Returns an error if the input is not 64 hex chars.
pub fn decode_hex_32(s: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(s.len() == 64, "expected 64 hex chars, got {}", s.len());
    let mut out = [0u8; 32];
    for (byte, chunk) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(chunk).context("non-utf8 hex pair")?;
        *byte = u8::from_str_radix(pair, 16).context("non-hex digit")?;
    }
    Ok(out)
}

/// Lower-hex encode arbitrary bytes (for emitting the log pubkey).
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}
