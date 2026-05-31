// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Chain-link verification composed with Sigsum-inclusion verification
//! per D0023 §6.2.
//!
//! ## Module location vs. D0023 §6.2's prose
//!
//! D0023 §6.2 nominates `verify_chain_links_with_sigsum` as a
//! cairn-trust-graph surface. As with [`crate::emit`] (§6.1), the
//! literal placement would require cairn-trust-graph to depend on
//! cairn-sigsum-client, which would invert the existing dependency
//! direction. The wrapper code-locates here in
//! `cairn-sigsum-client::verify` for the same DAG reason; the
//! architectural intent of §6.2 — chain-link integrity AND Sigsum
//! inclusion checked as one operation — is preserved unchanged.
//!
//! ## Composition order (D0023 §6.2)
//!
//! 1. [`cairn_trust_graph::verify_chain_links`] runs first. Any
//!    chain-link failure surfaces as
//!    [`VerifyChainWithSigsumError::ChainLink`] and the Sigsum loop
//!    is NOT entered — there is no point checking inclusion proofs
//!    against a chain that does not itself verify.
//! 2. For each op in the verified chain, [`SigsumClient::verify_-
//!    inclusion`] runs. The first failing op short-circuits with
//!    [`VerifyChainWithSigsumError::SigsumInclusion`] carrying its
//!    `op_index`.
//!
//! ## v1 skeleton status
//!
//! The wrapper composes against the v1 skeleton's stubbed
//! [`SigsumClient::verify_inclusion`] which returns
//! [`SigsumError::NetworkUnreached`] unconditionally. Every wrapper
//! invocation in v1 therefore surfaces
//! `SigsumInclusion { op_index: 0, source: NetworkUnreached }` once
//! the chain itself verifies. Once the network surface lands, the
//! wrapper returns `Ok(Vec<&TrustGraphOp>)` on full chain-and-
//! inclusion verification.

use cairn_crypto::ed25519::VerifyingKey;
use cairn_trust_graph::{SignedTrustGraphOp, TrustGraphError, TrustGraphOp, verify_chain_links};
use thiserror::Error;

use crate::client::SigsumClient;
use crate::error::SigsumError;

/// Top-level error type for [`verify_chain_links_with_sigsum`].
///
/// `#[non_exhaustive]` per D0018 §4.2. The two variants are
/// intentionally orthogonal per D0023 §6.2: chain-link integrity and
/// Sigsum inclusion are independent failure modes that must remain
/// distinguishable so the caller can quarantine the right ops + show
/// the right UI affordance.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerifyChainWithSigsumError {
    /// Chain-link integrity verification failed. The underlying
    /// [`TrustGraphError`] pinpoints the specific structural or
    /// cryptographic failure; most variants already carry their own
    /// `index` field per [`cairn_trust_graph::verify_chain_links`]'s
    /// surface, so an extra wrapper-level index is not needed here.
    #[error("verify_chain_links_with_sigsum: chain-link failure: {0}")]
    ChainLink(#[source] TrustGraphError),

    /// Sigsum-inclusion verification failed for the op at `op_index`
    /// in the input `ops` slice. The underlying [`SigsumError`]
    /// pinpoints the specific failure mode (network, malformed cache
    /// record, inclusion-proof verify, etc.).
    #[error(
        "verify_chain_links_with_sigsum: sigsum-inclusion failure at op_index {op_index}: {source}"
    )]
    SigsumInclusion {
        /// Index of the failing op in the input `ops` slice.
        op_index: usize,
        /// The underlying Sigsum failure.
        #[source]
        source: SigsumError,
    },
}

/// Verify a chain of signed trust-graph ops against both the local
/// chain-link integrity rules AND the configured Sigsum log per
/// D0023 §6.2.
///
/// Returns the verified `TrustGraphOp` references in chain order (same
/// shape as [`verify_chain_links`]) so callers can use the output
/// identically after the Sigsum gate passes.
///
/// # Errors
///
/// - [`VerifyChainWithSigsumError::ChainLink`] for any chain-link
///   failure surfaced by [`verify_chain_links`] (chain empty, prior-
///   hash mismatch, pair mismatch, timestamp regression, per-op
///   signature failure, etc.).
/// - [`VerifyChainWithSigsumError::SigsumInclusion`] for the first
///   op whose inclusion proof does not verify against the cached
///   accepted tree head, with `op_index` naming the failing position.
pub async fn verify_chain_links_with_sigsum<'a>(
    ops: &'a [SignedTrustGraphOp],
    token_bytes: &[u8],
    expected_operational_identity: &VerifyingKey,
    client: &SigsumClient,
) -> Result<Vec<&'a TrustGraphOp>, VerifyChainWithSigsumError> {
    // Step 1: chain-link integrity. A failure here short-circuits;
    // there's no value in running Sigsum-inclusion against an
    // unverified chain.
    let verified = verify_chain_links(ops, token_bytes, expected_operational_identity)
        .map_err(VerifyChainWithSigsumError::ChainLink)?;

    // Step 2: per-op Sigsum-inclusion verification. The first
    // failing op short-circuits with its op_index, so callers can
    // surface "op N is in the chain but not yet in the Sigsum log"
    // diagnostics directly.
    for (op_index, signed_op) in ops.iter().enumerate() {
        client
            .verify_inclusion(signed_op)
            .await
            .map_err(|source| VerifyChainWithSigsumError::SigsumInclusion { op_index, source })?;
    }

    Ok(verified)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::client::{SigsumClient, SigsumClientConfig};
    use crate::witness::parse_witness_pool;
    use cairn_crypto::ed25519::SigningKey;
    use cairn_identity::{CapabilityToken, capabilities};
    use cairn_storage::Storage;
    use cairn_storage::key_provider::testing::InMemoryKeyProvider;
    use cairn_trust_graph::TrustGraphOp;
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

    fn make_client() -> SigsumClient {
        let storage = open_storage();
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

    /// Build a single-op chain + the matching token bytes + the
    /// expected operational identity. The chain is structurally valid
    /// so `verify_chain_links` accepts it; this lets us exercise the
    /// Sigsum-inclusion gate cleanly.
    fn make_single_op_chain() -> (Vec<SignedTrustGraphOp>, Vec<u8>, VerifyingKey) {
        let mut rng = OsRng;
        let op_identity_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);
        let peer = SigningKey::generate(&mut rng).verifying_key();

        let token = CapabilityToken::new(
            op_identity_sk.verifying_key(),
            device_sk.verifying_key(),
            vec![capabilities::TRUST_GRAPH_ATTEST.to_string()],
            2_000_000_000,
            vec![],
        );
        let signed_token = token.sign(&op_identity_sk).unwrap();
        let token_bytes = signed_token.encode(false).unwrap();

        let op = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer,
            1_700_000_000,
            vec![],
            vec![],
        );
        let signed = SignedTrustGraphOp::sign(op, &device_sk).unwrap();

        (vec![signed], token_bytes, op_identity_sk.verifying_key())
    }

    #[tokio::test]
    async fn verify_chain_link_failure_surfaces_chain_link_variant() {
        // verify_chain_links rejects the empty chain. The wrapper
        // must surface this as ChainLink, NOT SigsumInclusion, even
        // though no inclusion check was attempted.
        let client = make_client();
        let (_, token_bytes, op_identity) = make_single_op_chain();

        let result = verify_chain_links_with_sigsum(&[], &token_bytes, &op_identity, &client).await;

        assert!(matches!(
            result,
            Err(VerifyChainWithSigsumError::ChainLink(
                TrustGraphError::ChainEmpty
            ))
        ));
    }

    #[tokio::test]
    async fn verify_chain_link_failure_short_circuits_before_sigsum() {
        // If the chain is structurally broken, the wrapper must NOT
        // attempt Sigsum-inclusion verification — the chain-link
        // failure is the source of truth. We construct a chain whose
        // genesis op has a non-empty prior_hash so verify_chain_links
        // rejects with ChainGenesisNotEmpty, then assert the wrapper
        // surfaces ChainLink (not SigsumInclusion).
        let client = make_client();
        let mut rng = OsRng;
        let op_identity_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);
        let peer = SigningKey::generate(&mut rng).verifying_key();

        let token = CapabilityToken::new(
            op_identity_sk.verifying_key(),
            device_sk.verifying_key(),
            vec![capabilities::TRUST_GRAPH_ATTEST.to_string()],
            2_000_000_000,
            vec![],
        );
        let signed_token = token.sign(&op_identity_sk).unwrap();
        let token_bytes = signed_token.encode(false).unwrap();

        // Construct an op with a non-empty prior_hash at genesis ⇒
        // ChainGenesisNotEmpty rejection by verify_chain_links.
        let op = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer,
            1_700_000_000,
            vec![0xAA; 32], // non-empty prior_hash at genesis
            vec![],
        );
        let signed = SignedTrustGraphOp::sign(op, &device_sk).unwrap();
        let ops = vec![signed];

        let result = verify_chain_links_with_sigsum(
            &ops,
            &token_bytes,
            &op_identity_sk.verifying_key(),
            &client,
        )
        .await;

        assert!(matches!(
            result,
            Err(VerifyChainWithSigsumError::ChainLink(
                TrustGraphError::ChainGenesisNotEmpty { index: 0 }
            ))
        ));
    }

    #[tokio::test]
    async fn sigsum_inclusion_failure_pinpoints_op_index_in_skeleton() {
        // In v1 skeleton, verify_inclusion always returns
        // NetworkUnreached. For a single-op chain the first failing
        // op is at index 0; the wrapper must surface that index in
        // SigsumInclusion.op_index per §6.2.
        let client = make_client();
        let (ops, token_bytes, op_identity) = make_single_op_chain();

        let result =
            verify_chain_links_with_sigsum(&ops, &token_bytes, &op_identity, &client).await;

        assert!(matches!(
            result,
            Err(VerifyChainWithSigsumError::SigsumInclusion {
                op_index: 0,
                source: SigsumError::NetworkUnreached,
            })
        ));
    }
}
