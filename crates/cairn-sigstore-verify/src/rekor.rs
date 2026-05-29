// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Rekor transparency-log verification per D0024 §3.
//!
//! ## v1 skeleton status
//!
//! The inclusion-proof + signed-checkpoint verifier returns
//! [`SigstoreVerifyError::NetworkUnreached`] pending the body
//! landing per D0024 §10. When the body lands, the function:
//!
//! 1. Reconstructs the Merkle path against the entry's claimed
//!    leaf hash + the checkpoint's claimed root hash per D0024
//!    §3.1.
//! 2. Verifies the signed checkpoint via Ed25519 against the
//!    pinned Rekor public key per D0024 §3.1.
//! 3. Surfaces the failure mode-by-mode: inclusion-proof failure
//!    vs. checkpoint-signature failure are distinct errors so the
//!    caller can route different mitigations.

use crate::error::SigstoreVerifyError;

/// Bundled Rekor inclusion proof + signed checkpoint per D0024 §3.
///
/// In offline mode (D0024 §6.4) all fields ship as part of the
/// release bundle alongside the APK; in online mode they're freshly
/// fetched from the Rekor endpoint.
#[derive(Debug, Clone)]
pub struct RekorBundle {
    /// SHA-256 of the leaf entry the inclusion proof witnesses
    /// inclusion of.
    pub leaf_hash: [u8; 32],
    /// 0-based index of the leaf in the Rekor log.
    pub leaf_index: u64,
    /// `tree_size` at which the inclusion proof was captured.
    pub tree_size: u64,
    /// Root hash from the signed checkpoint that backs the proof.
    pub checkpoint_root_hash: [u8; 32],
    /// Merkle intermediate-node hashes that compose the proof path.
    pub proof_nodes: Vec<[u8; 32]>,
    /// The signed checkpoint's Ed25519 signature over its body.
    pub checkpoint_signature: Vec<u8>,
}

/// Stub for the Rekor inclusion-proof + signed-checkpoint verifier
/// per D0024 §3.
///
/// v1 skeleton always returns
/// [`SigstoreVerifyError::NetworkUnreached`].
///
/// # Errors
///
/// - [`SigstoreVerifyError::NetworkUnreached`] (skeleton only;
///   replaced by
///   [`SigstoreVerifyError::RekorInclusionProofVerifyFailed`] /
///   [`SigstoreVerifyError::RekorCheckpointVerifyFailed`] once the
///   body lands)
#[allow(
    clippy::missing_const_for_fn,
    reason = "stub; the real body will perform Ed25519 verify + Merkle reconstruction"
)]
pub fn verify_rekor_inclusion(
    _bundle: &RekorBundle,
    _pinned_rekor_pubkey_pem: &[u8],
) -> Result<(), SigstoreVerifyError> {
    Err(SigstoreVerifyError::NetworkUnreached)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_bundle() -> RekorBundle {
        RekorBundle {
            leaf_hash: [0xAA; 32],
            leaf_index: 42,
            tree_size: 1024,
            checkpoint_root_hash: [0xBB; 32],
            proof_nodes: vec![[0x11; 32], [0x22; 32]],
            checkpoint_signature: vec![0xCC; 64],
        }
    }

    #[test]
    fn verify_rekor_inclusion_returns_network_unreached_in_skeleton() {
        let bundle = make_bundle();
        let result = verify_rekor_inclusion(&bundle, b"placeholder-rekor-pubkey-pem");
        assert!(matches!(result, Err(SigstoreVerifyError::NetworkUnreached)));
    }
}
