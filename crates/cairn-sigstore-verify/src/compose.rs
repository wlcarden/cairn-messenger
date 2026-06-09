// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Composition with the cairn-sigsum-client substrate per D0024 §5.
//!
//! ## Release leaf-hash schema (D0042 §3, superseding D0024 §5.1)
//!
//! ```text
//! release_leaf_hash = SHA-256( detached_ecdsa_p256_signature_bytes )
//! ```
//!
//! Under the Sigstore-native (B) model the release manifest is signed
//! as a **detached** ECDSA P-256 blob signature (the `cosign sign-blob`
//! model), not wrapped in a `COSE_Sign1`. The leaf hash therefore
//! commits to the raw detached-signature bytes directly.
//!
//! This is still the same single audited primitive as D0023 §1's
//! trust-graph leaf hash — `SHA-256(signature_bytes)` — per the "one
//! audited primitive, N use cases" property of D0024 §5.2. The
//! trust-graph path extracts the signature out of its `COSE_Sign1`
//! envelope first; the release path passes the detached signature
//! straight through. The composition lets a release that signs through
//! Sigstore get logged in BOTH Rekor (Sigstore's log) AND the witness-
//! cosigned Sigsum release log via the same code path the trust-graph
//! crate uses for trust-graph leaves.
//!
//! ## Shared leaf-hash primitive
//!
//! [`release_leaf_hash_for_signature`] is a thin crate-local wrapper
//! that delegates to `cairn-sigsum-client`'s shared
//! [`cairn_sigsum_client::leaf_hash_for_signature_bytes`]. The wrapper
//! is infallible — hashing raw signature bytes cannot fail, so unlike
//! the legacy COSE path there is no envelope-decode error surface.

use cairn_sigsum_client::{LeafHash, leaf_hash_for_signature_bytes};

/// Compute the release leaf hash for a detached ECDSA P-256 signature
/// per D0042 §3: `SHA-256(detached_signature_bytes)`.
///
/// `signature_bytes` are the DER-encoded detached signature over the
/// canonical-CBOR [`crate::manifest::ReleaseManifest`] bytes (the
/// `cosign sign-blob` artifact). Delegates to the shared
/// [`cairn_sigsum_client::leaf_hash_for_signature_bytes`] primitive.
///
/// Infallible: the leaf hash is `SHA-256` over raw bytes, which cannot
/// fail (the legacy COSE path's decode-failure surface is gone).
#[must_use]
pub fn release_leaf_hash_for_signature(signature_bytes: &[u8]) -> LeafHash {
    leaf_hash_for_signature_bytes(signature_bytes)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    use rand_core::OsRng;

    /// Produce a DER-encoded detached ECDSA P-256 signature over the
    /// supplied payload with a freshly-generated key — exactly the
    /// artifact shape the release pipeline feeds the leaf hash.
    fn detached_sig(payload: &[u8]) -> Vec<u8> {
        let sk = SigningKey::random(&mut OsRng);
        let sig: Signature = sk.sign(payload);
        sig.to_der().as_bytes().to_vec()
    }

    #[test]
    fn release_leaf_hash_is_deterministic_for_same_signature() {
        let sig = detached_sig(b"manifest-payload-A");
        let h_a = release_leaf_hash_for_signature(&sig);
        let h_b = release_leaf_hash_for_signature(&sig);
        assert_eq!(h_a, h_b);
    }

    #[test]
    fn distinct_signatures_produce_distinct_leaf_hashes() {
        let sig_a = detached_sig(b"manifest-payload-A");
        let sig_b = detached_sig(b"manifest-payload-B");
        let h_a = release_leaf_hash_for_signature(&sig_a);
        let h_b = release_leaf_hash_for_signature(&sig_b);
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn release_leaf_hash_length_is_32_bytes() {
        let sig = detached_sig(b"manifest-payload");
        let h = release_leaf_hash_for_signature(&sig);
        assert_eq!(h.as_bytes().len(), 32);
    }
}
