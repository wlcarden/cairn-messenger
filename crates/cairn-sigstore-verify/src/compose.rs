// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Composition with the cairn-sigsum-client substrate per D0024 §5.
//!
//! ## Release leaf-hash schema (D0024 §5.1)
//!
//! ```text
//! release_leaf_hash = SHA-256( COSE_Sign1.signature_bytes( signed_manifest ) )
//! ```
//!
//! This is byte-identical to D0023 §1's trust-graph leaf-hash schema
//! per the "one audited primitive, two use cases" property of D0024
//! §5.2. The composition lets a release that signs through Sigstore
//! get logged in BOTH Rekor (Sigstore's log) AND the witness-
//! cosigned Sigsum release log via the same code path the trust-
//! graph crate uses for trust-graph leaves.
//!
//! ## Shared leaf-hash primitive
//!
//! [`release_leaf_hash_for_envelope_bytes`] is a thin crate-local
//! wrapper that delegates to `cairn-sigsum-client`'s shared
//! [`cairn_sigsum_client::leaf_hash_for_cose_sign1_bytes`] (the
//! consolidation the skeleton deferred "until the network bodies
//! land", now done). The wrapper exists only to map the decode failure
//! onto this crate's [`SigstoreVerifyError`] surface so the release
//! path never `unwrap`s; the SHA-256-of-signature-bytes logic itself is
//! the single audited primitive shared with trust-graph leaves.

use cairn_sigsum_client::{LeafHash, leaf_hash_for_cose_sign1_bytes};

use crate::error::SigstoreVerifyError;

/// Compute the release leaf hash for a `COSE_Sign1` envelope per
/// D0024 §5.1.
///
/// The envelope bytes must be the canonical-CBOR encoded
/// `COSE_Sign1` over the [`crate::manifest::ReleaseManifest`]
/// canonical bytes. The leaf hash commits to the envelope's 64-byte
/// Ed25519 signature only. Delegates to the shared
/// [`cairn_sigsum_client::leaf_hash_for_cose_sign1_bytes`] primitive.
///
/// # Errors
///
/// - [`SigstoreVerifyError::ManifestDecodeFailed`] if the
///   `COSE_Sign1` envelope does not decode (unreachable for
///   envelopes constructed via the release pipeline; the variant
///   exists so we never `unwrap` on the decode path).
pub fn release_leaf_hash_for_envelope_bytes(
    envelope_bytes: &[u8],
) -> Result<LeafHash, SigstoreVerifyError> {
    leaf_hash_for_cose_sign1_bytes(envelope_bytes)
        .map_err(|_| SigstoreVerifyError::ManifestDecodeFailed)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use cairn_envelope::cose_sign1::Sign1Builder;
    use rand_core::OsRng;

    /// Build a real COSE_Sign1 envelope over the supplied payload,
    /// signed with a freshly-generated Ed25519 key, and return the
    /// canonical-CBOR encoded envelope bytes.
    fn sign_envelope(payload: &[u8]) -> Vec<u8> {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        Sign1Builder::new()
            .with_payload(payload.to_vec())
            .finalize(&sk)
            .unwrap()
            .encode(false)
            .unwrap()
    }

    #[test]
    fn release_leaf_hash_is_deterministic_for_same_envelope() {
        let envelope_bytes = sign_envelope(b"manifest-payload-A");
        let h_a = release_leaf_hash_for_envelope_bytes(&envelope_bytes).unwrap();
        let h_b = release_leaf_hash_for_envelope_bytes(&envelope_bytes).unwrap();
        assert_eq!(h_a, h_b);
    }

    #[test]
    fn distinct_envelopes_produce_distinct_leaf_hashes() {
        let envelope_a = sign_envelope(b"manifest-payload-A");
        let envelope_b = sign_envelope(b"manifest-payload-B");
        let h_a = release_leaf_hash_for_envelope_bytes(&envelope_a).unwrap();
        let h_b = release_leaf_hash_for_envelope_bytes(&envelope_b).unwrap();
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn malformed_envelope_bytes_fail_release_leaf_hash() {
        let result = release_leaf_hash_for_envelope_bytes(b"\xFF\x00\x01");
        assert!(matches!(
            result,
            Err(SigstoreVerifyError::ManifestDecodeFailed)
        ));
    }

    #[test]
    fn release_leaf_hash_length_is_32_bytes() {
        let envelope_bytes = sign_envelope(b"manifest-payload");
        let h = release_leaf_hash_for_envelope_bytes(&envelope_bytes).unwrap();
        assert_eq!(h.as_bytes().len(), 32);
    }
}
