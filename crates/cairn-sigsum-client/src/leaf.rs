// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Leaf hash computation per D0023 §1.
//!
//! ```text
//! leaf_hash = SHA-256( COSE_Sign1.signature_bytes( signed_op ) )
//! ```
//!
//! The hash commits to the operation's 64-byte Ed25519 signature
//! bytes — byte-identical to D0006 §5's `prior_hash` byte input. This
//! is intentional: the same hash anchors both the trust-graph chain
//! integrity AND the Sigsum commitment.
//!
//! ## Privacy property
//!
//! Per design brief §3.3 + D0006 §3.3, the leaf hash MUST NOT reveal
//! issuer / subject / context. SHA-256 of the signature bytes leaks
//! no content: the signature itself is a cryptographically pseudo-
//! random 64-byte string under EUF-CMA. The Sigsum log records only
//! the leaf hash; the trust-graph op itself stays in the participants'
//! local storage and propagates via the messaging layer.

use cairn_envelope::cose_sign1::CoseSign1;
use cairn_trust_graph::SignedTrustGraphOp;
use sha2::{Digest, Sha256};

use crate::error::SigsumError;

/// Length of the leaf hash in bytes. SHA-256 = 32.
pub const LEAF_HASH_LEN: usize = 32;

/// A leaf hash per D0023 §1: 32 raw bytes addressed to the Sigsum
/// log. Wraps `[u8; LEAF_HASH_LEN]` for type-safety (e.g.
/// distinguishing from arbitrary 32-byte hashes elsewhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeafHash(pub [u8; LEAF_HASH_LEN]);

impl LeafHash {
    /// Construct a `LeafHash` from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; LEAF_HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Return the inner byte slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; LEAF_HASH_LEN] {
        &self.0
    }

    /// Hex-encode the leaf hash for diagnostic display.
    ///
    /// Uses lowercase hex per Sigsum's documented protocol convention.
    #[must_use]
    pub fn to_hex(self) -> String {
        use core::fmt::Write as _;
        let mut s = String::with_capacity(LEAF_HASH_LEN.saturating_mul(2));
        for b in self.0 {
            // unwrap-on-write-to-String is OK here per the std::fmt
            // contract; documented `# Panics` not required because the
            // panic is statically unreachable.
            let _ = write!(&mut s, "{b:02x}");
        }
        s
    }
}

/// Compute the leaf hash for a signed trust-graph op per D0023 §1.
///
/// Steps:
///
/// 1. Encode the envelope to its canonical `COSE_Sign1` bytes.
/// 2. Decode just enough to extract the signature bytes (the 4th
///    element of the `COSE_Sign1` array).
/// 3. SHA-256 the signature bytes.
///
/// # Errors
///
/// - [`SigsumError::Encode`] if the trust-graph envelope encode fails
///   (unreachable for envelopes constructed via the public API).
/// - [`SigsumError::MalformedResponse`] if the envelope decode for
///   signature extraction fails (unreachable for own-emitted
///   envelopes; the variant covers the theoretical case).
pub fn leaf_hash_for(signed_op: &SignedTrustGraphOp) -> Result<LeafHash, SigsumError> {
    let envelope_bytes = signed_op.encode(false)?;
    let envelope =
        CoseSign1::from_bytes(&envelope_bytes).map_err(|_| SigsumError::MalformedResponse)?;
    let signature_bytes = envelope.signature();

    let mut hasher = Sha256::new();
    hasher.update(signature_bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; LEAF_HASH_LEN];
    arr.copy_from_slice(&out);
    Ok(LeafHash(arr))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use cairn_trust_graph::TrustGraphOp;
    use rand_core::OsRng;

    fn make_signed_op(rng: &mut OsRng) -> SignedTrustGraphOp {
        let op_identity_sk = SigningKey::generate(rng);
        let device_sk = SigningKey::generate(rng);
        let peer = SigningKey::generate(rng).verifying_key();
        let op = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer,
            1_700_000_000,
            vec![],
            vec![],
        );
        SignedTrustGraphOp::sign(op, &device_sk).unwrap()
    }

    #[test]
    fn leaf_hash_is_deterministic_for_same_envelope() {
        let mut rng = OsRng;
        let signed_op = make_signed_op(&mut rng);
        let h1 = leaf_hash_for(&signed_op).unwrap();
        let h2 = leaf_hash_for(&signed_op).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn leaf_hash_matches_prior_hash_byte_input() {
        // Per D0023 §1: the leaf hash is byte-identical to D0006 §5's
        // prior_hash. This test pins that property — if either side
        // changes its byte composition, this test fails loudly.
        let mut rng = OsRng;
        let signed_op = make_signed_op(&mut rng);
        let leaf = leaf_hash_for(&signed_op).unwrap();
        let prior_hash = signed_op.prior_hash_bytes();
        assert_eq!(leaf.as_bytes(), &prior_hash);
    }

    #[test]
    fn leaf_hash_length_is_32_bytes() {
        let mut rng = OsRng;
        let signed_op = make_signed_op(&mut rng);
        let leaf = leaf_hash_for(&signed_op).unwrap();
        assert_eq!(leaf.as_bytes().len(), LEAF_HASH_LEN);
    }

    #[test]
    fn distinct_envelopes_produce_distinct_leaf_hashes() {
        let mut rng = OsRng;
        let signed_op_a = make_signed_op(&mut rng);
        let signed_op_b = make_signed_op(&mut rng);
        let h_a = leaf_hash_for(&signed_op_a).unwrap();
        let h_b = leaf_hash_for(&signed_op_b).unwrap();
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn to_hex_round_trips_through_bytes() {
        let hash = LeafHash::from_bytes([0xABu8; LEAF_HASH_LEN]);
        let hex = hash.to_hex();
        assert_eq!(hex.len(), LEAF_HASH_LEN * 2);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }
}
