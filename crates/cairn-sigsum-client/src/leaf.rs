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

use cairn_crypto::ed25519::SigningKey;
use cairn_envelope::cose_sign1::CoseSign1;
use cairn_trust_graph::SignedTrustGraphOp;
use sha2::{Digest, Sha256};

use crate::error::SigsumError;

/// Length of the leaf hash in bytes. SHA-256 = 32.
pub const LEAF_HASH_LEN: usize = 32;

/// Sigsum tree-leaf signature namespace per the Sigsum v1 log spec
/// §2.2.4. The submitter signs `NAMESPACE ‖ 0x00 ‖ checksum`.
pub const TREE_LEAF_NAMESPACE: &[u8] = b"sigsum.org/v1/tree-leaf";

/// A Sigsum Merkle tree leaf per the Sigsum v1 log spec §2.2.4.
///
/// The 128-byte `checksum ‖ signature ‖ key_hash` whose RFC 6962 leaf
/// hash (`H(0x00 ‖ tree_leaf)`) is what the log's Merkle tree commits to
/// and what `get-inclusion-proof` addresses.
///
/// ## Cairn mapping (D0023 §1, revised 2026-05-31)
///
/// Cairn submits its [`LeafHash`] (`SHA-256(op signature bytes)`) as the
/// Sigsum `message` (exactly 32 bytes). The log-side `checksum` is then
/// `SHA-256(message)`; the submitter (Cairn's operational identity per
/// D0023 §3) signs the tree-leaf; `key_hash` is `SHA-256(submitter
/// pubkey)`. The original D0023 §1 framing called `leaf_hash` "the leaf
/// hash addressed to the log", which was imprecise: `leaf_hash` is the
/// *message*, and the log addresses by the Merkle leaf hash of the full
/// `tree_leaf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeLeaf {
    /// `SHA-256(message)` where `message` is Cairn's [`LeafHash`].
    pub checksum: [u8; 32],
    /// The submitter's Ed25519 signature over
    /// `TREE_LEAF_NAMESPACE ‖ 0x00 ‖ checksum`.
    pub signature: [u8; 64],
    /// `SHA-256(submitter Ed25519 public key)`.
    pub key_hash: [u8; 32],
}

impl TreeLeaf {
    /// The RFC 6962 Merkle leaf hash `H(0x00 ‖ checksum ‖ signature ‖
    /// key_hash)` — the value `get-inclusion-proof` addresses and the
    /// inclusion proof reconstructs to the tree root.
    #[must_use]
    pub fn merkle_leaf_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x00u8]);
        hasher.update(self.checksum);
        hasher.update(self.signature);
        hasher.update(self.key_hash);
        let out = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }
}

/// SHA-256 of a byte slice into a fixed `[u8; 32]`.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Build the Sigsum [`TreeLeaf`] for a submitted `message` (Cairn's
/// [`LeafHash`] bytes), signed by `submitter_sk` (the operational
/// identity per D0023 §3).
///
/// # Errors
///
/// [`SigsumError::LeafSignFailed`] if the Ed25519 signing fails
/// (effectively unreachable for a valid key).
pub fn build_tree_leaf(
    message: &[u8; LEAF_HASH_LEN],
    submitter_sk: &SigningKey,
) -> Result<TreeLeaf, SigsumError> {
    let checksum = sha256(message);

    let mut signing_input = Vec::with_capacity(
        TREE_LEAF_NAMESPACE
            .len()
            .saturating_add(1)
            .saturating_add(32),
    );
    signing_input.extend_from_slice(TREE_LEAF_NAMESPACE);
    signing_input.push(0x00);
    signing_input.extend_from_slice(&checksum);

    let signature = submitter_sk
        .sign(&signing_input)
        .map_err(|_| SigsumError::LeafSignFailed)?;
    let key_hash = sha256(&submitter_sk.verifying_key().to_bytes());

    Ok(TreeLeaf {
        checksum,
        signature: signature.to_bytes(),
        key_hash,
    })
}

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

/// Compute the leaf hash for the canonical bytes of a `COSE_Sign1`
/// envelope per D0023 §1: `SHA-256(COSE_Sign1.signature_bytes)`.
///
/// This is the shared primitive underlying both [`leaf_hash_for`]
/// (trust-graph ops, D0023 §1) and the release-manifest leaf hash
/// (D0024 §5.1) — the "one audited primitive, two use cases" property.
/// The trust-graph wrapper encodes the op to its envelope bytes first;
/// the release path (`cairn-sigstore-verify`) passes the signed-
/// manifest envelope bytes directly.
///
/// # Errors
///
/// [`SigsumError::MalformedResponse`] if `envelope_bytes` does not
/// decode as a `COSE_Sign1` (unreachable for own-emitted envelopes; the
/// variant covers the theoretical case).
pub fn leaf_hash_for_cose_sign1_bytes(envelope_bytes: &[u8]) -> Result<LeafHash, SigsumError> {
    let envelope =
        CoseSign1::from_bytes(envelope_bytes).map_err(|_| SigsumError::MalformedResponse)?;
    Ok(LeafHash(sha256(envelope.signature())))
}

/// Compute the leaf hash for a signed trust-graph op per D0023 §1.
///
/// Encodes the op to its canonical `COSE_Sign1` bytes, then delegates
/// to [`leaf_hash_for_cose_sign1_bytes`] (extract signature bytes →
/// SHA-256).
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
    leaf_hash_for_cose_sign1_bytes(&envelope_bytes)
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
    fn leaf_hash_for_matches_shared_cose_bytes_helper() {
        // The trust-graph wrapper must produce the byte-identical leaf
        // hash as the shared envelope-bytes primitive the release path
        // uses (D0024 §5.2 "one audited primitive, two use cases").
        let mut rng = OsRng;
        let signed_op = make_signed_op(&mut rng);
        let via_op = leaf_hash_for(&signed_op).unwrap();
        let envelope_bytes = signed_op.encode(false).unwrap();
        let via_bytes = leaf_hash_for_cose_sign1_bytes(&envelope_bytes).unwrap();
        assert_eq!(via_op, via_bytes);
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

    #[test]
    fn build_tree_leaf_is_deterministic_and_well_formed() {
        let sk = SigningKey::generate(&mut OsRng);
        let message = [0xABu8; LEAF_HASH_LEN];
        let tl1 = build_tree_leaf(&message, &sk).unwrap();
        let tl2 = build_tree_leaf(&message, &sk).unwrap();
        // Ed25519 (RFC 8032) is deterministic.
        assert_eq!(tl1, tl2);
        // checksum = SHA-256(message).
        assert_eq!(tl1.checksum, sha256(&message));
        // key_hash = SHA-256(submitter pubkey).
        assert_eq!(tl1.key_hash, sha256(&sk.verifying_key().to_bytes()));
        // Merkle leaf hash is deterministic + 32 bytes.
        assert_eq!(tl1.merkle_leaf_hash(), tl2.merkle_leaf_hash());
    }

    #[test]
    fn tree_leaf_signature_verifies_over_namespaced_checksum() {
        use cairn_crypto::ed25519::Signature;
        // Pin the exact Sigsum §2.2.4 signing input:
        // NAMESPACE ‖ 0x00 ‖ checksum (56 bytes).
        let sk = SigningKey::generate(&mut OsRng);
        let message = [0x11u8; LEAF_HASH_LEN];
        let tl = build_tree_leaf(&message, &sk).unwrap();

        let mut input = Vec::new();
        input.extend_from_slice(TREE_LEAF_NAMESPACE);
        input.push(0x00);
        input.extend_from_slice(&tl.checksum);
        assert_eq!(input.len(), 56);

        let sig = Signature::from_bytes(tl.signature);
        assert!(sk.verifying_key().verify(&input, &sig).is_ok());
    }
}
