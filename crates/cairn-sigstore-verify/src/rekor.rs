// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Rekor transparency-log verification per D0024 §3.
//!
//! ## What this verifies (offline)
//!
//! [`verify_rekor_inclusion`] performs the two D0024 §3.1 checks over
//! data carried in the [`RekorBundle`] — no network, pure crypto:
//!
//! 1. **Signed-checkpoint verify.** The Rekor checkpoint is a C2SP
//!    [tlog-checkpoint](https://c2sp.org/tlog-checkpoint) signed note.
//!    Its body (`checkpoint_note`) is verified with ECDSA P-256 against
//!    the pinned Rekor public key. _[Revised 2026-05-30]_ The original
//!    D0024 §3.2 said "Ed25519"; the public `rekor.sigstore.dev` log
//!    signs with **ECDSA P-256**, so the verify uses the `p256` crate.
//! 2. **Inclusion proof.** The bundle's RFC 6962 Merkle audit path is
//!    reconstructed from the leaf hash + leaf index up to a root, which
//!    must equal the root hash parsed out of the (now signature-
//!    verified) checkpoint note.
//!
//! The two failure modes are distinct typed errors
//! ([`SigstoreVerifyError::RekorCheckpointVerifyFailed`] vs
//! [`SigstoreVerifyError::RekorInclusionProofVerifyFailed`]) so the
//! caller can route different mitigations per D0024 §7.1.
//!
//! ## Note format (C2SP tlog-checkpoint)
//!
//! The signed `checkpoint_note` bytes are at least three
//! newline-terminated lines:
//!
//! ```text
//! <origin>\n              (e.g. rekor.sigstore.dev - <tree id>)
//! <tree_size decimal>\n
//! <base64-std(root_hash)>\n
//! ```
//!
//! The root hash + tree size used for the inclusion check are parsed
//! from these bytes AFTER the signature verifies, so a forged root in a
//! parallel field cannot influence the check — the signed note is the
//! single source of truth.
//!
//! ## RFC 6962 hashing
//!
//! Leaf nodes are domain-separated with a `0x00` prefix and interior
//! nodes with `0x01` (`hash_children`). The [`RekorBundle::leaf_hash`]
//! is already the leaf node value (the `0x00`-prefixed hash) at
//! `leaf_index`; this module only combines interior nodes.

use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;
use sha2::{Digest, Sha256};

use crate::error::SigstoreVerifyError;

/// Bundled Rekor inclusion proof + signed checkpoint per D0024 §3.
///
/// In offline mode (D0024 §6.4) all fields ship as part of the release
/// bundle alongside the APK; in online mode they're parsed from a
/// freshly-fetched Rekor entry (the signed-note line parsing — base64
/// decode + 4-byte C2SP key-id strip — happens at fetch time, so this
/// struct already carries the separated note body + DER signature).
///
/// _[Revised 2026-05-30]_ The original skeleton carried separate
/// `tree_size` + `checkpoint_root_hash` fields and a bare
/// `checkpoint_signature` with no signed body — which cannot actually
/// verify a signature. The schema now carries the exact signed
/// `checkpoint_note` bytes (the tree size + root hash are parsed out of
/// it after the signature verifies) + the DER ECDSA signature.
#[derive(Debug, Clone)]
pub struct RekorBundle {
    /// RFC 6962 leaf hash — the Merkle-tree node value at `leaf_index`
    /// (the `0x00`-prefixed hash of the log entry).
    pub leaf_hash: [u8; 32],
    /// 0-based index of the leaf in the Rekor log.
    pub leaf_index: u64,
    /// RFC 6962 inclusion-proof audit path: the sibling hashes from the
    /// leaf up to the root, in bottom-to-top order.
    pub proof_nodes: Vec<[u8; 32]>,
    /// The exact signed checkpoint note bytes (C2SP tlog-checkpoint
    /// body). These are the bytes the Rekor key signed.
    pub checkpoint_note: Vec<u8>,
    /// ECDSA P-256 signature (ASN.1 DER) over `checkpoint_note`, with
    /// the C2SP signed-note 4-byte key id already stripped.
    pub checkpoint_signature: Vec<u8>,
}

/// A verified Rekor checkpoint, returned by [`verify_rekor_inclusion`]
/// once both the signature + inclusion checks pass.
///
/// The `root_hash` is surfaced per D0024 §3.3 so an out-of-band tool
/// can compare it across log views for split-view detection (v1 does
/// not implement cross-checkpoint consistency proofs in the verifier).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekorCheckpoint {
    /// The checkpoint origin line (log identity); informational.
    pub origin: String,
    /// Tree size parsed from the signed checkpoint note.
    pub tree_size: u64,
    /// Root hash parsed from the signed checkpoint note.
    pub root_hash: [u8; 32],
}

/// Verify a Rekor inclusion proof + signed checkpoint per D0024 §3.
///
/// Offline + deterministic: no network. Verifies the ECDSA P-256
/// checkpoint signature against `pinned_rekor_pubkey_pem` (a PEM/SPKI
/// public key), parses the signed note, then reconstructs the RFC 6962
/// inclusion proof and checks it against the note's root hash.
///
/// # Errors
///
/// - [`SigstoreVerifyError::RekorCheckpointVerifyFailed`] if the pinned
///   key fails to parse, the DER signature fails to parse, the ECDSA
///   verification fails, or the signed note is malformed.
/// - [`SigstoreVerifyError::RekorInclusionProofVerifyFailed`] if the
///   leaf index is out of range, the proof length is wrong, or the
///   reconstructed root does not match the checkpoint root.
pub fn verify_rekor_inclusion(
    bundle: &RekorBundle,
    pinned_rekor_pubkey_pem: &[u8],
) -> Result<RekorCheckpoint, SigstoreVerifyError> {
    // (1) Verify the signed checkpoint FIRST: this establishes the
    // trusted root hash. A failure here means the checkpoint is not the
    // one Rekor signed, so the inclusion proof is moot.
    let pem = core::str::from_utf8(pinned_rekor_pubkey_pem)
        .map_err(|_| SigstoreVerifyError::RekorCheckpointVerifyFailed)?;
    let verifying_key = VerifyingKey::from_public_key_pem(pem)
        .map_err(|_| SigstoreVerifyError::RekorCheckpointVerifyFailed)?;
    let signature = Signature::from_der(&bundle.checkpoint_signature)
        .map_err(|_| SigstoreVerifyError::RekorCheckpointVerifyFailed)?;
    verifying_key
        .verify(&bundle.checkpoint_note, &signature)
        .map_err(|_| SigstoreVerifyError::RekorCheckpointVerifyFailed)?;

    // (2) Parse the now-trusted note. The tree size + root hash come
    // from the signed bytes — never from a separate, unsigned field.
    let checkpoint = parse_checkpoint_note(&bundle.checkpoint_note)
        .ok_or(SigstoreVerifyError::RekorCheckpointVerifyFailed)?;

    // (3) Reconstruct the inclusion proof and compare to the signed
    // root hash.
    let computed_root = root_from_inclusion_proof(
        bundle.leaf_index,
        checkpoint.tree_size,
        &bundle.leaf_hash,
        &bundle.proof_nodes,
    )
    .ok_or(SigstoreVerifyError::RekorInclusionProofVerifyFailed)?;

    if computed_root != checkpoint.root_hash {
        return Err(SigstoreVerifyError::RekorInclusionProofVerifyFailed);
    }

    Ok(checkpoint)
}

/// Parse a C2SP tlog-checkpoint note body into its origin, tree size,
/// and root hash. Returns `None` on any structural error (non-UTF-8,
/// missing lines, empty origin, non-decimal size, bad base64, wrong
/// root length).
fn parse_checkpoint_note(note: &[u8]) -> Option<RekorCheckpoint> {
    let text = core::str::from_utf8(note).ok()?;
    let mut lines = text.split('\n');

    let origin = lines.next()?;
    if origin.is_empty() {
        return None;
    }
    let tree_size = lines.next()?.parse::<u64>().ok()?;
    let root_b64 = lines.next()?;
    let root_bytes = base64::engine::general_purpose::STANDARD
        .decode(root_b64)
        .ok()?;
    if root_bytes.len() != 32 {
        return None;
    }
    let mut root_hash = [0u8; 32];
    for (slot, byte) in root_hash.iter_mut().zip(root_bytes.iter()) {
        *slot = *byte;
    }
    // Any further lines are opaque C2SP extension lines; ignored.
    Some(RekorCheckpoint {
        origin: origin.to_owned(),
        tree_size,
        root_hash,
    })
}

/// Reconstruct the RFC 6962 Merkle root from an inclusion proof.
///
/// Uses the transparency-dev decomposition: `inner` is the number of
/// proof nodes below the rightmost border (bit-length of
/// `index XOR (size-1)`), `border` the number above it
/// (`popcount(index >> inner)`). Returns `None` if the index is out of
/// range or the proof length is wrong.
fn root_from_inclusion_proof(
    index: u64,
    size: u64,
    leaf_hash: &[u8; 32],
    proof: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if index >= size {
        return None;
    }
    // size >= 1 here (index >= 0 and index < size).
    let size_minus_one = size.wrapping_sub(1);
    let inner: u32 = u64::BITS.saturating_sub((index ^ size_minus_one).leading_zeros());
    let border = index.checked_shr(inner).map_or(0, u64::count_ones);

    let inner_len = inner as usize;
    let expected_len = inner_len.saturating_add(border as usize);
    if proof.len() != expected_len {
        return None;
    }

    // inner_len <= proof.len(), so split_at does not panic.
    let (inner_nodes, border_nodes) = proof.split_at(inner_len);

    let mut res = *leaf_hash;
    for (i, node) in (0u32..).zip(inner_nodes.iter()) {
        // Bit i of `index` decides whether the proof node is the left
        // sibling (bit set) or the right sibling (bit clear). i < inner
        // <= 64, so the shift never exceeds the width.
        let bit = index.checked_shr(i).unwrap_or(0) & 1;
        res = if bit == 0 {
            hash_children(&res, node)
        } else {
            hash_children(node, &res)
        };
    }
    for node in border_nodes {
        res = hash_children(node, &res);
    }
    Some(res)
}

/// RFC 6962 interior-node hash: `SHA-256(0x01 || left || right)`.
fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01u8]);
    hasher.update(left);
    hasher.update(right);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    for (slot, byte) in arr.iter_mut().zip(out.iter()) {
        *slot = *byte;
    }
    arr
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer as _;
    use p256::pkcs8::{EncodePublicKey as _, LineEnding};
    use rand_core::OsRng;

    // ---- RFC 6962 reference tree (for building valid fixtures) ----

    /// Largest power of two strictly less than `n` (for `n >= 2`).
    const fn largest_pow2_below(n: usize) -> usize {
        let mut k = 1;
        while k * 2 < n {
            k *= 2;
        }
        k
    }

    /// RFC 6962 Merkle tree hash over already-hashed leaf nodes.
    fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves.len() {
            0 => panic!("empty tree not used in tests"),
            1 => leaves[0],
            n => {
                let k = largest_pow2_below(n);
                let (l, r) = leaves.split_at(k);
                hash_children(&mth(l), &mth(r))
            }
        }
    }

    /// RFC 6962 audit path for the leaf at `index`.
    fn audit_path(index: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
        if leaves.len() <= 1 {
            return vec![];
        }
        let k = largest_pow2_below(leaves.len());
        let (l, r) = leaves.split_at(k);
        if index < k {
            let mut p = audit_path(index, l);
            p.push(mth(r));
            p
        } else {
            let mut p = audit_path(index - k, r);
            p.push(mth(l));
            p
        }
    }

    /// A distinct leaf node value (already the RFC 6962 `0x00`-prefixed
    /// leaf hash conceptually; for tests any distinct 32-byte value
    /// works since the verifier only combines interior nodes).
    fn leaf(i: u8) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x00u8]);
        hasher.update([i]);
        let out = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }

    fn checkpoint_note(origin: &str, tree_size: u64, root: &[u8; 32]) -> Vec<u8> {
        let root_b64 = base64::engine::general_purpose::STANDARD.encode(root);
        format!("{origin}\n{tree_size}\n{root_b64}\n").into_bytes()
    }

    /// Build a valid bundle for `leaf_index` in a tree of `num_leaves`,
    /// signed by `sk`. Returns the bundle + the pinned PEM.
    fn make_valid_bundle(
        sk: &SigningKey,
        num_leaves: usize,
        leaf_index: usize,
    ) -> (RekorBundle, Vec<u8>) {
        let leaves: Vec<[u8; 32]> = (0..num_leaves)
            .map(|i| leaf(u8::try_from(i).unwrap()))
            .collect();
        let root = mth(&leaves);
        let proof = audit_path(leaf_index, &leaves);
        let note = checkpoint_note("rekor.example/test", num_leaves as u64, &root);
        let sig: Signature = sk.sign(&note);
        let pem = VerifyingKey::from(sk)
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .into_bytes();
        let bundle = RekorBundle {
            leaf_hash: leaves[leaf_index],
            leaf_index: leaf_index as u64,
            proof_nodes: proof,
            checkpoint_note: note,
            checkpoint_signature: sig.to_der().as_bytes().to_vec(),
        };
        (bundle, pem)
    }

    #[test]
    fn accepts_valid_inclusion_and_checkpoint() {
        let sk = SigningKey::random(&mut OsRng);
        let (bundle, pem) = make_valid_bundle(&sk, 5, 2);
        let checkpoint = verify_rekor_inclusion(&bundle, &pem).expect("valid bundle must verify");
        assert_eq!(checkpoint.tree_size, 5);
        assert_eq!(checkpoint.origin, "rekor.example/test");
    }

    #[test]
    fn accepts_single_leaf_tree_with_empty_proof() {
        let sk = SigningKey::random(&mut OsRng);
        let (bundle, pem) = make_valid_bundle(&sk, 1, 0);
        assert!(bundle.proof_nodes.is_empty());
        assert!(verify_rekor_inclusion(&bundle, &pem).is_ok());
    }

    #[test]
    fn accepts_every_index_in_a_seven_leaf_tree() {
        // Exercises the inner/border decomposition across an unbalanced
        // (non-power-of-two) tree at every position.
        let sk = SigningKey::random(&mut OsRng);
        for idx in 0..7 {
            let (bundle, pem) = make_valid_bundle(&sk, 7, idx);
            assert!(
                verify_rekor_inclusion(&bundle, &pem).is_ok(),
                "index {idx} of 7 must verify"
            );
        }
    }

    #[test]
    fn rejects_tampered_leaf_hash() {
        let sk = SigningKey::random(&mut OsRng);
        let (mut bundle, pem) = make_valid_bundle(&sk, 5, 2);
        bundle.leaf_hash[0] ^= 0xFF;
        assert!(matches!(
            verify_rekor_inclusion(&bundle, &pem),
            Err(SigstoreVerifyError::RekorInclusionProofVerifyFailed)
        ));
    }

    #[test]
    fn rejects_tampered_proof_node() {
        let sk = SigningKey::random(&mut OsRng);
        let (mut bundle, pem) = make_valid_bundle(&sk, 5, 2);
        bundle.proof_nodes[0][0] ^= 0xFF;
        assert!(matches!(
            verify_rekor_inclusion(&bundle, &pem),
            Err(SigstoreVerifyError::RekorInclusionProofVerifyFailed)
        ));
    }

    #[test]
    fn rejects_wrong_leaf_index() {
        let sk = SigningKey::random(&mut OsRng);
        let (mut bundle, pem) = make_valid_bundle(&sk, 5, 2);
        // The proof was built for index 2; claiming index 3 reshapes the
        // path and the reconstructed root will not match.
        bundle.leaf_index = 3;
        assert!(matches!(
            verify_rekor_inclusion(&bundle, &pem),
            Err(SigstoreVerifyError::RekorInclusionProofVerifyFailed)
        ));
    }

    #[test]
    fn rejects_leaf_index_out_of_range() {
        let sk = SigningKey::random(&mut OsRng);
        let (mut bundle, pem) = make_valid_bundle(&sk, 5, 2);
        bundle.leaf_index = 99; // >= tree_size
        assert!(matches!(
            verify_rekor_inclusion(&bundle, &pem),
            Err(SigstoreVerifyError::RekorInclusionProofVerifyFailed)
        ));
    }

    #[test]
    fn rejects_proof_of_wrong_length() {
        let sk = SigningKey::random(&mut OsRng);
        let (mut bundle, pem) = make_valid_bundle(&sk, 5, 2);
        bundle.proof_nodes.push([0x77; 32]); // one node too many
        assert!(matches!(
            verify_rekor_inclusion(&bundle, &pem),
            Err(SigstoreVerifyError::RekorInclusionProofVerifyFailed)
        ));
    }

    #[test]
    fn rejects_tampered_checkpoint_note() {
        let sk = SigningKey::random(&mut OsRng);
        let (mut bundle, pem) = make_valid_bundle(&sk, 5, 2);
        // Flip a byte of the signed note -> ECDSA verify fails.
        bundle.checkpoint_note[0] ^= 0xFF;
        assert!(matches!(
            verify_rekor_inclusion(&bundle, &pem),
            Err(SigstoreVerifyError::RekorCheckpointVerifyFailed)
        ));
    }

    #[test]
    fn rejects_checkpoint_signed_by_wrong_key() {
        let sk = SigningKey::random(&mut OsRng);
        let (bundle, _pem) = make_valid_bundle(&sk, 5, 2);
        // Pin a DIFFERENT key than the one that signed.
        let imposter = SigningKey::random(&mut OsRng);
        let imposter_pem = VerifyingKey::from(&imposter)
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .into_bytes();
        assert!(matches!(
            verify_rekor_inclusion(&bundle, &imposter_pem),
            Err(SigstoreVerifyError::RekorCheckpointVerifyFailed)
        ));
    }

    #[test]
    fn rejects_validly_signed_but_malformed_note() {
        // A note the key DID sign, but whose body is not a valid
        // checkpoint (bad base64 root): signature passes, parse fails ->
        // RekorCheckpointVerifyFailed.
        let sk = SigningKey::random(&mut OsRng);
        let note = b"rekor.example/test\n5\nnot-valid-base64-!!!\n".to_vec();
        let sig: Signature = sk.sign(&note);
        let pem = VerifyingKey::from(&sk)
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
            .into_bytes();
        let bundle = RekorBundle {
            leaf_hash: leaf(0),
            leaf_index: 0,
            proof_nodes: vec![],
            checkpoint_note: note,
            checkpoint_signature: sig.to_der().as_bytes().to_vec(),
        };
        assert!(matches!(
            verify_rekor_inclusion(&bundle, &pem),
            Err(SigstoreVerifyError::RekorCheckpointVerifyFailed)
        ));
    }

    #[test]
    fn rejects_garbage_pinned_key() {
        let sk = SigningKey::random(&mut OsRng);
        let (bundle, _pem) = make_valid_bundle(&sk, 5, 2);
        assert!(matches!(
            verify_rekor_inclusion(
                &bundle,
                b"-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----"
            ),
            Err(SigstoreVerifyError::RekorCheckpointVerifyFailed)
        ));
    }
}
