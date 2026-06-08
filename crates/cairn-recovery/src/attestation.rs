// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Master attestation data structure + signed-envelope wrapper.
//!
//! Payload schema (canonical-CBOR map with integer keys per COSE
//! conventions):
//!
//! | Key | Field | CBOR type | Notes |
//! |-----|-------|-----------|-------|
//! | 1 | `master` | bstr(32) | The user's long-lived master public key |
//! | 2 | `operational_identity` | bstr(32) | The new operational identity being attested |
//! | 3 | `timestamp` | uint | Unix-seconds when the attestation was issued |
//!
//! Signed by the master directly (NOT by a device key under a
//! capability token — the master is its own root of trust).

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, SigningKey, VerifyingKey};
use cairn_envelope::canonical::Value;
use cairn_envelope::cose_sign1::{CoseSign1, Sign1Builder};
use cairn_shamir::{Commitment, SECRET_LEN, Share, reconstruct, split};
use ciborium::Value as CiboriumValue;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::card::RecoveryCard;
use crate::error::RecoveryError;

/// Length of the SHA-256 hash output bound to `issuer_cert_hash` per
/// D0006 §7.
pub const ISSUER_CERT_HASH_LEN: usize = 32;

/// Canonical-CBOR map key for `master`.
const KEY_MASTER: i64 = 1;
/// Canonical-CBOR map key for `operational_identity`.
const KEY_OPERATIONAL_IDENTITY: i64 = 2;
/// Canonical-CBOR map key for `timestamp`.
const KEY_TIMESTAMP: i64 = 3;

/// Domain-separation tag for master attestations.
///
/// D0006 §8 explicitly enumerates two domain tags (`cairn-v1-capability-token`
/// and `cairn-v1-trust-graph-operation`) but the same cross-protocol
/// substitution defense applies to every distinct signed-envelope type
/// in the system. This tag extends D0006 §8 by analogy: master
/// attestations are a third signed envelope (signed by the master
/// directly, no capability token wrapping) and need their own domain
/// tag for the same reason — without it, an adversary who obtained
/// any Ed25519 signature from the master could attempt to reinterpret
/// the signed bytes as a master attestation.
///
/// Bound into the `COSE_Sign1` `Sig_structure` via `external_aad` per
/// RFC 9052 §4.4.
pub const DOMAIN_TAG: &[u8] = b"cairn-v1-master-attestation";

/// Master attestation of a new operational identity per D0005 +
/// D0006 §6.
///
/// Construct via [`Self::new`]; sign via [`Self::sign`]; verify via
/// [`SignedMasterAttestation::from_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterAttestation {
    /// The user's long-lived master Ed25519 public key.
    pub master: VerifyingKey,
    /// The new operational identity being attested.
    pub operational_identity: VerifyingKey,
    /// Unix-seconds when the attestation was issued.
    pub timestamp: u64,
}

impl MasterAttestation {
    /// Construct a master attestation.
    #[must_use]
    pub const fn new(
        master: VerifyingKey,
        operational_identity: VerifyingKey,
        timestamp: u64,
    ) -> Self {
        Self {
            master,
            operational_identity,
            timestamp,
        }
    }

    /// Encode as canonical-CBOR bytes (the `COSE_Sign1` payload).
    ///
    /// # Errors
    ///
    /// - [`RecoveryError::TimestampOutOfRange`] if `timestamp` doesn't
    ///   fit in `i64`.
    /// - [`RecoveryError::CanonicalEncode`] from the canonical encoder.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, RecoveryError> {
        let timestamp_i64 =
            i64::try_from(self.timestamp).map_err(|_| RecoveryError::TimestampOutOfRange)?;
        let map = Value::Map(vec![
            (
                Value::Int(KEY_MASTER),
                Value::Bytes(self.master.to_bytes().to_vec()),
            ),
            (
                Value::Int(KEY_OPERATIONAL_IDENTITY),
                Value::Bytes(self.operational_identity.to_bytes().to_vec()),
            ),
            (Value::Int(KEY_TIMESTAMP), Value::Int(timestamp_i64)),
        ]);
        map.encode().map_err(RecoveryError::from)
    }

    /// Decode from canonical-CBOR bytes.
    ///
    /// # Errors
    ///
    /// - [`RecoveryError::MalformedPayload`] for any CBOR / schema
    ///   structural error
    /// - [`RecoveryError::InvalidPubkeyLength`] /
    ///   [`RecoveryError::InvalidPubkey`] for pubkey-field issues
    /// - [`RecoveryError::TimestampOutOfRange`] for negative or
    ///   `> 2^63` timestamps
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, RecoveryError> {
        let parsed: CiboriumValue =
            ciborium::de::from_reader(bytes).map_err(|_| RecoveryError::MalformedPayload)?;
        let CiboriumValue::Map(entries) = parsed else {
            return Err(RecoveryError::MalformedPayload);
        };

        let mut master_bytes: Option<Vec<u8>> = None;
        let mut op_identity_bytes: Option<Vec<u8>> = None;
        let mut timestamp: Option<u64> = None;

        for (key, value) in entries {
            let CiboriumValue::Integer(key_int_ciborium) = key else {
                return Err(RecoveryError::MalformedPayload);
            };
            let key_int = i64::try_from(i128::from(key_int_ciborium))
                .map_err(|_| RecoveryError::MalformedPayload)?;
            match key_int {
                KEY_MASTER => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(RecoveryError::MalformedPayload);
                    };
                    master_bytes = Some(b);
                }
                KEY_OPERATIONAL_IDENTITY => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(RecoveryError::MalformedPayload);
                    };
                    op_identity_bytes = Some(b);
                }
                KEY_TIMESTAMP => {
                    let CiboriumValue::Integer(v) = value else {
                        return Err(RecoveryError::MalformedPayload);
                    };
                    timestamp = Some(
                        u64::try_from(i128::from(v))
                            .map_err(|_| RecoveryError::TimestampOutOfRange)?,
                    );
                }
                _ => {} // forward-compat
            }
        }

        let master_bytes = master_bytes.ok_or(RecoveryError::MalformedPayload)?;
        let op_identity_bytes = op_identity_bytes.ok_or(RecoveryError::MalformedPayload)?;
        let timestamp = timestamp.ok_or(RecoveryError::MalformedPayload)?;

        if master_bytes.len() != PUBLIC_KEY_LEN {
            return Err(RecoveryError::InvalidPubkeyLength {
                got_bytes: master_bytes.len(),
                expected_bytes: PUBLIC_KEY_LEN,
            });
        }
        if op_identity_bytes.len() != PUBLIC_KEY_LEN {
            return Err(RecoveryError::InvalidPubkeyLength {
                got_bytes: op_identity_bytes.len(),
                expected_bytes: PUBLIC_KEY_LEN,
            });
        }
        let master_arr: [u8; PUBLIC_KEY_LEN] = master_bytes
            .as_slice()
            .try_into()
            .map_err(|_| RecoveryError::InvalidPubkey)?;
        let op_arr: [u8; PUBLIC_KEY_LEN] = op_identity_bytes
            .as_slice()
            .try_into()
            .map_err(|_| RecoveryError::InvalidPubkey)?;
        let master =
            VerifyingKey::from_bytes(&master_arr).map_err(|_| RecoveryError::InvalidPubkey)?;
        let operational_identity =
            VerifyingKey::from_bytes(&op_arr).map_err(|_| RecoveryError::InvalidPubkey)?;
        Ok(Self {
            master,
            operational_identity,
            timestamp,
        })
    }

    /// Sign this attestation with the master signing key. The
    /// resulting [`SignedMasterAttestation`] is a `COSE_Sign1`
    /// envelope.
    ///
    /// # Errors
    ///
    /// Propagates encoding / signing failures via [`RecoveryError`].
    pub fn sign(
        &self,
        master_signing_key: &SigningKey,
    ) -> Result<SignedMasterAttestation, RecoveryError> {
        let payload = self.to_canonical_cbor()?;
        let envelope = Sign1Builder::new()
            .with_payload(payload)
            .with_external_aad(DOMAIN_TAG.to_vec())
            .finalize(master_signing_key)
            .map_err(|_| RecoveryError::SignFailed)?;
        Ok(SignedMasterAttestation {
            envelope,
            attestation: self.clone(),
        })
    }
}

/// A `COSE_Sign1`-wrapped master attestation.
///
/// Construct via [`MasterAttestation::sign`] (or
/// [`reconstruct_and_attest`]); decode + verify via
/// [`Self::from_bytes`]; re-encode via [`Self::encode`].
#[derive(Debug, Clone)]
pub struct SignedMasterAttestation {
    envelope: CoseSign1,
    attestation: MasterAttestation,
}

impl SignedMasterAttestation {
    /// Decode envelope bytes + verify the signature against the
    /// expected master pubkey.
    ///
    /// The verifier supplies the master pubkey they trust (typically
    /// loaded from the user's paper backup card at first boot).
    ///
    /// # Errors
    ///
    /// - [`RecoveryError::MalformedPayload`] for envelope / payload
    ///   parse failure
    /// - [`RecoveryError::MasterPubkeyMismatch`] if the embedded
    ///   master pubkey doesn't match the expected one
    /// - [`RecoveryError::SignatureVerifyFailed`] for any crypto-layer
    ///   verify failure (uniform per the no-error-oracle discipline)
    pub fn from_bytes(bytes: &[u8], expected_master: &VerifyingKey) -> Result<Self, RecoveryError> {
        let envelope = CoseSign1::from_bytes(bytes).map_err(|_| RecoveryError::MalformedPayload)?;
        let payload = envelope.payload().ok_or(RecoveryError::MalformedPayload)?;
        let attestation = MasterAttestation::from_canonical_cbor(payload)?;
        if attestation.master != *expected_master {
            return Err(RecoveryError::MasterPubkeyMismatch);
        }
        envelope
            .verify(expected_master, DOMAIN_TAG)
            .map_err(|_| RecoveryError::SignatureVerifyFailed)?;
        Ok(Self {
            envelope,
            attestation,
        })
    }

    /// Get the verified attestation contents.
    #[must_use]
    pub const fn attestation(&self) -> &MasterAttestation {
        &self.attestation
    }

    /// Encode the envelope back to bytes (canonical form).
    ///
    /// # Errors
    ///
    /// Propagates the underlying `COSE_Sign1` encoding error
    /// (unreachable for envelopes constructed via
    /// [`MasterAttestation::sign`] or [`Self::from_bytes`]).
    pub fn encode(&self, tagged: bool) -> Result<Vec<u8>, RecoveryError> {
        self.envelope.encode(tagged).map_err(RecoveryError::from)
    }

    /// Return the canonical D0006 §7 `issuer_cert_hash` for this
    /// master attestation.
    ///
    /// Computes
    /// `SHA-256( deterministic_cbor_encode( master_attestation.Sig_structure ) )`
    /// where `Sig_structure` is bound with the [`DOMAIN_TAG`] external
    /// AAD per D0006 §8 (master-attestation domain).
    ///
    /// The output is the byte string that a trust-graph or capability-
    /// token op writes into its `issuer_cert_hash` field to commit to
    /// the master attestation certifying the operational identity that
    /// signed (or whose device signs under a token for) the op.
    /// Hashing the `Sig_structure` (the bytes the master's signature
    /// covers) is the canonical commitment per D0006 §7's rationale.
    ///
    /// # Errors
    ///
    /// Propagates [`RecoveryError::CanonicalEncode`] from the
    /// `Sig_structure` encoder (unreachable for envelopes constructed
    /// via [`MasterAttestation::sign`] or [`Self::from_bytes`]).
    pub fn issuer_cert_hash(&self) -> Result<[u8; ISSUER_CERT_HASH_LEN], RecoveryError> {
        let sig_structure_bytes = self
            .envelope
            .sig_structure_bytes(DOMAIN_TAG)
            .map_err(RecoveryError::from)?;
        let mut hasher = Sha256::new();
        hasher.update(&sig_structure_bytes);
        let out = hasher.finalize();
        let mut arr = [0u8; ISSUER_CERT_HASH_LEN];
        arr.copy_from_slice(&out);
        Ok(arr)
    }
}

/// Reconstruct the master from Shamir shares + commitment, sign a
/// master attestation of `new_operational_identity_pubkey`, and zero
/// the reconstructed master seed.
///
/// The master seed is held in `Zeroizing<[u8; SECRET_LEN]>` for the
/// duration of this function and is wiped on exit (via the
/// `Zeroizing` Drop impl). The returned signed attestation does NOT
/// carry any master-secret material — only the master pubkey
/// (computed via `SigningKey::verifying_key`).
///
/// # Errors
///
/// - [`RecoveryError::ShamirReconstruct`] if the Shamir layer rejects
///   the share set (insufficient shares / tampered / wrong commitment;
///   uniform per D0018 §3.4)
/// - [`RecoveryError::CanonicalEncode`] / [`RecoveryError::SignFailed`]
///   from the attestation construction step
pub fn reconstruct_and_attest(
    master_shares: &[Share],
    master_commitment: &Commitment,
    new_operational_identity_pubkey: VerifyingKey,
    timestamp: u64,
) -> Result<SignedMasterAttestation, RecoveryError> {
    // Reconstruct the master seed (held in Zeroizing).
    let master_seed: Zeroizing<[u8; SECRET_LEN]> = reconstruct(master_shares, master_commitment)?;

    // Derive the master SigningKey from the seed. SigningKey stores
    // the seed in its own SecretBox internally; the local
    // `master_seed` will be wiped at function exit via Zeroizing.
    let master_signing_key = SigningKey::from_seed(&master_seed);
    let master_pubkey = master_signing_key.verifying_key();

    // Build and sign the attestation.
    let attestation =
        MasterAttestation::new(master_pubkey, new_operational_identity_pubkey, timestamp);
    let signed = attestation.sign(&master_signing_key)?;

    // master_signing_key drops here → its internal SecretBox is zeroized.
    // master_seed drops here → Zeroizing wipes the bytes.
    drop(master_signing_key);
    drop(master_seed);

    Ok(signed)
}

/// The public outputs of an atomic master re-split (D0040 §5).
///
/// Everything here is public-or-transportable: the [`SignedMasterAttestation`]
/// is a public credential, and each [`RecoveryCard`] carries a single Shamir
/// share (below the reconstruction threshold — reveals nothing about the seed)
/// plus the public new commitment + master pubkey. The reconstructed master
/// seed that produced them is **not** here — it never leaves
/// [`reconstruct_resplit_and_attest`].
#[derive(Debug, Clone)]
pub struct ResplitOutput {
    /// The master-signed attestation binding the master to the new operational
    /// identity (the hop-#3 credential, identical in kind to what
    /// [`reconstruct_and_attest`] returns).
    pub attestation: SignedMasterAttestation,
    /// The freshly-split recovery cards — one per NEW share, each
    /// self-contained (share + new commitment + master pubkey), ready to
    /// re-distribute to recovery peers.
    pub new_cards: Vec<RecoveryCard>,
    /// The recovered master public key (the verifier for the new card set).
    /// Surfaced explicitly so callers need not decode a card to learn it.
    pub master: VerifyingKey,
    /// The new share set's commitment. NOTE: this equals the OLD commitment —
    /// it is `BLAKE3(secret)` and the secret is unchanged across re-split — but
    /// it is surfaced so callers can store/verify against the new card set
    /// without reaching into an individual [`RecoveryCard`].
    pub new_commitment: Commitment,
}

/// Atomically reconstruct the master, **re-split** it into a fresh share set,
/// and attest a new operational identity (D0040 §5 — the secret-bearing core
/// of coercion-resistant re-split).
///
/// Runs the master seed's entire lifecycle in one call so the seed never
/// crosses a boundary:
///
/// 1. Reconstruct the seed from the OLD share set (held in `Zeroizing`).
/// 2. Derive the master key + pubkey.
/// 3. Re-split the SAME seed into `new_num_shares` fresh shares with a NEW
///    commitment under `new_threshold` (consuming `rng` for entropy).
/// 4. Sign the new-operational-identity attestation.
/// 5. Encode each new share as a self-contained [`RecoveryCard`].
/// 6. Wipe the seed + master key (`Zeroizing` / `SecretBox` `Drop`).
///
/// ## What this does and does NOT guarantee
///
/// The secret is **unchanged** — only its *sharing* is refreshed — so the OLD
/// shares still reconstruct the SAME master. The "old cards can no longer
/// recover" goal is therefore a **soft** property: it holds only if the honest
/// holders of the old cards delete them (D0040 §5). The **hard** property this
/// function provides is non-leaking atomicity: a failure at any step leaks no
/// master material (everything sensitive is local + zeroized on the way out),
/// and the new identity is attested only if the whole chain succeeds.
///
/// # Errors
///
/// - [`RecoveryError::ShamirReconstruct`] if the OLD shares do not reconstruct
///   to the committed master (insufficient / wrong / tampered cards) —
///   user-actionable (gather more cards).
/// - [`RecoveryError::ShamirSplit`] if the fresh split rejects its parameters
///   (`new_threshold` / `new_num_shares` out of range) or otherwise fails — an
///   internal fault, distinct from a reconstruct failure.
/// - [`RecoveryError::CanonicalEncode`] / [`RecoveryError::SignFailed`] from the
///   attestation construction step.
pub fn reconstruct_resplit_and_attest<R: CryptoRng + RngCore>(
    old_master_shares: &[Share],
    old_master_commitment: &Commitment,
    new_operational_identity_pubkey: VerifyingKey,
    new_threshold: u8,
    new_num_shares: u8,
    timestamp: u64,
    rng: &mut R,
) -> Result<ResplitOutput, RecoveryError> {
    // 1. Reconstruct the master seed from the OLD shares (Zeroizing wipes it on
    //    exit). A failure here is the user-actionable "wrong/insufficient
    //    cards" case.
    let master_seed: Zeroizing<[u8; SECRET_LEN]> =
        reconstruct(old_master_shares, old_master_commitment)?;

    // 2. Derive the master key. SigningKey stores the seed in its own
    //    SecretBox; both it and `master_seed` are wiped at function exit.
    let master_signing_key = SigningKey::from_seed(&master_seed);
    let master_pubkey = master_signing_key.verifying_key();

    // 3. Re-split the SAME seed into a fresh share set + NEW commitment. The
    //    split failure is mapped to the DISTINCT ShamirSplit variant so it is
    //    not confused with the reconstruct failure above (different
    //    remediation — see the variant docs).
    let (new_shares, new_commitment) = split(&master_seed, new_threshold, new_num_shares, rng)
        .map_err(RecoveryError::ShamirSplit)?;

    // 4. Sign the new-operational-identity attestation (the same hop-#3
    //    credential reconstruct_and_attest produces).
    let attestation =
        MasterAttestation::new(master_pubkey, new_operational_identity_pubkey, timestamp);
    let signed = attestation.sign(&master_signing_key)?;

    // 5. Encode each fresh share as a self-contained recovery card. The
    //    commitment + master pubkey are public; the share is below threshold.
    let commitment_bytes = new_commitment.to_bytes();
    let master_bytes = master_pubkey.to_bytes();
    let new_cards: Vec<RecoveryCard> = new_shares
        .iter()
        .map(|share| RecoveryCard {
            id: share.id(),
            value: *share.bytes(),
            commitment: commitment_bytes,
            master: master_bytes,
        })
        .collect();

    // 6. Wipe the seed + master key (Zeroizing / SecretBox Drop). Only the
    //    public ResplitOutput leaves.
    drop(master_signing_key);
    drop(master_seed);

    Ok(ResplitOutput {
        attestation: signed,
        new_cards,
        master: master_pubkey,
        new_commitment,
    })
}

#[cfg(test)]
mod tests {
    // `indexing_slicing` allowed at the test-module level: shares and
    // envelope bytes are produced by the test setup and have
    // statically-known lengths.
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use cairn_shamir::split;
    use rand_core::OsRng;

    /// Pre-condition for the recovery tests: produce a master
    /// `SigningKey` plus its 3-of-5 Shamir share set plus commitment.
    fn provision_master(rng: &mut OsRng) -> (SigningKey, Vec<Share>, Commitment) {
        use rand_core::RngCore as _;
        let mut seed_bytes = [0u8; SECRET_LEN];
        rng.fill_bytes(&mut seed_bytes);
        let master_seed = Zeroizing::new(seed_bytes);
        let master_signing_key = SigningKey::from_seed(&master_seed);
        let (shares, commitment) = split(&master_seed, 3, 5, rng).unwrap();
        (master_signing_key, shares, commitment)
    }

    #[test]
    fn reconstruct_and_attest_happy_path() {
        let mut rng = OsRng;
        let (master_sk, shares, commitment) = provision_master(&mut rng);
        let new_op_identity = SigningKey::generate(&mut rng).verifying_key();

        let signed =
            reconstruct_and_attest(&shares[..3], &commitment, new_op_identity, 1_700_000_000)
                .unwrap();

        let bytes = signed.encode(false).unwrap();
        let recovered =
            SignedMasterAttestation::from_bytes(&bytes, &master_sk.verifying_key()).unwrap();
        assert_eq!(recovered.attestation().master, master_sk.verifying_key());
        assert_eq!(
            recovered.attestation().operational_identity,
            new_op_identity
        );
        assert_eq!(recovered.attestation().timestamp, 1_700_000_000);
    }

    #[test]
    fn resplit_yields_fresh_shares_recovering_the_same_master() {
        // The atomic re-split core (D0040 §5): reconstruct from a threshold of
        // OLD cards, re-split into a FRESH set, attest the new op — and the
        // fresh set must recover the SAME master, under a NEW commitment.
        let mut rng = OsRng;
        let (master_sk, old_shares, old_commitment) = provision_master(&mut rng);
        let master_public = master_sk.verifying_key();
        let new_op_identity = SigningKey::generate(&mut rng).verifying_key();

        let out = reconstruct_resplit_and_attest(
            &old_shares[..3],
            &old_commitment,
            new_op_identity,
            3,
            5,
            1_700_000_000,
            &mut rng,
        )
        .unwrap();

        // (a) The attestation verifies against the SAME master + binds the new op.
        let bytes = out.attestation.encode(false).unwrap();
        let recovered = SignedMasterAttestation::from_bytes(&bytes, &master_public).unwrap();
        assert_eq!(recovered.attestation().master, master_public);
        assert_eq!(
            recovered.attestation().operational_identity,
            new_op_identity
        );

        // (b) The explicit-output fields state the contract directly, and each
        //     card agrees with them: a fresh 5-card set, all carrying the master
        //     pubkey + the (shared) new commitment.
        assert_eq!(out.master, master_public, "master surfaced explicitly");
        assert_eq!(out.new_cards.len(), 5);
        for card in &out.new_cards {
            assert_eq!(card.master, master_public.to_bytes());
            assert_eq!(card.commitment, out.new_commitment.to_bytes());
        }

        // (c) The NEW shares reconstruct the IDENTICAL master (the secret is
        //     unchanged; only its sharing is refreshed).
        let new_shares: Vec<Share> = out.new_cards[..3]
            .iter()
            .map(|c| Share::try_from_parts(c.id, Zeroizing::new(c.value)).unwrap())
            .collect();
        let new_seed = reconstruct(&new_shares, &out.new_commitment).unwrap();
        assert_eq!(
            SigningKey::from_seed(&new_seed).verifying_key(),
            master_public,
            "the fresh share set recovers the identical master"
        );

        // (d) The commitment is UNCHANGED across re-split — it is BLAKE3 of the
        //     SECRET (the master seed), which re-split leaves invariant; only the
        //     SHARES are re-randomized. So the freshness witness is on the share
        //     VALUES, while the commitment is asserted identical.
        assert_eq!(
            out.new_cards[0].commitment,
            old_commitment.to_bytes(),
            "the commitment is to the unchanged secret, so it is preserved"
        );
        let old_values: Vec<[u8; SECRET_LEN]> = old_shares.iter().map(|s| *s.bytes()).collect();
        let new_values: Vec<[u8; SECRET_LEN]> = out.new_cards.iter().map(|c| c.value).collect();
        assert_ne!(
            new_values, old_values,
            "re-split must draw a fresh polynomial → different share values"
        );

        // (e) Soft-property witness (D0040 §5): the OLD shares STILL reconstruct
        //     the same master — re-split does NOT cryptographically invalidate
        //     them; only honest deletion by their holders does.
        let old_seed = reconstruct(&old_shares[..3], &old_commitment).unwrap();
        assert_eq!(
            SigningKey::from_seed(&old_seed).verifying_key(),
            master_public,
            "old shares remain cryptographically valid post-re-split (soft property)"
        );
    }

    #[test]
    fn resplit_with_insufficient_old_shares_fails_reconstruct() {
        // Only 2 of a 3-of-5 OLD set → the reconstruct step fails BEFORE any
        // new split, surfacing the user-actionable ShamirReconstruct (not the
        // internal ShamirSplit).
        let mut rng = OsRng;
        let (_master_sk, old_shares, old_commitment) = provision_master(&mut rng);
        let new_op_identity = SigningKey::generate(&mut rng).verifying_key();

        let err = reconstruct_resplit_and_attest(
            &old_shares[..2],
            &old_commitment,
            new_op_identity,
            3,
            5,
            1_700_000_000,
            &mut rng,
        )
        .unwrap_err();
        assert!(
            matches!(err, RecoveryError::ShamirReconstruct(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn resplit_with_bad_new_parameters_maps_to_shamir_split() {
        // A valid OLD set reconstructs, but new_threshold > new_num_shares is an
        // invalid split → the DISTINCT ShamirSplit variant (internal fault),
        // never mislabeled as a reconstruct failure.
        let mut rng = OsRng;
        let (_master_sk, old_shares, old_commitment) = provision_master(&mut rng);
        let new_op_identity = SigningKey::generate(&mut rng).verifying_key();

        let err = reconstruct_resplit_and_attest(
            &old_shares[..3],
            &old_commitment,
            new_op_identity,
            5, // threshold ...
            3, // ... exceeds num_shares → InvalidParameters
            1_700_000_000,
            &mut rng,
        )
        .unwrap_err();
        assert!(matches!(err, RecoveryError::ShamirSplit(_)), "got {err:?}");
    }

    #[test]
    fn reconstruct_with_tampered_share_fails() {
        let mut rng = OsRng;
        let (_master_sk, shares, commitment) = provision_master(&mut rng);
        let new_op_identity = SigningKey::generate(&mut rng).verifying_key();

        // Tamper share[0]: flip a bit in the value bytes.
        let original = shares[0].clone();
        let mut tampered_bytes = *original.bytes();
        tampered_bytes[0] ^= 0xFF;
        let tampered_share =
            Share::try_from_parts(original.id(), Zeroizing::new(tampered_bytes)).unwrap();
        let mut tampered_shares = vec![tampered_share];
        tampered_shares.extend_from_slice(&shares[1..3]);

        let result = reconstruct_and_attest(
            &tampered_shares,
            &commitment,
            new_op_identity,
            1_700_000_000,
        );
        assert!(matches!(result, Err(RecoveryError::ShamirReconstruct(_))));
    }

    #[test]
    fn reconstruct_with_insufficient_shares_fails() {
        let mut rng = OsRng;
        let (_master_sk, shares, commitment) = provision_master(&mut rng);
        let new_op_identity = SigningKey::generate(&mut rng).verifying_key();

        // Only 2 shares for a 3-of-5 split.
        let result =
            reconstruct_and_attest(&shares[..2], &commitment, new_op_identity, 1_700_000_000);
        assert!(matches!(result, Err(RecoveryError::ShamirReconstruct(_))));
    }

    #[test]
    fn verify_with_wrong_expected_master_rejected() {
        let mut rng = OsRng;
        let (master_sk, shares, commitment) = provision_master(&mut rng);
        let new_op_identity = SigningKey::generate(&mut rng).verifying_key();
        let signed =
            reconstruct_and_attest(&shares[..3], &commitment, new_op_identity, 1_700_000_000)
                .unwrap();
        let bytes = signed.encode(false).unwrap();

        let other_master = SigningKey::generate(&mut rng).verifying_key();
        let result = SignedMasterAttestation::from_bytes(&bytes, &other_master);
        assert!(matches!(result, Err(RecoveryError::MasterPubkeyMismatch)));
        // Confirm the original master pubkey is what's actually inside.
        assert_ne!(other_master, master_sk.verifying_key());
    }

    #[test]
    fn tampered_attestation_bytes_fail_verify() {
        let mut rng = OsRng;
        let (master_sk, shares, commitment) = provision_master(&mut rng);
        let new_op_identity = SigningKey::generate(&mut rng).verifying_key();
        let signed =
            reconstruct_and_attest(&shares[..3], &commitment, new_op_identity, 1_700_000_000)
                .unwrap();
        let mut bytes = signed.encode(false).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        let result = SignedMasterAttestation::from_bytes(&bytes, &master_sk.verifying_key());
        assert!(result.is_err());
    }

    #[test]
    fn round_trip_canonical_cbor() {
        let mut rng = OsRng;
        let master = SigningKey::generate(&mut rng).verifying_key();
        let op_identity = SigningKey::generate(&mut rng).verifying_key();
        let att = MasterAttestation::new(master, op_identity, 1_700_000_000);
        let bytes = att.to_canonical_cbor().unwrap();
        let decoded = MasterAttestation::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(decoded, att);
    }

    #[test]
    fn deterministic_encoding() {
        let mut rng = OsRng;
        let master = SigningKey::generate(&mut rng).verifying_key();
        let op_identity = SigningKey::generate(&mut rng).verifying_key();
        let att = MasterAttestation::new(master, op_identity, 1_700_000_000);
        let a = att.to_canonical_cbor().unwrap();
        let b = att.to_canonical_cbor().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn signing_with_master_only_path() {
        // Demonstrate: build attestation from an existing master
        // SigningKey directly (no reconstruct step). This is the
        // path used at provisioning time when the master is freshly
        // generated.
        let mut rng = OsRng;
        let master_sk = SigningKey::generate(&mut rng);
        let new_op_identity = SigningKey::generate(&mut rng).verifying_key();
        let att = MasterAttestation::new(master_sk.verifying_key(), new_op_identity, 1_700_000_000);
        let signed = att.sign(&master_sk).unwrap();
        let bytes = signed.encode(false).unwrap();
        let recovered =
            SignedMasterAttestation::from_bytes(&bytes, &master_sk.verifying_key()).unwrap();
        assert_eq!(recovered.attestation(), &att);
    }

    #[test]
    fn domain_tag_value_is_pinned() {
        // Pin the tag byte string to catch accidental edits. The
        // value extends D0006 §8 by analogy; documented in the
        // module-level docs for DOMAIN_TAG.
        assert_eq!(DOMAIN_TAG, b"cairn-v1-master-attestation");
    }

    #[test]
    fn issuer_cert_hash_is_sha256_of_sig_structure_per_d0006_section_7() {
        // D0006 §7: issuer_cert_hash := SHA-256(deterministic_cbor_encode(
        //   master_attestation.Sig_structure
        // ))
        // Independently reconstruct the Sig_structure bytes and SHA-256
        // them; compare against the helper's output.
        use cairn_envelope::canonical::Value;
        use sha2::{Digest as _, Sha256};

        let mut rng = OsRng;
        let master_sk = SigningKey::generate(&mut rng);
        let new_op_identity = SigningKey::generate(&mut rng).verifying_key();
        let att = MasterAttestation::new(master_sk.verifying_key(), new_op_identity, 1_700_000_000);
        let signed = att.sign(&master_sk).unwrap();

        // Manual Sig_structure: ["Signature1", protected_bytes,
        // external_aad, payload]
        let envelope_bytes = signed.encode(false).unwrap();
        let envelope = CoseSign1::from_bytes(&envelope_bytes).unwrap();
        let manual_sig_structure = Value::Array(vec![
            Value::Text("Signature1".to_string()),
            Value::Bytes(envelope.protected_bytes().to_vec()),
            Value::Bytes(DOMAIN_TAG.to_vec()),
            Value::Bytes(envelope.payload().unwrap_or(&[]).to_vec()),
        ]);
        let manual_bytes = manual_sig_structure.encode().unwrap();
        let manual_hash = Sha256::digest(&manual_bytes);

        let helper_hash = signed.issuer_cert_hash().unwrap();
        assert_eq!(helper_hash.as_slice(), manual_hash.as_slice());
        assert_eq!(helper_hash.len(), ISSUER_CERT_HASH_LEN);
    }

    #[test]
    fn issuer_cert_hash_pinned_test_vector_d0006_section_7() {
        // D0006 §7 spec line: "A reference (master_attestation, expected
        // issuer_cert_hash bytes) pair is added to the v1 implementation
        // test suite." Use a deterministic seed pair so the hash output
        // is stable across runs and platforms — any change to the
        // canonical encoding, domain tag, payload schema, or hash
        // function fails this test loudly.
        use cairn_crypto::ed25519::SEED_LEN;
        use zeroize::Zeroizing;

        let master_seed = Zeroizing::new([0x42u8; SEED_LEN]);
        let op_identity_seed = Zeroizing::new([0x37u8; SEED_LEN]);
        let master_sk = SigningKey::from_seed(&master_seed);
        let op_identity_sk = SigningKey::from_seed(&op_identity_seed);

        let att = MasterAttestation::new(
            master_sk.verifying_key(),
            op_identity_sk.verifying_key(),
            1_700_000_000,
        );
        let signed = att.sign(&master_sk).unwrap();
        let hash = signed.issuer_cert_hash().unwrap();

        // Pin the hash bytes. If any of the canonical CBOR encoding,
        // DOMAIN_TAG value, payload schema (keys 1/2/3), or SHA-256
        // implementation changes upstream, this test fails — the
        // failure message prints both expected and actual so the
        // implementer can decide whether the change is intentional.
        let actual_hex = hex_encode(&hash);
        let expected_hex = "e3ee2121f19366b59ede1d48cd9bc4f7ad6f8177ac348f2a992bf32d1aee04b9";
        assert_eq!(
            actual_hex, expected_hex,
            "D0006 §7 reference test vector mismatch"
        );
    }

    /// Hex-encode bytes for printable test-vector pinning.
    fn hex_encode(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        // `saturating_mul` to satisfy `arithmetic_side_effects`; for
        // any realistic hash output (≤ 64 bytes) the saturation case
        // is never reached.
        let mut s = String::with_capacity(bytes.len().saturating_mul(2));
        for b in bytes {
            write!(&mut s, "{b:02x}").expect("writing to String cannot fail");
        }
        s
    }

    #[test]
    fn signature_does_not_verify_under_wrong_domain_tag() {
        // Sign a master attestation (binds the master-attestation tag),
        // then attempt verify under both the capability-token and
        // trust-graph-operation tags. Both must reject — cross-protocol
        // substitution defense.
        let mut rng = OsRng;
        let master_sk = SigningKey::generate(&mut rng);
        let new_op_identity = SigningKey::generate(&mut rng).verifying_key();
        let att = MasterAttestation::new(master_sk.verifying_key(), new_op_identity, 1_700_000_000);
        let signed = att.sign(&master_sk).unwrap();
        let bytes = signed.encode(false).unwrap();
        let envelope = CoseSign1::from_bytes(&bytes).unwrap();

        let wrong_tag_capability =
            envelope.verify(&master_sk.verifying_key(), b"cairn-v1-capability-token");
        assert!(
            wrong_tag_capability.is_err(),
            "master-attestation signature must not verify under capability-token tag"
        );
        let wrong_tag_trust_graph = envelope.verify(
            &master_sk.verifying_key(),
            b"cairn-v1-trust-graph-operation",
        );
        assert!(
            wrong_tag_trust_graph.is_err(),
            "master-attestation signature must not verify under trust-graph-operation tag"
        );
        let no_tag = envelope.verify(&master_sk.verifying_key(), b"");
        assert!(
            no_tag.is_err(),
            "master-attestation signature must not verify under empty AAD"
        );

        // Correct tag verifies — proves the test setup is sound.
        envelope
            .verify(&master_sk.verifying_key(), DOMAIN_TAG)
            .expect("verify must succeed under the master-attestation tag");
    }
}
