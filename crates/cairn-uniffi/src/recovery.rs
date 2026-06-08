// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Recovery export surface (D0027 §2 — the `recovery` per-domain
//! module).
//!
//! Two operations cross the boundary:
//!
//! 1. [`recovery_reconstruct_and_attest`] — the in-app recovery
//!    operation. Kotlin gathers a threshold of the user's Shamir
//!    shares (returned by recovery peers over the messaging layer) and
//!    passes them in; Rust reconstructs the master seed, derives the
//!    master key, signs a fresh master attestation of the new
//!    operational identity, and returns the **public** signed
//!    attestation. The master seed is held in `Zeroizing` and wiped
//!    inside `cairn_recovery::reconstruct_and_attest` — **it never
//!    crosses to Kotlin**.
//! 2. [`recovery_verify_master_attestation`] — hop #3 of the three-hop
//!    identity chain (the hop `cairn-trust-graph` explicitly defers to
//!    higher layers). Verifies a signed master attestation against the
//!    expected master pubkey and returns its public fields.
//!
//! ## What crosses, and what does not (D0027 §4)
//!
//! The master seed is the sealed secret — it is reconstructed, used,
//! and zeroized entirely Rust-side. A single Shamir **share**, by
//! contrast, is `Zeroizing` (sensitive) but NOT `NeverExport`: the
//! recovery design *requires* shares to be transportable (peers hold +
//! return them), so [`ShareRecord`] legitimately crosses as bytes. One
//! share below the threshold reveals nothing about the seed — that is
//! the security argument, encoded in the type system.
//!
//! Provisioning (the initial `split` of a freshly-generated master
//! seed into peer shares) is NOT here: per D0004 it is a facilitated
//! CLI ceremony, not an in-app flow. The app does recovery, not
//! provisioning.

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, VerifyingKey};
use cairn_recovery::{
    SignedMasterAttestation, decode_card, encode_card, reconstruct_and_attest,
    reconstruct_resplit_and_attest,
};
use cairn_shamir::{COMMITMENT_LEN, Commitment, SECRET_LEN, Share};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::error::CairnFfiError;

/// One Shamir share as it crosses the FFI boundary (D0027 §2.2).
///
/// `value` is the share's `SECRET_LEN`-byte payload (sensitive but
/// transportable — a single share is below the reconstruction
/// threshold and reveals nothing about the master seed). `id` is the
/// share's non-zero index. Becomes a `uniffi::Record` under the
/// feature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct ShareRecord {
    /// The share's non-zero index (`id` in the Shamir scheme).
    pub id: u8,
    /// The share's `SECRET_LEN`-byte value.
    pub value: Vec<u8>,
}

/// A decoded paper recovery card (D0038 §4): one Shamir share plus its recovery
/// header.
///
/// The header (the commitment + master pubkey) makes each card self-contained, so
/// the shell collects a threshold of cards and calls
/// [`recovery_reconstruct_and_attest`] without a separate header step.
///
/// All values are PUBLIC-or-transportable: the share is below the reconstruction
/// threshold (reveals nothing about the master seed); the commitment + master
/// pubkey are public.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct RecoveryCardRecord {
    /// The Shamir share this card carries.
    pub share: ShareRecord,
    /// The BLAKE3 commit-of-secret the threshold reconstructs against (32 bytes).
    pub commitment: Vec<u8>,
    /// The master Ed25519 public key (32 bytes) — the reconstruction verifier.
    pub master_pubkey: Vec<u8>,
}

/// Public fields of a verified master attestation (D0027 §2.2) — hop #3
/// of the identity chain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct MasterAttestationRecord {
    /// The user's long-lived master Ed25519 public key (32 bytes).
    pub master: Vec<u8>,
    /// The operational-identity Ed25519 public key (32 bytes) this
    /// attestation binds to the master.
    pub operational_identity: Vec<u8>,
    /// Unix-seconds when the attestation was issued.
    pub timestamp_unix_seconds: u64,
}

/// Decode a paper recovery-card text (`CAIRN-RECOVERY-…`, D0038 §4) into its
/// share and recovery header.
///
/// The shell scans/types one of these per card, collects a threshold, then calls
/// [`recovery_reconstruct_and_attest`]. Pure codec — no secret generation, no
/// RNG; split/provisioning stays a CLI ceremony (D0038 §2).
///
/// # Errors
///
/// [`CairnFfiError::MalformedData`] for a wrong/absent label, a non-base64 or
/// wrong-length body, an unknown magic/version, a zero share id, or a checksum
/// mismatch (a mistyped card).
#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
)]
pub fn recovery_decode_card(card_text: String) -> Result<RecoveryCardRecord, CairnFfiError> {
    let card = decode_card(&card_text).map_err(CairnFfiError::from)?;
    Ok(RecoveryCardRecord {
        share: ShareRecord {
            id: card.id,
            value: card.value.to_vec(),
        },
        commitment: card.commitment.to_vec(),
        master_pubkey: card.master.to_vec(),
    })
}

/// Derive the recovery-phrase commitment hash (D0040 §3 hardening): **Argon2id**
/// over the challenge phrase, keyed by the held share's per-share `salt`.
///
/// The peer stores this hash beside the card it gates. A bare SHA-256 (the prior
/// form) of a human-memorable phrase is brute-forceable in seconds from an
/// exfiltrated peer store (the at-rest finding from the Stage 3a adversarial
/// review); Argon2id raises the per-guess cost ~5–6 orders of magnitude, so a
/// memorable phrase moves from seconds to years. The phrase is expected already
/// normalized (NFC + trimmed) by the caller; we domain-separate it from any other
/// Argon2 use (e.g. the storage KEK) with a fixed prefix. Deterministic given
/// `(salt, phrase)` so the holder's set + verify agree.
///
/// Parameters: Argon2id, v1.3, m = 19 MiB, t = 2, p = 1 (the OWASP-recommended
/// floor) — strong against offline guessing yet light enough to run a handful of
/// times per verify on a phone. `salt` must be ≥ 8 bytes (the store uses 16).
///
/// # Errors
///
/// [`CairnFfiError::MalformedData`] if `salt` is shorter than the Argon2 minimum
/// (8 bytes); [`CairnFfiError::UnmappedInternal`] if Argon2id derivation fails
/// (e.g. a memory-allocation failure) — uniform per D0018 §1.4.
#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
)]
pub fn recovery_phrase_hash(salt: Vec<u8>, phrase: String) -> Result<Vec<u8>, CairnFfiError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    use zeroize::Zeroize;

    const DOMAIN: &[u8] = b"cairn-v1-recovery-phrase";
    const OUT_LEN: usize = 32;
    if salt.len() < 8 {
        return Err(CairnFfiError::MalformedData);
    }
    // m = 19_456 KiB (19 MiB), t = 2, p = 1, 32-byte output.
    let params =
        Params::new(19_456, 2, 1, Some(OUT_LEN)).map_err(|_| CairnFfiError::UnmappedInternal)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut pwd = Vec::with_capacity(DOMAIN.len().saturating_add(phrase.len()));
    pwd.extend_from_slice(DOMAIN);
    pwd.extend_from_slice(phrase.as_bytes());
    let mut out = [0u8; OUT_LEN];
    let res = argon.hash_password_into(&pwd, &salt, &mut out);
    pwd.zeroize();
    res.map_err(|_| CairnFfiError::UnmappedInternal)?;
    Ok(out.to_vec())
}

/// Reconstruct the master seed from a threshold of shares and attest a
/// new operational identity (D0027 §2.2).
///
/// Returns the encoded signed master attestation (public; to be stored
/// and distributed as the rotated identity's hop-#3 credential). The
/// master seed is reconstructed in `Zeroizing` and wiped inside Rust;
/// it never crosses to Kotlin.
///
/// # Errors
///
/// - [`CairnFfiError::MalformedData`] if `commitment` is not
///   [`COMMITMENT_LEN`] bytes, `new_operational_identity_pubkey` is not
///   a valid Ed25519 key, or any share's `value` is not
///   [`SECRET_LEN`] bytes / has a zero id.
/// - [`CairnFfiError::RecoveryFailed`] if the shares do not reconstruct
///   to the committed secret (wrong/insufficient shares) or the
///   attestation could not be signed.
#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
)]
pub fn recovery_reconstruct_and_attest(
    shares: Vec<ShareRecord>,
    commitment: Vec<u8>,
    new_operational_identity_pubkey: Vec<u8>,
    timestamp: u64,
) -> Result<Vec<u8>, CairnFfiError> {
    let commitment_bytes: [u8; COMMITMENT_LEN] = commitment
        .as_slice()
        .try_into()
        .map_err(|_| CairnFfiError::MalformedData)?;
    let commitment = Commitment::from_bytes(commitment_bytes);

    let pubkey_bytes: [u8; PUBLIC_KEY_LEN] = new_operational_identity_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| CairnFfiError::MalformedData)?;
    let new_operational =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| CairnFfiError::MalformedData)?;

    // Rehydrate each ShareRecord into a typed Share. The value bytes go
    // straight into a Zeroizing buffer so the only copy Rust keeps is
    // wiped on drop.
    let shares: Vec<Share> = shares
        .into_iter()
        .map(|share| -> Result<Share, CairnFfiError> {
            let value: [u8; SECRET_LEN] = share
                .value
                .as_slice()
                .try_into()
                .map_err(|_| CairnFfiError::MalformedData)?;
            Share::try_from_parts(share.id, Zeroizing::new(value))
                .map_err(|_| CairnFfiError::MalformedData)
        })
        .collect::<Result<_, _>>()?;

    // The master seed is reconstructed + zeroized entirely inside this
    // call; only the signed (public) attestation is returned.
    let signed = reconstruct_and_attest(&shares, &commitment, new_operational, timestamp)?;
    signed.encode(false).map_err(CairnFfiError::from)
}

/// The public outputs of an atomic master re-split (D0040 §5 / 3c) as they
/// cross the FFI boundary.
///
/// Everything here is public-or-transportable: the `attestation` is a public
/// credential; each entry in `new_cards` is a paper-card text carrying a single
/// Shamir share (below the reconstruction threshold) plus the public commitment
/// and master pubkey. The reconstructed master seed is NOT here — it was
/// reconstructed, re-split, used to sign, and zeroized entirely Rust-side inside
/// [`recovery_resplit_and_attest`]. Becomes a `uniffi::Record` under the feature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct ResplitResultRecord {
    /// The freshly-split recovery cards as paper-card text (`CAIRN-RECOVERY-…`),
    /// one per new share. These are BOTH the owner's new local kit AND what is
    /// sent to each recovery peer in a PREPARE (key 11 alongside the key-13
    /// control).
    pub new_cards: Vec<String>,
    /// The encoded signed master attestation of the new operational identity
    /// (the hop-#3 credential to persist + distribute).
    pub attestation: Vec<u8>,
    /// The recovered master Ed25519 public key (32 bytes).
    pub master_pubkey: Vec<u8>,
    /// The new share set's commitment (32 bytes). NOTE: equals the prior
    /// commitment — it commits to the unchanged master seed — surfaced so the
    /// shell can persist/verify against the new card set without decoding a card.
    pub new_commitment: Vec<u8>,
}

/// Reconstruct the master, **re-split** it into a fresh share set, and attest a
/// new operational identity — the secret-bearing core of coercion-resistant
/// re-split (D0040 §5 / 3c).
///
/// The shell gathers a threshold of the user's OLD shares (typically returned by
/// recovery peers) and passes them in with the OLD commitment; Rust reconstructs
/// the master seed, re-splits it into `new_num_shares` fresh shares under
/// `new_threshold` with a NEW commitment, signs the new-operational-identity
/// attestation, encodes each new share as a paper card, and zeroizes the seed.
/// **The master seed never crosses to Kotlin** — the entire lifecycle runs in
/// this one call (the structural non-leaking property of D0040 §5).
///
/// The returned cards recover the SAME master (the secret is unchanged; only its
/// sharing is refreshed). "Old cards can no longer recover" is therefore a SOFT
/// property — it holds only once the honest holders of the old cards delete them.
///
/// # Errors
///
/// - [`CairnFfiError::MalformedData`] if `old_commitment` is not
///   [`COMMITMENT_LEN`] bytes, `new_operational_identity_pubkey` is not a valid
///   Ed25519 key, any share's `value` is not [`SECRET_LEN`] bytes / has a zero
///   id, OR the fresh split rejects its parameters (`new_threshold` /
///   `new_num_shares` out of range) — all caller-supplied-data faults, kept
///   DISTINCT from the reconstruct failure below.
/// - [`CairnFfiError::RecoveryFailed`] if the OLD shares do not reconstruct to
///   the committed master (insufficient / wrong / tampered cards) — the
///   user-actionable "gather more cards" case.
#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
)]
pub fn recovery_resplit_and_attest(
    shares: Vec<ShareRecord>,
    old_commitment: Vec<u8>,
    new_operational_identity_pubkey: Vec<u8>,
    new_threshold: u8,
    new_num_shares: u8,
    timestamp: u64,
) -> Result<ResplitResultRecord, CairnFfiError> {
    let commitment_bytes: [u8; COMMITMENT_LEN] = old_commitment
        .as_slice()
        .try_into()
        .map_err(|_| CairnFfiError::MalformedData)?;
    let old_commitment = Commitment::from_bytes(commitment_bytes);

    let pubkey_bytes: [u8; PUBLIC_KEY_LEN] = new_operational_identity_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| CairnFfiError::MalformedData)?;
    let new_operational =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| CairnFfiError::MalformedData)?;

    // Rehydrate each OLD ShareRecord into a typed Share. The value bytes go
    // straight into a Zeroizing buffer so the only copy Rust keeps is wiped on
    // drop.
    let shares: Vec<Share> = shares
        .into_iter()
        .map(|share| -> Result<Share, CairnFfiError> {
            let value: [u8; SECRET_LEN] = share
                .value
                .as_slice()
                .try_into()
                .map_err(|_| CairnFfiError::MalformedData)?;
            Share::try_from_parts(share.id, Zeroizing::new(value))
                .map_err(|_| CairnFfiError::MalformedData)
        })
        .collect::<Result<_, _>>()?;

    // The master seed is reconstructed, re-split, used to sign, and zeroized
    // entirely inside this call; only the public ResplitOutput is returned. The
    // fresh split draws entropy from the OS CSPRNG.
    let mut rng = OsRng;
    let out = reconstruct_resplit_and_attest(
        &shares,
        &old_commitment,
        new_operational,
        new_threshold,
        new_num_shares,
        timestamp,
        &mut rng,
    )?;

    let attestation = out.attestation.encode(false).map_err(CairnFfiError::from)?;
    let new_cards: Vec<String> = out.new_cards.iter().map(encode_card).collect();
    Ok(ResplitResultRecord {
        new_cards,
        attestation,
        master_pubkey: out.master.to_bytes().to_vec(),
        new_commitment: out.new_commitment.to_bytes().to_vec(),
    })
}

/// Verify a signed master attestation against the expected master
/// pubkey, returning its public fields (D0027 §2.2) — hop #3.
///
/// # Errors
///
/// - [`CairnFfiError::MalformedData`] if `expected_master` is not a
///   valid 32-byte Ed25519 key or `attestation` is not well-formed.
/// - [`CairnFfiError::SignatureVerifyFailed`] if the attestation does
///   not verify against `expected_master` (bad signature or master
///   mismatch; sub-reason collapsed per D0027 §3.2).
#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
)]
pub fn recovery_verify_master_attestation(
    attestation: Vec<u8>,
    expected_master: Vec<u8>,
) -> Result<MasterAttestationRecord, CairnFfiError> {
    let master_bytes: [u8; PUBLIC_KEY_LEN] = expected_master
        .as_slice()
        .try_into()
        .map_err(|_| CairnFfiError::MalformedData)?;
    let expected =
        VerifyingKey::from_bytes(&master_bytes).map_err(|_| CairnFfiError::MalformedData)?;

    let signed = SignedMasterAttestation::from_bytes(&attestation, &expected)?;
    let attestation = signed.attestation();

    Ok(MasterAttestationRecord {
        master: attestation.master.to_bytes().to_vec(),
        operational_identity: attestation.operational_identity.to_bytes().to_vec(),
        timestamp_unix_seconds: attestation.timestamp,
    })
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
    use cairn_shamir::split;
    use rand_core::OsRng;

    /// Split a fixed master seed 3-of-5, returning the share records,
    /// the commitment bytes, and the master pubkey derived from the
    /// seed.
    fn split_master() -> (Vec<ShareRecord>, Vec<u8>, Vec<u8>) {
        let seed = Zeroizing::new([7u8; SECRET_LEN]);
        let (shares, commitment) = split(&seed, 3, 5, &mut OsRng).unwrap();
        let records: Vec<ShareRecord> = shares
            .iter()
            .map(|s| ShareRecord {
                id: s.id(),
                value: s.bytes().to_vec(),
            })
            .collect();
        let master_pubkey = SigningKey::from_seed(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec();
        (records, commitment.to_bytes().to_vec(), master_pubkey)
    }

    #[test]
    fn reconstruct_attest_then_verify_round_trip() {
        let (records, commitment, master_pubkey) = split_master();
        let mut rng = OsRng;
        let new_op = SigningKey::generate(&mut rng)
            .verifying_key()
            .to_bytes()
            .to_vec();

        // A threshold (3) of the 5 shares suffices.
        let threshold_shares = records[..3].to_vec();
        let attestation = recovery_reconstruct_and_attest(
            threshold_shares,
            commitment,
            new_op.clone(),
            1_700_000_000,
        )
        .unwrap();

        // The attestation verifies against the master pubkey and binds
        // the new operational identity.
        let record =
            recovery_verify_master_attestation(attestation, master_pubkey.clone()).unwrap();
        assert_eq!(record.master, master_pubkey);
        assert_eq!(record.operational_identity, new_op);
        assert_eq!(record.timestamp_unix_seconds, 1_700_000_000);
    }

    #[test]
    fn decode_card_round_trips_and_drives_reconstruction() {
        use cairn_recovery::{RecoveryCard, encode_card};
        let (records, commitment, master_pubkey) = split_master();

        // Encode each share as a paper card (the facilitator's CLI form).
        let cards: Vec<String> = records
            .iter()
            .map(|r| {
                let card = RecoveryCard {
                    id: r.id,
                    value: r.value.clone().try_into().unwrap(),
                    commitment: commitment.clone().try_into().unwrap(),
                    master: master_pubkey.clone().try_into().unwrap(),
                };
                encode_card(&card)
            })
            .collect();

        // One card decodes back to its share + header across the FFI.
        let decoded = recovery_decode_card(cards[0].clone()).unwrap();
        assert_eq!(decoded.share, records[0]);
        assert_eq!(decoded.commitment, commitment);
        assert_eq!(decoded.master_pubkey, master_pubkey);

        // The decoded cards drive the FULL recovery: 3 cards → reconstruct +
        // attest → verify against the recovered master.
        let shares: Vec<ShareRecord> = cards[..3]
            .iter()
            .map(|c| recovery_decode_card(c.clone()).unwrap().share)
            .collect();
        let new_op = SigningKey::generate(&mut OsRng)
            .verifying_key()
            .to_bytes()
            .to_vec();
        let att =
            recovery_reconstruct_and_attest(shares, commitment, new_op.clone(), 1_700_000_000)
                .unwrap();
        let rec = recovery_verify_master_attestation(att, master_pubkey.clone()).unwrap();
        assert_eq!(rec.master, master_pubkey);
        assert_eq!(rec.operational_identity, new_op);
    }

    #[test]
    fn decode_card_rejects_garbage() {
        assert_eq!(
            recovery_decode_card("not a recovery card".to_string()).unwrap_err(),
            CairnFfiError::MalformedData
        );
    }

    #[test]
    fn phrase_hash_is_deterministic_salted_and_rejects_short_salt() {
        let salt = vec![7u8; 16];
        let h1 = recovery_phrase_hash(salt.clone(), "open sesame".to_string()).unwrap();
        let h2 = recovery_phrase_hash(salt.clone(), "open sesame".to_string()).unwrap();
        assert_eq!(
            h1, h2,
            "same (salt, phrase) → same hash (set + verify must agree)"
        );
        assert_eq!(h1.len(), 32);

        // A different phrase under the same salt → different hash.
        let h_other = recovery_phrase_hash(salt, "open sesam".to_string()).unwrap();
        assert_ne!(h1, h_other);

        // A different salt under the same phrase → different hash (per-share salt
        // defeats cross-share precomputation).
        let h_salt2 = recovery_phrase_hash(vec![8u8; 16], "open sesame".to_string()).unwrap();
        assert_ne!(h1, h_salt2);

        // Salt below the Argon2 minimum is rejected (uniform malformed error).
        assert_eq!(
            recovery_phrase_hash(vec![0u8; 4], "x".to_string()).unwrap_err(),
            CairnFfiError::MalformedData
        );
    }

    #[test]
    fn insufficient_shares_map_to_recovery_failed() {
        // Only 2 of the 3-of-5 shares → reconstruction yields a value
        // that fails the commitment check → RecoveryFailed.
        let (records, commitment, _master) = split_master();
        let mut rng = OsRng;
        let new_op = SigningKey::generate(&mut rng)
            .verifying_key()
            .to_bytes()
            .to_vec();
        let too_few = records[..2].to_vec();
        let err = recovery_reconstruct_and_attest(too_few, commitment, new_op, 1_700_000_000)
            .unwrap_err();
        assert_eq!(err, CairnFfiError::RecoveryFailed);
    }

    #[test]
    fn wrong_length_share_value_maps_to_malformed_data() {
        let (mut records, commitment, _master) = split_master();
        let mut rng = OsRng;
        let new_op = SigningKey::generate(&mut rng)
            .verifying_key()
            .to_bytes()
            .to_vec();
        records[0].value.truncate(31); // no longer SECRET_LEN
        let err = recovery_reconstruct_and_attest(records, commitment, new_op, 1_700_000_000)
            .unwrap_err();
        assert_eq!(err, CairnFfiError::MalformedData);
    }

    #[test]
    fn resplit_round_trips_through_ffi() {
        // The 3c FFI core: 3 OLD cards → re-split into a fresh 3-of-5 + attest.
        let (records, commitment, master_pubkey) = split_master();
        let new_op = SigningKey::generate(&mut OsRng)
            .verifying_key()
            .to_bytes()
            .to_vec();

        let out = recovery_resplit_and_attest(
            records[..3].to_vec(),
            commitment.clone(),
            new_op.clone(),
            3,
            5,
            1_700_000_000,
        )
        .unwrap();

        // 5 fresh cards; the recovered master + (unchanged) commitment surfaced.
        assert_eq!(out.new_cards.len(), 5);
        assert_eq!(out.master_pubkey, master_pubkey);
        assert_eq!(
            out.new_commitment, commitment,
            "commitment is to the unchanged secret"
        );

        // The attestation verifies against the recovered master + binds the new op.
        let rec =
            recovery_verify_master_attestation(out.attestation, master_pubkey.clone()).unwrap();
        assert_eq!(rec.master, master_pubkey);
        assert_eq!(rec.operational_identity, new_op);

        // The FRESH cards decode and reconstruct the IDENTICAL master: feed 3 new
        // cards back through decode + reconstruct_and_attest, and it verifies
        // against the same master pubkey.
        let new_shares: Vec<ShareRecord> = out.new_cards[..3]
            .iter()
            .map(|c| recovery_decode_card(c.clone()).unwrap().share)
            .collect();
        let att2 = recovery_reconstruct_and_attest(
            new_shares,
            out.new_commitment.clone(),
            new_op,
            1_700_000_001,
        )
        .unwrap();
        let rec2 = recovery_verify_master_attestation(att2, master_pubkey.clone()).unwrap();
        assert_eq!(
            rec2.master, master_pubkey,
            "the fresh card set recovers the identical master"
        );

        // Freshness witness: the new card texts differ from the old (a new
        // polynomial was drawn, not the old set echoed back).
        let old_card_ids: Vec<u8> = records.iter().map(|r| r.id).collect();
        let new_decoded: Vec<RecoveryCardRecord> = out
            .new_cards
            .iter()
            .map(|c| recovery_decode_card(c.clone()).unwrap())
            .collect();
        for nd in &new_decoded {
            // same ids (1..=5), but a fresh value for each.
            assert!(old_card_ids.contains(&nd.share.id));
            let old = records.iter().find(|r| r.id == nd.share.id).unwrap();
            assert_ne!(
                nd.share.value, old.value,
                "each fresh share value must differ from the old"
            );
        }
    }

    #[test]
    fn resplit_insufficient_old_shares_maps_to_recovery_failed() {
        // 2 of a 3-of-5 OLD set → reconstruct fails BEFORE any new split →
        // the user-actionable RecoveryFailed (not an internal split fault).
        let (records, commitment, _master) = split_master();
        let new_op = SigningKey::generate(&mut OsRng)
            .verifying_key()
            .to_bytes()
            .to_vec();
        let err = recovery_resplit_and_attest(records[..2].to_vec(), commitment, new_op, 3, 5, 1)
            .unwrap_err();
        assert_eq!(err, CairnFfiError::RecoveryFailed);
    }

    #[test]
    fn resplit_bad_new_parameters_maps_to_malformed_data() {
        // A valid OLD set reconstructs, but new_threshold > new_num_shares is an
        // invalid split → MalformedData (a caller-supplied-parameter fault),
        // kept distinct from the user-actionable RecoveryFailed of a bad OLD set.
        let (records, commitment, _master) = split_master();
        let new_op = SigningKey::generate(&mut OsRng)
            .verifying_key()
            .to_bytes()
            .to_vec();
        let err = recovery_resplit_and_attest(records[..3].to_vec(), commitment, new_op, 5, 3, 1)
            .unwrap_err();
        assert_eq!(err, CairnFfiError::MalformedData);
    }

    #[test]
    fn verify_wrong_master_maps_to_signature_failure() {
        let (records, commitment, _master) = split_master();
        let mut rng = OsRng;
        let new_op = SigningKey::generate(&mut rng)
            .verifying_key()
            .to_bytes()
            .to_vec();
        let attestation = recovery_reconstruct_and_attest(
            records[..3].to_vec(),
            commitment,
            new_op,
            1_700_000_000,
        )
        .unwrap();

        // Verify against a DIFFERENT master pubkey → mismatch.
        let wrong_master = SigningKey::generate(&mut rng)
            .verifying_key()
            .to_bytes()
            .to_vec();
        let err = recovery_verify_master_attestation(attestation, wrong_master).unwrap_err();
        assert_eq!(err, CairnFfiError::SignatureVerifyFailed);
    }
}
