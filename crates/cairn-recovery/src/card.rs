// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Paper-share recovery-card codec (D0038 §4).
//!
//! A **recovery card** is the print/QR form of one Shamir share, made
//! self-contained by carrying the recovery header (the BLAKE3 commit-of-secret
//! and the master public key) alongside the share — so ANY threshold of cards
//! reconstructs the master without a separate header step. The facilitator's
//! CLI emits these at provisioning; the app scans/types them at recovery.
//! `split` stays a CLI ceremony per D0038 §2 — this module only **serialises a
//! share that was already produced**, it generates no secret and takes no RNG.
//!
//! ## Binary layout (before base64url)
//!
//! | Field      | Bytes | Notes |
//! |------------|-------|-------|
//! | magic      | 2     | `b"CR"` |
//! | version    | 1     | `1` |
//! | id         | 1     | the share's non-zero Shamir index |
//! | value      | 32    | the share value ([`cairn_shamir::SECRET_LEN`]) |
//! | commitment | 32    | BLAKE3 commit-of-secret ([`cairn_shamir::COMMITMENT_LEN`]) |
//! | master     | 32    | the master Ed25519 public key |
//! | checksum   | 4     | `BLAKE3(all preceding bytes)[..4]` |
//!
//! The checksum lets a mistyped card be rejected immediately (which-card
//! feedback) BEFORE reconstruction, where a single bad share would otherwise
//! surface only as an opaque commitment mismatch.
//!
//! ## Text form
//!
//! `CAIRN-RECOVERY-<base64url-no-pad of the 104 bytes>`. The prefix is a
//! human-recognisable label; the authoritative version is the binary `version`
//! byte, so a base32 / BIP-39 manual-entry-friendlier encoding can replace the
//! body later (D0038 §4) without breaking recognition or the scheme.

use base64::Engine as _;

use cairn_shamir::{COMMITMENT_LEN, SECRET_LEN};

use crate::error::RecoveryError;

/// Master Ed25519 public-key length.
pub const MASTER_PUBKEY_LEN: usize = 32;

const MAGIC: [u8; 2] = *b"CR";
const CARD_VERSION: u8 = 1;
const CHECKSUM_LEN: usize = 4;
/// The bytes the checksum covers: magic..master (everything but the checksum).
const SIGNED_LEN: usize = 2 + 1 + 1 + SECRET_LEN + COMMITMENT_LEN + MASTER_PUBKEY_LEN;
/// Full card length including the trailing checksum.
const CARD_LEN: usize = SIGNED_LEN + CHECKSUM_LEN;
/// Human-recognisable text prefix.
const LABEL: &str = "CAIRN-RECOVERY-";

/// A decoded recovery card (D0038 §4): one Shamir share + the recovery header.
///
/// `value` is a single share — sensitive but below the reconstruction threshold
/// (it reveals nothing about the master seed), matching the FFI `ShareRecord`'s
/// plain-bytes treatment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCard {
    /// The share's non-zero Shamir index.
    pub id: u8,
    /// The share value ([`cairn_shamir::SECRET_LEN`] bytes).
    pub value: [u8; SECRET_LEN],
    /// The BLAKE3 commit-of-secret the threshold reconstructs against.
    pub commitment: [u8; COMMITMENT_LEN],
    /// The master Ed25519 public key (the verifier for the reconstructed seed).
    pub master: [u8; MASTER_PUBKEY_LEN],
}

#[allow(
    clippy::indexing_slicing,
    reason = "the BLAKE3 hash is 32 bytes; CHECKSUM_LEN (4) is statically smaller"
)]
fn checksum(signed: &[u8]) -> [u8; CHECKSUM_LEN] {
    let hash = blake3::hash(signed);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&hash.as_bytes()[..CHECKSUM_LEN]);
    out
}

/// Encode a recovery card to its `CAIRN-RECOVERY-…` text form (D0038 §4).
#[must_use]
pub fn encode_card(card: &RecoveryCard) -> String {
    let mut buf = Vec::with_capacity(CARD_LEN);
    buf.extend_from_slice(&MAGIC);
    buf.push(CARD_VERSION);
    buf.push(card.id);
    buf.extend_from_slice(&card.value);
    buf.extend_from_slice(&card.commitment);
    buf.extend_from_slice(&card.master);
    buf.extend_from_slice(&checksum(&buf));
    let mut out = String::from(LABEL);
    out.push_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf));
    out
}

/// Decode a `CAIRN-RECOVERY-…` recovery-card text, the inverse of
/// [`encode_card`]. Tolerates surrounding whitespace and a case-insensitive
/// label.
///
/// # Errors
///
/// [`RecoveryError::MalformedPayload`] for a wrong/absent label, a non-base64
/// body, a wrong length, an unknown magic/version, a zero share id, or a
/// **checksum mismatch** (a mistyped card).
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "every fixed index is guarded by the early `bytes.len() != CARD_LEN` check; the offset arithmetic is constant additions summing below CARD_LEN (no overflow)"
)]
pub fn decode_card(text: &str) -> Result<RecoveryCard, RecoveryError> {
    let trimmed = text.trim();
    // Case-insensitive label match (`get` is char-boundary + bounds safe).
    let body = match trimmed.get(..LABEL.len()) {
        Some(prefix) if prefix.eq_ignore_ascii_case(LABEL) => trimmed[LABEL.len()..].trim(),
        _ => return Err(RecoveryError::MalformedPayload),
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| RecoveryError::MalformedPayload)?;
    if bytes.len() != CARD_LEN || bytes[0..2] != MAGIC || bytes[2] != CARD_VERSION {
        return Err(RecoveryError::MalformedPayload);
    }
    // Verify the checksum before trusting any field (which-card feedback).
    let (signed, cs) = bytes.split_at(SIGNED_LEN);
    if checksum(signed).as_slice() != cs {
        return Err(RecoveryError::MalformedPayload);
    }
    let id = bytes[3];
    if id == 0 {
        return Err(RecoveryError::MalformedPayload); // Shamir ids are non-zero
    }
    let mut value = [0u8; SECRET_LEN];
    let mut commitment = [0u8; COMMITMENT_LEN];
    let mut master = [0u8; MASTER_PUBKEY_LEN];
    let mut off = 4;
    value.copy_from_slice(&bytes[off..off + SECRET_LEN]);
    off += SECRET_LEN;
    commitment.copy_from_slice(&bytes[off..off + COMMITMENT_LEN]);
    off += COMMITMENT_LEN;
    master.copy_from_slice(&bytes[off..off + MASTER_PUBKEY_LEN]);
    Ok(RecoveryCard {
        id,
        value,
        commitment,
        master,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "tests unwrap + index + offset within known-good fixtures; a panic IS the failure signal"
)]
mod tests {
    use super::*;

    fn sample() -> RecoveryCard {
        RecoveryCard {
            id: 3,
            value: [0xA1; SECRET_LEN],
            commitment: [0xB2; COMMITMENT_LEN],
            master: [0xC3; MASTER_PUBKEY_LEN],
        }
    }

    #[test]
    fn card_round_trips() {
        let card = sample();
        let text = encode_card(&card);
        assert!(text.starts_with(LABEL));
        assert_eq!(decode_card(&text).unwrap(), card);
    }

    #[test]
    fn decode_tolerates_whitespace_and_label_case() {
        let text = encode_card(&sample());
        let body = text.strip_prefix(LABEL).unwrap();
        let messy = format!("  cairn-recovery-{body}  ");
        assert_eq!(decode_card(&messy).unwrap(), sample());
    }

    #[test]
    fn mistyped_card_fails_checksum() {
        // Flip one base64 char in the body → checksum mismatch, not silent
        // acceptance (the which-card-is-wrong guard).
        let text = encode_card(&sample());
        let mut chars: Vec<char> = text.chars().collect();
        let mid = chars.len() - 5;
        chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(matches!(
            decode_card(&tampered),
            Err(RecoveryError::MalformedPayload)
        ));
    }

    #[test]
    fn wrong_label_rejected() {
        let body = encode_card(&sample())
            .strip_prefix(LABEL)
            .unwrap()
            .to_string();
        assert!(matches!(
            decode_card(&format!("NOT-A-CAIRN-{body}")),
            Err(RecoveryError::MalformedPayload)
        ));
    }

    #[test]
    fn garbage_rejected() {
        assert!(matches!(
            decode_card("CAIRN-RECOVERY-!!!not base64!!!"),
            Err(RecoveryError::MalformedPayload)
        ));
        assert!(matches!(
            decode_card("totally unrelated text"),
            Err(RecoveryError::MalformedPayload)
        ));
    }

    #[test]
    fn zero_id_rejected() {
        // Hand-build a card with id=0 + a valid checksum; decode must still
        // reject it (Shamir indices are non-zero).
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.push(CARD_VERSION);
        buf.push(0); // zero id
        buf.extend_from_slice(&[0u8; SECRET_LEN]);
        buf.extend_from_slice(&[0u8; COMMITMENT_LEN]);
        buf.extend_from_slice(&[0u8; MASTER_PUBKEY_LEN]);
        buf.extend_from_slice(&checksum(&buf));
        let text = format!(
            "{LABEL}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf)
        );
        assert!(matches!(
            decode_card(&text),
            Err(RecoveryError::MalformedPayload)
        ));
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "proptests build known-length arrays + index the ASCII card body within generated bounds; a panic IS the failure signal"
)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy for a structurally-valid recovery card (non-zero Shamir id).
    fn arb_card() -> impl Strategy<Value = RecoveryCard> {
        (
            1u8..=u8::MAX,
            proptest::collection::vec(any::<u8>(), SECRET_LEN),
            proptest::collection::vec(any::<u8>(), COMMITMENT_LEN),
            proptest::collection::vec(any::<u8>(), MASTER_PUBKEY_LEN),
        )
            .prop_map(|(id, value, commitment, master)| RecoveryCard {
                id,
                value: value.try_into().expect("len == SECRET_LEN"),
                commitment: commitment.try_into().expect("len == COMMITMENT_LEN"),
                master: master.try_into().expect("len == MASTER_PUBKEY_LEN"),
            })
    }

    proptest! {
        /// Round-trip: any structurally-valid card encodes to the labelled
        /// text form and decodes back to the identical card. The unit test
        /// covers one fixed sample; this covers the whole input space.
        #[test]
        fn prop_card_round_trip(card in arb_card()) {
            let text = encode_card(&card);
            prop_assert!(text.starts_with(LABEL));
            let decoded = decode_card(&text).expect("valid card must decode");
            prop_assert_eq!(decoded, card);
        }

        /// Integrity: replacing any base64 char in the first 8 body
        /// positions (well inside the checksum-covered signed region, clear
        /// of base64 trailing-bit aliasing near the end) is always rejected.
        /// A mistyped or mutated card never silently decodes.
        #[test]
        fn prop_early_char_tamper_rejected(
            card in arb_card(),
            pos in 0usize..8,
            repl in 0usize..64,
        ) {
            const ALPHABET: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut bytes = encode_card(&card).into_bytes();
            // The base64 body is ASCII, so the byte index equals the char index.
            let i = LABEL.len() + pos;
            let new = ALPHABET[repl % ALPHABET.len()];
            prop_assume!(bytes[i] != new);
            bytes[i] = new;
            let tampered = String::from_utf8(bytes).expect("ascii stays utf8");
            prop_assert!(matches!(
                decode_card(&tampered),
                Err(RecoveryError::MalformedPayload)
            ));
        }
    }
}
