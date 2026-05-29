// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Per-record AEAD with AAD-binding per D0022 §2.3 + §2.4.
//!
//! ## Wire format
//!
//! ```text
//! ciphertext column =
//!     version_byte (1)
//!   ‖ nonce         (24, random per write)
//!   ‖ XChaCha20-Poly1305(DEK_category, payload, AAD)
//! ```
//!
//! The 16-byte Poly1305 tag is appended by the AEAD library and is
//! NOT separately framed.
//!
//! ## AAD construction
//!
//! ```text
//! AAD = canonical_cbor_encode([
//!   category_tag : tstr,
//!   record_id    : bstr,
//!   version      : uint,
//! ])
//! ```
//!
//! AAD-binding is the slot-swap defense: an adversary with write
//! access to the SQLite file who moves a row from `(category,
//! record_id_A)` to `(category, record_id_B)` invalidates the AEAD
//! tag because the AAD reconstructed at read time references the
//! destination row's id.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use cairn_envelope::canonical::Value;

use crate::error::StorageError;
use crate::{DEK_LEN, NONCE_LEN, TAG_LEN};

/// Current per-record schema version emitted by [`seal`]. Bound into
/// the AAD per D0022 §2.4 so a downgrade-or-swap attack invalidates
/// the AEAD tag.
pub const CURRENT_RECORD_VERSION: u8 = 1;

/// Minimum well-formed ciphertext length: 41 bytes.
///
/// `1-byte version` + `24-byte nonce` + `16-byte AEAD tag`. Records
/// shorter than this cannot be AEAD-verified and surface as
/// [`StorageError::CiphertextTruncated`] before any cryptographic
/// operation runs.
pub const MIN_CIPHERTEXT_LEN: usize = 1 + NONCE_LEN + TAG_LEN;

/// Seal a payload into the per-record format per D0022 §2.3.
///
/// Produces `version_byte ‖ nonce(24) ‖ AEAD(DEK, payload, AAD)`
/// where AAD is the canonical-CBOR encoding of
/// `(category_tag, record_id, version)` per D0022 §2.4.
///
/// # Errors
///
/// - [`StorageError::CanonicalEncode`] if AAD canonical-CBOR encoding
///   fails (unreachable for typed inputs)
/// - [`StorageError::DecryptFailed`] is NOT a sealing-path variant
///   — see [`open`] for the read-side check
///
/// The AEAD encrypt step itself cannot fail for valid 32-byte keys
/// and 24-byte nonces; if `chacha20poly1305`'s encrypt ever returns
/// `Err` for a well-formed input, this code surfaces it through
/// `StorageError::DecryptFailed` as the only available unified error
/// path (in practice unreachable).
pub fn seal(
    dek: &Zeroizing<[u8; DEK_LEN]>,
    category_tag: &str,
    record_id: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, StorageError> {
    let aad = build_aad(category_tag, record_id, CURRENT_RECORD_VERSION)?;

    // Fresh random nonce per write (D0022 §2.3 spec).
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(dek.as_ref())
        // Unreachable: 32-byte DEK always satisfies the 32-byte key
        // length requirement. If new_from_slice ever rejects a
        // 32-byte key, surface uniformly as DecryptFailed.
        .map_err(|_| StorageError::DecryptFailed)?;

    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: payload,
                aad: &aad,
            },
        )
        // Unreachable for well-formed inputs. Surface uniformly.
        .map_err(|_| StorageError::DecryptFailed)?;

    let mut out = Vec::with_capacity(
        1usize
            .saturating_add(NONCE_LEN)
            .saturating_add(ciphertext.len()),
    );
    out.push(CURRENT_RECORD_VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a record produced by [`seal`].
///
/// Validates structural framing (length ≥ MIN_CIPHERTEXT_LEN; known
/// version byte); reconstructs the AAD from the supplied
/// `category_tag` + `record_id` + the version byte read from the
/// record; runs AEAD verify+decrypt.
///
/// AEAD failure is uniform per D0018 §1.4 no-error-oracle discipline:
/// wrong DEK, ciphertext tamper, AAD mismatch (slot-swap attack),
/// truncation past the structural check — all surface as
/// [`StorageError::DecryptFailed`].
///
/// # Errors
///
/// - [`StorageError::CiphertextTruncated`] if the record is shorter
///   than `MIN_CIPHERTEXT_LEN`
/// - [`StorageError::UnsupportedRecordVersion`] if the version byte
///   isn't one this build recognizes
/// - [`StorageError::DecryptFailed`] for any AEAD verification
///   failure (uniform per D0018 §1.4)
/// - [`StorageError::CanonicalEncode`] from AAD reconstruction
///   (unreachable for typed inputs)
pub fn open(
    dek: &Zeroizing<[u8; DEK_LEN]>,
    category_tag: &str,
    record_id: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    if sealed.len() < MIN_CIPHERTEXT_LEN {
        return Err(StorageError::CiphertextTruncated {
            got_bytes: sealed.len(),
            min_bytes: MIN_CIPHERTEXT_LEN,
        });
    }

    // Statically safe: length check above guarantees sealed.len() >=
    // 1 + NONCE_LEN + TAG_LEN.
    #[allow(
        clippy::indexing_slicing,
        reason = "MIN_CIPHERTEXT_LEN check above pins the bounds"
    )]
    let version = sealed[0];

    if version != CURRENT_RECORD_VERSION {
        return Err(StorageError::UnsupportedRecordVersion { got: version });
    }

    #[allow(clippy::indexing_slicing, reason = "see above")]
    let nonce_bytes: &[u8] = &sealed[1..=NONCE_LEN];
    let nonce = XNonce::from_slice(nonce_bytes);

    #[allow(clippy::indexing_slicing, reason = "see above")]
    let ciphertext: &[u8] = &sealed[1 + NONCE_LEN..];

    let aad = build_aad(category_tag, record_id, version)?;

    let cipher =
        XChaCha20Poly1305::new_from_slice(dek.as_ref()).map_err(|_| StorageError::DecryptFailed)?;

    let plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| StorageError::DecryptFailed)?;

    Ok(Zeroizing::new(plaintext))
}

/// Build the AAD canonical-CBOR encoding of
/// `(category_tag, record_id, version)` per D0022 §2.4.
///
/// The encoding is the project-owned canonical CBOR encoder from
/// `cairn-envelope::canonical` to ensure byte-stable AAD across
/// implementations + runs.
///
/// # Errors
///
/// Propagates [`cairn_envelope::EnvelopeError`] from the canonical
/// encoder (unreachable for the typed inputs we feed it).
fn build_aad(category_tag: &str, record_id: &[u8], version: u8) -> Result<Vec<u8>, StorageError> {
    Value::Array(vec![
        Value::Text(category_tag.to_string()),
        Value::Bytes(record_id.to_vec()),
        Value::Int(i64::from(version)),
    ])
    .encode()
    .map_err(StorageError::from)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::categories;
    use crate::key_provider::{KeyProvider, derive_category_dek, testing::InMemoryKeyProvider};
    use zeroize::Zeroizing;

    /// Helper: derive a DEK using the same path production code uses.
    fn test_dek(category: &str) -> Zeroizing<[u8; DEK_LEN]> {
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"test passphrase".to_vec());
        let kek = provider
            .derive_kek(&passphrase, b"test-salt-16-byt")
            .unwrap();
        let sb = provider.strongbox_material().unwrap();
        derive_category_dek(&kek, &sb, category).unwrap()
    }

    #[test]
    fn round_trip_succeeds_for_well_formed_inputs() {
        let dek = test_dek(categories::IDENTITY);
        let payload = b"the operational identity seed (notional)";
        let sealed = seal(&dek, categories::IDENTITY, b"record-id-1", payload).unwrap();
        let opened = open(&dek, categories::IDENTITY, b"record-id-1", &sealed).unwrap();
        assert_eq!(opened.as_slice(), payload);
    }

    #[test]
    fn nonce_is_random_per_seal_call() {
        let dek = test_dek(categories::IDENTITY);
        let payload = b"deterministic payload";
        let sealed_a = seal(&dek, categories::IDENTITY, b"id-1", payload).unwrap();
        let sealed_b = seal(&dek, categories::IDENTITY, b"id-1", payload).unwrap();
        // Same DEK + same payload + same id → different ciphertext
        // because the nonce is fresh per call. This is the
        // birthday-bound defense per D0022 §2.3.
        assert_ne!(sealed_a, sealed_b);
        // Both still decrypt to the same payload.
        assert_eq!(
            open(&dek, categories::IDENTITY, b"id-1", &sealed_a)
                .unwrap()
                .as_slice(),
            payload
        );
        assert_eq!(
            open(&dek, categories::IDENTITY, b"id-1", &sealed_b)
                .unwrap()
                .as_slice(),
            payload
        );
    }

    #[test]
    fn slot_swap_attack_fails_aead() {
        // The defining slot-swap defense per D0022 §2.4: encrypt under
        // (category, id_A); attempt decrypt with the destination
        // (category, id_B). The AAD changes, the AEAD tag fails.
        let dek = test_dek(categories::IDENTITY);
        let payload = b"sensitive payload";
        let sealed = seal(&dek, categories::IDENTITY, b"id-A", payload).unwrap();
        let result = open(&dek, categories::IDENTITY, b"id-B", &sealed);
        assert!(matches!(result, Err(StorageError::DecryptFailed)));
    }

    #[test]
    fn cross_category_swap_fails_aead() {
        // Defense: a record sealed under category X cannot be opened
        // under category Y even with the same record_id. This
        // composes the per-category DEK derivation with the AAD
        // binding — both defenses fail; the AEAD tag check catches
        // both via the unified DecryptFailed.
        let identity_dek = test_dek(categories::IDENTITY);
        let messages_dek = test_dek(categories::MESSAGES);
        let payload = b"sensitive payload";
        let sealed = seal(&identity_dek, categories::IDENTITY, b"id-1", payload).unwrap();
        // Attempt to open with the WRONG category tag (AAD mismatch)
        // AND wrong DEK (per-category DEK derivation).
        let result = open(&messages_dek, categories::MESSAGES, b"id-1", &sealed);
        assert!(matches!(result, Err(StorageError::DecryptFailed)));
    }

    #[test]
    fn wrong_dek_fails_aead() {
        let dek_a = test_dek(categories::IDENTITY);
        // Distinct DEK derived from a different category tag.
        let dek_b = test_dek(categories::MESSAGES);
        let sealed = seal(&dek_a, categories::IDENTITY, b"id-1", b"payload").unwrap();
        let result = open(&dek_b, categories::IDENTITY, b"id-1", &sealed);
        assert!(matches!(result, Err(StorageError::DecryptFailed)));
    }

    #[test]
    fn ciphertext_tamper_fails_aead() {
        let dek = test_dek(categories::IDENTITY);
        let payload = b"sensitive payload";
        let mut sealed = seal(&dek, categories::IDENTITY, b"id-1", payload).unwrap();
        // Flip a byte in the middle of the ciphertext.
        let mid = sealed.len() / 2;
        sealed[mid] ^= 0x01;
        let result = open(&dek, categories::IDENTITY, b"id-1", &sealed);
        assert!(matches!(result, Err(StorageError::DecryptFailed)));
    }

    #[test]
    fn nonce_tamper_fails_aead() {
        let dek = test_dek(categories::IDENTITY);
        let payload = b"sensitive payload";
        let mut sealed = seal(&dek, categories::IDENTITY, b"id-1", payload).unwrap();
        // Flip a bit in the nonce region (bytes 1..=24).
        sealed[5] ^= 0x80;
        let result = open(&dek, categories::IDENTITY, b"id-1", &sealed);
        assert!(matches!(result, Err(StorageError::DecryptFailed)));
    }

    #[test]
    fn version_tamper_is_caught_structurally_or_via_aad() {
        let dek = test_dek(categories::IDENTITY);
        let payload = b"sensitive payload";
        let mut sealed = seal(&dek, categories::IDENTITY, b"id-1", payload).unwrap();
        // Set version byte to a value this build doesn't recognize.
        sealed[0] = 0xFF;
        let result = open(&dek, categories::IDENTITY, b"id-1", &sealed);
        assert!(matches!(
            result,
            Err(StorageError::UnsupportedRecordVersion { got: 0xFF })
        ));
    }

    #[test]
    fn truncated_ciphertext_surfaces_structurally_before_aead() {
        let dek = test_dek(categories::IDENTITY);
        // 40-byte sealed = below MIN_CIPHERTEXT_LEN (41).
        let truncated = vec![0u8; 40];
        let result = open(&dek, categories::IDENTITY, b"id-1", &truncated);
        match result {
            Err(StorageError::CiphertextTruncated {
                got_bytes: 40,
                min_bytes,
            }) => assert_eq!(min_bytes, MIN_CIPHERTEXT_LEN),
            other => panic!("expected CiphertextTruncated, got {other:?}"),
        }
    }

    #[test]
    fn empty_payload_round_trip() {
        // AEAD on empty plaintext is valid; ciphertext is just the tag.
        let dek = test_dek(categories::IDENTITY);
        let sealed = seal(&dek, categories::IDENTITY, b"id-1", b"").unwrap();
        let opened = open(&dek, categories::IDENTITY, b"id-1", &sealed).unwrap();
        assert!(opened.as_slice().is_empty());
    }

    #[test]
    fn large_payload_round_trip() {
        let dek = test_dek(categories::MESSAGES);
        let payload = vec![0xABu8; 1_000_000]; // 1 MB
        let sealed = seal(&dek, categories::MESSAGES, b"id-1", &payload).unwrap();
        let opened = open(&dek, categories::MESSAGES, b"id-1", &sealed).unwrap();
        assert_eq!(opened.as_slice(), payload.as_slice());
    }
}
