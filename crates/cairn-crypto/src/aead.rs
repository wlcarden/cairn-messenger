// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! `XChaCha20`-`Poly1305` AEAD wrappers.
//!
//! Thin typed wrappers over `chacha20poly1305` 0.10.1 (per D0018 §1.4). The
//! discipline:
//!
//! - [`Key`] wraps a 32-byte `XChaCha20`-`Poly1305` key in
//!   `SecretBox<[u8; 32]>` with `Zeroize` on drop.
//! - [`Nonce`] is a plain 24-byte wrapper (no secret material). The
//!   `XChaCha20` extended nonce is large enough that random nonces are
//!   safe — collision probability across the device's lifetime is
//!   negligible, so no nonce counter needs persisting across restarts.
//! - [`encrypt`] and [`decrypt`] are stateless functions. AAD is
//!   authenticated but not encrypted, used for the envelope's outer header
//!   (sender identity hash, version tag) per D0006 §3.
//!
//! ## `XChaCha20` vs `ChaCha20` nonce semantics
//!
//! `ChaCha20` uses a 12-byte nonce; collision risk requires a stateful
//! counter coordinated across all encryptions under the same key.
//! `XChaCha20` uses a 24-byte nonce derived via `HChaCha20` from the upper
//! 16 bytes, leaving the birthday-bound collision probability negligible
//! for any realistic key lifetime. Cairn picks `XChaCha20` specifically so
//! a recovered device on a fresh install does not need to consult prior
//! nonce state — a hard requirement of the trust-graph + recovery model
//! per D0018 §3.
//!
//! ## Maximum plaintext length
//!
//! Per RFC 8439 §2.5 and the underlying `ChaCha20` design, a single
//! encryption is bounded by the `ChaCha20` keystream length:
//! `(2^32 - 1)` blocks of 64 bytes, minus the block overhead. Cairn caps
//! at `(2^32 - 1) * 64` bytes conservatively. Practical envelope payloads
//! are orders of magnitude smaller than this ceiling.
//!
//! ## Failure-mode discipline
//!
//! Decryption returns a uniform [`AeadError::DecryptFailed`] for any
//! failure (truncated ciphertext, wrong tag, wrong key, wrong nonce, wrong
//! AAD). Distinguishing failure modes constitutes an error oracle and is
//! forbidden per D0006 / D0018 §1.4.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload, generic_array::GenericArray},
};
use rand_core::{CryptoRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use crate::error::AeadError;

/// Length of an `XChaCha20`-`Poly1305` key in bytes.
pub const KEY_LEN: usize = 32;

/// Length of an `XChaCha20`-`Poly1305` nonce in bytes.
pub const NONCE_LEN: usize = 24;

/// Length of a `Poly1305` authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// Maximum plaintext length for a single `XChaCha20`-`Poly1305` encryption.
///
/// Derived from `ChaCha20`'s `(2^32 - 1)`-block keystream ceiling.
/// Practical envelope payloads are orders of magnitude smaller; this
/// ceiling exists to give a defined error rather than a silent wraparound.
pub const MAX_PLAINTEXT_LEN: usize = (u32::MAX as usize) * 64;

/// `XChaCha20`-`Poly1305` symmetric key.
///
/// Stores 32 bytes in `SecretBox<[u8; 32]>`. Implements
/// [`crate::never_export::NeverExport`] (via the `SecretBox<[u8; 32]>` impl
/// in [`crate::never_export`]).
pub struct Key {
    bytes: SecretBox<[u8; KEY_LEN]>,
}

impl Key {
    /// Generate a fresh AEAD key from the provided CSPRNG.
    ///
    /// Per D0018 §1.7, callers should pass `OsRng` or another `OS`-backed
    /// CSPRNG; `thread_rng` and `SmallRng` are not suitable for key
    /// generation.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Self {
            bytes: SecretBox::new(Box::new(bytes)),
        }
    }

    /// Reconstruct a key from raw 32-byte material.
    ///
    /// Typically used to wrap KDF output (e.g., HKDF-Expand result). The
    /// input `Zeroizing` wrapper ensures the caller's local copy zeroes on
    /// drop; the stored copy zeroes via `SecretBox`.
    #[must_use]
    pub fn from_bytes(bytes: &Zeroizing<[u8; KEY_LEN]>) -> Self {
        let mut copy = [0u8; KEY_LEN];
        copy.copy_from_slice(bytes.as_ref());
        Self {
            bytes: SecretBox::new(Box::new(copy)),
        }
    }
}

/// `XChaCha20`-`Poly1305` nonce (24 bytes).
///
/// Not secret material. The 24-byte extended nonce is large enough that a
/// random draw per encryption avoids collision across the device's
/// lifetime. The type intentionally does NOT implement `Default` or
/// `Copy`; reusing a nonce under the same key is a critical error and the
/// API makes that path inconvenient.
#[derive(Clone, Debug)]
pub struct Nonce {
    inner: [u8; NONCE_LEN],
}

impl Nonce {
    /// Generate a fresh random nonce from the provided CSPRNG.
    ///
    /// Per the `XChaCha20` design, random 24-byte nonces are safe for any
    /// realistic key lifetime; no nonce counter is required.
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut inner = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut inner);
        Self { inner }
    }

    /// Construct from raw bytes.
    ///
    /// Use this only when the caller has an externally-supplied nonce
    /// (e.g., parsed from a network frame). Generating nonces in-process
    /// should use [`Self::random`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self { inner: bytes }
    }

    /// Return the 24-byte nonce.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; NONCE_LEN] {
        self.inner
    }
}

/// Encrypt `plaintext` with `key` and `nonce`, authenticating `ad`.
///
/// Returns a `Vec<u8>` containing the ciphertext followed by the
/// 16-byte `Poly1305` tag. `ad` (associated data) is authenticated but not
/// encrypted; typical use is to bind the outer envelope header to the
/// ciphertext.
///
/// # Errors
///
/// - [`AeadError::PayloadTooLarge`] if `plaintext.len() > MAX_PLAINTEXT_LEN`.
/// - [`AeadError::InternalEncrypt`] for unreachable internal failures.
pub fn encrypt(
    key: &Key,
    nonce: &Nonce,
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(AeadError::PayloadTooLarge {
            got_bytes: plaintext.len(),
            max_bytes: MAX_PLAINTEXT_LEN,
        });
    }
    let cipher = cipher_from_key(key);
    let xnonce = XNonce::from_slice(&nonce.inner);
    cipher
        .encrypt(
            xnonce,
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .map_err(|_| AeadError::InternalEncrypt)
}

/// Decrypt `ciphertext` with `key` and `nonce`, verifying `ad`.
///
/// `ciphertext` is the concatenation of ciphertext bytes and the 16-byte
/// `Poly1305` tag (the [`encrypt`] output format).
///
/// # Errors
///
/// Returns a uniform [`AeadError::DecryptFailed`] for any failure
/// (truncation, wrong tag, wrong key, wrong nonce, wrong AAD). Per
/// D0006 / D0018 §1.4, decryption failure modes must NOT be distinguishable
/// — this would constitute an error oracle exploitable by an active
/// adversary.
pub fn decrypt(
    key: &Key,
    nonce: &Nonce,
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = cipher_from_key(key);
    let xnonce = XNonce::from_slice(&nonce.inner);
    cipher
        .decrypt(
            xnonce,
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| AeadError::DecryptFailed)
}

/// Construct the underlying `XChaCha20Poly1305` instance from our `Key`.
///
/// Pulled into a helper so the `GenericArray::from_slice` invocation (which
/// would panic on a wrong-length input — unreachable since `KEY_LEN` is
/// fixed at 32) appears only once.
fn cipher_from_key(key: &Key) -> XChaCha20Poly1305 {
    let key_bytes = key.bytes.expose_secret();
    let ga = GenericArray::from_slice(key_bytes.as_slice());
    XChaCha20Poly1305::new(ga)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn round_trip() {
        let mut rng = OsRng;
        let key = Key::generate(&mut rng);
        let nonce = Nonce::random(&mut rng);
        let plaintext = b"Cairn envelope payload for round-trip test";
        let ad = b"v1|sender:abc123";

        let ct = encrypt(&key, &nonce, ad, plaintext).expect("encrypt should succeed");
        let pt = decrypt(&key, &nonce, ad, &ct).expect("decrypt should succeed");

        assert_eq!(pt.as_slice(), plaintext);
    }

    #[test]
    fn round_trip_empty_aad() {
        let mut rng = OsRng;
        let key = Key::generate(&mut rng);
        let nonce = Nonce::random(&mut rng);
        let plaintext = b"no aad here";

        let ct = encrypt(&key, &nonce, b"", plaintext).unwrap();
        let pt = decrypt(&key, &nonce, b"", &ct).unwrap();

        assert_eq!(pt.as_slice(), plaintext);
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let mut rng = OsRng;
        let key = Key::generate(&mut rng);
        let nonce = Nonce::random(&mut rng);
        let ad = b"only-aad";

        let ct = encrypt(&key, &nonce, ad, b"").unwrap();
        // Even empty plaintext produces a 16-byte tag.
        assert_eq!(ct.len(), TAG_LEN);
        let pt = decrypt(&key, &nonce, ad, &ct).unwrap();
        assert_eq!(pt.len(), 0);
    }

    #[test]
    fn wrong_key_decrypt_fails() {
        let mut rng = OsRng;
        let key_a = Key::generate(&mut rng);
        let key_b = Key::generate(&mut rng);
        let nonce = Nonce::random(&mut rng);
        let ct = encrypt(&key_a, &nonce, b"ad", b"hello").unwrap();
        let result = decrypt(&key_b, &nonce, b"ad", &ct);
        assert!(matches!(result, Err(AeadError::DecryptFailed)));
    }

    #[test]
    fn wrong_nonce_decrypt_fails() {
        let mut rng = OsRng;
        let key = Key::generate(&mut rng);
        let nonce_a = Nonce::random(&mut rng);
        let nonce_b = Nonce::random(&mut rng);
        let ct = encrypt(&key, &nonce_a, b"ad", b"hello").unwrap();
        let result = decrypt(&key, &nonce_b, b"ad", &ct);
        assert!(matches!(result, Err(AeadError::DecryptFailed)));
    }

    #[test]
    fn wrong_ad_decrypt_fails() {
        let mut rng = OsRng;
        let key = Key::generate(&mut rng);
        let nonce = Nonce::random(&mut rng);
        let ct = encrypt(&key, &nonce, b"ad-a", b"hello").unwrap();
        let result = decrypt(&key, &nonce, b"ad-b", &ct);
        assert!(matches!(result, Err(AeadError::DecryptFailed)));
    }

    // `indexing_slicing` / `arithmetic_side_effects` allowed in the two
    // tamper tests below: `encrypt` of non-empty plaintext always returns a
    // `Vec` of length `plaintext.len() + TAG_LEN`, so `ct[0]` and
    // `ct.len() - 1` are statically safe. The lint is correct for
    // production code; here the bound is proven by construction.
    #[test]
    #[allow(clippy::indexing_slicing)]
    fn tampered_ciphertext_decrypt_fails() {
        let mut rng = OsRng;
        let key = Key::generate(&mut rng);
        let nonce = Nonce::random(&mut rng);
        let mut ct = encrypt(&key, &nonce, b"ad", b"hello world").unwrap();
        // Flip a bit in the body (not the tag).
        ct[0] ^= 0x01;
        let result = decrypt(&key, &nonce, b"ad", &ct);
        assert!(matches!(result, Err(AeadError::DecryptFailed)));
    }

    #[test]
    #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    fn tampered_tag_decrypt_fails() {
        let mut rng = OsRng;
        let key = Key::generate(&mut rng);
        let nonce = Nonce::random(&mut rng);
        let mut ct = encrypt(&key, &nonce, b"ad", b"hello").unwrap();
        // Flip a bit in the last byte (`Poly1305` tag).
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let result = decrypt(&key, &nonce, b"ad", &ct);
        assert!(matches!(result, Err(AeadError::DecryptFailed)));
    }

    #[test]
    fn truncated_ciphertext_decrypt_fails() {
        let mut rng = OsRng;
        let key = Key::generate(&mut rng);
        let nonce = Nonce::random(&mut rng);
        let mut ct = encrypt(&key, &nonce, b"ad", b"hello").unwrap();
        // Drop the last byte of the tag.
        ct.pop();
        let result = decrypt(&key, &nonce, b"ad", &ct);
        assert!(matches!(result, Err(AeadError::DecryptFailed)));
    }

    #[test]
    fn from_bytes_round_trip() {
        let key_bytes = Zeroizing::new([0x42_u8; KEY_LEN]);
        let key = Key::from_bytes(&key_bytes);
        let nonce = Nonce::from_bytes([0x55_u8; NONCE_LEN]);

        let ct = encrypt(&key, &nonce, b"ad", b"deterministic test").unwrap();

        // Reconstructing the same key from the same bytes decrypts the
        // ciphertext (deterministic-decryption check, not deterministic
        // encryption — XChaCha20 IS deterministic under fixed nonce, but
        // that property is for kat vectors).
        let key2 = Key::from_bytes(&key_bytes);
        let pt = decrypt(&key2, &nonce, b"ad", &ct).unwrap();
        assert_eq!(pt.as_slice(), b"deterministic test");
    }

    /// `XChaCha20`-`Poly1305` test vector from draft-irtf-cfrg-xchacha-03
    /// §A.3.
    ///
    /// Verifies our wrapper produces the exact byte string the spec
    /// mandates — a tighter check than round-trip property tests, since it
    /// fails closed against subtle construction bugs (wrong endianness,
    /// wrong nonce derivation, etc.).
    #[test]
    // `arithmetic_side_effects` allowed: `ct.len() >= TAG_LEN` always holds
    // because `encrypt()` always appends a `TAG_LEN`-byte `Poly1305` tag to
    // the ciphertext body. If that invariant ever breaks at the wrapper
    // layer, the subtraction's panic is the correct failure signal —
    // surfacing the bug rather than silently producing a zero-length body.
    #[allow(clippy::arithmetic_side_effects)]
    fn xchacha20poly1305_kat_draft_a3() {
        let key_bytes = hex_literal::hex!(
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
        );
        let nonce_bytes = hex_literal::hex!(
            "404142434445464748494a4b4c4d4e4f"
            "5051525354555657"
        );
        let aad = hex_literal::hex!("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
                          If I could offer you only one tip for the future, \
                          sunscreen would be it.";
        let expected_ciphertext = hex_literal::hex!(
            "bd6d179d3e83d43b9576579493c0e939"
            "572a1700252bfaccbed2902c21396cbb"
            "731c7f1b0b4aa6440bf3a82f4eda7e39"
            "ae64c6708c54c216cb96b72e1213b452"
            "2f8c9ba40db5d945b11b69b982c1bb9e"
            "3f3fac2bc369488f76b2383565d3fff9"
            "21f9664c97637da9768812f615c68b13"
            "b52e"
        );
        let expected_tag = hex_literal::hex!("c0875924c1c7987947deafd8780acf49");

        let key = Key::from_bytes(&Zeroizing::new(key_bytes));
        let nonce = Nonce::from_bytes(nonce_bytes);

        let ct = encrypt(&key, &nonce, &aad, plaintext).expect("encrypt should succeed");

        // The `aead` crate returns ciphertext || tag concatenated. Split
        // and verify each half against the KAT.
        let split_at = ct.len() - TAG_LEN;
        let (body, tag) = ct.split_at(split_at);
        assert_eq!(body, &expected_ciphertext[..]);
        assert_eq!(tag, &expected_tag[..]);

        // Round-trip check using the same fixed inputs.
        let pt = decrypt(&key, &nonce, &aad, &ct).expect("decrypt should succeed");
        assert_eq!(pt.as_slice(), plaintext);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use rand_core::OsRng;

    proptest! {
        /// Property: encrypt-then-decrypt round-trips for any plaintext +
        /// AAD pair under a freshly-generated key and nonce.
        #[test]
        fn prop_encrypt_decrypt_round_trip(
            plaintext in proptest::collection::vec(any::<u8>(), 0..4096),
            ad in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let mut rng = OsRng;
            let key = Key::generate(&mut rng);
            let nonce = Nonce::random(&mut rng);

            let ct = encrypt(&key, &nonce, &ad, &plaintext).unwrap();
            let pt = decrypt(&key, &nonce, &ad, &ct).unwrap();

            prop_assert_eq!(pt, plaintext);
        }

        /// Property: any single-bit tamper of the ciphertext or tag causes
        /// decryption to fail.
        ///
        /// `arithmetic_side_effects` allowed: `plaintext` is bounded
        /// `1..512` so `ct.len() >= 1 + TAG_LEN`, making `% ct.len()`
        /// well-defined (no div-by-zero). `indexing_slicing` allowed: the
        /// `%` result is by construction in `0..ct.len()`.
        #[test]
        #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
        fn prop_tamper_decrypt_fails(
            plaintext in proptest::collection::vec(any::<u8>(), 1..512),
            ad in proptest::collection::vec(any::<u8>(), 0..64),
            tamper_index in 0usize..1024,
            tamper_mask in 1u8..=255u8,
        ) {
            let mut rng = OsRng;
            let key = Key::generate(&mut rng);
            let nonce = Nonce::random(&mut rng);

            let mut ct = encrypt(&key, &nonce, &ad, &plaintext).unwrap();
            let idx = tamper_index % ct.len();
            // Tamper at idx; tamper_mask != 0 guarantees the byte changes.
            ct[idx] ^= tamper_mask;

            let result = decrypt(&key, &nonce, &ad, &ct);
            prop_assert!(matches!(result, Err(AeadError::DecryptFailed)));
        }

        /// Property: decrypting with a different fresh key always fails.
        #[test]
        fn prop_wrong_key_decrypt_fails(
            plaintext in proptest::collection::vec(any::<u8>(), 1..512),
            ad in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let mut rng = OsRng;
            let key_a = Key::generate(&mut rng);
            let key_b = Key::generate(&mut rng);
            let nonce = Nonce::random(&mut rng);

            let ct = encrypt(&key_a, &nonce, &ad, &plaintext).unwrap();
            let result = decrypt(&key_b, &nonce, &ad, &ct);
            prop_assert!(matches!(result, Err(AeadError::DecryptFailed)));
        }
    }
}
