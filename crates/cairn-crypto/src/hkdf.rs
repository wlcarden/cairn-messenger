// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! HKDF-SHA256 derivation wrapper.
//!
//! Thin typed wrapper over `hkdf` 0.12.4 + `sha2` 0.10.9 (per D0018 §1.3).
//! The discipline:
//!
//! - [`Prk`] is the extracted pseudorandom key (HKDF-Extract output). It
//!   wraps `SecretBox<[u8; PRK_LEN]>` and zeroizes on drop.
//! - [`Prk::extract`] runs HKDF-Extract (HMAC-SHA256(salt, ikm) per RFC 5869
//!   §2.2). Salt is optional per RFC 5869.
//! - [`Prk::expand`] runs HKDF-Expand into a caller-allocated buffer. The
//!   caller controls the buffer's zeroization, allowing fine-grained
//!   lifetime management at the use site.
//!
//! ## Why cache PRK
//!
//! Protocols like X3DH and Signal's Triple Ratchet (per D0006 §5.4) extract
//! a single PRK from one ECDH output, then expand it multiple times with
//! distinct `info` labels to derive separate root-key, chain-key, and
//! message-key streams. The [`Prk`] type makes this pattern explicit and
//! zero-cost compared to re-running extract per expand.
//!
//! ## Underlying construction
//!
//! [`Prk`] stores the 32-byte PRK in `SecretBox<[u8; 32]>` and reconstructs
//! `hkdf::Hkdf<Sha256>` on demand for each [`Prk::expand`] call via
//! `Hkdf::from_prk`. This matches the `cairn-crypto::ed25519` and
//! `cairn-crypto::x25519` pattern of storing raw key material under
//! `SecretBox` discipline rather than retaining the cryptographic primitive
//! directly.
//!
//! ## Test vector coverage
//!
//! The unit-test suite validates against RFC 5869 §A.1, §A.2, and §A.3 test
//! vectors (the SHA-256 cases). The proptest suite verifies extract/expand
//! determinism and that distinct `info` labels produce distinct outputs.

use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;

use crate::error::HkdfError;

/// Length of an HKDF-SHA256 pseudorandom key in bytes (= SHA-256 output length).
pub const PRK_LEN: usize = 32;

/// Maximum HKDF-SHA256 expand output length in bytes.
///
/// Per RFC 5869 §2.3, the maximum OKM length is `255 * HashLen` where
/// `HashLen` is the underlying hash's output length. For SHA-256 this is
/// `255 * 32 = 8160` bytes.
pub const MAX_OKM_LEN: usize = 255 * PRK_LEN;

/// HKDF-SHA256 pseudorandom key (output of the Extract step).
///
/// Stores the 32-byte PRK in `SecretBox<[u8; 32]>`. The bytes are
/// exposed only via the private `Self::with_hkdf` helper for use inside
/// [`Self::expand`]; there is no public byte-level accessor.
///
/// Implements [`crate::never_export::NeverExport`] (via the
/// `SecretBox<[u8; 32]>` impl in [`crate::never_export`]).
pub struct Prk {
    bytes: SecretBox<[u8; PRK_LEN]>,
}

impl Prk {
    /// HKDF-Extract: derive a pseudorandom key from input keying material.
    ///
    /// `salt` is the (optional) HKDF salt per RFC 5869 §2.2. `None` is
    /// equivalent to a zero-byte salt of `HashLen` bytes. `ikm` is the input
    /// keying material — typically an ECDH shared secret or a concatenation
    /// of several.
    ///
    /// Extract cannot fail (HMAC-SHA256 always produces a 32-byte output).
    #[must_use]
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let (prk_array, _hk) = Hkdf::<Sha256>::extract(salt, ikm);
        let mut bytes = [0u8; PRK_LEN];
        bytes.copy_from_slice(prk_array.as_slice());
        Self {
            bytes: SecretBox::new(Box::new(bytes)),
        }
    }

    /// HKDF-Expand: derive output keying material into the caller-allocated
    /// buffer.
    ///
    /// `info` is the (optional) context-and-application-specific information
    /// per RFC 5869 §2.3 — typically a protocol label like `b"cairn:rk:v1"`.
    /// `out` is filled with `out.len()` bytes of derived keying material.
    ///
    /// # Errors
    ///
    /// Returns [`HkdfError::OutputTooLong`] if `out.len() > MAX_OKM_LEN`
    /// (8160 bytes for SHA-256).
    pub fn expand(&self, info: &[u8], out: &mut [u8]) -> Result<(), HkdfError> {
        let hk = Hkdf::<Sha256>::from_prk(self.bytes.expose_secret()).map_err(|_| {
            // Unreachable in practice: PRK_LEN matches Hkdf<Sha256>'s expected
            // PRK size. This branch exists to satisfy the type system; if it
            // ever fires, it indicates a hkdf-crate API change.
            HkdfError::OutputTooLong {
                got_bytes: out.len(),
                max_bytes: MAX_OKM_LEN,
            }
        })?;
        hk.expand(info, out).map_err(|_| HkdfError::OutputTooLong {
            got_bytes: out.len(),
            max_bytes: MAX_OKM_LEN,
        })
    }
}

/// One-shot HKDF-SHA256 derivation: extract then expand in a single call.
///
/// Convenience for the common pattern where a PRK is used for exactly one
/// expand call. For protocols that need multiple expand calls on the same
/// PRK (Triple Ratchet, X3DH), construct a [`Prk`] via [`Prk::extract`]
/// directly.
///
/// # Errors
///
/// Returns [`HkdfError::OutputTooLong`] if `out.len() > MAX_OKM_LEN`.
pub fn derive(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), HkdfError> {
    let prk = Prk::extract(salt, ikm);
    prk.expand(info, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 §A.1: SHA-256 basic test.
    ///
    /// IKM:  0x0b repeated 22 times
    /// salt: 0x000102030405060708090a0b0c
    /// info: 0xf0f1f2f3f4f5f6f7f8f9
    /// L:    42
    #[test]
    fn rfc5869_appendix_a_1() {
        let ikm = [0x0b_u8; 22];
        let salt = hex_literal::hex!("000102030405060708090a0b0c");
        let info = hex_literal::hex!("f0f1f2f3f4f5f6f7f8f9");
        let expected_okm = hex_literal::hex!(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        );

        let mut okm = [0u8; 42];
        derive(Some(&salt), &ikm, &info, &mut okm).expect("derive should succeed");
        assert_eq!(okm, expected_okm);
    }

    /// RFC 5869 §A.2: SHA-256 with longer inputs.
    ///
    /// IKM:  0x00..0x4f (80 bytes)
    /// salt: 0x60..0xaf (80 bytes)
    /// info: 0xb0..0xff (80 bytes)
    /// L:    82
    #[test]
    fn rfc5869_appendix_a_2() {
        let ikm: [u8; 80] = core::array::from_fn(|i| u8::try_from(i).expect("0..80 fits in u8"));
        let salt: [u8; 80] =
            core::array::from_fn(|i| u8::try_from(0x60 + i).expect("0x60..0xb0 fits in u8"));
        let info: [u8; 80] =
            core::array::from_fn(|i| u8::try_from(0xb0 + i).expect("0xb0..0x100 fits in u8"));
        let expected_okm = hex_literal::hex!(
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87"
        );

        let mut okm = [0u8; 82];
        derive(Some(&salt), &ikm, &info, &mut okm).expect("derive should succeed");
        assert_eq!(okm, expected_okm);
    }

    /// RFC 5869 §A.3: SHA-256 with empty salt and info.
    ///
    /// IKM:  0x0b repeated 22 times
    /// salt: (empty)
    /// info: (empty)
    /// L:    42
    #[test]
    fn rfc5869_appendix_a_3() {
        let ikm = [0x0b_u8; 22];
        let expected_okm = hex_literal::hex!(
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8"
        );

        let mut okm = [0u8; 42];
        derive(None, &ikm, b"", &mut okm).expect("derive should succeed");
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn prk_extract_expand_matches_one_shot() {
        // The two-step Prk::extract + Prk::expand path must produce the same
        // output as the one-shot derive() helper.
        let ikm = b"input keying material";
        let salt = b"salt";
        let info = b"info label";

        let mut okm_two_step = [0u8; 64];
        let prk = Prk::extract(Some(salt), ikm);
        prk.expand(info, &mut okm_two_step)
            .expect("expand should succeed");

        let mut okm_one_shot = [0u8; 64];
        derive(Some(salt), ikm, info, &mut okm_one_shot).expect("derive should succeed");

        assert_eq!(okm_two_step, okm_one_shot);
    }

    #[test]
    fn prk_supports_multiple_expand_calls() {
        // The libsignal/X3DH/Triple-Ratchet pattern: one PRK, many expand
        // calls with distinct info labels. Each call should produce
        // independent keying material.
        let prk = Prk::extract(Some(b"salt"), b"shared secret");

        let mut root_key = [0u8; 32];
        let mut chain_key = [0u8; 32];
        let mut header_key = [0u8; 32];

        prk.expand(b"cairn:rk:v1", &mut root_key).unwrap();
        prk.expand(b"cairn:ck:v1", &mut chain_key).unwrap();
        prk.expand(b"cairn:hk:v1", &mut header_key).unwrap();

        // Each label produces a distinct stream.
        assert_ne!(root_key, chain_key);
        assert_ne!(root_key, header_key);
        assert_ne!(chain_key, header_key);
    }

    #[test]
    fn expand_rejects_over_long_output() {
        let prk = Prk::extract(Some(b"salt"), b"ikm");

        // MAX_OKM_LEN + 1 is rejected; vec to avoid stack overflow on large
        // arrays.
        let mut okm = vec![0u8; MAX_OKM_LEN + 1];
        let result = prk.expand(b"info", &mut okm);
        assert!(matches!(result, Err(HkdfError::OutputTooLong { .. })));
    }

    #[test]
    fn expand_accepts_max_length_output() {
        let prk = Prk::extract(Some(b"salt"), b"ikm");
        let mut okm = vec![0u8; MAX_OKM_LEN];
        prk.expand(b"info", &mut okm)
            .expect("expand at max length should succeed");
    }

    #[test]
    fn extract_with_none_salt_equals_extract_with_empty_salt() {
        // RFC 5869 §2.2: salt=None is equivalent to salt of HashLen zero
        // bytes. The hkdf crate handles this normalization; we just verify
        // it.
        let ikm = b"ikm";
        let info = b"info";

        let mut okm_none = [0u8; 32];
        derive(None, ikm, info, &mut okm_none).unwrap();

        let mut okm_zero = [0u8; 32];
        let zero_salt = [0u8; PRK_LEN];
        derive(Some(&zero_salt), ikm, info, &mut okm_zero).unwrap();

        assert_eq!(okm_none, okm_zero);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Property: HKDF is deterministic — the same (salt, ikm, info,
        /// length) inputs always produce the same OKM.
        #[test]
        fn prop_derive_determinism(
            salt in proptest::collection::vec(any::<u8>(), 0..64),
            ikm in proptest::collection::vec(any::<u8>(), 1..256),
            info in proptest::collection::vec(any::<u8>(), 0..64),
            len in 1usize..256,
        ) {
            let mut okm1 = vec![0u8; len];
            let mut okm2 = vec![0u8; len];

            derive(Some(&salt), &ikm, &info, &mut okm1).unwrap();
            derive(Some(&salt), &ikm, &info, &mut okm2).unwrap();

            prop_assert_eq!(okm1, okm2);
        }

        /// Property: distinct `info` labels produce distinct OKM (with
        /// overwhelming probability) for the same PRK.
        #[test]
        fn prop_distinct_info_distinct_okm(
            ikm in proptest::collection::vec(any::<u8>(), 16..128),
            info_a in proptest::collection::vec(any::<u8>(), 1..32),
            info_b in proptest::collection::vec(any::<u8>(), 1..32),
        ) {
            // Skip identical-info case (the property is about distinct
            // inputs).
            prop_assume!(info_a != info_b);

            let prk = Prk::extract(None, &ikm);
            let mut okm_a = [0u8; 32];
            let mut okm_b = [0u8; 32];
            prk.expand(&info_a, &mut okm_a).unwrap();
            prk.expand(&info_b, &mut okm_b).unwrap();

            prop_assert_ne!(okm_a, okm_b);
        }

        /// Property: two distinct `ikm` values yield distinct OKM (with
        /// overwhelming probability) for the same (salt, info, length).
        #[test]
        fn prop_distinct_ikm_distinct_okm(
            ikm_a in proptest::collection::vec(any::<u8>(), 16..128),
            ikm_b in proptest::collection::vec(any::<u8>(), 16..128),
            info in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            prop_assume!(ikm_a != ikm_b);

            let mut okm_a = [0u8; 32];
            let mut okm_b = [0u8; 32];

            derive(None, &ikm_a, &info, &mut okm_a).unwrap();
            derive(None, &ikm_b, &info, &mut okm_b).unwrap();

            prop_assert_ne!(okm_a, okm_b);
        }
    }
}
