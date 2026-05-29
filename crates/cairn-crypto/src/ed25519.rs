// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Ed25519 signing key wrappers.
//!
//! Thin typed wrappers over `ed25519-dalek` 2.2.0 (per D0018 §1.1). The
//! discipline:
//!
//! - [`SigningKey`] stores the 32-byte seed (RFC 8032 §5.1.5) wrapped in
//!   `secrecy::SecretBox<[u8; 32]>` so the seed is automatically zeroized on
//!   drop and cannot be accidentally `Debug`-printed. The seed (not the
//!   derived scalar) is what Cairn's Shamir splitting operates on per D0006
//!   §9. The `ed25519_dalek::SigningKey` is reconstructed on demand from the
//!   seed for each signing operation; this is cheap (a single SHA-512
//!   expansion) and means only seed bytes ever sit in long-lived memory.
//! - [`VerifyingKey`] is a thin wrapper over the public key — non-secret;
//!   the type is `Copy + Clone + Debug + Eq` with constant-time `PartialEq`.
//! - [`Signature`] is a thin newtype wrapper over a 64-byte Ed25519
//!   signature (public value; no secret bytes).
//!
//! ## Constant-time properties
//!
//! `ed25519-dalek::SigningKey::sign` is constant-time per the upstream
//! audited construction. `verify_strict` defends against malleability and
//! small-subgroup attacks per the upstream documentation. Cairn always uses
//! `verify_strict` (not the looser `verify`) per D0018 §1.1.
//!
//! ## Seed-not-scalar
//!
//! Cairn's Shamir Secret Sharing splits the **32-byte Ed25519 seed** (RFC
//! 8032 §5.1.5), not the derived signing scalar. This preserves Ed25519's
//! deterministic nonce contract: reconstructing a scalar instead of a seed
//! and then signing would produce nonces derived from a different input
//! than the master signature, which can produce nonce-collision risk if
//! multiple devices ever reconstruct independently.
//!
//! [`SigningKey::from_seed`] is the constructor Cairn uses after Shamir
//! reconstruction; it takes the 32-byte seed and stores it directly.

use ed25519_dalek::Signer as _;
use rand_core::{CryptoRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{SignError, VerifyError};

/// Maximum signable payload size in bytes.
///
/// Ed25519 has no inherent payload-size limit (the protocol hashes the input
/// before signing), but Cairn imposes an application-layer cap so that
/// signing operations cannot be used as a `DoS` vector via unbounded allocator
/// pressure on the SHA-512 input.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// Length of an Ed25519 seed per RFC 8032 §5.1.5.
pub const SEED_LEN: usize = 32;

/// Length of an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Cairn-side Ed25519 signing key.
///
/// Stores the 32-byte seed (RFC 8032 §5.1.5) wrapped in
/// `SecretBox<[u8; 32]>`. The `ed25519_dalek::SigningKey` is reconstructed on
/// demand from the seed for each signing operation. This design means:
///
/// - The seed is automatically zeroized when the [`SigningKey`] is dropped
///   (subject to the limitations of `zeroize` documented in the crate-level
///   memory-hygiene section).
/// - The seed cannot be accidentally `Debug`-printed or `Display`-formatted;
///   `Debug` for `SecretBox` redacts the value.
/// - Only seed bytes sit in long-lived memory. The derived scalar and any
///   intermediate computation state used during a signing operation live on
///   the stack during the call and are not retained.
/// - The type holds a value of type `SecretBox<[u8; 32]>`, which Cairn
///   marks [`crate::never_export::NeverExport`] in the
///   [`crate::never_export`] module so the type cannot accidentally cross
///   the `UniFFI` boundary.
pub struct SigningKey {
    seed: SecretBox<[u8; SEED_LEN]>,
}

impl SigningKey {
    /// Generate a fresh Ed25519 signing key from the provided CSPRNG.
    ///
    /// The CSPRNG must implement both `CryptoRng` (marker for cryptographic
    /// suitability) and `RngCore` (actual random-byte source). Per D0018
    /// §1.7, the caller should pass `OsRng` or another `OS`-backed CSPRNG;
    /// `thread_rng` and `SmallRng` are NOT cryptographically suitable for
    /// key generation.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut seed = [0u8; SEED_LEN];
        rng.fill_bytes(&mut seed);
        Self {
            seed: SecretBox::new(Box::new(seed)),
        }
    }

    /// Reconstruct a signing key from a 32-byte seed.
    ///
    /// This is the constructor Cairn uses after Shamir reconstruction: the
    /// `cairn-shamir` crate produces a `Zeroizing<[u8; 32]>` reconstructed
    /// seed; this constructor copies it into a new `SecretBox`. The caller's
    /// `Zeroizing` wrapper will zero the original location on its own drop
    /// (with the usual limitations documented in the crate-level
    /// memory-hygiene section).
    #[must_use]
    pub fn from_seed(seed: &Zeroizing<[u8; SEED_LEN]>) -> Self {
        let mut bytes = [0u8; SEED_LEN];
        bytes.copy_from_slice(seed.as_ref());
        Self {
            seed: SecretBox::new(Box::new(bytes)),
        }
    }

    /// Reconstruct the inner `ed25519_dalek::SigningKey` from the stored seed.
    ///
    /// Private helper. The reconstructed key lives only on the stack for the
    /// duration of the caller's operation; it is not stored in
    /// [`SigningKey`].
    ///
    /// `disallowed_types` is allowed here because `cairn-crypto::ed25519` is
    /// the wrapper layer that legitimately owns the inner dalek type. The
    /// `disallowed_types` discipline applies to code OUTSIDE `cairn-crypto`
    /// per D0018 §1.6 secret-handling discipline.
    #[allow(clippy::disallowed_types)]
    fn dalek_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(self.seed.expose_secret())
    }

    /// Derive the public verifying key.
    ///
    /// The public key is non-secret; it can cross the `UniFFI` boundary
    /// freely.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: self.dalek_key().verifying_key(),
        }
    }

    /// Sign a payload.
    ///
    /// Returns the 64-byte Ed25519 signature, or an error if the payload
    /// exceeds the application-layer size cap [`MAX_PAYLOAD_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`SignError::PayloadTooLarge`] if the payload exceeds
    /// [`MAX_PAYLOAD_BYTES`].
    pub fn sign(&self, payload: &[u8]) -> Result<Signature, SignError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(SignError::PayloadTooLarge {
                got_bytes: payload.len(),
                max_bytes: MAX_PAYLOAD_BYTES,
            });
        }
        let sig = self.dalek_key().sign(payload);
        Ok(Signature {
            inner: sig.to_bytes(),
        })
    }
}

/// Ed25519 verifying (public) key.
///
/// Carries no secret material. `Clone`-able and `Copy`-able; exported across
/// FFI as 32-byte plain bytes.
#[derive(Clone, Copy)]
pub struct VerifyingKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl VerifyingKey {
    /// Construct from a 32-byte public-key byte string.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::Invalid`] if the bytes do not encode a valid
    /// Ed25519 public key (e.g., point not on curve).
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, VerifyError> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(|_| VerifyError::Invalid)
    }

    /// Return the 32-byte public-key byte string.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.inner.to_bytes()
    }

    /// Verify a signature against this public key.
    ///
    /// Uses Ed25519 strict verification (rejects signatures with
    /// non-canonical `s` values and small-subgroup public keys) per D0018
    /// §1.1 discipline.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::Invalid`] on any verification failure. The
    /// error is deliberately opaque: no further information about why
    /// verification failed is returned, per the cryptographic discipline of
    /// avoiding verification oracles.
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> Result<(), VerifyError> {
        let sig = ed25519_dalek::Signature::from_bytes(&signature.inner);
        self.inner
            .verify_strict(payload, &sig)
            .map_err(|_| VerifyError::Invalid)
    }
}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Public key is non-secret; we display only a short hex prefix to
        // keep log output compact.
        let bytes = self.to_bytes();
        write!(
            f,
            "VerifyingKey({:02x}{:02x}{:02x}{:02x}…)",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        // Public-key equality. Constant-time even though public keys are
        // non-secret, for API consistency with the discipline that key types
        // never use `==` directly on raw bytes.
        self.to_bytes().ct_eq(&other.to_bytes()).into()
    }
}

impl Eq for VerifyingKey {}

/// Ed25519 signature.
///
/// 64-byte public value. `Copy` + `Clone` + `Debug` + `Eq`.
#[derive(Clone, Copy)]
pub struct Signature {
    inner: [u8; SIGNATURE_LEN],
}

impl Signature {
    /// Construct from a 64-byte signature byte string.
    ///
    /// Does NOT validate the signature against any key or payload; this is
    /// purely a typed wrapper around the byte string.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self { inner: bytes }
    }

    /// Return the 64-byte signature byte string.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.inner
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Signature({:02x}{:02x}{:02x}{:02x}…)",
            self.inner[0], self.inner[1], self.inner[2], self.inner[3]
        )
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner).into()
    }
}

impl Eq for Signature {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn sign_verify_round_trip() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let payload = b"hello cairn";
        let sig = sk.sign(payload).expect("sign should succeed");

        vk.verify(payload, &sig).expect("verify should succeed");
    }

    #[test]
    fn from_seed_round_trip() {
        let seed = Zeroizing::new([0xAB_u8; SEED_LEN]);
        let sk1 = SigningKey::from_seed(&seed);
        let sk2 = SigningKey::from_seed(&seed);

        // Deterministic from seed: both signatures should be byte-identical
        // (Ed25519 uses deterministic nonces per RFC 8032).
        let payload = b"determinism check";
        let sig1 = sk1.sign(payload).expect("sign should succeed");
        let sig2 = sk2.sign(payload).expect("sign should succeed");

        assert_eq!(sig1.to_bytes(), sig2.to_bytes());

        // Both keys should produce the same verifying key.
        assert_eq!(sk1.verifying_key(), sk2.verifying_key());
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let payload = b"hello cairn";
        let sig = sk.sign(payload).expect("sign should succeed");

        // Flip one bit of the signature.
        let mut tampered_bytes = sig.to_bytes();
        tampered_bytes[0] ^= 0x01;
        let tampered = Signature::from_bytes(tampered_bytes);

        assert!(vk.verify(payload, &tampered).is_err());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let sig = sk.sign(b"original payload").expect("sign should succeed");

        assert!(vk.verify(b"different payload", &sig).is_err());
    }

    #[test]
    fn payload_size_limit_enforced() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let payload = vec![0u8; MAX_PAYLOAD_BYTES + 1];

        let err = sk.sign(&payload).expect_err("expected PayloadTooLarge");
        let SignError::PayloadTooLarge {
            got_bytes,
            max_bytes,
        } = err;
        assert_eq!(got_bytes, MAX_PAYLOAD_BYTES + 1);
        assert_eq!(max_bytes, MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn verifying_key_round_trip() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let bytes = vk.to_bytes();
        let vk2 = VerifyingKey::from_bytes(&bytes).expect("valid public key");

        assert_eq!(vk, vk2);
    }

    #[test]
    fn signature_round_trip() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let sig = sk.sign(b"round trip").expect("sign should succeed");

        let bytes = sig.to_bytes();
        let sig2 = Signature::from_bytes(bytes);

        assert_eq!(sig, sig2);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use rand_core::OsRng;

    proptest! {
        /// Property: sign-then-verify always succeeds for any payload up to
        /// the application-layer cap with any key.
        #[test]
        fn prop_sign_verify_round_trip(payload in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let mut rng = OsRng;
            let sk = SigningKey::generate(&mut rng);
            let vk = sk.verifying_key();

            let sig = sk.sign(&payload).expect("sign should succeed");
            vk.verify(&payload, &sig).expect("verify should succeed");
        }

        /// Property: signing the same payload with the same seed produces
        /// the same signature (Ed25519 deterministic nonces).
        #[test]
        fn prop_seed_determinism(
            seed in any::<[u8; SEED_LEN]>(),
            payload in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            let seed = Zeroizing::new(seed);
            let sk1 = SigningKey::from_seed(&seed);
            let sk2 = SigningKey::from_seed(&seed);

            let sig1 = sk1.sign(&payload).expect("sign should succeed");
            let sig2 = sk2.sign(&payload).expect("sign should succeed");

            prop_assert_eq!(sig1.to_bytes(), sig2.to_bytes());
        }

        /// Property: any single-bit flip in a valid signature makes it fail
        /// verification.
        ///
        /// `indexing_slicing` is allowed because `flip_byte` is bounded by the
        /// proptest `Strategy` to `0..SIGNATURE_LEN`, so the index is safe.
        #[test]
        #[allow(clippy::indexing_slicing)]
        fn prop_signature_tamper_resistance(
            payload in proptest::collection::vec(any::<u8>(), 1..256),
            flip_byte in 0usize..SIGNATURE_LEN,
            flip_bit in 0u8..8
        ) {
            let mut rng = OsRng;
            let sk = SigningKey::generate(&mut rng);
            let vk = sk.verifying_key();

            let sig = sk.sign(&payload).expect("sign should succeed");
            let mut tampered_bytes = sig.to_bytes();
            tampered_bytes[flip_byte] ^= 1 << flip_bit;
            let tampered = Signature::from_bytes(tampered_bytes);

            prop_assert!(vk.verify(&payload, &tampered).is_err());
        }
    }
}
