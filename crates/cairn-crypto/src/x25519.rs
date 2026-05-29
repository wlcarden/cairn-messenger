// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! X25519 ECDH key-agreement wrappers.
//!
//! Thin typed wrappers over `x25519-dalek` 2.0.1 (per D0018 §1.2). The
//! discipline:
//!
//! - [`EphemeralKey`] is a one-shot key with consume-on-agree semantics. The
//!   type-system enforces single-use: [`EphemeralKey::agree`] takes `self` by
//!   value, so after one agreement the key is dropped and zeroized.
//! - [`StaticKey`] is a reusable long-lived key with `agree(&self, ...)`
//!   semantics. Used for the operational identity's long-term key per D0006
//!   §9.
//! - [`PublicKey`] is a thin wrapper over the 32-byte public-key bytes (no
//!   secret material).
//! - [`SharedSecret`] wraps the 32-byte agreement output in
//!   `SecretBox<[u8; 32]>` and is constructed ONLY via the agreement
//!   functions; the constructor enforces the mandatory `was_contributory()`
//!   check.
//!
//! ## Was-contributory discipline (D0018 §1.2)
//!
//! Per the vodozemac 2026 audit finding (Soatok blog, February 2026), even
//! mature E2EE codebases have shipped X25519 implementations that omit the
//! `was_contributory()` check. The check rejects key agreements where the
//! peer's public key is in the curve's small subgroup, producing a zero or
//! near-zero shared secret. This crate enforces the check **at the type
//! level**: a [`SharedSecret`] only exists if the agreement passed the
//! check. Construction outside [`agree`](EphemeralKey::agree) /
//! [`StaticKey::agree`] is not possible from outside the module because the
//! constructor is private.
//!
//! ## Underlying construction
//!
//! Both [`EphemeralKey`] and [`StaticKey`] store the 32-byte seed in
//! `SecretBox<[u8; 32]>`. The `x25519_dalek::StaticSecret` is reconstructed
//! on-demand from the seed for each operation (`x25519_dalek::EphemeralSecret`
//! is not used directly because it lacks a `from_bytes` constructor; we
//! achieve ephemeral semantics via the consume-on-agree API instead).
//!
//! `x25519_dalek::StaticSecret::from(bytes)` performs the standard clamp per
//! RFC 7748 §5; the stored seed therefore yields the same scalar across
//! reconstructions.

use rand_core::{CryptoRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::AgreeError;

/// Length of an X25519 secret key (seed bytes) in bytes.
pub const SECRET_KEY_LEN: usize = 32;

/// Length of an X25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of an X25519 shared secret in bytes.
pub const SHARED_SECRET_LEN: usize = 32;

/// Ephemeral X25519 key with consume-on-agree semantics.
///
/// Used for one-shot key agreements where forward secrecy is the goal: the
/// key is generated, used for exactly one [`Self::agree`] call, then dropped
/// and zeroized. The type system enforces single-use: [`Self::agree`] takes
/// `self` by value.
pub struct EphemeralKey {
    seed: SecretBox<[u8; SECRET_KEY_LEN]>,
}

impl EphemeralKey {
    /// Generate a fresh ephemeral key from the provided CSPRNG.
    ///
    /// Per D0018 §1.7, the caller should pass `OsRng` or another `OS`-backed
    /// CSPRNG; `thread_rng` and `SmallRng` are NOT cryptographically suitable
    /// for key generation.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut seed = [0u8; SECRET_KEY_LEN];
        rng.fill_bytes(&mut seed);
        Self {
            seed: SecretBox::new(Box::new(seed)),
        }
    }

    /// Derive the public key for this ephemeral key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        let sk = dalek_static_secret(self.seed.expose_secret());
        let pk = x25519_dalek::PublicKey::from(&sk);
        PublicKey {
            inner: pk.to_bytes(),
        }
    }

    /// Perform an X25519 key agreement with a peer's public key.
    ///
    /// Consumes `self` — after this call, the ephemeral key is dropped and
    /// zeroized.
    ///
    /// # Errors
    ///
    /// Returns [`AgreeError::NonContributory`] if the agreement produces a
    /// zero or small-subgroup shared secret (per the
    /// `was_contributory()` check). This indicates either a malformed peer
    /// public key or a deliberate small-subgroup attack.
    pub fn agree(self, peer: &PublicKey) -> Result<SharedSecret, AgreeError> {
        let sk = dalek_static_secret(self.seed.expose_secret());
        let peer_pk = x25519_dalek::PublicKey::from(peer.inner);
        let shared = sk.diffie_hellman(&peer_pk);
        SharedSecret::from_dalek(&shared)
    }
}

/// Long-lived X25519 key with `&self` agreement semantics.
///
/// Used for keys that persist across multiple agreements (e.g., the
/// operational identity's long-term X25519 key per D0006 §9). The same key
/// can be used for many [`Self::agree`] calls.
pub struct StaticKey {
    seed: SecretBox<[u8; SECRET_KEY_LEN]>,
}

impl StaticKey {
    /// Generate a fresh static key from the provided CSPRNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut seed = [0u8; SECRET_KEY_LEN];
        rng.fill_bytes(&mut seed);
        Self {
            seed: SecretBox::new(Box::new(seed)),
        }
    }

    /// Reconstruct a static key from a 32-byte seed.
    ///
    /// The seed is clamped per RFC 7748 §5 by the underlying
    /// `x25519_dalek::StaticSecret::from(bytes)` constructor on each
    /// agreement; the stored bytes are the pre-clamp seed.
    #[must_use]
    pub fn from_seed(seed: &Zeroizing<[u8; SECRET_KEY_LEN]>) -> Self {
        let mut bytes = [0u8; SECRET_KEY_LEN];
        bytes.copy_from_slice(seed.as_ref());
        Self {
            seed: SecretBox::new(Box::new(bytes)),
        }
    }

    /// Derive the public key for this static key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        let sk = dalek_static_secret(self.seed.expose_secret());
        let pk = x25519_dalek::PublicKey::from(&sk);
        PublicKey {
            inner: pk.to_bytes(),
        }
    }

    /// Perform an X25519 key agreement with a peer's public key.
    ///
    /// `&self` — the static key remains usable for further agreements.
    ///
    /// # Errors
    ///
    /// Returns [`AgreeError::NonContributory`] if the agreement produces a
    /// non-contributory shared secret.
    pub fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, AgreeError> {
        let sk = dalek_static_secret(self.seed.expose_secret());
        let peer_pk = x25519_dalek::PublicKey::from(peer.inner);
        let shared = sk.diffie_hellman(&peer_pk);
        SharedSecret::from_dalek(&shared)
    }
}

/// X25519 public key.
///
/// 32 bytes of non-secret data. `Copy + Clone + Debug + Eq` with
/// constant-time `PartialEq` for API consistency.
#[derive(Clone, Copy)]
pub struct PublicKey {
    inner: [u8; PUBLIC_KEY_LEN],
}

impl PublicKey {
    /// Construct from raw bytes.
    ///
    /// Does NOT validate the bytes as a valid curve point; X25519's design
    /// accepts any 32-byte string as a public key (with curve clamping
    /// performed during agreement). Small-subgroup detection is enforced at
    /// agreement time via [`SharedSecret`]'s mandatory
    /// `was_contributory()` check.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self { inner: bytes }
    }

    /// Return the 32-byte public-key byte string.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.inner
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "X25519PublicKey({:02x}{:02x}{:02x}{:02x}…)",
            self.inner[0], self.inner[1], self.inner[2], self.inner[3]
        )
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.ct_eq(&other.inner).into()
    }
}

impl Eq for PublicKey {}

/// X25519 shared secret.
///
/// Constructed only via [`EphemeralKey::agree`] or [`StaticKey::agree`];
/// construction enforces the mandatory `was_contributory()` check per D0018
/// §1.2.
///
/// Holds the 32-byte agreement output in `SecretBox<[u8; 32]>`; the bytes
/// are accessible only via [`Self::expose_secret`] and the type implements
/// [`crate::never_export::NeverExport`] (via the `SecretBox<[u8; 32]>` impl
/// in [`crate::never_export`]).
pub struct SharedSecret {
    inner: SecretBox<[u8; SHARED_SECRET_LEN]>,
}

impl SharedSecret {
    /// Construct from a raw `x25519_dalek::SharedSecret`, enforcing the
    /// `was_contributory()` check.
    ///
    /// Private — callers must go through [`EphemeralKey::agree`] or
    /// [`StaticKey::agree`]. Takes `&secret` rather than consuming because
    /// `was_contributory()` and `to_bytes()` are both `&self`; the caller's
    /// owning binding drops and zeroizes at the end of its enclosing scope.
    fn from_dalek(secret: &x25519_dalek::SharedSecret) -> Result<Self, AgreeError> {
        if !secret.was_contributory() {
            return Err(AgreeError::NonContributory);
        }
        let bytes = secret.to_bytes();
        Ok(Self {
            inner: SecretBox::new(Box::new(bytes)),
        })
    }

    /// Expose the 32-byte shared-secret bytes.
    ///
    /// Used by downstream cryptographic operations (typically HKDF
    /// derivation per `cairn-crypto::hkdf` once that module lands). The
    /// returned reference is bound to the lifetime of `&self`; callers
    /// should not retain the bytes beyond the immediate derivation
    /// operation.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; SHARED_SECRET_LEN] {
        self.inner.expose_secret()
    }
}

/// Reconstruct an `x25519_dalek::StaticSecret` from a 32-byte seed.
///
/// `disallowed_types` allowed here because `cairn-crypto::x25519` is the
/// wrapper layer that legitimately owns the inner dalek type. The
/// `disallowed_types` discipline applies to code OUTSIDE `cairn-crypto` per
/// D0018 §1.6.
#[allow(clippy::disallowed_types)]
fn dalek_static_secret(seed: &[u8; SECRET_KEY_LEN]) -> x25519_dalek::StaticSecret {
    x25519_dalek::StaticSecret::from(*seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn ephemeral_agree_round_trip() {
        let mut rng = OsRng;

        // Alice and Bob each generate ephemeral keys.
        let alice = EphemeralKey::generate(&mut rng);
        let bob = EphemeralKey::generate(&mut rng);

        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();

        // Each side performs the agreement with the other's public key.
        let alice_shared = alice.agree(&bob_pub).expect("agree should succeed");
        let bob_shared = bob.agree(&alice_pub).expect("agree should succeed");

        // Both sides arrive at the same shared secret.
        assert_eq!(
            alice_shared.expose_secret(),
            bob_shared.expose_secret(),
            "alice and bob should derive the same shared secret"
        );
    }

    #[test]
    fn static_agree_round_trip() {
        let mut rng = OsRng;

        let alice = StaticKey::generate(&mut rng);
        let bob = StaticKey::generate(&mut rng);

        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();

        let alice_shared = alice.agree(&bob_pub).expect("agree should succeed");
        let bob_shared = bob.agree(&alice_pub).expect("agree should succeed");

        assert_eq!(alice_shared.expose_secret(), bob_shared.expose_secret());

        // Static keys are reusable: alice can agree with bob again and get
        // the same shared secret.
        let alice_shared_again = alice.agree(&bob_pub).expect("agree should succeed");
        assert_eq!(
            alice_shared.expose_secret(),
            alice_shared_again.expose_secret()
        );
    }

    #[test]
    fn static_from_seed_round_trip() {
        let seed = Zeroizing::new([0xAB_u8; SECRET_KEY_LEN]);
        let sk1 = StaticKey::from_seed(&seed);
        let sk2 = StaticKey::from_seed(&seed);

        // Same seed produces same public key.
        assert_eq!(sk1.public_key(), sk2.public_key());
    }

    #[test]
    fn ephemeral_and_static_interop() {
        // An EphemeralKey on one side and a StaticKey on the other should
        // produce the same shared secret. (This is the typical handshake
        // pattern: one side is ephemeral, the other is identity-bound.)
        let mut rng = OsRng;
        let alice = EphemeralKey::generate(&mut rng);
        let bob = StaticKey::generate(&mut rng);

        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();

        let alice_shared = alice.agree(&bob_pub).expect("agree should succeed");
        let bob_shared = bob.agree(&alice_pub).expect("agree should succeed");

        assert_eq!(alice_shared.expose_secret(), bob_shared.expose_secret());
    }

    #[test]
    fn agree_with_zero_public_key_is_non_contributory() {
        // The all-zero public key maps to the small-subgroup point that
        // produces a zero shared secret. was_contributory() should return
        // false, and agree() should return AgreeError::NonContributory.
        let mut rng = OsRng;
        let alice = EphemeralKey::generate(&mut rng);
        let zero_pk = PublicKey::from_bytes([0u8; PUBLIC_KEY_LEN]);

        let result = alice.agree(&zero_pk);
        assert!(
            matches!(result, Err(AgreeError::NonContributory)),
            "agreement with all-zero pk should be non-contributory"
        );
    }

    #[test]
    fn public_key_round_trip() {
        let mut rng = OsRng;
        let sk = StaticKey::generate(&mut rng);
        let pk = sk.public_key();

        let bytes = pk.to_bytes();
        let pk2 = PublicKey::from_bytes(bytes);

        assert_eq!(pk, pk2);
    }

    #[test]
    fn different_keys_produce_different_shared_secrets() {
        let mut rng = OsRng;
        let alice = StaticKey::generate(&mut rng);
        let bob = StaticKey::generate(&mut rng);
        let carol = StaticKey::generate(&mut rng);

        let bob_pub = bob.public_key();
        let carol_pub = carol.public_key();

        let alice_with_bob = alice.agree(&bob_pub).expect("agree should succeed");
        let alice_with_carol = alice.agree(&carol_pub).expect("agree should succeed");

        assert_ne!(
            alice_with_bob.expose_secret(),
            alice_with_carol.expose_secret(),
            "shared secrets with different peers should differ"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use rand_core::OsRng;

    proptest! {
        /// Property: ECDH agreement is symmetric — alice and bob always
        /// derive the same shared secret from any pair of valid keys.
        #[test]
        fn prop_ecdh_symmetry(
            alice_seed in any::<[u8; SECRET_KEY_LEN]>(),
            bob_seed in any::<[u8; SECRET_KEY_LEN]>()
        ) {
            let alice = StaticKey::from_seed(&Zeroizing::new(alice_seed));
            let bob = StaticKey::from_seed(&Zeroizing::new(bob_seed));

            let alice_pub = alice.public_key();
            let bob_pub = bob.public_key();

            // For randomly-generated seeds, the agreement should almost
            // always be contributory. The exceptions (tiny probability) are
            // when the derived public keys happen to land in the small
            // subgroup — proptest's shrinking will not reliably find these,
            // and they are not the property under test.
            if let (Ok(alice_shared), Ok(bob_shared)) =
                (alice.agree(&bob_pub), bob.agree(&alice_pub))
            {
                prop_assert_eq!(alice_shared.expose_secret(), bob_shared.expose_secret());
            }
        }

        /// Property: agree-with-zero-pk is consistently non-contributory.
        #[test]
        fn prop_zero_pk_always_non_contributory(seed in any::<[u8; SECRET_KEY_LEN]>()) {
            let sk = StaticKey::from_seed(&Zeroizing::new(seed));
            let zero_pk = PublicKey::from_bytes([0u8; PUBLIC_KEY_LEN]);
            let result = sk.agree(&zero_pk);
            prop_assert!(matches!(result, Err(AgreeError::NonContributory)));
        }

        /// Property: an `EphemeralKey` and a `StaticKey` derive the same
        /// shared secret when they perform mutual agreement.
        #[test]
        fn prop_ephemeral_static_interop(static_seed in any::<[u8; SECRET_KEY_LEN]>()) {
            let mut rng = OsRng;
            let ephemeral = EphemeralKey::generate(&mut rng);
            let static_key = StaticKey::from_seed(&Zeroizing::new(static_seed));

            let ephemeral_pub = ephemeral.public_key();
            let static_pub = static_key.public_key();

            let from_ephemeral = ephemeral.agree(&static_pub);
            let from_static = static_key.agree(&ephemeral_pub);

            if let (Ok(a), Ok(b)) = (from_ephemeral, from_static) {
                prop_assert_eq!(a.expose_secret(), b.expose_secret());
            }
        }
    }
}
