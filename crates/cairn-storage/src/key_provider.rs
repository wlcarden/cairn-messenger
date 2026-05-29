// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! The hardware-abstraction-layer surface for cairn-storage per D0022 §4.
//!
//! Per D0020 §3.4 hardware-element operations route through UniFFI's
//! `callback_interface` because Rust cannot directly call Android's
//! KeyStore. [`KeyProvider`] abstracts that mediation; the Android
//! shell implements it via UniFFI; tests use [`testing::InMemoryKeyProvider`].
//!
//! Per D0022 §2.2 the storage layer's DEK derivation is:
//!
//! ```text
//! passphrase
//!     → Argon2id(passphrase, kek_salt, m=64 MiB, t=3, p=1)  ─┐
//!                                                             │ KEK
//! StrongBox-attested key material                ─────────────┤
//!                                                             ▼
//! HKDF-SHA256(KEK ‖ StrongBox material, salt, info=category) → DEK_category
//! ```
//!
//! The KEK derivation is the responsibility of [`KeyProvider::derive_kek`]
//! because Android's Argon2 implementation may live in the Kotlin
//! shell (a Java/Kotlin libargon2 binding) rather than in Rust. Tests
//! use a reduced-parameter Argon2 inline so unit tests stay fast.

use zeroize::Zeroizing;

use crate::{DEK_LEN, KEK_LEN, STRONGBOX_MATERIAL_LEN};

/// Hardware-abstraction-layer trait per D0022 §4.
///
/// Implementations:
///
/// - [`testing::InMemoryKeyProvider`] — for workspace tests.
/// - `cairn-uniffi::AndroidKeyProvider` — for Android shell (future
///   crate per D0018 §8.6).
///
/// The trait is `Send + Sync` because storage operations may run on
/// any thread (within the single-writer discipline of D0022 §1.3).
/// Implementations must ensure thread-safety of their internal state.
pub trait KeyProvider: Send + Sync {
    /// Derive the Key-Encryption Key from the user's passphrase using
    /// Argon2id with the stored salt per D0022 §2.2.
    ///
    /// # Errors
    ///
    /// Returns [`KeyProviderError::ArgonFailed`] if the underlying
    /// Argon2 implementation fails (memory allocation failure,
    /// out-of-range parameters, etc.). Uniform error across causes
    /// per D0018 §1.4 no-error-oracle discipline.
    fn derive_kek(
        &self,
        passphrase: &Zeroizing<Vec<u8>>,
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; KEK_LEN]>, KeyProviderError>;

    /// Return the StrongBox-attested key material to combine with the
    /// KEK per D0022 §2.2.
    ///
    /// On Android this delegates through UniFFI to the Kotlin shell,
    /// which invokes Android KeyStore (the wrapped key is bound to
    /// the device's hardware-backed credential per D0020 §3.4). In
    /// tests this returns a fixed in-memory byte pattern.
    ///
    /// # Errors
    ///
    /// Returns [`KeyProviderError::StrongBoxUnavailable`] if the
    /// hardware element is not available (test environment without
    /// the bound key; Android device that doesn't have StrongBox /
    /// TEE-backing for the relevant capability).
    fn strongbox_material(
        &self,
    ) -> Result<Zeroizing<[u8; STRONGBOX_MATERIAL_LEN]>, KeyProviderError>;

    /// Return the device's current unlock state.
    ///
    /// `cairn-storage` uses this to decide whether to keep DEKs
    /// cached in memory (`UnlockState::Unlocked`) vs. re-derive on
    /// each operation (`UnlockState::Locked`). Tests typically
    /// return `Unlocked` unconditionally.
    fn unlock_state(&self) -> UnlockState;
}

/// Device unlock state per D0022 §4 — the signal cairn-storage uses
/// to decide DEK caching behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnlockState {
    /// Device is unlocked; cached DEKs are usable.
    Unlocked,
    /// Device is locked; cached DEKs must be wiped + re-derived
    /// after the next unlock event.
    Locked,
}

/// Errors surfaced by [`KeyProvider`] implementations.
///
/// `#[non_exhaustive]` per D0018 §4.2.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyProviderError {
    /// Argon2id failed. Uniform across causes per D0018 §1.4.
    #[error("Argon2id key derivation failed")]
    ArgonFailed,
    /// StrongBox-attested key material is not available.
    #[error("StrongBox-attested key material is unavailable")]
    StrongBoxUnavailable,
    /// The KeyProvider's hardware-backed credential was invalidated
    /// (passphrase change, biometric enrollment change, factory
    /// reset of the StrongBox). The caller must trigger the recovery
    /// flow.
    #[error("hardware-backed credential was invalidated")]
    CredentialInvalidated,
}

/// Combine a [`KeyProvider`]-derived KEK + StrongBox material into a
/// per-category Data Encryption Key per D0022 §2.2.
///
/// ```text
/// DEK_category = HKDF-SHA256(
///     IKM  = KEK ‖ StrongBox material,
///     salt = "cairn-v1-storage-kdf",
///     info = category_tag,
/// )
/// ```
///
/// # Errors
///
/// Propagates the underlying HKDF expansion failure
/// (`hkdf::InvalidLength`), unreachable for the fixed 32-byte output
/// length we request.
pub fn derive_category_dek(
    kek: &Zeroizing<[u8; KEK_LEN]>,
    strongbox_material: &Zeroizing<[u8; STRONGBOX_MATERIAL_LEN]>,
    category_tag: &str,
) -> Result<Zeroizing<[u8; DEK_LEN]>, KeyProviderError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut ikm = Zeroizing::new([0u8; KEK_LEN + STRONGBOX_MATERIAL_LEN]);
    // Statically safe: split_at_mut at the KEK_LEN boundary gives
    // two slices whose lengths exactly match the source slices we
    // copy into them (KEK_LEN and STRONGBOX_MATERIAL_LEN).
    let (kek_dest, sb_dest) = ikm.split_at_mut(KEK_LEN);
    kek_dest.copy_from_slice(kek.as_ref());
    sb_dest.copy_from_slice(strongbox_material.as_ref());

    let hkdf = Hkdf::<Sha256>::new(Some(crate::STORAGE_KDF_SALT), ikm.as_ref());
    let mut dek = [0u8; DEK_LEN];
    hkdf.expand(category_tag.as_bytes(), &mut dek)
        // hkdf::InvalidLength is unreachable for our fixed output
        // length (32 bytes < 255 * Sha256::OutputSize = 8160). Map
        // through KeyProviderError for type uniformity.
        .map_err(|_| KeyProviderError::ArgonFailed)?;
    Ok(Zeroizing::new(dek))
}

/// Test-only [`KeyProvider`] implementations.
///
/// `InMemoryKeyProvider` uses Argon2id with reduced parameters so
/// unit tests stay fast (~10 ms per derive vs. ~500 ms for the
/// production parameters). Production storage MUST use the Android
/// shell's `KeyProvider` per D0020 §3.4.
pub mod testing {
    use argon2::{Algorithm, Argon2, Params, Version};
    use zeroize::Zeroizing;

    use super::{KeyProvider, KeyProviderError, UnlockState};
    use crate::{KEK_LEN, STRONGBOX_MATERIAL_LEN};

    /// Fixed StrongBox material for tests — `[0x55; 32]` per
    /// D0022 §4. Production must NOT use this; the Android shell
    /// provides hardware-bound material via UniFFI callback.
    pub const TEST_STRONGBOX_MATERIAL: [u8; STRONGBOX_MATERIAL_LEN] =
        [0x55; STRONGBOX_MATERIAL_LEN];

    /// In-memory `KeyProvider` for workspace tests.
    ///
    /// Uses Argon2id with reduced parameters (m=1 MiB, t=1, p=1) so
    /// unit tests stay sub-100ms per derive. Production parameters
    /// (m=64 MiB, t=3, p=1) are documented in D0022 §2.2 and
    /// enforced by the Android implementation.
    #[derive(Debug, Default)]
    pub struct InMemoryKeyProvider {
        /// Whether the simulated device is "unlocked" (most tests
        /// want this true; locked-state tests construct via
        /// `InMemoryKeyProvider::locked()`).
        unlocked: bool,
    }

    impl InMemoryKeyProvider {
        /// Construct an `InMemoryKeyProvider` simulating an unlocked
        /// device.
        #[must_use]
        pub const fn new() -> Self {
            Self { unlocked: true }
        }

        /// Construct an `InMemoryKeyProvider` simulating a locked
        /// device.
        #[must_use]
        pub const fn locked() -> Self {
            Self { unlocked: false }
        }
    }

    impl KeyProvider for InMemoryKeyProvider {
        fn derive_kek(
            &self,
            passphrase: &Zeroizing<Vec<u8>>,
            salt: &[u8],
        ) -> Result<Zeroizing<[u8; KEK_LEN]>, KeyProviderError> {
            // Reduced parameters: m=1024 KiB, t=1, p=1.
            let params = Params::new(1024, 1, 1, Some(KEK_LEN))
                .map_err(|_| KeyProviderError::ArgonFailed)?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut kek = [0u8; KEK_LEN];
            argon
                .hash_password_into(passphrase.as_slice(), salt, &mut kek)
                .map_err(|_| KeyProviderError::ArgonFailed)?;
            Ok(Zeroizing::new(kek))
        }

        fn strongbox_material(
            &self,
        ) -> Result<Zeroizing<[u8; STRONGBOX_MATERIAL_LEN]>, KeyProviderError> {
            Ok(Zeroizing::new(TEST_STRONGBOX_MATERIAL))
        }

        fn unlock_state(&self) -> UnlockState {
            if self.unlocked {
                UnlockState::Unlocked
            } else {
                UnlockState::Locked
            }
        }
    }

    #[cfg(test)]
    #[allow(clippy::indexing_slicing, clippy::panic)]
    mod tests {
        use super::*;

        #[test]
        fn derive_kek_is_deterministic_for_fixed_inputs() {
            let provider = InMemoryKeyProvider::new();
            let passphrase = Zeroizing::new(b"correct horse battery staple".to_vec());
            let salt = b"test-salt-16-byt";
            let kek_a = provider.derive_kek(&passphrase, salt).unwrap();
            let kek_b = provider.derive_kek(&passphrase, salt).unwrap();
            assert_eq!(kek_a.as_ref(), kek_b.as_ref());
        }

        #[test]
        fn derive_kek_differs_across_salts() {
            let provider = InMemoryKeyProvider::new();
            let passphrase = Zeroizing::new(b"correct horse battery staple".to_vec());
            let kek_a = provider
                .derive_kek(&passphrase, b"salt-A-pattern16")
                .unwrap();
            let kek_b = provider
                .derive_kek(&passphrase, b"salt-B-pattern16")
                .unwrap();
            assert_ne!(kek_a.as_ref(), kek_b.as_ref());
        }

        #[test]
        fn derive_kek_differs_across_passphrases() {
            let provider = InMemoryKeyProvider::new();
            let salt = b"test-salt-16-byt";
            let kek_a = provider
                .derive_kek(&Zeroizing::new(b"passphrase A".to_vec()), salt)
                .unwrap();
            let kek_b = provider
                .derive_kek(&Zeroizing::new(b"passphrase B".to_vec()), salt)
                .unwrap();
            assert_ne!(kek_a.as_ref(), kek_b.as_ref());
        }

        #[test]
        fn strongbox_material_is_fixed_for_tests() {
            let provider = InMemoryKeyProvider::new();
            let material = provider.strongbox_material().unwrap();
            assert_eq!(material.as_ref(), &TEST_STRONGBOX_MATERIAL);
        }

        #[test]
        fn unlock_state_reflects_constructor() {
            assert_eq!(
                InMemoryKeyProvider::new().unlock_state(),
                UnlockState::Unlocked
            );
            assert_eq!(
                InMemoryKeyProvider::locked().unlock_state(),
                UnlockState::Locked
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::categories;
    use testing::InMemoryKeyProvider;

    #[test]
    fn derive_category_dek_is_deterministic_for_fixed_inputs() {
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"correct horse battery staple".to_vec());
        let kek = provider
            .derive_kek(&passphrase, b"test-salt-16-byt")
            .unwrap();
        let sb = provider.strongbox_material().unwrap();
        let dek_a = derive_category_dek(&kek, &sb, categories::IDENTITY).unwrap();
        let dek_b = derive_category_dek(&kek, &sb, categories::IDENTITY).unwrap();
        assert_eq!(dek_a.as_ref(), dek_b.as_ref());
    }

    #[test]
    fn derive_category_dek_differs_across_categories() {
        let provider = InMemoryKeyProvider::new();
        let kek = provider
            .derive_kek(
                &Zeroizing::new(b"correct horse battery staple".to_vec()),
                b"test-salt-16-byt",
            )
            .unwrap();
        let sb = provider.strongbox_material().unwrap();
        let identity_dek = derive_category_dek(&kek, &sb, categories::IDENTITY).unwrap();
        let messages_dek = derive_category_dek(&kek, &sb, categories::MESSAGES).unwrap();
        assert_ne!(identity_dek.as_ref(), messages_dek.as_ref());
    }

    #[test]
    fn derive_category_dek_differs_across_strongbox_material() {
        // Simulate two different devices: same passphrase, different
        // StrongBox material. Per D0022 §2.2 the DEKs must differ —
        // this is the device-binding property.
        let provider = InMemoryKeyProvider::new();
        let kek = provider
            .derive_kek(
                &Zeroizing::new(b"correct horse battery staple".to_vec()),
                b"test-salt-16-byt",
            )
            .unwrap();
        let sb_a = Zeroizing::new([0x11u8; STRONGBOX_MATERIAL_LEN]);
        let sb_b = Zeroizing::new([0x22u8; STRONGBOX_MATERIAL_LEN]);
        let dek_a = derive_category_dek(&kek, &sb_a, categories::IDENTITY).unwrap();
        let dek_b = derive_category_dek(&kek, &sb_b, categories::IDENTITY).unwrap();
        assert_ne!(dek_a.as_ref(), dek_b.as_ref());
    }

    #[test]
    fn derive_category_dek_differs_across_keks() {
        // Simulate two different passphrases: same StrongBox material,
        // different KEK. The DEKs must differ — this is the
        // passphrase-binding property.
        let provider = InMemoryKeyProvider::new();
        let kek_a = provider
            .derive_kek(
                &Zeroizing::new(b"passphrase A".to_vec()),
                b"test-salt-16-byt",
            )
            .unwrap();
        let kek_b = provider
            .derive_kek(
                &Zeroizing::new(b"passphrase B".to_vec()),
                b"test-salt-16-byt",
            )
            .unwrap();
        let sb = provider.strongbox_material().unwrap();
        let dek_a = derive_category_dek(&kek_a, &sb, categories::IDENTITY).unwrap();
        let dek_b = derive_category_dek(&kek_b, &sb, categories::IDENTITY).unwrap();
        assert_ne!(dek_a.as_ref(), dek_b.as_ref());
    }
}
