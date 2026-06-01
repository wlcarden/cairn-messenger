// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Storage export surface (D0027 §2 — the `storage` per-domain module).
//!
//! The first opaque `uniffi::Object`: [`StorageHandle`] wraps
//! `cairn_storage::Storage` (already `Send + Sync` — it holds a
//! `Mutex<Connection>`) and exposes the encrypted category
//! put/get/delete surface across the FFI.
//!
//! ## At-rest key material across the FFI (the security boundary)
//!
//! D0027 §2.4 + §4.1: the storage KEK + per-category DEKs are
//! `NeverExport` — they MUST NOT cross the boundary. But
//! `cairn_storage::Storage::open` needs a `KeyProvider` whose
//! `derive_kek` *produces* the KEK. key_provider.rs (D0022 §4)
//! originally assumed `derive_kek` (and thus Argon2id) runs in the
//! Kotlin shell — which would lower the KEK to Rust across the FFI,
//! contradicting §2.4/§4.1.
//!
//! **Resolution (2026-06-01): the KEK derivation runs in Rust.**
//! The crate-internal `FfiKeyProvider` performs Argon2id (D0022 §2.2
//! production parameters) inside this crate; the Kotlin shell implements only the
//! narrow [`StrongBoxKeyMaterial`] callback (the hardware-bound
//! material + unlock state). The passphrase + StrongBox material cross
//! **in** as bytes (the sensitive-input pattern, wrapped `Zeroizing`
//! Rust-side); the KEK + DEKs are born, used, and dropped entirely
//! Rust-side — they never cross **out**. (This overrides D0022 §4's
//! "Argon2 may live in the Kotlin shell" in favor of the no-secret-
//! crossing discipline.)
//!
//! Decrypted record plaintext DOES cross out — that is the application
//! data the shell renders; the `NeverExport` boundary protects keys,
//! not the app's own decrypted content.

use std::path::Path;
use std::sync::Arc;

use argon2::{Algorithm, Argon2, Params, Version};
use cairn_storage::key_provider::{KeyProvider, KeyProviderError, UnlockState};
use cairn_storage::{ALL_CATEGORIES, KEK_LEN, STRONGBOX_MATERIAL_LEN, Storage, StorageError};
use zeroize::Zeroizing;

use crate::error::CairnFfiError;

/// The hardware-element key-material callback for storage unlock
/// (D0027 §2.2 / D0020 §3.4).
///
/// Implemented by the Kotlin shell. It supplies ONLY the StrongBox-
/// attested key material + the device unlock state — NOT the KEK (the
/// KEK is derived in Rust per the module-level note). The returned
/// material is hardware-bound key material: sensitive, crossing INTO
/// Rust where it is immediately wrapped in `Zeroizing`.
#[cfg_attr(feature = "uniffi-bindings", uniffi::export(callback_interface))]
pub trait StrongBoxKeyMaterial: Send + Sync {
    /// Return the StrongBox-attested key material
    /// ([`STRONGBOX_MATERIAL_LEN`] bytes) bound to the device's
    /// hardware-backed credential (D0022 §2.2).
    ///
    /// # Errors
    ///
    /// Returns [`CairnFfiError`] if the hardware element is unavailable
    /// or the credential was invalidated (the Kotlin side maps the
    /// Android exception; no detail crosses per D0027 §3).
    fn strongbox_material(&self) -> Result<Vec<u8>, CairnFfiError>;

    /// Whether the device is currently unlocked (cached DEKs usable).
    fn is_unlocked(&self) -> bool;
}

/// Rust-side [`cairn_storage::key_provider::KeyProvider`] adapter that
/// keeps the KEK Rust-side.
///
/// `derive_kek` runs Argon2id here (NOT in Kotlin); `strongbox_material`
/// + `unlock_state` delegate to the [`StrongBoxKeyMaterial`] callback.
struct FfiKeyProvider {
    callback: Box<dyn StrongBoxKeyMaterial>,
}

impl KeyProvider for FfiKeyProvider {
    fn derive_kek(
        &self,
        passphrase: &Zeroizing<Vec<u8>>,
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; KEK_LEN]>, KeyProviderError> {
        // D0022 §2.2 production parameters: Argon2id, m = 64 MiB
        // (65536 KiB), t = 3, p = 1, output = KEK_LEN.
        let params =
            Params::new(65536, 3, 1, Some(KEK_LEN)).map_err(|_| KeyProviderError::ArgonFailed)?;
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
        let bytes = self
            .callback
            .strongbox_material()
            .map_err(|_| KeyProviderError::StrongBoxUnavailable)?;
        let arr: [u8; STRONGBOX_MATERIAL_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeyProviderError::StrongBoxUnavailable)?;
        Ok(Zeroizing::new(arr))
    }

    fn unlock_state(&self) -> UnlockState {
        if self.callback.is_unlocked() {
            UnlockState::Unlocked
        } else {
            UnlockState::Locked
        }
    }
}

/// Validate an incoming category string against the known category
/// tags, returning the matching `&'static str` the storage layer
/// requires.
fn validate_category(category: &str) -> Result<&'static str, CairnFfiError> {
    ALL_CATEGORIES
        .iter()
        .copied()
        .find(|&known| known == category)
        .ok_or(CairnFfiError::MalformedData)
}

/// An opaque handle to the unlocked encrypted record store (D0027
/// §2.2). Holds the `cairn_storage::Storage` (an `Arc`-shared
/// `uniffi::Object`); the DEKs live inside it, Rust-side only.
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct StorageHandle {
    storage: Storage,
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
impl StorageHandle {
    /// Open (or create) the encrypted store at `path`, deriving the
    /// per-category DEKs from `passphrase` + the callback's StrongBox
    /// material (D0022 §2.2).
    ///
    /// The passphrase crosses in as bytes and is wrapped `Zeroizing`
    /// immediately; the KEK is derived + dropped Rust-side.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::StorageFailure`] if the database cannot be
    ///   opened or the key material cannot be derived (StrongBox
    ///   unavailable, Argon2 failure).
    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI constructors take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub fn open(
        path: String,
        passphrase: Vec<u8>,
        key_material: Box<dyn StrongBoxKeyMaterial>,
    ) -> Result<Arc<Self>, CairnFfiError> {
        let provider = FfiKeyProvider {
            callback: key_material,
        };
        let passphrase = Zeroizing::new(passphrase);
        let storage =
            Storage::open(Path::new(&path), &provider, &passphrase).map_err(CairnFfiError::from)?;
        Ok(Arc::new(Self { storage }))
    }

    /// Insert or overwrite an encrypted record in `category`.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `category` is not a known
    ///   category tag.
    /// - [`CairnFfiError::StorageFailure`] for an underlying SQLite or
    ///   encryption failure.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub fn put(
        &self,
        category: String,
        record_id: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), CairnFfiError> {
        let category = validate_category(&category)?;
        self.storage
            .put(category, &record_id, &payload)
            .map_err(CairnFfiError::from)
    }

    /// Fetch + decrypt a record, returning its plaintext, or `None` if
    /// no record exists for `(category, record_id)`.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `category` is unknown.
    /// - [`CairnFfiError::StorageDecryptFailed`] if the record cannot
    ///   be decrypted (wrong passphrase / corrupted ciphertext).
    /// - [`CairnFfiError::StorageFailure`] for other SQLite failures.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub fn get(
        &self,
        category: String,
        record_id: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, CairnFfiError> {
        let category = validate_category(&category)?;
        match self.storage.get(category, &record_id) {
            Ok(plaintext) => Ok(Some(plaintext.to_vec())),
            Err(StorageError::RecordNotFound { .. }) => Ok(None),
            Err(e) => Err(CairnFfiError::from(e)),
        }
    }

    /// Delete a record. Returns `true` if a record was removed,
    /// `false` if none existed.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `category` is unknown.
    /// - [`CairnFfiError::StorageFailure`] for an underlying SQLite
    ///   failure.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub fn delete(&self, category: String, record_id: Vec<u8>) -> Result<bool, CairnFfiError> {
        let category = validate_category(&category)?;
        self.storage
            .delete(category, &record_id)
            .map_err(CairnFfiError::from)
    }
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
    use cairn_storage::categories;

    /// Mock StrongBox callback returning the fixed test material (the
    /// same `[0x55; 32]` cairn-storage's test provider uses).
    struct MockKeyMaterial;
    impl StrongBoxKeyMaterial for MockKeyMaterial {
        fn strongbox_material(&self) -> Result<Vec<u8>, CairnFfiError> {
            Ok(vec![0x55u8; STRONGBOX_MATERIAL_LEN])
        }
        fn is_unlocked(&self) -> bool {
            true
        }
    }

    /// Open an in-memory store via the real FfiKeyProvider (production
    /// Argon2id). One open per test — keep the count low (Argon2 at
    /// 64 MiB is ~0.5s).
    fn open_in_memory_handle() -> StorageHandle {
        let provider = FfiKeyProvider {
            callback: Box::new(MockKeyMaterial),
        };
        let passphrase = Zeroizing::new(b"correct horse battery staple".to_vec());
        let storage = Storage::open_in_memory(&provider, &passphrase).unwrap();
        StorageHandle { storage }
    }

    #[test]
    fn validate_category_accepts_known_rejects_unknown() {
        assert_eq!(
            validate_category(categories::MESSAGES).unwrap(),
            categories::MESSAGES
        );
        assert_eq!(
            validate_category("not-a-real-category"),
            Err(CairnFfiError::MalformedData)
        );
    }

    #[test]
    fn put_get_delete_round_trip() {
        let handle = open_in_memory_handle();
        let record_id = b"record-1".to_vec();
        let payload = b"hello cairn".to_vec();

        // Absent before put.
        assert_eq!(
            handle
                .get(categories::MESSAGES.to_string(), record_id.clone())
                .unwrap(),
            None
        );

        // Put then get returns the plaintext.
        handle
            .put(
                categories::MESSAGES.to_string(),
                record_id.clone(),
                payload.clone(),
            )
            .unwrap();
        assert_eq!(
            handle
                .get(categories::MESSAGES.to_string(), record_id.clone())
                .unwrap(),
            Some(payload)
        );

        // Delete removes it; second delete reports nothing removed.
        assert!(
            handle
                .delete(categories::MESSAGES.to_string(), record_id.clone())
                .unwrap()
        );
        assert!(
            !handle
                .delete(categories::MESSAGES.to_string(), record_id.clone())
                .unwrap()
        );
        assert_eq!(
            handle
                .get(categories::MESSAGES.to_string(), record_id)
                .unwrap(),
            None
        );

        // An unknown category is rejected before touching the DB.
        assert_eq!(
            handle.put("bogus".to_string(), b"x".to_vec(), b"y".to_vec()),
            Err(CairnFfiError::MalformedData)
        );
    }
}
