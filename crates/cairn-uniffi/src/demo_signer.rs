// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Software Ed25519 signer for the Android chat DEMO identity.
//!
//! The demo's device key is a SOFTWARE Ed25519 key, not a StrongBox/TEE key.
//! AndroidKeyStore's Ed25519 encodes public keys + signatures in its own
//! X.509/DER conventions that do NOT match the raw 32-byte public key + raw
//! 64-byte signature `cairn-envelope`'s `ed25519-dalek` verifier requires — the
//! on-device two-party finding (D0026 §12) was that the COSE_Sign1 self-verify
//! AND the peer's `VerifyingKey::from_bytes` both rejected the AndroidKeyStore
//! bytes. Signing here with the SAME `cairn-crypto` Ed25519 the verifier uses
//! makes the signature byte-compatible by construction.
//!
//! This is the DEMO path only. The v1 hardened device key signs in StrongBox
//! via the `HardwareKeySigner` callback (D0020 §3.4 / D0028) — that key never
//! crosses the FFI. This software seed does: it is a demo key, minted by the
//! Kotlin shell (`SecureRandom`) and handed in once at construction.

use std::sync::Arc;

use cairn_crypto::ed25519::{SEED_LEN, SigningKey};
use zeroize::Zeroizing;

use crate::CairnFfiError;

/// A software Ed25519 signer over a caller-supplied 32-byte seed, exposing the
/// raw public key + raw 64-byte signatures that `cairn-envelope` verifies.
///
/// The Kotlin demo identity mints the seed and drives [`Self::sign`] from its
/// `HardwareKeySigner` callback; the produced signature is byte-identical to
/// what the Rust verifier expects (same `ed25519-dalek`), so the envelope's
/// self-verify and the peer's signature check both pass.
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct DemoEd25519Signer {
    key: SigningKey,
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
impl DemoEd25519Signer {
    /// Build a signer from a 32-byte Ed25519 seed.
    ///
    /// # Errors
    ///
    /// [`CairnFfiError::MalformedData`] if `seed` is not exactly [`SEED_LEN`]
    /// (32) bytes.
    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI constructors take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub fn from_seed(seed: Vec<u8>) -> Result<Arc<Self>, CairnFfiError> {
        let seed: [u8; SEED_LEN] = seed
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        let key = SigningKey::from_seed(&Zeroizing::new(seed));
        Ok(Arc::new(Self { key }))
    }

    /// The raw 32-byte Ed25519 public key — the demo's operational + device
    /// pubkey (the two coincide for the 1:1 demo).
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }

    /// Raw 64-byte Ed25519 signature over `payload` (the COSE `Sig_structure`
    /// the envelope builder hands to the device signer, D0026 §2.3).
    ///
    /// # Errors
    ///
    /// [`CairnFfiError::MalformedData`] if signing fails (not expected for a
    /// well-formed key + payload).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, CairnFfiError> {
        self.key
            .sign(&payload)
            .map(|sig| sig.to_bytes().to_vec())
            .map_err(|_| CairnFfiError::MalformedData)
    }
}
