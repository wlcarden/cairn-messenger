// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Double-ratchet derivative per D0026 §3.
//!
//! ## v1 skeleton status
//!
//! The full double-ratchet implementation tracks the SimpleX
//! upstream double-ratchet derivative spec; the implementation
//! cycle lands the body with cross-validation against the
//! SimpleX upstream test vectors per D0026 §1.4 + §12 step 4.
//!
//! The v1 skeleton provides:
//!
//! - [`RatchetState`] type (struct exists; private fields opaque
//!   until the body lands).
//! - [`RatchetState::placeholder`] constructor producing an empty
//!   state for testing-the-type-tag (so storage round-trip work
//!   per D0026 §3.2 can sequence ahead of the ratchet body).
//! - [`RatchetState::encrypt`] + [`RatchetState::decrypt`] stubs
//!   returning [`SimplexAdapterError::NetworkUnreached`] — same
//!   stub-pattern the rest of the workspace's network-bound
//!   surfaces follow.
//!
//! When the body lands, the type gains:
//!
//! - Root key + sending chain key + receiving chain key + header
//!   keys, all under `SecretBox`/`Zeroizing` per D0018 §1.6.
//! - `encrypt(plaintext, &mut self)` advancing the sending chain.
//! - `decrypt(ciphertext, &mut self)` advancing the receiving chain.
//! - X3DH initialization per
//!   [`RatchetState::initialize`].
//! - Canonical-CBOR serialization for storage per D0026 §3.2.

use zeroize::Zeroize;

use crate::error::SimplexAdapterError;

/// Per-conversation double-ratchet state per D0026 §3.1.
///
/// In v1 skeleton this type has private fields that hold a
/// zeroized empty-state placeholder; the implementation cycle
/// replaces them with the SimpleX upstream double-ratchet derivative
/// fields per D0026 §3.1.
///
/// The type is `Zeroize`-aware: when dropped, any future fields
/// holding key material per D0018 §1.6 are wiped.
#[derive(Debug, Default, Zeroize)]
#[zeroize(drop)]
pub struct RatchetState {
    /// Private skeleton placeholder. The implementation cycle
    /// replaces this with the root key / chain keys / header keys
    /// per the SimpleX upstream spec.
    ///
    /// Named with a `skeleton_` prefix (not `_`-prefixed) so clippy
    /// does not flag the binding as intentionally-unused — the
    /// field IS used by the `Zeroize` derive's drop path even at
    /// skeleton scope.
    skeleton_placeholder: [u8; 1],
}

impl RatchetState {
    /// Construct a placeholder ratchet state for testing the type
    /// tag. v1 skeleton only; the real constructor is
    /// [`RatchetState::initialize`] which lands with the body.
    #[must_use]
    pub const fn placeholder() -> Self {
        Self {
            skeleton_placeholder: [0],
        }
    }

    /// Initialize a fresh ratchet via X3DH key agreement per the
    /// SimpleX upstream spec.
    ///
    /// v1 skeleton: returns `Err(NetworkUnreached)` — initialization
    /// requires the X3DH inputs which themselves require the SMP
    /// session-establishment surface that hasn't landed yet.
    ///
    /// # Errors
    ///
    /// - [`SimplexAdapterError::NetworkUnreached`] (skeleton only;
    ///   replaced by the X3DH-failure variant set once the body
    ///   lands).
    #[allow(
        clippy::missing_const_for_fn,
        reason = "stub; the real body will perform X3DH computation"
    )]
    pub fn initialize() -> Result<Self, SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }

    /// Encrypt a plaintext payload through the sending chain per
    /// the double-ratchet derivative spec.
    ///
    /// v1 skeleton: returns `Err(NetworkUnreached)`.
    ///
    /// # Errors
    ///
    /// - [`SimplexAdapterError::NetworkUnreached`] (skeleton only;
    ///   replaced by the encrypt-path failure variants once the
    ///   body lands).
    #[allow(
        clippy::missing_const_for_fn,
        clippy::needless_pass_by_ref_mut,
        reason = "stub; the real body mutates the ratchet state"
    )]
    pub fn encrypt(&mut self, _plaintext: &[u8]) -> Result<Vec<u8>, SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }

    /// Decrypt a ciphertext through the receiving chain per the
    /// double-ratchet derivative spec.
    ///
    /// v1 skeleton: returns `Err(NetworkUnreached)`.
    ///
    /// # Errors
    ///
    /// - [`SimplexAdapterError::NetworkUnreached`] (skeleton only;
    ///   replaced by the decrypt-path failure variants once the
    ///   body lands — including
    ///   [`SimplexAdapterError::RatchetOutOfSync`] when the
    ///   wire ciphertext doesn't match the next-expected message
    ///   number).
    #[allow(
        clippy::missing_const_for_fn,
        clippy::needless_pass_by_ref_mut,
        reason = "stub; the real body mutates the ratchet state"
    )]
    pub fn decrypt(&mut self, _ciphertext: &[u8]) -> Result<Vec<u8>, SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_constructor_succeeds() {
        let _state = RatchetState::placeholder();
    }

    #[test]
    fn placeholder_default_constructor_succeeds() {
        let _state = RatchetState::default();
    }

    #[test]
    fn initialize_returns_network_unreached_in_skeleton() {
        let result = RatchetState::initialize();
        assert!(matches!(result, Err(SimplexAdapterError::NetworkUnreached)));
    }

    #[test]
    fn encrypt_returns_network_unreached_in_skeleton() {
        let mut state = RatchetState::placeholder();
        let result = state.encrypt(b"plaintext");
        assert!(matches!(result, Err(SimplexAdapterError::NetworkUnreached)));
    }

    #[test]
    fn decrypt_returns_network_unreached_in_skeleton() {
        let mut state = RatchetState::placeholder();
        let result = state.decrypt(b"ciphertext");
        assert!(matches!(result, Err(SimplexAdapterError::NetworkUnreached)));
    }
}
