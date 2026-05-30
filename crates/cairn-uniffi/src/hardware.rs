// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Hardware-element mediation per D0027 §2.3 (re-stating, not
//! re-deciding, D0020 §3.4).
//!
//! Rust cannot directly access the Android KeyStore / StrongBox — the
//! KeyStore API is Binder-based Java. Per D0020 §3.4, both the
//! device-key and the operational-identity signing keys live in
//! StrongBox; Rust requests signing / key-generation / attestation-
//! chain operations via a callback the Kotlin shell implements. The
//! signing keys never leave hardware; only the resulting signature /
//! public-key / certificate-chain BYTES return to Rust.
//!
//! ## v1 skeleton status
//!
//! [`HardwareKeySigner`] is declared here as a plain Rust trait. The
//! `#[uniffi::export(callback_interface)]` attribute (D0020 §3.4)
//! lands behind the `uniffi-bindings` feature per D0027 §8 — the
//! trait shape + the spec types are plain Rust + reviewable now; the
//! UniFFI wiring + the Kotlin `AndroidKeyStoreSigner` impl land with
//! the binding-generation body.
//!
//! ## What does NOT cross
//!
//! Note the asymmetry that makes this safe: the trait's methods take
//! a `key_alias: String` (an opaque KeyStore handle name, NOT key
//! material) + a `payload: Vec<u8>` (the bytes to sign — public), and
//! return signature / pubkey / cert bytes (all public). No private
//! key material is ever a parameter or a return value. The
//! `NeverExport` gate (D0027 §4 / [`crate::never_export_gate`])
//! enforces that no secret type appears in this surface.

use crate::error::CairnFfiError;

/// Spec for generating a hardware-backed key per D0020 §3.4.
///
/// Plain-data record (`uniffi::Record` once bindings land). Carries
/// no secret material — only the generation parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyGenSpec {
    /// Whether the key requires user authentication (biometric /
    /// device-credential) before each use.
    pub require_auth: bool,
    /// The attestation challenge bytes to embed in the generated
    /// key's attestation certificate (public; a freshness nonce).
    pub attestation_challenge: Vec<u8>,
}

/// A public key returned from hardware key generation per D0020 §3.4.
///
/// The PUBLIC key only — the private key never leaves StrongBox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwarePublicKey {
    /// Encoded public-key bytes (e.g., the SubjectPublicKeyInfo DER).
    pub encoded: Vec<u8>,
}

/// One certificate in an attestation chain per D0020 §3.4 + §3.8.
///
/// The chain is verified in Rust (`cairn-identity`) against Google's
/// attestation root + the GrapheneOS verified-boot fingerprint per
/// D0020 §3.9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationCertificate {
    /// Encoded X.509 certificate bytes (DER).
    pub encoded: Vec<u8>,
}

/// The hardware-element mediation callback per D0020 §3.4.
///
/// Implemented by the Kotlin shell (`AndroidKeyStoreSigner` per
/// D0020 §3.4) against the Android KeyStore. Rust calls these methods;
/// the signing keys stay in StrongBox; only public bytes return.
///
/// When the `uniffi-bindings` feature lands, this trait gains
/// `#[uniffi::export(callback_interface)]` per D0020 §3.4. At the
/// skeleton stage it is a plain Rust trait so the shape is reviewable
/// + a mock impl can drive tests of the consuming logic.
///
/// `Send + Sync` because the callback may be invoked from any thread
/// driving an async export per D0027 §5.
pub trait HardwareKeySigner: Send + Sync {
    /// Sign `payload` with the StrongBox key named `key_alias`. The
    /// private key never leaves hardware; the signature bytes return.
    ///
    /// # Errors
    ///
    /// Returns [`CairnFfiError`] if the KeyStore operation fails
    /// (key not found, user-auth declined, hardware error). The
    /// Kotlin side maps the Android exception to the facade variant;
    /// no Android exception detail crosses per the no-error-oracle
    /// discipline (D0027 §3).
    fn sign(&self, key_alias: String, payload: Vec<u8>) -> Result<Vec<u8>, CairnFfiError>;

    /// Generate a hardware-backed key named `key_alias` per `spec`.
    /// Returns the PUBLIC key; the private key stays in StrongBox.
    ///
    /// # Errors
    ///
    /// Returns [`CairnFfiError`] if generation fails (StrongBox
    /// unavailable, alias collision, unsupported spec).
    fn generate_key(
        &self,
        key_alias: String,
        spec: KeyGenSpec,
    ) -> Result<HardwarePublicKey, CairnFfiError>;

    /// Retrieve the attestation certificate chain for `key_alias`
    /// per D0020 §3.4. Verified in Rust against the pinned roots per
    /// D0020 §3.8-§3.9.
    ///
    /// # Errors
    ///
    /// Returns [`CairnFfiError`] if the chain cannot be retrieved
    /// (key not found, no attestation extension).
    fn attestation_chain(
        &self,
        key_alias: String,
    ) -> Result<Vec<AttestationCertificate>, CairnFfiError>;
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A mock `HardwareKeySigner` standing in for the Kotlin
    /// `AndroidKeyStoreSigner` — confirms the trait is object-safe +
    /// implementable, and lets the consuming logic be tested without
    /// a real StrongBox once that logic lands.
    struct MockSigner;

    impl HardwareKeySigner for MockSigner {
        fn sign(&self, _key_alias: String, payload: Vec<u8>) -> Result<Vec<u8>, CairnFfiError> {
            // Echo a deterministic "signature" of fixed length so the
            // shape is exercised; the real impl signs in StrongBox.
            Ok(payload.iter().take(64).copied().collect())
        }

        fn generate_key(
            &self,
            _key_alias: String,
            _spec: KeyGenSpec,
        ) -> Result<HardwarePublicKey, CairnFfiError> {
            Ok(HardwarePublicKey {
                encoded: vec![0xAB; 32],
            })
        }

        fn attestation_chain(
            &self,
            _key_alias: String,
        ) -> Result<Vec<AttestationCertificate>, CairnFfiError> {
            Ok(vec![AttestationCertificate {
                encoded: vec![0xCD; 16],
            }])
        }
    }

    #[test]
    fn trait_is_object_safe() {
        // Box<dyn HardwareKeySigner> is the shape D0020 §3.4's
        // build_capability_token consumes; confirm object-safety.
        let signer: Box<dyn HardwareKeySigner> = Box::new(MockSigner);
        let sig = signer
            .sign("device-key".to_string(), vec![1, 2, 3])
            .unwrap();
        assert_eq!(sig, vec![1, 2, 3]);
    }

    #[test]
    fn generate_key_returns_public_key_only() {
        let signer = MockSigner;
        let spec = KeyGenSpec {
            require_auth: true,
            attestation_challenge: vec![0x01, 0x02],
        };
        let pk = signer.generate_key("op-key".to_string(), spec).unwrap();
        assert_eq!(pk.encoded.len(), 32);
    }

    #[test]
    fn attestation_chain_returns_certificates() {
        let signer = MockSigner;
        let chain = signer.attestation_chain("device-key".to_string()).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].encoded.len(), 16);
    }
}
