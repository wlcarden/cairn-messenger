// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Identity export surface (D0027 §2 — the `identity` per-domain
//! module).
//!
//! ## StrongBox-only: no software signing handle
//!
//! D0027 §2.2 originally listed an `OpIdentityKeyHandle` wrapping a
//! software `SecretBox<SigningKey>`. That contradicted §2.3 / D0020
//! §3.4, which place the operational-identity signing key in StrongBox
//! (signing flows through [`crate::hardware::HardwareKeySigner`]; Rust
//! never holds the key). The contradiction was resolved in favor of
//! the hardware-binding commitment (D0027 §2.2 revision 2026-06-01):
//! **there is no software op-identity signing handle at the FFI
//! boundary.** Op-identity signatures are produced in StrongBox via the
//! hardware callback.
//!
//! With no secret to wrap, this module is pure verify/decode over
//! PUBLIC credentials. The capability token is a public authorization
//! credential (it names which device a given operational identity
//! authorizes, for which capabilities, until when); it carries no
//! secret, so its metadata crosses by value as a `uniffi::Record`
//! rather than behind an opaque handle.
//!
//! ## Verify-then-decode
//!
//! [`identity_verify_capability_token`] verifies the token's signature
//! against the expected issuer BEFORE returning any field — the same
//! discipline as the trust-graph export: Kotlin never receives
//! unverified token data it might treat as authoritative. Errors
//! flatten to [`CairnFfiError`] via the facade `From<IdentityError>`
//! mapping (D0027 §3); no source `Display` string crosses.

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, VerifyingKey};
use cairn_identity::SignedCapabilityToken;

use crate::error::CairnFfiError;

/// Public metadata of a verified capability token (D0027 §2.2).
///
/// Every field is PUBLIC: the issuer (operational-identity) pubkey, the
/// subject device pubkey, the authorized capability scope, and the
/// expiry. The token's opaque `signature_chain_to_master` is internal
/// plumbing (verified by higher layers) and is deliberately NOT
/// surfaced. Becomes a `uniffi::Record` under the feature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct CapabilityTokenRecord {
    /// The operational-identity Ed25519 public key (32 bytes) that
    /// issued + signed this token.
    pub issuer: Vec<u8>,
    /// The device Ed25519 public key (32 bytes) the token authorizes.
    pub subject_device: Vec<u8>,
    /// The capability strings the subject device is authorized to
    /// perform (e.g. `trust-graph:attest`).
    pub scope: Vec<String>,
    /// Unix-seconds at which the token expires. Freshness-against-now
    /// is the caller's policy decision; this is the raw value.
    pub expiry_unix_seconds: u64,
}

/// Verify a capability token against the expected issuer, returning its
/// public metadata (D0027 §2.2).
///
/// `token` is the encoded `SignedCapabilityToken`; `expected_issuer` is
/// the 32-byte operational-identity pubkey the token must verify
/// against. The signature is checked BEFORE any field is returned — a
/// failed verification yields an error, never a partially-trusted
/// record.
///
/// # Errors
///
/// - [`CairnFfiError::MalformedData`] if `expected_issuer` is not
///   exactly [`PUBLIC_KEY_LEN`] bytes / not a valid Ed25519 key, or the
///   token bytes are not well-formed.
/// - [`CairnFfiError::SignatureVerifyFailed`] if the token signature
///   does not verify against `expected_issuer`, or the token's issuer
///   does not match (the sub-reason is collapsed per D0027 §3.2).
#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
)]
pub fn identity_verify_capability_token(
    token: Vec<u8>,
    expected_issuer: Vec<u8>,
) -> Result<CapabilityTokenRecord, CairnFfiError> {
    let issuer_bytes: [u8; PUBLIC_KEY_LEN] = expected_issuer
        .as_slice()
        .try_into()
        .map_err(|_| CairnFfiError::MalformedData)?;
    let expected =
        VerifyingKey::from_bytes(&issuer_bytes).map_err(|_| CairnFfiError::MalformedData)?;

    // Verify-then-decode: from_bytes checks the signature against the
    // expected issuer; an IdentityError flattens via the facade.
    let signed = SignedCapabilityToken::from_bytes(&token, &expected)?;
    let token = signed.token();

    Ok(CapabilityTokenRecord {
        issuer: token.issuer.to_bytes().to_vec(),
        subject_device: token.subject.to_bytes().to_vec(),
        scope: token.scope.clone(),
        expiry_unix_seconds: token.expiry_unix_seconds,
    })
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
    use cairn_crypto::ed25519::SigningKey;
    use cairn_identity::{CapabilityToken, capabilities};
    use rand_core::OsRng;

    /// Build `(expected_issuer_bytes, token_bytes, subject_device_bytes)`
    /// for a token authorizing `device` under the attest scope.
    fn signed_token() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let issuer_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);

        let token = CapabilityToken::new(
            issuer_sk.verifying_key(),
            device_sk.verifying_key(),
            vec![capabilities::TRUST_GRAPH_ATTEST.to_string()],
            2_000_000_000,
            vec![],
        );
        let token_bytes = token.sign(&issuer_sk).unwrap().encode(false).unwrap();

        (
            issuer_sk.verifying_key().to_bytes().to_vec(),
            token_bytes,
            device_sk.verifying_key().to_bytes().to_vec(),
        )
    }

    #[test]
    fn verify_returns_public_metadata() {
        let (issuer, token, device) = signed_token();
        let record = identity_verify_capability_token(token, issuer.clone()).unwrap();
        assert_eq!(record.issuer, issuer);
        assert_eq!(record.subject_device, device);
        assert_eq!(
            record.scope,
            vec![capabilities::TRUST_GRAPH_ATTEST.to_string()]
        );
        assert_eq!(record.expiry_unix_seconds, 2_000_000_000);
    }

    #[test]
    fn wrong_issuer_maps_to_signature_failure() {
        // Verify the token against a DIFFERENT issuer pubkey than the
        // one that signed it → IssuerMismatch → SignatureVerifyFailed.
        let (_issuer, token, _device) = signed_token();
        let mut rng = OsRng;
        let other_issuer = SigningKey::generate(&mut rng)
            .verifying_key()
            .to_bytes()
            .to_vec();
        let err = identity_verify_capability_token(token, other_issuer).unwrap_err();
        assert_eq!(err, CairnFfiError::SignatureVerifyFailed);
    }

    #[test]
    fn wrong_length_issuer_maps_to_malformed_data() {
        let (_issuer, token, _device) = signed_token();
        let err = identity_verify_capability_token(token, vec![0u8; 31]).unwrap_err();
        assert_eq!(err, CairnFfiError::MalformedData);
    }

    #[test]
    fn malformed_token_bytes_map_to_malformed_data() {
        let (issuer, _token, _device) = signed_token();
        let err = identity_verify_capability_token(vec![0xFFu8; 8], issuer).unwrap_err();
        assert_eq!(err, CairnFfiError::MalformedData);
    }

    #[test]
    fn tampered_signature_maps_to_signature_failure() {
        // Flip the last byte (signature tail); verification fails.
        let (issuer, mut token, _device) = signed_token();
        let last = token.len() - 1;
        token[last] ^= 0x01;
        let err = identity_verify_capability_token(token, issuer).unwrap_err();
        // A tamper may surface as a sig failure or a decode fault
        // depending on where it lands; both are honest non-success
        // flattenings. Assert it is one of those, never Ok.
        assert!(
            matches!(
                err,
                CairnFfiError::SignatureVerifyFailed | CairnFfiError::MalformedData
            ),
            "tampered token must not verify; got {err:?}"
        );
    }
}
