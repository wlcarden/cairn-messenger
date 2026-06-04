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
use cairn_identity::{
    AttestationError, AttestationFacts, SecurityLevel, SignedCapabilityToken, VerifiedBootState,
    verify_key_attestation,
};

use crate::error::CairnFfiError;
use crate::hardware::AttestationCertificate;

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

/// The advisory result of verifying the device key's Android Key
/// Attestation chain (D0033 §2, Stage 1).
///
/// Per D0033 §4 attestation is a TRUST SIGNAL, not an availability gate:
/// this record NEVER throws at the FFI boundary. A failed or absent
/// attestation yields `attested = false` (the device key is "unattested")
/// and the app keeps running on its software-fallback path. The caller
/// (CairnSession) records the fact + surfaces it on My-Identity
/// ("Device key: hardware-attested ✓ — TEE" vs "unattested").
///
/// Optional fields use empty sentinels (empty string / empty bytes) when
/// `attested = false`, so the Kotlin side reads them only when
/// `attested` is true. Becomes a `uniffi::Record` under the feature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct AttestationResultRecord {
    /// Whether the chain verified to the pinned Google root with all four
    /// D0033 §2 assertions (challenge, hardware security level, generated
    /// origin, sign purpose). The master gate for the UI.
    pub attested: bool,
    /// The attested security level when `attested`: `"TEE"` or
    /// `"StrongBox"`. Empty string otherwise.
    pub security_level: String,
    /// Convenience: `true` iff the security level is StrongBox (the
    /// strongest tier). Always `false` when not attested.
    pub strongbox: bool,
    /// The leaf cert's 32-byte Ed25519 device public key when attested +
    /// the leaf SPKI is Ed25519; empty otherwise. The caller cross-checks
    /// this equals the device key it expects, binding the attestation to
    /// a specific key.
    pub device_public_key: Vec<u8>,
    /// The KeyMint `attestationVersion` (e.g. 400) when attested; 0
    /// otherwise.
    pub attestation_version: u32,
    /// Advisory verified-boot (D0033 §3): whether the bootloader is
    /// locked. `false` when absent/unparsed — surfaced, not asserted, in
    /// Stage 1.
    pub device_locked: bool,
    /// Advisory verified-boot state when present: `"Verified"`,
    /// `"SelfSigned"`, `"Unverified"`, or `"Failed"`. Empty otherwise.
    pub verified_boot_state: String,
    /// A coarse diagnostic tag when `attested = false` (e.g.
    /// `"challenge-mismatch"`, `"software-only"`, `"not-google-rooted"`),
    /// for DEBUG logging + the My-Identity diagnostic line. Empty when
    /// attested. NOT a crypto oracle: this runs on the device's OWN key,
    /// never over a remote/attacker-supplied boundary.
    pub failure: String,
}

impl AttestationResultRecord {
    /// Build the success record from verified [`AttestationFacts`].
    fn attested(facts: &AttestationFacts) -> Self {
        let (level, strongbox) = match facts.security_level {
            SecurityLevel::StrongBox => ("StrongBox".to_string(), true),
            SecurityLevel::TrustedEnvironment => ("TEE".to_string(), false),
            // verify_key_attestation only returns Ok for hardware levels;
            // Software is unreachable here but mapped honestly.
            SecurityLevel::Software => ("Software".to_string(), false),
        };
        let (device_locked, verified_boot_state) = facts.verified_boot.as_ref().map_or_else(
            || (false, String::new()),
            |vb| {
                (
                    vb.device_locked,
                    verified_boot_state_str(vb.verified_boot_state),
                )
            },
        );
        Self {
            attested: true,
            security_level: level,
            strongbox,
            device_public_key: facts.device_public_key.clone().unwrap_or_default(),
            attestation_version: facts.attestation_version,
            device_locked,
            verified_boot_state,
            failure: String::new(),
        }
    }

    /// Build the not-attested record from an [`AttestationError`].
    fn unattested(err: &AttestationError) -> Self {
        Self {
            attested: false,
            security_level: String::new(),
            strongbox: false,
            device_public_key: Vec::new(),
            attestation_version: 0,
            device_locked: false,
            verified_boot_state: String::new(),
            failure: failure_tag(err).to_string(),
        }
    }
}

/// Render a [`VerifiedBootState`] as a stable display string.
fn verified_boot_state_str(state: VerifiedBootState) -> String {
    match state {
        VerifiedBootState::Verified => "Verified",
        VerifiedBootState::SelfSigned => "SelfSigned",
        VerifiedBootState::Unverified => "Unverified",
        VerifiedBootState::Failed => "Failed",
    }
    .to_string()
}

/// Map an [`AttestationError`] to a coarse, stable diagnostic tag. These
/// are deliberately collapsed (no cert index / no payload bytes) — a
/// device-local diagnostic, not a remote crypto oracle.
const fn failure_tag(err: &AttestationError) -> &'static str {
    match err {
        AttestationError::EmptyChain
        | AttestationError::TooFewCertificates { .. }
        | AttestationError::ChainTooLong { .. } => "no-chain",
        AttestationError::MalformedCertificate { .. }
        | AttestationError::MissingKeymintExtension
        | AttestationError::MalformedKeymintExtension => "malformed",
        AttestationError::ValidityWindowFailed { .. } => "expired",
        AttestationError::IssuerSubjectMismatch { .. }
        | AttestationError::LinkSignatureInvalid { .. } => "bad-signature",
        AttestationError::RootNotSelfSigned | AttestationError::RootNotPinned => {
            "not-google-rooted"
        }
        AttestationError::ChallengeMismatch => "challenge-mismatch",
        AttestationError::SecurityLevelTooLow => "software-only",
        AttestationError::OriginNotGenerated => "not-generated",
        AttestationError::PurposeMissingSign => "no-sign-purpose",
        // `AttestationError` is #[non_exhaustive]; future Stage 2 variants
        // (verified-boot pin, revocation) collapse to a generic tag.
        _ => "unverified",
    }
}

/// Verify the device key's Android Key Attestation chain (D0033 §2,
/// Stage 1) and return an advisory [`AttestationResultRecord`].
///
/// `chain` is the cert chain (leaf-first) from the Android KeyStore
/// (`HardwareKeySigner::attestation_chain`); `expected_challenge` is the
/// 32-byte nonce persisted at key-generation; `now_unix` is the current
/// time (seconds) for the validity-window checks.
///
/// This export does NOT return a `Result`: per D0033 §4 attestation is
/// advisory, so a failure is reported in-band as `attested = false` with
/// a diagnostic [`AttestationResultRecord::failure`] tag, never as a
/// thrown [`CairnFfiError`]. The caller decides how to surface it.
#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
)]
#[must_use]
pub fn verify_device_key_attestation(
    chain: Vec<AttestationCertificate>,
    expected_challenge: Vec<u8>,
    now_unix: u64,
) -> AttestationResultRecord {
    let der: Vec<Vec<u8>> = chain.into_iter().map(|c| c.encoded).collect();
    match verify_key_attestation(&der, &expected_challenge, now_unix) {
        Ok(facts) => AttestationResultRecord::attested(&facts),
        Err(err) => AttestationResultRecord::unattested(&err),
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

    // ===================================================================
    // Device-key attestation export (D0033 §2). The verifier itself is
    // exhaustively tested in `cairn_identity::attestation`; here we prove
    // the FFI wrapper maps Ok → attested=true (+ facts) and Err →
    // attested=false (+ diagnostic tag), never throwing.
    // ===================================================================

    // The same real on-device chain + challenge captured per D0033 §1,
    // shared from the cairn-identity test vectors.
    const ATT_CERT_0: &[u8] =
        include_bytes!("../../cairn-identity/tests/vectors/attestation/cert-0.der");
    const ATT_CERT_1: &[u8] =
        include_bytes!("../../cairn-identity/tests/vectors/attestation/cert-1.der");
    const ATT_CERT_2: &[u8] =
        include_bytes!("../../cairn-identity/tests/vectors/attestation/cert-2.der");
    const ATT_CERT_3: &[u8] =
        include_bytes!("../../cairn-identity/tests/vectors/attestation/cert-3.der");
    const ATT_CERT_4: &[u8] =
        include_bytes!("../../cairn-identity/tests/vectors/attestation/cert-4.der");
    const ATT_CHALLENGE: &[u8] =
        include_bytes!("../../cairn-identity/tests/vectors/attestation/challenge.bin");
    // Inside every cert's validity window at capture time (2026-06-04).
    const ATT_NOW: u64 = 1_780_574_400;

    fn att_chain() -> Vec<AttestationCertificate> {
        [ATT_CERT_0, ATT_CERT_1, ATT_CERT_2, ATT_CERT_3, ATT_CERT_4]
            .iter()
            .map(|der| AttestationCertificate {
                encoded: der.to_vec(),
            })
            .collect()
    }

    #[test]
    fn attestation_export_maps_real_chain_to_attested_record() {
        let rec = verify_device_key_attestation(att_chain(), ATT_CHALLENGE.to_vec(), ATT_NOW);
        assert!(rec.attested);
        assert_eq!(rec.security_level, "TEE");
        assert!(!rec.strongbox);
        assert_eq!(rec.attestation_version, 400);
        assert_eq!(rec.device_public_key.len(), 32);
        assert!(rec.device_locked);
        assert!(rec.failure.is_empty());
    }

    #[test]
    fn attestation_export_wrong_challenge_is_unattested_with_tag() {
        let rec = verify_device_key_attestation(att_chain(), vec![0u8; 32], ATT_NOW);
        assert!(!rec.attested);
        assert_eq!(rec.failure, "challenge-mismatch");
        assert!(rec.security_level.is_empty());
        assert!(rec.device_public_key.is_empty());
    }

    #[test]
    fn attestation_export_empty_chain_is_unattested_no_chain() {
        let rec = verify_device_key_attestation(vec![], ATT_CHALLENGE.to_vec(), ATT_NOW);
        assert!(!rec.attested);
        assert_eq!(rec.failure, "no-chain");
    }

    #[test]
    fn attestation_export_never_throws_on_garbage() {
        // A malformed leaf + a valid root: the export returns a record,
        // not an error (advisory posture, D0033 §4).
        let chain = vec![
            AttestationCertificate {
                encoded: vec![0xFF, 0x00, 0x01],
            },
            AttestationCertificate {
                encoded: ATT_CERT_4.to_vec(),
            },
        ];
        let rec = verify_device_key_attestation(chain, ATT_CHALLENGE.to_vec(), ATT_NOW);
        assert!(!rec.attested);
        assert_eq!(rec.failure, "malformed");
    }
}
