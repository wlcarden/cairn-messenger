// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Capability token data structure + signed-envelope wrapper.
//!
//! Per D0006 §9 token payload schema (integer-keyed canonical CBOR map):
//!
//! | Key | Field   | CBOR type      |
//! |-----|---------|----------------|
//! | 1   | issuer  | bstr(32)       |
//! | 2   | subject | bstr(32)       |
//! | 3   | scope   | array of text  |
//! | 4   | expiry  | uint           |
//! | 5   | chain   | bstr           |
//!
//! Construction: [`CapabilityToken::new`] → [`CapabilityToken::sign`].
//! Verification: [`SignedCapabilityToken::from_bytes`] (decodes +
//! verifies against an expected issuer).

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, SigningKey, VerifyingKey};
use cairn_envelope::canonical::Value;
use cairn_envelope::cose_sign1::{CoseSign1, Sign1Builder};
use ciborium::Value as CiboriumValue;

use crate::error::IdentityError;

/// Canonical-CBOR map key for the issuer public key.
const KEY_ISSUER: i64 = 1;
/// Canonical-CBOR map key for the subject public key.
const KEY_SUBJECT: i64 = 2;
/// Canonical-CBOR map key for the scope array.
const KEY_SCOPE: i64 = 3;
/// Canonical-CBOR map key for the expiry timestamp.
const KEY_EXPIRY: i64 = 4;
/// Canonical-CBOR map key for the signature-chain-to-master bytes.
const KEY_CHAIN: i64 = 5;

/// D0006 §8 domain-separation tag for capability tokens.
///
/// Bound into the `COSE_Sign1` `Sig_structure` via the `external_aad`
/// field per RFC 9052 §4.4. A signature produced for a capability
/// token cannot verify in a different domain (trust-graph operations,
/// master attestations, application messages) even if the payload bits
/// happen to overlap — the `Sig_structure` covers `external_aad`, so
/// the AAD value is part of the signed input.
///
/// This is one of two tags explicitly enumerated in D0006 §8; the
/// matching trust-graph-operation tag lives in `cairn-trust-graph`.
pub const DOMAIN_TAG: &[u8] = b"cairn-v1-capability-token";

/// A capability token authorizing a device key to perform a set of
/// operations on behalf of an operational identity per D0006 §9.
///
/// Construct via [`Self::new`]; sign via [`Self::sign`] to produce a
/// [`SignedCapabilityToken`] envelope. The token's bytes-level form is
/// the canonical CBOR map per the schema in the module-level docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityToken {
    /// Operational identity Ed25519 public key (issuer).
    pub issuer: VerifyingKey,
    /// Device Ed25519 public key (subject) — the key whose signatures
    /// the token authorizes within the named scope.
    pub subject: VerifyingKey,
    /// Capability strings naming the operations the subject is
    /// authorized to perform. See [`crate::capabilities`] for the v1
    /// constants.
    pub scope: Vec<String>,
    /// Unix-seconds timestamp at which the token expires. Verification
    /// against current time is the caller's responsibility (per
    /// operation type's freshness policy).
    pub expiry_unix_seconds: u64,
    /// Opaque signature chain binding the issuer to the master
    /// identity. Verified by higher layers (`cairn-recovery` /
    /// `cairn-trust-graph`); this module carries it as bytes through
    /// the round trip.
    pub signature_chain_to_master: Vec<u8>,
}

impl CapabilityToken {
    /// Construct a new capability token.
    ///
    /// All fields are taken by value (the scope vector and chain bytes
    /// are owned). The issuer + subject are `Copy`.
    #[must_use]
    pub const fn new(
        issuer: VerifyingKey,
        subject: VerifyingKey,
        scope: Vec<String>,
        expiry_unix_seconds: u64,
        signature_chain_to_master: Vec<u8>,
    ) -> Self {
        Self {
            issuer,
            subject,
            scope,
            expiry_unix_seconds,
            signature_chain_to_master,
        }
    }

    /// Return `true` if the token's scope contains the named capability.
    ///
    /// Compares string-equality against the entries; v1 capability
    /// constants are in [`crate::capabilities`].
    #[must_use]
    pub fn has_capability(&self, capability: &str) -> bool {
        self.scope.iter().any(|s| s == capability)
    }

    /// Encode the token as canonical CBOR bytes (the `COSE_Sign1`
    /// payload).
    ///
    /// # Errors
    ///
    /// - [`IdentityError::ExpiryOutOfRange`] if `expiry_unix_seconds`
    ///   does not fit in `i64`.
    /// - [`IdentityError::CanonicalEncode`] if the underlying
    ///   canonical encoder fails (unreachable for the schema's typed
    ///   inputs).
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, IdentityError> {
        let expiry_i64 =
            i64::try_from(self.expiry_unix_seconds).map_err(|_| IdentityError::ExpiryOutOfRange)?;

        let scope_array = self
            .scope
            .iter()
            .map(|s| Value::Text(s.clone()))
            .collect::<Vec<_>>();

        let map = Value::Map(vec![
            (
                Value::Int(KEY_ISSUER),
                Value::Bytes(self.issuer.to_bytes().to_vec()),
            ),
            (
                Value::Int(KEY_SUBJECT),
                Value::Bytes(self.subject.to_bytes().to_vec()),
            ),
            (Value::Int(KEY_SCOPE), Value::Array(scope_array)),
            (Value::Int(KEY_EXPIRY), Value::Int(expiry_i64)),
            (
                Value::Int(KEY_CHAIN),
                Value::Bytes(self.signature_chain_to_master.clone()),
            ),
        ]);

        map.encode().map_err(IdentityError::from)
    }

    /// Decode a token from canonical CBOR bytes.
    ///
    /// Unknown map keys are silently ignored for forward-compatibility
    /// per D0006 §6.4's "operation types unknown to a client are
    /// retained but ignored" principle. Required keys (1, 2, 3, 4, 5)
    /// must all be present; missing any returns
    /// [`IdentityError::MalformedPayload`].
    ///
    /// # Errors
    ///
    /// - [`IdentityError::MalformedPayload`] for any CBOR or schema
    ///   structural error
    /// - [`IdentityError::InvalidPubkeyLength`] if `issuer` or
    ///   `subject` is not exactly 32 bytes
    /// - [`IdentityError::InvalidPubkey`] if the pubkey bytes are
    ///   not a valid Ed25519 curve point
    /// - [`IdentityError::ExpiryOutOfRange`] if the expiry integer
    ///   doesn't fit in `u64`
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, IdentityError> {
        let parsed: CiboriumValue =
            ciborium::de::from_reader(bytes).map_err(|_| IdentityError::MalformedPayload)?;

        let CiboriumValue::Map(entries) = parsed else {
            return Err(IdentityError::MalformedPayload);
        };

        let mut issuer_bytes: Option<Vec<u8>> = None;
        let mut subject_bytes: Option<Vec<u8>> = None;
        let mut scope: Option<Vec<String>> = None;
        let mut expiry: Option<u64> = None;
        let mut chain: Option<Vec<u8>> = None;

        for (key, value) in entries {
            let CiboriumValue::Integer(key_int_ciborium) = key else {
                return Err(IdentityError::MalformedPayload);
            };
            let key_int = i64::try_from(i128::from(key_int_ciborium))
                .map_err(|_| IdentityError::MalformedPayload)?;

            match key_int {
                KEY_ISSUER => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(IdentityError::MalformedPayload);
                    };
                    issuer_bytes = Some(b);
                }
                KEY_SUBJECT => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(IdentityError::MalformedPayload);
                    };
                    subject_bytes = Some(b);
                }
                KEY_SCOPE => {
                    let CiboriumValue::Array(items) = value else {
                        return Err(IdentityError::MalformedPayload);
                    };
                    let strs = items
                        .into_iter()
                        .map(|v| {
                            if let CiboriumValue::Text(t) = v {
                                Ok(t)
                            } else {
                                Err(IdentityError::MalformedPayload)
                            }
                        })
                        .collect::<Result<Vec<String>, _>>()?;
                    scope = Some(strs);
                }
                KEY_EXPIRY => {
                    let CiboriumValue::Integer(exp_ciborium) = value else {
                        return Err(IdentityError::MalformedPayload);
                    };
                    expiry = Some(
                        u64::try_from(i128::from(exp_ciborium))
                            .map_err(|_| IdentityError::ExpiryOutOfRange)?,
                    );
                }
                KEY_CHAIN => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(IdentityError::MalformedPayload);
                    };
                    chain = Some(b);
                }
                // Unknown keys: forward-compat — silently ignored.
                _ => {}
            }
        }

        let issuer_bytes = issuer_bytes.ok_or(IdentityError::MalformedPayload)?;
        let subject_bytes = subject_bytes.ok_or(IdentityError::MalformedPayload)?;
        let scope = scope.ok_or(IdentityError::MalformedPayload)?;
        let expiry_unix_seconds = expiry.ok_or(IdentityError::MalformedPayload)?;
        let signature_chain_to_master = chain.ok_or(IdentityError::MalformedPayload)?;

        if issuer_bytes.len() != PUBLIC_KEY_LEN {
            return Err(IdentityError::InvalidPubkeyLength {
                got_bytes: issuer_bytes.len(),
                expected_bytes: PUBLIC_KEY_LEN,
            });
        }
        if subject_bytes.len() != PUBLIC_KEY_LEN {
            return Err(IdentityError::InvalidPubkeyLength {
                got_bytes: subject_bytes.len(),
                expected_bytes: PUBLIC_KEY_LEN,
            });
        }

        let issuer_arr: [u8; PUBLIC_KEY_LEN] = issuer_bytes
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::InvalidPubkey)?;
        let subject_arr: [u8; PUBLIC_KEY_LEN] = subject_bytes
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::InvalidPubkey)?;

        let issuer =
            VerifyingKey::from_bytes(&issuer_arr).map_err(|_| IdentityError::InvalidPubkey)?;
        let subject =
            VerifyingKey::from_bytes(&subject_arr).map_err(|_| IdentityError::InvalidPubkey)?;

        Ok(Self {
            issuer,
            subject,
            scope,
            expiry_unix_seconds,
            signature_chain_to_master,
        })
    }

    /// Sign this token with the issuer's signing key.
    ///
    /// The resulting [`SignedCapabilityToken`] envelope is a
    /// ``COSE_Sign1`` wrapping the canonical-CBOR encoding of this
    /// token; the signature is over the canonical bytes per RFC 9052
    /// §4.4 `Sig_structure` construction (handled by
    /// `cairn_envelope::cose_sign1`).
    ///
    /// # Errors
    ///
    /// Propagates [`IdentityError::CanonicalEncode`] from canonical
    /// encoding or `COSE_Sign1` sign failures.
    pub fn sign(&self, signing_key: &SigningKey) -> Result<SignedCapabilityToken, IdentityError> {
        let payload = self.to_canonical_cbor()?;
        let envelope = Sign1Builder::new()
            .with_payload(payload)
            .with_external_aad(DOMAIN_TAG.to_vec())
            .finalize(signing_key)
            .map_err(IdentityError::from)?;
        Ok(SignedCapabilityToken {
            envelope,
            token: self.clone(),
        })
    }

    /// Sign this token with an **external** issuer signer (Android
    /// `StrongBox`, where the private key never enters the process —
    /// D0020 §3.4 / D0035 §4).
    ///
    /// `sign_fn` receives the `COSE_Sign1` signing input (the RFC 9052
    /// §4.4 `Sig_structure` bytes, bound to the capability-token
    /// [`DOMAIN_TAG`]) and must return the 64-byte Ed25519 signature the
    /// issuer key produces over **exactly** those bytes. This is the
    /// hardware counterpart to [`Self::sign`]; because `finalize` is
    /// `signing_input` + an in-process sign + assemble, the two paths
    /// produce **byte-identical** envelopes for the same key. In the
    /// collapsed v1 identity (D0035 §1) the issuer == the device key, so
    /// the same `StrongBox` device key that signs trust-graph ops also
    /// signs this self-issued token.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::CanonicalEncode`] from encoding the token
    ///   payload or building the signing input (or if the returned
    ///   signature is not 64 bytes).
    /// - Whatever `sign_fn` returns on signer failure (callers map their
    ///   hardware error to [`IdentityError::ExternalSignerFailed`]).
    pub fn sign_external<F>(&self, sign_fn: F) -> Result<SignedCapabilityToken, IdentityError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, IdentityError>,
    {
        let payload = self.to_canonical_cbor()?;
        let builder = Sign1Builder::new()
            .with_payload(payload)
            .with_external_aad(DOMAIN_TAG.to_vec());
        // signing_input() borrows; finalize_with_signature() consumes —
        // the builder MUST NOT be mutated between the two (it is not).
        let signing_input = builder.signing_input().map_err(IdentityError::from)?;
        let signature = sign_fn(&signing_input)?;
        let envelope = builder
            .finalize_with_signature(&signature)
            .map_err(IdentityError::from)?;
        Ok(SignedCapabilityToken {
            envelope,
            token: self.clone(),
        })
    }
}

/// A ``COSE_Sign1``-wrapped capability token with a verified payload.
///
/// Constructed only via [`Self::from_bytes`] (decoding-with-verification
/// path) or as the output of [`CapabilityToken::sign`]. The verified
/// token contents are accessible via [`Self::token`]; the byte form via
/// [`Self::encode`].
#[derive(Debug, Clone)]
pub struct SignedCapabilityToken {
    envelope: CoseSign1,
    token: CapabilityToken,
}

impl SignedCapabilityToken {
    /// Decode an envelope from bytes + verify the signature against the
    /// expected issuer's public key.
    ///
    /// The verifier supplies `expected_issuer` — the public key it
    /// expects signed this token. The decoder then:
    ///
    /// 1. Parses the `COSE_Sign1` envelope from `bytes`.
    /// 2. Parses the payload bytes into a [`CapabilityToken`].
    /// 3. Verifies the embedded `issuer` field matches
    ///    `expected_issuer` (defends against key-substitution).
    /// 4. Verifies the `COSE_Sign1` signature against `expected_issuer`.
    ///
    /// All four steps must succeed to return `Ok`. Failures are
    /// uniform in the sense that they reveal only the failure mode,
    /// not the secret-bearing details, per the no-error-oracle
    /// discipline (D0006 / D0018 §1.4).
    ///
    /// # Errors
    ///
    /// - [`IdentityError::MalformedPayload`] if the envelope or its
    ///   payload is malformed
    /// - [`IdentityError::IssuerMismatch`] if the embedded issuer
    ///   does not match `expected_issuer`
    /// - [`IdentityError::SignatureVerifyFailed`] if the signature
    ///   does not verify
    /// - Plus the [`CapabilityToken::from_canonical_cbor`] errors
    ///   (pubkey length / curve point / expiry range)
    pub fn from_bytes(bytes: &[u8], expected_issuer: &VerifyingKey) -> Result<Self, IdentityError> {
        let envelope = CoseSign1::from_bytes(bytes).map_err(|_| IdentityError::MalformedPayload)?;

        let payload_bytes = envelope.payload().ok_or(IdentityError::MalformedPayload)?;

        let token = CapabilityToken::from_canonical_cbor(payload_bytes)?;

        if token.issuer != *expected_issuer {
            return Err(IdentityError::IssuerMismatch);
        }

        envelope
            .verify(expected_issuer, DOMAIN_TAG)
            .map_err(|_| IdentityError::SignatureVerifyFailed)?;

        Ok(Self { envelope, token })
    }

    /// Get the verified token contents.
    #[must_use]
    pub const fn token(&self) -> &CapabilityToken {
        &self.token
    }

    /// Encode the envelope back to bytes.
    ///
    /// If `tagged` is true the output is wrapped in CBOR tag 18
    /// ([`cairn_envelope::cose_sign1::COSE_SIGN1_TAG`]); otherwise the
    /// bare 4-tuple is emitted.
    ///
    /// # Errors
    ///
    /// Propagates the underlying `COSE_Sign1` encoding error (unreachable
    /// for envelopes constructed via [`Self::from_bytes`] or
    /// [`CapabilityToken::sign`]).
    pub fn encode(&self, tagged: bool) -> Result<Vec<u8>, IdentityError> {
        self.envelope.encode(tagged).map_err(IdentityError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use rand_core::OsRng;

    use crate::capabilities;

    fn make_token() -> (SigningKey, SigningKey, CapabilityToken) {
        let mut rng = OsRng;
        let issuer_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);
        let token = CapabilityToken::new(
            issuer_sk.verifying_key(),
            device_sk.verifying_key(),
            vec![
                capabilities::MESSAGING_SEND.to_string(),
                capabilities::TRUST_GRAPH_ATTEST.to_string(),
            ],
            2_000_000_000,
            b"opaque-chain-bytes".to_vec(),
        );
        (issuer_sk, device_sk, token)
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (issuer_sk, _device_sk, token) = make_token();
        let signed = token.sign(&issuer_sk).unwrap();

        let bytes = signed.encode(false).unwrap();
        let recovered =
            SignedCapabilityToken::from_bytes(&bytes, &issuer_sk.verifying_key()).unwrap();
        assert_eq!(recovered.token(), &token);
    }

    #[test]
    fn external_signer_path_matches_in_process() {
        // The external-signer path (StrongBox counterpart, D0035 §4) must
        // produce a byte-identical envelope to the in-process sign for the
        // same key — and the externally-signed token must verify.
        let (issuer_sk, _device_sk, token) = make_token();
        let in_process = token.sign(&issuer_sk).unwrap();
        let external = token
            .sign_external(|tbs| {
                issuer_sk
                    .sign(tbs)
                    .map(|sig| sig.to_bytes().to_vec())
                    .map_err(|_| IdentityError::ExternalSignerFailed)
            })
            .unwrap();

        let in_process_bytes = in_process.encode(false).unwrap();
        let external_bytes = external.encode(false).unwrap();
        assert_eq!(in_process_bytes, external_bytes);
        assert!(
            SignedCapabilityToken::from_bytes(&external_bytes, &issuer_sk.verifying_key()).is_ok()
        );
    }

    #[test]
    fn external_signer_failure_propagates() {
        let (_issuer_sk, _device_sk, token) = make_token();
        let result = token.sign_external(|_tbs| Err(IdentityError::ExternalSignerFailed));
        assert!(matches!(result, Err(IdentityError::ExternalSignerFailed)));
    }

    #[test]
    fn sign_and_verify_round_trip_tagged() {
        let (issuer_sk, _device_sk, token) = make_token();
        let signed = token.sign(&issuer_sk).unwrap();

        let bytes = signed.encode(true).unwrap();
        let recovered =
            SignedCapabilityToken::from_bytes(&bytes, &issuer_sk.verifying_key()).unwrap();
        assert_eq!(recovered.token(), &token);
    }

    #[test]
    fn wrong_expected_issuer_fails_with_mismatch() {
        let (issuer_sk, _device_sk, token) = make_token();
        let signed = token.sign(&issuer_sk).unwrap();
        let bytes = signed.encode(false).unwrap();

        let mut rng = OsRng;
        let other_sk = SigningKey::generate(&mut rng);
        let result = SignedCapabilityToken::from_bytes(&bytes, &other_sk.verifying_key());
        assert!(matches!(result, Err(IdentityError::IssuerMismatch)));
    }

    #[test]
    fn wrong_signing_key_fails_with_signature_verify_failed() {
        // Mismatch between the embedded issuer (matches expected) and
        // the actual signing key: lie about the issuer in the payload
        // but sign with a different key.
        let mut rng = OsRng;
        let real_sk = SigningKey::generate(&mut rng);
        let imposter_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);

        // Embed real_sk as the issuer field but sign with imposter_sk.
        let token = CapabilityToken::new(
            real_sk.verifying_key(),
            device_sk.verifying_key(),
            vec![capabilities::MESSAGING_SEND.to_string()],
            2_000_000_000,
            vec![],
        );
        let signed = token.sign(&imposter_sk).unwrap();
        let bytes = signed.encode(false).unwrap();

        // Verifier expects real_sk's pubkey (matches embedded).
        // Decode succeeds (payload says real_sk); signature verification
        // against real_sk fails because the signature is from imposter_sk.
        let result = SignedCapabilityToken::from_bytes(&bytes, &real_sk.verifying_key());
        assert!(matches!(result, Err(IdentityError::SignatureVerifyFailed)));
    }

    #[test]
    fn has_capability_check() {
        let (_, _, token) = make_token();
        assert!(token.has_capability(capabilities::MESSAGING_SEND));
        assert!(token.has_capability(capabilities::TRUST_GRAPH_ATTEST));
        assert!(!token.has_capability(capabilities::RECOVERY_PARTICIPATE));
        assert!(!token.has_capability("unknown:capability"));
    }

    #[test]
    fn forward_compat_unknown_capability_round_trips() {
        // A token with a future capability we don't know about must
        // still round-trip cleanly.
        let mut rng = OsRng;
        let issuer_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);
        let token = CapabilityToken::new(
            issuer_sk.verifying_key(),
            device_sk.verifying_key(),
            vec![
                "future-capability:v2-only".to_string(),
                capabilities::MESSAGING_SEND.to_string(),
            ],
            2_000_000_000,
            vec![],
        );
        let signed = token.sign(&issuer_sk).unwrap();
        let bytes = signed.encode(false).unwrap();
        let recovered =
            SignedCapabilityToken::from_bytes(&bytes, &issuer_sk.verifying_key()).unwrap();

        assert!(
            recovered
                .token()
                .has_capability("future-capability:v2-only")
        );
        assert!(
            recovered
                .token()
                .has_capability(capabilities::MESSAGING_SEND)
        );
    }

    #[test]
    fn empty_scope_round_trips() {
        let mut rng = OsRng;
        let issuer_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);
        let token = CapabilityToken::new(
            issuer_sk.verifying_key(),
            device_sk.verifying_key(),
            vec![],
            2_000_000_000,
            vec![],
        );
        let signed = token.sign(&issuer_sk).unwrap();
        let bytes = signed.encode(false).unwrap();
        let recovered =
            SignedCapabilityToken::from_bytes(&bytes, &issuer_sk.verifying_key()).unwrap();
        assert!(recovered.token().scope.is_empty());
    }

    #[test]
    fn encoding_is_deterministic() {
        let (_, _, token) = make_token();
        let a = token.to_canonical_cbor().unwrap();
        let b = token.to_canonical_cbor().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn signed_envelope_encoding_is_deterministic() {
        let (issuer_sk, _, token) = make_token();
        let signed = token.sign(&issuer_sk).unwrap();
        let a = signed.encode(false).unwrap();
        let b = signed.encode(false).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn malformed_bytes_fail_to_decode() {
        let mut rng = OsRng;
        let issuer_sk = SigningKey::generate(&mut rng);
        let result = SignedCapabilityToken::from_bytes(b"\xff\x00\x01", &issuer_sk.verifying_key());
        assert!(matches!(result, Err(IdentityError::MalformedPayload)));
    }

    #[test]
    // `indexing_slicing` allowed: `signed.encode()` always returns a
    // non-empty Vec for a finalized token; `bytes.len() / 2` is a
    // statically-safe in-range index.
    #[allow(clippy::indexing_slicing)]
    fn tampered_payload_fails_verification() {
        let (issuer_sk, _, token) = make_token();
        let signed = token.sign(&issuer_sk).unwrap();
        let mut bytes = signed.encode(false).unwrap();

        // Flip a bit somewhere in the middle (well after the structural
        // header bytes — likely lands in the payload or signature).
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;

        let result = SignedCapabilityToken::from_bytes(&bytes, &issuer_sk.verifying_key());
        // The tamper could land in payload bytes (MalformedPayload or
        // InvalidPubkey or IssuerMismatch), in the signature
        // (SignatureVerifyFailed), or in the `COSE_Sign1` structure
        // (MalformedPayload). All are valid failures.
        assert!(result.is_err());
    }

    #[test]
    fn from_canonical_cbor_round_trip() {
        let (_, _, token) = make_token();
        let bytes = token.to_canonical_cbor().unwrap();
        let recovered = CapabilityToken::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(recovered, token);
    }

    #[test]
    fn signature_does_not_verify_under_wrong_domain_tag() {
        // Sign with the capability-token domain tag (default in
        // `CapabilityToken::sign`), then attempt verify with a
        // different external_aad. The COSE_Sign1 `Sig_structure` binds
        // external_aad per RFC 9052 §4.4, so a signature produced for
        // one domain cannot verify in another even if the embedded
        // issuer and payload bytes are identical. This is the D0006 §8
        // cross-protocol substitution defense.
        let (issuer_sk, _device_sk, token) = make_token();
        let signed = token.sign(&issuer_sk).unwrap();
        let bytes = signed.encode(false).unwrap();

        let envelope = CoseSign1::from_bytes(&bytes).unwrap();
        let wrong_tag_result = envelope.verify(
            &issuer_sk.verifying_key(),
            b"cairn-v1-trust-graph-operation",
        );
        assert!(
            wrong_tag_result.is_err(),
            "signature must not verify under the trust-graph-operation tag"
        );
        let no_tag_result = envelope.verify(&issuer_sk.verifying_key(), b"");
        assert!(
            no_tag_result.is_err(),
            "signature must not verify under the empty / no-tag AAD"
        );

        // And the correct tag verifies (proving the test setup is
        // structurally sound rather than failing for unrelated reasons).
        envelope
            .verify(&issuer_sk.verifying_key(), DOMAIN_TAG)
            .expect("verify must succeed under the capability-token tag");
    }

    #[test]
    fn domain_tag_value_matches_d0006() {
        // D0006 §8 specifies the canonical byte string. Pin to catch
        // accidental edits.
        assert_eq!(DOMAIN_TAG, b"cairn-v1-capability-token");
    }

    #[test]
    fn payload_with_unknown_keys_is_forward_compat() {
        // Construct a payload manually with an extra unknown key and
        // verify the decoder skips it cleanly.
        let mut rng = OsRng;
        let issuer_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);

        let scope_array = vec![Value::Text(capabilities::MESSAGING_SEND.to_string())];

        let map = Value::Map(vec![
            (
                Value::Int(KEY_ISSUER),
                Value::Bytes(issuer_sk.verifying_key().to_bytes().to_vec()),
            ),
            (
                Value::Int(KEY_SUBJECT),
                Value::Bytes(device_sk.verifying_key().to_bytes().to_vec()),
            ),
            (Value::Int(KEY_SCOPE), Value::Array(scope_array)),
            (Value::Int(KEY_EXPIRY), Value::Int(2_000_000_000)),
            (Value::Int(KEY_CHAIN), Value::Bytes(vec![])),
            // Unknown future key — should be ignored.
            (
                Value::Int(99),
                Value::Text("future-field-content".to_string()),
            ),
        ]);
        let bytes = map.encode().unwrap();

        let token = CapabilityToken::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(token.issuer, issuer_sk.verifying_key());
        assert_eq!(token.scope.len(), 1);
        assert_eq!(token.expiry_unix_seconds, 2_000_000_000);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use proptest::prelude::*;
    use rand_core::OsRng;

    use crate::capabilities;

    proptest! {
        /// Property: any well-formed token round-trips through
        /// sign → encode → from_bytes → verify and yields an equal token.
        #[test]
        fn prop_round_trip(
            scope_strs in proptest::collection::vec("[a-z:-]{0,32}", 0..6),
            expiry in 0u64..=u64::from(i32::MAX as u32),
            chain in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let mut rng = OsRng;
            let issuer_sk = SigningKey::generate(&mut rng);
            let device_sk = SigningKey::generate(&mut rng);

            let token = CapabilityToken::new(
                issuer_sk.verifying_key(),
                device_sk.verifying_key(),
                scope_strs,
                expiry,
                chain,
            );

            let signed = token.sign(&issuer_sk).unwrap();
            let bytes = signed.encode(false).unwrap();
            let recovered = SignedCapabilityToken::from_bytes(
                &bytes,
                &issuer_sk.verifying_key()
            ).unwrap();

            prop_assert_eq!(recovered.token(), &token);
        }

        /// Property: at minimum, MESSAGING_SEND tokens consistently
        /// answer the has_capability check correctly.
        #[test]
        fn prop_has_capability_consistent(
            other_caps in proptest::collection::vec("[a-z:-]{1,32}", 0..4),
            include_messaging in any::<bool>(),
        ) {
            let mut rng = OsRng;
            let issuer_sk = SigningKey::generate(&mut rng);
            let device_sk = SigningKey::generate(&mut rng);

            let mut scope = other_caps;
            if include_messaging {
                scope.push(capabilities::MESSAGING_SEND.to_string());
            }
            // Filter out any random string that happens to equal the
            // known MESSAGING_SEND value, so the assertion below is
            // deterministic.
            scope.retain(|s|
                include_messaging || s != capabilities::MESSAGING_SEND
            );

            let token = CapabilityToken::new(
                issuer_sk.verifying_key(),
                device_sk.verifying_key(),
                scope,
                2_000_000_000,
                vec![],
            );

            prop_assert_eq!(
                token.has_capability(capabilities::MESSAGING_SEND),
                include_messaging
            );
        }
    }
}
