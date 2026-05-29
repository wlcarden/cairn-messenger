// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Signed trust-graph operation envelope (`COSE_Sign1` wrapping +
//! capability-token chain verification).
//!
//! Per D0006 §9 the verification chain is three-hop. This module's
//! [`SignedTrustGraphOp::verify_chain`] performs hops #1 + #2:
//!
//! 1. Verify the operation envelope's `COSE_Sign1` signature against
//!    the device public key embedded in the capability token's
//!    `subject` field.
//! 2. Verify the capability token itself against the expected
//!    operational-identity (issuer) public key. The token's scope
//!    must contain the operation-type's required capability.
//!
//! Hop #3 (master attestation chain) belongs at higher layers — this
//! module trusts the operational-identity pubkey supplied by the
//! caller.

use cairn_crypto::ed25519::{SigningKey, VerifyingKey};
use cairn_envelope::cose_sign1::{CoseSign1, Sign1Builder};
use cairn_identity::SignedCapabilityToken;
use sha2::{Digest, Sha256};

use crate::error::TrustGraphError;
use crate::op::TrustGraphOp;

/// Length of the SHA-256 hash output bound to `prior_hash` per D0006 §5.
pub const PRIOR_HASH_LEN: usize = 32;

/// D0006 §8 domain-separation tag for trust-graph operations.
///
/// Bound into the `COSE_Sign1` `Sig_structure` via the `external_aad`
/// field per RFC 9052 §4.4. A signature produced for a trust-graph
/// operation cannot verify in a different domain (capability tokens,
/// master attestations, application messages) — the `Sig_structure`
/// covers `external_aad`, so the AAD value is part of the signed
/// input.
///
/// This is one of two tags explicitly enumerated in D0006 §8; the
/// matching capability-token tag lives in `cairn-identity`.
pub const DOMAIN_TAG: &[u8] = b"cairn-v1-trust-graph-operation";

/// A `COSE_Sign1`-wrapped trust-graph operation envelope.
///
/// Construct via [`SignedTrustGraphOp::sign`]; decode via
/// [`Self::from_bytes`]; verify against a token + expected operational
/// identity via [`Self::verify_chain`].
#[derive(Debug, Clone)]
pub struct SignedTrustGraphOp {
    envelope: CoseSign1,
    op: TrustGraphOp,
}

impl SignedTrustGraphOp {
    /// Sign `op` with the device key (whose pubkey must match the
    /// `subject` field of the capability token that authorizes this
    /// operation).
    ///
    /// # Errors
    ///
    /// - [`TrustGraphError::CanonicalEncode`] / `IntegerOutOfRange`
    ///   from the canonical CBOR encoding of the op payload.
    /// - The underlying `COSE_Sign1` finalize error if `Ed25519` signing
    ///   itself fails (e.g., payload size limit).
    pub fn sign(
        op: TrustGraphOp,
        device_signing_key: &SigningKey,
    ) -> Result<Self, TrustGraphError> {
        let payload = op.to_canonical_cbor()?;
        let envelope = Sign1Builder::new()
            .with_payload(payload)
            .with_external_aad(DOMAIN_TAG.to_vec())
            .finalize(device_signing_key)
            .map_err(TrustGraphError::from)?;
        Ok(Self { envelope, op })
    }

    /// Encode the envelope back to bytes (canonical form). If
    /// `tagged`, wraps with CBOR tag 18.
    ///
    /// # Errors
    ///
    /// Propagates the underlying `COSE_Sign1` encoding error (unreachable
    /// for envelopes constructed via [`Self::sign`] or
    /// [`Self::from_bytes`]).
    pub fn encode(&self, tagged: bool) -> Result<Vec<u8>, TrustGraphError> {
        self.envelope.encode(tagged).map_err(TrustGraphError::from)
    }

    /// Decode envelope bytes without verification. The returned
    /// [`SignedTrustGraphOp`]'s signature has NOT been checked; the
    /// caller MUST follow up with [`Self::verify_chain`] before
    /// trusting any field.
    ///
    /// # Errors
    ///
    /// - [`TrustGraphError::MalformedPayload`] if the bytes are not
    ///   well-formed `COSE_Sign1` or the payload does not parse to a
    ///   trust-graph op schema.
    /// - [`TrustGraphError`] propagated from
    ///   [`TrustGraphOp::from_canonical_cbor`] (pubkey errors, etc.).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TrustGraphError> {
        let envelope =
            CoseSign1::from_bytes(bytes).map_err(|_| TrustGraphError::MalformedPayload)?;
        let payload_bytes = envelope
            .payload()
            .ok_or(TrustGraphError::MalformedPayload)?;
        let op = TrustGraphOp::from_canonical_cbor(payload_bytes)?;
        Ok(Self { envelope, op })
    }

    /// Get the (potentially-unverified) operation contents.
    ///
    /// **WARNING**: Use [`Self::verify_chain`] before trusting any
    /// field on a newly-decoded envelope. This accessor exists for
    /// inspection during decode (e.g. extracting `issuer_cert_hash`
    /// to look up the token) and for use after a successful verify.
    #[must_use]
    pub const fn op(&self) -> &TrustGraphOp {
        &self.op
    }

    /// Return the canonical D0006 §5 `prior_hash` for this operation.
    ///
    /// Computes `SHA-256( COSE_Sign1.signature_bytes( self ) )` —
    /// the value the next operation in this issuer's chain places in
    /// its `prior_hash` field. Hashing the signature bytes (not the
    /// payload or full envelope) is intentional: the signature is the
    /// unambiguous canonical commitment to the operation's content
    /// (the signature covers the `Sig_structure`, which covers
    /// payload, protected header, and `external_aad`), and hashing it
    /// produces a fixed-size input regardless of payload complexity
    /// per D0006 §5.
    ///
    /// The output is the byte string callers should write into the
    /// next op's `prior_hash` field (zero-length for genesis ops only).
    #[must_use]
    pub fn prior_hash_bytes(&self) -> [u8; PRIOR_HASH_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(self.envelope.signature());
        let out = hasher.finalize();
        let mut arr = [0u8; PRIOR_HASH_LEN];
        arr.copy_from_slice(&out);
        arr
    }

    /// Verify the three-hop chain (modulo hop #3 which higher layers
    /// own):
    ///
    /// 1. The capability token verifies against
    ///    `expected_operational_identity`.
    /// 2. The token's scope authorizes this operation's required
    ///    capability (per [`crate::OpType::required_capability`]).
    /// 3. The op envelope's `COSE_Sign1` signature verifies against the
    ///    token's `subject` (device pubkey).
    /// 4. The op's `issuer` field matches the token's `issuer`
    ///    field (same operational identity).
    ///
    /// # Errors
    ///
    /// - [`TrustGraphError::CapabilityTokenVerify`] from the token
    ///   verification (wraps [`cairn_identity::IdentityError`]).
    /// - [`TrustGraphError::CapabilityNotAuthorized`] if the token's
    ///   scope does not contain the required capability.
    /// - [`TrustGraphError::SignatureVerifyFailed`] for any
    ///   crypto-layer failure verifying the op envelope (uniform per
    ///   the no-error-oracle discipline).
    /// - [`TrustGraphError::DeviceTokenMismatch`] if the operation's
    ///   `issuer` does not match the token's `issuer` (peer trying
    ///   to issue trust-graph ops on someone else's behalf).
    pub fn verify_chain(
        &self,
        token_bytes: &[u8],
        expected_operational_identity: &VerifyingKey,
    ) -> Result<&TrustGraphOp, TrustGraphError> {
        // Hop #2a: verify the capability token.
        let signed_token =
            SignedCapabilityToken::from_bytes(token_bytes, expected_operational_identity)?;
        let token = signed_token.token();

        // Sanity check: the op's `issuer` claims to be from the
        // operational identity we expect; refuse mismatches early.
        if token.issuer != *expected_operational_identity {
            // Unreachable: SignedCapabilityToken::from_bytes already
            // verifies this above. Kept as defense-in-depth in case
            // the upstream check ever becomes optional.
            return Err(TrustGraphError::CapabilityTokenVerify(
                cairn_identity::IdentityError::IssuerMismatch,
            ));
        }
        if self.op.issuer != *expected_operational_identity {
            return Err(TrustGraphError::DeviceTokenMismatch);
        }

        // Hop #2b: scope check.
        let required = self.op.op_type.required_capability();
        if !token.has_capability(required) {
            return Err(TrustGraphError::CapabilityNotAuthorized {
                op_type: self.op.op_type.as_i64(),
                required,
            });
        }

        // Hop #1: verify the operation signature against the token's
        // subject (device pubkey). The envelope is bound to the
        // trust-graph-operation domain tag per D0006 §8 — a signature
        // produced for a capability token or master attestation cannot
        // verify here.
        let device_pubkey = token.subject;
        self.envelope
            .verify(&device_pubkey, DOMAIN_TAG)
            .map_err(|_| TrustGraphError::SignatureVerifyFailed)?;

        Ok(&self.op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpType;
    use cairn_crypto::ed25519::SigningKey;
    use cairn_identity::{CapabilityToken, capabilities};
    use rand_core::OsRng;

    /// Build a complete (operational identity, device, capability
    /// token) bundle authorizing the device for the requested scope.
    /// Returns `(op_identity_sk, device_sk, token_envelope_bytes)`.
    fn make_token_bundle(scope: &[&str]) -> (SigningKey, SigningKey, Vec<u8>) {
        let mut rng = OsRng;
        let op_identity_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);

        let token = CapabilityToken::new(
            op_identity_sk.verifying_key(),
            device_sk.verifying_key(),
            scope.iter().map(|s| (*s).to_string()).collect(),
            2_000_000_000,
            vec![],
        );
        let signed_token = token.sign(&op_identity_sk).unwrap();
        let token_bytes = signed_token.encode(false).unwrap();

        (op_identity_sk, device_sk, token_bytes)
    }

    #[test]
    fn attest_sign_and_verify_chain() {
        let (op_identity_sk, device_sk, token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);

        let mut rng = OsRng;
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();

        let op = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![],
            b"token-hash-placeholder".to_vec(),
        );
        let signed = SignedTrustGraphOp::sign(op.clone(), &device_sk).unwrap();
        let bytes = signed.encode(false).unwrap();

        let decoded = SignedTrustGraphOp::from_bytes(&bytes).unwrap();
        let verified_op = decoded
            .verify_chain(&token_bytes, &op_identity_sk.verifying_key())
            .unwrap();
        assert_eq!(verified_op, &op);
    }

    #[test]
    fn withdraw_revoke_sign_and_verify_chain() {
        let (op_identity_sk, device_sk, token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_REVOKE_WITHDRAW]);
        let mut rng = OsRng;
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();
        let op = TrustGraphOp::new_withdraw_revoke(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![1u8; 32], // dummy prior_hash
            vec![],
        );
        let signed = SignedTrustGraphOp::sign(op.clone(), &device_sk).unwrap();
        let bytes = signed.encode(false).unwrap();
        let decoded = SignedTrustGraphOp::from_bytes(&bytes).unwrap();
        assert_eq!(
            decoded
                .verify_chain(&token_bytes, &op_identity_sk.verifying_key())
                .unwrap(),
            &op
        );
    }

    #[test]
    fn compromise_revoke_sign_and_verify_chain() {
        let (op_identity_sk, device_sk, token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_REVOKE_COMPROMISE]);
        let mut rng = OsRng;
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();
        let op = TrustGraphOp::new_compromise_revoke(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![],
            vec![],
            1_690_000_000, // revoked_as_of
        );
        let signed = SignedTrustGraphOp::sign(op, &device_sk).unwrap();
        let bytes = signed.encode(false).unwrap();
        let decoded = SignedTrustGraphOp::from_bytes(&bytes).unwrap();
        let verified = decoded
            .verify_chain(&token_bytes, &op_identity_sk.verifying_key())
            .unwrap();
        assert_eq!(verified.revoked_as_of, Some(1_690_000_000));
    }

    #[test]
    fn re_attest_sign_and_verify_chain() {
        let (op_identity_sk, device_sk, token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let mut rng = OsRng;
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();
        let op = TrustGraphOp::new_re_attest(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![],
            vec![],
            b"prior-revocation-hash".to_vec(),
        );
        let signed = SignedTrustGraphOp::sign(op, &device_sk).unwrap();
        let bytes = signed.encode(false).unwrap();
        let decoded = SignedTrustGraphOp::from_bytes(&bytes).unwrap();
        let verified = decoded
            .verify_chain(&token_bytes, &op_identity_sk.verifying_key())
            .unwrap();
        assert_eq!(
            verified.prior_revocation_ref,
            Some(b"prior-revocation-hash".to_vec())
        );
    }

    #[test]
    fn scope_check_rejects_op_type_not_in_token_scope() {
        // Token authorizes attestation only; try to issue a
        // compromise-revocation under it.
        let (op_identity_sk, device_sk, token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let mut rng = OsRng;
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();
        let op = TrustGraphOp::new_compromise_revoke(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![],
            vec![],
            1_690_000_000,
        );
        let signed = SignedTrustGraphOp::sign(op, &device_sk).unwrap();
        let bytes = signed.encode(false).unwrap();
        let decoded = SignedTrustGraphOp::from_bytes(&bytes).unwrap();
        let result = decoded.verify_chain(&token_bytes, &op_identity_sk.verifying_key());
        assert!(matches!(
            result,
            Err(TrustGraphError::CapabilityNotAuthorized { .. })
        ));
    }

    #[test]
    fn op_issuer_mismatch_rejected() {
        // The token names operational-identity A; the op claims to be
        // issued by operational-identity B; verify must reject.
        let (op_identity_alpha, device_sk, token_bytes_alpha) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let mut rng = OsRng;
        let op_identity_bravo = SigningKey::generate(&mut rng);
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();

        let op = TrustGraphOp::new_attest(
            // Forged: claim issuer = bravo even though token names alpha.
            op_identity_bravo.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![],
            vec![],
        );
        let signed = SignedTrustGraphOp::sign(op, &device_sk).unwrap();
        let bytes = signed.encode(false).unwrap();
        let decoded = SignedTrustGraphOp::from_bytes(&bytes).unwrap();
        let result = decoded.verify_chain(&token_bytes_alpha, &op_identity_alpha.verifying_key());
        assert!(matches!(result, Err(TrustGraphError::DeviceTokenMismatch)));
    }

    #[test]
    fn wrong_device_signing_key_rejected() {
        // The token authorizes device D1; an op signed by a different
        // device D2 must fail signature verification.
        let (op_identity_sk, _device_d1_sk, token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let mut rng = OsRng;
        let device_d2_sk = SigningKey::generate(&mut rng);
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();

        let op = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![],
            vec![],
        );
        let signed = SignedTrustGraphOp::sign(op, &device_d2_sk).unwrap();
        let bytes = signed.encode(false).unwrap();
        let decoded = SignedTrustGraphOp::from_bytes(&bytes).unwrap();
        let result = decoded.verify_chain(&token_bytes, &op_identity_sk.verifying_key());
        assert!(matches!(
            result,
            Err(TrustGraphError::SignatureVerifyFailed)
        ));
    }

    #[test]
    fn wrong_expected_operational_identity_rejected() {
        // Token signed by issuer A; verifier supplies issuer B as
        // expected — the token's verify path (in
        // SignedCapabilityToken::from_bytes) rejects on IssuerMismatch.
        let (_op_identity_a_sk, device_sk, token_bytes_a) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let mut rng = OsRng;
        let op_identity_b_sk = SigningKey::generate(&mut rng);
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();

        let op = TrustGraphOp::new_attest(
            // Op claims B as issuer.
            op_identity_b_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![],
            vec![],
        );
        let signed = SignedTrustGraphOp::sign(op, &device_sk).unwrap();
        let bytes = signed.encode(false).unwrap();
        let decoded = SignedTrustGraphOp::from_bytes(&bytes).unwrap();
        let result = decoded.verify_chain(&token_bytes_a, &op_identity_b_sk.verifying_key());
        // The token verifies against A but verifier supplied B; coset
        // token verification path catches this via IssuerMismatch.
        assert!(matches!(
            result,
            Err(TrustGraphError::CapabilityTokenVerify(_))
        ));
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let (op_identity_sk, _device_sk, _token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_REVOKE_COMPROMISE]);
        let mut rng = OsRng;
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();
        let op = TrustGraphOp::new_compromise_revoke(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            b"prior-hash-bytes-here".to_vec(),
            b"cert-hash-here".to_vec(),
            1_650_000_000,
        );
        let bytes = op.to_canonical_cbor().unwrap();
        let decoded = TrustGraphOp::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(decoded, op);
    }

    #[test]
    fn compromise_missing_revoked_as_of_field_rejected_on_decode() {
        // Construct a malformed op (CompromiseRevoke variant with no
        // revoked_as_of field) by manually encoding without the
        // optional field. We do this by constructing the Value::Map
        // ourselves to bypass `new_compromise_revoke`'s field-setting.
        use cairn_envelope::canonical::Value;
        let mut rng = OsRng;
        let issuer = SigningKey::generate(&mut rng).verifying_key();
        let subject = SigningKey::generate(&mut rng).verifying_key();
        let map = Value::Map(vec![
            (Value::Int(1), Value::Int(3)), // op_type = CompromiseRevoke
            (Value::Int(2), Value::Bytes(issuer.to_bytes().to_vec())),
            (Value::Int(3), Value::Bytes(subject.to_bytes().to_vec())),
            (Value::Int(4), Value::Int(1_700_000_000)),
            (Value::Int(5), Value::Bytes(vec![])),
            (Value::Int(6), Value::Bytes(vec![])),
            // No KEY_REVOKED_AS_OF (7).
        ]);
        let bytes = map.encode().unwrap();
        let result = TrustGraphOp::from_canonical_cbor(&bytes);
        assert!(matches!(
            result,
            Err(TrustGraphError::MissingRequiredField {
                variant: "CompromiseRevoke"
            })
        ));
    }

    #[test]
    fn unknown_op_type_rejected() {
        use cairn_envelope::canonical::Value;
        let mut rng = OsRng;
        let issuer = SigningKey::generate(&mut rng).verifying_key();
        let subject = SigningKey::generate(&mut rng).verifying_key();
        let map = Value::Map(vec![
            (Value::Int(1), Value::Int(99)), // unknown op_type
            (Value::Int(2), Value::Bytes(issuer.to_bytes().to_vec())),
            (Value::Int(3), Value::Bytes(subject.to_bytes().to_vec())),
            (Value::Int(4), Value::Int(1_700_000_000)),
            (Value::Int(5), Value::Bytes(vec![])),
            (Value::Int(6), Value::Bytes(vec![])),
        ]);
        let bytes = map.encode().unwrap();
        let result = TrustGraphOp::from_canonical_cbor(&bytes);
        assert!(matches!(
            result,
            Err(TrustGraphError::UnknownOpType { value: 99 })
        ));
    }

    #[test]
    fn forward_compat_unknown_map_keys_ignored_on_decode() {
        use cairn_envelope::canonical::Value;
        let mut rng = OsRng;
        let issuer = SigningKey::generate(&mut rng).verifying_key();
        let subject = SigningKey::generate(&mut rng).verifying_key();
        let map = Value::Map(vec![
            (Value::Int(1), Value::Int(1)), // Attest
            (Value::Int(2), Value::Bytes(issuer.to_bytes().to_vec())),
            (Value::Int(3), Value::Bytes(subject.to_bytes().to_vec())),
            (Value::Int(4), Value::Int(1_700_000_000)),
            (Value::Int(5), Value::Bytes(vec![])),
            (Value::Int(6), Value::Bytes(vec![])),
            (Value::Int(99), Value::Text("future-field".to_string())),
        ]);
        let bytes = map.encode().unwrap();
        let op = TrustGraphOp::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(op.op_type, OpType::Attest);
    }

    #[test]
    fn encoding_is_deterministic() {
        let mut rng = OsRng;
        let issuer = SigningKey::generate(&mut rng).verifying_key();
        let subject = SigningKey::generate(&mut rng).verifying_key();
        let op = TrustGraphOp::new_attest(issuer, subject, 1_700_000_000, vec![], vec![]);
        let a = op.to_canonical_cbor().unwrap();
        let b = op.to_canonical_cbor().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn required_capability_mapping() {
        assert_eq!(
            OpType::Attest.required_capability(),
            capabilities::TRUST_GRAPH_ATTEST
        );
        assert_eq!(
            OpType::ReAttest.required_capability(),
            capabilities::TRUST_GRAPH_ATTEST
        );
        assert_eq!(
            OpType::WithdrawRevoke.required_capability(),
            capabilities::TRUST_GRAPH_REVOKE_WITHDRAW
        );
        assert_eq!(
            OpType::CompromiseRevoke.required_capability(),
            capabilities::TRUST_GRAPH_REVOKE_COMPROMISE
        );
    }

    #[test]
    fn domain_tag_value_matches_d0006() {
        assert_eq!(DOMAIN_TAG, b"cairn-v1-trust-graph-operation");
    }

    #[test]
    fn prior_hash_bytes_is_sha256_of_signature_per_d0006_section_5() {
        // D0006 §5: prior_hash := SHA-256(COSE_Sign1.signature_bytes(prior_op))
        // Verify the helper output matches a manual SHA-256 of the
        // envelope's signature.
        use sha2::{Digest as _, Sha256};

        let (op_identity_sk, device_sk, _token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let mut rng = OsRng;
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();
        let op = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![],
            vec![],
        );
        let signed = SignedTrustGraphOp::sign(op, &device_sk).unwrap();

        // Reproduce the hash manually.
        let envelope_bytes = signed.encode(false).unwrap();
        let decoded = SignedTrustGraphOp::from_bytes(&envelope_bytes).unwrap();
        let envelope = CoseSign1::from_bytes(&envelope_bytes).unwrap();
        let expected = Sha256::digest(envelope.signature());

        assert_eq!(decoded.prior_hash_bytes().as_slice(), expected.as_slice());
        assert_eq!(signed.prior_hash_bytes().as_slice(), expected.as_slice());
        assert_eq!(decoded.prior_hash_bytes().len(), PRIOR_HASH_LEN);
    }

    #[test]
    fn signature_does_not_verify_under_wrong_domain_tag() {
        // Sign a trust-graph op (binds the trust-graph-operation tag),
        // then attempt verify with the capability-token tag. Must
        // reject — D0006 §8 cross-protocol substitution defense.
        let (op_identity_sk, device_sk, _token_bytes) =
            make_token_bundle(&[capabilities::TRUST_GRAPH_ATTEST]);
        let mut rng = OsRng;
        let peer_pubkey = SigningKey::generate(&mut rng).verifying_key();
        let op = TrustGraphOp::new_attest(
            op_identity_sk.verifying_key(),
            peer_pubkey,
            1_700_000_000,
            vec![],
            vec![],
        );
        let signed = SignedTrustGraphOp::sign(op, &device_sk).unwrap();
        let bytes = signed.encode(false).unwrap();
        let envelope = CoseSign1::from_bytes(&bytes).unwrap();

        let wrong_tag_result =
            envelope.verify(&device_sk.verifying_key(), b"cairn-v1-capability-token");
        assert!(
            wrong_tag_result.is_err(),
            "trust-graph-op signature must not verify under capability-token tag"
        );
        let no_tag_result = envelope.verify(&device_sk.verifying_key(), b"");
        assert!(
            no_tag_result.is_err(),
            "trust-graph-op signature must not verify under empty AAD"
        );

        // Correct tag verifies — proves the test setup is structurally sound.
        envelope
            .verify(&device_sk.verifying_key(), DOMAIN_TAG)
            .expect("verify must succeed under the trust-graph-operation tag");
    }
}
