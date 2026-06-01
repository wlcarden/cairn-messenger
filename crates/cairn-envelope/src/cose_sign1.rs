// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! `COSE_Sign1` construction + verification per RFC 9052 §4.4.
//!
//! Cairn's envelope uses `COSE_Sign1` as the outer signed wrapper around an
//! AEAD ciphertext (or any opaque payload). This module is the byte-level
//! signer/verifier; it does NOT itself perform AEAD or key agreement.
//! Composing it with [`cairn_crypto::aead`] for the inner payload is the
//! caller's job (the higher-level envelope assembly will live in a
//! separate surface).
//!
//! ## Structure (RFC 9052 §2 + §4.4)
//!
//! ```text
//! COSE_Sign1 = [
//!     protected:   bstr  (canonical-CBOR-encoded protected header map,
//!                         or zero-length bstr if no protected headers)
//!     unprotected: map   (unprotected header map)
//!     payload:     bstr / nil  (the message, or nil for detached
//!                               signatures)
//!     signature:   bstr  (the Ed25519 signature)
//! ]
//! ```
//!
//! Optionally CBOR-tagged with tag 18 (`COSE_Sign1`).
//!
//! ## Signing-input construction
//!
//! Per RFC 9052 §4.4 the signing input is the canonical CBOR encoding of
//! a 4-tuple `Sig_structure`:
//!
//! ```text
//! Sig_structure = [
//!     context:        text   (= "Signature1")
//!     body_protected: bstr   (same protected-header bytes as in COSE_Sign1)
//!     external_aad:   bstr   (caller-supplied AAD; often empty)
//!     payload:        bstr   (the message, even if COSE_Sign1.payload
//!                             carries `nil` for detached signatures)
//! ]
//! ```
//!
//! The `body_protected` field carries the protected-header bytes as a
//! `bstr` (not a re-encoded map). This is structural defense against
//! mauling: an attacker who re-encodes the same logical headers in
//! non-canonical form would change the signing input only via the
//! `protected_bytes` field, which is the original bytes — so the
//! signature still binds to the canonical form.
//!
//! ## Algorithm
//!
//! Cairn fixes `alg = EdDSA` (COSE algorithm `-8`, per RFC 9053 §2.2) in
//! the protected header by default. Future support for additional
//! algorithms requires a coordinated decision (per D0018 §1.1 and
//! D0006 §4) — Cairn does NOT support algorithm agility at v1.
//!
//! ## Decode strategy
//!
//! Decoding parses bytes with `ciborium` (which accepts any well-formed
//! CBOR, canonical or not) and walks the tree into a [`CoseSign1`]. A
//! strict-canonical-input gate (rejecting peer bytes that are not in
//! canonical form) is a separate surface — at v1 we accept and verify
//! per-tuple-field correctness, leaving canonical-input enforcement to
//! the higher-level envelope assembly.

use ciborium::Value as CiboriumValue;

use cairn_crypto::ed25519::{SIGNATURE_LEN, Signature, SigningKey, VerifyingKey};

use crate::canonical::Value;
use crate::error::EnvelopeError;

/// COSE algorithm label for `EdDSA` per RFC 9053 §2.2.
pub const COSE_ALG_EDDSA: i64 = -8;

/// COSE common-header label for `alg` per RFC 9052 §3.1.
pub const COSE_HEADER_ALG: i64 = 1;

/// COSE common-header label for `kid` per RFC 9052 §3.1.
pub const COSE_HEADER_KID: i64 = 4;

/// CBOR tag value for `COSE_Sign1` per RFC 9052 §2.
pub const COSE_SIGN1_TAG: u64 = 18;

/// Context string for the `COSE_Sign1` `Sig_structure` per RFC 9052 §4.4.
pub const SIGNATURE1_CONTEXT: &str = "Signature1";

/// Builder for a [`CoseSign1`] envelope.
///
/// Defaults to `alg = EdDSA` in the protected header. Add a `kid` via
/// [`Self::with_kid`] (unprotected header per RFC 9052 §3.1) before
/// finalizing.
pub struct Sign1Builder {
    protected_headers: Vec<(Value, Value)>,
    unprotected_headers: Vec<(Value, Value)>,
    payload: Option<Vec<u8>>,
    external_aad: Vec<u8>,
}

impl Default for Sign1Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Sign1Builder {
    /// Construct a new builder with `alg = EdDSA` in the protected header.
    #[must_use]
    pub fn new() -> Self {
        Self {
            protected_headers: vec![(Value::Int(COSE_HEADER_ALG), Value::Int(COSE_ALG_EDDSA))],
            unprotected_headers: Vec::new(),
            payload: None,
            external_aad: Vec::new(),
        }
    }

    /// Add a `kid` (key identifier) to the unprotected header.
    ///
    /// Per RFC 9052 §3.1: `kid` is conventionally an unprotected header so
    /// it can be inspected by the recipient before signature verification
    /// to select the right verifying key.
    #[must_use]
    pub fn with_kid(mut self, kid: Vec<u8>) -> Self {
        self.unprotected_headers
            .push((Value::Int(COSE_HEADER_KID), Value::Bytes(kid)));
        self
    }

    /// Set the payload to be signed and carried inside the envelope.
    ///
    /// If never called, the envelope is constructed with payload = `nil`
    /// (a detached signature, where the payload is conveyed
    /// out-of-band).
    #[must_use]
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Set the external additional authenticated data (AAD).
    ///
    /// Per RFC 9052 §4.4: `external_aad` is mixed into the signing input
    /// but NOT carried in the envelope bytes. Both signer and verifier
    /// must agree on its value out-of-band.
    #[must_use]
    pub fn with_external_aad(mut self, aad: Vec<u8>) -> Self {
        self.external_aad = aad;
        self
    }

    /// Finalize the envelope by signing it in-process with `signing_key`.
    ///
    /// For hardware-backed signers where the private key never enters the
    /// process (Android `StrongBox` per D0020 §3.4), use
    /// [`Self::signing_input`] + [`Self::finalize_with_signature`] instead.
    /// This method is exactly those two composed with an in-process Ed25519
    /// sign, so all three produce byte-identical envelopes for the same key
    /// and builder state (the equivalence is regression-tested by the
    /// test `external_signer_path_matches_finalize`).
    ///
    /// # Errors
    ///
    /// - [`EnvelopeError::CoseSign1SignFailed`] if the underlying Ed25519
    ///   signing operation fails (typically because the canonical-CBOR
    ///   signing input exceeds `cairn-crypto`'s payload-size limit).
    /// - [`EnvelopeError::CanonicalCborDuplicateMapKey`] from the
    ///   canonical encoder (unreachable when only the default headers
    ///   are populated; possible if a caller-injected variant adds
    ///   duplicate keys).
    pub fn finalize(self, signing_key: &SigningKey) -> Result<CoseSign1, EnvelopeError> {
        let tbs = self.signing_input()?;
        let signature = signing_key
            .sign(&tbs)
            .map_err(|_| EnvelopeError::CoseSign1SignFailed)?;
        self.finalize_with_signature(&signature.to_bytes())
    }

    /// Compute the `COSE_Sign1` signing input — the canonical-CBOR
    /// `Sig_structure` bytes per RFC 9052 §4.4 — for the builder's current
    /// payload + external AAD + protected headers, WITHOUT signing.
    ///
    /// These are the bytes an external signer (e.g. an Android `StrongBox`
    /// `HardwareKeySigner` per D0020 §3.4) signs with the device key; pair
    /// the returned signature with [`Self::finalize_with_signature`] to
    /// assemble the envelope. The builder MUST NOT be mutated between the
    /// two calls, or the signature will not match the assembled envelope.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::CanonicalCborDuplicateMapKey`] (or another canonical
    /// encoder error) from encoding the protected headers / `Sig_structure`
    /// — unreachable for builders using only the defaults + at most one
    /// `kid`.
    pub fn signing_input(&self) -> Result<Vec<u8>, EnvelopeError> {
        let protected_bytes = self.protected_bytes()?;
        build_sig_structure(
            &protected_bytes,
            &self.external_aad,
            self.payload.as_deref().unwrap_or(&[]),
        )
    }

    /// Assemble the finalized envelope from an externally-produced Ed25519
    /// `signature` over [`Self::signing_input`].
    ///
    /// `signature` MUST be over the exact bytes [`Self::signing_input`]
    /// returned for this builder's state. This is the hardware-signer
    /// counterpart to [`Self::finalize`]: the device key signs the signing
    /// input out-of-process (`StrongBox` per D0020 §3.4) and only the 64-byte
    /// signature crosses back into the process — the key itself never does.
    ///
    /// # Errors
    ///
    /// - [`EnvelopeError::CoseSign1InvalidSignatureLength`] if `signature`
    ///   is not exactly [`SIGNATURE_LEN`] (64) bytes.
    /// - [`EnvelopeError::CanonicalCborDuplicateMapKey`] from re-encoding
    ///   the protected headers (unreachable for default builders).
    pub fn finalize_with_signature(self, signature: &[u8]) -> Result<CoseSign1, EnvelopeError> {
        if signature.len() != SIGNATURE_LEN {
            return Err(EnvelopeError::CoseSign1InvalidSignatureLength {
                got_bytes: signature.len(),
                expected_bytes: SIGNATURE_LEN,
            });
        }
        let protected_bytes = self.protected_bytes()?;
        Ok(CoseSign1 {
            protected_bytes,
            unprotected_headers: self.unprotected_headers,
            payload: self.payload,
            signature: signature.to_vec(),
        })
    }

    /// Canonical-CBOR-encode the protected headers.
    ///
    /// Per RFC 9052 §4.4 + §3: an empty protected-header map MUST encode as
    /// a zero-length bstr (NOT `0xa0` for an empty map). Cairn always
    /// inserts `alg`, so the empty branch is currently unreachable — kept
    /// for forward-compat if callers ever construct builders without `alg`.
    fn protected_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        if self.protected_headers.is_empty() {
            Ok(Vec::new())
        } else {
            Value::Map(self.protected_headers.clone()).encode()
        }
    }
}

/// A finalized `COSE_Sign1` envelope.
///
/// Construct via [`Sign1Builder::finalize`] or [`CoseSign1::from_bytes`].
/// Encode via [`Self::encode`]; verify via [`Self::verify`].
#[derive(Debug, Clone)]
pub struct CoseSign1 {
    protected_bytes: Vec<u8>,
    unprotected_headers: Vec<(Value, Value)>,
    payload: Option<Vec<u8>>,
    signature: Vec<u8>,
}

impl CoseSign1 {
    /// Encode this envelope as canonical CBOR.
    ///
    /// If `tagged` is true the output is wrapped in CBOR tag 18
    /// ([`COSE_SIGN1_TAG`]); otherwise the bare 4-tuple is emitted.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::CanonicalCborDuplicateMapKey`] if the
    /// unprotected headers contain duplicate canonical-encoded keys
    /// (unreachable for builders constructed via [`Sign1Builder`] using
    /// only the defaults + at most one `kid`).
    pub fn encode(&self, tagged: bool) -> Result<Vec<u8>, EnvelopeError> {
        let payload_value = self
            .payload
            .as_ref()
            .map_or(Value::Null, |p| Value::Bytes(p.clone()));
        let inner = Value::Array(vec![
            Value::Bytes(self.protected_bytes.clone()),
            Value::Map(self.unprotected_headers.clone()),
            payload_value,
            Value::Bytes(self.signature.clone()),
        ]);
        let inner_bytes = inner.encode()?;

        if tagged {
            // CBOR tag head: major 6, argument 18. Since 18 ≤ 23, the
            // argument fits in the low 5 bits of the head byte.
            let tag_head: u8 = (6 << 5) | 18;
            // `saturating_add` on the capacity hint avoids the
            // `arithmetic_side_effects` lint without affecting correctness:
            // if `inner_bytes.len() == usize::MAX` (impossible in practice),
            // the saturated value is still a valid (slightly lower) capacity
            // hint; `Vec` will reallocate as needed.
            let mut out = Vec::with_capacity(inner_bytes.len().saturating_add(1));
            out.push(tag_head);
            out.extend_from_slice(&inner_bytes);
            Ok(out)
        } else {
            Ok(inner_bytes)
        }
    }

    /// Verify the envelope's signature using `verifying_key` and the same
    /// `external_aad` used at construction.
    ///
    /// # Errors
    ///
    /// - [`EnvelopeError::CoseSign1InvalidSignatureLength`] if the
    ///   signature field is not exactly 64 bytes (the Ed25519 signature
    ///   length).
    /// - [`EnvelopeError::CoseSign1VerifyFailed`] if the signature does
    ///   not verify (uniform across all crypto-layer failure modes per
    ///   the no-error-oracle discipline from D0006 / D0018 §1.4).
    /// - [`EnvelopeError::CanonicalCborDuplicateMapKey`] from re-encoding
    ///   the `Sig_structure` (unreachable for normal use).
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        external_aad: &[u8],
    ) -> Result<(), EnvelopeError> {
        if self.signature.len() != SIGNATURE_LEN {
            return Err(EnvelopeError::CoseSign1InvalidSignatureLength {
                got_bytes: self.signature.len(),
                expected_bytes: SIGNATURE_LEN,
            });
        }
        let sig_array: [u8; SIGNATURE_LEN] =
            self.signature.as_slice().try_into().map_err(|_| {
                EnvelopeError::CoseSign1InvalidSignatureLength {
                    got_bytes: self.signature.len(),
                    expected_bytes: SIGNATURE_LEN,
                }
            })?;
        let sig = Signature::from_bytes(sig_array);

        let tbs = build_sig_structure(
            &self.protected_bytes,
            external_aad,
            self.payload.as_deref().unwrap_or(&[]),
        )?;

        verifying_key
            .verify(&tbs, &sig)
            .map_err(|_| EnvelopeError::CoseSign1VerifyFailed)
    }

    /// Decode a `COSE_Sign1` envelope from bytes.
    ///
    /// Accepts both tagged (with [`COSE_SIGN1_TAG`]) and untagged forms.
    /// Uses `ciborium` to parse the outer CBOR structure; strict
    /// canonical-input checking is intentionally NOT performed here —
    /// callers requiring it can re-encode via [`Self::encode`] and
    /// compare byte-for-byte to the input.
    ///
    /// # Errors
    ///
    /// - [`EnvelopeError::CoseSign1MalformedCbor`] if the bytes are not
    ///   well-formed CBOR or do not match the `COSE_Sign1` 4-tuple
    ///   structure.
    /// - [`EnvelopeError::CoseSign1IntegerOutOfRange`] if a header map
    ///   contains an integer outside the `i64` range.
    /// - [`EnvelopeError::CoseSign1UnsupportedCborType`] if a header
    ///   value uses a CBOR type not in the canonical [`Value`] AST
    ///   (floats, big-int tags, etc.).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let parsed: CiboriumValue =
            ciborium::de::from_reader(bytes).map_err(|_| EnvelopeError::CoseSign1MalformedCbor)?;

        // Unwrap optional COSE_Sign1 tag (18).
        let array = match parsed {
            CiboriumValue::Tag(tag, inner) if tag == COSE_SIGN1_TAG => match *inner {
                CiboriumValue::Array(a) => a,
                _ => return Err(EnvelopeError::CoseSign1MalformedCbor),
            },
            CiboriumValue::Array(a) => a,
            _ => return Err(EnvelopeError::CoseSign1MalformedCbor),
        };

        if array.len() != 4 {
            return Err(EnvelopeError::CoseSign1MalformedCbor);
        }
        // Destructure exactly the 4 tuple positions per RFC 9052.
        let mut iter = array.into_iter();
        // Safe `unwrap`-free extraction via `.next()` + the length check.
        let protected_raw = iter.next().ok_or(EnvelopeError::CoseSign1MalformedCbor)?;
        let unprotected_raw = iter.next().ok_or(EnvelopeError::CoseSign1MalformedCbor)?;
        let payload_raw = iter.next().ok_or(EnvelopeError::CoseSign1MalformedCbor)?;
        let signature_raw = iter.next().ok_or(EnvelopeError::CoseSign1MalformedCbor)?;

        let CiboriumValue::Bytes(protected_bytes) = protected_raw else {
            return Err(EnvelopeError::CoseSign1MalformedCbor);
        };

        let CiboriumValue::Map(unprotected_entries) = unprotected_raw else {
            return Err(EnvelopeError::CoseSign1MalformedCbor);
        };
        let unprotected_headers: Vec<(Value, Value)> = unprotected_entries
            .into_iter()
            .map(|(k, v)| Ok((ciborium_to_value(&k)?, ciborium_to_value(&v)?)))
            .collect::<Result<Vec<_>, EnvelopeError>>()?;

        let payload = match payload_raw {
            CiboriumValue::Bytes(b) => Some(b),
            CiboriumValue::Null => None,
            _ => return Err(EnvelopeError::CoseSign1MalformedCbor),
        };

        let CiboriumValue::Bytes(signature) = signature_raw else {
            return Err(EnvelopeError::CoseSign1MalformedCbor);
        };

        Ok(Self {
            protected_bytes,
            unprotected_headers,
            payload,
            signature,
        })
    }

    /// Return the envelope's payload bytes, if any.
    #[must_use]
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    /// Return the envelope's unprotected header entries.
    #[must_use]
    pub fn unprotected_headers(&self) -> &[(Value, Value)] {
        &self.unprotected_headers
    }

    /// Return the canonical-CBOR-encoded protected header bytes.
    ///
    /// May be zero-length when no protected headers are present.
    #[must_use]
    pub fn protected_bytes(&self) -> &[u8] {
        &self.protected_bytes
    }

    /// Return the raw signature bytes.
    ///
    /// 64 bytes for Ed25519; the [`Self::verify`] entry point performs
    /// the length check, so callers reading this for diagnostic purposes
    /// should not rely on the length without re-checking.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Return the canonical-CBOR-encoded `Sig_structure` bytes per
    /// RFC 9052 §4.4 for the given `external_aad`.
    ///
    /// The `Sig_structure` is the byte string the signature commits
    /// to (its content under canonical CBOR encoding is exactly what
    /// `verify` reconstructs and `finalize` signs). Callers need
    /// these bytes for protocol-level hash-of-attestation
    /// constructions per D0006 §7 (e.g., `issuer_cert_hash :=
    /// SHA-256( deterministic_cbor_encode( Sig_structure ) )`).
    ///
    /// The `external_aad` argument must match the value bound at
    /// sign time — `CoseSign1` does not store the AAD (it's external
    /// to the wire format) so the caller supplies it. For Cairn's
    /// protocol crates the AAD is the crate-level `DOMAIN_TAG`
    /// constant per D0006 §8.
    ///
    /// # Errors
    ///
    /// Propagates [`EnvelopeError`] from the canonical encoder
    /// (unreachable for envelopes constructed via [`Sign1Builder::finalize`]
    /// or [`Self::from_bytes`]).
    pub fn sig_structure_bytes(&self, external_aad: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        build_sig_structure(
            &self.protected_bytes,
            external_aad,
            self.payload.as_deref().unwrap_or(&[]),
        )
    }
}

/// Build the canonical CBOR `Sig_structure` bytes per RFC 9052 §4.4.
///
/// Used at both finalize-time (in [`Sign1Builder::finalize`]) and
/// verify-time (in [`CoseSign1::verify`]) to produce the same byte
/// string that the signature commits to.
fn build_sig_structure(
    protected_bytes: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let sig_structure = Value::Array(vec![
        Value::Text(SIGNATURE1_CONTEXT.to_string()),
        Value::Bytes(protected_bytes.to_vec()),
        Value::Bytes(external_aad.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]);
    sig_structure.encode()
}

/// Convert a `ciborium::Value` into our canonical [`Value`] AST.
///
/// Used by [`CoseSign1::from_bytes`] to lift the unprotected header map
/// (the only place where header values pass through our canonical
/// representation; protected headers stay as raw bytes per RFC 9052
/// `Sig_structure` discipline).
fn ciborium_to_value(v: &CiboriumValue) -> Result<Value, EnvelopeError> {
    match v {
        CiboriumValue::Null => Ok(Value::Null),
        CiboriumValue::Bool(b) => Ok(Value::Bool(*b)),
        CiboriumValue::Integer(i) => {
            let as_i128: i128 = (*i).into();
            let as_i64 =
                i64::try_from(as_i128).map_err(|_| EnvelopeError::CoseSign1IntegerOutOfRange)?;
            Ok(Value::Int(as_i64))
        }
        CiboriumValue::Bytes(b) => Ok(Value::Bytes(b.clone())),
        CiboriumValue::Text(t) => Ok(Value::Text(t.clone())),
        CiboriumValue::Array(a) => {
            let items: Result<Vec<_>, _> = a.iter().map(ciborium_to_value).collect();
            Ok(Value::Array(items?))
        }
        CiboriumValue::Map(m) => {
            let entries: Result<Vec<_>, EnvelopeError> = m
                .iter()
                .map(|(k, v)| Ok((ciborium_to_value(k)?, ciborium_to_value(v)?)))
                .collect();
            Ok(Value::Map(entries?))
        }
        // Floats, big-ints (tags 2/3), other tags, and undefined are
        // intentionally excluded from the canonical Value AST.
        _ => Err(EnvelopeError::CoseSign1UnsupportedCborType),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use rand_core::OsRng;

    fn fresh_key() -> SigningKey {
        let mut rng = OsRng;
        SigningKey::generate(&mut rng)
    }

    #[test]
    fn sign_and_verify_round_trip_payload() {
        let sk = fresh_key();
        let vk = sk.verifying_key();

        let envelope = Sign1Builder::new()
            .with_payload(b"hello cose".to_vec())
            .finalize(&sk)
            .expect("finalize should succeed");

        envelope
            .verify(&vk, b"")
            .expect("verify should succeed with empty external AAD");
    }

    #[test]
    fn external_signer_path_matches_finalize() {
        // The external-signer path (signing_input + finalize_with_signature)
        // must produce a byte-identical envelope to the in-process
        // finalize(&key) for the same key + builder state. Ed25519 is
        // deterministic (RFC 8032), so the signatures — and thus the whole
        // encoded envelopes — are equal. This is the guarantee that lets a
        // `StrongBox` HardwareKeySigner (D0020 §3.4) substitute for an
        // in-process key without changing the wire bytes.
        let sk = fresh_key();
        let vk = sk.verifying_key();
        let payload = b"external signer parity".to_vec();
        let aad = b"cairn-v1-message-envelope".to_vec();

        let direct = Sign1Builder::new()
            .with_payload(payload.clone())
            .with_external_aad(aad.clone())
            .finalize(&sk)
            .unwrap();

        // The external path: get the signing input, sign it out-of-band
        // (here with the same key, standing in for the hardware signer),
        // then inject the resulting signature.
        let builder = Sign1Builder::new()
            .with_payload(payload)
            .with_external_aad(aad.clone());
        let signing_input = builder.signing_input().unwrap();
        let signature = sk.sign(&signing_input).unwrap();
        let external = builder
            .finalize_with_signature(&signature.to_bytes())
            .unwrap();

        assert_eq!(
            direct.encode(true).unwrap(),
            external.encode(true).unwrap(),
            "external-signer path must be byte-identical to finalize(&key)"
        );
        external
            .verify(&vk, &aad)
            .expect("externally-signed envelope must verify");
    }

    #[test]
    fn finalize_with_signature_rejects_wrong_length() {
        // A signature that is not exactly 64 bytes is rejected at assembly
        // (the same length guard verify() applies), so a malformed
        // hardware-signer return cannot yield a structurally-invalid
        // envelope.
        let builder = Sign1Builder::new().with_payload(b"x".to_vec());
        let result = builder.finalize_with_signature(&[0u8; 32]);
        assert!(matches!(
            result,
            Err(EnvelopeError::CoseSign1InvalidSignatureLength {
                got_bytes: 32,
                expected_bytes: 64
            })
        ));
    }

    #[test]
    fn sign_and_verify_with_kid() {
        let sk = fresh_key();
        let vk = sk.verifying_key();

        let envelope = Sign1Builder::new()
            .with_kid(b"key-id-123".to_vec())
            .with_payload(b"signed with kid".to_vec())
            .finalize(&sk)
            .unwrap();

        envelope.verify(&vk, b"").expect("verify should succeed");
        // kid is in unprotected headers (RFC 9052 §3.1 convention).
        let kid_entry = envelope
            .unprotected_headers()
            .iter()
            .find(|(k, _)| *k == Value::Int(COSE_HEADER_KID))
            .expect("kid header should be present");
        assert_eq!(kid_entry.1, Value::Bytes(b"key-id-123".to_vec()));
    }

    #[test]
    fn sign_and_verify_with_external_aad() {
        let sk = fresh_key();
        let vk = sk.verifying_key();
        let aad = b"v1|channel:abc".to_vec();

        let envelope = Sign1Builder::new()
            .with_payload(b"aad-bound payload".to_vec())
            .with_external_aad(aad.clone())
            .finalize(&sk)
            .unwrap();

        // Correct AAD verifies.
        envelope.verify(&vk, &aad).expect("verify with correct AAD");
        // Wrong AAD fails.
        let result = envelope.verify(&vk, b"different aad");
        assert!(matches!(result, Err(EnvelopeError::CoseSign1VerifyFailed)));
    }

    #[test]
    fn detached_signature_round_trip() {
        // No payload set → COSE_Sign1.payload = nil. Verify must still
        // succeed when external_aad reconstructs the same Sig_structure.
        let sk = fresh_key();
        let vk = sk.verifying_key();

        let envelope = Sign1Builder::new().finalize(&sk).unwrap();
        envelope
            .verify(&vk, b"")
            .expect("verify detached should succeed");
        assert!(envelope.payload().is_none());
    }

    #[test]
    fn wrong_key_verify_fails() {
        let sk_a = fresh_key();
        let sk_b = fresh_key();

        let envelope = Sign1Builder::new()
            .with_payload(b"hello".to_vec())
            .finalize(&sk_a)
            .unwrap();

        let result = envelope.verify(&sk_b.verifying_key(), b"");
        assert!(matches!(result, Err(EnvelopeError::CoseSign1VerifyFailed)));
    }

    #[test]
    fn tampered_payload_verify_fails() {
        let sk = fresh_key();
        let vk = sk.verifying_key();

        let mut envelope = Sign1Builder::new()
            .with_payload(b"original payload".to_vec())
            .finalize(&sk)
            .unwrap();

        // Tamper with the payload field directly.
        envelope.payload = Some(b"tampered payload".to_vec());

        let result = envelope.verify(&vk, b"");
        assert!(matches!(result, Err(EnvelopeError::CoseSign1VerifyFailed)));
    }

    #[test]
    // `indexing_slicing` allowed: `finalize()` produces a full 64-byte
    // Ed25519 signature, so `signature[0]` is statically safe.
    #[allow(clippy::indexing_slicing)]
    fn tampered_signature_verify_fails() {
        let sk = fresh_key();
        let vk = sk.verifying_key();

        let mut envelope = Sign1Builder::new()
            .with_payload(b"hello".to_vec())
            .finalize(&sk)
            .unwrap();

        // Flip a bit in the signature.
        envelope.signature[0] ^= 0x01;

        let result = envelope.verify(&vk, b"");
        assert!(matches!(result, Err(EnvelopeError::CoseSign1VerifyFailed)));
    }

    #[test]
    fn truncated_signature_rejected() {
        let sk = fresh_key();
        let vk = sk.verifying_key();

        let mut envelope = Sign1Builder::new()
            .with_payload(b"hello".to_vec())
            .finalize(&sk)
            .unwrap();

        envelope.signature.pop();

        let result = envelope.verify(&vk, b"");
        assert!(matches!(
            result,
            Err(EnvelopeError::CoseSign1InvalidSignatureLength {
                got_bytes: 63,
                expected_bytes: 64
            })
        ));
    }

    #[test]
    fn encode_decode_round_trip_untagged() {
        let sk = fresh_key();
        let vk = sk.verifying_key();

        let original = Sign1Builder::new()
            .with_kid(b"my-key".to_vec())
            .with_payload(b"round-trip payload".to_vec())
            .finalize(&sk)
            .unwrap();

        let bytes = original.encode(false).unwrap();
        let decoded = CoseSign1::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.protected_bytes(), original.protected_bytes());
        assert_eq!(decoded.payload(), original.payload());
        assert_eq!(decoded.signature(), original.signature());
        decoded
            .verify(&vk, b"")
            .expect("decoded verify should succeed");
    }

    #[test]
    // `indexing_slicing` allowed: `encode(true)` always emits at least
    // one byte (the tag head); `bytes[0]` is statically safe.
    #[allow(clippy::indexing_slicing)]
    fn encode_decode_round_trip_tagged() {
        let sk = fresh_key();
        let vk = sk.verifying_key();

        let original = Sign1Builder::new()
            .with_payload(b"tagged round-trip".to_vec())
            .finalize(&sk)
            .unwrap();

        let bytes = original.encode(true).unwrap();
        // First byte must be the COSE_Sign1 tag head (major 6, value 18).
        assert_eq!(bytes[0], (6 << 5) | 18);

        let decoded = CoseSign1::from_bytes(&bytes).unwrap();
        decoded
            .verify(&vk, b"")
            .expect("decoded-from-tagged verify should succeed");
    }

    #[test]
    fn encode_is_deterministic() {
        // Encoding the same finalized envelope twice produces identical
        // bytes (the canonical-encoder property propagated through the
        // outer COSE structure).
        let sk = fresh_key();
        let envelope = Sign1Builder::new()
            .with_kid(b"k".to_vec())
            .with_payload(b"determinism test".to_vec())
            .finalize(&sk)
            .unwrap();

        let a = envelope.encode(false).unwrap();
        let b = envelope.encode(false).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn malformed_bytes_decode_fails() {
        // Random bytes that aren't well-formed CBOR.
        let result = CoseSign1::from_bytes(b"\xff\x00\x01\x02");
        assert!(matches!(result, Err(EnvelopeError::CoseSign1MalformedCbor)));
    }

    #[test]
    fn wrong_arity_array_decode_fails() {
        // 3-element array is not a valid COSE_Sign1 structure.
        let three_element_array =
            Value::Array(vec![Value::Bytes(vec![]), Value::Map(vec![]), Value::Null])
                .encode()
                .unwrap();

        let result = CoseSign1::from_bytes(&three_element_array);
        assert!(matches!(result, Err(EnvelopeError::CoseSign1MalformedCbor)));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use proptest::prelude::*;
    use rand_core::OsRng;

    proptest! {
        /// Property: round-trip survives any payload up to a bounded size.
        /// Build → encode → decode → verify must always succeed.
        #[test]
        fn prop_round_trip_random_payload(
            payload in proptest::collection::vec(any::<u8>(), 0..4096),
            kid in proptest::collection::vec(any::<u8>(), 0..32),
            aad in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let mut rng = OsRng;
            let sk = SigningKey::generate(&mut rng);
            let vk = sk.verifying_key();

            let mut builder = Sign1Builder::new()
                .with_payload(payload.clone())
                .with_external_aad(aad.clone());
            if !kid.is_empty() {
                builder = builder.with_kid(kid);
            }

            let envelope = builder.finalize(&sk).unwrap();
            let bytes = envelope.encode(true).unwrap();
            let decoded = CoseSign1::from_bytes(&bytes).unwrap();

            prop_assert_eq!(decoded.payload(), Some(payload.as_slice()));
            decoded.verify(&vk, &aad).unwrap();
        }

        /// Property: any single-bit tamper of the envelope payload causes
        /// verification to fail.
        ///
        /// `arithmetic_side_effects` / `indexing_slicing` allowed:
        /// `tamper_index % payload.len()` is well-defined because
        /// `payload.len() >= 1` by the strategy bound; the resulting
        /// index is in-range by construction.
        #[test]
        #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
        fn prop_payload_tamper_fails_verify(
            payload in proptest::collection::vec(any::<u8>(), 1..256),
            tamper_index in 0usize..1024,
            tamper_mask in 1u8..=255u8,
        ) {
            let mut rng = OsRng;
            let sk = SigningKey::generate(&mut rng);
            let vk = sk.verifying_key();

            let mut envelope = Sign1Builder::new()
                .with_payload(payload.clone())
                .finalize(&sk)
                .unwrap();

            // Tamper the in-memory payload (the on-wire bytes would
            // similarly fail to decode + verify). Consume the original
            // `payload` here — it is not used again in this case.
            let mut new_payload = payload;
            let idx = tamper_index % new_payload.len();
            new_payload[idx] ^= tamper_mask;
            envelope.payload = Some(new_payload);

            let result = envelope.verify(&vk, b"");
            prop_assert!(matches!(result, Err(EnvelopeError::CoseSign1VerifyFailed)));
        }
    }
}

/// Cross-implementation interop tests.
///
/// Per D0018 §2.5 + D0021 §2.3: the canonical `COSE_Sign1` bytes Cairn
/// emits must decode and verify correctly through an independent COSE
/// implementation. The full D0018 §2.4 reference is
/// `veraison/go-cose` (Go); coset 0.4.2 plays the Rust-side oracle
/// role per D0021 §2.3 — both must agree that Cairn-emitted bytes are
/// well-formed `COSE_Sign1` envelopes with valid signatures.
///
/// The Go-side `veraison/go-cose` check is deferred until the Go
/// toolchain is set up in CI; the harness will read fixture files
/// emitted from a future `cairn-envelope` example binary. Until
/// then, the coset cross-check below provides the v1 interop
/// evidence at the Rust side.
#[cfg(test)]
mod interop_tests {
    use super::*;
    use cairn_crypto::ed25519::{SIGNATURE_LEN, Signature, SigningKey, VerifyingKey};
    use coset::{CborSerializable, CoseSign1 as CosetCoseSign1};
    use rand_core::OsRng;

    /// Verify a Cairn signature using `coset`'s `verify_signature`
    /// closure pattern. Returns `Ok(())` on success, `Err(())` on
    /// any verification failure (uniform, matching `coset`'s API
    /// shape).
    fn coset_verify_with_cairn_key(
        sig_bytes: &[u8],
        tbs_bytes: &[u8],
        vk: &VerifyingKey,
    ) -> Result<(), ()> {
        let sig_array: [u8; SIGNATURE_LEN] = sig_bytes.try_into().map_err(|_| ())?;
        let signature = Signature::from_bytes(sig_array);
        vk.verify(tbs_bytes, &signature).map_err(|_| ())
    }

    #[test]
    fn cairn_emitted_bytes_decode_via_coset_and_verify_signature() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let envelope = Sign1Builder::new()
            .with_payload(b"interop test payload".to_vec())
            .finalize(&sk)
            .expect("Cairn finalize should succeed");

        let bytes = envelope.encode(false).expect("Cairn encode should succeed");

        // Decode via coset.
        let coset_envelope =
            CosetCoseSign1::from_slice(&bytes).expect("coset should decode Cairn bytes");

        // Verify via coset's verify_signature closure, using
        // ed25519-dalek (through cairn-crypto's wrapper) inside.
        coset_envelope
            .verify_signature(b"", |sig, tbs| coset_verify_with_cairn_key(sig, tbs, &vk))
            .expect("coset should verify Cairn-emitted signature");
    }

    #[test]
    fn cairn_emitted_tagged_bytes_decode_via_coset() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let envelope = Sign1Builder::new()
            .with_payload(b"tagged interop payload".to_vec())
            .finalize(&sk)
            .unwrap();

        let bytes = envelope.encode(true).unwrap();

        // Tagged form: coset's `from_tagged_slice` strips the
        // outer CBOR tag 18 then decodes the inner 4-tuple.
        let coset_envelope =
            <CosetCoseSign1 as coset::TaggedCborSerializable>::from_tagged_slice(&bytes)
                .expect("coset should decode Cairn tagged bytes");

        coset_envelope
            .verify_signature(b"", |sig, tbs| coset_verify_with_cairn_key(sig, tbs, &vk))
            .expect("coset should verify Cairn-emitted tagged signature");
    }

    #[test]
    fn cairn_emitted_bytes_with_kid_decode_via_coset() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();
        let kid = b"interop-kid-v1".to_vec();

        let envelope = Sign1Builder::new()
            .with_kid(kid.clone())
            .with_payload(b"interop payload with kid".to_vec())
            .finalize(&sk)
            .unwrap();

        let bytes = envelope.encode(false).unwrap();

        let coset_envelope =
            CosetCoseSign1::from_slice(&bytes).expect("coset should decode Cairn+kid bytes");

        // Coset should see the kid in the unprotected header.
        let coset_kid_label = coset::Label::Int(crate::cose_sign1::COSE_HEADER_KID);
        let kid_value = coset_envelope
            .unprotected
            .rest
            .iter()
            .find(|(label, _)| *label == coset_kid_label)
            .map(|(_, v)| v.clone());
        // Coset stores the kid as either ciborium::Value::Bytes in
        // `rest` (older versions) or the typed `unprotected.key_id`
        // field (newer versions). Check both for robustness.
        let key_id_field = coset_envelope.unprotected.key_id.clone();
        let kid_recovered: Vec<u8> = if let Some(ciborium::Value::Bytes(b)) = kid_value {
            b
        } else {
            key_id_field
        };
        assert!(
            !kid_recovered.is_empty(),
            "coset should expose Cairn-emitted kid"
        );
        assert_eq!(kid_recovered, kid);

        coset_envelope
            .verify_signature(b"", |sig, tbs| coset_verify_with_cairn_key(sig, tbs, &vk))
            .expect("coset should verify Cairn+kid signature");
    }

    #[test]
    fn tampered_cairn_bytes_fail_coset_verify() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let envelope = Sign1Builder::new()
            .with_payload(b"interop tamper test".to_vec())
            .finalize(&sk)
            .unwrap();
        let mut bytes = envelope.encode(false).unwrap();

        // Tamper at mid-bytes. Any of:
        //  - CBOR structure → coset decode fails
        //  - payload bytes → signature verify fails (Sig_structure
        //    no longer matches the original signing input)
        //  - signature bytes → signature verify fails
        let mid = bytes.len() / 2;
        // `indexing_slicing` allowed: `encode()` always returns a
        // non-empty Vec for finalized envelopes.
        #[allow(clippy::indexing_slicing)]
        {
            bytes[mid] ^= 0x01;
        }

        // Either decode fails OR verify fails — both are valid
        // outcomes for a tampered envelope. We check that no
        // pass-through verification succeeds.
        if let Ok(coset_envelope) = CosetCoseSign1::from_slice(&bytes) {
            let verify_result: Result<(), ()> = coset_envelope
                .verify_signature(b"", |sig, tbs| coset_verify_with_cairn_key(sig, tbs, &vk));
            assert!(
                verify_result.is_err(),
                "tampered envelope should not pass coset verification"
            );
        }
        // If coset's `from_slice` failed, that's also a valid outcome.
    }
}
