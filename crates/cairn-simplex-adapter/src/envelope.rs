// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Cairn message envelope per D0026 §2.
//!
//! ## Schema (integer-keyed canonical-CBOR map per D0018 §2.3)
//!
//! | Key | Field                            | CBOR type      | Notes |
//! |-----|----------------------------------|----------------|-------|
//! | 1   | `version`                        | uint           | v1 = 1 |
//! | 2   | `sender_operational_pubkey`      | bstr (32)      | D0006 §9 |
//! | 3   | `recipient_operational_pubkey`   | bstr (32)      | D0006 §9 |
//! | 4   | `timestamp`                      | uint           | Unix-seconds |
//! | 5   | `prior_envelope_hash`            | bstr           | Empty for first envelope; SHA-256 of prior envelope signature otherwise |
//! | 6   | `payload`                        | bstr           | Application-level payload |
//! | 7   | `padding`                        | bstr           | Per D0026 §4 size-bin padding |
//!
//! ## Signing model
//!
//! The encoded canonical-CBOR map is the `COSE_Sign1` payload per
//! D0018 §2.1, signed with the device key per D0006 §9 hop #1 with
//! AAD = [`DOMAIN_TAG`] per D0006 §8.
//!
//! ## Chain integrity property (D0026 §2.3)
//!
//! `prior_envelope_hash` = `SHA-256(prior envelope's COSE_Sign1
//! signature bytes)` per the same composition D0023 §1 + D0024 §5
//! use for leaf hashes. A recipient observing the per-sender chain
//! can detect gaps or substitutions by walking the hash chain.

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, SIGNATURE_LEN, SigningKey, VerifyingKey};
use cairn_envelope::canonical::Value;
use cairn_envelope::cose_sign1::{CoseSign1, Sign1Builder};
use ciborium::Value as CiboriumValue;
use sha2::{Digest, Sha256};

use crate::error::SimplexAdapterError;

/// AAD domain tag per D0006 §8.
///
/// Bound at every signing + verifying call so a Cairn message
/// envelope signature CANNOT be re-applied as a trust-graph op,
/// master attestation, capability token, or release manifest.
/// Cross-protocol substitution attempts surface as
/// [`SimplexAdapterError::EnvelopeDomainTagMismatch`].
pub const DOMAIN_TAG: &[u8] = b"cairn-v1-message-envelope";

/// Envelope schema version this build emits. v1 = 1.
pub const ENVELOPE_SCHEMA_VERSION: u64 = 1;

// === Canonical-CBOR map keys ===
const KEY_VERSION: i64 = 1;
const KEY_SENDER_PUBKEY: i64 = 2;
const KEY_RECIPIENT_PUBKEY: i64 = 3;
const KEY_TIMESTAMP: i64 = 4;
const KEY_PRIOR_ENVELOPE_HASH: i64 = 5;
const KEY_PAYLOAD: i64 = 6;
const KEY_PADDING: i64 = 7;

/// Produces the device-key Ed25519 signature over a Cairn message
/// envelope's COSE `Sig_structure` (D0006 §9 hop #1).
///
/// This is the seam that lets the device signature be produced EITHER
/// in-process (a software [`SigningKey`], used by the `cairn-cli` demo +
/// the tests) OR out-of-process in hardware (an Android StrongBox
/// `HardwareKeySigner` bridged in `cairn-uniffi` per D0020 §3.4), without
/// the adapter's `send` path knowing which. The signing input is the
/// canonical COSE `Sig_structure` built Rust-side, so the AAD domain tag
/// (D0006 §8) is bound regardless of signer; for a hardware signer only
/// the 64-byte signature crosses back — the device key never enters the
/// process. See D0026 §2.3.
pub trait EnvelopeSigner: Send + Sync {
    /// Sign `signing_input` (the COSE `Sig_structure` bytes) with the
    /// device key, returning the Ed25519 signature.
    ///
    /// # Errors
    ///
    /// [`SimplexAdapterError::EnvelopeSignatureVerifyFailed`] if signing
    /// fails (e.g. a software-key payload-size limit, or a hardware-signer
    /// failure surfaced by the FFI bridge).
    fn sign_envelope(
        &self,
        signing_input: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], SimplexAdapterError>;
}

/// In-process software-key signer: the `cairn-cli` demo + the crate's
/// tests sign with a held [`SigningKey`]. The production Android path
/// substitutes a hardware-backed [`EnvelopeSigner`] instead.
impl EnvelopeSigner for SigningKey {
    fn sign_envelope(
        &self,
        signing_input: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], SimplexAdapterError> {
        let signature = self
            .sign(signing_input)
            .map_err(|_| SimplexAdapterError::EnvelopeSignatureVerifyFailed)?;
        Ok(signature.to_bytes())
    }
}

/// Unsigned Cairn message envelope per D0026 §2.1.
///
/// The padded `payload` is the application-level message body the
/// receiver consumes; `padding` is random bytes per D0026 §4 to
/// reach the configured size bucket and is discarded on receive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEnvelope {
    /// Envelope schema version per D0026 §2.1 key 1.
    pub version: u64,
    /// Sender's operational identity pubkey per D0026 §2.1 key 2.
    pub sender_operational_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Recipient's operational identity pubkey per D0026 §2.1 key 3.
    pub recipient_operational_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Unix-seconds at envelope construction time per D0026 §2.1
    /// key 4.
    pub timestamp: u64,
    /// Chain link to the predecessor envelope per D0026 §2.1 key 5
    /// + D0006 §5.
    ///
    /// Empty for the first envelope between this `(sender,
    /// recipient)` pair; otherwise SHA-256 of the prior envelope's
    /// `COSE_Sign1` signature bytes.
    pub prior_envelope_hash: Vec<u8>,
    /// Application-level payload bytes per D0026 §2.1 key 6.
    pub payload: Vec<u8>,
    /// Random padding bytes per D0026 §2.1 key 7. Receiver discards.
    pub padding: Vec<u8>,
}

impl MessageEnvelope {
    /// Encode the envelope as canonical-CBOR per D0018 §2.3.
    ///
    /// # Errors
    ///
    /// Propagates [`SimplexAdapterError::EnvelopeDecodeFailed`] for
    /// any canonical encoder error (unreachable for typed inputs).
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SimplexAdapterError> {
        let timestamp_i64 =
            i64::try_from(self.timestamp).map_err(|_| SimplexAdapterError::EnvelopeDecodeFailed)?;
        let version_i64 =
            i64::try_from(self.version).map_err(|_| SimplexAdapterError::EnvelopeDecodeFailed)?;

        let map = Value::Map(vec![
            (Value::Int(KEY_VERSION), Value::Int(version_i64)),
            (
                Value::Int(KEY_SENDER_PUBKEY),
                Value::Bytes(self.sender_operational_pubkey.to_vec()),
            ),
            (
                Value::Int(KEY_RECIPIENT_PUBKEY),
                Value::Bytes(self.recipient_operational_pubkey.to_vec()),
            ),
            (Value::Int(KEY_TIMESTAMP), Value::Int(timestamp_i64)),
            (
                Value::Int(KEY_PRIOR_ENVELOPE_HASH),
                Value::Bytes(self.prior_envelope_hash.clone()),
            ),
            (Value::Int(KEY_PAYLOAD), Value::Bytes(self.payload.clone())),
            (Value::Int(KEY_PADDING), Value::Bytes(self.padding.clone())),
        ]);
        map.encode()
            .map_err(|_| SimplexAdapterError::EnvelopeDecodeFailed)
    }

    /// Decode an envelope from canonical-CBOR bytes.
    ///
    /// Unknown integer keys are tolerated per D0006 §6.4's forward-
    /// compatibility discipline.
    ///
    /// # Errors
    ///
    /// [`SimplexAdapterError::EnvelopeDecodeFailed`] for any CBOR
    /// or schema structural error.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SimplexAdapterError> {
        let parsed: CiboriumValue = ciborium::de::from_reader(bytes)
            .map_err(|_| SimplexAdapterError::EnvelopeDecodeFailed)?;
        let CiboriumValue::Map(entries) = parsed else {
            return Err(SimplexAdapterError::EnvelopeDecodeFailed);
        };

        let mut version: Option<u64> = None;
        let mut sender: Option<[u8; PUBLIC_KEY_LEN]> = None;
        let mut recipient: Option<[u8; PUBLIC_KEY_LEN]> = None;
        let mut timestamp: Option<u64> = None;
        let mut prior_envelope_hash: Option<Vec<u8>> = None;
        let mut payload: Option<Vec<u8>> = None;
        let mut padding: Option<Vec<u8>> = None;

        for (key, value) in entries {
            let CiboriumValue::Integer(key_int_ciborium) = key else {
                return Err(SimplexAdapterError::EnvelopeDecodeFailed);
            };
            let key_int = i64::try_from(i128::from(key_int_ciborium))
                .map_err(|_| SimplexAdapterError::EnvelopeDecodeFailed)?;
            match key_int {
                KEY_VERSION => version = Some(int_to_u64(&value)?),
                KEY_SENDER_PUBKEY => sender = Some(bytes_to_pubkey_array(value)?),
                KEY_RECIPIENT_PUBKEY => recipient = Some(bytes_to_pubkey_array(value)?),
                KEY_TIMESTAMP => timestamp = Some(int_to_u64(&value)?),
                KEY_PRIOR_ENVELOPE_HASH => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(SimplexAdapterError::EnvelopeDecodeFailed);
                    };
                    prior_envelope_hash = Some(b);
                }
                KEY_PAYLOAD => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(SimplexAdapterError::EnvelopeDecodeFailed);
                    };
                    payload = Some(b);
                }
                KEY_PADDING => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(SimplexAdapterError::EnvelopeDecodeFailed);
                    };
                    padding = Some(b);
                }
                _ => {} // forward-compat per D0006 §6.4
            }
        }

        Ok(Self {
            version: version.ok_or(SimplexAdapterError::EnvelopeDecodeFailed)?,
            sender_operational_pubkey: sender.ok_or(SimplexAdapterError::EnvelopeDecodeFailed)?,
            recipient_operational_pubkey: recipient
                .ok_or(SimplexAdapterError::EnvelopeDecodeFailed)?,
            timestamp: timestamp.ok_or(SimplexAdapterError::EnvelopeDecodeFailed)?,
            prior_envelope_hash: prior_envelope_hash
                .ok_or(SimplexAdapterError::EnvelopeDecodeFailed)?,
            payload: payload.ok_or(SimplexAdapterError::EnvelopeDecodeFailed)?,
            padding: padding.ok_or(SimplexAdapterError::EnvelopeDecodeFailed)?,
        })
    }

    /// Sign the envelope in-process under a software device key per D0006
    /// §9 hop #1 with AAD = [`DOMAIN_TAG`].
    ///
    /// A convenience wrapper over [`Self::sign_with`] for a [`SigningKey`]
    /// (the `cairn-cli` demo + the tests); the production Android/FFI path
    /// uses [`Self::sign_with`] with a hardware-backed signer so the device
    /// key never enters the process.
    ///
    /// Returns the canonical `COSE_Sign1` envelope bytes consuming code
    /// passes to the transport.
    ///
    /// # Errors
    ///
    /// See [`Self::sign_with`].
    pub fn sign(&self, device_key: &SigningKey) -> Result<Vec<u8>, SimplexAdapterError> {
        self.sign_with(device_key)
    }

    /// Sign the envelope via an arbitrary [`EnvelopeSigner`] — a software
    /// [`SigningKey`] OR a hardware StrongBox signer — per D0026 §2.3.
    ///
    /// Builds the canonical COSE `Sig_structure` Rust-side (binding the AAD
    /// domain tag per D0006 §8), hands those bytes to `signer`, and
    /// assembles the `COSE_Sign1` from the returned signature — so the
    /// device key need never enter the process. Byte-identical to a direct
    /// `finalize` when `signer` is the same software key: the
    /// `cairn-envelope` external-signer path (`signing_input` +
    /// `finalize_with_signature`) is the exact code `finalize` runs.
    ///
    /// # Errors
    ///
    /// - [`SimplexAdapterError::EnvelopeDecodeFailed`] if the canonical-CBOR
    ///   encoding fails (unreachable for typed inputs).
    /// - [`SimplexAdapterError::EnvelopeSignatureVerifyFailed`] wrapping a
    ///   COSE builder failure or a `signer` failure.
    pub fn sign_with(&self, signer: &dyn EnvelopeSigner) -> Result<Vec<u8>, SimplexAdapterError> {
        let payload = self.to_canonical_cbor()?;
        let builder = Sign1Builder::new()
            .with_payload(payload)
            .with_external_aad(DOMAIN_TAG.to_vec());
        let signing_input = builder
            .signing_input()
            .map_err(|_| SimplexAdapterError::EnvelopeSignatureVerifyFailed)?;
        let sig_bytes = signer.sign_envelope(&signing_input)?;
        let cose = builder
            .finalize_with_signature(&sig_bytes)
            .map_err(|_| SimplexAdapterError::EnvelopeSignatureVerifyFailed)?;
        cose.encode(false)
            .map_err(|_| SimplexAdapterError::EnvelopeSignatureVerifyFailed)
    }
}

/// Verify a `COSE_Sign1` envelope's signature against the supplied
/// device pubkey AND check the AAD matches [`DOMAIN_TAG`].
///
/// On success, decodes + returns the inner [`MessageEnvelope`].
///
/// # Errors
///
/// - [`SimplexAdapterError::EnvelopeSignatureVerifyFailed`] if the
///   signature does not verify under `device_pubkey` + the AAD
///   domain tag.
/// - [`SimplexAdapterError::EnvelopeDomainTagMismatch`] if the
///   verification path detected a wrong-AAD substitution attempt.
///   (In the current cairn-envelope API the domain tag is bound at
///   verify-call time; tampering with the AAD surfaces as a
///   signature failure. The variant remains in the surface so a
///   future cairn-envelope API change can route to it cleanly.)
/// - [`SimplexAdapterError::EnvelopeDecodeFailed`] if the
///   `COSE_Sign1` bytes don't parse, or the inner payload fails
///   canonical-CBOR decode.
pub fn verify_envelope(
    envelope_bytes: &[u8],
    device_pubkey: &VerifyingKey,
) -> Result<MessageEnvelope, SimplexAdapterError> {
    let cose = CoseSign1::from_bytes(envelope_bytes)
        .map_err(|_| SimplexAdapterError::EnvelopeDecodeFailed)?;
    cose.verify(device_pubkey, DOMAIN_TAG)
        .map_err(|_| SimplexAdapterError::EnvelopeSignatureVerifyFailed)?;
    let payload = cose
        .payload()
        .ok_or(SimplexAdapterError::EnvelopeDecodeFailed)?;
    MessageEnvelope::from_canonical_cbor(payload)
}

/// Verify an envelope **learning the sender from the envelope itself** — no
/// pre-known device key (TOFU on first contact).
///
/// Used by the inviter-side pairing bootstrap (D0026 §12): the inviter shares a
/// one-time invitation and cannot know the acceptor's key until the acceptor's
/// first envelope arrives. This parses the `COSE_Sign1` payload **unverified**
/// to read the embedded `sender_operational_pubkey`, then verifies the
/// signature against THAT key.
///
/// **Assumes the v1 1:1 identity model (operational pubkey == device signing
/// key, D0028).** In that model a valid signature against the embedded
/// operational key proves the envelope is self-consistent and yields the
/// sender's operational identity. The binding of that learned key to a
/// real-world identity is the D0006 trust graph (a v1.x layer); this is no
/// weaker than the demo's prior out-of-band key exchange, which was equally
/// unauthenticated.
///
/// **Safe by construction under op≠device.** When the operational and device
/// keys differ (the general model; capability tokens bind device→op per D0006
/// §9), the signature was made by the device key, so verifying it against the
/// embedded operational key simply **fails** — no envelope is wrongly accepted.
/// A future op≠device pairing path must verify the embedded device key + its
/// capability token, not assume op==device.
///
/// # Errors
///
/// - [`SimplexAdapterError::EnvelopeDecodeFailed`] if the `COSE_Sign1` bytes or
///   the inner payload don't parse.
/// - [`SimplexAdapterError::EnvelopeSignatureVerifyFailed`] if the embedded
///   operational pubkey is not a valid Ed25519 key, or the signature does not
///   verify against it (incl. every op≠device envelope).
pub fn verify_envelope_learning_sender(
    envelope_bytes: &[u8],
) -> Result<MessageEnvelope, SimplexAdapterError> {
    let cose = CoseSign1::from_bytes(envelope_bytes)
        .map_err(|_| SimplexAdapterError::EnvelopeDecodeFailed)?;
    let payload = cose
        .payload()
        .ok_or(SimplexAdapterError::EnvelopeDecodeFailed)?;
    let envelope = MessageEnvelope::from_canonical_cbor(payload)?;
    // 1:1 demo identity: the operational pubkey IS the device signing key, so
    // it doubles as the COSE verification key. A bad key or a signature made by
    // a DIFFERENT device key (op≠device) fails here.
    let device_vk = VerifyingKey::from_bytes(&envelope.sender_operational_pubkey)
        .map_err(|_| SimplexAdapterError::EnvelopeSignatureVerifyFailed)?;
    cose.verify(&device_vk, DOMAIN_TAG)
        .map_err(|_| SimplexAdapterError::EnvelopeSignatureVerifyFailed)?;
    Ok(envelope)
}

/// Compute the `prior_envelope_hash` that the NEXT envelope between
/// the same `(sender, recipient)` pair must commit to.
///
/// `SHA-256(COSE_Sign1.signature_bytes(envelope_bytes))` — the same
/// byte composition D0006 §5 + D0023 §1 + D0024 §5 use for leaf /
/// chain-link hashes. The "one audited primitive across the
/// workspace" property holds for the messaging chain the same way
/// it does for trust-graph + release-log chains.
///
/// # Errors
///
/// - [`SimplexAdapterError::EnvelopeDecodeFailed`] if the supplied
///   bytes do not parse as a `COSE_Sign1` envelope.
pub fn next_prior_envelope_hash(envelope_bytes: &[u8]) -> Result<[u8; 32], SimplexAdapterError> {
    let cose = CoseSign1::from_bytes(envelope_bytes)
        .map_err(|_| SimplexAdapterError::EnvelopeDecodeFailed)?;
    let sig = cose.signature();
    let mut hasher = Sha256::new();
    hasher.update(sig);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Ok(arr)
}

// === Internal helpers ===

fn int_to_u64(value: &CiboriumValue) -> Result<u64, SimplexAdapterError> {
    let CiboriumValue::Integer(v) = value else {
        return Err(SimplexAdapterError::EnvelopeDecodeFailed);
    };
    u64::try_from(i128::from(*v)).map_err(|_| SimplexAdapterError::EnvelopeDecodeFailed)
}

fn bytes_to_pubkey_array(
    value: CiboriumValue,
) -> Result<[u8; PUBLIC_KEY_LEN], SimplexAdapterError> {
    let CiboriumValue::Bytes(b) = value else {
        return Err(SimplexAdapterError::EnvelopeDecodeFailed);
    };
    if b.len() != PUBLIC_KEY_LEN {
        return Err(SimplexAdapterError::EnvelopeDecodeFailed);
    }
    let mut arr = [0u8; PUBLIC_KEY_LEN];
    arr.copy_from_slice(&b);
    Ok(arr)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use rand_core::OsRng;

    fn make_envelope() -> (MessageEnvelope, SigningKey, SigningKey) {
        let mut rng = OsRng;
        let sender_op_sk = SigningKey::generate(&mut rng);
        let recipient_op_sk = SigningKey::generate(&mut rng);
        let device_sk = SigningKey::generate(&mut rng);

        let envelope = MessageEnvelope {
            version: ENVELOPE_SCHEMA_VERSION,
            sender_operational_pubkey: sender_op_sk.verifying_key().to_bytes(),
            recipient_operational_pubkey: recipient_op_sk.verifying_key().to_bytes(),
            timestamp: 1_700_000_000,
            prior_envelope_hash: vec![],
            payload: b"hello world".to_vec(),
            padding: vec![0xAA; 200], // pads to 256 bucket with envelope overhead
        };
        (envelope, device_sk, recipient_op_sk)
    }

    #[test]
    fn canonical_cbor_round_trip_preserves_all_fields() {
        let (envelope, _, _) = make_envelope();
        let bytes = envelope.to_canonical_cbor().unwrap();
        let recovered = MessageEnvelope::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(recovered, envelope);
    }

    #[test]
    fn round_trip_with_non_empty_prior_envelope_hash() {
        let (mut envelope, _, _) = make_envelope();
        envelope.prior_envelope_hash = vec![0xBB; 32];
        let bytes = envelope.to_canonical_cbor().unwrap();
        let recovered = MessageEnvelope::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(recovered, envelope);
    }

    #[test]
    fn malformed_cbor_fails_decode() {
        let result = MessageEnvelope::from_canonical_cbor(b"\xFF\x00\x01");
        assert!(matches!(
            result,
            Err(SimplexAdapterError::EnvelopeDecodeFailed)
        ));
    }

    #[test]
    fn decode_rejects_wrong_pubkey_length() {
        // Forge a CBOR map with a 16-byte sender_pubkey instead of 32.
        let map = Value::Map(vec![
            (Value::Int(KEY_VERSION), Value::Int(1)),
            (Value::Int(KEY_SENDER_PUBKEY), Value::Bytes(vec![0xAB; 16])),
            (
                Value::Int(KEY_RECIPIENT_PUBKEY),
                Value::Bytes(vec![0xCD; 32]),
            ),
            (Value::Int(KEY_TIMESTAMP), Value::Int(1_700_000_000)),
            (Value::Int(KEY_PRIOR_ENVELOPE_HASH), Value::Bytes(vec![])),
            (Value::Int(KEY_PAYLOAD), Value::Bytes(b"payload".to_vec())),
            (Value::Int(KEY_PADDING), Value::Bytes(vec![0; 200])),
        ]);
        let bytes = map.encode().unwrap();
        assert!(matches!(
            MessageEnvelope::from_canonical_cbor(&bytes),
            Err(SimplexAdapterError::EnvelopeDecodeFailed)
        ));
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let (envelope, device_sk, _) = make_envelope();
        let signed_bytes = envelope.sign(&device_sk).unwrap();
        let recovered = verify_envelope(&signed_bytes, &device_sk.verifying_key()).unwrap();
        assert_eq!(recovered, envelope);
    }

    /// A stand-in for the Android StrongBox `HardwareKeySigner` bridge: it
    /// holds a software key and signs the COSE `Sig_structure` exactly as
    /// the hardware callback would — only the signature bytes "cross back",
    /// never the key. Used to exercise the `EnvelopeSigner` seam without an
    /// in-process `SigningKey` on the signing path.
    struct DelegatingSigner(SigningKey);

    impl EnvelopeSigner for DelegatingSigner {
        fn sign_envelope(
            &self,
            signing_input: &[u8],
        ) -> Result<[u8; SIGNATURE_LEN], SimplexAdapterError> {
            self.0
                .sign(signing_input)
                .map(|s| s.to_bytes())
                .map_err(|_| SimplexAdapterError::EnvelopeSignatureVerifyFailed)
        }
    }

    #[test]
    fn sign_with_external_signer_matches_sign_and_verifies() {
        // sign_with via an arbitrary EnvelopeSigner (here a delegating
        // stand-in for the hardware bridge) must be byte-identical to the
        // in-process sign(&key) for the same key, and the result must
        // verify under the device verifying key. This is the adapter-level
        // guarantee that the StrongBox signing path (D0026 §2.3) produces
        // the same wire envelope as the software path.
        let (envelope, device_sk, _) = make_envelope();
        let vk = device_sk.verifying_key();

        let direct = envelope.sign(&device_sk).unwrap();

        // Move the key into the signer AFTER the borrow above ends.
        let signer = DelegatingSigner(device_sk);
        let external = envelope.sign_with(&signer).unwrap();

        assert_eq!(
            direct, external,
            "sign_with(&signer) must match sign(&key) byte-for-byte"
        );
        let recovered = verify_envelope(&external, &vk).unwrap();
        assert_eq!(recovered, envelope);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (envelope, device_sk, _) = make_envelope();
        let signed_bytes = envelope.sign(&device_sk).unwrap();

        let mut rng = OsRng;
        let imposter_pubkey = SigningKey::generate(&mut rng).verifying_key();
        let result = verify_envelope(&signed_bytes, &imposter_pubkey);
        assert!(matches!(
            result,
            Err(SimplexAdapterError::EnvelopeSignatureVerifyFailed)
        ));
    }

    #[test]
    fn verify_rejects_tampered_envelope_bytes() {
        let (envelope, device_sk, _) = make_envelope();
        let mut signed_bytes = envelope.sign(&device_sk).unwrap();
        // Flip a byte in the middle of the envelope.
        let mid = signed_bytes.len() / 2;
        signed_bytes[mid] ^= 0xFF;
        let result = verify_envelope(&signed_bytes, &device_sk.verifying_key());
        // Tamper surfaces either as decode-failed (if the CBOR
        // structure broke) or signature-verify-failed (if the
        // CBOR survived but the signature input changed).
        assert!(matches!(
            result,
            Err(SimplexAdapterError::EnvelopeSignatureVerifyFailed
                | SimplexAdapterError::EnvelopeDecodeFailed)
        ));
    }

    #[test]
    fn verify_rejects_aad_mismatch_via_wrong_domain() {
        // Sign with a DIFFERENT AAD then verify with our domain
        // tag — must surface as a signature failure (which is
        // exactly the no-error-oracle outcome we want for AAD
        // mismatch — the failure mode does not differ from any
        // other tamper).
        let (envelope, device_sk, _) = make_envelope();
        let payload = envelope.to_canonical_cbor().unwrap();
        let wrong_domain = b"cairn-v1-trust-graph-op"; // different AAD
        let signed = Sign1Builder::new()
            .with_payload(payload)
            .with_external_aad(wrong_domain.to_vec())
            .finalize(&device_sk)
            .unwrap();
        let signed_bytes = signed.encode(false).unwrap();

        let result = verify_envelope(&signed_bytes, &device_sk.verifying_key());
        assert!(matches!(
            result,
            Err(SimplexAdapterError::EnvelopeSignatureVerifyFailed)
        ));
    }

    #[test]
    fn next_prior_envelope_hash_is_deterministic_for_same_envelope() {
        let (envelope, device_sk, _) = make_envelope();
        let signed_bytes = envelope.sign(&device_sk).unwrap();
        let h_a = next_prior_envelope_hash(&signed_bytes).unwrap();
        let h_b = next_prior_envelope_hash(&signed_bytes).unwrap();
        assert_eq!(h_a, h_b);
        assert_eq!(h_a.len(), 32);
    }

    #[test]
    fn distinct_envelopes_produce_distinct_next_prior_envelope_hashes() {
        // Two independent envelopes (distinct sender/recipient/
        // payload) MUST hash to distinct prior_envelope_hash values.
        // make_envelope() generates fresh keys per call, so the
        // resulting envelopes differ across every field.
        let (envelope_a, device_sk_a, _) = make_envelope();
        let (envelope_b, device_sk_b, _) = make_envelope();

        let bytes_a = envelope_a.sign(&device_sk_a).unwrap();
        let bytes_b = envelope_b.sign(&device_sk_b).unwrap();

        let h_a = next_prior_envelope_hash(&bytes_a).unwrap();
        let h_b = next_prior_envelope_hash(&bytes_b).unwrap();
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn forward_compat_tolerates_unknown_keys() {
        // Encode a map that includes an unknown key #99; decode
        // must succeed per D0006 §6.4 forward-compat discipline.
        let map = Value::Map(vec![
            (Value::Int(KEY_VERSION), Value::Int(1)),
            (Value::Int(KEY_SENDER_PUBKEY), Value::Bytes(vec![0xAA; 32])),
            (
                Value::Int(KEY_RECIPIENT_PUBKEY),
                Value::Bytes(vec![0xBB; 32]),
            ),
            (Value::Int(KEY_TIMESTAMP), Value::Int(1_700_000_000)),
            (Value::Int(KEY_PRIOR_ENVELOPE_HASH), Value::Bytes(vec![])),
            (Value::Int(KEY_PAYLOAD), Value::Bytes(b"hello".to_vec())),
            (Value::Int(KEY_PADDING), Value::Bytes(vec![0; 200])),
            (Value::Int(99), Value::Text("future field".to_string())),
        ]);
        let bytes = map.encode().unwrap();
        let recovered = MessageEnvelope::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(recovered.payload, b"hello");
    }
}
