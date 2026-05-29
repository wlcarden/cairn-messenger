// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Trust-graph operation data structure + canonical-CBOR encoding.
//!
//! Per D0006 §2 + canonical CBOR per D0018 §2.3. Operations are
//! canonically encoded so two implementations produce byte-identical
//! signing inputs.

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, VerifyingKey};
use cairn_envelope::canonical::Value;
use ciborium::Value as CiboriumValue;

use crate::error::TrustGraphError;

/// Canonical-CBOR map key for `op_type`.
const KEY_OP_TYPE: i64 = 1;
/// Canonical-CBOR map key for `issuer_pubkey`.
const KEY_ISSUER: i64 = 2;
/// Canonical-CBOR map key for `subject_pubkey`.
const KEY_SUBJECT: i64 = 3;
/// Canonical-CBOR map key for `timestamp`.
const KEY_TIMESTAMP: i64 = 4;
/// Canonical-CBOR map key for `prior_hash`.
const KEY_PRIOR_HASH: i64 = 5;
/// Canonical-CBOR map key for `issuer_cert_hash`.
const KEY_ISSUER_CERT_HASH: i64 = 6;
/// Canonical-CBOR map key for `revoked_as_of` (`CompromiseRevoke` only).
const KEY_REVOKED_AS_OF: i64 = 7;
/// Canonical-CBOR map key for `prior_revocation_ref` (`ReAttest` only).
const KEY_PRIOR_REVOCATION_REF: i64 = 8;

/// Trust-graph operation type discriminator per D0006 §2.
///
/// Encoded as a canonical-CBOR `uint` (integer in the range 1..=4).
/// Unknown values rejected at decode per the v1 schema closure; future
/// versions add variants via a coordinated D-doc decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpType {
    /// Issuer claims a trust relationship with the subject peer.
    Attest,
    /// Issuer cleanly withdraws their previous attestation of the
    /// subject. NO cascade.
    WithdrawRevoke,
    /// Issuer revokes their attestation of the subject because of a
    /// security incident. Triggers the cascade quarantine per D0006
    /// §2. The `revoked_as_of` field marks the prior-to-which time
    /// considered compromised.
    CompromiseRevoke,
    /// Issuer re-attests a subject whose previous attestation was
    /// revoked. The `prior_revocation_ref` field references the
    /// revocation being healed.
    ReAttest,
}

impl OpType {
    /// Numeric encoding per D0006 §2.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        match self {
            Self::Attest => 1,
            Self::WithdrawRevoke => 2,
            Self::CompromiseRevoke => 3,
            Self::ReAttest => 4,
        }
    }

    /// Decode from the wire-format integer value.
    ///
    /// # Errors
    ///
    /// Returns [`TrustGraphError::UnknownOpType`] if `value` is not in
    /// the v1 enumeration (1..=4).
    pub const fn from_i64(value: i64) -> Result<Self, TrustGraphError> {
        match value {
            1 => Ok(Self::Attest),
            2 => Ok(Self::WithdrawRevoke),
            3 => Ok(Self::CompromiseRevoke),
            4 => Ok(Self::ReAttest),
            _ => Err(TrustGraphError::UnknownOpType { value }),
        }
    }

    /// The required `cairn-identity` capability string the issuing
    /// device's capability token must contain for this op type to be
    /// authorized.
    #[must_use]
    pub const fn required_capability(self) -> &'static str {
        match self {
            // Attest and ReAttest both need the `attest` capability.
            Self::Attest | Self::ReAttest => cairn_identity::capabilities::TRUST_GRAPH_ATTEST,
            Self::WithdrawRevoke => cairn_identity::capabilities::TRUST_GRAPH_REVOKE_WITHDRAW,
            Self::CompromiseRevoke => cairn_identity::capabilities::TRUST_GRAPH_REVOKE_COMPROMISE,
        }
    }
}

/// A trust-graph operation per D0006 §2.
///
/// Construct via the variant-specific helpers
/// ([`Self::new_attest`], [`Self::new_withdraw_revoke`],
/// [`Self::new_compromise_revoke`], [`Self::new_re_attest`]) — these
/// enforce the per-variant required fields. Encode via
/// [`Self::to_canonical_cbor`]; decode via [`Self::from_canonical_cbor`].
/// Signing happens at the [`crate::SignedTrustGraphOp`] layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustGraphOp {
    /// Variant discriminator.
    pub op_type: OpType,
    /// Operational identity public key (the peer whose trust graph
    /// this operation belongs to).
    pub issuer: VerifyingKey,
    /// Subject peer public key — the peer being attested / revoked
    /// / re-attested.
    pub subject: VerifyingKey,
    /// Unix-seconds when the operation was issued.
    pub timestamp: u64,
    /// Hash of the previous operation in this issuer's trust-graph
    /// chain. Zero-length bytes for genesis (the first op an issuer
    /// signs); higher layers validate the chain.
    pub prior_hash: Vec<u8>,
    /// Hash of the capability token authorizing the device that signs
    /// this op to issue trust-graph ops on the operational identity's
    /// behalf.
    pub issuer_cert_hash: Vec<u8>,
    /// For [`OpType::CompromiseRevoke`]: prior-to-this-Unix-seconds
    /// considered compromised. Must be present iff `op_type ==
    /// CompromiseRevoke`.
    pub revoked_as_of: Option<u64>,
    /// For [`OpType::ReAttest`]: reference (hash) of the revocation
    /// op being healed. Must be present iff `op_type == ReAttest`.
    pub prior_revocation_ref: Option<Vec<u8>>,
}

impl TrustGraphOp {
    /// Construct an `Attest` operation.
    #[must_use]
    pub const fn new_attest(
        issuer: VerifyingKey,
        subject: VerifyingKey,
        timestamp: u64,
        prior_hash: Vec<u8>,
        issuer_cert_hash: Vec<u8>,
    ) -> Self {
        Self {
            op_type: OpType::Attest,
            issuer,
            subject,
            timestamp,
            prior_hash,
            issuer_cert_hash,
            revoked_as_of: None,
            prior_revocation_ref: None,
        }
    }

    /// Construct a `WithdrawRevoke` operation.
    #[must_use]
    pub const fn new_withdraw_revoke(
        issuer: VerifyingKey,
        subject: VerifyingKey,
        timestamp: u64,
        prior_hash: Vec<u8>,
        issuer_cert_hash: Vec<u8>,
    ) -> Self {
        Self {
            op_type: OpType::WithdrawRevoke,
            issuer,
            subject,
            timestamp,
            prior_hash,
            issuer_cert_hash,
            revoked_as_of: None,
            prior_revocation_ref: None,
        }
    }

    /// Construct a `CompromiseRevoke` operation. `revoked_as_of` is
    /// the Unix-seconds before which the subject's actions are
    /// considered compromised (triggers the cascade quarantine).
    #[must_use]
    pub const fn new_compromise_revoke(
        issuer: VerifyingKey,
        subject: VerifyingKey,
        timestamp: u64,
        prior_hash: Vec<u8>,
        issuer_cert_hash: Vec<u8>,
        revoked_as_of: u64,
    ) -> Self {
        Self {
            op_type: OpType::CompromiseRevoke,
            issuer,
            subject,
            timestamp,
            prior_hash,
            issuer_cert_hash,
            revoked_as_of: Some(revoked_as_of),
            prior_revocation_ref: None,
        }
    }

    /// Construct a `ReAttest` operation. `prior_revocation_ref` is
    /// the reference (hash) of the revocation op being healed.
    #[must_use]
    pub const fn new_re_attest(
        issuer: VerifyingKey,
        subject: VerifyingKey,
        timestamp: u64,
        prior_hash: Vec<u8>,
        issuer_cert_hash: Vec<u8>,
        prior_revocation_ref: Vec<u8>,
    ) -> Self {
        Self {
            op_type: OpType::ReAttest,
            issuer,
            subject,
            timestamp,
            prior_hash,
            issuer_cert_hash,
            revoked_as_of: None,
            prior_revocation_ref: Some(prior_revocation_ref),
        }
    }

    /// Encode this operation as canonical-CBOR bytes per D0018 §2.3.
    ///
    /// The encoded bytes are what the device key signs (via
    /// [`crate::SignedTrustGraphOp::sign`]).
    ///
    /// # Errors
    ///
    /// - [`TrustGraphError::IntegerOutOfRange`] if `timestamp` or
    ///   `revoked_as_of` does not fit in `i64`.
    /// - [`TrustGraphError::CanonicalEncode`] from the canonical
    ///   encoder (unreachable for the schema's typed inputs).
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, TrustGraphError> {
        let timestamp_i64 =
            i64::try_from(self.timestamp).map_err(|_| TrustGraphError::IntegerOutOfRange)?;

        let mut entries: Vec<(Value, Value)> = vec![
            (Value::Int(KEY_OP_TYPE), Value::Int(self.op_type.as_i64())),
            (
                Value::Int(KEY_ISSUER),
                Value::Bytes(self.issuer.to_bytes().to_vec()),
            ),
            (
                Value::Int(KEY_SUBJECT),
                Value::Bytes(self.subject.to_bytes().to_vec()),
            ),
            (Value::Int(KEY_TIMESTAMP), Value::Int(timestamp_i64)),
            (
                Value::Int(KEY_PRIOR_HASH),
                Value::Bytes(self.prior_hash.clone()),
            ),
            (
                Value::Int(KEY_ISSUER_CERT_HASH),
                Value::Bytes(self.issuer_cert_hash.clone()),
            ),
        ];

        if let Some(revoked_as_of) = self.revoked_as_of {
            let v = i64::try_from(revoked_as_of).map_err(|_| TrustGraphError::IntegerOutOfRange)?;
            entries.push((Value::Int(KEY_REVOKED_AS_OF), Value::Int(v)));
        }

        if let Some(prior_ref) = &self.prior_revocation_ref {
            entries.push((
                Value::Int(KEY_PRIOR_REVOCATION_REF),
                Value::Bytes(prior_ref.clone()),
            ));
        }

        Value::Map(entries).encode().map_err(TrustGraphError::from)
    }

    /// Decode a trust-graph operation from canonical-CBOR bytes.
    ///
    /// Validates the variant-required fields per D0006 §2: a
    /// `CompromiseRevoke` must carry `revoked_as_of`; a `ReAttest`
    /// must carry `prior_revocation_ref`; the others must NOT carry
    /// either.
    ///
    /// # Errors
    ///
    /// - [`TrustGraphError::MalformedPayload`] for any CBOR / schema
    ///   structural error
    /// - [`TrustGraphError::InvalidPubkeyLength`] / `InvalidPubkey`
    ///   for the pubkey fields
    /// - [`TrustGraphError::UnknownOpType`] for `op_type ∉ {1, 2, 3, 4}`
    /// - [`TrustGraphError::MissingRequiredField`] when variant-
    ///   required fields are absent
    /// - [`TrustGraphError::IntegerOutOfRange`] for negative or
    ///   `> 2^63` integers
    #[allow(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "CBOR decoder with 8 field positions + 4 variant-required-field checks; \
                  splitting the function loses local context without reducing complexity"
    )]
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, TrustGraphError> {
        let parsed: CiboriumValue =
            ciborium::de::from_reader(bytes).map_err(|_| TrustGraphError::MalformedPayload)?;
        let CiboriumValue::Map(entries) = parsed else {
            return Err(TrustGraphError::MalformedPayload);
        };

        let mut op_type_int: Option<i64> = None;
        let mut issuer_bytes: Option<Vec<u8>> = None;
        let mut subject_bytes: Option<Vec<u8>> = None;
        let mut timestamp: Option<u64> = None;
        let mut prior_hash: Option<Vec<u8>> = None;
        let mut issuer_cert_hash: Option<Vec<u8>> = None;
        let mut revoked_as_of: Option<u64> = None;
        let mut prior_revocation_ref: Option<Vec<u8>> = None;

        for (key, value) in entries {
            let CiboriumValue::Integer(key_int_ciborium) = key else {
                return Err(TrustGraphError::MalformedPayload);
            };
            let key_int = i64::try_from(i128::from(key_int_ciborium))
                .map_err(|_| TrustGraphError::MalformedPayload)?;

            match key_int {
                KEY_OP_TYPE => {
                    let CiboriumValue::Integer(v) = value else {
                        return Err(TrustGraphError::MalformedPayload);
                    };
                    op_type_int = Some(
                        i64::try_from(i128::from(v))
                            .map_err(|_| TrustGraphError::IntegerOutOfRange)?,
                    );
                }
                KEY_ISSUER => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(TrustGraphError::MalformedPayload);
                    };
                    issuer_bytes = Some(b);
                }
                KEY_SUBJECT => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(TrustGraphError::MalformedPayload);
                    };
                    subject_bytes = Some(b);
                }
                KEY_TIMESTAMP => {
                    let CiboriumValue::Integer(v) = value else {
                        return Err(TrustGraphError::MalformedPayload);
                    };
                    timestamp = Some(
                        u64::try_from(i128::from(v))
                            .map_err(|_| TrustGraphError::IntegerOutOfRange)?,
                    );
                }
                KEY_PRIOR_HASH => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(TrustGraphError::MalformedPayload);
                    };
                    prior_hash = Some(b);
                }
                KEY_ISSUER_CERT_HASH => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(TrustGraphError::MalformedPayload);
                    };
                    issuer_cert_hash = Some(b);
                }
                KEY_REVOKED_AS_OF => {
                    let CiboriumValue::Integer(v) = value else {
                        return Err(TrustGraphError::MalformedPayload);
                    };
                    revoked_as_of = Some(
                        u64::try_from(i128::from(v))
                            .map_err(|_| TrustGraphError::IntegerOutOfRange)?,
                    );
                }
                KEY_PRIOR_REVOCATION_REF => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(TrustGraphError::MalformedPayload);
                    };
                    prior_revocation_ref = Some(b);
                }
                // Unknown keys forward-compat per D0006 §6.4.
                _ => {}
            }
        }

        let op_type_int = op_type_int.ok_or(TrustGraphError::MalformedPayload)?;
        let op_type = OpType::from_i64(op_type_int)?;
        let issuer_bytes = issuer_bytes.ok_or(TrustGraphError::MalformedPayload)?;
        let subject_bytes = subject_bytes.ok_or(TrustGraphError::MalformedPayload)?;
        let timestamp = timestamp.ok_or(TrustGraphError::MalformedPayload)?;
        let prior_hash = prior_hash.ok_or(TrustGraphError::MalformedPayload)?;
        let issuer_cert_hash = issuer_cert_hash.ok_or(TrustGraphError::MalformedPayload)?;

        // Variant-required field presence check.
        match op_type {
            OpType::CompromiseRevoke => {
                if revoked_as_of.is_none() {
                    return Err(TrustGraphError::MissingRequiredField {
                        variant: "CompromiseRevoke",
                    });
                }
                if prior_revocation_ref.is_some() {
                    return Err(TrustGraphError::MalformedPayload);
                }
            }
            OpType::ReAttest => {
                if prior_revocation_ref.is_none() {
                    return Err(TrustGraphError::MissingRequiredField {
                        variant: "ReAttest",
                    });
                }
                if revoked_as_of.is_some() {
                    return Err(TrustGraphError::MalformedPayload);
                }
            }
            OpType::Attest | OpType::WithdrawRevoke => {
                if revoked_as_of.is_some() || prior_revocation_ref.is_some() {
                    return Err(TrustGraphError::MalformedPayload);
                }
            }
        }

        // Pubkey length + curve-point checks.
        if issuer_bytes.len() != PUBLIC_KEY_LEN {
            return Err(TrustGraphError::InvalidPubkeyLength {
                got_bytes: issuer_bytes.len(),
                expected_bytes: PUBLIC_KEY_LEN,
            });
        }
        if subject_bytes.len() != PUBLIC_KEY_LEN {
            return Err(TrustGraphError::InvalidPubkeyLength {
                got_bytes: subject_bytes.len(),
                expected_bytes: PUBLIC_KEY_LEN,
            });
        }
        let issuer_arr: [u8; PUBLIC_KEY_LEN] = issuer_bytes
            .as_slice()
            .try_into()
            .map_err(|_| TrustGraphError::InvalidPubkey)?;
        let subject_arr: [u8; PUBLIC_KEY_LEN] = subject_bytes
            .as_slice()
            .try_into()
            .map_err(|_| TrustGraphError::InvalidPubkey)?;
        let issuer =
            VerifyingKey::from_bytes(&issuer_arr).map_err(|_| TrustGraphError::InvalidPubkey)?;
        let subject =
            VerifyingKey::from_bytes(&subject_arr).map_err(|_| TrustGraphError::InvalidPubkey)?;

        Ok(Self {
            op_type,
            issuer,
            subject,
            timestamp,
            prior_hash,
            issuer_cert_hash,
            revoked_as_of,
            prior_revocation_ref,
        })
    }
}
