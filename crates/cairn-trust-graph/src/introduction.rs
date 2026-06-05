// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Consent-gated introduction wire codec per D0037 §5.
//!
//! An **introduction** is a three-message, dual-consent handshake brokered by
//! an introducer who has verified both parties (D0037 §3). Each message is one
//! canonical-CBOR blob carried by the message-envelope key-10 `introduction`
//! field. This module is only the byte structure: the introducer's vouch
//! ([`crate::encode_vouch`]) rides inside it, and the orchestration +
//! per-message consent live at the FFI handle (D0037 §5). Authentication of the
//! *sender* of each message is the transport's `COSE_Sign1` envelope (D0037 §9).
//!
//! ## The three message types (D0037 §3)
//!
//! - [`IntroductionKind::Request`] — introducer → introducee: "I'd like to
//!   introduce you to `peer_key`; here is my [`vouch`](IntroductionMessage::vouch)
//!   for them — do you consent?"
//! - [`IntroductionKind::Response`] — introducee → introducer: the consent
//!   decision in [`accept`](IntroductionMessage::accept); on accept it also
//!   carries the freshly-minted one-time
//!   [`invite_uri`](IntroductionMessage::invite_uri).
//! - [`IntroductionKind::Deliver`] — introducer → the other introducee: "they
//!   consented; here is my [`vouch`](IntroductionMessage::vouch) for them and
//!   their [`invite_uri`](IntroductionMessage::invite_uri) — connect if you
//!   consent."
//!
//! ## Integer-keyed canonical-CBOR map
//!
//! | Key | Field        | CBOR type | Notes |
//! |-----|--------------|-----------|-------|
//! | 1   | `kind`       | uint      | 1 = Request, 2 = Response, 3 = Deliver |
//! | 2   | `peer_key`   | bstr (32) | operational pubkey of the introduced third party |
//! | 3   | `vouch`      | bstr      | OPTIONAL — introducer's vouch for `peer_key` (Request + Deliver) |
//! | 4   | `invite_uri` | tstr      | OPTIONAL — one-time pairing invitation, opaque at this layer (Response-accept + Deliver) |
//! | 5   | `accept`     | bool      | OPTIONAL — consent decision (Response) |
//!
//! Optional keys 3–5 are omitted when `None`, so each message type carries only
//! the fields it needs and encodes to a single deterministic byte string. The
//! codec is purely structural — it does NOT enforce that, e.g., a `Request`
//! carries a `vouch`; the per-kind invariants are the orchestration layer's
//! (D0037 §5).

use cairn_crypto::ed25519::PUBLIC_KEY_LEN;
use cairn_envelope::canonical::Value;
use ciborium::Value as CiboriumValue;

use crate::error::TrustGraphError;

/// Canonical-CBOR map key for the message kind discriminant.
const KEY_KIND: i64 = 1;
/// Canonical-CBOR map key for the introduced third party's operational pubkey.
const KEY_PEER_KEY: i64 = 2;
/// Canonical-CBOR map key for the introducer's vouch for `peer_key`.
const KEY_VOUCH: i64 = 3;
/// Canonical-CBOR map key for the one-time pairing invitation.
const KEY_INVITE_URI: i64 = 4;
/// Canonical-CBOR map key for the consent decision.
const KEY_ACCEPT: i64 = 5;

/// Wire discriminant for [`IntroductionKind::Request`].
const KIND_REQUEST: i64 = 1;
/// Wire discriminant for [`IntroductionKind::Response`].
const KIND_RESPONSE: i64 = 2;
/// Wire discriminant for [`IntroductionKind::Deliver`].
const KIND_DELIVER: i64 = 3;

/// Which of the three consent-gated introduction messages this is (D0037 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntroductionKind {
    /// Introducer → introducee: "do you consent to meet `peer_key`?" — carries
    /// the introducer's vouch for `peer_key`.
    Request,
    /// Introducee → introducer: the consent decision; on accept also carries
    /// the freshly-minted one-time invitation.
    Response,
    /// Introducer → the other introducee: "they consented" — carries the
    /// introducer's vouch for `peer_key` + the peer's one-time invitation.
    Deliver,
}

impl IntroductionKind {
    /// The stable wire discriminant (D0037 §5).
    #[must_use]
    const fn to_wire(self) -> i64 {
        match self {
            Self::Request => KIND_REQUEST,
            Self::Response => KIND_RESPONSE,
            Self::Deliver => KIND_DELIVER,
        }
    }

    /// Parse a wire discriminant; an unknown value is a malformed payload.
    const fn from_wire(wire: i64) -> Result<Self, TrustGraphError> {
        match wire {
            KIND_REQUEST => Ok(Self::Request),
            KIND_RESPONSE => Ok(Self::Response),
            KIND_DELIVER => Ok(Self::Deliver),
            _ => Err(TrustGraphError::MalformedPayload),
        }
    }
}

/// One decoded introduction message (D0037 §5).
///
/// The optional fields are populated per [`kind`](Self::kind): a `Request`/`Deliver`
/// carries [`vouch`](Self::vouch); a `Response`/`Deliver` carries
/// [`invite_uri`](Self::invite_uri); a `Response` carries [`accept`](Self::accept).
/// The codec does not enforce these — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroductionMessage {
    /// Which of the three handshake messages this is.
    pub kind: IntroductionKind,
    /// Operational pubkey of the third party being introduced.
    pub peer_key: [u8; PUBLIC_KEY_LEN],
    /// The introducer's vouch for `peer_key` ([`crate::encode_vouch`] bytes),
    /// present on `Request` + `Deliver`.
    pub vouch: Option<Vec<u8>>,
    /// The one-time pairing invitation (opaque at this layer), present on an
    /// accepting `Response` + `Deliver`.
    pub invite_uri: Option<String>,
    /// The consent decision, present on a `Response`.
    pub accept: Option<bool>,
}

/// Encode an introduction message per D0037 §5.
///
/// Optional fields are appended in ascending key order only when `Some`, so the
/// encoding is deterministic and minimal for each message kind.
///
/// # Errors
///
/// [`TrustGraphError::CanonicalEncode`] from the canonical encoder
/// (unreachable for the byte inputs here).
pub fn encode_introduction(msg: &IntroductionMessage) -> Result<Vec<u8>, TrustGraphError> {
    let mut entries = vec![
        (Value::Int(KEY_KIND), Value::Int(msg.kind.to_wire())),
        (
            Value::Int(KEY_PEER_KEY),
            Value::Bytes(msg.peer_key.to_vec()),
        ),
    ];
    if let Some(vouch) = &msg.vouch {
        entries.push((Value::Int(KEY_VOUCH), Value::Bytes(vouch.clone())));
    }
    if let Some(invite_uri) = &msg.invite_uri {
        entries.push((Value::Int(KEY_INVITE_URI), Value::Text(invite_uri.clone())));
    }
    if let Some(accept) = msg.accept {
        entries.push((Value::Int(KEY_ACCEPT), Value::Bool(accept)));
    }
    Value::Map(entries).encode().map_err(TrustGraphError::from)
}

/// Decode an introduction message, the inverse of [`encode_introduction`].
///
/// # Errors
///
/// [`TrustGraphError::MalformedPayload`] for any CBOR / schema structural error
/// (not a map, missing/mistyped key, unknown kind, wrong-length `peer_key`).
pub fn decode_introduction(bytes: &[u8]) -> Result<IntroductionMessage, TrustGraphError> {
    let parsed: CiboriumValue =
        ciborium::de::from_reader(bytes).map_err(|_| TrustGraphError::MalformedPayload)?;
    let CiboriumValue::Map(entries) = parsed else {
        return Err(TrustGraphError::MalformedPayload);
    };

    let mut kind: Option<IntroductionKind> = None;
    let mut peer_key: Option<[u8; PUBLIC_KEY_LEN]> = None;
    let mut vouch: Option<Vec<u8>> = None;
    let mut invite_uri: Option<String> = None;
    let mut accept: Option<bool> = None;

    for (key, value) in entries {
        let CiboriumValue::Integer(key_int) = key else {
            return Err(TrustGraphError::MalformedPayload);
        };
        match i64::try_from(i128::from(key_int)) {
            Ok(KEY_KIND) => {
                let CiboriumValue::Integer(k) = value else {
                    return Err(TrustGraphError::MalformedPayload);
                };
                let wire =
                    i64::try_from(i128::from(k)).map_err(|_| TrustGraphError::MalformedPayload)?;
                kind = Some(IntroductionKind::from_wire(wire)?);
            }
            Ok(KEY_PEER_KEY) => {
                let CiboriumValue::Bytes(b) = value else {
                    return Err(TrustGraphError::MalformedPayload);
                };
                peer_key = Some(
                    <[u8; PUBLIC_KEY_LEN]>::try_from(b.as_slice())
                        .map_err(|_| TrustGraphError::MalformedPayload)?,
                );
            }
            Ok(KEY_VOUCH) => {
                let CiboriumValue::Bytes(b) = value else {
                    return Err(TrustGraphError::MalformedPayload);
                };
                vouch = Some(b);
            }
            Ok(KEY_INVITE_URI) => {
                let CiboriumValue::Text(t) = value else {
                    return Err(TrustGraphError::MalformedPayload);
                };
                invite_uri = Some(t);
            }
            Ok(KEY_ACCEPT) => {
                let CiboriumValue::Bool(b) = value else {
                    return Err(TrustGraphError::MalformedPayload);
                };
                accept = Some(b);
            }
            _ => {} // forward-compat per D0006 §6.4
        }
    }

    Ok(IntroductionMessage {
        kind: kind.ok_or(TrustGraphError::MalformedPayload)?,
        peer_key: peer_key.ok_or(TrustGraphError::MalformedPayload)?,
        vouch,
        invite_uri,
        accept,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests unwrap known-good fixtures; an unwrap panic IS the failure signal"
)]
mod tests {
    use super::*;

    fn peer() -> [u8; PUBLIC_KEY_LEN] {
        [7u8; PUBLIC_KEY_LEN]
    }

    #[test]
    fn request_round_trips_with_vouch_only() {
        // A Request carries kind + peer_key + vouch; no invite_uri, no accept.
        let msg = IntroductionMessage {
            kind: IntroductionKind::Request,
            peer_key: peer(),
            vouch: Some(b"introducer-vouch-cbor".to_vec()),
            invite_uri: None,
            accept: None,
        };
        let recovered = decode_introduction(&encode_introduction(&msg).unwrap()).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn accepting_response_round_trips_invite_and_accept() {
        // An accepting Response carries kind + peer_key + invite_uri + accept.
        let msg = IntroductionMessage {
            kind: IntroductionKind::Response,
            peer_key: peer(),
            vouch: None,
            invite_uri: Some("https://simplex.example/invite#one-time".to_string()),
            accept: Some(true),
        };
        let recovered = decode_introduction(&encode_introduction(&msg).unwrap()).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn declining_response_round_trips_accept_false_without_invite() {
        let msg = IntroductionMessage {
            kind: IntroductionKind::Response,
            peer_key: peer(),
            vouch: None,
            invite_uri: None,
            accept: Some(false),
        };
        let recovered = decode_introduction(&encode_introduction(&msg).unwrap()).unwrap();
        assert_eq!(recovered, msg);
        assert_eq!(recovered.accept, Some(false));
    }

    #[test]
    fn deliver_round_trips_vouch_and_invite() {
        // A Deliver carries kind + peer_key + vouch + invite_uri; no accept.
        let msg = IntroductionMessage {
            kind: IntroductionKind::Deliver,
            peer_key: peer(),
            vouch: Some(b"introducer-vouch-cbor".to_vec()),
            invite_uri: Some("https://simplex.example/invite#one-time".to_string()),
            accept: None,
        };
        let recovered = decode_introduction(&encode_introduction(&msg).unwrap()).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn unknown_kind_rejected() {
        // kind = 9 is not a known discriminant.
        let entries = vec![
            (Value::Int(KEY_KIND), Value::Int(9)),
            (Value::Int(KEY_PEER_KEY), Value::Bytes(peer().to_vec())),
        ];
        let bytes = Value::Map(entries).encode().unwrap();
        assert!(matches!(
            decode_introduction(&bytes),
            Err(TrustGraphError::MalformedPayload)
        ));
    }

    #[test]
    fn wrong_length_peer_key_rejected() {
        let entries = vec![
            (Value::Int(KEY_KIND), Value::Int(KIND_REQUEST)),
            (Value::Int(KEY_PEER_KEY), Value::Bytes(vec![0u8; 16])),
        ];
        let bytes = Value::Map(entries).encode().unwrap();
        assert!(matches!(
            decode_introduction(&bytes),
            Err(TrustGraphError::MalformedPayload)
        ));
    }

    #[test]
    fn missing_peer_key_rejected() {
        let entries = vec![(Value::Int(KEY_KIND), Value::Int(KIND_REQUEST))];
        let bytes = Value::Map(entries).encode().unwrap();
        assert!(matches!(
            decode_introduction(&bytes),
            Err(TrustGraphError::MalformedPayload)
        ));
    }

    #[test]
    fn garbage_rejected() {
        assert!(matches!(
            decode_introduction(&[0xFF, 0xFF, 0xFF]),
            Err(TrustGraphError::MalformedPayload)
        ));
    }
}
