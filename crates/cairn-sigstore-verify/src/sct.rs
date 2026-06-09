// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Embedded Signed Certificate Timestamp (SCT) verification per
//! RFC 6962 §3.2 — the CT-log-inclusion half of full Sigstore Fulcio
//! verification (D0042 §6.5).
//!
//! A real Fulcio leaf embeds one or more SCTs in the
//! `1.3.6.1.4.1.11129.2.4.2` extension, each a CT log's signed promise
//! that the certificate was published to the public Certificate
//! Transparency log. Verifying the SCT against a **pinned** CT-log key
//! closes a Fulcio-compromise gap that the Rekor inclusion + OIDC pins do
//! not: a cert that Fulcio issued but never CT-logged (so it would not be
//! publicly visible) is rejected.
//!
//! ## What the CT log signed (RFC 6962 §3.2)
//!
//! For an **embedded** SCT the log signed a `digitally-signed` blob over a
//! `precert_entry`, NOT the final certificate:
//!
//! ```text
//! version(1=0) || signature_type(1=0) || timestamp(8) ||
//! entry_type(2 = precert_entry(1)) ||
//!   issuer_key_hash(32 = SHA-256(issuer SPKI DER)) ||
//!   tbs_certificate(3-byte length || precert TBSCertificate) ||
//! ct_extensions(2-byte length || bytes)
//! ```
//!
//! The `precert TBSCertificate` is the **final leaf's TBSCertificate with
//! the SCT-list extension removed** and re-encoded. This module rebuilds
//! it by surgically excising that one extension's DER TLV and recomputing
//! the enclosing definite-length headers. The reconstruction is validated
//! **byte-exact** by the downstream check: if it were wrong by one byte,
//! `SHA-256(blob)` would differ and the real CT log's ECDSA signature
//! would not verify — so a green real-cert test (`tests/sct_vector.rs`,
//! over the captured production GitHub Actions leaf) is the proof of
//! correctness, not an assertion about the splice.
//!
//! Pure byte-work + the in-tree `p256` (ECDSA-P256 verify) + `sha2`
//! (SHA-256). No second X.509 parser / DER re-encoder is pulled in: the
//! transformation is mechanical and its correctness is fully witnessed by
//! the signature check (unlike chain-signature verification, which D0024
//! §6.5 deliberately delegated to a vetted library).

// DER byte-offset parsing + RFC 6962 TLS-struct length arithmetic. Every
// access is explicitly bounds-checked before use (out-of-range -> a
// verification error, never a panic), and the whole reconstruction is
// validated byte-exact by the real-cert SCT signature. Mirrors the
// produce.rs Merkle-math allowance; `unwrap`/`expect`/`panic` stay denied.
// `cast_possible_truncation`: the length-of-length casts are bounded <= 8
// (a usize is <= 8 bytes), and the blob length-prefix casts cannot cause a
// false ACCEPT — a truncated prefix yields a non-matching signed blob, so
// the ECDSA check fails closed.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "DER/TLS byte-offset surgery, bounds-checked + signature-witnessed; never panics, never false-accepts"
)]

use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::error::SigstoreVerifyError;

/// The embedded SCT-list extension OID `1.3.6.1.4.1.11129.2.4.2`, as the
/// full DER OID TLV (`06 0A …`) — matched against the head of each
/// Extension's content during the TBS walk.
const SCT_OID_TLV: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02,
];

/// A minimal DER TLV view: the tag byte + the value slice.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

const fn sct_err() -> SigstoreVerifyError {
    SigstoreVerifyError::SctVerifyFailed
}

/// Read one DER TLV from the front of `buf`; return it + the trailing
/// bytes. Supports short-form and long-form (≤4-byte) definite lengths.
fn read_tlv(buf: &[u8]) -> Result<(Tlv<'_>, &[u8]), SigstoreVerifyError> {
    if buf.len() < 2 {
        return Err(sct_err());
    }
    let tag = buf[0];
    let first = buf[1];
    let (len, hdr) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return Err(sct_err());
        }
        let mut l = 0usize;
        for k in 0..n {
            l = (l << 8) | usize::from(buf[2 + k]);
        }
        (l, 2 + n)
    };
    let end = hdr.checked_add(len).ok_or_else(sct_err)?;
    if buf.len() < end {
        return Err(sct_err());
    }
    Ok((
        Tlv {
            tag,
            value: &buf[hdr..end],
        },
        &buf[end..],
    ))
}

/// Encode a DER definite length.
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut bytes = n.to_be_bytes().to_vec();
    while bytes.first() == Some(&0) {
        bytes.remove(0);
    }
    let mut out = vec![0x80 | (bytes.len() as u8)];
    out.extend_from_slice(&bytes);
    out
}

/// Wrap `content` in a DER TLV with `tag`.
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Reconstruct the **precert** TBSCertificate (the leaf TBS with the
/// SCT-list extension removed) and return it alongside the SCT extension's
/// `extnValue` content (the inner DER OCTET STRING wrapping the TLS SCT
/// list).
///
/// # Errors
///
/// [`SigstoreVerifyError::SctMissing`] if no SCT-list extension is present;
/// [`SigstoreVerifyError::SctVerifyFailed`] if the DER does not parse.
fn precert_tbs_and_sct_value(leaf_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SigstoreVerifyError> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, sig }
    let (cert, _) = read_tlv(leaf_der)?;
    if cert.tag != 0x30 {
        return Err(sct_err());
    }
    let (tbs, _) = read_tlv(cert.value)?;
    if tbs.tag != 0x30 {
        return Err(sct_err());
    }
    let tbs_content = tbs.value;

    // The extensions are the `[3] EXPLICIT` element (tag 0xA3), the last
    // member of the TBSCertificate. Walk to it, tracking the prefix.
    let mut rest = tbs_content;
    loop {
        if rest.is_empty() {
            return Err(SigstoreVerifyError::SctMissing);
        }
        let (tlv, after) = read_tlv(rest)?;
        if tlv.tag == 0xA3 {
            break;
        }
        rest = after;
    }
    let prefix_len = tbs_content.len() - rest.len();
    let prefix = &tbs_content[..prefix_len];

    let (a3, _) = read_tlv(rest)?; // [3] EXPLICIT
    let (exts_seq, _) = read_tlv(a3.value)?; // SEQUENCE OF Extension
    if exts_seq.tag != 0x30 {
        return Err(sct_err());
    }

    // Walk the extensions: keep every non-SCT extension's full TLV, and
    // capture the SCT extension's extnValue content.
    let mut kept: Vec<u8> = Vec::new();
    let mut sct_value: Option<Vec<u8>> = None;
    let mut ext_rest = exts_seq.value;
    while !ext_rest.is_empty() {
        let (ext, after) = read_tlv(ext_rest)?;
        let ext_tlv = &ext_rest[..ext_rest.len() - after.len()];
        if ext.value.starts_with(SCT_OID_TLV) {
            // Extension content = OID || [critical BOOLEAN] || extnValue.
            let after_oid = &ext.value[SCT_OID_TLV.len()..];
            let (maybe, tail) = read_tlv(after_oid)?;
            let extn_value = if maybe.tag == 0x01 {
                // skip the optional critical BOOLEAN
                read_tlv(tail)?.0
            } else {
                maybe
            };
            if extn_value.tag != 0x04 {
                return Err(sct_err());
            }
            sct_value = Some(extn_value.value.to_vec());
        } else {
            kept.extend_from_slice(ext_tlv);
        }
        ext_rest = after;
    }
    let sct_value = sct_value.ok_or(SigstoreVerifyError::SctMissing)?;

    // Rebuild: TBS = prefix || [3]( SEQUENCE( kept ) ).
    let new_seq = der_tlv(0x30, &kept);
    let new_a3 = der_tlv(0xA3, &new_seq);
    let mut new_tbs_content = Vec::with_capacity(prefix.len() + new_a3.len());
    new_tbs_content.extend_from_slice(prefix);
    new_tbs_content.extend_from_slice(&new_a3);
    let precert_tbs = der_tlv(0x30, &new_tbs_content);

    Ok((precert_tbs, sct_value))
}

/// One parsed SCT (RFC 6962 §3.2 `SignedCertificateTimestamp`).
struct ParsedSct<'a> {
    log_id: [u8; 32],
    timestamp: u64,
    extensions: &'a [u8],
    signature_der: &'a [u8],
}

/// Split a TLS `SignedCertificateTimestampList` (`opaque sct<...>` vector,
/// 2-byte outer length, each entry a 2-byte-prefixed SCT) into its SCTs.
fn split_sct_list(tls: &[u8]) -> Result<Vec<&[u8]>, SigstoreVerifyError> {
    if tls.len() < 2 {
        return Err(sct_err());
    }
    let total = usize::from(u16::from_be_bytes([tls[0], tls[1]]));
    let body = &tls[2..];
    if body.len() < total {
        return Err(sct_err());
    }
    let mut out = Vec::new();
    let mut p = &body[..total];
    while !p.is_empty() {
        if p.len() < 2 {
            return Err(sct_err());
        }
        let n = usize::from(u16::from_be_bytes([p[0], p[1]]));
        if p.len() < 2 + n {
            return Err(sct_err());
        }
        out.push(&p[2..2 + n]);
        p = &p[2 + n..];
    }
    Ok(out)
}

/// Parse a single v1 SCT. Returns `None` for any malformed / unsupported
/// SCT (caller skips it rather than failing the whole list).
fn parse_sct(sct: &[u8]) -> Option<ParsedSct<'_>> {
    // version(1) logID(32) timestamp(8) ext_len(2) ext... algos(2) sig_len(2) sig
    if sct.len() < 1 + 32 + 8 + 2 || sct[0] != 0 {
        return None;
    }
    let log_id: [u8; 32] = sct[1..33].try_into().ok()?;
    let timestamp = u64::from_be_bytes(sct[33..41].try_into().ok()?);
    let ext_len = usize::from(u16::from_be_bytes([sct[41], sct[42]]));
    let after_ext = 43usize.checked_add(ext_len)?;
    if sct.len() < after_ext.checked_add(4)? {
        return None;
    }
    let extensions = &sct[43..after_ext];
    let hash_alg = sct[after_ext];
    let sig_alg = sct[after_ext + 1];
    // SHA-256 (4) + ECDSA (3) — the Sigstore CT-log algorithm.
    if hash_alg != 4 || sig_alg != 3 {
        return None;
    }
    let sig_len = usize::from(u16::from_be_bytes([sct[after_ext + 2], sct[after_ext + 3]]));
    let sig_start = after_ext + 4;
    let sig_end = sig_start.checked_add(sig_len)?;
    if sct.len() < sig_end {
        return None;
    }
    Some(ParsedSct {
        log_id,
        timestamp,
        extensions,
        signature_der: &sct[sig_start..sig_end],
    })
}

/// Build the `digitally-signed` precert blob the CT log signed over.
fn precert_signed_blob(sct: &ParsedSct, issuer_key_hash: &[u8; 32], precert_tbs: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(44 + precert_tbs.len() + sct.extensions.len());
    b.push(0); // sct_version = v1
    b.push(0); // signature_type = certificate_timestamp
    b.extend_from_slice(&sct.timestamp.to_be_bytes());
    b.extend_from_slice(&[0x00, 0x01]); // entry_type = precert_entry(1)
    b.extend_from_slice(issuer_key_hash);
    // tbs_certificate: 24-bit length prefix.
    let l = precert_tbs.len();
    b.push((l >> 16) as u8);
    b.push((l >> 8) as u8);
    b.push(l as u8);
    b.extend_from_slice(precert_tbs);
    // ct_extensions: 16-bit length prefix.
    b.extend_from_slice(&(sct.extensions.len() as u16).to_be_bytes());
    b.extend_from_slice(sct.extensions);
    b
}

/// Verify that `leaf_der` embeds an SCT issued by the **pinned** CT log
/// (`ctlog_pubkey_der`, a P-256 SPKI), proving the Fulcio leaf was
/// published to Certificate Transparency (RFC 6962 §3.2; D0042 §6.5).
///
/// `issuer_cert_der` is the DER of the leaf's issuing CA (the Fulcio
/// intermediate) — Fulcio signs precertificates directly with it, so the
/// SCT's `issuer_key_hash` is `SHA-256` of its SubjectPublicKeyInfo.
///
/// Succeeds if **any** embedded SCT whose log ID matches the pinned log's
/// (`SHA-256(ctlog_pubkey_der)`) verifies.
///
/// # Errors
///
/// - [`SigstoreVerifyError::SctMissing`] — no SCT-list extension present.
/// - [`SigstoreVerifyError::SctVerifyFailed`] — the DER/SCT did not parse,
///   the pinned CT key is invalid, or no SCT from the pinned log verified
///   against the reconstructed precert.
pub fn verify_embedded_sct(
    leaf_der: &[u8],
    issuer_cert_der: &[u8],
    ctlog_pubkey_der: &[u8],
) -> Result<(), SigstoreVerifyError> {
    let (precert_tbs, sct_value) = precert_tbs_and_sct_value(leaf_der)?;
    // sct_value is the inner DER OCTET STRING wrapping the TLS SCT list.
    let (inner, _) = read_tlv(&sct_value)?;
    if inner.tag != 0x04 {
        return Err(sct_err());
    }
    let scts = split_sct_list(inner.value)?;

    // issuer_key_hash = SHA-256(issuer SubjectPublicKeyInfo DER).
    let (_, issuer) = X509Certificate::from_der(issuer_cert_der)
        .map_err(|_| SigstoreVerifyError::SctVerifyFailed)?;
    let issuer_key_hash: [u8; 32] = Sha256::digest(issuer.public_key().raw).into();

    // The pinned CT log: its key + its log ID (SHA-256 of the SPKI DER).
    let ctlog_key = VerifyingKey::from_public_key_der(ctlog_pubkey_der)
        .map_err(|_| SigstoreVerifyError::SctVerifyFailed)?;
    let ctlog_log_id: [u8; 32] = Sha256::digest(ctlog_pubkey_der).into();

    for sct_bytes in scts {
        let Some(sct) = parse_sct(sct_bytes) else {
            continue;
        };
        if sct.log_id != ctlog_log_id {
            continue; // not the pinned log
        }
        let Ok(sig) = Signature::from_der(sct.signature_der) else {
            continue;
        };
        let blob = precert_signed_blob(&sct, &issuer_key_hash, &precert_tbs);
        if ctlog_key.verify(&blob, &sig).is_ok() {
            return Ok(());
        }
    }
    Err(SigstoreVerifyError::SctVerifyFailed)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{Tlv, der_len, der_tlv, read_tlv};

    /// DER definite-length encoding, including the short↔long-form and the
    /// long-form byte-count boundaries that extension removal can cross
    /// (the real-cert SCT proof doesn't stress these because removing one
    /// extension keeps the big containers in the same width).
    #[test]
    fn der_len_encodes_boundaries() {
        assert_eq!(der_len(0), vec![0x00]);
        assert_eq!(der_len(127), vec![0x7F]); // last short form
        assert_eq!(der_len(128), vec![0x81, 0x80]); // first long form
        assert_eq!(der_len(255), vec![0x81, 0xFF]); // last 1-byte long form
        assert_eq!(der_len(256), vec![0x82, 0x01, 0x00]); // first 2-byte
        assert_eq!(der_len(65535), vec![0x82, 0xFF, 0xFF]);
        assert_eq!(der_len(65536), vec![0x83, 0x01, 0x00, 0x00]);
    }

    /// `der_tlv` then `read_tlv` round-trips across the length boundaries —
    /// the property the precert rebuild relies on when a container's length
    /// shrinks past a width boundary after the SCT extension is excised.
    #[test]
    fn tlv_round_trips_across_length_widths() {
        for len in [0usize, 1, 127, 128, 255, 256, 300, 65535, 65536] {
            let content = vec![0xABu8; len];
            let encoded = der_tlv(0x04, &content);
            let (Tlv { tag, value }, rest) = read_tlv(&encoded).unwrap();
            assert_eq!(tag, 0x04);
            assert_eq!(value, &content[..], "len {len}");
            assert!(rest.is_empty(), "len {len}");
        }
    }

    #[test]
    fn read_tlv_rejects_truncated_long_form() {
        // 0x82 promises 2 length bytes but only 1 follows.
        assert!(read_tlv(&[0x04, 0x82, 0x01]).is_err());
        // length exceeds the buffer.
        assert!(read_tlv(&[0x04, 0x05, 0x00]).is_err());
    }
}
