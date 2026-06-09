// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Release manifest schema per D0024 §4.
//!
//! ## Schema (integer-keyed canonical-CBOR map per D0018 §2.3)
//!
//! | Key | Field                     | CBOR type        | Notes |
//! |-----|---------------------------|------------------|-------|
//! | 1   | `version`                 | text             | Semver string, e.g. `"1.0.0-pilot"` |
//! | 2   | `artifact_sha256`         | array of map     | Each: `{1: name (text), 2: sha256 (bstr 32)}` |
//! | 3   | `build_provenance_sha256` | bstr (32 bytes)  | SHA-256 of the SLSA-style build-provenance attestation |
//! | 4   | `release_timestamp`       | uint             | Unix-seconds when the manifest was signed |
//! | 5   | `prior_release_hash`      | bstr             | SHA-256 of the previous release's signed manifest; zero-length for the first release |
//!
//! ## Signing model
//!
//! The manifest is encoded canonical-CBOR per D0018 §2.3, wrapped in
//! a `COSE_Sign1` envelope per D0018 §2.1, and signed via the
//! Sigstore signing event. The Sigstore signature commits to the
//! canonical-CBOR encoded manifest bytes (the COSE_Sign1 payload).
//!
//! ## Rollback resistance (D0024 §4.2)
//!
//! `prior_release_hash` chains the release log so a client that
//! observes release N's manifest can verify it commits to release
//! N-1's manifest. A downgrade attack would require producing a
//! manifest whose `prior_release_hash` references a release whose
//! hash predates N — detectable by the client's stored release-log
//! state.
//!
//! **The chain alone does NOT establish "newest."** It links N→N-1; it
//! does not, by itself, prevent serving a validly-signed *older* release.
//! Downgrade resistance requires the CLIENT to (a) pass its stored
//! predecessor hash as `expected_predecessor_hash` and (b) refuse a
//! lower version/`versionCode`. `release_timestamp` and `version` are
//! carried for identification but are NOT verifier-checked anti-rollback
//! inputs — monotonicity is the client's obligation (D0041 §6, deferred).

use cairn_envelope::canonical::Value;
use ciborium::Value as CiboriumValue;
use sha2::{Digest, Sha256};

use crate::error::SigstoreVerifyError;

// === Canonical-CBOR map keys for the ReleaseManifest schema ===
const KEY_MANIFEST_VERSION: i64 = 1;
const KEY_MANIFEST_ARTIFACT_SHA256: i64 = 2;
const KEY_MANIFEST_BUILD_PROVENANCE: i64 = 3;
const KEY_MANIFEST_RELEASE_TIMESTAMP: i64 = 4;
const KEY_MANIFEST_PRIOR_RELEASE_HASH: i64 = 5;

// === Canonical-CBOR map keys for each ArtifactHash entry ===
const KEY_ARTIFACT_NAME: i64 = 1;
const KEY_ARTIFACT_SHA256: i64 = 2;

/// Length of every SHA-256 digest the manifest carries. 32 bytes.
pub const SHA256_LEN: usize = 32;

/// COSE_Sign1 external AAD domain for the release manifest envelope.
///
/// _[Added 2026-05-31]_ D0024 §4 specifies the manifest is signed via
/// `COSE_Sign1` but does not name an external AAD. Per the D0006 §8
/// AAD-domain-separation discipline (every Cairn envelope type binds a
/// distinct AAD so a signature over one envelope type cannot be replayed
/// as another), the release manifest uses this domain. The release
/// signing pipeline (out of scope per D0024 §8) MUST sign with this AAD;
/// [`crate::client::SigstoreVerifier::verify_release`] verifies against
/// it.
pub const RELEASE_MANIFEST_AAD: &[u8] = b"cairn-v1-release-manifest";

/// One artifact's name + SHA-256 binding, as enumerated by
/// [`ReleaseManifest::artifact_sha256`] per D0024 §4.1 key 2.
///
/// Equality + hash include both fields so the same artifact-name
/// with a different SHA-256 (the rollback / substitution attack
/// surface) does not match an expected entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArtifactHash {
    /// Human-readable artifact identifier, e.g. `"cairn-1.0.0.apk"`.
    pub name: String,
    /// SHA-256 digest of the artifact bytes.
    pub sha256: [u8; SHA256_LEN],
}

/// Canonical release manifest per D0024 §4.1.
///
/// The manifest is the payload of the Sigstore-signed `COSE_Sign1`
/// envelope: a client that holds the envelope bytes + the Fulcio-
/// issued signing certificate + the Rekor inclusion proof + the
/// Sigsum witness cosignatures can verify the full v1 release-
/// security stack against the pinned trust roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseManifest {
    /// Semver string identifying this release. Free-form text per
    /// D0024 §4.1 key 1 (e.g. `"1.0.0-pilot"`).
    pub version: String,
    /// SHA-256 binding for each artifact in the release set per
    /// D0024 §4.1 key 2.
    pub artifact_sha256: Vec<ArtifactHash>,
    /// SHA-256 of the SLSA-style build-provenance attestation per
    /// D0024 §4.1 key 3. The attestation itself ships as a bundled
    /// release artifact for independent verification.
    pub build_provenance_sha256: [u8; SHA256_LEN],
    /// Unix-seconds when the manifest was signed per D0024 §4.1
    /// key 4.
    pub release_timestamp: u64,
    /// Chain link to the predecessor release per D0024 §4.1 key 5.
    /// Zero-length for the first release; SHA-256 of the predecessor
    /// signed manifest for every subsequent release. The empty-vs-
    /// non-empty distinction is the same posture as D0006 §5's
    /// `prior_hash` for the trust-graph chain.
    pub prior_release_hash: Vec<u8>,
}

impl ReleaseManifest {
    /// Encode the manifest as canonical-CBOR per D0018 §2.3.
    ///
    /// # Errors
    ///
    /// Propagates [`SigstoreVerifyError::ManifestDecodeFailed`] for
    /// any canonical encoder error (unreachable for typed inputs).
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SigstoreVerifyError> {
        let release_ts_i64 = i64::try_from(self.release_timestamp)
            .map_err(|_| SigstoreVerifyError::ManifestDecodeFailed)?;

        let artifacts_array = self
            .artifact_sha256
            .iter()
            .map(|a| {
                Value::Map(vec![
                    (Value::Int(KEY_ARTIFACT_NAME), Value::Text(a.name.clone())),
                    (
                        Value::Int(KEY_ARTIFACT_SHA256),
                        Value::Bytes(a.sha256.to_vec()),
                    ),
                ])
            })
            .collect::<Vec<_>>();

        let map = Value::Map(vec![
            (
                Value::Int(KEY_MANIFEST_VERSION),
                Value::Text(self.version.clone()),
            ),
            (
                Value::Int(KEY_MANIFEST_ARTIFACT_SHA256),
                Value::Array(artifacts_array),
            ),
            (
                Value::Int(KEY_MANIFEST_BUILD_PROVENANCE),
                Value::Bytes(self.build_provenance_sha256.to_vec()),
            ),
            (
                Value::Int(KEY_MANIFEST_RELEASE_TIMESTAMP),
                Value::Int(release_ts_i64),
            ),
            (
                Value::Int(KEY_MANIFEST_PRIOR_RELEASE_HASH),
                Value::Bytes(self.prior_release_hash.clone()),
            ),
        ]);
        map.encode()
            .map_err(|_| SigstoreVerifyError::ManifestDecodeFailed)
    }

    /// Decode the manifest from canonical-CBOR bytes.
    ///
    /// Unknown integer keys are tolerated per D0006 §6.4's forward-
    /// compatibility discipline.
    ///
    /// # Errors
    ///
    /// [`SigstoreVerifyError::ManifestDecodeFailed`] for any CBOR or
    /// schema structural error.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SigstoreVerifyError> {
        // Strict canonical map decode (D0041 §6.3): rejects trailing bytes +
        // duplicate keys; unknown integer keys are still tolerated (D0006 §6.4).
        let entries = crate::decode::decode_canonical_map(bytes)
            .ok_or(SigstoreVerifyError::ManifestDecodeFailed)?;

        let mut version: Option<String> = None;
        let mut artifact_sha256: Option<Vec<ArtifactHash>> = None;
        let mut build_provenance_sha256: Option<[u8; SHA256_LEN]> = None;
        let mut release_timestamp: Option<u64> = None;
        let mut prior_release_hash: Option<Vec<u8>> = None;

        for (key_int, value) in entries {
            match key_int {
                KEY_MANIFEST_VERSION => {
                    let CiboriumValue::Text(s) = value else {
                        return Err(SigstoreVerifyError::ManifestDecodeFailed);
                    };
                    version = Some(s);
                }
                KEY_MANIFEST_ARTIFACT_SHA256 => {
                    artifact_sha256 = Some(decode_artifact_hashes(value)?);
                }
                KEY_MANIFEST_BUILD_PROVENANCE => {
                    build_provenance_sha256 = Some(bytes_to_array_32(value)?);
                }
                KEY_MANIFEST_RELEASE_TIMESTAMP => {
                    release_timestamp = Some(int_to_u64(&value)?);
                }
                KEY_MANIFEST_PRIOR_RELEASE_HASH => {
                    let CiboriumValue::Bytes(b) = value else {
                        return Err(SigstoreVerifyError::ManifestDecodeFailed);
                    };
                    // Exactly zero-length (genesis) or a 32-byte SHA-256 link —
                    // reject any other length so "genesis vs linked" is a total,
                    // validated distinction with no ambiguous third state (review
                    // remediation). The rollback check (D0024 §4.2) compares this
                    // against a `[u8; 32]`, so a wrong length already fails closed;
                    // rejecting at decode makes the intent explicit.
                    if !b.is_empty() && b.len() != SHA256_LEN {
                        return Err(SigstoreVerifyError::ManifestDecodeFailed);
                    }
                    prior_release_hash = Some(b);
                }
                _ => {} // forward-compat per D0006 §6.4
            }
        }

        Ok(Self {
            version: version.ok_or(SigstoreVerifyError::ManifestDecodeFailed)?,
            artifact_sha256: artifact_sha256.ok_or(SigstoreVerifyError::ManifestDecodeFailed)?,
            build_provenance_sha256: build_provenance_sha256
                .ok_or(SigstoreVerifyError::ManifestDecodeFailed)?,
            release_timestamp: release_timestamp
                .ok_or(SigstoreVerifyError::ManifestDecodeFailed)?,
            prior_release_hash: prior_release_hash
                .ok_or(SigstoreVerifyError::ManifestDecodeFailed)?,
        })
    }

    /// Compute `SHA-256(canonical-CBOR encoded manifest bytes)`.
    ///
    /// This is the value the NEXT release's [`Self::prior_release_hash`]
    /// must equal for the rollback-resistance check per D0024 §4.2.
    ///
    /// # Errors
    ///
    /// Propagates [`SigstoreVerifyError::ManifestDecodeFailed`] for
    /// encode failures (unreachable for typed inputs).
    pub fn canonical_self_hash(&self) -> Result<[u8; SHA256_LEN], SigstoreVerifyError> {
        let encoded = self.to_canonical_cbor()?;
        let mut hasher = Sha256::new();
        hasher.update(&encoded);
        let out = hasher.finalize();
        let mut arr = [0u8; SHA256_LEN];
        arr.copy_from_slice(&out);
        Ok(arr)
    }
}

// === Internal decode helpers ===

fn int_to_u64(value: &CiboriumValue) -> Result<u64, SigstoreVerifyError> {
    let CiboriumValue::Integer(v) = value else {
        return Err(SigstoreVerifyError::ManifestDecodeFailed);
    };
    u64::try_from(i128::from(*v)).map_err(|_| SigstoreVerifyError::ManifestDecodeFailed)
}

fn bytes_to_array_32(value: CiboriumValue) -> Result<[u8; SHA256_LEN], SigstoreVerifyError> {
    let CiboriumValue::Bytes(b) = value else {
        return Err(SigstoreVerifyError::ManifestDecodeFailed);
    };
    if b.len() != SHA256_LEN {
        return Err(SigstoreVerifyError::ManifestDecodeFailed);
    }
    let mut arr = [0u8; SHA256_LEN];
    arr.copy_from_slice(&b);
    Ok(arr)
}

fn decode_artifact_hashes(value: CiboriumValue) -> Result<Vec<ArtifactHash>, SigstoreVerifyError> {
    let CiboriumValue::Array(entries) = value else {
        return Err(SigstoreVerifyError::ManifestDecodeFailed);
    };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let CiboriumValue::Map(map_entries) = entry else {
            return Err(SigstoreVerifyError::ManifestDecodeFailed);
        };
        let mut name: Option<String> = None;
        let mut sha256: Option<[u8; SHA256_LEN]> = None;
        for (k, v) in map_entries {
            let CiboriumValue::Integer(ki) = k else {
                return Err(SigstoreVerifyError::ManifestDecodeFailed);
            };
            let ki_i64 = i64::try_from(i128::from(ki))
                .map_err(|_| SigstoreVerifyError::ManifestDecodeFailed)?;
            match ki_i64 {
                KEY_ARTIFACT_NAME => {
                    let CiboriumValue::Text(s) = v else {
                        return Err(SigstoreVerifyError::ManifestDecodeFailed);
                    };
                    name = Some(s);
                }
                KEY_ARTIFACT_SHA256 => {
                    sha256 = Some(bytes_to_array_32(v)?);
                }
                _ => {} // forward-compat per D0006 §6.4
            }
        }
        out.push(ArtifactHash {
            name: name.ok_or(SigstoreVerifyError::ManifestDecodeFailed)?,
            sha256: sha256.ok_or(SigstoreVerifyError::ManifestDecodeFailed)?,
        });
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_manifest() -> ReleaseManifest {
        ReleaseManifest {
            version: "1.0.0-pilot".to_string(),
            artifact_sha256: vec![
                ArtifactHash {
                    name: "cairn-1.0.0.apk".to_string(),
                    sha256: [0xAAu8; SHA256_LEN],
                },
                ArtifactHash {
                    name: "cairn-1.0.0.apk.idsig".to_string(),
                    sha256: [0xBBu8; SHA256_LEN],
                },
            ],
            build_provenance_sha256: [0xCCu8; SHA256_LEN],
            release_timestamp: 1_700_000_000,
            prior_release_hash: vec![],
        }
    }

    #[test]
    fn manifest_round_trips_through_canonical_cbor() {
        let original = make_manifest();
        let bytes = original.to_canonical_cbor().unwrap();
        let recovered = ReleaseManifest::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn manifest_with_non_empty_prior_release_hash_round_trips() {
        let mut original = make_manifest();
        original.prior_release_hash = vec![0xDD; SHA256_LEN];
        let bytes = original.to_canonical_cbor().unwrap();
        let recovered = ReleaseManifest::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn manifest_rejects_wrong_length_prior_release_hash() {
        // {0, 32} only — a 5-byte prior is neither a valid genesis (empty)
        // nor a valid 32-byte chain link, so decode must reject it (review
        // remediation: make "genesis vs linked" a total, validated distinction).
        let mut m = make_manifest();
        m.prior_release_hash = vec![0xABu8; 5];
        let bytes = m.to_canonical_cbor().unwrap();
        assert!(matches!(
            ReleaseManifest::from_canonical_cbor(&bytes),
            Err(SigstoreVerifyError::ManifestDecodeFailed)
        ));
    }

    #[test]
    fn manifest_with_empty_artifact_set_round_trips() {
        let mut original = make_manifest();
        original.artifact_sha256.clear();
        let bytes = original.to_canonical_cbor().unwrap();
        let recovered = ReleaseManifest::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn malformed_bytes_fail_manifest_decode() {
        let result = ReleaseManifest::from_canonical_cbor(b"\xFF\x00\x01");
        assert!(matches!(
            result,
            Err(SigstoreVerifyError::ManifestDecodeFailed)
        ));
    }

    #[test]
    fn canonical_self_hash_is_deterministic() {
        let m = make_manifest();
        let h1 = m.canonical_self_hash().unwrap();
        let h2 = m.canonical_self_hash().unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), SHA256_LEN);
    }

    #[test]
    fn canonical_self_hash_differs_for_distinct_manifests() {
        let m_a = make_manifest();
        let mut m_b = make_manifest();
        m_b.version = "1.0.1-pilot".to_string();
        assert_ne!(
            m_a.canonical_self_hash().unwrap(),
            m_b.canonical_self_hash().unwrap()
        );
    }

    #[test]
    fn canonical_self_hash_pins_artifact_sha256_substitution() {
        // D0024 §4.2 rollback-resistance argument: a manifest with
        // a substituted artifact SHA-256 produces a distinct
        // canonical_self_hash. This pins the property that an
        // attacker who swaps an artifact's hash cannot then claim
        // the same manifest identity downstream.
        let m_a = make_manifest();
        let mut m_b = make_manifest();
        m_b.artifact_sha256[0].sha256 = [0xEE; SHA256_LEN];
        assert_ne!(
            m_a.canonical_self_hash().unwrap(),
            m_b.canonical_self_hash().unwrap()
        );
    }

    /// Re-encode `valid` canonical-CBOR map bytes with the first `(key,
    /// value)` entry duplicated, to exercise the duplicate-key strictness
    /// gate (D0041 §6.3) without hand-assembling CBOR.
    fn duplicate_first_map_key(valid: &[u8]) -> Vec<u8> {
        let value: ciborium::Value = ciborium::de::from_reader(valid).unwrap();
        let ciborium::Value::Map(mut entries) = value else {
            panic!("expected a top-level CBOR map");
        };
        let first = entries[0].clone();
        entries.push(first);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Map(entries), &mut out).unwrap();
        out
    }

    #[test]
    fn manifest_rejects_trailing_bytes() {
        // The canonical wire form is exactly one CBOR item; a trailing byte
        // is a malleability vector the strict decoder must reject (D0041 §6.3).
        // The manifest payload is also COSE-signature-pinned in the full
        // verify path, but the codec itself rejects this independently.
        let mut bytes = make_manifest().to_canonical_cbor().unwrap();
        bytes.push(0x00);
        assert!(matches!(
            ReleaseManifest::from_canonical_cbor(&bytes),
            Err(SigstoreVerifyError::ManifestDecodeFailed)
        ));
    }

    #[test]
    fn manifest_rejects_duplicate_key() {
        // Duplicate integer keys are non-canonical (D0018 §2.3) and a
        // parser-differential footgun; the strict decoder must reject them.
        let dup = duplicate_first_map_key(&make_manifest().to_canonical_cbor().unwrap());
        assert!(matches!(
            ReleaseManifest::from_canonical_cbor(&dup),
            Err(SigstoreVerifyError::ManifestDecodeFailed)
        ));
    }
}
