// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Witness pool config + cosignature verification per D0023 §3.
//!
//! ## Witness pool config format
//!
//! ```toml
//! [[witness]]
//! name = "Witness Alpha"
//! pubkey_hex = "..."
//! url = "https://witness-alpha.example.org"
//!
//! [[witness]]
//! name = "Witness Bravo"
//! pubkey_hex = "..."
//! url = "https://witness-bravo.example.org"
//!
//! [[witness]]
//! name = "Witness Charlie"
//! pubkey_hex = "..."
//! url = "https://witness-charlie.example.org"
//! ```
//!
//! Pool changes require a release per D0023 §3.3 — runtime mutation
//! is not supported.
//!
//! ## Cosignature signing input (C2SP `tlog-cosignature/v1`)
//!
//! Per the Sigsum v1 log spec + <https://c2sp.org/tlog-cosignature>,
//! each witness cosignature is an Ed25519 signature over a short ASCII
//! message — NOT a fixed binary concatenation. The message is the
//! `cosignature/v1` header + a `time` line + the log's checkpoint note:
//!
//! ```text
//! cosignature/v1\n
//! time <posix_seconds>\n
//! sigsum.org/v1/tree/<hex(SHA-256(log_pubkey))>\n
//! <tree_size in decimal>\n
//! <base64(root_hash)>\n
//! ```
//!
//! The last three lines are the **checkpoint note** the LOG itself
//! signs (the `signature=` field of `get-tree-head`); the witness
//! wraps that note with the `cosignature/v1` header + its own `time`
//! line. [`build_tree_head_note`] produces the note;
//! [`build_cosignature_signed_message`] wraps it into the witness
//! signing input.
//!
//! The `cosignature/v1` / `sigsum.org/v1/tree/...` prefixes are the
//! C2SP context binding; they prevent cross-protocol signature
//! substitution against e.g. message envelopes signed under the same
//! Ed25519 key. (Cairn's own envelopes use AAD-binding per D0006 §8 —
//! different domain, same defense.) The per-cosignature `timestamp` is
//! part of the signed bytes, so it MUST be carried alongside the
//! signature to re-verify a cached cosignature (see
//! [`crate::cache::Cosignature`]).
//!
//! A witness is identified on the wire by its 4-byte C2SP key id,
//! [`witness_key_hash`] = `SHA-256(name ‖ "\n" ‖ 0x04 ‖ pubkey)[:4]`.
//!
//! > Historical note: an earlier draft of D0023 §3.1 specified a
//! > 48-byte binary input `tree_size ‖ root_hash ‖ timestamp`. That
//! > was never the Sigsum wire format; it was corrected to the C2SP
//! > format above (D0023 revision 2026-05-30).
//!
//! ## Acceptance threshold
//!
//! D0023 §3.4 (revised 2026-06-24): pool size and cosignature
//! threshold are governed by a [`WitnessPolicy`] supplied at
//! construction time. The original policy required exactly 3
//! witnesses with a 2-of-3 threshold ([`WitnessPolicy::LEGACY`]);
//! the revised design supports graduated deployment from 1-of-1
//! ([`WitnessPolicy::BOOTSTRAP`]) through majority quorums of
//! larger pools ([`WitnessPolicy::TARGET`]: 3-of-5).
//!
//! Pools smaller than the policy's minimum fail with
//! [`crate::SigsumError::WitnessPoolTooSmall`].

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, VerifyingKey};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::SigsumError;

/// Legacy minimum witness pool size per the original D0023 §3.4.
///
/// Callers should use [`WitnessPolicy`] instead of bare constants.
/// Retained for backward-compatible test references; new code should
/// construct a policy via [`WitnessPolicy::legacy`].
pub const MIN_WITNESS_COUNT: u8 = 3;

/// Legacy required cosignature count per the original D0023 §3.4.
///
/// See [`MIN_WITNESS_COUNT`] note. New code should use
/// [`WitnessPolicy`].
pub const REQUIRED_COSIGNATURE_COUNT: u8 = 2;

/// Witness acceptance policy per D0023 §3.4 (revised 2026-06-24).
///
/// Encapsulates the minimum pool size and the required cosignature
/// threshold. The threshold expresses how many configured witnesses
/// must produce a valid cosignature for a tree head to be accepted.
///
/// ## Rationale for flexibility
///
/// The original D0023 §3.4 hard-coded "exactly 3 witnesses, 2-of-3".
/// Per guidance from Rasmus Dahlberg (Sigsum maintainer): one external
/// witness is strictly better than none, and the independence of each
/// witness (different org, country, sw/hw stack) matters more than
/// count. The sweet spot is somewhere around 5/9 or 7/11, with
/// diminishing returns past ~15.
///
/// A graduated policy lets Cairn ship with whatever witnesses are
/// recruited — 1-of-1 during bootstrap, scaling toward a majority
/// quorum as the pool grows — without code changes at each step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessPolicy {
    /// Minimum number of witnesses the pool must contain.
    /// [`parse_witness_pool`] rejects pools smaller than this.
    min_pool_size: u8,
    /// Number of valid cosignatures required for acceptance. The
    /// `verify_parsed_tree_head` path rejects a tree head when fewer
    /// than this many witnesses verify.
    required_cosignatures: u8,
}

impl WitnessPolicy {
    /// Construct a policy, validating that `required <= min_pool_size`
    /// and both are nonzero.
    ///
    /// Returns `None` if the invariant fails: a threshold larger than
    /// the pool can never be satisfied, and a zero-witness pool or
    /// zero-threshold acceptance is meaningless.
    #[must_use]
    pub const fn new(min_pool_size: u8, required_cosignatures: u8) -> Option<Self> {
        if min_pool_size == 0 || required_cosignatures == 0 {
            return None;
        }
        if required_cosignatures > min_pool_size {
            return None;
        }
        Some(Self {
            min_pool_size,
            required_cosignatures,
        })
    }

    /// The original D0023 §3.4 policy: 3 witnesses, 2-of-3 threshold.
    /// Retained for backward compatibility and tests.
    pub const LEGACY: Self = Self {
        min_pool_size: 3,
        required_cosignatures: 2,
    };

    /// Bootstrap policy: one external witness, one cosignature
    /// required. Strictly better than the self-minted status quo;
    /// appropriate during initial witness recruitment.
    pub const BOOTSTRAP: Self = Self {
        min_pool_size: 1,
        required_cosignatures: 1,
    };

    /// Target policy: 5 witnesses, 3-of-5 majority required. Balances
    /// independence against recruitment difficulty per Dahlberg's
    /// guidance that the sweet spot is somewhere around 5/9 or 7/11.
    pub const TARGET: Self = Self {
        min_pool_size: 5,
        required_cosignatures: 3,
    };

    /// Minimum pool size for this policy.
    #[must_use]
    pub const fn min_pool_size(&self) -> u8 {
        self.min_pool_size
    }

    /// Required cosignature count for acceptance.
    #[must_use]
    pub const fn required_cosignatures(&self) -> u8 {
        self.required_cosignatures
    }
}

/// C2SP `tlog-cosignature/v1` header line — the domain-separation
/// prefix of the message a witness signs (per
/// <https://c2sp.org/tlog-cosignature>). Defends against cross-
/// protocol signature substitution.
pub const COSIGNATURE_V1_HEADER: &[u8] = b"cosignature/v1\n";

/// Sigsum checkpoint origin prefix per the Sigsum v1 log spec. The
/// full origin line is this prefix followed by the lowercase-hex log
/// key hash, e.g. `sigsum.org/v1/tree/<hex>`.
pub const SIGSUM_ORIGIN_PREFIX: &str = "sigsum.org/v1/tree/";

/// Length of a C2SP Ed25519 key id (the first 4 bytes of the
/// key-hash) per <https://c2sp.org/tlog-cosignature>.
pub const WITNESS_KEY_HASH_LEN: usize = 4;

/// One witness in the configured pool.
///
/// Derives `Serialize` + `Deserialize` for the witnesses.toml parse
/// path; the on-disk representation has the pubkey as a hex string
/// for human-readability, which decodes into the typed `pubkey` field
/// at parse time.
#[derive(Debug, Clone)]
pub struct Witness {
    /// Display name (operational use; informs error messages).
    pub name: String,
    /// Ed25519 public key the witness signs cosignatures under.
    pub pubkey: VerifyingKey,
    /// HTTPS endpoint the client fetches cosignatures from.
    pub url: Url,
}

/// Raw TOML representation of one witness entry. Decoded into
/// [`Witness`] at parse time.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct WitnessRaw {
    name: String,
    pubkey_hex: String,
    url: String,
}

/// The configured witness pool. Constructed via [`parse_witness_pool`].
///
/// Discipline: any pool with fewer entries than the
/// [`WitnessPolicy`]'s minimum is rejected at parse time.
#[derive(Debug, Clone)]
pub struct WitnessPool {
    witnesses: Vec<Witness>,
}

impl WitnessPool {
    /// Return the configured witnesses in pool order.
    #[must_use]
    pub fn witnesses(&self) -> &[Witness] {
        &self.witnesses
    }

    /// Return the witness at `index`, if present.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&Witness> {
        self.witnesses.get(index)
    }

    /// Pool size. Guaranteed `>= policy.min_pool_size()` for any pool
    /// constructed via the public API.
    #[must_use]
    pub fn len(&self) -> u8 {
        // The constructor enforces len() <= u8::MAX (it would fail
        // earlier on more than ~255 witnesses).
        u8::try_from(self.witnesses.len()).unwrap_or(u8::MAX)
    }

    /// Return `true` if the pool size is below the minimum threshold.
    /// Since the constructor rejects undersized pools, this should
    /// always return `false` for a successfully-constructed pool.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.witnesses.is_empty()
    }
}

/// Parse a witness pool from a TOML config string, validated against
/// the given [`WitnessPolicy`].
///
/// Rejects pools with fewer than `policy.min_pool_size()` entries.
/// Each entry's pubkey hex must decode to exactly [`PUBLIC_KEY_LEN`]
/// bytes and parse as a valid Ed25519 curve point.
///
/// # Errors
///
/// - [`SigsumError::WitnessConfigParse`] for any TOML parse failure,
///   missing field, malformed pubkey hex, or invalid URL
/// - [`SigsumError::WitnessPoolTooSmall`] if the parsed pool has
///   fewer than `policy.min_pool_size()` entries
pub fn parse_witness_pool(toml_text: &str, policy: &WitnessPolicy) -> Result<WitnessPool, SigsumError> {
    #[derive(Deserialize, Default)]
    struct Wrapper {
        #[serde(default, rename = "witness")]
        witnesses: Vec<WitnessRaw>,
    }

    let wrapper: Wrapper =
        toml::from_str(toml_text).map_err(|_| SigsumError::WitnessConfigParse)?;

    let mut witnesses = Vec::with_capacity(wrapper.witnesses.len());
    for raw in wrapper.witnesses {
        let pubkey_bytes = decode_hex(&raw.pubkey_hex).ok_or(SigsumError::WitnessConfigParse)?;
        if pubkey_bytes.len() != PUBLIC_KEY_LEN {
            return Err(SigsumError::WitnessConfigParse);
        }
        let mut pubkey_arr = [0u8; PUBLIC_KEY_LEN];
        pubkey_arr.copy_from_slice(&pubkey_bytes);
        let pubkey =
            VerifyingKey::from_bytes(&pubkey_arr).map_err(|_| SigsumError::WitnessConfigParse)?;
        let url = Url::parse(&raw.url).map_err(|_| SigsumError::WitnessConfigParse)?;
        witnesses.push(Witness {
            name: raw.name,
            pubkey,
            url,
        });
    }

    let configured = u8::try_from(witnesses.len()).unwrap_or(u8::MAX);
    if configured < policy.min_pool_size() {
        return Err(SigsumError::WitnessPoolTooSmall {
            configured,
            minimum: policy.min_pool_size(),
        });
    }

    Ok(WitnessPool { witnesses })
}

/// Verify a single witness cosignature against the C2SP
/// `tlog-cosignature/v1` signed message per D0023 §3.1.
///
/// `signed_message` is the value [`build_cosignature_signed_message`]
/// produces — `cosignature/v1\n` + `time <ts>\n` + the checkpoint
/// note body. Routes through
/// `cairn_crypto::ed25519::VerifyingKey::verify_strict` per D0018 §1.1
/// — same code path as every other Ed25519 verification in Cairn.
///
/// # Errors
///
/// Returns [`SigsumError::CosignatureVerifyFailed`] for any
/// verification failure (uniform per D0018 §1.4 no-error-oracle).
pub fn verify_cosignature(
    pubkey: &VerifyingKey,
    witness_index: u8,
    signed_message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), SigsumError> {
    use cairn_crypto::ed25519::Signature;

    if signature_bytes.len() != cairn_crypto::ed25519::SIGNATURE_LEN {
        return Err(SigsumError::CosignatureVerifyFailed { witness_index });
    }
    let mut sig_arr = [0u8; cairn_crypto::ed25519::SIGNATURE_LEN];
    sig_arr.copy_from_slice(signature_bytes);
    let signature = Signature::from_bytes(sig_arr);

    pubkey
        .verify(signed_message, &signature)
        .map_err(|_| SigsumError::CosignatureVerifyFailed { witness_index })
}

/// Build the Sigsum checkpoint note body that the LOG signs — and
/// that the witness cosignature wraps — per the Sigsum v1 log spec
/// (`get-tree-head`):
///
/// ```text
/// sigsum.org/v1/tree/<hex(log_key_hash)>\n
/// <tree_size in decimal, no leading zeros>\n
/// <base64(root_hash)>\n
/// ```
///
/// Each of the three lines is newline-terminated. The log's
/// `signature=` field in `get-tree-head` is an Ed25519 signature over
/// exactly these bytes.
#[must_use]
pub fn build_tree_head_note(
    log_key_hash: &[u8; 32],
    tree_size: u64,
    root_hash: &[u8; 32],
) -> Vec<u8> {
    use base64::Engine as _;
    use core::fmt::Write as _;

    let mut s = String::new();
    s.push_str(SIGSUM_ORIGIN_PREFIX);
    s.push_str(&encode_hex(log_key_hash));
    s.push('\n');
    // Decimal, no leading zeros (Rust's Display for u64 already does
    // this; 0 renders as "0" which the spec permits).
    let _ = writeln!(&mut s, "{tree_size}");
    s.push_str(&base64::engine::general_purpose::STANDARD.encode(root_hash));
    s.push('\n');
    s.into_bytes()
}

/// Build the C2SP `tlog-cosignature/v1` signed message a witness
/// signs per <https://c2sp.org/tlog-cosignature> + D0023 §3.1:
///
/// ```text
/// cosignature/v1\n
/// time <posix timestamp in decimal>\n
/// <tree_head_note>
/// ```
///
/// `tree_head_note` is the value [`build_tree_head_note`] produces.
/// The entire byte string (including all newlines) is the Ed25519
/// signing input.
#[must_use]
pub fn build_cosignature_signed_message(timestamp: u64, tree_head_note: &[u8]) -> Vec<u8> {
    use core::fmt::Write as _;

    let mut out = Vec::with_capacity(
        COSIGNATURE_V1_HEADER
            .len()
            .saturating_add(24)
            .saturating_add(tree_head_note.len()),
    );
    out.extend_from_slice(COSIGNATURE_V1_HEADER);
    let mut time_line = String::new();
    let _ = writeln!(&mut time_line, "time {timestamp}");
    out.extend_from_slice(time_line.as_bytes());
    out.extend_from_slice(tree_head_note);
    out
}

/// Compute the C2SP Ed25519 key id for a witness per
/// <https://c2sp.org/tlog-cosignature>:
/// `SHA-256(name ‖ "\n" ‖ 0x04 ‖ pubkey)[:4]`.
///
/// The `get-tree-head` `cosignature=` lines identify their witness by
/// this 4-byte id; the client computes it per configured witness to
/// map a cosignature back to its pool entry.
#[must_use]
pub fn witness_key_hash(name: &str, pubkey: &VerifyingKey) -> [u8; WITNESS_KEY_HASH_LEN] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"\n");
    hasher.update([0x04u8]);
    hasher.update(pubkey.to_bytes());
    let out = hasher.finalize();
    let mut arr = [0u8; WITNESS_KEY_HASH_LEN];
    // Take the first WITNESS_KEY_HASH_LEN bytes without slicing: SHA-256
    // always yields 32 bytes, so the zip copies exactly the 4-byte
    // prefix and never indexes out of bounds.
    for (slot, byte) in arr.iter_mut().zip(out.iter()) {
        *slot = *byte;
    }
    arr
}

/// Lowercase-hex-encode a byte slice (no `0x` prefix). Inverse of
/// [`decode_hex`]; used for the origin line's log key hash.
fn encode_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Decode a hex string (lowercase or uppercase, no whitespace, no
/// `0x` prefix). Returns `None` on any structural error so the caller
/// can surface a single typed error variant.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let pairs = bytes.len() / 2;
    for i in 0..pairs {
        let hi = hex_value(*bytes.get(i.saturating_mul(2))?)?;
        let lo = hex_value(*bytes.get(i.saturating_mul(2).saturating_add(1))?)?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

const fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use rand_core::OsRng;

    fn make_witness_toml(count: usize) -> String {
        let mut rng = OsRng;
        let mut out = String::new();
        for i in 0..count {
            let sk = SigningKey::generate(&mut rng);
            let pubkey_hex =
                sk.verifying_key()
                    .to_bytes()
                    .iter()
                    .fold(String::new(), |mut acc, b| {
                        use core::fmt::Write as _;
                        let _ = write!(&mut acc, "{b:02x}");
                        acc
                    });
            out.push_str(&format!(
                "[[witness]]\nname = \"Witness {i}\"\npubkey_hex = \"{pubkey_hex}\"\nurl = \"https://witness-{i}.example.org\"\n\n"
            ));
        }
        out
    }

    #[test]
    fn parse_witness_pool_with_three_entries_succeeds_legacy_policy() {
        let toml_text = make_witness_toml(3);
        let pool = parse_witness_pool(&toml_text, &WitnessPolicy::LEGACY).unwrap();
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn parse_witness_pool_with_one_entry_succeeds_bootstrap_policy() {
        let toml_text = make_witness_toml(1);
        let pool = parse_witness_pool(&toml_text, &WitnessPolicy::BOOTSTRAP).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn parse_witness_pool_with_two_entries_rejects_legacy_policy() {
        let toml_text = make_witness_toml(2);
        let result = parse_witness_pool(&toml_text, &WitnessPolicy::LEGACY);
        assert!(matches!(
            result,
            Err(SigsumError::WitnessPoolTooSmall {
                configured: 2,
                minimum: 3
            })
        ));
    }

    #[test]
    fn parse_witness_pool_with_empty_rejects_any_policy() {
        let result = parse_witness_pool("", &WitnessPolicy::BOOTSTRAP);
        assert!(matches!(
            result,
            Err(SigsumError::WitnessPoolTooSmall { configured: 0, .. })
        ));
    }

    #[test]
    fn parse_witness_pool_with_malformed_toml_rejects() {
        let result = parse_witness_pool("not valid toml at all!!!", &WitnessPolicy::LEGACY);
        assert!(matches!(result, Err(SigsumError::WitnessConfigParse)));
    }

    #[test]
    fn parse_witness_pool_with_bad_pubkey_hex_rejects() {
        let toml = r#"
            [[witness]]
            name = "Witness A"
            pubkey_hex = "this is not hex"
            url = "https://example.org"
        "#;
        assert!(matches!(
            parse_witness_pool(toml, &WitnessPolicy::BOOTSTRAP),
            Err(SigsumError::WitnessConfigParse)
        ));
    }

    #[test]
    fn parse_witness_pool_with_short_pubkey_rejects() {
        let toml = r#"
            [[witness]]
            name = "Witness A"
            pubkey_hex = "abcdef"
            url = "https://example.org"
        "#;
        assert!(matches!(
            parse_witness_pool(toml, &WitnessPolicy::BOOTSTRAP),
            Err(SigsumError::WitnessConfigParse)
        ));
    }

    #[test]
    fn witness_policy_new_validates_invariants() {
        // Both nonzero, required <= pool.
        assert!(WitnessPolicy::new(3, 2).is_some());
        assert!(WitnessPolicy::new(1, 1).is_some());
        assert!(WitnessPolicy::new(5, 3).is_some());

        // Zero pool or zero threshold.
        assert!(WitnessPolicy::new(0, 0).is_none());
        assert!(WitnessPolicy::new(3, 0).is_none());
        assert!(WitnessPolicy::new(0, 1).is_none());

        // Required > pool.
        assert!(WitnessPolicy::new(2, 3).is_none());
    }

    #[test]
    fn witness_policy_presets_satisfy_own_invariants() {
        let legacy = WitnessPolicy::LEGACY;
        assert_eq!(legacy.min_pool_size(), 3);
        assert_eq!(legacy.required_cosignatures(), 2);

        let bootstrap = WitnessPolicy::BOOTSTRAP;
        assert_eq!(bootstrap.min_pool_size(), 1);
        assert_eq!(bootstrap.required_cosignatures(), 1);

        let target = WitnessPolicy::TARGET;
        assert_eq!(target.min_pool_size(), 5);
        assert_eq!(target.required_cosignatures(), 3);
    }

    #[test]
    fn tree_head_note_has_c2sp_checkpoint_shape() {
        use base64::Engine as _;

        // Per the Sigsum v1 log spec: three newline-terminated lines —
        // origin (sigsum.org/v1/tree/<hex keyhash>), decimal size,
        // base64 root hash.
        let log_key_hash = [0xBBu8; 32];
        let root_hash = [0xAAu8; 32];
        let note = build_tree_head_note(&log_key_hash, 1234, &root_hash);
        let text = core::str::from_utf8(&note).unwrap();
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        assert_eq!(lines.len(), 3, "note is three newline-terminated lines");
        assert_eq!(
            lines[0],
            "sigsum.org/v1/tree/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        );
        assert_eq!(lines[1], "1234\n");
        // base64(32 * 0xAA) — fixed, computed by the audited base64 crate.
        let expected_root = base64::engine::general_purpose::STANDARD.encode([0xAAu8; 32]);
        assert_eq!(lines[2], format!("{expected_root}\n"));
    }

    #[test]
    fn cosignature_signed_message_wraps_note_with_header_and_timestamp() {
        // Per C2SP tlog-cosignature/v1: "cosignature/v1\n" + "time <ts>\n"
        // + the note body.
        let note = build_tree_head_note(&[0x01; 32], 7, &[0x02; 32]);
        let msg = build_cosignature_signed_message(1_700_000_000, &note);
        let text = core::str::from_utf8(&msg).unwrap();
        assert!(text.starts_with("cosignature/v1\n"));
        assert!(text.contains("\ntime 1700000000\n"));
        assert!(text.ends_with(core::str::from_utf8(&note).unwrap()));
    }

    #[test]
    fn witness_key_hash_matches_c2sp_construction() {
        use sha2::{Digest, Sha256};

        // SHA-256(name ‖ "\n" ‖ 0x04 ‖ pubkey)[:4].
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let pk = sk.verifying_key();
        let kh = witness_key_hash("Witness Alpha", &pk);

        let mut h = Sha256::new();
        h.update(b"Witness Alpha");
        h.update(b"\n");
        h.update([0x04u8]);
        h.update(pk.to_bytes());
        let expected = h.finalize();
        assert_eq!(kh, expected[..4]);
    }

    #[test]
    fn verify_cosignature_succeeds_for_valid_c2sp_signature() {
        // A witness signs the real C2SP cosignature/v1 message; verify
        // it round-trips.
        let mut rng = OsRng;
        let witness_sk = SigningKey::generate(&mut rng);
        let note = build_tree_head_note(&[0x01; 32], 1234, &[0x02; 32]);
        let msg = build_cosignature_signed_message(1_700_000_000, &note);
        let signature = witness_sk.sign(&msg).unwrap();
        let result =
            verify_cosignature(&witness_sk.verifying_key(), 0, &msg, &signature.to_bytes());
        assert!(result.is_ok());
    }

    #[test]
    fn verify_cosignature_rejects_wrong_timestamp() {
        // A cosignature is bound to its timestamp: signing the message
        // at ts=A then verifying the message rebuilt at ts=B fails.
        let mut rng = OsRng;
        let witness_sk = SigningKey::generate(&mut rng);
        let note = build_tree_head_note(&[0x01; 32], 1234, &[0x02; 32]);
        let msg_a = build_cosignature_signed_message(1_700_000_000, &note);
        let msg_b = build_cosignature_signed_message(1_700_000_001, &note);
        let signature_a = witness_sk.sign(&msg_a).unwrap();
        let result = verify_cosignature(
            &witness_sk.verifying_key(),
            0,
            &msg_b,
            &signature_a.to_bytes(),
        );
        assert!(matches!(
            result,
            Err(SigsumError::CosignatureVerifyFailed { witness_index: 0 })
        ));
    }

    #[test]
    fn verify_cosignature_rejects_wrong_key() {
        let mut rng = OsRng;
        let witness_sk = SigningKey::generate(&mut rng);
        let imposter_sk = SigningKey::generate(&mut rng);
        let note = build_tree_head_note(&[0x01; 32], 1234, &[0x02; 32]);
        let msg = build_cosignature_signed_message(1_700_000_000, &note);
        let signature = imposter_sk.sign(&msg).unwrap();
        let result =
            verify_cosignature(&witness_sk.verifying_key(), 2, &msg, &signature.to_bytes());
        assert!(matches!(
            result,
            Err(SigsumError::CosignatureVerifyFailed { witness_index: 2 })
        ));
    }

    #[test]
    fn verify_cosignature_rejects_truncated_signature() {
        let mut rng = OsRng;
        let witness_sk = SigningKey::generate(&mut rng);
        let note = build_tree_head_note(&[0x01; 32], 1234, &[0x02; 32]);
        let msg = build_cosignature_signed_message(1_700_000_000, &note);
        let result = verify_cosignature(
            &witness_sk.verifying_key(),
            1,
            &msg,
            &[0u8; 32], // truncated; valid signatures are 64 bytes
        );
        assert!(matches!(
            result,
            Err(SigsumError::CosignatureVerifyFailed { witness_index: 1 })
        ));
    }

    #[test]
    fn encode_hex_round_trips_through_decode_hex() {
        let bytes = [0x00u8, 0x0f, 0xa5, 0xff, 0xbb];
        assert_eq!(decode_hex(&encode_hex(&bytes)), Some(bytes.to_vec()));
    }

    #[test]
    fn decode_hex_handles_lowercase_and_uppercase() {
        assert_eq!(decode_hex("abcdef"), Some(vec![0xab, 0xcd, 0xef]));
        assert_eq!(decode_hex("ABCDEF"), Some(vec![0xab, 0xcd, 0xef]));
        assert_eq!(decode_hex("AbCdEf"), Some(vec![0xab, 0xcd, 0xef]));
    }

    #[test]
    fn decode_hex_rejects_odd_length() {
        assert_eq!(decode_hex("abc"), None);
    }

    #[test]
    fn decode_hex_rejects_non_hex_chars() {
        assert_eq!(decode_hex("xx"), None);
        assert_eq!(decode_hex("ab cd"), None);
    }
}
