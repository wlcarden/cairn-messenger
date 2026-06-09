// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Per-schema fuzz target: the offline release-bundle decoders
//! (D0024 §6.4 / D0041 §6.3).
//!
//! This is the attacker-reachable entry point a client feeds with a
//! downloaded software-update bundle, so it gets the strongest fuzz
//! discipline. Two invariants are asserted:
//!
//! 1. NEVER PANIC. Arbitrary bytes must surface as a
//!    `SigstoreVerifyError` (an `Err`), never an unwind. A
//!    `ReleaseBundle` map nests a `RekorBundle` and a Sigsum
//!    `EmittedLeaf` as CBOR byte strings, so the bundle path
//!    transitively fuzzes three of the four release-pipeline decoders;
//!    the standalone `ReleaseManifest` decoder is exercised on the same
//!    input as the fourth.
//!
//! 2. IDEMPOTENT RE-ENCODE. Any bytes that DO decode must round-trip to
//!    a canonical fixpoint: `encode(decode(b))` must equal
//!    `encode(decode(encode(decode(b))))`. A successful decode whose
//!    value cannot be re-encoded, or whose re-encoding is
//!    non-deterministic or lossy, is a codec bug.
//!
//! We deliberately do NOT assert the re-encoding equals the *input*:
//! the strict decoder (D0041 §6.3) closes trailing-bytes and
//! duplicate-key malleability but still tolerates non-minimal integer
//! heads and unknown integer keys (forward-compat, D0006 §6.4), so a
//! non-canonical-but-decodable input legitimately re-encodes to a
//! different (canonical) byte string. Idempotence of the canonical form
//! is the invariant that holds.

#![no_main]

use cairn_sigstore_verify::{ReleaseBundle, ReleaseManifest};
use libfuzzer_sys::fuzz_target;

/// Decode → (if accepted) re-encode → re-decode → re-encode, and assert
/// the two canonical encodings match. Panics (i.e. surfaces a fuzz
/// crash) only if a decoded bundle cannot be re-encoded/re-decoded or
/// the canonical form is not a fixpoint.
fn bundle_reencode_is_idempotent(bytes: &[u8]) {
    let Ok(bundle) = ReleaseBundle::from_canonical_cbor(bytes) else {
        return; // structurally invalid input — the expected common case
    };
    let once = bundle
        .to_canonical_cbor()
        .expect("a decoded ReleaseBundle must re-encode to canonical CBOR");
    let twice = ReleaseBundle::from_canonical_cbor(&once)
        .expect("the canonical re-encoding of a ReleaseBundle must re-decode")
        .to_canonical_cbor()
        .expect("the second ReleaseBundle re-encode must succeed");
    assert_eq!(
        once, twice,
        "canonical re-encoding of a ReleaseBundle must be idempotent"
    );
}

/// Same idempotence discipline for the standalone manifest decoder (the
/// fourth release-pipeline decoder; the manifest payload is also
/// COSE-signature-pinned in the full verify path, but the codec must be
/// panic-free and idempotent on its own).
fn manifest_reencode_is_idempotent(bytes: &[u8]) {
    let Ok(manifest) = ReleaseManifest::from_canonical_cbor(bytes) else {
        return;
    };
    let once = manifest
        .to_canonical_cbor()
        .expect("a decoded ReleaseManifest must re-encode to canonical CBOR");
    let twice = ReleaseManifest::from_canonical_cbor(&once)
        .expect("the canonical re-encoding of a ReleaseManifest must re-decode")
        .to_canonical_cbor()
        .expect("the second ReleaseManifest re-encode must succeed");
    assert_eq!(
        once, twice,
        "canonical re-encoding of a ReleaseManifest must be idempotent"
    );
}

fuzz_target!(|bytes: &[u8]| {
    bundle_reencode_is_idempotent(bytes);
    manifest_reencode_is_idempotent(bytes);
});
