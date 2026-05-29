// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Per-schema fuzz target: `TrustGraphOp::from_canonical_cbor`.
//!
//! Goal: assert that the cairn-trust-graph payload schema decoder
//! does NOT panic on arbitrary input bytes. Per D0006 §2 op payloads
//! are 8-key integer-keyed canonical CBOR maps with variant-required
//! fields (`revoked_as_of` for `CompromiseRevoke`,
//! `prior_revocation_ref` for `ReAttest`). The decoder's correctness
//! depends on cleanly rejecting any structural mismatch — fuzz
//! coverage catches the malformed-input panics that property tests
//! can't reach.

#![no_main]

use cairn_trust_graph::TrustGraphOp;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = TrustGraphOp::from_canonical_cbor(bytes);
});
