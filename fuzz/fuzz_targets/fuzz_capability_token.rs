// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Per-schema fuzz target: `CapabilityToken::from_canonical_cbor`.
//!
//! Goal: assert that the cairn-identity payload schema decoder does
//! NOT panic on arbitrary input bytes. Per D0006 §9 token payloads
//! are integer-keyed canonical CBOR maps; the decoder walks the
//! `ciborium::Value` tree and must surface every malformed shape as
//! a typed `IdentityError` variant per D0018 §4.2.
//!
//! Complements `fuzz_envelope_parse` (which exercises the outer
//! `COSE_Sign1` decode but not the inner payload schema walk).

#![no_main]

use cairn_identity::CapabilityToken;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = CapabilityToken::from_canonical_cbor(bytes);
});
