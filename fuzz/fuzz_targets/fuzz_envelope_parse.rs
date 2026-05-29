// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! D0018 §5.2 target #1: `fuzz_envelope_parse`.
//!
//! Goal: assert that `CoseSign1::from_bytes` does NOT panic on
//! arbitrary input bytes. Any panic uncovered here is an audit-target
//! bug (the decoder must surface structural errors as `EnvelopeError`
//! variants per D0018 §4.2's no-Vec<u8>-in-errors discipline).
//!
//! Outcome is intentionally ignored: `Ok` means the bytes happened to
//! be a structurally-valid COSE_Sign1 envelope (rare for random
//! input); `Err` means the decoder rejected them — both are valid
//! results. The harness fails only on panic or infinite-loop
//! (libfuzzer timeout).

#![no_main]

use cairn_envelope::cose_sign1::CoseSign1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    // Decode-without-verify path. If from_bytes ever panics on
    // structurally malformed input, the fuzzer surfaces the
    // crashing input under fuzz/artifacts/fuzz_envelope_parse/.
    let _ = CoseSign1::from_bytes(bytes);
});
