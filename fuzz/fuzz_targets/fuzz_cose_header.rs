// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! D0018 §5.2: `fuzz_cose_header` — the COSE header re-encode + Sig_structure path.
//!
//! `fuzz_envelope_parse` covers `CoseSign1::from_bytes` but discards the
//! decoded value. This target keeps it and exercises the header-handling
//! paths that decode alone does not reach: the canonical re-encode of the
//! (attacker-controlled) unprotected-header map, the COSE tag-wrapping
//! encode, the `Sig_structure` reconstruction over the parsed
//! protected-header bytes, and the accessors.
//!
//! None of these may panic on a successfully-parsed but adversarial
//! envelope. Structural problems (duplicate canonical keys, integer
//! out-of-range, unsupported CBOR types) must surface as `EnvelopeError`,
//! not a panic. The harness fails only on panic or a libfuzzer timeout.

#![no_main]

use cairn_envelope::cose_sign1::CoseSign1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(env) = CoseSign1::from_bytes(bytes) {
        // Re-encode both forms: exercises the canonical encoder on the
        // parsed-from-untrusted unprotected-header map.
        let _ = env.encode(false);
        let _ = env.encode(true);
        // Rebuild the Sig_structure over the parsed protected-header bytes
        // with an input-derived AAD (the protocol crates pass a domain tag
        // here; arbitrary bytes must not panic the builder).
        let _ = env.sig_structure_bytes(bytes);
        let _ = env.sig_structure_bytes(b"");
        // Touch every accessor.
        let _ = env.protected_bytes();
        let _ = env.payload();
        let _ = env.signature();
        for (k, v) in env.unprotected_headers() {
            let _ = (k, v);
        }
    }
});
