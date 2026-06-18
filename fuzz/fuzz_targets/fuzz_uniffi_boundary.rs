// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! D0018 §5.2: `fuzz_uniffi_boundary` — the FFI-boundary memory-safety harness.
//!
//! The UniFFI decode entry points take attacker-controlled input that
//! crosses the Kotlin/Rust boundary. A panic in any of them would unwind
//! across the FFI, which is unsound; every structural error must instead
//! surface as a `CairnFfiError`. This target drives the two byte/string
//! decode surfaces with arbitrary input and asserts no panic.
//!
//! `cairn-uniffi` is depended on with default features (the
//! `uniffi-bindings` macro surface stays off), so the exports are plain
//! `pub fn`s callable in-process — the parse logic the FFI marshals is
//! identical with or without the binding macros.
//!
//! The harness fails only on panic or a libfuzzer timeout; a returned
//! `Err` is the expected outcome for almost all inputs.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    // String-decode boundary: the recovery-card codec a recovering device
    // feeds from pasted or scanned text (D0038). Lossy conversion keeps
    // the fuzzer exploring the decoder, not UTF-8 validation.
    let card_text = String::from_utf8_lossy(bytes).into_owned();
    let _ = cairn_uniffi::recovery::recovery_decode_card(card_text);

    // Byte-decode boundary: the introduction-message wire bytes a received
    // message-envelope key-10 field carries (D0037 §5).
    let _ = cairn_uniffi::trust_graph::decode_introduction_message(bytes.to_vec());
});
