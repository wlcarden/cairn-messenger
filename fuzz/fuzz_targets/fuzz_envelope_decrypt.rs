// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! D0018 §5.2: `fuzz_envelope_decrypt` — the AEAD decrypt boundary.
//!
//! Goal: assert that `cairn_crypto::aead::decrypt` (the inner-payload
//! XChaCha20-Poly1305 layer of the envelope wire form) does NOT panic on
//! arbitrary ciphertext. A buffer shorter than the 16-byte Poly1305 tag, a
//! wrong tag, a wrong key/nonce, or wrong AAD must all surface as the
//! uniform `AeadError::DecryptFailed` per D0006 / D0018 §1.4 — never a
//! panic, and never a distinguishable error (the no-error-oracle
//! discipline).
//!
//! The key and nonce are fixed: the surface under test is the decrypt
//! parser's handling of adversarial ciphertext, not the key/nonce space.
//! The first input byte selects an AAD split so the AAD path is fuzzed
//! alongside the ciphertext.
//!
//! Outcome is intentionally ignored: `Ok` would mean the fuzzer forged a
//! valid ciphertext for the fixed key (cryptographically negligible);
//! `Err` is the expected result. The harness fails only on panic or a
//! libfuzzer timeout.

#![no_main]

use cairn_crypto::aead::{KEY_LEN, Key, NONCE_LEN, Nonce, decrypt};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

fuzz_target!(|bytes: &[u8]| {
    let key = Key::from_bytes(&Zeroizing::new([0u8; KEY_LEN]));
    let nonce = Nonce::from_bytes([0u8; NONCE_LEN]);

    // First byte (if present) selects an AAD length so the AAD path is
    // exercised; the remainder is treated as ciphertext.
    let (ad, ct) = match bytes.split_first() {
        Some((&n, rest)) => rest.split_at((n as usize).min(rest.len())),
        None => (&[][..], &[][..]),
    };
    let _ = decrypt(&key, &nonce, ad, ct);

    // Also exercise the empty-AAD path over the whole input, so a tag-only
    // or sub-tag-length buffer is hit directly.
    let _ = decrypt(&key, &nonce, b"", bytes);
});
