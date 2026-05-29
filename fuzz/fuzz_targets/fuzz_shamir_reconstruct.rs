// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! D0018 §5.2 target #3: `fuzz_shamir_reconstruct`.
//!
//! Goal: assert that `cairn_shamir::reconstruct` does NOT panic on
//! arbitrary share + commitment inputs. The reconstruction path
//! routes through `vsss-rs::Gf256::combine_array` (third-party) plus
//! Cairn's commitment-check (`blake3::derive_key`); both must surface
//! every malformed shape as a `ShamirError` variant per D0018 §3.4's
//! uniform-error discipline (no panic, no error-oracle).
//!
//! Input is structured manually from raw fuzz bytes (avoids the
//! `arbitrary` derive-macro version-skew issue against the workspace
//! `arbitrary = "=1.3.2"` pin — a future D0021 audit revision can
//! migrate to the derive once the pins are aligned).
//!
//! Wire shape parsed from input bytes:
//!   first 32 bytes  → commitment (BLAKE3 commit-of-secret)
//!   each next 33 bytes → one share: `[id_byte, value_bytes_32]`
//! Trailing bytes that don't form a full 33-byte share are ignored.
//! Share count is capped at 255 (the parameter limit per
//! D0018 §3.4).

#![no_main]

use cairn_shamir::{Commitment, SECRET_LEN, Share, reconstruct};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

const COMMITMENT_BYTES: usize = 32;
const SHARE_WIRE_BYTES: usize = SECRET_LEN + 1; // id byte + value bytes
const MAX_SHARES: usize = 255;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() < COMMITMENT_BYTES {
        return; // insufficient input for even the commitment
    }

    let mut commitment_arr = [0u8; COMMITMENT_BYTES];
    commitment_arr.copy_from_slice(&bytes[..COMMITMENT_BYTES]);
    let commitment = Commitment::from_bytes(commitment_arr);

    let mut shares: Vec<Share> = Vec::new();
    let mut offset = COMMITMENT_BYTES;
    while offset + SHARE_WIRE_BYTES <= bytes.len() && shares.len() < MAX_SHARES {
        let id = bytes[offset];
        let mut value = [0u8; SECRET_LEN];
        value.copy_from_slice(&bytes[offset + 1..offset + SHARE_WIRE_BYTES]);
        // Share::try_from_parts can reject id == 0; skip silently
        // because the goal is to stress reconstruct, not the share
        // constructor.
        if let Ok(share) = Share::try_from_parts(id, Zeroizing::new(value)) {
            shares.push(share);
        }
        offset += SHARE_WIRE_BYTES;
    }

    let _ = reconstruct(&shares, &commitment);
});
