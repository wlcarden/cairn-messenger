// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Per-schema fuzz target: `MasterAttestation::from_canonical_cbor`.
//!
//! Goal: assert that the cairn-recovery payload schema decoder does
//! NOT panic on arbitrary input bytes. Per D0006 §6 master
//! attestations are 3-key integer-keyed canonical CBOR maps (master
//! pubkey + operational-identity pubkey + timestamp). The decoder is
//! small but it parses pubkey bytes via `VerifyingKey::from_bytes`
//! which has its own validation paths — fuzz coverage catches any
//! interaction-effect panic between the schema walk and the curve-
//! point check.

#![no_main]

use cairn_recovery::MasterAttestation;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = MasterAttestation::from_canonical_cbor(bytes);
});
