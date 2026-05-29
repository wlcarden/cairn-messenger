// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! D0018 §5.2 target #5: `fuzz_canonical_cbor`.
//!
//! Goal: assert that the canonical-CBOR decoder does NOT panic on
//! arbitrary input bytes. The decoder lives in ciborium (we don't own
//! it directly) but the surfaces that consume its output
//! (`from_canonical_cbor` paths in cairn-identity, cairn-trust-graph,
//! cairn-recovery) ARE ours — they walk the decoded `ciborium::Value`
//! tree and must surface every malformed shape as a typed error per
//! D0018 §4.2.
//!
//! This target stresses the ciborium decode boundary. For per-schema
//! coverage see `fuzz_capability_token`, `fuzz_trust_graph_op`,
//! `fuzz_master_attestation`.
//!
//! Outcome is intentionally ignored — both Ok and Err are valid
//! results. The harness fails only on panic or libfuzzer timeout.

#![no_main]

use ciborium::Value as CiboriumValue;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _: Result<CiboriumValue, _> = ciborium::de::from_reader(bytes);
});
