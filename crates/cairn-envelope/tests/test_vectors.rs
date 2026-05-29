// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// Integration tests run under workspace lints; .expect() is the
// idiomatic way to surface a fixture-construction failure here (and
// has a descriptive message). The workspace forbids it in production
// to enforce typed-error discipline per D0018 §4.2; that discipline
// doesn't apply to known-deterministic test fixtures.
#![allow(clippy::expect_used, clippy::panic)]

//! D0018 §2.4 test vector corpus for canonical CBOR + `COSE_Sign1`.
//!
//! Each test pins:
//!
//! - Deterministic input (signing key seed, payload structure, AAD)
//!   so the output is reproducible across runs and platforms.
//! - Expected intermediate hex (protected header bytes,
//!   `Sig_structure` bytes, signature bytes, full envelope bytes) so
//!   a failure points at which step diverged.
//!
//! The JSON files at `tests/vectors/*.json` document the same data
//! in the cross-implementation format per D0018 §2.4. The Rust-side
//! test is the source of truth; the JSON files are reference data for
//! cross-impl verifiers (`veraison/go-cose`, `pycose`, `t_cose`) per
//! D0021 §6's deferred Go-side CI lane.
//!
//! ## Vector inventory
//!
//! - `capability_token_001`: capability-token envelope per D0006 §9
//!   plus D0006 §8 domain tag `cairn-v1-capability-token`. Payload
//!   is a canonical-CBOR map matching `cairn_identity::token`'s
//!   schema (issuer, subject, scope, expiry, chain).
//! - `trust_graph_op_001`: trust-graph operation envelope per D0006
//!   §2 plus D0006 §8 domain tag `cairn-v1-trust-graph-operation`.
//!   Payload is a canonical-CBOR map matching
//!   `cairn_trust_graph::op`'s schema (attest variant, 6 fields).
//! - `master_attestation_001`: master attestation envelope per D0006
//!   §6 plus extended D0006 §8 domain tag
//!   `cairn-v1-master-attestation`. Payload is a canonical-CBOR map
//!   matching `cairn_recovery::attestation`'s schema (master,
//!   operational identity, timestamp).
//!
//! Per cairn-envelope's design boundary, the payload bytes for the
//! downstream protocol envelopes are constructed here from the
//! canonical `Value` AST directly — no upstream dep on
//! cairn-identity / cairn-trust-graph / cairn-recovery. The
//! downstream crates' own tests pin their payload-schema
//! correctness; this corpus pins the envelope-construction
//! correctness given fixed payload bytes.

use cairn_crypto::ed25519::SigningKey;
use cairn_envelope::canonical::Value;
use cairn_envelope::cose_sign1::{CoseSign1, Sign1Builder};
use zeroize::Zeroizing;

/// Encode bytes as a lowercase hex string for assertion diagnostics.
fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("writing to String cannot fail");
    }
    s
}

/// Build the deterministic 32-byte signing-key seed for a vector
/// (`pattern` byte repeated 32 times).
fn seed_pattern(pattern: u8) -> Zeroizing<[u8; 32]> {
    Zeroizing::new([pattern; 32])
}

/// Build + verify one vector. Asserts the produced hex matches the
/// pinned expected hex at each intermediate.
#[allow(clippy::too_many_arguments)]
fn check_vector(
    name: &str,
    seed_pattern_byte: u8,
    payload: Vec<u8>,
    external_aad: &[u8],
    expected_payload_hex: &str,
    expected_protected_hex: &str,
    expected_sig_structure_hex: &str,
    expected_signature_hex: &str,
    expected_envelope_hex: &str,
) {
    // Pin payload bytes first — catches any encoding drift before the
    // envelope-level checks.
    assert_eq!(
        hex(&payload),
        expected_payload_hex,
        "{name}: payload_cbor_hex mismatch"
    );

    let seed = seed_pattern(seed_pattern_byte);
    let signing_key = SigningKey::from_seed(&seed);

    let envelope = Sign1Builder::new()
        .with_payload(payload)
        .with_external_aad(external_aad.to_vec())
        .finalize(&signing_key)
        .expect("Sign1Builder finalize should succeed for valid inputs");

    assert_eq!(
        hex(envelope.protected_bytes()),
        expected_protected_hex,
        "{name}: protected_header_cbor_hex mismatch"
    );

    let sig_structure_bytes = envelope
        .sig_structure_bytes(external_aad)
        .expect("sig_structure_bytes should produce canonical CBOR");
    assert_eq!(
        hex(&sig_structure_bytes),
        expected_sig_structure_hex,
        "{name}: sig_structure_cbor_hex mismatch"
    );

    assert_eq!(
        hex(envelope.signature()),
        expected_signature_hex,
        "{name}: signature_hex mismatch"
    );

    let envelope_bytes = envelope
        .encode(false)
        .expect("envelope encode should succeed");
    assert_eq!(
        hex(&envelope_bytes),
        expected_envelope_hex,
        "{name}: envelope_cbor_hex mismatch"
    );

    // Round-trip: decode + verify against the originating key + AAD.
    let decoded = CoseSign1::from_bytes(&envelope_bytes).expect("decode succeeds");
    decoded
        .verify(&signing_key.verifying_key(), external_aad)
        .expect("verify succeeds under originating key + matching AAD");
}

/// Build the canonical-CBOR payload for `capability_token_001`.
///
/// Fields (per cairn-identity's `CapabilityToken` schema):
/// - 1 → issuer pubkey (derived from seed = `[0x55; 32]`)
/// - 2 → subject pubkey (derived from seed = `[0x33; 32]`)
/// - 3 → scope = `["messaging:send"]`
/// - 4 → expiry = `1_700_000_000`
/// - 5 → chain = `[]`
fn capability_token_001_payload() -> Vec<u8> {
    let issuer = SigningKey::from_seed(&seed_pattern(0x55))
        .verifying_key()
        .to_bytes();
    let subject = SigningKey::from_seed(&seed_pattern(0x33))
        .verifying_key()
        .to_bytes();
    Value::Map(vec![
        (Value::Int(1), Value::Bytes(issuer.to_vec())),
        (Value::Int(2), Value::Bytes(subject.to_vec())),
        (
            Value::Int(3),
            Value::Array(vec![Value::Text("messaging:send".to_string())]),
        ),
        (Value::Int(4), Value::Int(1_700_000_000)),
        (Value::Int(5), Value::Bytes(vec![])),
    ])
    .encode()
    .expect("capability token payload encodes")
}

/// Build the canonical-CBOR payload for `trust_graph_op_001`
/// (attest variant).
///
/// Fields (per cairn-trust-graph's `TrustGraphOp` schema, attest):
/// - 1 → `op_type` = 1 (Attest)
/// - 2 → issuer pubkey (seed = `[0x55; 32]`)
/// - 3 → subject pubkey (seed = `[0x33; 32]`)
/// - 4 → timestamp = `1_700_000_000`
/// - 5 → `prior_hash` = `[]` (genesis)
/// - 6 → `issuer_cert_hash` = `[]`
fn trust_graph_op_001_payload() -> Vec<u8> {
    let issuer = SigningKey::from_seed(&seed_pattern(0x55))
        .verifying_key()
        .to_bytes();
    let subject = SigningKey::from_seed(&seed_pattern(0x33))
        .verifying_key()
        .to_bytes();
    Value::Map(vec![
        (Value::Int(1), Value::Int(1)),
        (Value::Int(2), Value::Bytes(issuer.to_vec())),
        (Value::Int(3), Value::Bytes(subject.to_vec())),
        (Value::Int(4), Value::Int(1_700_000_000)),
        (Value::Int(5), Value::Bytes(vec![])),
        (Value::Int(6), Value::Bytes(vec![])),
    ])
    .encode()
    .expect("trust-graph op payload encodes")
}

/// Build the canonical-CBOR payload for `master_attestation_001`.
///
/// Fields (per cairn-recovery's `MasterAttestation` schema):
/// - 1 → master pubkey (seed = `[0x42; 32]`)
/// - 2 → `operational_identity` pubkey (seed = `[0x37; 32]`)
/// - 3 → timestamp = `1_700_000_000`
fn master_attestation_001_payload() -> Vec<u8> {
    let master = SigningKey::from_seed(&seed_pattern(0x42))
        .verifying_key()
        .to_bytes();
    let op_identity = SigningKey::from_seed(&seed_pattern(0x37))
        .verifying_key()
        .to_bytes();
    Value::Map(vec![
        (Value::Int(1), Value::Bytes(master.to_vec())),
        (Value::Int(2), Value::Bytes(op_identity.to_vec())),
        (Value::Int(3), Value::Int(1_700_000_000)),
    ])
    .encode()
    .expect("master attestation payload encodes")
}

#[test]
fn vector_capability_token_001() {
    check_vector(
        "capability_token_001",
        // signing key = the issuer
        0x55,
        capability_token_001_payload(),
        b"cairn-v1-capability-token",
        "a5015820c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f7324202582017cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce03816e6d6573736167696e673a73656e64041a6553f1000540",
        "a10127",
        "846a5369676e61747572653143a101275819636169726e2d76312d6361706162696c6974792d746f6b656e5860a5015820c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f7324202582017cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce03816e6d6573736167696e673a73656e64041a6553f1000540",
        "92f40d185e8eefb1761bcffb6089f58f230e7eeabd96dcbfa186cd95d3c014a3d72b5b4fe66d43ea7df7211ffb367609347621fa842b71f831d83eaa1eba2a0a",
        "8443a10127a05860a5015820c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f7324202582017cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce03816e6d6573736167696e673a73656e64041a6553f1000540584092f40d185e8eefb1761bcffb6089f58f230e7eeabd96dcbfa186cd95d3c014a3d72b5b4fe66d43ea7df7211ffb367609347621fa842b71f831d83eaa1eba2a0a",
    );
}

#[test]
fn vector_trust_graph_op_001() {
    check_vector(
        "trust_graph_op_001",
        // device key — seed = `[0x77; 32]` so it's distinct from the
        // issuer/subject in the payload
        0x77,
        trust_graph_op_001_payload(),
        b"cairn-v1-trust-graph-operation",
        "a60101025820c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f7324203582017cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce041a6553f10005400640",
        "a10127",
        "846a5369676e61747572653143a10127581e636169726e2d76312d74727573742d67726170682d6f7065726174696f6e5853a60101025820c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f7324203582017cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce041a6553f10005400640",
        "6e378cee93e9fe5219038552c677d0961a5e11c681a39452c9cfc97d0518960f219f8ffd8447d871a91d7761cdde4a1d88f0347dab738a56964bf678c55ffc0f",
        "8443a10127a05853a60101025820c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f7324203582017cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce041a6553f1000540064058406e378cee93e9fe5219038552c677d0961a5e11c681a39452c9cfc97d0518960f219f8ffd8447d871a91d7761cdde4a1d88f0347dab738a56964bf678c55ffc0f",
    );
}

#[test]
fn vector_master_attestation_001() {
    check_vector(
        "master_attestation_001",
        // signing key = the master (which is also the issuer here)
        0x42,
        master_attestation_001_payload(),
        b"cairn-v1-master-attestation",
        "a30158202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db120258202c848ad8664ee651e4896c13a84a89a2964aca5eb77a8b881e60ded5c81b4e9d031a6553f100",
        "a10127",
        "846a5369676e61747572653143a10127581b636169726e2d76312d6d61737465722d6174746573746174696f6e584da30158202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db120258202c848ad8664ee651e4896c13a84a89a2964aca5eb77a8b881e60ded5c81b4e9d031a6553f100",
        "c554d4041cb8ce957848feca91a2ffe1a4d8f4c62862ea9dcf9e401659ce73809e64cb7058a6999fa0de6ac87e41e31e5bc092204cbe7a6d4add6aca92366908",
        "8443a10127a0584da30158202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db120258202c848ad8664ee651e4896c13a84a89a2964aca5eb77a8b881e60ded5c81b4e9d031a6553f1005840c554d4041cb8ce957848feca91a2ffe1a4d8f4c62862ea9dcf9e401659ce73809e64cb7058a6999fa0de6ac87e41e31e5bc092204cbe7a6d4add6aca92366908",
    );
}
