# Test vector corpus (D0018 §2.4)

Cross-implementation reference fixtures for canonical CBOR + `COSE_Sign1` envelope construction per [D0018 §2.4](../../../../docs/decisions/D0018-engineering-foundation.md#24-test-vector-corpus).

## Files

| File                          | Envelope type                                    | Domain tag                       | Notes                                                                                                                                                                                                                     |
| ----------------------------- | ------------------------------------------------ | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `capability_token_001.json`   | Capability token (D0006 §9)                      | `cairn-v1-capability-token`      | 5-field payload; issuer + subject pubkeys + scope + expiry + chain                                                                                                                                                        |
| `trust_graph_op_001.json`     | Trust-graph operation, attest variant (D0006 §2) | `cairn-v1-trust-graph-operation` | 6-field payload (genesis attest, empty `prior_hash` + `issuer_cert_hash`); device-signed under a fictional capability token                                                                                               |
| `master_attestation_001.json` | Master attestation (D0006 §6)                    | `cairn-v1-master-attestation`    | 3-field payload (master pubkey + operational identity pubkey + timestamp); matches the D0006 §7 reference test vector pinned in `cairn_recovery::attestation::tests::issuer_cert_hash_pinned_test_vector_d0006_section_7` |

## Per-vector schema

Each JSON file pins every intermediate byte string in the envelope-construction pipeline. A cross-implementation reader can independently reconstruct every intermediate and assert byte equality at each step — this is what makes interop divergence tractable to debug (per D0018 §2.4's "a failing test points exactly at which step diverged").

Fields:

| Field                         | Type     | Description                                                                                                                                                       |
| ----------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`                        | string   | Vector identifier; matches the Rust test name                                                                                                                     |
| `description`                 | string   | Free-form explanation of the vector's intent + schema reference                                                                                                   |
| `domain_separation_tag`       | string   | D0006 §8 external_aad value (UTF-8)                                                                                                                               |
| `signing_key_seed_hex`        | hex(32)  | Ed25519 seed bytes per RFC 8032 §5.1.5; deterministic across runs                                                                                                 |
| `*_verifying_key_hex`         | hex(32)  | Derived pubkey bytes (32 = `PUBLIC_KEY_LEN`)                                                                                                                      |
| `*_seed_hex`                  | hex(32)  | Auxiliary seeds for payload fields (e.g. subject, operational identity)                                                                                           |
| `protected_header_cbor_hex`   | hex      | Canonical-CBOR-encoded protected header map per RFC 9052 §3                                                                                                       |
| `protected_header_decoded`    | object   | Human-readable decode of the protected header for inspection                                                                                                      |
| `unprotected_header_cbor_hex` | hex      | Canonical-CBOR-encoded unprotected header map (usually `a0` = empty)                                                                                              |
| `payload_cbor_hex`            | hex      | Canonical-CBOR-encoded payload (matches the downstream crate's schema)                                                                                            |
| `external_aad_utf8`           | string   | The domain separation tag as a UTF-8 string                                                                                                                       |
| `external_aad_hex`            | hex      | The domain separation tag as raw bytes                                                                                                                            |
| `sig_structure_cbor_hex`      | hex      | Canonical-CBOR-encoded RFC 9052 §4.4 `Sig_structure` (4-tuple: context, body_protected, external_aad, payload) — this is the byte string the signature commits to |
| `signature_hex`               | hex(64)  | 64-byte Ed25519 signature over `sig_structure_cbor_hex`                                                                                                           |
| `envelope_cbor_hex`           | hex      | Final wire-format `COSE_Sign1` envelope (untagged 4-tuple: protected, unprotected, payload, signature)                                                            |
| `verification_expectation`    | string   | Human-readable statement of the verification contract                                                                                                             |
| `expected_*`                  | (varies) | Optional pinned expected hashes for downstream uses (e.g. D0006 §7 `issuer_cert_hash`)                                                                            |

## Rust-side enforcement

Each vector's intermediates are independently pinned in `crates/cairn-envelope/tests/test_vectors.rs`. The Rust test:

1. Reconstructs each input from the seed pattern + schema
2. Calls `Sign1Builder::new().with_payload(...).with_external_aad(...).finalize(&signing_key)`
3. Asserts each produced intermediate matches the pinned hex (payload, protected, sig_structure, signature, envelope)
4. Decodes the envelope + verifies the signature against the originating pubkey + AAD

Any drift in canonical CBOR encoding, header construction, `Sig_structure` order, Ed25519 implementation, or domain tag value fails the matching assertion with both expected + actual hex printed.

## Cross-implementation reference

The JSON files are the canonical reference format consumed by:

- `veraison/go-cose` (Go) — **landed**: the harness in [`../../interop/go-cose/`](../../interop/go-cose/) (CI job `go-cose-interop`)
- `pycose` (Python) — academic / IETF audit cross-check
- `laurencelundblade/t_cose` (C) — embedded-focused validation

The Go cross-check is implemented in [`../../interop/go-cose/interop_test.go`](../../interop/go-cose/interop_test.go). For each vector it:

1. derives the signing pubkey from `signing_key_seed_hex`
2. decodes `envelope_cbor_hex` via `veraison/go-cose` and checks the payload matches `payload_cbor_hex`
3. verifies the Ed25519 signature under that pubkey + `external_aad_hex` (a divergent `Sig_structure` would fail here), and confirms a single-byte tamper fails

The Rust-side tests remain the source of truth for every pinned intermediate; the Go harness is the independent-implementation oracle per D0018 §2.5.

## Adding new vectors

To extend the corpus:

1. Add a deterministic input recipe (seed pattern, payload schema, AAD) to `test_vectors.rs`
2. Run the test once — it fails with the produced hex in the "left:" diagnostic
3. Paste the produced hex into the `check_vector(...)` call as the pinned expected value
4. Create the matching `*.json` file documenting all fields per the schema above
5. Update this README's "Files" table

The Rust-side `check_vector(...)` helper validates each intermediate independently — if the wire format drifts, the failure points exactly at which byte string diverged.
