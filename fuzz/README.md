# Cairn fuzz harness

In-tree `cargo-fuzz` targets per [D0018 §5.2](../docs/decisions/D0018-engineering-foundation.md#52-fuzzing-cargo-fuzz-for-in-tree-oss-fuzz-once-open-source).

## Targets landed

| Target                    | Surface                                                              | D0018 §5.2 ref      |
| ------------------------- | -------------------------------------------------------------------- | ------------------- |
| `fuzz_envelope_parse`     | `CoseSign1::from_bytes` (panic-resistance)                           | target #1           |
| `fuzz_canonical_cbor`     | `ciborium::de::from_reader` (panic-resistance)                       | target #5           |
| `fuzz_shamir_reconstruct` | `cairn_shamir::reconstruct` (structure-aware via `Arbitrary` derive) | target #3           |
| `fuzz_capability_token`   | `CapabilityToken::from_canonical_cbor` (per-schema decode)           | target #1 extension |
| `fuzz_trust_graph_op`     | `TrustGraphOp::from_canonical_cbor` (per-schema decode)              | target #1 extension |
| `fuzz_master_attestation` | `MasterAttestation::from_canonical_cbor` (per-schema decode)         | target #1 extension |

## Targets deferred

| Target                  | Reason                                                                                                                                 | Owning surface               |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| `fuzz_envelope_decrypt` | AEAD round-trip needs a structure-aware harness with a paired key + nonce input shape; deferred for separate audit-target task         | `cairn_crypto::aead`         |
| `fuzz_cose_header`      | Header-only decode is currently a sub-path of `CoseSign1::from_bytes`; would need a separate exposed entry point to fuzz independently | `cairn_envelope::cose_sign1` |
| `fuzz_uniffi_boundary`  | Requires `cairn-uniffi` crate which doesn't exist yet                                                                                  | TBD                          |

## Running

`cargo-fuzz` requires nightly Rust toolchain per upstream documentation; this matches the CI spec in D0018 §8.5:

```bash
rustup install nightly  # one-time
cargo install cargo-fuzz  # one-time

# Run a single target for 60 seconds (CI budget):
cd fuzz
cargo +nightly fuzz run fuzz_envelope_parse -- -max_total_time=60

# Run all targets in sequence:
for target in fuzz_envelope_parse fuzz_canonical_cbor fuzz_shamir_reconstruct \
              fuzz_capability_token fuzz_trust_graph_op fuzz_master_attestation; do
  cargo +nightly fuzz run "$target" -- -max_total_time=60
done

# Continuous run (production validation — local, not CI):
cargo +nightly fuzz run fuzz_envelope_parse  # runs until crash or Ctrl-C
```

## Corpus management

Per D0018 §5.2:

- Seed from project test vectors (per [D0018 §2.4](../docs/decisions/D0018-engineering-foundation.md#24-test-vector-corpus) once that surface lands)
- Commit `fuzz/corpus/<target>/` to git
- Minimize before commit with `cargo fuzz cmin <target>`

The `fuzz/corpus/` directories are currently empty placeholders; seed-corpus population is its own task (depends on the test vector corpus surface).

## Discipline notes

- Every target asserts **no panic** — any panic uncovered is an audit-target bug per D0018 §4.2's typed-error discipline.
- `Result::Ok` vs. `Result::Err` outcomes are intentionally ignored. The decoder is allowed to reject arbitrary bytes (and usually does); the property under test is "doesn't panic, doesn't infinite-loop".
- `arbitrary::Arbitrary` derive is used for structure-aware inputs (currently only `fuzz_shamir_reconstruct`); raw `&[u8]` inputs work for surface-decode targets that don't have natural structure beyond bytes.
- The `fuzz/` package is **excluded from the main workspace** via its own `[workspace]` table — `libfuzzer-sys`'s link discipline (`-fsanitize=fuzzer`) would propagate to every workspace crate if included.

## Out-of-scope (deferred to future surfaces)

- **OSS-Fuzz integration**: lands once the project repository is public per D0019.
- **CIFuzz PR-time runs**: requires CI configuration; the CI workflow at `.github/workflows/ci.yml` has the spec'd `fuzz-pr` job per D0018 §8.5 once the harness lands.
- **`fuzz_envelope_decrypt`, `fuzz_cose_header`, `fuzz_uniffi_boundary`**: see the "Targets deferred" table above.
