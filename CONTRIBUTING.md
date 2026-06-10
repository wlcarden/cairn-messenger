# Contributing to Cairn

Thanks for your interest in Cairn. The project is in active v1
implementation and is structured as a solo-developer
project at volunteer baseline per
[`docs/decisions/D0008-volunteer-baseline-cadence.md`](docs/decisions/D0008-volunteer-baseline-cadence.md).
That said, contributor onboarding is a real concern (tracked as Q27 in the
open-questions register), and the project will benefit materially from
contributions in a few specific surfaces.

Before contributing, please read at minimum:

- `docs/design-brief.md` §§1-3 (executive summary, problem statement,
  threat model)
- `docs/decisions/D0018-engineering-foundation.md` (library selections and
  ecosystem discipline)
- This document

## First-PR-friendly surfaces (per Q27)

The maintainer has identified the following surfaces as concrete entry
points for first contributions. These do **not** require deep cryptographic
expertise — they require careful engineering and willingness to follow the
project's discipline framework.

1. **Property-based test additions.** The cryptographic surfaces (envelope
   round-trip, Shamir threshold completeness, signing determinism, CBOR
   canonicalization idempotence) per D0018 §5.1 have specific properties
   committed to. Adding test coverage for these properties using `proptest`
   is high-value work and a good way to get familiar with the codebase.

2. **Fuzz harness expansion.** Seven `cargo-fuzz` targets are built and run in
   CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml) is the source of
   truth): `fuzz_envelope_parse`, `fuzz_shamir_reconstruct`,
   `fuzz_canonical_cbor`, `fuzz_capability_token`, `fuzz_trust_graph_op`,
   `fuzz_master_attestation`, and `fuzz_release_bundle`. Corpus expansion and
   edge-case generation for these are well-scoped first-PR work. Three targets
   from the original D0018 §5.2 set are still unwritten and are open
   contribution opportunities: `fuzz_envelope_decrypt`, `fuzz_cose_header`, and
   `fuzz_uniffi_boundary` (the FFI-boundary memory-safety harness, the last
   open UniFFI-surface gate).

3. **Documentation improvements.** The user-facing onboarding documentation
   (the facilitator handbook; the peer-recovery handbook for share holders;
   the post-coercion recovery guidance) is sketched in the brief but not
   yet drafted. Contributors with civil-society protective-tech writing
   experience are particularly welcome here.

4. **Reviewer toolkit improvements.** Per D0015, the v1.5 recruited reviewer
   pool depends on a documented attestation toolkit (Docker/Nix environments
   for reviewers; verification scripts; build comparison tooling). Even at
   v1, working out the reviewer-side experience makes the v1.5 rollout
   substantially easier.

5. **Test-vector cross-validation.** Per D0018 §2.4, Cairn's COSE envelope
   test vectors are byte-validated against `veraison/go-cose`. Writing the
   cross-validation harness (Cairn produces; go-cose verifies; differences
   are CI-blocking) is bounded work that establishes the project's
   audit-credibility substrate.

## Larger contribution surfaces

These require maintainer collaboration before starting; they cross the
project's discipline boundary in ways that need design coordination:

- Cryptographic primitive code (in `cairn-crypto`, `cairn-envelope`,
  `cairn-shamir`). Subject to the constant-time discipline (the `dudect` CI
  smoke test plus out-of-band threshold validation); bound by
  the libsignal/vodozemac version pinning per D0018 §1.
- Integration adapter code (in `cairn-simplex-adapter`, `cairn-tor-transport`).
  Requires familiarity with D0020 integration architecture decisions and the
  cairn-transport trait abstraction.
- UniFFI binding changes. Requires familiarity with D0020 §3 FFI architecture
  and the secret-non-exportable sealed marker trait pattern.

## Discipline framework

By contributing, you commit to following the project's engineering
discipline framework. The discipline is enforced via CI gates per D0018 §8.5
— PRs that violate the discipline cannot merge until the issue is
addressed.

Key disciplines:

### 1. No raw byte payloads in error variants

`thiserror::Error` variants carry indices, lengths, and type tags — never
`Vec<u8>` or `&[u8]`. See D0018 §4.2 for the rationale.

### 2. No secret-leak in logs

Use `subtle::ConstantTimeEq` for all comparison on secret types. Never
`debug!`/`trace!`/`info!`/`warn!`/`error!` with `?secret` or
`?{key,share,plaintext,private_key}` argument patterns. See D0018 §4.3.

### 3. No `==` on secret-bearing types

Use `subtle::ConstantTimeEq::ct_eq`. The clippy `disallowed-types` list in
`clippy.toml` flags this; CI catches violations.

### 4. No `unsafe`

Crate-level `unsafe_code = "forbid"` per workspace lints. Specific
exceptions (mlock wrapper; JNI callback boundary) require crate-level opt-in
with documented justification.

### 5. Memory hygiene

Every type holding key/seed bytes derives `ZeroizeOnDrop`. All API-boundary
secret material wrapped in `secrecy::SecretBox<T>`. The honest acknowledgment
of zeroize limitations per `docs/design-brief.md` §5.1 names what this
discipline does and does not deliver; do not overclaim memory hygiene in
documentation.

### 6. Constant-time discipline

For any function that operates on secret bytes, the implementation is
exercised by the `dudect-bencher` harness. CI runs it as a **smoke test**
(it builds and runs the harness); hosted runners are too noisy for reliable
threshold gating, so the Welch's t-statistic < 4.5 threshold is validated
out-of-band on dedicated hardware per D0018. This is the operational answer to the
Sprint 1 C15 audit-scope finding.

### 7. License consistency

Every new source file gets the SPDX header:

```rust
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors
```

By contributing, you license your contribution under AGPL-3.0-only per
[`docs/decisions/D0019-license.md`](docs/decisions/D0019-license.md).

## Pull request workflow

1. **Fork and branch.** Branch from `main` with a descriptive name
   (`feat/shamir-blake3-commit`; `docs/contributor-guide-update`; `fix/...`).

2. **Run local checks.** Before pushing:

   ```sh
   cargo fmt --all
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features
   ```

3. **Commit message.** Conventional Commits format preferred but not
   required. Reference relevant D-docs or open-questions in the body if
   applicable.

4. **Open PR against `main`.** Describe what changed, why, and any
   architectural cross-references. If the change touches a discipline gate,
   document the rationale for crossing it.

5. **CI must pass.** All required CI checks per D0018 §8.5 must pass before
   merge. The `dudect` constant-time check runs as a smoke test (it does not
   fail the build on the threshold; see §6) and does not block; the others —
   clippy, test, doc, fmt, cargo-audit, cargo-deny, cargo-machete,
   discipline-grep — do.

6. **Maintainer review.** At v1 phase, the single maintainer is the entire
   review path. Review windows vary with maintainer availability per the
   volunteer-baseline cadence per D0008. The project commits to surfacing
   review delays transparently rather than letting PRs queue silently.

## Architectural decision changes

Substantial architectural changes (anything that would warrant a new D-doc
or modify an existing D-doc) require maintainer discussion before
implementation work begins. Open a GitHub issue describing the proposed
change; reference the D-doc(s) it would affect; the maintainer will respond
within reasonable cadence and the architectural-decision delegation path
per D0018 §9 governs how the change lands.

## Code of Conduct

The project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/)
v2.1 with maintainer enforcement. Conflicts at the architectural-decision
layer are addressed per the D-doc / open-questions discipline; conflicts at
the social layer are addressed by the maintainer.

## Questions

For questions about contributing, open a GitHub Discussion or email
`contact@cairn-project.org` (placeholder; operational email lands before v1
alpha).

For security-relevant questions, see [`SECURITY.md`](SECURITY.md) — do not
discuss security issues in public GitHub issues or discussions.
