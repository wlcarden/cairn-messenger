# Cairn

Secure communications for users facing state-actor adversaries — mercenary
spyware (Pegasus, Predator), forensic-extraction tooling (Cellebrite, MSAB,
GrayKey), and traditional state intelligence services. Cairn integrates
existing cryptographic substrates (SimpleX, Briar, Tor, Sigstore, Sigsum,
Shamir Secret Sharing, COSE) with original cryptographic engineering at the
integration boundary: a three-tier identity model, a cryptographic trust graph
with cascade-quarantine semantics, social recovery without centralized
trustees, and a release-security stack with multi-channel distribution and
multi-party verification.

**Status:** Pre-implementation. The design brief at `docs/design-brief.md` is
substantively complete (v0.10). Implementation begins May 29, 2026 with the
Tier 1 MDC (cryptographic foundation crates). No releases yet.

**Audience:** v1 is a closed pilot targeting 10–15 users in one or two local
groups already known to the developer. The architecture is calibrated against
the threat tier above; the deployable population at v1 is materially smaller
than the threat tier the architecture is designed against. See
`docs/design-brief.md` §1.2 and §2.2 for honest audience framing.

## Documentation

The complete project documentation is in `docs/`:

- **`docs/design-brief.md`** — the substantive design brief (~1,900 lines).
  Read §1 for executive summary; §2 for problem statement; §3 for threat
  model; §5 for architecture; §6-7 for engineering scope and release roadmap;
  §8-10 for operational, governance, and funding posture.

- **`docs/decisions/`** — every architectural and operational decision
  documented as an ADR with rationale, alternatives considered, and
  consequences. D0001 through D0020 as of May 2026.

- **`docs/architecture-diagrams.md`** — eight Mermaid diagrams covering the
  layered architecture, software components, identity tiers, trust graph
  semantics, recovery flow, release pipeline, external dependency surface,
  and build/test/release pipeline.

- **`docs/open-questions.md`** — the project's open-questions tracker
  (Q1-Q27).

- **`docs/runbooks/`** — operational runbooks (CVE response; multi-party APK
  signing-key custody).

- **`docs/reviews/`** — adversarial-review artifacts from the design phase:
  per-lens findings, consolidated triages, external-read prompts and
  findings.

## Engineering foundation (D0018)

This repository ships under **AGPL-3.0-only** (per D0019). The cryptographic
foundation is the RustCrypto stack at versions pinned to match libsignal and
vodozemac production deployments. Memory hygiene via `zeroize` + `secrecy` +
`subtle`. Constant-time discipline enforced by `subtle::ConstantTimeEq` at
every secret comparison and `dudect-bencher` CI gate against release-profile
builds.

The Rust toolchain is pinned to `1.85.0` per `rust-toolchain.toml`. Target
ABIs for Android: `aarch64-linux-android` and `x86_64-linux-android`. NDK
r28+ required (16 KB page-size mandate).

For library selections + rationale + version-pinning policy see
[`docs/decisions/D0018-engineering-foundation.md`](docs/decisions/D0018-engineering-foundation.md).

## Building

This section is a placeholder until the first crate compiles. Once
`cairn-crypto` lands, build with:

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Reproducible builds use Nix; `flake.nix` will land alongside the build-system
integration crates.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The project specifically welcomes
contributions to documentation, test infrastructure, and the reviewer
toolkit. Cryptographic-engineering contributions require maintainer review +
the constant-time CI gate to pass.

## Security disclosure

See [`SECURITY.md`](SECURITY.md). Vulnerability reports go to
`security@cairn-project.org` (PGP key fingerprint TBD; will be published once
the production email and PGP key are established).

For coordinated disclosure, Cairn's preferred relationships are with
research labs whose work model is structured to disclose rather than sell:
Citizen Lab, Amnesty International Security Lab, Access Now Digital Security
Helpline, EFF Threat Lab. These are candidate disclosure-relationship
partners; relationships are negotiated as part of Q5 partner outreach (not
yet started; tracked in `docs/open-questions.md`).

## License

Copyright © 2026 Cairn maintainers and contributors.

Cairn is free software: you can redistribute it and/or modify it under the
terms of the GNU Affero General Public License version 3, as published by
the Free Software Foundation. See [LICENSE](LICENSE).

The AGPL-3.0 license choice is deliberate and documented in
[`docs/decisions/D0019-license.md`](docs/decisions/D0019-license.md).
