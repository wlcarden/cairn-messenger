# Decisions

One file per significant architectural or product decision. Each entry captures:

- The decision (one line, in imperative or declarative form)
- Context — what problem the decision addresses
- Alternatives considered, with reasons each was not selected
- Consequences — what the decision implies for adjacent systems
- References — prior art, papers, RFCs, related discussions

Format suggestion (lightweight ADR):

```
# DNNNN — Short title

**Status:** Proposed | Accepted | Superseded by [DNNNN]
**Date:** YYYY-MM-DD

## Context
What problem this decision addresses.

## Decision
What was chosen.

## Alternatives
What else was considered, and why each was not selected.

## Consequences
What this implies. Both intended consequences and accepted tradeoffs.

## References
Links to prior work, papers, related decisions.
```

When an open question from `../open-questions.md` is resolved, the resolution moves here as a decision file, and the question entry gets a closing note linking to the decision file.

## Index

Complete, current list of all architecture decision records (generated; statuses abbreviated — see each file for the full status). **Note:** D0039 was never allocated; the sequence skips from D0038 to D0040.

| ADR                                                | Title                                                                                                                                   | Status                                                              |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| [D0001](D0001-project-name.md)                     | Project working name: Cairn                                                                                                             | Accepted                                                            |
| [D0002](D0002-duress-profile.md)                   | Duress profile: out of v1, duress wipe deferred to v1.5                                                                                 | Accepted                                                            |
| [D0003](D0003-implementation-language.md)          | Implementation language: Rust core + Kotlin UI                                                                                          | Accepted                                                            |
| [D0004](D0004-v1-scope-cuts.md)                    | v1 scope cuts: defer Briar and reproducible builds to v1.5; drop local CRDT permanently; narrow v1 UX                                   | Accepted                                                            |
| [D0005](D0005-peer-verification.md)                | Recovery peer verification mechanism: pre-shared challenges plus delay-and-confirm                                                      | Accepted                                                            |
| [D0006](D0006-cryptographic-envelope.md)           | Cryptographic envelope completion: schema additions, cascade semantics, vocabulary precision                                            | Accepted                                                            |
| [D0007](D0007-multi-device.md)                     | Multi-device commitment demoted: v1 and v2 single-device-per-identity de facto                                                          | Accepted                                                            |
| [D0008](D0008-volunteer-baseline-cadence.md)       | Volunteer-baseline release cadence: slippage acceptance with quarterly as post-honoraria target                                         | Accepted                                                            |
| [D0009](D0009-sudden-unavailability.md)            | Sudden-developer-unavailability contingency: dead-man's-switch plus pre-arranged partner advisory authority                             | Accepted                                                            |
| [D0010](D0010-foundation-jurisdiction.md)          | Foundation jurisdiction handling: placeholder pending legal consultation, with fiscal-sponsor stage and factual corrections             | Accepted                                                            |
| [D0011](D0011-audit-budget-and-timing.md)          | Audit budget and timing: widen budget to market range, add pre-pilot primitives-only audit                                              | Accepted                                                            |
| [D0012](D0012-researcher-safe-harbor.md)           | Researcher Safe Harbor: stated intent until foundation incorporation, formalized at incorporation                                       | Accepted                                                            |
| [D0013](D0013-pilot-consent-exit.md)               | Pilot consent and exit protocol                                                                                                         | Accepted                                                            |
| [D0014](D0014-non-peer-recovery.md)                | Non-peer recovery path policy: out of scope for v1 with explicit acknowledgment; named v1.5+ candidate paths                            | Accepted                                                            |
| [D0015](D0015-v1-release-security-posture.md)      | v1 release-security posture: developer-signed + public log + multi-channel distribution; recruited reviewer pool deferred to v1.5       | Accepted                                                            |
| [D0016](D0016-foundation-incorporation-trigger.md) | Foundation incorporation deferred with v1.5 broader-release evaluation trigger                                                          | Accepted                                                            |
| [D0017](D0017-calyxos-inclusion.md)                | CalyxOS inclusion at v1: GrapheneOS-only baseline retained; CalyxOS evaluation deferred to v1.x                                         | Accepted                                                            |
| [D0018](D0018-engineering-foundation.md)           | Engineering foundation: cryptographic library selections, Rust ecosystem discipline, and Cargo workspace baseline for v1 implementation | Accepted                                                            |
| [D0019](D0019-license.md)                          | Project license: AGPL-3.0-only                                                                                                          | Accepted                                                            |
| [D0020](D0020-integration-architecture.md)         | Integration architecture: SimpleX + Tor + FFI hybrid                                                                                    | Accepted                                                            |
| [D0021](D0021-library-pin-audit.md)                | Library pin audit + revision (Cargo.toml drift, coset role, hygiene)                                                                    | Accepted                                                            |
| [D0022](D0022-storage-layer.md)                    | cairn-storage layer: rusqlite + per-value XChaCha20-Poly1305                                                                            | Accepted                                                            |
| [D0023](D0023-sigsum-integration.md)               | cairn-sigsum-client: commitment-only logging + witness-cosignature verification                                                         | Accepted (wire format revised 2026-05-30; leaf/emit model revised…  |
| [D0024](D0024-sigstore-release-verification.md)    | cairn-sigstore-verify: release-artifact identity verification + Rekor inclusion + Sigsum-anchored release log composition               | Accepted (Rekor checkpoint algorithm revised 2026-05-30)            |
| [D0025](D0025-cairn-tor-transport.md)              | cairn-tor-transport: crate surface over the C-Tor ForegroundService per D0020 §2                                                        | Accepted                                                            |
| [D0026](D0026-cairn-simplex-adapter.md)            | cairn-simplex-adapter: SimplOxide-sidecar transport + Cairn message envelope per D0020 §1                                               | Accepted                                                            |
| [D0027](D0027-cairn-uniffi-crate-surface.md)       | cairn-uniffi: crate surface implementing the D0020 §3 FFI architecture                                                                  | Accepted                                                            |
| [D0028](D0028-android-shell-build-pipeline.md)     | android/ shell build pipeline: the realized cargo-ndk → UniFFI → APK chain                                                              | Accepted                                                            |
| [D0029](D0029-quick-unlock.md)                     | biometric / device-credential quick-unlock (opt-in passphrase wrap)                                                                     | Accepted                                                            |
| [D0030](D0030-change-passphrase.md)                | change-passphrase: decouple the SimpleX DB key, then atomic single-DB rekey                                                             | Accepted                                                            |
| [D0031](D0031-delete-purge.md)                     | deeper delete-purge: message history + libsimplex connection                                                                            | Accepted                                                            |
| [D0032](D0032-read-receipts.md)                    | read receipts: off-by-default, reciprocal, read-only                                                                                    | Accepted                                                            |
| [D0033](D0033-key-attestation-verification.md)     | device-key attestation verification (Android Key Attestation)                                                                           | Accepted (Stage 1)                                                  |
| [D0034](D0034-group-chat-scope.md)                 | group chat scope: delegate the protocol, per-sender integrity, provenance-not-reputation                                                | Accepted (scope + architecture-model decision; group features…      |
| [D0035](D0035-trust-graph-activation.md)           | trust-graph activation: self-rooted attestations on the v1 single-key identity                                                          | Accepted (Stage 1 design; implementation staged)                    |
| [D0036](D0036-provenance-annotation.md)            | provenance annotation: deliberate attestation-sharing + transitive-trust display (depth-1)                                              | Accepted (scope + design; implementation staged)                    |
| [D0037](D0037-introductions.md)                    | introductions: consent-gated, connection-making, symmetric (introducer-initiated)                                                       | Accepted (scope + design; implementation staged)                    |
| [D0038](D0038-recovery-app-integration.md)         | Recovery model: app integration (paper-share-first staging)                                                                             | Accepted (staging + the two foundational forks decided 2026-06-05). |
| [D0040](D0040-recovery-coercion-resistance.md)     | Recovery coercion-resistance: the in-app build of D0005 (recovery Stage 3)                                                              | Accepted                                                            |
| [D0041](D0041-release-producer-pipeline.md)        | Release-producer pipeline: `cairn-release` + on-device verify (the D0024 §6 producer side)                                              | Accepted (phase 1 — self-minted roots — pipeline _mechanics_…       |
| [D0042](D0042-sigstore-phase2-keyless-signing.md)  | Sigstore phase 2: real keyless signing + pinned staging trust roots (the D0041 §6.1 hard blocker)                                       | Accepted (design; phase-2 staging).                                 |
