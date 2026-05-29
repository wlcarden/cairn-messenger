# D0019 — Project license: AGPL-3.0-only

**Status:** Accepted
**Date:** 2026-05-29

## Context

Sprint 3 of the consolidated external-reads triage (per `docs/reviews/external-reads-consolidated.md`) committed the project to making engineering-foundation decisions before partner-conversation outreach (per the MDC pathway: working code first, then partner conversations against code-as-evidence). The license decision is on the critical path because:

- **Cargo workspace baseline** requires a `license` field in `Cargo.toml` per workspace metadata
- **`cargo deny` license allowlist** requires knowing which licenses are compatible with the project's own choice
- **SimpleX integration** per the consolidated triage SimpleX research (`docs/runbooks/apk-signing-custody.md` and Sprint 3 D0020 integration architecture): SimpleX Chat's reference implementation is AGPL-3.0; integration approach determines whether Cairn is forced into AGPL-3.0 contagion or can choose freely
- **Partner-conversation framing** depends on the license — civil-society organizations evaluating facilitation read the license as a signal about the project's posture toward downstream use

The decision is also a **values decision** (the brief's §2.1 grassroots positioning; §4.2 minimal-project-operated-infrastructure principle; the rejection of commercial-trajectory in §10.4) rather than a purely technical one. The license signals to partner organizations and downstream users what kind of project Cairn intends to be.

## Decision

**Cairn ships under the GNU Affero General Public License version 3.0 only (AGPL-3.0-only), per SPDX license identifier `AGPL-3.0-only`.**

The license applies to:

- All Cairn-original source code (Rust core crates `cairn-crypto`, `cairn-envelope`, `cairn-shamir`, `cairn-identity`, `cairn-trust-graph`, `cairn-recovery`, `cairn-storage`, `cairn-simplex-adapter`, `cairn-tor-transport`, `cairn-sigsum-client`, `cairn-sigstore-verify`; Kotlin Android shell `cairn-android-shell`, `cairn-ui`, `cairn-trust-badges`, `cairn-recovery-flow`; UniFFI binding `cairn.udl`)
- Project-original documentation under `docs/` (the design brief; D-docs; runbooks; reviews; architecture diagrams)
- Project-original build infrastructure (Cargo workspace configuration; Nix flake; CI workflows; Gradle modules)
- Project-original test vectors and fuzzing corpora

The license does NOT apply to:

- Upstream dependencies the project consumes (each retains its own license; managed via `cargo deny` license allowlist)
- The SimpleX Chat CLI binary bundled as sidecar (retains its own AGPL-3.0 license; consumed as separate-process binary)
- The Tor C-Tor binary bundled via `guardianproject/tor-android` (retains its own BSD-3-Clause license)
- Lyrebird pluggable-transport binary (retains its own BSD-2-Clause license)

## Alternatives considered

### Apache-2.0 + MIT dual-license (Rust ecosystem norm)

_Considered, rejected._ Most Rust crates dual-license under Apache-2.0 and MIT to maximize downstream use. `libsignal` uses AGPL-3.0 but most RustCrypto crates use MIT or Apache-2.0. The permissive licenses would let commercial messengers embed Cairn's cryptographic engineering as a library; would let upstream-integrator projects (Briar; SimpleX; messaging-tool aggregators) consume Cairn's trust-graph or recovery components without source-disclosure obligation.

**Why rejected:** the §10.4 "structural collapse most likely outcome" framing makes commercial-trajectory unrealistic for Cairn directly. The brief's §2.1 grassroots positioning and §4.2 minimal-project-operated-infrastructure principle do not target commercial-integration audiences. A permissive license invites a future where a commercial vendor forks Cairn's cryptographic engineering, hardens UX, ships at scale, and Cairn's contribution becomes substrate for a product positioned against the audience Cairn was designed for. AGPL-3.0 prevents this trajectory while permitting non-commercial civil-society and academic integration that the project actively wants.

### GPL-3.0-only

_Considered, rejected._ GPL-3.0 provides strong copyleft for desktop/mobile applications but exempts network use (the "ASP loophole"): a hosted service can use GPL-3.0 code internally without obligation to publish its modifications. For Cairn-the-application (a phone app users install), this distinction is mostly moot. But for Cairn-as-substrate (if a hosted secure-messaging service emerges using Cairn's protocol implementation), GPL-3.0 would let that hosted service modify Cairn without source disclosure.

**Why rejected:** the brief's §4.2 minimal-project-operated-infrastructure principle explicitly avoids the hosted-service model, but the license should also discourage downstream hosted-service forks that would compete with Cairn's protocol implementation while concealing their modifications. AGPL-3.0's network-use clause closes this. Signal-Android uses GPL-3.0; Briar uses AGPL-3.0; Cwtch uses GPL-3.0. Cairn's audience-and-architecture posture is closer to Briar's than to Signal's, which supports AGPL-3.0.

### MPL-2.0 (Mozilla Public License)

_Considered, rejected._ MPL-2.0 provides file-level copyleft: modifications to MPL-2.0 files must be disclosed under MPL-2.0, but the modified files can be combined with non-MPL code in a larger work. This is the license Mozilla uses for Firefox, Rustls, and several Rust crates.

**Why rejected:** the file-level granularity is appropriate when the project's contribution is a discrete component embeddable in larger applications. Cairn's contribution is an integration — the architecture is the value, not individual cryptographic primitives. A file-level copyleft would let downstream projects copy Cairn's `cairn-trust-graph` and `cairn-recovery` files into permissively-licensed products with only those files staying MPL-2.0. The work-level copyleft of AGPL-3.0 better matches the project's contribution being the integration discipline, not the individual crates.

### Hybrid: AGPL-3.0 for the app, Apache-2.0+MIT for library crates

_Considered, rejected._ Some research projects ship the user-facing application under strong copyleft while permissively licensing the underlying library crates (e.g., Microsoft's GitHub Copilot CLI is MIT for its protocol library; Microsoft's PowerToys are MIT but specific components vary). The case for the hybrid: the cryptographic primitives in `cairn-crypto` are wrappers over already-permissively-licensed dependencies (RustCrypto stack), and permissively licensing them lets Cairn's engineering benefit upstream projects without forcing them to AGPL-3.0.

**Why rejected:** the documentation and discipline overhead of managing per-crate licenses is substantial; partner-organization conversations would need to explain the split; auditors evaluating the project would need to track multiple license boundaries; downstream contributors would need to understand which crate they're contributing to. The benefit (some downstream projects could use `cairn-crypto` without AGPL contagion) is small relative to the cost. Single-license posture is operationally simpler and matches the integration-as-contribution framing.

### LGPL-3.0 (Lesser GPL)

_Considered, rejected._ LGPL-3.0 was designed for runtime-linkable libraries that should not impose copyleft on consumers. Cairn's contribution is the integration layer above protocol primitives; the integration is the value, and LGPL-3.0's "library exception" framing does not match the project's value-delivery model.

## Rationale

### Civil-society messaging precedent

The civil-society secure-messaging tradition uses strong copyleft. Briar (AGPL-3.0), SimpleX Chat (AGPL-3.0), Cwtch (GPL-3.0), Tor Browser (Mozilla Public License 2.0 for Mozilla components; mixed for Tor itself; Tor C-Tor is BSD-3-Clause), and Signal-Android (GPL-3.0) all sit in this tradition. AGPL-3.0 matches the closest comparable projects in the brief's §2.3 landscape positioning.

Partner organizations evaluating Cairn for facilitation evaluate the license as a signal about project posture. AGPL-3.0 signals: this project is in the civil-society messaging tradition; downstream commercial forks face source-disclosure obligations; the project does not invite trajectories that would damage the audience it serves. This is the signal the brief wants to send.

### SimpleX integration license-isolation strategy

D0020 (integration architectures) commits to the CLI-sidecar pattern for SimpleX integration: the SimpleX Chat CLI runs as a separate process; Cairn's Rust core communicates with it via local WebSocket. This pattern isolates SimpleX's AGPL-3.0 license to its own process — Cairn could choose any license. Combined with Cairn's own choice of AGPL-3.0, the integrated product is uniformly AGPL-3.0 across both components, which simplifies partner-organization license review.

If Cairn had chosen a permissive license and integrated SimpleX in-process (FFI), AGPL-3.0 contagion would force the combined work to AGPL-3.0 anyway. The CLI-sidecar pattern means Cairn's license choice is genuinely free; AGPL-3.0 is selected on its own merits, not forced by SimpleX integration.

### Grassroots positioning per §2.1 / §4.2

The brief's §2.1 problem statement frames Cairn for users whose adversaries deploy state-actor capability; §4.2 minimal-project-operated-infrastructure principle commits to a structure where the project does not operate user-facing services. These framings are incompatible with a commercial-trajectory license. AGPL-3.0 makes the commitment legally enforceable rather than only stated.

The §10.4 honest-acknowledgment that maintainer compensation does not materialize at Phase D scale similarly implies that Cairn is not positioned for commercial-trajectory. The license decision aligns with the operational posture rather than contradicting it.

### Honest acknowledgment of limitations

AGPL-3.0 reduces the project's downstream-integration audience materially. Specifically:

- **Commercial messenger vendors** will not use Cairn's cryptographic engineering as a library substrate because the AGPL-3.0 obligation extends to their product. This is intentional — the brief's audience and positioning do not target commercial vendors.
- **Some academic projects** that publish under permissive licenses may decline to use AGPL-3.0-licensed components. This is an acknowledged loss; the brief's §8.6 partner-organization roles do not depend on academic-integration trajectories that require permissive licensing.
- **Some downstream civil-society projects** with internal license-policy constraints (often inherited from foundation funding requirements) may have difficulty integrating AGPL-3.0 components. Mitigation: partner-conversation framing explains the license rationale; foundations funding civil-society security tools (OTF; NLnet; Mozilla) generally support AGPL-3.0 for projects in this space.

The losses are real but consistent with the brief's positioning. The license trades downstream-integration breadth for upstream-trajectory protection.

### Consistency with audit-credibility framing

Audit-firm precedent for Rust security-critical projects shipping under AGPL-3.0 is strong: Briar (audited by Cure53); SimpleX (audited by Trail of Bits); a substantial fraction of the audit-firm public-report record involves AGPL-3.0 projects. AGPL-3.0 does not impede audit-firm engagement.

The pre-pilot audit per D0011 evaluates cryptographic-construction correctness against the source code (Rust core; canonical encoding helper; Shamir wrapper); license has no bearing on audit deliverable quality.

## Consequences

### Cargo workspace license field

`Cargo.toml` workspace package metadata:

```toml
[workspace.package]
license = "AGPL-3.0-only"
```

Per-crate `Cargo.toml` files inherit via `license.workspace = true`.

### `cargo deny` license allowlist

The `deny.toml` license configuration per Sprint 3 D0018 baseline allows the following permissive licenses for dependencies (consumed-as-libraries):

- `Apache-2.0`
- `MIT`
- `BSD-3-Clause`
- `BSD-2-Clause`
- `ISC`
- `Unicode-DFS-2016`
- `Zlib`
- `CC0-1.0`
- `MPL-2.0` (file-level copyleft is consumable without forcing Cairn under MPL)

The following copyleft licenses are explicitly **rejected** for dependencies (they would force Cairn into a different license):

- `GPL-2.0-only`, `GPL-2.0-or-later` (would force GPL-2.0 contagion; incompatible with AGPL-3.0-only)
- `GPL-3.0-only`, `GPL-3.0-or-later` (compatibility is technical; rejected to avoid mixed-copyleft confusion)
- `LGPL-2.1-only`, `LGPL-2.1-or-later`, `LGPL-3.0-only`, `LGPL-3.0-or-later` (would require library-exception-handling discipline Cairn does not need)
- `EUPL-1.2` (European Union Public License; compatibility is complex)
- `CDDL-1.0`, `CDDL-1.1` (Sun/Oracle licenses; explicitly incompatible with AGPL)

The following copyleft licenses are **case-by-case** for dependencies (each requires explicit allowlisting after review):

- `AGPL-3.0-only`, `AGPL-3.0-or-later` (matches Cairn's own license; consumed at-process-level only via sidecar pattern; in-process FFI of AGPL-3.0 dependencies is permitted per Cairn's own license)

The SimpleX Chat CLI sidecar binary is AGPL-3.0; it is bundled as a separate-process binary, not linked into the Rust core; license consistency is preserved.

### License-grant text in repository

The project ships:

- `LICENSE` file at repository root containing the full AGPL-3.0 license text (verbatim from <https://www.gnu.org/licenses/agpl-3.0.txt>)
- `COPYING` symlink to `LICENSE` for tooling that expects it (some Linux distributions)
- Per-file SPDX license identifier header on all Cairn-original source files:

```rust
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 [maintainer name + email] and contributors
```

### Section 5.5 release-security implications

Per §5.5, the Sigsum-anchored release log includes the license identifier in release attestations so downstream verifiers can confirm the license declaration is consistent across releases. Sigstore identity-signing covers the source-code release; the license declaration is part of the signed content.

### D0013 pilot consent implications

The pilot consent protocol per D0013 includes a license-disclosure section: pilot users are informed that the software is AGPL-3.0-licensed and that the source code is published. This is part of the §5.5 release-security disclosure stack, not a separate consent element.

### Brief section updates

The following brief sections are updated to reference the license decision:

- **§1.4 v1 scope**: add "the project ships under AGPL-3.0-only per [D0019](decisions/D0019-license.md); source code is published on a public repository under that license"
- **§4.2 minimal-project-operated-infrastructure principle**: add license-rationale paragraph explaining AGPL-3.0 alignment with the principle
- **§5.5 release security**: reference license-disclosure as part of the signed release content
- **§7.1 release sequence**: no changes (license applies uniformly across releases)
- **§8.5 security disclosure**: reference license-as-published-property of the disclosure-policy substrate
- **§10.6 funding strategy**: add note that funder application materials confirm the project's AGPL-3.0 license; foundations funding civil-society security tools (OTF, NLnet, Mozilla) generally support AGPL-3.0

### Reversibility

The license decision is **partially reversible at low cost during pre-public-release** and **fully irreversible after public release** without re-licensing-by-all-contributors consent (which is impractical for a community-contributed project). Specifically:

- Before public source release: license can be revised to any other license (with maintainer agreement only, since maintainer is the sole contributor at that stage)
- After public source release: re-licensing requires consent from all contributors who have contributed code under AGPL-3.0; in practice, this means re-licensing is not feasible for the project's lifetime
- The decision should be considered binding once the first public commit lands under AGPL-3.0

Reversal scenarios contemplated and explicitly accepted as the decision's permanent consequence:

- If commercial-vendor adoption later becomes desirable (e.g., a vendor wants to license Cairn for embedding), AGPL-3.0 forces them to make their product AGPL-3.0 — and they decline. The project does not pursue commercial-trajectory revenue.
- If academic-integration projects with permissive-only license policies decline to use Cairn, the project does not pursue those integrations.
- If a downstream civil-society project finds AGPL-3.0 inconsistent with their foundation funding requirements, the project explains the rationale; if the project cannot accommodate, the integration does not proceed.

These outcomes are acceptable trade-offs for the protection AGPL-3.0 provides against trajectories the brief's positioning explicitly does not want.

## References

- AGPL-3.0 official text: <https://www.gnu.org/licenses/agpl-3.0.txt>
- SPDX license identifier registry: <https://spdx.org/licenses/AGPL-3.0-only.html>
- Briar AGPL-3.0 precedent: <https://code.briarproject.org/briar/briar/-/blob/master/LICENSE>
- SimpleX Chat AGPL-3.0 precedent: <https://github.com/simplex-chat/simplex-chat/blob/stable/LICENSE>
- Cwtch GPL-3.0 precedent: <https://git.openprivacy.ca/cwtch.im/cwtch/src/branch/trunk/LICENSE>
- Signal-Android GPL-3.0 precedent: <https://github.com/signalapp/Signal-Android/blob/main/LICENSE>
- [D0018](D0018-engineering-foundation.md) — Sprint 3 cryptographic library and Rust ecosystem foundation (consumes this license decision in workspace baseline)
- [D0020](D0020-integration-architecture.md) — Sprint 3 SimpleX + Tor + FFI integration architectures (consumes this license decision in SimpleX sidecar isolation rationale)
- [docs/reviews/external-reads-consolidated.md](../reviews/external-reads-consolidated.md) — Sprint 3 origin
- [docs/design-brief.md](../design-brief.md) §2.1, §2.3, §4.2, §10.4 — positioning context informing license rationale
