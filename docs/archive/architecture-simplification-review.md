# Architecture Simplification Review — Consolidated Findings

**Date:** 2026-05-28
**Source:** Five parallel sub-agent reviews, each applying a distinct simplification lens to the architectural commitments in §§4, 5, 6, and 8 of the design brief.

- Lens A — YAGNI / over-engineering (aggressive cuts at v1 audience scale): [arch-simpl-lA-yagni.md](reviews/arch-simpl-lA-yagni.md)
- Lens B — component-by-component necessity (each commitment against v1 audience and §3 threat tier): [arch-simpl-lB-necessity.md](reviews/arch-simpl-lB-necessity.md)
- Lens C — comparable products (what Briar, SimpleX, Threema, Tails, F-Droid, GrapheneOS ship without): [arch-simpl-lC-comparable.md](reviews/arch-simpl-lC-comparable.md)
- Lens D — operational maintenance cost (ongoing per-cycle cost vs v1 value at the volunteer baseline): [arch-simpl-lD-operational.md](reviews/arch-simpl-lD-operational.md)
- Lens E — multi-year solo-developer feasibility (recurring coordination loops across v1→v3): [arch-simpl-lE-multi-year-solo.md](reviews/arch-simpl-lE-multi-year-solo.md)

**Raw findings:** 56 across reviewers (Critical 22, Significant 23, Minor 11). After deduplication and theming: 19 consolidated findings below.
**Companion to:** [design-brief.md](design-brief.md) §§4, 5, 6, 7, 8, 10, with cross-references to decision documents D0001–D0014 and open questions Q1–Q26.

---

## Executive summary

This review crosses §§4, 5, 6, and 8 to ask, lens by lens, which v1 architectural commitments are load-bearing for the §2.2 audience at the §3 threat tier, and which are defensible engineering that the brief could cut, defer, or simplify without weakening the value v1 actually delivers. The brief's own design discipline (§4.3 "compound rather than add"; §6.4 honesty about the cost of forward-compatibility scaffolding; §6.1's "smallest cut" framing) already invites this scrutiny; the five lenses execute it from non-overlapping angles.

The headline finding across all five lenses is that **the v1 architecture has accumulated commitments calibrated to a foundation-operated quarterly-cadence product running on funded teams, then commits to operating that architecture at the solo-developer "as available" volunteer baseline named in §10.1 and D0008.** The mismatch concentrates engineering cost in the v1 implementation window (Lens A, B), audit-and-review scope (Lens D), and recurring partner-coordination loops that compound across v1→v1.5→v1.6→v2→v3 (Lens E). Three of four §4.3 differentiating commitments — three-tier identity, cryptographic trust graph with cascade quarantine, social recovery with layered peer verification — survive all five lenses as load-bearing for the v1 audience and threat tier. The fourth differentiator — the recruited 5+ reviewer pool with 3-of-5 Sigsum-anchored attestation as v1 critical path — does not survive the comparable-products and operational-cost lenses, and is the single highest-leverage simplification target this review surfaces. Three v1 commitments (crash-reporting infrastructure, multi-target build pipeline, property-based migration framework) draw consensus cuts across all four lenses that evaluated them; eight more are split-lens findings the author should decide based on which lens's framing dominates.

Phase D sustainability (§10.4) shifts materially if the consensus cuts are applied. Lens E's framing — that the maintainer-comp aspiration is "load-bearing for survival" rather than "preference for higher throughput" because recurring coordination loops consume the engineering capacity §10.4 budgets for engineering — is the strategic frame for this review. The consensus cuts plus the highest-leverage split-lens cuts (reviewer-pool deferral; foundation-incorporation deferral; v1.6 collapse; multi-channel-distribution narrowing) drop the recurring-coordination floor enough that the maintainer-comp question becomes a quality-and-throughput preference rather than a project-survival precondition. This changes how §1, §4.3, §9.1, and §10.4 should frame the project's posture; it does not change the audience-serving architecture for users at the §3 threat tier.

---

## Patterns

Six cross-lens patterns emerge that matter more than any single finding:

**P1. Double-defenses against threats §3 acknowledges as residual.** Caught by Lens A and Lens B. Three v1 commitments combine two distinct mechanisms against the same threat surface: cascade quarantine + 90-day stale-flag escalation (§5.2); pre-shared peer challenges + 48-hour delay-and-confirm (§5.3); long-lived APK key + per-release Sigstore identity (§5.5). In each case §3 already names the threat as residual; the layered defense produces audit complexity and operational state without closing the residual surface. Lens A recommends cutting the second layer in each case; Lens B disagrees on cascade-quarantine and peer-verification specifically, treating both layers as load-bearing for the §3 threat tier. This is a genuine disagreement (preserved in §5 below).

**P2. Forward-compatibility scaffolding for v2/v3 features whose funding §10.8 does not promise.** Caught by Lens A, Lens B, Lens D, and Lens E (the latter via its v3-cut recommendation). Four §6.4 commitments — multi-target build pipeline, capability-token scope vocabulary, property-based migration framework, issuer-cert-hash binding — exist to make v2/v3 work cheaper _if_ v2/v3 ships, and §6.4 itself acknowledges three of them as "dedicated v1 engineering line-items rather than zero-cost architectural commitments." §7.1 and §10.8 frame v2 and v3 as conditional on Phase D funding and partner relationships the project does not control. Building the scaffolding before the destination is known pays v1 cost from the volunteer-baseline budget §9.1 names as the binding constraint.

**P3. Population-scale machinery deployed at pilot scale.** Caught by Lens A, Lens C, Lens D. At v1 pilot scale (10–15 users known to the developer per §6.3, with the developer-as-facilitator per §5.6), several mechanisms exist to substitute for the developer's direct contact with each user — the cascade-stale-flag escalation, the project-operated crash-reporting queue, the UnifiedPush distributor-selection UX, the per-release Sigstore identity-signing layer. At population scale these substitutions are necessary; at pilot scale they duplicate a channel the developer-as-facilitator already operates. Lens C's framing is sharpest: comparable products (Briar, F-Droid, GrapheneOS) ship credible release-security postures at overlapping audience scale without recruiting parallel reviewer pools or operating equivalent infrastructure.

**P4. Recurring loops vs one-time scope is the structural fault line.** Caught most distinctly by Lens E, supported by Lens D. The brief estimates one-time engineering cost (9–12 person-months for v1 per §6.1, 6–9 for v1.5 per §7.1) but does not aggregate the recurring coordination cost the architectural commitments install: audit cycles (~80–200 hrs every 18–24 months per D0011/§8.5); upstream-protocol tracking (~210–420 hrs/yr by v3 per Lens E F2 — SimpleX, Briar, Tor PT, GrapheneOS, optionally Meshtastic+MeshCore, optionally PQ); reviewer-pool rotation (~80–200 hrs/yr per Lens E F3); witness-pool maintenance (~40–100 hrs/yr per Lens E F4); foundation-and-partner-advisory coordination per D0009/D0010/§8.4; D0009 monthly check-in (~24–36 hrs/yr); trust-roots health report (~80–320 hrs/cycle per §9.4); multi-channel distribution (~50–150 hrs/yr per Lens E F6). Lens E's sum: **400–1,000 hrs/yr of recurring solo coordination** at Phase D steady state, before any engineering work. At a sustainable volunteer baseline of 15–20 hours/week, this leaves 0–500 hrs/yr for engineering. §10.4's "every contributor except the engineer-operator" framing is the funding symptom; the architectural cause is the recurring-coordination floor.

**P5. The §4.3 four-commitment integration holds for three commitments and not the fourth.** Caught by Lens C, supported by Lens B's F5 and F7. The "compound rather than add" framing in §4.3 is structurally true for three-tier identity + trust graph + recovery — removing any one breaks the others (the trust graph depends on persistent identity, recovery depends on the master tier, identity rotation depends on trust-graph cascade). It is structurally weaker for the 5-of-N recruited reviewer pool: the pool is not a precondition for identity/trust/recovery layers to function; it is a separate trust placement operating in parallel. F-Droid's rebuild pipeline, GrapheneOS's multi-signer release process, and Signal Android's reproducible builds + F-Droid posture each ship credible release-security postures for overlapping audiences without recruiting a parallel pool. The §4.3 differentiation argument should narrow to the three commitments that genuinely compound, with release security framed as Cairn's distinct-from-Signal-but-not-distinct-from-GrapheneOS posture rather than as a fourth equal commitment.

**P6. v1's three trust-graph engineering surfaces are calibrated for reviewer/funder defensibility, not v1 user value.** Caught most pointedly by Lens A. The nine-field envelope, the five-operation type system with cascade-with-escalation, and the issuer-cert-hash binding all make the trust graph more defensible in an adversarial review than in the original §5 draft (the §5 adversarial review F4/F11 findings the brief absorbed into D0006). The pre-pilot audit scope per D0011 must cover all three additions; the audit hours are paid against a finite budget that could otherwise cover the load-bearing primitives (Shamir reconstruction, COSE*Sign1 envelope, recovery-flow memory hygiene). Lens A's framing — "prioritize audit coverage of the components a v1 user depends on, not the components a v1.5 user \_would* depend on" — is the structural critique. Lens B disagrees on cascade and operation-type count specifically and Lens D agrees on audit-scope narrowing; preserved as a disagreement in §5 below.

---

## Severity distribution

- **Critical (F1–F8):** 8 findings. Components multiple lenses agree to cut or defer entirely, or cuts whose cumulative effect changes Phase D sustainability (§10.4) materially.
- **Significant (F9–F15):** 7 findings. Components lenses agree to simplify (not eliminate), or split-lens findings where surfacing the disagreement is itself the value.
- **Minor (F16–F19):** 4 findings. Editorial framing changes, smaller scope tightenings, cost-visibility additions.

---

## Consolidated findings table

| ID  | Severity    | Lens(es)                       | Component                                                                      | Cut-or-Simplify                                                                                                                    | Cross-section impact                                                            |
| --- | ----------- | ------------------------------ | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| F1  | Critical    | A, B, D                        | §5.7/§6.1 project-operated SimpleX crash-reporting queue                       | **Cut entirely** at v1                                                                                                             | §4.2 principle (removes named exception); §6.1; §10.4 ops                       |
| F2  | Critical    | A, B, E (via F13)              | §6.4 multi-target build pipeline                                               | **Cut** at v1; Rust core preserves portability natively                                                                            | §6.4; §7.1 v2/v3; §10.1 Phase A scope                                           |
| F3  | Critical    | A, B                           | §5.7/§6.4 property-based migration test framework                              | **Defer to v1.5** when first real migration exists                                                                                 | §5.7; §6.4; §8.5 audit scope                                                    |
| F4  | Critical    | C, A (partial), B (partial), E | §5.5 5+/3-of-5 recruited reviewer pool as v1 critical path                     | **Defer to v1.5** alongside reproducible-builds + F-Droid integration; v1 = developer Sigstore + Rekor + Sigsum + multi-channel    | §4.3 differentiation; §5.5; §6.1 ship gate; §8.2; §10.3 Phase C; D0011; Q3, Q5  |
| F5  | Critical    | D, E                           | §8.5/D0011 pre-pilot audit four-component scope                                | **Narrow** to COSE_Sign1 envelope + recovery-flow crypto only; Shamir as Rust-core check; trust-graph schema as source-review item | §6.1 pre-pilot gate; §8.5; §10.2 Phase B; D0011                                 |
| F6  | Critical    | E                              | §8.4/D0010 foundation incorporation as 18–24-month milestone                   | **Defer indefinitely**; operate under fiscal sponsor as Phase D steady state                                                       | §8.4; §9.4 sunset; §10.3 Phase C; §10.4 Phase D; D0009; D0010; D0012            |
| F7  | Critical    | E                              | v1.6 as a distinct release                                                     | **Collapse into v1.5 or push to v2**                                                                                               | §6.2; §7.1 release sequence; D0002; D0004                                       |
| F8  | Critical    | E                              | v3 mesh integration + iOS-at-v2 + multi-channel distribution count             | **Cut v3 to v4+ candidate; reduce v1 distribution to F-Droid + Accrescent only**                                                   | §5.5; §6.2; §7.1 v2/v3; §10.4; §10.5; Q25                                       |
| F9  | Significant | A, B (disagrees)               | §5.2 cascade quarantine + 90-day stale-flag escalation                         | **Disagreement** — A: cut both withdrawal-as-op-type and escalation; B: load-bearing for §3 threat tier                            | §5.2; §6.1; D0006; D0011 audit scope                                            |
| F10 | Significant | A, B (disagrees)               | §5.3 pre-shared challenges + 48-hour delay-and-confirm                         | **Disagreement** — A: ship challenges only, defer delay; B: both load-bearing per layered-resistance framing                       | §5.3; §6.1; D0005; D0011 audit scope                                            |
| F11 | Significant | A, B (disagrees)               | §5.5 long-lived APK key + per-release Sigstore identity dual-signing           | **Disagreement** — A and B: APK key non-cuttable; A and B (partial): Sigstore layer defensibly v1.5 with named tradeoffs           | §3.4 trust roots (removes OIDC + Rekor at v1); §5.5; §8.5 audit scope; Q11 OIDC |
| F12 | Significant | A, D                           | §5.4/§6.1 UnifiedPush distributor-selection UX                                 | **Simplify**: ship v1 polling-only; defer UnifiedPush UX to v1.5                                                                   | §5.4; §6.1; §6.4 forward-compat preserved; pilot-feedback gate                  |
| F13 | Significant | A, B (disagrees)               | §5.1/§6.4 capability-token scope vocabulary                                    | **Disagreement** — A: all-or-nothing v1 token; B: scope-bounding is v1 security property not forward-compat                        | §5.1; §6.4; D0007; v2 multi-device                                              |
| F14 | Significant | A (F3)                         | §5.2 issuer-cert-hash binding (9th field)                                      | **Cut** at v1; reintroduce in v1.5 with rotation flow                                                                              | §5.2; D0006; D0011 audit scope; §6.4 schema-fields                              |
| F15 | Significant | D, E (F3)                      | §8.2 reviewer-pool 18-month rotation cadence (if F4 not adopted)               | **Simplify** to "rotation at reviewer initiative; project does not impose cycle" at volunteer baseline; or extend to 36 months     | §8.2; §10.3 Phase C; D0008 cadence; §10.7                                       |
| F16 | Minor       | A                              | §6.1 loaner-pool inventory (2–4 devices)                                       | **Cut** standing inventory; handle hardware case-by-case at pilot                                                                  | §6.3 pilot; §10.1 Phase A capital                                               |
| F17 | Minor       | A, D                           | §5.5/§6.1 inconsistency: §5.5 lists 5 channels, §6.1 narrows to 3              | **Reconcile to 3 (or 2)** — confirm v1 scope, defer Tor onion + offline images                                                     | §5.5; §6.1; §4.2 principle                                                      |
| F18 | Minor       | C (F4, F5)                     | §2.2/§2.3 audience-overlap with Threema and Tails not surfaced                 | **Editorial** — name the Cairn-audience-not-served-by-Threema and Cairn-audience-not-served-by-Tails subsets explicitly in §2.2    | §2.2; §2.3; §4.3                                                                |
| F19 | Minor       | D, E                           | Upstream-tracking and witness-pool-management ongoing cost unbudgeted in §10.4 | **Name** as explicit §10.4 line items                                                                                              | §10.4; §10.7; §9.1                                                              |

---

## Consensus cuts (2+ lenses agree to cut entirely)

These are the high-confidence simplifications the project should seriously consider. Each is grounded in the integrated evidence across the lenses that recommend the cut.

### F1. Project-operated SimpleX crash-reporting queue — cut entirely at v1

**Lenses:** A (F6), B (F1), D (F4). All three agree to cut.

- **Current commitment:** §5.7 and §6.1:607 commit to opt-in encrypted crash reports delivered through SimpleX to a "Cairn-team-controlled SimpleX queue" with consent flow at provisioning, encrypted report delivery, and intake/triage infrastructure. §6.1:607 names this as "the one acknowledged exception to the §4.2 minimal-project-operated-infrastructure principle."
- **Integrated evidence:** At pilot scale (10–15 users known to the developer per §6.3, with developer-as-facilitator per §5.6 and partner-mediated consent/exit per D0013), the crash-reporting infrastructure duplicates a channel the developer-as-facilitator already operates. Lens A names it as "population-scale machinery deployed at pilot scale"; Lens B names the §4.2 exception as the strongest reason to cut (removing it lets the §4.2 principle become operative without an exception); Lens D notes the recurring per-cycle ops cost (queue maintenance, intake/triage, consent-flow maintenance) is real at any non-zero report volume and contradicts §4.2.
- **What v1 loses:** Structured telemetry from pilot users to developer during the 9–12 month implementation period and the gated pilot. Pilot crash signals flow through the D0013 partner-mediated channel and the §6.3 direct facilitator-user channel instead.
- **What v1 gains:** Removes the explicit §4.2 exception (cleaner architectural story for funders and reviewers); eliminates project-operated queue, triage tooling, retention policy, project-side key management, eventual key rotation per §8.4 transition; removes one informed-consent module from provisioning (§5.6); narrows audit scope per §8.5/D0011.
- **Recommendation:** Cut from v1. Document the v1 simplification in [D0004](decisions/D0004-v1-scope-cuts.md). The §5.7 architecture is preserved as a v1.5 candidate; v1.5 broader-than-pilot release is the moment to reconsider when direct facilitator-user channels do not exist for every user.

### F2. Multi-target build pipeline cross-compilation scaffolding — cut at v1

**Lenses:** A (F4), B (F2), E (F13 via v3 cut). All agree.

- **Current commitment:** §6.4:693 commits the v1 build pipeline to accept "additional targets — the v2 USB image, the v2 iOS bundle, the v3 mesh-node firmware — without restructuring," with explicit acknowledgment that this is "a v1 architectural commitment with real engineering cost ... rather than zero-cost engineering hygiene."
- **Integrated evidence:** §6.4:693 itself names this as a dedicated v1 engineering line-item absorbed into the 9–12 person-month estimate. Lens A: it pays v1 engineering cost for v2/v3 features §10.8 does not promise the project reaches. Lens B: the Rust core's cross-compilability is a _language_ property (D0003), not a _pipeline_ property; v2 USB form factor compiling the same Rust core to a different target uses Rust's cross-compilation natively. Lens E: if v3 cuts (F8 below), one of the three target categories the pipeline accommodates disappears anyway, and recurring CI maintenance per additional target is a Lens-E recurring-load item.
- **What v1 loses:** v2 USB and iOS work (~12–18 months post-v1 per §6.2) will require build-system restructuring at that time rather than only target-addition. The §6.4 forward-compatibility promise weakens from "additive" to "restructure-then-add."
- **What v1 gains:** Materially reduced v1 implementation scope; narrower CI surface; honest framing that v2 platform expansion is v2 work paid against Phase D funding (§7.1:713) rather than against Phase A volunteer baseline.
- **Recommendation:** Cut. Ship v1 with a single-target Android build pipeline. Keep the Rust/Kotlin boundary clean (D0003 mandates it for security). Document §6.4 as committing the things that genuinely cost nothing to commit, and deferring the things that cost real v1 engineering. Saves weeks of v1 build-system work.

### F3. Property-based migration test framework — defer to v1.5

**Lenses:** A (F9), B (F3). Both agree.

- **Current commitment:** §5.7:574 and §6.4:691 commit to "SQLite with explicit schema versioning and migration tests using property-based round-trip verification through each migration step." §6.4:695 explicitly names this as a "dedicated subsystem, not free."
- **Integrated evidence:** v1 has one schema version. The property-based framework's first actual use is v1→v1.5 migration. Both lenses note: writing round-trip properties for migrations that do not exist yet, against a future schema that has not been specified yet, is the standard YAGNI shape.
- **What v1 loses:** Nothing v1 needs. Schema-versioning _fields_ ship in v1 (they cost ~nothing — the forward-compatibility property §6.4:691 requires); the _test framework_ that exercises migrations is the v1.5 line-item.
- **What v1 gains:** One fewer v1 subsystem to build and audit; honest acknowledgment that migration discipline is incrementally accumulated against real schema changes.
- **Recommendation:** Defer. v1.5's first concrete migration (likely the trust-graph caching layer per §5.2:416) is when the framework lands, against an actual migration to test.

### F4. Recruited 5+ reviewer pool with 3-of-5 Sigsum-anchored attestation as v1 critical path — defer to v1.5

**Lenses:** C (F1, F2, F7), A (F12, partial via §3.4 narrowing), B (F7, simplifies but does not cut), E (F3, simplifies aggressively).

This is the **single highest-leverage cut this review surfaces.** Lenses C and E recommend deferring or radically reducing the pool; Lens B accepts the principle but proposes 2-of-3 / 36-month rotation softening rather than a full v1 deferral.

- **Current commitment:** §5.5:506 commits to 5+ recruited reviewers with 3-of-5 attestation threshold. §6.1:609 gates v1 release shipping on "first-quorum attestation forming." §8.2 commits to 18-month rotation cadence with overlap. §4.3:309 names this as a primary Cairn differentiator: "substitutes the developer's single signing identity with a distributed trust set."
- **Integrated evidence:**
  - **Lens C:** F-Droid's rebuild/resign pipeline (named in §4.3 as prior art) constitutes independent attestation for overlapping-audience products at lower cost. Briar — §2.3's closest threat-tier comparator — ships through F-Droid's pipeline, does not maintain a recruited reviewer pool, and serves an audience substantially overlapping Cairn's. GrapheneOS's multi-signer release process precedent applies to OS-layer; for application-layer, F-Droid + reproducible builds is the path. Signal Android ships reproducible builds + F-Droid posture. The marginal property the recruited pool adds over the comparable-products posture is jurisdictional diversity at attestation and v1-source-review-before-reproducible-builds.
  - **Lens E:** Reviewer-pool coordination is a **continuous** partner-coordination loop. Per-release: 8–20 hrs (3-of-5 attestation collection, Sigsum entry). 18-month rotation: at least one reviewer transition per 3–4 months on average, ~12–30 hrs/transition. Compounded annual recurring coordination: **80–200 hrs/yr** at steady state. Q3 (honoraria funding) and Q5 (NGO partner outreach) gates make recruitment dependent on outcomes outside project control. D0009 successor-takeover viability is very low for the relationship-state portion.
  - **Lens A:** Cutting F4 narrows §3.4's enumeration of trust roots (reviewer pool + reviewer onboarding toolkit), simplifies the §6.1:609 ship-gate framing, and removes one of the three recruitment-dependent items currently gating v1 ship.
  - **Lens B:** The multi-party-attestation property is what substitutes the developer's single signing identity (§4.3:309); cutting it weakens v1 release security. Proposes 3+/2-of-3 v1 threshold with v1.5 tightening to 5+/3-of-5 alongside reproducible-builds transition.
- **The disagreement (preserved):** Lens B treats the pool as load-bearing for the §3 threat tier and proposes softening (smaller pool, longer rotation). Lenses C and E treat the pool as duplicative of F-Droid's posture and propose deferral.
- **Cumulative effect on Phase D sustainability:** Removing this commitment from v1 critical path eliminates the largest single recurring partner-coordination loop in §8. Combined with F1, F2, F3, F6, F7, F8 below, the recurring-coordination floor drops materially.
- **Recommendation:** Defer the recruited pool to v1.5 alongside reproducible-builds + F-Droid integration. v1 release-security stack: developer Sigstore + Rekor + Sigsum release log + multi-channel distribution + F-Droid rebuild (when v1.5 reproducible builds land). v1.5+ optionally adds the 5+/3-of-5 recruited pool if Phase C honoraria funding closes (§10.3). **If the author rejects this deferral**, adopt Lens B's softening: v1 ships 3+/2-of-3 pool with v1.5 tightening to 5+/3-of-5, explicitly framing as recruitment-gate softening. The full §4.3 framing of release security as a Cairn differentiator should narrow to "Cairn's release-security posture is distinct from Signal Foundation's posture but not distinct from GrapheneOS's posture or Briar's posture."

### F5. Pre-pilot audit four-component scope (D0011) — narrow to two components

**Lenses:** D (F1), E (F1, partial).

- **Current commitment:** §8.5 / D0011 scope: (1) COSE_Sign1 envelope verification, (2) Shamir SSS reconstruction with memory hygiene, (3) trust-graph operation envelope nine-field schema and signature chain including issuer-cert-hash binding, (4) recovery-flow cryptographic operations. Budget $15–30K subsidized; 1–2 person-weeks senior auditor time.
- **Integrated evidence:** Lens D — v1 cryptographic-correctness assurance at pilot scale (10–15 users per §6.3) is dominated by (1) COSE_Sign1 envelope and (4) recovery-flow crypto — the two surfaces where Cairn does original construction no upstream audit covers. (2) Shamir over GF(256) is a well-understood primitive whose memory hygiene is a Rust-core property auditable through `cargo test` + property-based testing. (3) The nine-field schema is closed-form and check-able from the source review §5.5 reviewers do; it does not need separate cryptographic audit treatment. D0011's contingency clause already names a narrower scope as defensible ("If pre-pilot audit funding does not close, the project either reduces pre-pilot scope further (e.g., capability-token construction only)"). Lens E — audit-cycle execution is recurring (§8.5 "Continuous review post-launch... a second external cryptographic audit approximately 18–24 months after the first"); per-cycle developer load 80–200 hrs over 3–6 months for application, scoping, Q&A, remediation, re-verification, publication. §7.2 acknowledges "audit findings may trigger architectural-revisitation work the roadmap does not currently plan for."
- **What v1 loses:** Audit coverage of Shamir memory hygiene as an external attestation (vs as a Rust-core property check); audit coverage of trust-graph schema (vs as a source-review item). The pilot operates with the same cryptographic correctness assurance level for the two surfaces that matter most at pilot scale.
- **What v1 gains:** Audit budget effectively doubles per-component (same $15–30K against narrower scope); per-cycle developer prep cost drops; D0011's contingency-mode scope becomes the v1 baseline rather than the contingency.
- **Recommendation:** Narrow pre-pilot audit scope to COSE_Sign1 envelope construction + recovery-flow cryptographic operations. Shamir hygiene and trust-graph schema are handled via Rust-core property tests + source review. Update D0011 to reflect the narrowed default scope. Cross-section impact: tightens §6.1 pre-pilot gate; lowers §10.2 Phase B first-dollar threshold marginally; aligns with the §8.5 honesty that "Audit explicitly does not duplicate upstream-project audits."

### F6. Foundation incorporation (D0010) as 18–24-month milestone — defer indefinitely

**Lenses:** E (F5). Sole-lens finding but consequential and highest-leverage among Lens E's recurring-load cuts.

- **Current commitment:** §8.4 intends foundation incorporation 18–24 months post-v1. D0010 names it as placeholder pending legal consultation. §10.3 frames incorporation at $5–25K. §10.4 frames foundation overhead at $10–30K/yr recurring. D0009 names partner advisory authority pre-incorporation; the foundation board takes over post-incorporation per §8.4. D0012 Safe Harbor formalization commits to occur at incorporation.
- **Integrated evidence:** The foundation pathway is structured so that **every structural mitigation in the brief is conditional on it landing**: formalized Safe Harbor (D0012), board-bound governance, formal partner advisory authority (D0009), reviewer-honoraria operating model (§8.2). §10.7 explicitly names this as "structural mitigations remain at stated-intent posture" pre-incorporation. Lens E details the multi-year deferred coordination commitment: pre-incorporation legal consultation; fiscal-sponsor selection (2–6 months per §10.2); incorporation work ($5–25K Phase C-funded plus developer-side IP-assignment evaluation, board recruitment, governance-document review, jurisdiction-specific filing coordination); post-incorporation overhead $10–30K/yr at §10.4 budget but **does not budget developer time** for board-interface coordination, accounting oversight, regulatory-compliance review, fiscal-infrastructure operation. Successor-takeover viability under D0009 is very low: foundation incorporation is by definition a state transition that has not happened; the successor would inherit the same multi-year incorporation work plus the partner-advisory-authority renewal cycle.
- **What v1 loses:** None of the structural mitigations land at all — Safe Harbor remains preference, partner advisory authority remains partner-arranged, reviewer honoraria operate without foundation legal structure. §10.4 maintainer-comp aspiration loses the foundation legal scaffolding it currently leans on.
- **What v1 gains:** Removes the foundation-overhead-without-maintainer-comp posture from §10.4. Removes D0010 as placeholder commitment. Simplifies §10.3 Phase C unlock to "audit + honoraria" without foundation-incorporation costs. Phase D maintainer-comp aspiration moves materially closer to "preference" rather than "load-bearing for survival." Multi-year deferred coordination commitment is removed from the developer's working set.
- **Recommendation:** Reframe foundation incorporation as "conditional on project reaching operational scale that supports the foundation overhead" rather than as an aspirational milestone. Alternative: explicitly commit to operating under a fiscal sponsor indefinitely with foundation incorporation as out-of-scope-indefinitely (§6.2 pattern). Cross-section impact: §8.4 selection-criteria scope collapses; D0010 reframes from placeholder to "conditional, indefinite"; §10.3 Phase C scope narrows; §10.4 Phase D scope drops foundation-overhead line items; §10.7 stated-intent posture persists indefinitely rather than ending at incorporation; D0009 partner advisory authority becomes the permanent governance scaffold rather than the transition state.

### F7. v1.6 as a distinct release — collapse into v1.5 or push to v2

**Lenses:** E (F9). Sole-lens finding but high cross-section impact.

- **Current commitment:** §7.1 splits v1.5 and v1.6 with v1.6 covering deferred UX (multi-profile, in-app compelled-unlock flow, duress-wipe, §5.6 UX polish, voice/video, localization).
- **Integrated evidence:** Per-release engineering cycle has fixed overhead independent of scope: reviewer pool engagement; audit-coordination-window adjustment; release-engineering automation per-channel; release notes + CHANGELOG; transparency-log entry publication; pilot-or-user notification cycle. Per-release overhead floor: ~80–160 hrs regardless of scope. The v1.5/v1.6 split adds one full release cycle to the multi-year roadmap (~80–160 hrs one-time-but-recurring-coordination). The §§8/9 review F9 created the v1.5/v1.6 split for engineering-scope honesty (avoiding v1.5 timeline over-commitment); Lens E identifies that release-cycle overhead is fixed per cycle and the split adds a cycle for a scope cut that could be absorbed into the adjacent cycle.
- **What's at stake:** v1.6 contents — multi-profile UX, in-app compelled-unlock flow, duress-wipe, §5.6 UX polish, voice/video, localization — are real user-facing improvements. Collapsing into v1.5 makes the v1.5 scope larger (per §§8/9 F9, this was the original problem); pushing to v2 means the deferred UX waits for v2 platform expansion to land first.
- **What v1 loses:** Either v1.5 grows larger (recreating the §§8/9 F9 over-commitment) or v1.6 deferrals slip to v2 timing (~12–18 months post-v1.5 instead of ~6 months post-v1.5).
- **What v1 gains:** One full release cycle of ~80–160 hrs eliminated from the multi-year roadmap.
- **Recommendation:** Evaluate the trade explicitly — fewer releases at larger scope vs more releases at smaller scope — against the recurring-coordination load. If the §§8/9 F9 timeline-realism framing dominates, keep the v1.6 split and pay the per-cycle overhead. If the Lens E recurring-load framing dominates, push v1.6 contents to v2 (compelled-unlock flow + duress-wipe + multi-profile) as additive UX work bundled with the platform-expansion cycle. **Recommendation:** push v1.6 contents to v2, framing the release sequence as v1 → v1.5 (architecture completeness) → v2 (USB + iOS + the deferred UX previously called v1.6). This is the more conservative cut against recurring-coordination load. Cross-section impact: §6.2 v1.6 list moves to v2 list; §7.1 release sequence collapses to v1, v1.5, v2, v3, v4+; D0002 and D0004 references update; §10.3 Phase C UX-engineer funding remains tied to the merged release.

### F8. v3 mesh integration + multi-channel distribution count + iOS-at-v2 timing

**Lenses:** E (F2, F6). Sole-lens finding but consequential for multi-year sustainability.

This finding bundles three related cuts Lens E recommends together because the joint effect on the recurring-coordination floor is what matters.

**F8a. Cut v3 mesh integration (Meshtastic + MeshCore) to v4+ candidate.**

- **Current commitment:** §7.1 v3 (~18–24 months post-v1) adds mesh radio integration via Meshtastic and MeshCore. §10.5 lists hardware partnerships as v3+ aspiration; §6.2 lists them as v4+. Q25 names the inconsistency.
- **Integrated evidence:** §7.1 acknowledges "both communities have made breaking changes within 18-month windows." Adding v3 adds two parallel upstream-tracking loops on top of SimpleX + Briar + Tor + GrapheneOS — Lens E estimates ~40–80 hrs/yr recurring. §8.6 contains no partner category for mesh-radio communities; partner outreach extension would be required. v3 is conditional on funding §10.8 explicitly does not promise.
- **Recommendation:** Cut v3 from the committed roadmap. Reframe as v4+ candidate "if mesh-community partnerships emerge and Phase D funding supports the engineering scope." Eliminates two parallel upstream-tracking loops and removes the §6.2/§10.5 inconsistency Q25 names.

**F8b. Reduce v1 multi-channel distribution to F-Droid + Accrescent only.**

- **Current commitment:** §5.5:516 commits to F-Droid, Accrescent, GitHub releases, a Tor onion service operated by the project, and offline signed images. §6.1:609 narrows to "F-Droid, Accrescent, and direct download from a project-controlled domain." The inconsistency between §5.5 and §6.1 is itself an F17 minor finding.
- **Integrated evidence:** Lens E F6 — each distribution channel has channel-specific release engineering and ongoing operation. F-Droid (4–8 hrs/release), Accrescent (2–6 hrs/release), GitHub (1–2 hrs/release), Tor onion service (recurring infrastructure operations — hidden-service key management, onion-address rotation policy, uptime monitoring, on-call — outside §4.2 minimal-project-operated-infrastructure framing), offline signed images (4–12 hrs/release + partner-mediated distribution). Lens D F10 supports: confirm §6.1's narrower scope and defer Tor onion + offline images. Lens B F12 supports: F-Droid + Accrescent is sufficient for §5.5 "multi-channel cross-check" because the two platforms have independent infrastructure.
- **Recommendation:** Reduce to F-Droid + Accrescent only. Cut self-operated Tor onion service from v1 (inconsistent with §4.2). Cut offline signed images from v1 distribution-infrastructure commitments; the facilitator-mediated USB hand-delivery to pilot users per §6.1:601 is operational practice, not committed distribution infrastructure. Saves ~50–100 hrs/yr recurring; restores §4.2 consistency.

**F8c. Defer iOS to v3+ rather than v2.** (Lens E alternative framing.)

- **Current commitment:** §7.1 v2 (~12–18 months post-v1) includes iOS support.
- **Integrated evidence:** Lens E — iOS introduces a parallel platform-coordination commitment one release earlier; §7.1:713 itself names iOS upstream dependencies (App Store policies for Tor-integrating apps; iOS code-signing posture not native fit for Sigstore; Briar iOS unavailability) the project does not control. §7.1:713 also acknowledges "v2 iOS therefore serves a meaningfully different (and lower) threat tier than v1's."
- **Recommendation:** Lens E flags this but does not strongly insist; the case for cutting v3 is stronger than for deferring iOS. **Decision: keep iOS at v2** if author judges iOS audience-reach as material to the project; the platform-coordination cost is real but is a one-platform additive load, not a parallel-protocol-loop addition. This is the cut to revisit only if F8a (v3 cut) is rejected.

**Joint recommendation for F8:** apply F8a + F8b; treat F8c as optional. Together these eliminate two parallel upstream-tracking loops (Meshtastic + MeshCore), two self-operated infrastructure components (Tor onion + offline-image pipeline), and ~90–180 hrs/yr recurring coordination.

---

## Consensus simplifications (2+ lenses agree to simplify, not eliminate)

### F12. UnifiedPush distributor-selection UX — ship v1 polling-only, defer to v1.5

**Lenses:** A (F7), B (F8, defensible cut), D (F7).

- **Current commitment:** §5.4:480 and §6.1:605 ship v1 with push notifications off by default and polling at user-configurable intervals (default 15 minutes), plus battery-aware polling-loop implementation, UnifiedPush distributor-selection UX, and opt-in flow during provisioning.
- **Integrated evidence:** Lens A — push is off by default at v1; the brief itself names v1.5 as the moment to revisit (§5.4:480); building the opt-in path in v1 is paying for a feature whose default the brief has not committed to. Lens D — full UnifiedPush distributor-selection UX + battery-aware polling implementation is calibrated for broader-release where users routinely opt in. Lens B — UnifiedPush integration is not load-bearing for v1; polling-only is a coherent v1 posture and arguably more consistent with §4.2 minimal-infrastructure principle (UnifiedPush distributors are third-party metadata channels per §5.4:478, even when self-hosted).
- **Recommendation:** Ship v1 polling-only. Defer UnifiedPush opt-in path to v1.5 when pilot feedback exists. The architectural slot for push is preserved per §6.4. Pilot users requiring active push are managed by the facilitator on a per-user basis through the in-person provisioning ceremony.
- **Cross-section:** §5.4; §6.1; §6.4 forward-compat preserved; pilot-feedback gate per §5.4:480 unchanged.

### F15. Reviewer-pool 18-month rotation cadence — softer at volunteer baseline

**Lenses:** D (F2), E (F3 partial). Applies only if F4 above (full pool deferral) is rejected.

- **Current commitment:** §8.2 18-month rotation cadence with overlap. 5+ pool, 3-of-5 threshold.
- **Integrated evidence:** Lens D — rotation cadence calibrated to a foundation operating quarterly releases with honoraria; at volunteer baseline median 4–6 month cadence per D0008, the rotation cycle's compounded coordination cost exceeds the marginal security gain. Reviewer fatigue at 3–4 releases/cycle is materially different from reviewer fatigue at 6 releases/cycle. Lens E — at 5+ pool and 18-month rotation, at least one reviewer transition per 3–4 months on average plus overlap onboarding time; per-transition load 12–30 hrs.
- **Recommendation if F4 is rejected:** At volunteer baseline, commitment is "reviewers may rotate at their own initiative; the project does not impose a rotation cycle." Alternatively, extend rotation to 36 months from 18, halving rotation-cycle coordination load. Surface in §10.4 explicitly as a Phase D operational cost (currently §10.4 budgets honoraria but not coordination). Defer the imposed rotation cadence to Phase C honoraria-funded operations when quarterly cadence is feasible and the rotation cycle's coordination cost is funded as partner coordination.

### F19. Upstream-tracking and witness-pool-management cost — name as §10.4 line items

**Lenses:** D (P3, F5, F6, F8), E (P5).

- **Current commitment:** §10.4 enumerates partner coordination and audit coordination as unenumerated operational load; does not enumerate upstream-tracking (SimpleX, Briar, Tor PT, GrapheneOS-Pixel, optionally Meshtastic+MeshCore, PQ) or witness-pool-management ongoing cost.
- **Integrated evidence:** Lens D — upstream-dependency surface ongoing cost is acknowledged in §9.1/9.2 but not budgeted in §10.4. §10.4's "unenumerated operational load" mentions partner coordination and audit coordination but does not enumerate upstream-tracking. Lens E — the architectural-side cause of §10.4's "every contributor except the engineer-operator" framing is the recurring-coordination floor; the brief should pair §10.7's failure-mode honesty with §6/§7's scope honesty.
- **Recommendation:** Add explicit §10.4 line items: "upstream-tracking (SimpleX, Briar, Tor pluggable transports, GrapheneOS-Pixel, post-quantum standardization)"; "witness-pool management ongoing (recruitment, monitoring, rotation)"; "test infrastructure maintenance (property-based test suite evolution, fuzzing harness maintenance, differential-test-against-SimpleX upstream tracking)"; "reviewer-pool coordination (recruitment, onboarding, per-release attestation coordination, rotation cycles)" if F4 not adopted. No architectural change; the simplification is honest cost-naming.

---

## Disagreements between lenses

These are components where the lenses diverge. Surfacing the disagreement is the value; the author decides based on which lens's framing dominates.

### F9. §5.2 cascade quarantine + 90-day stale-flag escalation

- **Lens A (F1):** Cut. Two distinct path-computation modes (soft vs. hard), per-attestation timer state surviving app restarts/reinstalls, three-branch quarantine-decision UX, audit coverage on the 90-day clock's correctness, all to defend a cascade-laundering attack that at pilot scale (10–15 users, developer-as-facilitator) the developer can close operationally through direct contact. The cascade-laundering attack §5.2:374 cites is real, but the laundering threat presupposes a population large enough that the user-re-attestation channel is the only feasible response. Ship v1 with **one** revocation operation type (the hard "key compromise" form); drop attestation withdrawal and the 90-day stale-flag escalation; bring withdrawal + cascade + escalation back in v1.5.
- **Lens B (F4):** Keep all five operation types and cascade semantics — load-bearing for §3 threat tier. The withdrawal vs revocation split is what closes the cascade-laundering attack (§5.2:396); removing it weakens the trust-graph security model in a way the §3 threat tier cannot tolerate.
- **The disagreement:** Lens A treats the cascade-laundering attack as operationally closable at pilot scale via the developer-as-facilitator backstop. Lens B treats the cascade-laundering attack as a §3 threat-tier surface that must be cryptographically closed regardless of pilot-scale operational substitutes, because the architecture is shipping for the §2.2 audience tier, not the §6.3 pilot specifically.
- **Resolution framing:** This is a question about whether the v1 architecture is calibrated to (a) the pilot audience the developer can directly support, or (b) the §2.2 audience tier even if v1 pilot scale does not reach that tier. The brief's §6.1 framing ("smallest cut of the architecture that delivers a defensible product to the v1 audience") nominally supports (a); the §4.3 differentiation framing (Cairn as integration for the threat tier) nominally supports (b). The author's call.

### F10. §5.3 pre-shared peer challenges + 48-hour delay-and-confirm

- **Lens A (F2):** Cut the 48-hour delay; ship v1 with pre-shared challenges only. The challenge alone closes the unlock-then-impersonate chain at the cost the threat tier cares about (adversary needs material _not on the device_). §4.3:307 acknowledges "the chain remains achievable for a continuous-control adversary who can hold the user 48 hours and extract per-peer challenges from on-device storage" — the 48-hour window does not defeat the named threat tier on its own merits. At pilot scale, recovery events will be visible to the developer-facilitator in real time anyway.
- **Lens B (F11):** Keep both. §5.3:440 layered-resistance framing depends on both: challenges defend against impersonation (user-was-not-the-one-asking case); the cooling-off window defends against continuous-control coercion (user-asked-while-coerced case). Cutting either reduces the layered resistance to a single layer.
- **The disagreement:** Same shape as F9. Lens A treats the continuous-control coercion threat as either residual (§4.3:307 acknowledges) or operationally closable at pilot. Lens B treats both layers as necessary for the layered-resistance property §5.3:440 names.
- **Resolution framing:** This is a question about how much defense-in-depth v1 should commit to versus deferring the deeper layer to v1.5. The brief's §4.3:307 honesty about the residual surface is the Lens A footing; the §5.3:440 framing of layered resistance is the Lens B footing. The pilot-scale-vs-broader-tier framing from F9 applies similarly here.

### F11. §5.5 long-lived APK key + per-release Sigstore identity dual-signing

- **Lens A (F8):** APK key non-cuttable (Android requires it). Cut Sigstore identity-signing layer; v1 ships long-lived APK key + reviewer attestations in Sigsum. Removes OIDC operational hardening (§5.5:510 hardware key, alerts on issuance, regular Rekor audit), removes U.S. legal-process trust surface explicitly named in §5.5:510, removes Rekor monitoring infrastructure, removes ~one trust root from §3.4 v1 enumeration.
- **Lens B (F5):** APK key non-cuttable. Sigstore-per-release signing is the cuttable layer; defensibly v1.5 with named tradeoffs. Argument against deferral: §4.3:309 differentiation framing names "Sigstore identity-based per-release signing on top of the long-lived APK key" as part of the architectural differentiation. Argument for deferral: reviewer-pool Sigsum attestations are already the operative transparency anchor; the second layer's value is partially the forward-compatibility property the brief would gain by waiting until OIDC jurisdiction question (Q24) resolves.
- **The disagreement:** Both lenses agree Sigstore is the cuttable layer; both lenses surface the OIDC trust placement as the trade. Lens A treats the v1 cut as cleanly correct; Lens B presents it as a defensible call with named tradeoffs.
- **Resolution framing:** This is a question about whether v1 needs the second transparency anchor (Sigstore-via-Rekor) in addition to reviewer attestations in Sigsum. If F4 above (reviewer-pool deferral) is adopted, Sigstore-via-Rekor becomes the only release-attestation layer in v1, which inverts the framing: Sigstore becomes load-bearing for v1, and the OIDC trust placement is unavoidable. **Consequence:** F4 and F11 interact. The author should resolve F4 first; if F4 adopts the deferral, F11 becomes "keep Sigstore as v1 release-attestation layer with OIDC operational hardening." If F4 is rejected, F11 becomes a clean cut.

### F13. §5.1/§6.4 capability-token scope vocabulary

- **Lens A (F5):** Ship v1 with all-or-nothing capability tokens. At v1 single-device-per-identity per D0007, the scope mechanism is doing no work — the same device that sends messages also signs trust-graph operations and receives recovery shares. The scope distinction protects nothing v1 has; post-extraction defense is operational-identity revocation through the trust graph, not scope distinction. Reintroduce scope strings in v2 when USB form factor requires the distinction.
- **Lens B (F9):** Keep. A closed enumeration (single boolean per device, or a fixed set of permissions) cannot express the v1 scope vocabulary without giving every device every permission, which defeats the scope-bounded property §5.1:343 commits to: "a device with a `messaging-send` token cannot issue trust graph attestations even if its key material is fully extracted by forensic tooling." This is a v1 security property, not a forward-compatibility property.
- **The disagreement:** Lens A: at v1 single-device, the device that has been forensically extracted _also has the `trust-graph-attest` token_; the scope distinction does no v1 work. Lens B: the scope-bounded property is the v1 security property even at single-device, because forensic extraction is the v1 threat surface.
- **Resolution framing:** This is a question about whether §5.1:343's named v1 security property ("compromised device cannot exceed token scope") is genuinely operative at v1 single-device, or whether it is a v2 multi-device property dressed up as a v1 property. Lens A's argument is stronger at the single-device-per-identity layer; Lens B's argument is stronger at the schema-design layer (a closed enum is a one-way ratchet that v2 cannot easily reverse). **Recommendation:** keep arbitrary scope strings (Lens B); the cost vs closed-enum is small. But document explicitly that the scope-bounded property is the v2 multi-device security property the v1 schema preserves, not a v1 single-device security property — closing Lens A's framing gap honestly.

---

## Components correctly retained (all lenses agree are load-bearing)

The simplification analysis converges on a defensible v1 architecture core. These components survive scrutiny across all five lenses; the author should be confident in retaining them.

- **§5.1 three-tier identity model (master / operational / device).** Lens A retains; Lens B (F10) explicitly: "the three-tier model is the simplest construction that delivers (master cold + operational rotatable + device scope-bounded)." Lens C (F6) treats it as Cairn's integration value above SimpleX. Lens D and Lens E do not contest. The §5.1:345–351 alternatives discussion (single rotatable identity, HD derivation, threshold signatures for daily operation) holds.
- **§5.2 trust graph as a structural commitment** (with disagreements above on operation-type count and stale-flag escalation). All five lenses retain the graph structure itself; Lens C (F3) explicitly names the cascade-quarantine semantics as "genuinely novel and audience-serving for users whose threat tier includes post-compromise attestation issuance — a real attack on Briar's model that §5.2 correctly identifies."
- **§5.3 social recovery via Shamir-among-peers** (with disagreement above on whether both peer-verification layers ship at v1). All five lenses retain the recovery model. Lens C: alternative comparators (Threema-style centralization, Tails-style no-persistent-identity) are not appropriate substitutes for the §2.2 audience.
- **§5.4 SimpleX as v1 messaging substrate.** All five lenses retain. Lens C (F6) explicitly: "SimpleX's identifier-less queues are the metadata-protection property §3.3 requires."
- **§5.5 APK signing key.** Lens A and Lens B explicitly: non-cuttable (Android requires it).
- **§5.5 Sigsum integration for trust-graph operations and release log.** Lens D (F5) accepts with cost-visibility; Lens B (F6) keeps architecturally with sharper acknowledgment of v1 ship-or-degrade decision; Lens A does not contest. The Sigsum integration is what makes the §4.3 public-audit property external rather than internal.
- **§5.7 Rust core + Kotlin UI per D0003.** Lens D (F8) accepts as proportionate at v1 with v1.5 cliff flagged for §10.3 contingency planning; not contested elsewhere. The security properties (`zeroize`, `secrecy`, `subtle`, typestate; D0003) are load-bearing for the §3.3 endpoint-surface threat model.
- **§6.1 Android-only / GrapheneOS-on-Pixel platform.** Not contested. The §6.2 indefinite-out-of-scope framing for non-Pixel Android holds.
- **D0002 no duress-profile concealment, D0005 peer-verification mechanism (with disagreement above on 48-hour delay layer), D0007 single-device-per-identity at v1, D0014 non-peer-recovery deferred.** Not contested.

The defensible v1 architecture core is therefore: three-tier identity + trust graph + Shamir social recovery + SimpleX-only messaging + Rust-core implementation + GrapheneOS-Pixel platform + long-lived APK signing + Sigsum integration + the existing scope decisions in D0002, D0004, D0005, D0007, D0013, D0014. **This is the v1 product the architectural commitments above defend.** Everything else in the brief is candidate for cut, simplification, or deferral; the consensus cuts (F1–F8) and the simplifications (F12, F15, F19) operate at the periphery of this core.

---

## Pattern observations: where is the brief over-engineered vs appropriately engineered?

**Appropriately engineered:** §5.1, §5.2 (operation-type semantics and cascade — disagreement about which ops to ship at v1, but the design is right), §5.3 (recovery flow — disagreement about both-verification-layers at v1, but the recovery model is right), §5.4 (SimpleX selection), §5.7 implementation language (D0003), §6.1 platform choice. These survive all five lenses without serious challenge to the core design.

**Defensibly engineered but with cuttable extensions:** §5.2 (issuer-cert-hash binding F14, retain-and-forward-unknown-operation-types F4 partial, stale-flag escalation F9 disagreement), §5.3 (48-hour delay F10 disagreement), §5.5 (Sigstore identity-signing F11 disagreement, multi-channel distribution F8b/F17), §6.4 (capability-token scope vocabulary F13 disagreement, property-based migration framework F3, multi-target build pipeline F2).

**Over-engineered for v1 audience:** §5.7 crash-reporting infrastructure (F1 — population-scale machinery at pilot scale), §6.4 multi-target build pipeline (F2 — forward-compat scaffolding for v2/v3 features §10.8 doesn't promise), §5.7 property-based migration framework (F3 — testing migrations that don't exist yet). All three are explicit consensus cuts.

**Over-committed for solo-developer multi-year sustainability:** §5.5 5+/3-of-5 recruited reviewer pool (F4 — recurring partner-coordination loop that compounds across releases), §8.4 foundation incorporation as 18–24-month milestone (F6 — multi-year deferred coordination commitment), §7.1 v3 mesh integration (F8a — two parallel upstream-tracking loops), §7.1 v1.6 as distinct release (F7 — per-cycle release overhead). All four are Lens-E findings; the cumulative effect on Phase D sustainability is the highest-leverage strategic question this review surfaces.

**Audit-scope over-committed:** §8.5/D0011 four-component pre-pilot audit scope (F5 — narrower contingency-mode scope is the defensible v1 default).

The strategic shape: the brief's §5 cryptographic-architecture work is largely correct; the brief's §6 and §8 forward-compatibility and operational commitments accumulate scope faster than the solo-developer-volunteer-baseline can absorb. The simplification opportunity is concentrated in §6.4 (forward-compatibility scaffolding), §5.5/§5.7 (release-security and crash-reporting infrastructure operating at population scale at pilot scale), §8.2/§8.4/§8.5 (operational commitments calibrated to funded foundation scale), and §7.1 (v3 + iOS + v1.6 release-cycle multiplication).

---

## Action plan

### A. Cuts to apply now (high-consensus, low-controversy)

These cuts are recommended by 2+ lenses with no contesting lens. The author should adopt them and update the brief accordingly.

- **F1 — Cut project-operated SimpleX crash-reporting queue from v1.** Updates §5.7, §6.1; restores §4.2 principle without exception. Add to D0004 (v1 scope cuts).
- **F2 — Cut multi-target build pipeline cross-compilation scaffolding from v1.** Updates §6.4; honest framing in §6.4:693–695 that v1 commits only zero-cost architectural commitments and defers v2/v3 build-system work to v2 absorbing that cost. Add to D0004.
- **F3 — Defer property-based migration test framework to v1.5.** Updates §5.7, §6.4. Schema-versioning fields ship in v1; migration framework lands with the first real migration in v1.5. Add to D0004.
- **F12 — Ship v1 polling-only; defer UnifiedPush distributor-selection UX to v1.5.** Updates §5.4, §6.1. Architectural slot preserved per §6.4. Add to D0004.
- **F17 — Reconcile §5.5 / §6.1 distribution-channel inconsistency.** Confirm §6.1's narrower scope; defer Tor onion + offline images to v1.5 per F8b. Editorial pass in §5.5.
- **F19 — Add explicit §10.4 line items for upstream-tracking, witness-pool management, test-infrastructure maintenance, reviewer-pool coordination.** Editorial pass in §10.4.

### B. Cuts to debate (split-lens findings the author should decide)

These cuts split the lenses or require the author's judgment on framing dominance.

- **F4 — Recruited 5+ reviewer pool as v1 critical path.** Lenses C and E recommend deferral to v1.5; Lens B recommends 2-of-3 / 36-month softening. The author's call depends on whether F-Droid's pipeline + reproducible builds at v1.5 is treated as the v1 critical path (Lens C framing) or whether the recruited pool is treated as the v1 critical path (Lens B framing). **This is the single highest-leverage cut in the review.** If adopted, materially changes §4.3 differentiation framing and §10.3 Phase C unlock conditions.
- **F5 — Narrow pre-pilot audit scope to COSE_Sign1 envelope + recovery-flow crypto only.** Lens D and Lens E both recommend; D0011's own contingency clause supports the narrowing. Modest controversy. Updates D0011.
- **F6 — Defer foundation incorporation indefinitely.** Lens-E sole finding but consequential. The author's call depends on whether foundation incorporation is treated as a Phase D structural commitment or as a conditional milestone. If adopted, D0010 reframes; §10.4 maintainer-comp aspiration moves materially closer to preference.
- **F7 — Collapse v1.6 into v1.5 or push to v2.** Lens-E sole finding. Recommendation: push v1.6 contents to v2. Conservative against recurring-coordination load. Updates §6.2, §7.1; references in D0002, D0004.
- **F8 — Cut v3 mesh + reduce v1 distribution to F-Droid + Accrescent + (optional) defer iOS to v3+.** Lens-E sole findings with Lens-B and Lens-D support on the distribution-channel narrowing. Recommendation: apply F8a (cut v3) + F8b (reduce distribution); skip F8c (keep iOS at v2). Updates §5.5, §6.2, §7.1, §10.4, §10.5; resolves Q25.
- **F9 — Cascade quarantine + stale-flag escalation.** Lens A vs Lens B disagreement. Author's call on pilot-scale vs §2.2-audience-tier framing.
- **F10 — Pre-shared challenges + 48-hour delay-and-confirm.** Lens A vs Lens B disagreement. Same framing as F9.
- **F11 — Sigstore identity-signing layer.** Lens A clean cut; Lens B defensible v1.5 with named tradeoffs. **Interacts with F4:** if F4 deferral adopted, F11 must keep Sigstore as v1 release-attestation layer. Resolve F4 first.
- **F13 — Capability-token scope vocabulary.** Lens A vs Lens B disagreement. Recommendation: keep arbitrary strings (Lens B); document scope-bounded property as v2 security property the v1 schema preserves, not a v1 single-device security property (closing Lens A's framing gap).
- **F14 — Issuer-cert-hash binding (9th field).** Lens A sole finding. Cut at v1; reintroduce in v1.5 with rotation flow completeness. Updates D0006, D0011 audit scope.
- **F15 — Reviewer-pool 18-month rotation cadence.** Lens D + Lens E. Applies only if F4 rejected. If F4 rejected, soften to volunteer-baseline "rotation at reviewer initiative; project does not impose cycle"; reintroduce 18-month cadence at Phase C honoraria.

### C. Cross-section consequences

The cuts touch the following decisions, open questions, and brief sections. The author should expect these changes as a cumulative consequence of adopting the action plan.

**Decision documents to update:**

- **D0004 (v1-scope-cuts):** absorb F1, F2, F3, F12, F14, F17. Major revision.
- **D0006 (cryptographic-envelope):** F14 (issuer-cert-hash deferred), F9 (operation-type-count disagreement-dependent), F13 (clarify scope-bounded property as v2). Moderate revision.
- **D0005 (peer-verification):** F10 disagreement-dependent. If Lens A framing dominates, defer 48-hour layer to v1.5. Moderate revision.
- **D0007 (multi-device):** F13 disagreement-dependent reference. Minor revision.
- **D0008 (volunteer-baseline-cadence):** F15 if F4 rejected. Minor revision.
- **D0009 (sudden-unavailability):** F6 — partner advisory authority becomes permanent governance scaffold rather than transition state. Moderate revision.
- **D0010 (foundation-jurisdiction):** F6 — reframe from "placeholder pending legal consultation" to "conditional, indefinite." Major revision.
- **D0011 (audit-budget-and-timing):** F5 (narrow scope), F14 (remove issuer-cert-hash from scope), F11 if F11 cut adopted (remove release-security stack scope). Major revision.
- **D0012 (researcher-safe-harbor):** F6 — if foundation deferred indefinitely, Safe Harbor formalization becomes "pursue when foundation lands, else remain published preference indefinitely." Minor revision.
- **D0013 (pilot-consent-exit):** F1 — pilot crash signals flow through D0013 partner-mediated channel. Minor revision to add the crash-feedback channel.

**Open questions affected:**

- **Q3 (funding strategy):** F4, F6 simplify Phase C unlock conditions. Q3 framing tightens.
- **Q5 (NGO partner outreach):** F4 deferral removes one recruitment gate from v1 ship; Q5 framing tightens around witness-pool only.
- **Q11 / Q24 (OIDC provider):** F11 if cut adopted, Q11 may resolve as "deferred to v1.5 alongside Sigstore identity-signing."
- **Q13 (volunteer-baseline operational ceiling):** F4, F6, F7, F8 materially change the recurring-coordination floor; Q13 framing tightens around the reduced floor.
- **Q14 (partner advisory authority):** F6 — D0009 partner advisory authority becomes the permanent governance scaffold rather than transition state; Q14 framing tightens.
- **Q15 (fiscal sponsor):** F6 — fiscal sponsor becomes Phase D steady state rather than 18–24-month transition. Q15 framing tightens.
- **Q16 (Safe Harbor template):** F6 — formalization timing becomes "if/when foundation lands, else indefinite." Q16 framing softens.
- **Q20 (self-funding runway disclosure):** the reduced recurring-coordination floor materially changes the runway arithmetic. Q20 framing should account for the post-cut floor.
- **Q25 (v3 hardware partnership timing):** F8a — v3 cut resolves Q25 by removing v3 from the committed roadmap.

**Brief sections affected:**

- **§1 Executive Summary:** F4 reframes the §4.3-quoted "fourth commitment" (release security) to acknowledge v1 release-security posture as Cairn-distinct-from-Signal-but-not-distinct-from-GrapheneOS. F6 reframes the foundation-incorporation language. F8a removes v3 from the committed roadmap language.
- **§2.2 Audience:** F18 — add Cairn-audience-not-served-by-Threema and Cairn-audience-not-served-by-Tails subsets explicitly.
- **§3.4 Trust roots:** F1 + F11 narrow the enumeration (removes OIDC provider, Rekor, possibly reviewer pool + reviewer onboarding toolkit + Sigsum witness pool depending on F4 resolution). F6 + F14 + F19 add the foundation-jurisdiction-deferred-indefinitely framing and the upstream-tracking trust-root acknowledgment.
- **§4.3 Differentiation:** F4 reframes the four-commitment integration to three-commitment integration + a Cairn-distinct-from-Signal-but-not-distinct-from-GrapheneOS release-security posture.
- **§5.2 Trust Graph:** F9, F13, F14 disagreement-dependent revisions.
- **§5.3 Recovery Model:** F10 disagreement-dependent revision.
- **§5.4 Communications Protocols:** F12 revision (drop UnifiedPush UX from v1).
- **§5.5 Updates and Release Security:** F4, F8b, F11, F17 revisions.
- **§5.7 Implementation:** F1, F3 revisions.
- **§6.1 What ships in v1:** F1, F2, F3, F12 revisions; F4-conditional ship-gate revision.
- **§6.2 What's explicitly deferred:** F1, F2, F3, F7, F12 additions; F8a v3 reframing.
- **§6.4 Forward-compatibility:** F2, F3, F14 revisions; the §6.4:693–695 honesty note expands to acknowledge the cuts.
- **§7.1 Release sequence:** F7 (v1.6 collapse), F8a (v3 cut), F4-conditional v1.5 reproducible-builds-+-F-Droid-attestation framing.
- **§7.2 Dependencies:** v1.6 / v3 references update.
- **§8.4 Path to foundation:** F6 reframing as conditional-indefinite.
- **§8.5 Audit and assurance:** F5 (narrow scope).
- **§9.4 Mitigations and monitoring:** trust-roots health report scope per Lens-E F8 narrowing if adopted.
- **§10.3 Phase C:** F4, F6 simplify the unlock conditions; F4 removes reviewer-honoraria operations as v1.5 ship-gate.
- **§10.4 Phase D:** F6 removes foundation-overhead line items; F19 adds explicit upstream-tracking + witness-pool-management line items.
- **§10.7 Funding risks:** F6 changes the "structural mitigations remain at stated-intent posture" framing from "ends at incorporation" to "persists indefinitely."

### D. New decision documents required

Two new decisions warrant their own documents given the substantive scope of the cuts.

- **D0015 — v1 release-security posture (if F4 deferral adopted).** Document the v1 release-security stack as developer Sigstore + Rekor + Sigsum release log + multi-channel distribution + F-Droid rebuild (when v1.5 reproducible builds land), with the recruited reviewer pool deferred to v1.5 alongside reproducible-builds + F-Droid integration. Record the §4.3 differentiation reframing and the Lens-C comparable-products evidence. Names the v1.5 unlock conditions for reintroducing the recruited pool.
- **D0016 — Foundation incorporation deferred indefinitely (if F6 adopted).** Reframe D0010 from "placeholder pending legal consultation" to "conditional, indefinite, pursued if/when project reaches operational scale that supports foundation overhead." Document the consequence for D0009 (partner advisory authority becomes permanent governance scaffold), D0012 (Safe Harbor remains published preference indefinitely), §10.4 (foundation-overhead line items removed), §10.7 (stated-intent posture persists indefinitely).

A third document may be warranted depending on disagreement resolution:

- **D0017 — v1 trust-graph operation-type and verification-layer scope (if F9, F10, F13, F14 cuts adopted).** Document which §5.2/§5.3/§5.1 layers ship at v1 and which defer to v1.5, with the named threat-tier-vs-pilot-scale framing decision. Updates D0005, D0006, D0007.

---

## Strategic note

This review's contribution is counter-pressure against a brief that defends every commitment. The brief's design discipline is strong; the brief's scoping discipline already cut substantively at D0004. The cuts above are the next round of scoping discipline — calibrated not to v1 engineering scope (which D0004 addressed) but to **recurring coordination load that compounds across v1 → v1.5 → v1.6 → v2 → v3**, which D0004 did not address.

The consensus cuts (F1, F2, F3, F12, F17, F19) are unambiguous wins; the author should adopt them. The split-lens findings (F4, F5, F6, F7, F8, F9, F10, F11, F13, F14, F15) are the structural questions about v1 architecture the project has not yet resolved; this review's framing of each disagreement is the input the author needs. F4 + F6 + F7 + F8 together are the highest-leverage strategic cuts: applied jointly, they shift §10.4's Phase D maintainer-comp aspiration from "load-bearing for survival" to "preference for higher throughput," which is the §1-and-§4.3-level reframing the brief's overall posture rests on.

The materiality assessment for the brief's framing: **yes**, if all consensus cuts plus F4, F6, F7, F8 apply. §1's "four-commitment integration" reframes to three commitments. §4.3's "substitutes the developer's single signing identity with a distributed trust set" reframes to "ships through the F-Droid pipeline that comparable products use" with the recruited-pool framing as v1.5 strengthening. §10.4's "every contributor except the engineer-operator" framing softens because the engineer-operator's coordination floor drops below the bandwidth a self-funded solo developer can sustain. §9.4's sunset trajectory becomes more recoverable because the deferred foundation work simplifies successor handover. §7.1's roadmap commits to fewer releases over a longer horizon, which is honest about the recurring-coordination realities §10.7 names. The brief's audience-serving architecture for users at the §3 threat tier does not change; what changes is the project's framing of its own posture, which the brief itself names as load-bearing for funder and partner trust (§8 introduction's register discipline).

---

## 250-word summary

This review consolidates five lens-specific adversarial simplification reviews into 19 findings (Critical 8, Significant 7, Minor 4). The top five most consequential cuts: **F1** (project-operated SimpleX crash-reporting queue — cut, restores §4.2 principle without exception); **F2** (multi-target build pipeline — cut, removes v1 engineering cost paid against v2/v3 features §10.8 doesn't promise); **F4** (recruited 5+ reviewer pool as v1 critical path — defer to v1.5 alongside reproducible-builds + F-Droid integration, the highest-leverage cut surfaced); **F6** (foundation incorporation as 18–24-month milestone — defer indefinitely, materially relieves Phase D sustainability); **F8** (cut v3 mesh integration to v4+ candidate + reduce v1 distribution to F-Droid + Accrescent only). Three disagreements worth surfacing: **F9** (cascade quarantine + stale-flag escalation: Lens A cut vs Lens B keep, framing-dependent on pilot-scale vs §2.2-audience-tier calibration); **F10** (pre-shared challenges + 48-hour delay: same shape as F9); **F11** (Sigstore identity-signing layer: cut cleanly per Lens A, defensible v1.5 with tradeoffs per Lens B; resolution interacts with F4). Components all lenses keep — the defensible v1 architecture core: three-tier identity + trust graph + Shamir social recovery + SimpleX-only messaging + Rust-core implementation + GrapheneOS-Pixel platform + long-lived APK signing + Sigsum integration. Recommended next steps: 6 consensus cuts to apply now (A); 11 split-lens cuts to debate (B); 10 decision-document updates and 2–3 new decision documents (C, D). **Materiality:** if all consensus cuts plus F4, F6, F7, F8 apply, §1's "four-commitment integration" reframes to three commitments, §4.3's release-security differentiator narrows, and §10.4's maintainer-comp aspiration shifts from "load-bearing for survival" to "preference for higher throughput."
