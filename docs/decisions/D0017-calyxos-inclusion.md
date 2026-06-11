# D0017 — CalyxOS inclusion at v1: GrapheneOS-only baseline retained; CalyxOS evaluation deferred to v1.x

**Status:** Accepted
**Date:** 2026-05-29

## Context

Q26 in [open-questions.md](../open-questions.md) surfaced the question whether CalyxOS should be added to v1's supported configuration alongside GrapheneOS-on-Pixel as the security baseline. The consolidated external-reads triage (`docs/archive/reviews/external-reads-consolidated.md` X10 / P3) elevated Q26's resolution timing from "after pilot evidence" to "before formal pilot recruitment" because partner-organization evaluation of v1 facilitation feasibility depends on knowing the device baseline; pilot-recruitment math is materially different under GrapheneOS-only vs GrapheneOS-and-CalyxOS scope.

This decision evaluates the four dimensions Q26 names: (a) which GrapheneOS-specific hardening properties Cairn depends on; (b) whether CalyxOS provides equivalent properties; (c) whether §3.4 trust-roots framing extends cleanly; (d) whether §5.5 release-security stack operates identically on CalyxOS.

## Decision

**v1 ships with GrapheneOS-only support. CalyxOS inclusion is evaluated for v1.x based on pilot evidence and on technical investigation deferred to post-pilot.**

The decision retains the prior v1 baseline rather than expanding it. The rationale and the operational consequences are documented below; reversibility is discussed in the Consequences section.

### Rationale for retaining GrapheneOS-only at v1

**Dimension (a): Cairn architecture dependence on GrapheneOS-specific properties.** Cairn's security architecture depends on the following platform properties:

- **Hardware-backed key storage via StrongBox or TEE.** Both GrapheneOS and CalyxOS run on Pixel hardware that includes the Titan M2 secure element supporting StrongBox; both can theoretically expose StrongBox-backed key storage to applications. This dimension is equivalent across the two OSes at the hardware layer.
- **Verified boot attestation.** GrapheneOS implements verified boot with attestation chains the user (and Cairn) can verify against Google's published boot-image attestation. CalyxOS implements verified boot but uses Google's stock locked-bootloader implementation on Pixel devices; CalyxOS's verified-boot attestation chain is materially different from GrapheneOS's and surfaces less granular state to applications. Cairn's tier-separated identity model in §5.1 depends on verified-boot-attestation properties to bound the reconstruction-window exposure; CalyxOS's verified-boot model provides equivalent bounds for the GrapheneOS-equivalent surface but not for the additional GrapheneOS-specific hardening (hardened malloc, sandboxed Google Play Services, exec-spawning hardening, MAC randomization persistence).
- **Sandbox hardening.** GrapheneOS ships hardened_malloc; CalyxOS does not. GrapheneOS ships exec spawning hardening; CalyxOS does not. GrapheneOS ships PaX-equivalent kernel hardening features (page-table protections; ASLR strengthening) that CalyxOS does not. These properties bound forensic-implant-on-device attack surfaces named in §3.3 Returned-after-seizure surface and §3.3 Endpoint surface. Cairn's bounded-window-exposure claim in §5.1 depends on the sandbox hardening as part of the "bounded as far as software can" framing; the bound is materially weaker on CalyxOS.
- **MicroG and Google Services integration.** CalyxOS ships with microG (a free-software re-implementation of some Google Play Services APIs) enabled by default for users who want app compatibility with apps depending on those APIs. MicroG re-introduces a Google-mediated trust placement that GrapheneOS specifically avoids. For Cairn at the §3 threat tier, microG's network behavior (signed connections to Google's services in some configurations) is itself a metadata channel adversary-correlatable to user activity. GrapheneOS's "no Google Services" baseline is materially preferable for this threat tier.

**Dimension (b): CalyxOS equivalence assessment.** Per the analysis above, CalyxOS provides equivalent properties for hardware-backed key storage but materially weaker properties for sandbox hardening and verified-boot attestation granularity, plus the additional microG-mediated trust placement Cairn's §3.4 trust roots framing would need to incorporate. The equivalence is partial: CalyxOS users could run Cairn with reduced security properties relative to GrapheneOS users, not equivalent properties.

**Dimension (c): §3.4 trust-roots framing extension.** Adding CalyxOS as a supported configuration would require §3.4 to enumerate CalyxOS-specific trust roots separately from GrapheneOS-specific ones. The two OSes' trust postures differ enough that "GrapheneOS-or-CalyxOS" is not a clean trust-root expansion — it is two distinct trust-root configurations. The brief would need to surface this honestly to users at deployment, explaining that their security properties depend on which OS they run, which is itself a configuration-management burden the v1 documentation scope does not absorb cleanly.

**Dimension (d): §5.5 release-security stack equivalence.** The Sigstore + Rekor + Sigsum + multi-channel distribution release-security stack operates identically on both OSes. APK Signature Scheme v3 verification, F-Droid client behavior, Accrescent behavior all work the same. This dimension does not differentiate the OSes.

### Why CalyxOS evaluation is preserved for v1.x

The decision is to retain GrapheneOS-only at v1 with a clear v1.x evaluation lane rather than to indefinitely reject CalyxOS inclusion. Reasoning:

- **Pilot evidence may surface CalyxOS-relevant cases.** The v1 pilot may include users in jurisdictions where GrapheneOS adoption is operationally riskier than CalyxOS adoption (the "more identifiable security choice" framing in the original Q26 context). If pilot evidence indicates significant population overlap, CalyxOS inclusion at v1.x becomes a higher-priority addition.
- **CalyxOS hardening may improve over multi-year horizons.** The technical gap analysis above reflects CalyxOS's posture as of 2026; the CalyxOS project may close some of the gaps in subsequent releases. The v1.x evaluation lane lets the decision be revisited against the then-current CalyxOS state rather than locked against the 2026 state indefinitely.
- **Audience-expansion calculus may shift under v1.5+ broader-release planning.** If §1.2 audience reframing under the consolidated triage S5 structural decision moves toward a deployable-population-first framing, the CalyxOS inclusion case becomes more pressing because CalyxOS materially expands the deployable population.

The v1.x evaluation lane is concrete: a follow-up Q26-successor question opens at v1 pilot completion that re-evaluates against the four dimensions above with pilot-evidence input and current-CalyxOS-posture input.

## Alternatives considered

**Option A — Add CalyxOS as v1 supported configuration alongside GrapheneOS.** _(Considered, rejected.)_ Would expand addressable population materially (per partner-organization external-reads triage P3 framing) but introduces (a) reduced sandbox hardening that weakens §5.1's bounded-window claim and §3.3's forensic-extraction surface; (b) microG-mediated trust placement that conflicts with the §4.2 minimal-project-operated-infrastructure principle's extension to user-side infrastructure; (c) configuration-management burden in user-facing documentation that the solo-developer v1 documentation scope cannot absorb cleanly. The audience expansion is operationally real but is purchased with a security-property reduction the brief would have to honestly document, which would itself complicate the audience-framing already under triage as S5.

**Option B — Make CalyxOS support a v1.x ship-when-ready item with explicit pilot-evidence dependency.** _(Considered, partially adopted.)_ The pilot-evidence-dependency framing is preserved as the v1.x evaluation lane; the difference from Option B's full position is that the v1.x evaluation does not commit to ship-when-ready timing — it commits to re-evaluation at v1 pilot completion with the option of v1.x or v1.5 addition depending on the evaluation outcome.

**Option C — Defer CalyxOS evaluation indefinitely as out-of-scope for any planned version.** _(Considered, rejected.)_ Closing the door on CalyxOS inclusion forecloses an audience-expansion lever the audience-reframing structural question (S5) may need. The brief is honest about the security-property tradeoff Option A makes; deferral preserves the option without committing to it.

**Option D — Re-scope v1 to include CalyxOS but explicitly document the security-property reduction.** _(Considered, rejected.)_ This is Option A with explicit honest framing. The honest framing is achievable, but the brief's commitment to single-OS architectural simplicity at v1 — which D0004 scope cuts and the §6.1 single-device-per-identity framing reflect — argues against introducing a configuration matrix at v1 ship. The configuration-management burden falls on partner organizations facilitating deployment as much as on the developer; partner-organization helpline operators would need to walk users through OS-selection tradeoffs that v1 documentation does not equip them to handle.

## Consequences

### Section 2.2 update

Section 2.2's BYOD/Pixel paragraph references Q26 resolution; the paragraph now reflects D0017's decision. The "Pixel-affording, GrapheneOS-tolerant, second-device-capable" audience precondition framing remains; Q26's v1.x evaluation lane is named so partner organizations and pilot users see the trajectory.

### Section 3.4 update

Section 3.4 trust roots remain GrapheneOS-only at v1; the v1.x evaluation lane is named in the trust-roots framing so the brief is honest that future expansion may add CalyxOS-specific trust placements.

### Open-question Q26 update

Q26 is **resolved** by this decision. The v1.x evaluation lane is tracked as a successor question (Q26.1 or as a separate v1.x evaluation item, depending on the brief's question-numbering convention) and is opened formally at v1 pilot completion.

### Partner-conversation framing

Q5 partner-organization conversations now have a clear v1 device baseline answer: "v1 is GrapheneOS-on-Pixel only; CalyxOS evaluation is on the v1.x evaluation lane subject to pilot evidence." Partner organizations evaluating facilitation can act on this answer immediately rather than evaluating against an open question.

### Reversibility

The decision is **fully reversible at low cost**: if v1 pilot evidence surfaces CalyxOS-relevant cases (users in jurisdictions where GrapheneOS adoption is the operationally risky choice; users for whom the audience-expansion calculus has materially shifted), the v1.x evaluation lane opens with the four-dimensional analysis above as the substrate. CalyxOS addition at v1.x requires:

- Re-evaluation of dimension (a)/(b)/(c)/(d) against the then-current CalyxOS posture
- Configuration-management documentation for users selecting between OSes
- Trust-roots framing update in §3.4 to enumerate CalyxOS-specific trust placements
- Pilot-evidence-informed audience-framing update if §1.2 has by then absorbed the S5 structural decision

The v1.5 broader-release evaluation (per §7.1) is a natural moment for re-evaluation if it has not occurred earlier.

## References

- [open-questions.md](../open-questions.md) Q26 — the question this decision resolves
- [docs/archive/reviews/external-reads-consolidated.md](../archive/reviews/external-reads-consolidated.md) X10 / P3 — the elevation of Q26 resolution timing to pre-pilot-recruitment
- [docs/design-brief.md](../design-brief.md) §2.2 — Pixel-affordability precondition framing
- [docs/design-brief.md](../design-brief.md) §3.4 — trust roots
- [docs/decisions/D0004-v1-scope-cuts.md](D0004-v1-scope-cuts.md) — the single-OS architectural simplicity framing this decision reinforces
- GrapheneOS: <https://grapheneos.org>
- CalyxOS: <https://calyxos.org>
