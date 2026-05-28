# Sections 6 and 7 Adversarial Review — Consolidated Findings

**Date:** 2026-05-28
**Source:** Five parallel sub-agent reviews, distinct lenses (scope discipline, roadmap credibility, dependency realism, pilot-to-broader-release gates, solo-developer feasibility).
**Raw findings:** 56 across reviewers (Critical 19, Significant 27, Minor 10). After deduplication and theming: 24 consolidated findings below.
**Companion to:** [design-brief.md](design-brief.md) Sections 6 and 7, with cross-references to Sections 3–5, Section 8, Section 10, and the decision documents.

---

## Executive summary

Across all five lenses, the consensus posture is that §§6 and 7 read as a confident, internally-coherent product plan that does not import the conditionality the rest of the brief carefully establishes. §6.1 is a clean enumeration of v1 deliverables, §6.2 is a clean enumeration of deferrals, §6.3 is a descriptive pilot plan, §6.4 is a forward-compatibility checklist, and §7 is a five-release roadmap with calendar windows on every release. None of these surfaces — at the point a §§6/7-first reader encounters them — propagates the gating from §8.4 (foundation incorporation timeline), §8.5 (no-skip-the-audit posture), §8.6 (partner intent-not-commitment register), §10.1 ("as available" volunteer cadence with no calendar commitment), §10.2 (Phase B as pilot gate), §10.3 (Phase C as broader-release gate), §10.7 (reviewer-pool erosion), or D0008 (4–6 month median release interval, not quarterly).

The three highest-consequence patterns are convergent across lenses. First, §6.1 silently absorbs the specialist roles §8.1 names as separately-funded — cryptographic engineer, UX engineer, documentation/community — into one developer's plate, while §6.3 commits that same developer to in-person facilitation throughput for 10–15 users in parallel with v1.5 implementation. Second, §7's calendar-anchored windows ("target ~6–9 months post-v1") directly contradict §10.1's explicit refusal to commit to a calendar schedule and §10.8's "what unlocks what, not when" framing; v1.5 timing sits before the pre-beta audit, Phase C funding, and foundation incorporation that §10 and §8 establish as preconditions for everything v1.5 promises. Third, §6.1 commits to deliverables whose machinery §8.2/§8.5/§8.6/§9.1 simultaneously frame as conditional on Q3 (funding) and Q5 (partner outreach) — most acutely the reviewer pool whose absence blocks every release.

The credibility risk is not in the substance of §§8 and 10 (which have been tightened) or in the architectural ambition of §5 (which is defensible). It is in §§6/7 inheriting none of those qualifications inline, so that a funder, partner, or pilot user reading §§6/7 first acquires a more concrete, calendar-anchored, less-conditional project than the brief actually commits to. Fixing this is largely prose work, but it is structural prose work: the brief has two registers operating in parallel, and §§6/7 currently carry the wrong one.

---

## Patterns

Ten patterns emerge that span multiple lenses and matter more than any single finding:

**P1. §§6/7 inherit no qualifications from §§8, 10, or 9 — the conditional register stops at the section boundary.** Caught independently by Roadmap-Credibility, Dependency-Realism, and Release-Gates lenses. Every reviewer-pool gate, witness-pool gate, partner-collaboration dependency, funding gate, audit gate, and foundation-incorporation gate that §§8 and 10 establish is invisible in §§6/7. A §§6/7-first reader (the natural skim path for "what is v1?" and "what comes next?") forms a deliverable-focused model; the actual model — architecture _and_ funding _and_ audit _and_ incorporation _and_ partner outreach, each independently gating — is recoverable only by cross-reading. Roadmap-Credibility P2 and Release-Gates P1 are the same observation.

**P2. §6.1 is a press-release summary of §5, not the §5 v1 spec.** Caught by Scope-Discipline lens, supported by Solo-Feasibility. The recurring pattern is that §5 commits multi-month engineering for v1 (COSE_Sign1 envelope, cascade quarantine, key-rotation flow, rollback resistance, UnifiedPush polling, crash-reporting infrastructure, three persistent stores with property-based migration tests, Tor pluggable-transport tracking), and §6.1 either names it in one phrase or omits it. The discipline §6 advertises (Briar deferred, CRDT dropped, UX narrowed, single-platform) is real, but the resulting v1 is still substantially larger than §6.1's bulleted scope suggests. Findings F4, F8, F9, F11, F12, F13, F18 are all instances.

**P3. §7's "target ~X months post-v1" calendar language is the form §10.1 explicitly says the project will not use.** Caught most sharply by Roadmap-Credibility lens, echoed by Release-Gates and Solo-Feasibility. §10.1 line 1024 disavows month-denominated commitments because the volunteer baseline cannot back them; D0008 records 4–6 month median release intervals as "as quorum forms," not as planned cadence. §7.1 then stamps calendar windows on every release. The two sections do not describe the same project. The fix is mechanical (replace each window with a phase-gate reference) but the framing in §7 currently undermines §10's careful funding-stance honesty. Findings F2, F5, F14 instances; pattern noted in F7's split-honesty observation.

**P4. §6.1 commits to what §8 frames as conditional.** Caught by Scope-Discipline and Dependency-Realism. Reviewer pool, Sigsum witnesses, partner-collaborative documentation, and pre-pilot audit are presented as v1 deliverables in §6 while §8.2, §8.5, §8.6, and §9.1 frame them as conditional on Q3 (funding) and Q5 (partner outreach). A funder reading §6 sees deliverables; the same funder reading §8/§9 sees risks. Findings F4, F8, F9, F19.

**P5. Solo-developer specialization breadth is the central feasibility question §6.1 doesn't answer.** Caught most sharply by Solo-Feasibility lens. §6.1 bundles Rust crypto core, Android Keystore/StrongBox integration, Kotlin UI with security-calibrated UX, UniFFI binding maintenance, reviewer-pool coordination, and six documentation artifacts onto one developer's plate. §8.1 names three of these as separately-funded specialist roles and estimates §5.6 UX alone at 30–50% of v1 effort. The contradiction is unresolved. Findings F3, F11, F17, F22.

**P6. v1.5 timing precedes every condition v1.5 presupposes.** Caught by Roadmap-Credibility, Release-Gates, and Dependency-Realism. v1.5 "~6–9 months post-v1" sits before pilot completion (6 months), before the pre-beta audit ($60–150K, Phase C), before foundation incorporation (~18–24 months post-v1 per §3.4 and D0010), before reviewer honoraria fund, and before §10's named structural mitigations (formalized Safe Harbor per D0012, board-bound governance per §8.4, formal partner advisory authority per D0009) activate. §7 presents this as engineering sequencing; it is funding-, audit-, and governance-gated. Findings F2, F5, F14, F15.

**P7. §6.4 forward-compatibility framing hides v1 engineering as "design choices."** Caught by Scope-Discipline. Several items in §6.4 read as zero-cost architectural commitments when they are in fact dedicated v1 engineering line-items: protocol-versioning enforcement across every signed message, property-based migration test framework, multi-artifact build pipeline, schema-level multi-device support for v2 that the v1 schema must accommodate. §6.4 line 656 explicitly calls multi-target build "mostly engineering hygiene rather than a feature commitment" — minimizing real architectural work. Findings F11, F23.

**P8. v2, v3, and v4 commitments rest on partner relationships and funding the brief admits are unsecured, but §7 borrows v4's honest framing only for v4.** Caught by Roadmap-Credibility. §7.1 line 708 explicitly says "the project will reach v4 only if the prior versions have delivered enough operational value to attract the funding and organizational commitment." The same logic applies to v1.5 (Phase C), v2 (team growth per §9.1, Apple-side feasibility, Briar iOS unavailability), and v3 (Meshtastic/MeshCore partnerships, hardware ambiguity between §6.2 v4+ and §10.5 v3+), but §7 attaches the framing only to v4. Findings F6, F15, F16, F20.

**P9. The v1.5/v1.6 split is a credibility-honest move; the calendar windows on the split are not.** Caught by Roadmap-Credibility. The §7.1 line 670 rationale for splitting v1.5 explicitly cites the §§8/9 review F9 finding that the original v1.5 was 9–15 months of solo-developer work; the split itself is the right correction. But the new v1.5 ("~6–9 months post-v1") and v1.6 ("~12–15 months post-v1") windows are smaller versions of the same wishful framing: month-anchored at the volunteer baseline that §10.1 says cannot back month-anchored commitments. The split addressed scope realism but not cadence realism. Finding F2 (subfinding F7 in Roadmap-Credibility lens).

**P10. §6.2/§7.1 disagreements about v1.5 contents and hardware-partnership timing are unresolved.** Caught by Scope-Discipline and Dependency-Realism. §6.2 lists duress-wipe in v1.5; §7.1 moves it to v1.6. §6.2 lists hardware partnerships as v4+; §10.5 lists them as v3+ aspiration; §7.1 commits a v3 mesh release that needs the hardware path resolved. The boundaries between v1.5/v1.6/v2/v3/v4+ are sliding without re-baselining. Findings F18, F20.

---

## Severity Distribution

- **Critical (F1–F8):** 8 findings. Commitments materially undercommunicated against §5 spec or §10 conditionality; framings that contradict §10's explicit register.
- **Significant (F9–F19):** 11 findings. Unstated assumptions, missing acknowledgments, mechanisms specified but not budgeted or sequenced.
- **Minor (F20–F24):** 5 findings. Prose-level imprecision, smaller gaps, internal-consistency cleanups.

---

## Consolidated findings table

| ID  | Severity    | Lens(es)                                               | Short title                                                                                                 | Location                         |
| --- | ----------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- | -------------------------------- |
| F1  | Critical    | Roadmap-Credibility, Release-Gates, Solo-Feasibility   | §7.1 calendar windows contradict §10.1 "as available" register                                              | §7.1:666-674                     |
| F2  | Critical    | Roadmap-Credibility, Release-Gates, Dependency-Realism | v1.5/v1.6 timing precedes audit, Phase C, foundation, reviewer-honoraria                                    | §7.1:668-670, §6.2:589           |
| F3  | Critical    | Solo-Feasibility, Scope-Discipline                     | §6.1 absorbs §8.1's three specialist roles into one solo developer                                          | §6.1:567-583                     |
| F4  | Critical    | Scope-Discipline, Release-Gates, Dependency-Realism    | Reviewer-pool, Sigsum witnesses, partner documentation: v1 deliverables vs §8 conditional intent            | §6.1:579, §6.1:581               |
| F5  | Critical    | Release-Gates, Roadmap-Credibility                     | §6.3 pilot framing elides pre-pilot audit gate (§8.5/§10.2) and Phase B funding gate                        | §6.3:624-638                     |
| F6  | Critical    | Roadmap-Credibility, Dependency-Realism                | v2 and v3 framed declaratively despite unsecured partner/funding/team-growth dependencies                   | §7.1:672-674, §7.2:684-688       |
| F7  | Critical    | Release-Gates                                          | §7 never references foundation incorporation as gate for broader-release structural mitigations             | §7.1, §7.2                       |
| F8  | Critical    | Scope-Discipline                                       | §6.1 silently omits COSE_Sign1 envelope, Sigsum integration, rollback resistance, key-rotation flow         | §6.1:573-579                     |
| F9  | Significant | Scope-Discipline                                       | §6.1 commits to Sigsum integration without naming witness-pool precondition                                 | §6.1:573                         |
| F10 | Significant | Roadmap-Credibility                                    | "9–12 months from start of full-time development" presumes uncommitted full-time mode                       | §7.1:666                         |
| F11 | Significant | Scope-Discipline, Solo-Feasibility                     | §6.4 forward-compatibility commitments smuggle multi-month engineering into v1                              | §6.4:640-656                     |
| F12 | Significant | Scope-Discipline                                       | Cascade quarantine, stale-flag escalation: v1 trust-graph work named only as operation types                | §6.1:573, §5.2:374-380           |
| F13 | Significant | Scope-Discipline                                       | Rollback resistance, push-notification posture, crash-reporting infrastructure: v1 per §5, absent from §6.1 | §5.5:492, §5.4:456-458, §5.7:558 |
| F14 | Significant | Roadmap-Credibility                                    | §7.1 v1 audience line ("pilot users running GrapheneOS") permissive vs §6.3 10–15 users                     | §7.1:666 vs §6.3:628             |
| F15 | Significant | Roadmap-Credibility, Dependency-Realism                | v1.5 reviewer-attestation transition assumes stable pool §10.7 acknowledges may erode                       | §7.1:668                         |
| F16 | Significant | Dependency-Realism                                     | v2 iOS commitment lacks App Store/code-signing/Briar-unavailability acknowledgment                          | §7.1:672                         |
| F17 | Significant | Solo-Feasibility                                       | §6.3 pilot facilitation: 120–360 hour parallel commitment, unbudgeted                                       | §6.3:625-636                     |
| F18 | Significant | Dependency-Realism                                     | v3 mesh integration depends on protocol stability and hardware path not named in §7                         | §7.1:674                         |
| F19 | Significant | Release-Gates                                          | §6.3 Phase B funding framed as supplementary; §10.2 frames as pilot-gating                                  | §6.3:638 vs §10.2:1077           |
| F20 | Minor       | Roadmap-Credibility, Release-Gates                     | v4 "established-organization tier" treated as product expansion, not foundation event                       | §7.1:676                         |
| F21 | Significant | Solo-Feasibility                                       | D0003 UniFFI binding maintenance and bilingual context cost not budgeted                                    | §6.1:583, D0003:14               |
| F22 | Minor       | Dependency-Realism                                     | F-Droid distribution policy dependency unacknowledged                                                       | §6.1, §7                         |
| F23 | Minor       | Scope-Discipline                                       | §7.2 "no significant revisitation through v3" contradicts §9.1's "another such case may emerge"             | §7.2:688 vs §9.1                 |
| F24 | Minor       | Release-Gates                                          | v3 timing (~18–24 months) collides with foundation-incorporation timing without acknowledgment              | §7.1:674 vs §8.4:766             |

---

# Critical Findings

## F1. §7.1 calendar windows contradict §10.1 "as available" register and §10.8's "not by when"

**Category:** Roadmap framing / Register inconsistency
**Location:** §7.1 lines 666, 668, 670, 672, 674
**Lenses:** Roadmap-Credibility F1; Release-Gates F2, P3; Solo-Feasibility P2

**Issue.** Every release header in §7.1 carries a "target ~X months post-v1" window. §10.1 line 1024 explicitly disavows this kind of timing language: "the brief does not commit to a calendar schedule for Phase A completion because the operating reality is an 'as available' cadence consistent with D0008... the brief does not characterize that timeline in months or person-years because doing so would imply a guarantee the volunteer baseline cannot back." §10.8 line 1167 states: "Specific timelines tied to funding events. The phase descriptions are 'what unlocks what,' not 'by when.'" D0008 line 14 records the cadence assumption as "as quorum forms, expected 4–6 months." §7.1 then commits to v1 at 9–12 months, v1.5 at ~6–9 months post-v1, v1.6 at ~12–15 months, v2 at ~12–18 months, v3 at ~18–24 months. The two sections do not describe the same project. The opening sentence of §7 ("Timing estimates are conditional on funding outcomes") attaches the condition once, then proceeds to give calendar windows for every release without re-attaching the condition.

**Impact.** The calendar framing is what gets quoted in partner conversations and funder briefings — it is the form §7 presents declaratively. A funder reading §7 first comes away with "v1 in ~9–12 months, v1.5 ~6–9 months later"; the same reader hitting §10 finds the project disclaiming any such calendar commitment. §10.1's careful funding-stance honesty is undermined by §7's framing. This pattern suggests §7 was written before §10 was tightened and was not updated when §10's "as available" framing was committed.

**Recommendation.** Either (a) delete the parenthetical month windows from §7.1 release headers and replace with phase-gate language ("v1.5 after Phase C funding closes," "v2 after foundation incorporation"), or (b) attach the same "if funding closes at the relevant phase" qualifier §10 uses to every estimate. Replace "target 9–12 months from start of full-time development" for v1 with person-month framing ("estimated 9–12 person-months of focused engineering effort") and explicitly note that calendar-time-to-v1 depends on whether the developer is operating at "as available" volunteer cadence or whether grant funding has freed full-time engineering capacity. Cross-reference §9.1's "self-funding floor" and §10.4's maintainer-compensation aspiration.

---

## F2. v1.5 and v1.6 timing precedes the pre-beta audit, Phase C funding, foundation incorporation, and reviewer honoraria

**Category:** Roadmap-vs-funding sequencing
**Location:** §7.1 lines 668, 670; §6.2 line 589
**Lenses:** Roadmap-Credibility F3; Release-Gates F2, F3; Dependency-Realism F4, F5

**Issue.** §7.1 places v1.5 at ~6–9 months post-v1 and v1.6 at ~12–15 months post-v1; §6.2 line 589 reinforces "Deferred to v1.5 (the 'complete the v1 architecture' release, ~6 months post-v1)." Against these timings:

- §6.3 line 634 commits to six months of pilot active use before any broader release decision.
- §10.2 line 1077: "The project does not deploy a pilot without the pre-pilot audit, per D0011's no-skip-the-audit posture."
- §10.3 lines 1085–1098: Phase C unlocks "broader-than-pilot release" and includes the pre-beta full audit ($60–150K) and foundation incorporation ($5–25K); "If Phase C funding does not close at all, the pilot continues at the Phase B-funded posture and broader release is deferred indefinitely."
- §3.4 line 210 and D0010: foundation incorporation "approximately 18-24 months post-v1."
- §10.3 line 1096: Phase C unlocks formalized Safe Harbor (D0012), board-bound governance (§8.4), formal partner advisory authority (D0009), and reviewer-honoraria operating model.
- §10.7 line 1158: honoraria gaps revert to volunteer-attestation baseline with median 4–6 month release cadence.

v1.5 at "~6–9 months post-v1" ships before pilot completion (6 months), before the pre-beta audit closes, before foundation incorporation happens, and before reviewer honoraria fund. v1.6 at "~12–15 months post-v1" still sits 3–12 months before the foundation. §7 presents these as engineering-sequenced releases when §10 establishes them as funding-, audit-, and governance-gated.

**Impact.** A reader of §7 alone concludes v1.5 ships ~6–9 months after v1. A reader who triangulates with §10.3 and D0010 sees v1.5 cannot ship until Phase C closes, which the brief nowhere commits to closing on a timeline. Pilot users evaluating v1 consent on §6.3 grounds, and broader-release users evaluating their protections on §7 grounds, are reading materially different protection regimes that §§6 and 7 do not surface. A partner evaluating whether to commit to v1.5 facilitation work on the §7.1 timeline does not see that the timeline depends on funding outcomes §10.3 explicitly says the project does not control.

**Recommendation.** Rewrite each release header to lead with the funding gate, not the calendar window. Example: "v1.5 — ships after pilot completion and Phase C funding (pre-beta audit, foundation incorporation, reviewer honoraria); engineering effort estimated at 6–9 person-months post-v1." Add to §7 (either as a new §7.4 "Governance and assurance milestones" or as additions to §7.2 "Dependencies between releases") explicit cross-references to §8.4 foundation incorporation and §10.3 Phase C, naming which roadmap items shift from "stated intent" to "structurally enforceable" at incorporation. Reconcile §6.2 "~6 months post-v1" with §7.1's "~6–9 months" — pick one.

---

## F3. §6.1 absorbs §8.1's three specialist roles into one solo developer without acknowledging the contradiction

**Category:** Solo-developer feasibility
**Location:** §6.1 lines 567–583; cross-check §8.1 lines 724–726
**Lenses:** Solo-Feasibility F1, P1; Scope-Discipline (implicit in P1)

**Issue.** §6.1 lists, as the solo developer's v1 output: (a) Rust cryptographic primitives wrapper plus Shamir reconstruction with memory hygiene plus COSE_Sign1 capability tokens plus trust-graph operation envelope and Sigsum client per D0003 and D0006; (b) Kotlin UI with Signal-familiar surface, trust-badge rendering, recovery-flow walkthroughs, and calibrated security-communication per §5.6; (c) external reviewer-pool recruitment, onboarding, and per-release coordination per §5.5 and §8.2; (d) six documentation artifacts per §6.1 line 581. §8.1 names three of these as funding-gated specialist roles: "Part-time cryptographic consulting" for the design-and-implementation cryptographic engineering, "UX-focused engineer" for §5.6 estimated at "30–50% of v1 total per the engineering review," and "Documentation and community-management role" for §5.7-scope documentation work. §6.1 silently re-absorbs all three.

**Impact.** This is the structural feasibility question §6.1 does not answer. The brief's own §8.1 estimate is that §5.6 UX alone is 30–50% of v1 effort; §10.3 budgets a 3–6 month UX-engineer engagement for it. If §8.1's estimate is directionally correct, the solo developer either takes 6–10 months on UX alone (consistent with the 18–30 month full-scope estimate D0004 cited from the §5 review) or the UX ships at materially lower quality than §5.6 specifies (subtle trust signals, warning-fatigue-avoiding calibration, recovery-flow walkthroughs designed for users under coercion stress). The latter is a security property regression, not a feature compromise: §5.6 line 514 frames "friction in security software translates directly to operational mistakes" — UX quality at this threat tier is in the security boundary.

**Recommendation.** §6.1 should explicitly name which §8.1 specialist work the solo developer absorbs, at what quality bar, and where the brief acknowledges the gap. The current "what one developer can ship soundly" framing implies the bundle is solo-feasible; the §8.1 listing implies it is not. One of those needs to give. Candidate framings: (a) name §5.6 UX as "MVP-quality at v1, deferred to UX engineer for v1.5/v1.6 polish"; (b) move the documentation deliverable to "intent subject to partner co-production" rather than committed solo output (consistent with §8.6's framing for partner-collaborative items); (c) name reviewer-pool coordination as separate from implementation effort with its own time budget; (d) cross-reference §8.1's specialist-role enumeration explicitly in §6.1 with a sentence acknowledging the solo-developer absorption and its quality implications.

---

## F4. Reviewer-pool, Sigsum-witness, and partner-documentation commitments in §6.1 contradict §8's conditional framing

**Category:** Cross-section contradiction
**Location:** §6.1 lines 573, 579, 581
**Lenses:** Scope-Discipline F2, F3, F9; Dependency-Realism F4, F5; Release-Gates (subfinding F4)

**Issue.** Three §6.1 v1 commitments are framed as deliverables while §8.2, §8.5, §8.6, and §9.1 frame their underlying machinery as conditional on Q3 (funding) and Q5 (partner outreach):

- **Reviewer pool (§6.1:579).** "External source-code review by a recruited reviewer pool with the 5+ membership and 3-of-5 attestation threshold targets specified in 5.5 and 8.6." §5.5 line 486: "the project does not ship below 3-of-5 attestation; releases wait for quorum." §8.2 line 740 frames reviewers as volunteer-attestation basis at the baseline; honoraria contingent on Phase C. §9.1 line 867: pools "may not form or may erode"; recruitment "contingent on Q3 (funding for honoraria) and Q5 (NGO partner outreach) resolving."
- **Sigsum integration (§6.1:573).** "trust evaluation queries Sigsum directly in v1" presumes the witness pool operates. §8.6 line 832 lists Sigsum witnesses as a partner role the project "seeks partners for"; §8.6 line 827: "they are not confirmed partnership arrangements." §5.5 line 490: the same witnesses cosign the release log.
- **Documentation (§6.1:581).** Six documentation artifacts committed as v1 deliverables; §5.7 line 557 names partner organizations (Tactical Tech, EFF SSD, Front Line Defenders) as "candidates for co-producing the user-facing and facilitator documentation"; §8.6 line 836 lists user training as a partner role.

**Impact.** A funder reading §6 sees deliverables; the same funder reading §8/§9 sees risks. Releases cannot ship until 3-of-5 attestations form — if the volunteer pool doesn't form, v1 doesn't ship. Trust-graph evaluation in v1 literally cannot run without the witness pool. Six documentation artifacts, several explicitly framed as partner-collaborative, depend on partners that have not yet been recruited. Per D0008 the median release interval is 4–6 months as quorum forms — that is not a v1 timeline property surfaced in §6.

**Recommendation.** Move reviewer-pool recruitment, witness-pool recruitment, and partner-collaborative documentation into a "v1 preconditions" subsection in §6.1 with explicit dependency on Q3 and Q5. Revise §6.1 line 579 to state v1 launch is gated on first-quorum attestation. Distinguish in §6.1 between documentation the developer can solo and documentation that requires partner collaboration; for the latter, frame as "intent subject to partner outreach Q5" consistent with §8.6. For Sigsum specifically: §6.1 must either (a) name witness-pool recruitment as a v1 precondition with a target completion date before v1 launch, or (b) demote Sigsum integration to v1.5 with v1 shipping operations as locally-signed-and-cached only. Status quo is incompatible with D0004's "honest scope" framing.

---

## F5. §6.3 pilot framing elides Phase B funding gate (§10.2) and Phase C broader-release gate (§10.3/§8.5)

**Category:** Pilot sequencing / Cross-section contradiction
**Location:** §6.3 lines 624–638
**Lenses:** Release-Gates F1, F5, P2; Roadmap-Credibility F7

**Issue.** §6.3 describes the pilot in three load-bearing ways that §10 contradicts:

- **Pilot proceeds on developer self-funding (§6.3:638).** "The pilot does not depend on external funding to proceed." §10.2 line 1077 and §10.7 line 1155 establish that Phase B funding (which includes the pre-pilot audit per §10.2) is _gating to pilot deployment_: "The project does not deploy a pilot without the pre-pilot audit, per D0011's no-skip-the-audit posture." The §6.3 line 638 framing is true at the hardware level but false at the audit level.
- **Six months active use before broader release (§6.3:634).** Phrasing elides the audit and funding gates §10.3 makes structural. The actual model is "pilot completes → pre-beta audit must close → Phase C funding must close → foundation incorporation work must be in progress → _then_ broader release."
- **No mention of pre-pilot audit (§6.3 generally, §6.1 line 579).** §8.5 line 808 names the D0011 pre-pilot cryptographic-primitives audit ($15–30K subsidized) as a Phase B gate. §6.1 and §6.3 — the natural places a pilot user would look — do not enumerate the pre-pilot audit as part of what ships.

**Impact.** A funder evaluating Phase B against the §6.3 framing may treat Phase B as funding the path to broader release rather than as funding the path to a pilot that is itself gated to broader release by a separate (Phase C) event. A pilot user who consented to v1 on the §6.3 framing would not know they may be operating at pilot scale indefinitely under the §10.3 contingency. The asymmetry between pilot users (who receive a pre-pilot primitives-only audit) and broader-release users (who receive the pre-pilot audit plus the pre-beta full audit) is the entire structural rationale for D0011's two-stage approach — §6.1/§6.3 elide the pilot side of that structure.

**Recommendation.** Add to §6.3 a "Pilot exit conditions" paragraph: pilot-to-broader-release is gated on (1) pre-beta audit closing per §8.5/D0011, (2) Phase C funding closing per §10.3, and (3) foundation-incorporation work materially advancing such that the structural mitigations §10.3 line 1096 enumerates can be operative at broader-release time. Revise §6.3 line 638 to distinguish what pilot-baseline self-funding covers (hardware, developer time per Phase A) from what gates pilot deployment (the pre-pilot audit per Phase B, conditional on subsidy-program funding closing). Add to §6.1 a "Pre-pilot assurance" item naming the D0011 pre-pilot primitives-only audit, cross-referencing §8.5 line 808.

---

## F6. v2 and v3 framed declaratively despite unsecured partner relationships, funding, team growth, and upstream-protocol dependencies

**Category:** Roadmap declarative-vs-conditional asymmetry
**Location:** §7.1 lines 672–674; §7.2 lines 684–688
**Lenses:** Roadmap-Credibility F4, P4; Dependency-Realism F1, F2, F11

**Issue.** §7.1 line 672 ("**v2** (target ~12-18 months post-v1). USB-bootable form factor and iOS support") and line 674 ("**v3** (target ~18-24 months post-v1). Mesh radio integration...") are presented declaratively. §7.3 line 708 explicitly: "The roadmap commits the project to specific extensions of the v1 architecture across v1.5, v2, and v3." Against this:

- §9.1 line 853: "v2+ scale assumes team growth (Section 8.1 placeholder); v1 does not."
- §10.4 line 1117: maintainer compensation that would fund team growth is "aspirational" and "not... a committed Phase D line item."
- §8.6 line 827: partnership commitments "are not confirmed partnership arrangements."
- §10.8 line 1168: "That the project reaches Phase C or D... depends on... external funding decisions the project does not control."

For v2 iOS specifically (Dependency-Realism F1): v2 iOS is gated on Apple App Store policies (which routinely affect Tor/anonymity apps), iOS code-signing posture (Sigstore identity-based signing is not a native fit for App Store distribution), and the inability to ship Briar at all on iOS (Briar's Tor-over-LAN/Bluetooth model has no iOS port). §7.1 says "the security baseline iOS allows is documented as part of v2 work" — this papers over a release-security stack that does not exist on iOS. v1.5 commits Briar; v2 claims iOS; the brief does not say how a v2 iOS user accesses the v1.5-promised highest-sensitivity tier.

For v2 USB (Dependency-Realism F11): A USB-bootable amnesic OS for cryptographic identity is not a standard target the Rust ecosystem cross-compiles to without significant integration effort (Tails is the existing prior art). §7 treats this as a cross-compilation exercise. "Likely a minimal terminal or framebuffer UI" is a hand-wave at one of the most complex deliverables on the roadmap.

For v3 mesh (Dependency-Realism F2): Meshtastic and MeshCore are independent volunteer communities with protocol roadmaps the project does not control; both have made breaking changes within 18-month windows. §8.6 contains no partner category for mesh-radio communities. §6.2 lists hardware partnerships as v4+; §10.5 lists them as v3+ aspiration; §7 commits a v3 mesh release without resolving the hardware path.

**Impact.** §7.1 v4 explicitly says "the project will reach v4 only if the prior versions have delivered enough operational value to attract the funding and organizational commitment." The same logic applies to v1.5/v2/v3 (Phase B, C, D respectively per §10), but §7 only attaches the framing to v4. The asymmetry is not defended anywhere and reads as the brief being honest about the far-future release and aspirational about the near-future ones.

**Recommendation.** Reclassify v2 and v3 from "roadmap commitments" to "roadmap aspirations conditional on Phase D funding, team growth, and partner outreach." Extend §7.1 line 708's v4 framing to v1.5/v2/v3. For v2 specifically: acknowledge (a) Apple distribution policy is an upstream dependency the project does not control, (b) Briar tier is unavailable on iOS (or document the alternative), (c) the §5.5 release-security stack will require restatement for iOS, and (d) USB substrate (Tails-derivative? Debian-live? from-scratch?) must be named or v2 USB downgraded to "design study pending that determination." For v3: name the Meshtastic/MeshCore protocol stability dependency (the brief gives this treatment to SimpleX/GrapheneOS/Tor but not to mesh substrates); resolve the §6.2-vs-§10.5 hardware-partnership ambiguity; either add a mesh-community partner category to §8.6 or move v3 to v4+ "longer-term horizon" framing.

---

## F7. §7 nowhere references foundation incorporation as the gate for structural mitigations broader-release users receive

**Category:** Governance milestone elision
**Location:** §7.1 lines 666–676, §7.2 lines 680–688
**Lenses:** Release-Gates F3; Dependency-Realism F6

**Issue.** §10.3 line 1096 enumerates what Phase C unlocks: "formalized Safe Harbor per D0012, board-bound governance per §8.4, formal partner advisory authority per D0009, and the reviewer-honoraria operating model per §8.2." §8.4 line 766 states foundation incorporation is "approximately 18-24 months post-v1 launch." §7 release sequence covers v1.5 (~6–9 months), v1.6 (~12–15 months), v2 (~12–18 months), v3 (~18–24 months) without referencing that v2 and v3 timeline overlaps with foundation-incorporation timing and that the structural protections users receive at broader release depend on incorporation. §7.1 v4 line 676 mentions "established-organization tier" but frames it as a product-tier expansion, not as the foundation-governance milestone §8.4 makes it. §3.4 lines 210 onward make foundation jurisdiction a trust-root activation event.

**Impact.** A reader following §7's release sequence forms a model where v1.5/v2/v3 are released to a continuously growing audience under the same governance posture v1 has — a natural-person-operated project. The actual model per §8.4, §10.3, and D0012 is that users receiving broader-than-pilot releases at or near v1.5 onward will receive a _materially different_ protection posture (formalized Safe Harbor, board-bound governance) than v1 pilot users — but only if foundation incorporation closes, which per §10.3 depends on Phase C funding, which per §10.7 line 1160 may not close. v4's "established-organization tier" presupposes (a) a foundation entity exists, (b) it has legal/operational capacity to enter B2B-style relationships, and (c) the v3-to-v4 transition has resolved the hardware-partnership ambiguity (F6).

**Recommendation.** Add to §7 (either as a new §7.4 "Governance and assurance milestones" or as expansions to §7.2 "Dependencies between releases") explicit cross-references to §8.4 foundation incorporation and §10.3 Phase C, naming which roadmap items shift from "stated intent" to "structurally enforceable" at incorporation. §7.1 v4 paragraph should name foundation incorporation (D0010) as a hard prerequisite, not just an organizational-design assumption. The brief's honesty posture in §8.4 line 766 and §10.3 line 1096 is not surfaced where the roadmap-reader would benefit from it.

---

## F8. §6.1 silently omits COSE_Sign1 envelope, Sigsum integration work, rollback resistance, and key-rotation flow as v1 deliverables

**Category:** v1 scope undercommunication
**Location:** §6.1 lines 573–579
**Lenses:** Scope-Discipline F1, F5, F10

**Issue.** Multiple §5 architectural elements committed to v1 are absent from §6.1's enumeration:

- **COSE_Sign1 + deterministic CBOR envelopes.** §5.1 specifies capability tokens as COSE_Sign1 structures with deterministic CBOR encoding (RFC 9052, RFC 8949 §4.2.1) using the `coset` crate. §5.2 specifies every trust-graph operation as the same envelope with a nine-field schema, with prior-hash chain, issuer-cert-hash binding, and per-(issuer, subject) equivocation detection all v1. D0004 §43–46 confirms the schema and prior-hash chain are v1. §6.1 line 573 says "COSE-formatted capability tokens" once but never names the envelope as v1 cryptographic engineering for the trust-graph operations side, never names deterministic CBOR as a v1 requirement, and never lists prior-hash chain / issuer-cert-hash anti-equivocation work. §9.1 line 724 confirms v1 ships "substantial original cryptographic engineering."
- **Rollback resistance.** §5.5 line 492: "Version numbers in signed release metadata are monotonic, and the client refuses to install a release whose version is lower than the highest version it has previously installed." Requires persistent client state surviving reinstall/wipe, signed release metadata format work, install-time enforcement. Not in §6.1.
- **Key-rotation flow.** §5.1 lines 309–311 commit v1 to operational-key rotation at three moments (provisioning, post-coercion, proactive). Includes rotation UI flow, master reconstruction during rotation, new operational key generation, signing the new operational key with the master, trust-graph key-rotation operation issuance, revocation of prior operational identity. Rotation under coercion is "itself a vulnerable moment" requiring peer-coordinated master reconstruction. §6.1 names "key rotation" as one of five operation types but not the UX flow or master-reconstruction-for-routine-rotation case.

**Impact.** This is multi-month original cryptographic engineering plus persistent-state UX plus protocol-issuance UX. §6.1's tidy enumeration hides it. The 9–12 month claim was supposedly rebudgeted around D0004's cuts, but D0004 didn't cut this work — it preserved it, and §6.1 doesn't surface it. A reader who reads §6.1 in isolation gets a smaller v1 than §5 specifies.

**Recommendation.** Add explicit lines to §6.1 enumerating: (a) "Cryptographic envelopes and anti-equivocation" naming COSE_Sign1 + deterministic CBOR for both capability tokens and trust-graph operations, the nine-field signed-operation schema per D0006, prior-hash chain implementation, issuer-cert-hash binding; (b) rollback resistance as a v1 client-side mechanism; (c) "operational-identity rotation flow (provisioning, recovery, proactive)" as a v1 UX/protocol deliverable, or defer proactive rotation to v1.5 with the architectural slot preserved. Either keep these in v1 honestly or move the equivocation-detection portion to v1.5 with explicit architectural-slot framing.

---

# Significant Findings

## F9. §6.1 commits to Sigsum integration without naming witness-pool precondition

**Category:** Cross-section contradiction (witness-pool subset of F4)
**Location:** §6.1 line 573
**Lenses:** Scope-Discipline F2; Dependency-Realism F5

**Issue.** §6.1 line 573 "trust evaluation queries Sigsum directly in v1" presumes witness pool operates across multi-year operation. §3.4 names Sigsum log operator and witness pool as trust roots. §8.6 lists Sigsum witnesses as a partner-role category requiring "operational capacity to maintain witness cosignature over multi-year timelines." §9.1: "Reviewer and witness pools may not form or may erode." v1 release security (§5.5 log cosignature) and v1's trust-graph audit substrate both require the witness pool. If the witness pool erodes mid-roadmap, §7's release-security model degrades silently.

**Recommendation.** §7 should reference §8.6's witness-pool dependency alongside the reviewer-pool gate. Treat as v1 precondition with explicit Q3/Q5 dependency, or defer Sigsum to v1.5 (cross-references F4).

---

## F10. v1 "9–12 months from start of full-time development" presumes full-time mode the brief does not commit to

**Category:** Timing framing
**Location:** §7.1 line 666
**Lenses:** Roadmap-Credibility F2

**Issue.** §10.1 line 1039 commits to "developer's time, at 'as available' cadence consistent with D0008." §10.1 line 1043: "the developer's contribution is volunteer until grant funding makes a maintainer-compensation question concrete (Phase D aspiration)." The "9–12 months from full-time" framing is therefore a conditional measured from a condition the brief does not commit to satisfying.

**Recommendation.** State the v1 timing in person-months ("estimated 9–12 person-months of focused engineering effort") and explicitly note that calendar-time-to-v1 depends on whether the developer is operating at "as available" volunteer cadence or whether grant funding has freed full-time engineering capacity. Cross-reference §9.1's "self-funding floor" and §10.4's maintainer-compensation aspiration. (Compatible with F1 recommendation.)

---

## F11. §6.4 forward-compatibility commitments smuggle multi-month engineering into v1 framed as "design choices"

**Category:** Engineering-scope undercommunication
**Location:** §6.4 lines 644, 646, 652, 654, 656
**Lenses:** Scope-Discipline F4, F15; Solo-Feasibility F7

**Issue.** §6.4 reads as "things v1 chooses for free":

- Line 644: "Protocol versioning fields in all signed messages from day one" — enforcement across every signed message is v1 engineering.
- Line 646: "Capability tokens with arbitrary scope strings" — scope-vocabulary discipline imposed across v1 codebase.
- Line 652: "Trust graph operation types designed for extension" — extensible-schema design plus prior-hash chain and Sigsum logging supporting unknown ops.
- Line 654: "Storage schemas with version fields and migration framework" — §5.7 line 552 makes the framework concrete: "SQLite with explicit schema versioning and migration tests using property-based round-trip verification through each migration step." Property-based migration testing is a dedicated subsystem.
- Line 656: "Build system designed to produce multiple artifacts" — cross-compilation discipline for Rust core targeting Android in v1 + USB/iOS in v2 + embedded in v3 is real architectural constraint on v1 build system. Framed as "mostly engineering hygiene" minimizes the work.

Additionally, multi-device pairing per D0007 (v1 schema-level support, v1.5 multi-profile UX) imposes v1 schema-design constraints the developer must hold context for during v1 implementation — schema-level forward-compatibility for an unshipped feature is a known source of solo-developer drift (Solo-Feasibility F7).

**Impact.** These are dedicated v1 engineering line-items, not zero-cost commitments. The 9–12 month estimate, post-D0004 cuts, must absorb them.

**Recommendation.** Restructure §6.4 to distinguish "v1 architectural commitments that require no additional engineering" from "v1 forward-compatibility deliverables that require dedicated v1 engineering effort." Move the property-based migration test framework, multi-target build pipeline, and protocol-version enforcement into the latter category and surface them in the §6.1 v1 scope enumeration. Re-frame line 656 as "v1 build-system architectural commitment: cross-compilation paths kept clean from day one to support v2/v3 targets without restructuring."

---

## F12. Cascade quarantine semantics and 90-day stale-flag escalation are v1 trust-graph work named only as "five operation types"

**Category:** v1 scope undercommunication
**Location:** §6.1 line 573; cross-check §5.2 lines 374–380
**Lenses:** Scope-Discipline F11

**Issue.** §6.1 names "five operation types (attestation, attestation withdrawal, key compromise revocation, introduction, key rotation)" and "commitment-only Sigsum anchoring." §5.2 lines 374–380 specify the cascade quarantine on revocation: attestation withdrawal soft-flags downstream attestations from the withdrawal date forward; key compromise revocation hard-suspends post-`revoked_as_of` attestations and soft-flags prior ones; 90-day stale-flag auto-quarantine escalation; per-attestation timer resetting on user touch. This is the load-bearing v1 trust-graph computation. §6.1 names the operation types but not the cascade semantics or stale-flag escalation logic as v1 deliverables.

**Impact.** Naming operation types without the cascade logic makes v1 sound like a CRUD-of-signed-claims feature when in fact it is the original adversarial-design work D0006 records.

**Recommendation.** Add explicit "cascade quarantine semantics per D0006 and 90-day stale-flag escalation" to §6.1's trust-graph commitment.

---

## F13. Rollback resistance, push-notification posture, crash-reporting infrastructure: v1 per §5, absent from §6.1

**Category:** v1 scope undercommunication
**Location:** §5.5 line 492, §5.4 lines 456–458, §5.7 line 558
**Lenses:** Scope-Discipline F5, F7, F8

**Issue.** Three v1 deliverables specified in §5 are absent from §6.1:

- **Push-notification posture (§5.4:456–458).** "UnifiedPush is the architectural choice." "v1 ships with push notifications off by default. The client polls at user-configurable intervals (default 15 minutes)." Requires UnifiedPush distributor selection UX, polling-loop implementation with battery-aware behavior, user-configurable interval setting, opt-in flow during provisioning. §6.1 closest match is "Signal-familiar messaging surface."
- **Crash-reporting infrastructure (§5.7:558).** "Opt-in only, end-to-end encrypted, delivered through the existing messaging layer to a Cairn-team-controlled SimpleX queue." Requires project-operated SimpleX queue, consent flow at provisioning, encrypted report delivery, intake/triage infrastructure. Project-operated infrastructure conflicts with §4.2's "minimal project-operated infrastructure" principle without acknowledgment.
- **Rollback resistance (§5.5:492).** See F8 critical finding; included here for completeness.

**Recommendation.** Add push-notification posture to §6.1's UI-surface paragraph or as a separate notification-architecture line. Either name crash reporting as a v1 deliverable with operational implications in §6.1, or defer to v1.5 with documented-only "report via partner channel" as v1 substitute.

---

## F14. §7.1 v1 audience line is more permissive than §6.3 10–15 user scope

**Category:** Internal inconsistency
**Location:** §7.1 line 666 vs §6.3 line 628
**Lenses:** Roadmap-Credibility F9

**Issue.** §7.1 line 666: "Audience: pilot users running GrapheneOS on Pixel, onboarded in person by the developer-as-facilitator." §6.3 line 628: "The pilot targets 10–15 users in one or two local groups already known to the developer." A reader could miss that v1 is not a public release in the usual sense — it is a 10–15-user closed pilot.

**Recommendation.** Tighten §7.1's v1 audience line to "pilot users (10–15 per §6.3) running GrapheneOS on Pixel."

---

## F15. v1.5 reviewer-attestation transition assumes stable pool §10.7 acknowledges may erode

**Category:** Reviewer-pool continuity
**Location:** §7.1 line 668
**Lenses:** Roadmap-Credibility F5

**Issue.** §7.1 line 668: v1.5 "Adds reproducible Android builds, with reviewer attestations transitioning from source review to binary-equivalence verification." §10.7 line 1158 acknowledges the pool may erode during honoraria gaps; §8.6 line 831 acknowledges recruitment from partner organizations is itself contingent. §7 does not surface that the v1.5 verification transition presumes a stable five-reviewer pool plus binary-equivalence training, neither of which §8 commits to having ready at the v1.5 ship date.

**Recommendation.** Add a sentence to v1.5 acknowledging the transition depends on reviewer-pool continuity through the v1-to-v1.5 interval, and cross-reference §10.7's reviewer-pool-erosion risk.

---

## F16. v2 iOS commitment lacks App Store policy, code-signing, and Briar-unavailability acknowledgment

**Category:** Dependency surface
**Location:** §7.1 line 672
**Lenses:** Dependency-Realism F1; Roadmap-Credibility F10

**Issue.** Already detailed in F6. iOS support is gated on Apple App Store policies, iOS code-signing posture incompatible with Sigstore identity-based signing, and Briar's iOS unavailability. "The security baseline iOS allows is documented as part of v2 work" papers over a release-security stack that does not exist on iOS.

**Recommendation.** Acknowledge in v2 that iOS support requires defining a meaningfully lower threat tier than v1's, and that the v2 iOS audience is therefore a different audience than v1's, not an extension of it. Acknowledge App Store policy as upstream dependency. State whether Briar tier is unavailable on iOS or document the alternative.

---

## F17. §6.3 pilot facilitation is a 120–360 hour parallel commitment, unbudgeted and competing with v1.5 implementation

**Category:** Solo-developer feasibility
**Location:** §6.3 lines 625–636
**Lenses:** Solo-Feasibility F2, P3

**Issue.** §6.3 commits the developer personally to in-person provisioning ceremony facilitation for 10–15 pilot users; each user has 3–5 recovery peers per §5.3 default (30–75 peer-side challenge establishments, each requiring out-of-band coordination). §6.3 line 634 commits a six-month pilot duration with the developer holding facilitator role through the full pilot, in parallel with v1.5 implementation. §5.6 line 530 makes facilitator presence "the unit of operational discipline" — a security property of the deployment, not a launch-day operation.

Reasonable estimate from §5.3 + §6.3 + §5.6: 8–16 hours per user for initial ceremony (selection guidance walkthrough, peer-by-peer challenge establishment with out-of-band channels, trust-graph seeding) plus 2–4 hours per user per quarter for follow-up (peer rotation events, recovery scenarios, support-channel issues) — 120–360 hours of facilitator work in pilot calendar time. The Sections 8/9 review F11 estimated 350–400 hours by similar methodology. The brief's §10.1 Phase A risk paragraph acknowledges "developer burnout extends Phase A indefinitely or terminates it prematurely" but does not acknowledge that the facilitator role is itself a sustained burnout vector. Additionally, §6.3 line 636 partner debriefs at 3-month and 6-month marks add coordination work; §8.6 commits partner time without explicit consultation (Sections 8/9 review F17).

**Recommendation.** §6.3 should either (a) name a co-facilitator role (partner organization staff, recruited volunteer facilitator) and acknowledge facilitator throughput as the binding constraint on pilot scale rather than "10–15 in one or two local groups," or (b) name the facilitator-hour estimate explicitly and acknowledge it as a draw on the developer's volunteer time that competes with v1.5 implementation. The current framing — "at pilot scale the developer can sustain the facilitator role personally" — is asserted without a time-cost grounding.

---

## F18. v3 mesh integration depends on protocol stability and hardware path not named in §7

**Category:** Dependency surface
**Location:** §7.1 line 674
**Lenses:** Dependency-Realism F2

**Issue.** Detailed in F6. Meshtastic and MeshCore are independent volunteer communities with protocol roadmaps the project does not control; §8.6 has no partner category for them; hardware-partnership timing is inconsistent across §6.2 (v4+), §10.5 (v3+ aspiration), and §7 (v3 mesh release). The brief gives §3.4 / §9.2 dependency treatment to SimpleX/GrapheneOS/Tor but not to Briar, Meshtastic, MeshCore, or UnifiedPush (Dependency-Realism Pattern 2).

**Recommendation.** §7.1 v3 paragraph should name the upstream protocol dependency (Meshtastic + MeshCore protocol stability over multi-year windows) and resolve the v3-vs-v4 ambiguity about hardware partnerships. If mesh hardware is BYOD, say so; if hardware partnerships are required, move them into §7's v3 dependency list. Apply the same treatment to Briar in v1.5 (its release cadence is sporadic, primary maintainer pool is small, Android Tor-bundling has changed) and UnifiedPush in v1/v1.5 push-default revisitation.

---

## F19. §6.3 Phase B funding framed as supplementary; §10.2 frames as pilot-gating

**Category:** Cross-section contradiction (subset of F5)
**Location:** §6.3 line 638 vs §10.2 line 1077
**Lenses:** Release-Gates F5

**Issue.** §6.3 line 638: "the developer covers pilot hardware out of pocket through v1 launch; partner contributions and grant funding when secured supplement rather than fund the pilot baseline. The pilot does not depend on external funding to proceed." §10.2 line 1077: "The project does not deploy a pilot without the pre-pilot audit, per D0011's no-skip-the-audit posture." Phase B funding (which includes the pre-pilot audit per §10.2 line 1063) is gating, not supplementary.

**Recommendation.** Revise §6.3 line 638 to distinguish what pilot-baseline self-funding covers (hardware, developer time per Phase A) from what gates pilot deployment (the pre-pilot audit per Phase B, conditional on subsidy-program funding closing). Honest phrasing parallels §10.2 line 1077 directly. (Compatible with F5 recommendation.)

---

# Minor Findings

## F20. v4 "established-organization tier" treated as product expansion, not foundation event

**Severity:** Minor
**Location:** §7.1 line 676
**Lenses:** Roadmap-Credibility F6 (subfinding); Release-Gates F6

§7.1 v4 frames "established-organization tier" as a product-tier expansion when §8.4/§10.4/D0010 make it the foundation-governance milestone. §10.8 line 1168 explicitly does not promise reaching Phase D. Add conditional framing: "v4 and beyond is reached only if Phases C and D sustainably close per §10.3, §10.4, §10.7" and cross-reference §10.8.

---

## F21. D0003 UniFFI binding maintenance and bilingual context cost not budgeted

**Severity:** Significant (left here for grouping with feasibility minor items; arguable as Significant)
**Location:** §6.1 line 583; D0003 line 14
**Lenses:** Solo-Feasibility F3

D0003 commits to Rust core plus Kotlin UI with UniFFI bindings; line 14 names UniFFI binding maintenance as ongoing per-feature cost; line 78 notes reproducible-build pipeline must reproduce both artifacts; line 79 splits testing across three infrastructures. §6.1 doesn't name UniFFI binding maintenance, integration testing at the boundary, or Rust↔Kotlin reproducible-build coordination as deliverables. Developer must hold simultaneous Rust ownership-model context and Kotlin/Android-lifecycle context across every iteration; at "as available" cadence per D0008, bilingual context-switching cost compounds across calendar duration. §10.1 Phase A line 1029 lists "Rust core implementation per D0003" and "Kotlin Android UI via UniFFI" as separate items but not binding-layer maintenance.

Recommendation: §6.1 should acknowledge UniFFI binding maintenance and the bilingual-context-switching cost as part of the developer's v1 working set. Phase A deliverables in §10.1 should add binding-layer maintenance, integration testing at the boundary, and Rust↔Kotlin reproducible-build coordination as explicit items.

---

## F22. F-Droid distribution policy dependency unacknowledged

**Severity:** Minor
**Location:** §6.1, §7
**Lenses:** Dependency-Realism F8

§6.1 names Sigstore/APK signing but not the distribution channel. F-Droid has its own inclusion criteria, anti-features policy, reproducible-build requirements, and review backlog (frequently multi-month). If v1 ships via F-Droid, every release in §7 is gated on F-Droid acceptance. F-Droid is subject to its own policy changes (recent debates about anti-features for Tor-bundled apps). Add the v1 distribution channel and the upstream policy dependency it creates. Also addresses Scope-Discipline F6 (multi-channel distribution conflict between §5.5 and §4.2): §6.1 should explicitly name the v1 distribution channels (per §4.2's stricter scope — F-Droid, Accrescent, GitHub) and §5.5 should be revised to match.

---

## F23. §7.2 "no significant revisitation through v3" contradicts §9.1's "another such case may emerge"

**Severity:** Minor
**Location:** §7.2 line 688 vs §9.1
**Lenses:** Dependency-Realism F13

§7.2 line 688: "Through v3, no significant revisitation of v1 architecture is anticipated." §9.1: "the Section 5 adversarial review surfaced multiple cases where forward-compatibility claims required explicit decisions (D0007 demoted the multi-device claim; D0006 added schema fields that v1 deployments cannot retroactively gain). Another such case may emerge during implementation or pilot." §7.2 reads as more confident than §9.1 supports.

Recommendation: §7.2 should reference §9.1's acknowledgment that forward-compatibility revisitation has already occurred (D0006/D0007) and may recur.

---

## F24. v3 timing collides with foundation-incorporation timing without acknowledgment

**Severity:** Minor
**Location:** §7.1 line 674 vs §8.4 line 766
**Lenses:** Release-Gates F8

§7.1 v3 timing is "~18-24 months post-v1." §8.4 foundation incorporation is "approximately 18-24 months post-v1 launch." The two timelines overlap exactly. The implication — that v3 release and foundation incorporation are concurrent work streams competing for the same developer and same funding pool — is not surfaced in §7. §10.3/§10.4 Phase D figures (excluding maintainer compensation) at $90K–250K/year suggest one stream is fundable; concurrent execution of both at the stated quality is not modeled.

Recommendation: Acknowledge in §7.1 v3 that the timeline assumes foundation incorporation per §8.4 is sufficiently advanced to absorb operational governance work, or restate v3 timing as conditional on the post-incorporation steady-state operating posture §10.4 describes.

---

# Recommended action plan

Findings break into four action categories:

**A. Prose edits to §§6 and 7 — surgical, straightforward.**

- **F1** — Replace §7.1 calendar windows with phase-gate language; restate v1 timing in person-months.
- **F2** — Rewrite each §7.1 release header to lead with funding gate, not calendar window. Reconcile §6.2 "~6 months post-v1" with §7.1's "~6–9 months."
- **F4** — Move reviewer-pool recruitment, witness-pool recruitment, and partner-collaborative documentation into a "v1 preconditions" subsection in §6.1 with explicit Q3/Q5 dependency.
- **F5** — Add to §6.3 a "Pilot exit conditions" paragraph naming pre-beta audit, Phase C funding, and foundation incorporation. Add to §6.1 a "Pre-pilot assurance" item naming D0011.
- **F6** — Reclassify v2 and v3 from commitments to conditional aspirations; extend §7.1 line 708's v4 framing.
- **F7** — Add §7.4 "Governance and assurance milestones" or expand §7.2 to name foundation-incorporation gating.
- **F8** — Add explicit lines to §6.1 for COSE_Sign1 envelope work, rollback resistance, key-rotation flow.
- **F9** — Reference §8.6 witness-pool dependency alongside reviewer-pool gate.
- **F10** — State v1 timing in person-months with explicit cadence conditionality.
- **F11** — Restructure §6.4 to distinguish architectural commitments from v1 forward-compatibility engineering deliverables.
- **F12** — Add cascade quarantine semantics + 90-day stale-flag escalation to §6.1 trust-graph commitment.
- **F13** — Add push-notification posture and crash-reporting infrastructure to §6.1.
- **F14** — Tighten §7.1 v1 audience line to reference §6.3 10–15 users.
- **F15** — Add sentence to v1.5 acknowledging reviewer-pool continuity dependency.
- **F16, F18** — Add upstream-protocol dependency acknowledgments for iOS (App Store, code-signing, Briar absence), mesh (Meshtastic/MeshCore protocol stability, hardware path), Briar (cadence, maintainer pool), UnifiedPush.
- **F19** — Revise §6.3 line 638 to distinguish hardware self-funding from audit-gating.
- **F20** — Add conditional framing to §7.1 v4.
- **F22** — Name v1 distribution channels in §6.1 (per §4.2's stricter scope); reconcile §5.5.
- **F23** — Acknowledge §9.1's "another such case may emerge" in §7.2.
- **F24** — Acknowledge §7.1 v3 / §8.4 foundation timeline collision.

**B. New decision documents — judgment calls required.**

- **D-new: §6.1 specialist-role absorption policy** (F3, F17, F21). The brief's core feasibility contradiction — §6.1 absorbs §8.1's three specialist roles into one developer, §6.3 commits that developer to 120–360 hours of parallel facilitation, and §6.1 does not name UniFFI binding maintenance as ongoing cost. Either a decision document explicitly resolving the specialist-role absorption (which work the solo developer does at MVP quality, which is partner-collaborative, which is funded-state-only, what quality bar applies to each) or substantive §6.1/§6.3 revision committing to one of those answers. This is the single highest-leverage decision in this review.
- **D-new: Pilot-to-broader-release governance gate decision** (F5, F7). Codify the §10.3 Phase C structural-mitigation gating (Safe Harbor, board-bound governance, partner advisory authority, honoraria operating model) at the §7 release-boundary level. Either decision document or §7.4 subsection committing to which release boundary activates which mitigation, contingent on which Phase.
- **D-new: v1.5/v1.6 contents and timing reconciliation** (F2, P10). §6.2 lists v1.5 contents per D0004; §7.1 splits v1.5 into v1.5/v1.6 with duress-wipe in v1.6 contrary to D0002/§6.2; D0004 §65–67 still describes v1.5 as a single release. The boundary needs a baseline.

**C. Architectural-claim reframing — register adjustments.**

- **F1** — Audit §7.1 calendar windows; reclassify conditional timing; tighten §7 introduction's register claim to match §10.1 / §10.8.
- **F3** — Acknowledge solo-developer specialization ceiling honestly; either scope §6.1 to fit or commit to honest specialization gap.
- **F6** — Extend §7.1 line 708's v4 honest framing to v1.5/v2/v3 explicitly.
- **F8, F11, F12, F13** — §6.1 enumeration must surface §5 v1 engineering that §6.1 currently elides. The press-release tone must give way to scope-honest enumeration.

**D. New open questions.**

- **Q-new (suggested Q17): Solo-developer specialist-role absorption.** Which §8.1 specialist work does the solo developer absorb at v1, at what quality bar, with what acknowledgment? Cross-references F3, F17.
- **Q-new (suggested Q18): Pilot facilitation throughput.** Per-user facilitation budget; per-peer onboarding budget; ongoing support budget; partner-debrief budget; whether 10–15 users is sustainable on solo time or co-facilitator is required. Cross-references F17.
- **Q-new (suggested Q19): v1.5/v1.6 release contents and timing.** Reconcile §6.2 (D0004 v1.5 as single release with duress-wipe) with §7.1 (v1.5/v1.6 split with duress-wipe in v1.6). Cross-references F2, P10.
- **Q-new (suggested Q20): v2 iOS scope.** Threat-tier expectations for iOS audience; Briar tier availability/substitute; release-security stack restatement. Cross-references F6, F16.
- **Q-new (suggested Q21): v3 mesh hardware path.** BYOD vs hardware partnerships; resolve §6.2-vs-§10.5-vs-§7.1 ambiguity. Cross-references F6, F18.

**E. Items to reject — none.** No findings warrant outright rejection. The closest candidates would be F22 (F-Droid policy dependency) and F23 (§7.2 vs §9.1 revisitation phrasing) as Minor — both are real but easily addressed with single-sentence acknowledgments rather than substantive rework.

---

# Strategic note

This review is structurally smaller than the §§8/9 review (24 consolidated findings vs 30) but the findings are concentrated in two places: the contradiction between §§6/7's deliverable-and-calendar register and §§8/10's conditional-and-funding-gated register, and the contradiction between §6.1's solo-developer scope and §8.1's specialist-role enumeration. These are not architectural problems; they are register and budget problems.

The §§8/9 review observed that the brief's "design discipline is strong; the brief's operational-commitment discipline has not yet been audited at the same depth." This §§6/7 review observes the next layer: §§6/7 are the surface that funders, partners, and pilot users encounter first, and they carry the wrong register. The fix is largely prose work — but it is structural prose work that has to be coordinated across §6.1, §6.2, §6.3, §6.4, §7.1, §7.2, and §7.3 simultaneously, because changing one without the others creates new internal inconsistencies.

The most actionable single edit is F1's calendar-window-to-phase-gate replacement in §7.1. The next-highest leverage is F3's specialist-role absorption decision (which §8.1 specialist work folds into the solo developer at what quality bar), followed by F2 + F5 + F7 (the funding-gate / audit-gate / governance-gate sequencing that §10 establishes but §§6/7 do not import). After these, the §6.1-vs-§5 scope-enumeration findings (F8, F11, F12, F13) close the gap between §6.1's press-release surface and §5's actual v1 spec.

The brief's overall posture — self-funded MVP, conditional register, honest about limits — remains the right posture. The remaining gaps in §§6/7 are at the level of specific commitments not living up to the conditional register §§8 and 10 already establish; closing them does not require revising the strategy, only the prose in the sections that currently read in the wrong register.
