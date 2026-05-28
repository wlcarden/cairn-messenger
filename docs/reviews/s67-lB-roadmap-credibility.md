# §§6/7 — Roadmap Credibility Lens

## Summary

Section 7 presents a five-tier release sequence (v1, v1.5, v1.6, v2, v3, v4+) with calendar-anchored "target ~X months post-v1" timing on every release. This timing language is structurally incompatible with the project's own operating reality elsewhere in the brief: §10.1 (line 1024) explicitly refuses to commit to a calendar schedule because the volunteer baseline operates "as available," and D0008 records a 4-6 month median release interval as "as-quorum-forms" rather than a planned cadence. §7.1's parenthetical month-ranges read as commitments to readers (especially funders and partners), but the brief commits nowhere else to deliver them on that schedule. The §7 prose acknowledges "Timing estimates are conditional on funding outcomes" (line 662) in a single opening sentence, then proceeds to give calendar windows for every release without re-attaching the condition to each item.

The deeper credibility problem is that v1.5 and v1.6 are presented as architectural commitments without surfacing the funding gates that §10 places between v1 and them. v2 (USB + iOS) and v3 (mesh) are presented as engineering plans without surfacing that they depend on (a) foundation incorporation, (b) team growth, and (c) partner relationships that the brief elsewhere candidly admits have not been negotiated. Most consequentially, the v1.5 timing of "~6-9 months post-v1" sits before the foundation-incorporation window (~18-24 months post-v1 per §3.4 line 210 and D0010), but §7 does not acknowledge that the foundation, its grant-routing infrastructure, the audit-funding scaffold, and the post-pilot honoraria model that make v1.5+ work are nowhere near being in place at the v1.5 ship date §7 names.

## Critical findings

### F1: §7.1 calendar windows contradict §10.1 and D0008 "as available" framing

- **Evidence:**
  - §7.1 line 666: "**v1** (target 9–12 months from start of full-time development)."
  - §7.1 line 668: "**v1.5** (target ~6-9 months post-v1...)"
  - §7.1 line 670: "**v1.6** (target ~12-15 months post-v1...)"
  - §7.1 line 672: "**v2** (target ~12-18 months post-v1)."
  - §7.1 line 674: "**v3** (target ~18-24 months post-v1)."
  - vs. §10.1 line 1024: "The work proceeds as the developer's time allows; the brief does not commit to a calendar schedule for Phase A completion because the operating reality is an 'as available' cadence consistent with D0008... the brief does not characterize that timeline in months or person-years because doing so would imply a guarantee the volunteer baseline cannot back."
  - vs. D0008 line 14: "the cadence assumption changes from 'quarterly' to 'as quorum forms, expected 4-6 months.'"
- **Impact:** §10.1 explicitly refuses to commit to month-denominated timing because doing so would imply a guarantee the volunteer baseline cannot back. §7.1 then does exactly that for every release. A funder or partner reading §7 first comes away with "v1 in ~9-12 months, v1.5 ~6-9 months later"; the same reader hitting §10 finds the project disclaiming any such calendar commitment. The two sections do not describe the same project. The contradiction is most damaging because §7's framing is what gets quoted in partner conversations.
- **Recommendation:** Either delete the parenthetical month windows from §7.1 release headers and replace with phase-gate language ("v1.5 after Phase C funding closes," "v2 after foundation incorporation"), or attach the same "if funding closes at the relevant phase" qualifier §10 uses to every estimate. The bare "target ~6-9 months post-v1" framing is the form §10.1 explicitly says the project will not use.

### F2: v1 "9–12 months from start of full-time development" presumes full-time development that §10.1 says is not committed

- **Evidence:**
  - §7.1 line 666: "v1 (target 9–12 months from start of full-time development)."
  - vs. §10.1 line 1039: "Developer's time, at 'as available' cadence consistent with D0008."
  - vs. §10.1 line 1043: "the developer's contribution is volunteer until grant funding makes a maintainer-compensation question concrete (Phase D aspiration)."
- **Impact:** The v1 timing estimate is conditioned on "start of full-time development," but the brief nowhere commits to the developer entering full-time development. §10.1 commits to "as available" volunteer time as the operating reality, and §10.4 line 1117 confirms maintainer compensation is a Phase D aspiration, not a Phase A line item. The "9-12 months from full-time" framing is therefore a conditional measured from a condition the brief does not commit to satisfying. A funder taking the 9-12 month window at face value is implicitly being asked to assume full-time work that the funding model does not yet support.
- **Recommendation:** State the v1 timing in person-months ("estimated 9-12 person-months of focused engineering effort") rather than calendar months, and explicitly note that calendar-time-to-v1 depends on whether the developer is operating at "as available" volunteer cadence or whether grant funding has freed full-time engineering capacity. Cross-reference §9.1's "self-funding floor" promise and §10.4's maintainer-compensation aspiration.

### F3: v1.5/v1.6 timing precedes the foundation, the post-pilot audit, and honoraria funding that §10 places between v1 and them

- **Evidence:**
  - §7.1 line 668: v1.5 "target ~6-9 months post-v1"; line 670: v1.6 "target ~12-15 months post-v1."
  - §6.2 line 589: "Deferred to v1.5 (the 'complete the v1 architecture' release, ~6 months post-v1)."
  - vs. §3.4 line 210: "the project intends to incorporate as a non-profit foundation approximately 18-24 months post-v1."
  - vs. §10.3 line 1085-1087: Phase C unlocks "broader-than-pilot release" and includes the pre-beta full audit ($60-150K) and foundation incorporation ($5-25K) — neither of which is funded at the volunteer baseline.
  - vs. §6.3 line 634: pilot is six months of active use before any broader release decision.
  - vs. §10.1 line 1047: "What Phase A cannot deliver" includes the pre-pilot audit, i.e., Phase A does not even reach pilot deployment without Phase B funding closing.
- **Impact:** The v1.5 "~6-9 months post-v1" window means v1.5 ships before pilot completion (6 months) finishes, before the pre-beta audit ($60-150K, Phase C) closes, before foundation incorporation happens, and before reviewer honoraria fund. v1.6 at "~12-15 months post-v1" still sits 3-12 months before the foundation. §7 does not flag any of this. A reader of §7 alone concludes the project plans to ship v1.5 in ~6-9 months; a reader who triangulates with §10.3 and D0010 sees v1.5 cannot ship until Phase C closes, which the brief nowhere commits to closing on a timeline. The sequencing is presented as engineering when it is actually funding-gated.
- **Recommendation:** Rewrite each release header to lead with the funding gate, not the calendar window. Example: "v1.5 — ships after pilot completion and Phase C funding (pre-beta audit, foundation incorporation, reviewer honoraria); engineering effort estimated at 6-9 person-months post-v1." This is what §10 actually describes; §7 should match.

### F4: v2 and v3 framed as roadmap commitments rest on partner relationships and funding the brief admits are unsecured

- **Evidence:**
  - §7.1 line 672: "**v2** (target ~12-18 months post-v1). USB-bootable form factor and iOS support." Presented declaratively.
  - §7.1 line 674: "**v3** (target ~18-24 months post-v1). Mesh radio integration..." Presented declaratively.
  - §7.2 line 688: "Through v3, no significant revisitation of v1 architecture is anticipated."
  - vs. §9.1 line 853: "v2+ scale assumes team growth (Section 8.1 placeholder); v1 does not."
  - vs. §10.4 line 1117: maintainer compensation that would fund team growth is "aspirational" and "not... a committed Phase D line item."
  - vs. §8.6 line 827: partnership commitments "are not confirmed partnership arrangements."
  - vs. §10.8 line 1168: "That the project reaches Phase C or D... depends on... external funding decisions the project does not control." (The brief does not promise reaching them.)
- **Impact:** v2 and v3 require team growth (§9.1), which requires sustained Phase D funding (§10.4), which the brief explicitly does not promise (§10.8). Mesh integration in v3 also requires partnerships with the Meshtastic/MeshCore communities that §8.6 says the project has not negotiated. §7.1 presents v2 and v3 with the same declarative form as v1; §7.3 even commits to v1.5/v2/v3 specifically: "The roadmap commits the project to specific extensions of the v1 architecture across v1.5, v2, and v3" (line 708). This contradicts §10.8's explicit non-commitment to reaching Phase C/D.
- **Recommendation:** Reclassify v2 and v3 from "roadmap commitments" to "roadmap aspirations conditional on Phase D funding and team growth." Use the framing §7.1 already applies to v4: "The honest framing of v4 and beyond is that the project will reach v4 only if the prior versions have delivered enough operational value to attract the funding and organizational commitment..." (line 708). This sentence currently quarantines v4; the same logic applies to v2 and v3 and should be extended to them.

## Significant findings

### F5: v1.5 reviewer-attestation transition assumes a reviewer-pool state §8.2 cannot guarantee

- **Evidence:**
  - §7.1 line 668: v1.5 "Adds reproducible Android builds, with reviewer attestations transitioning from source review to binary-equivalence verification."
  - vs. §10.7 line 1158: "Reviewer honoraria cannot be funded indefinitely... the project reverts to the volunteer-attestation baseline with surfaced transparency; release cadence reverts to the median-4-6-month 'as-quorum-forms' pattern. Reviewer-pool composition may shift as some volunteer-baseline reviewers depart and the recruitment pool changes."
  - vs. §8.6 line 831: reviewer pool recruitment depends on partner organizations whose participation "is not their standard collaboration model."
- **Impact:** The v1.5 attestation-method transition assumes the reviewer pool exists and has capacity to learn a new verification workflow. §10.7 acknowledges the pool may erode during honoraria gaps; §8.6 acknowledges recruitment from partner organizations is itself contingent. §7 does not surface that the v1.5 verification transition presumes a stable five-reviewer pool plus binary-equivalence training, neither of which §8 commits to having ready at the v1.5 ship date.
- **Recommendation:** Add a sentence to v1.5 acknowledging the transition depends on reviewer-pool continuity through the v1-to-v1.5 interval, and cross-reference §10.7's reviewer-pool-erosion risk.

### F6: §7.2 dependency chain compounds funding uncertainty without flagging it

- **Evidence:**
  - §7.2 line 684: "v1 and v1.5 enable v2."
  - §7.2 line 686: "v2 enables v3."
  - §6.4 line 648: "Multi-device pairing specified for v2 but not built in v1 (per D0007). v1 capability tokens support multiple device keys per operational identity at the schema level; v1 client behavior is single-device-per-identity. v2 may introduce additional protocol operations..."
- **Impact:** The "v1.5 enables v2 enables v3" chain is structurally sound at the architecture level, but at the delivery level it means v3 is downstream of three uncommitted phases of funding (B, C, D) plus team growth. §7.2 presents the dependency chain as an engineering convenience ("forward compatibility means later versions extend without breaking") without acknowledging that the chain is also a funding-and-team dependency chain: if any phase does not fund, none of the downstream releases ship. The brief should state this once explicitly.
- **Recommendation:** Add a closing paragraph to §7.2 acknowledging the dependency chain has a funding-and-organizational dimension parallel to its architectural dimension, and that the architectural readiness of v1.5/v2/v3 does not by itself guarantee they ship.

### F7: Pre-pilot audit dependency for pilot is in §10 but missing from §6.3 sequencing

- **Evidence:**
  - §6.3 line 624-638: pilot deployment plan describes 10-15 users, six months active use, device provisioning, ceremony, feedback collection, budget — does not mention the pre-pilot audit as a precondition.
  - vs. §10.2 line 1077: "If Phase B funding does not close, Phase A continues. The project does not deploy a pilot without the pre-pilot audit, per D0011's no-skip-the-audit posture."
  - vs. D0011 line 29: "Pilot users receive an implementation whose cryptographic core has been externally reviewed."
- **Impact:** §6.3 reads as if the pilot is a v1 deliverable on the §7.1 v1 timeline (9-12 months). §10.2 makes it clear the pilot is gated on Phase B funding ($17K floor, mostly the pre-pilot audit) closing. A funder reading §6.3 first sees a pilot plan with no funding gate attached; a reader who reaches §10.2 discovers the pilot is conditional on Phase B closing. The pilot's funding gate is the most consequential single sentence in the §6/§7 sequencing and it appears only in §10.
- **Recommendation:** Add to §6.3 a line stating pilot deployment is gated on Phase B funding closing (the pre-pilot audit) per D0011 and §10.2. The pilot is not a v1-completion item; it is a v1-plus-Phase-B item.

### F8: v1.6 split rationale references "Sections 8/9 review F9" without surfacing it as a credibility-honest move in the right direction

- **Evidence:**
  - §7.1 line 670: "The v1.5/v1.6 split (in this update from a single v1.5 release) reflects honest engineering scope per the Sections 8/9 review F9: the original v1.5 scope was 9-15 months of solo-developer work; splitting into architecture-completeness and deferred-UX releases lets the architecture-completeness ship on a credible timeline..."
- **Impact:** This is the most honest framing in §7 — explicitly acknowledging a prior version was wishful thinking and the split is the correction. The credibility move is good, but it accidentally highlights that the _new_ timing (v1.5 ~6-9 months, v1.6 ~12-15 months) is itself just a smaller version of the same wishful framing: month-anchored at the volunteer baseline that §10.1 says cannot back month-anchored commitments. The fix addressed scope realism but not cadence realism.
- **Recommendation:** Extend the same honesty to the cadence question. The v1.5/v1.6 split assumes the volunteer-baseline cadence (line 670 says this); the next sentence should say the calendar windows assume Phase C funding has closed to put the project on honoraria-funded quarterly cadence rather than as-quorum-forms cadence.

## Minor findings

### F9: §7.1 v1 audience line conflicts with §6.3 scale

- **Evidence:**
  - §7.1 line 666: "Audience: pilot users running GrapheneOS on Pixel, onboarded in person by the developer-as-facilitator."
  - §6.3 line 628: "The pilot targets 10–15 users in one or two local groups already known to the developer."
- **Impact:** Minor — §7.1's "Audience" line for v1 implies a broader audience than §6.3's 10-15 users; a reader could miss that v1 is not a public release in the usual sense, it is a 10-15-user closed pilot. The brief is internally consistent but the framing in §7.1 is more permissive than §6.3.
- **Recommendation:** Tighten §7.1's v1 audience line to "pilot users (10-15 per §6.3) running GrapheneOS on Pixel."

### F10: v2 iOS support depends on a security baseline iOS does not yet provide

- **Evidence:**
  - §7.1 line 672: "iOS support extends the platform to users who cannot or will not move to GrapheneOS-Pixel; the security baseline iOS allows is documented as part of v2 work."
  - vs. §3.5 line 216 (referenced): "Compromise of GrapheneOS or Pixel hardware. Section 3.5 names these as indefinitely out of scope."
- **Impact:** The brief's threat model is built on the GrapheneOS-Pixel baseline. v2 iOS support is presented as a platform extension but the security baseline iOS provides is materially weaker than GrapheneOS-Pixel; the v2 line acknowledges this ("the security baseline iOS allows is documented as part of v2 work") but does not commit to a defensible documentation outcome. A skeptical reader could ask whether the v2 commitment is to iOS support at GrapheneOS-Pixel parity (impossible) or at some lower baseline (the threat-tier audience may not accept).
- **Recommendation:** Acknowledge in v2 that iOS support requires defining a meaningfully lower threat tier than v1's, and that the v2 iOS audience is therefore a different audience than v1's, not an extension of it.

### F11: §7.1 v3 mesh integration assumes mesh community partnerships not in §8.6

- **Evidence:**
  - §7.1 line 674: "Mesh radio integration via Meshtastic and MeshCore... The integration is protocol-agnostic — supporting both Meshtastic's flood-routing model and MeshCore's intelligent-routing model — so users can follow local mesh community conventions."
  - vs. §8.6 line 829-836: partner role categories listed do not include mesh-radio community partnerships.
- **Impact:** v3 mesh integration is the most external-dependency-heavy release in the roadmap and §8.6 contains no partner category for it. The brief commits to v3 mesh integration without identifying who in the Meshtastic/MeshCore communities the project would work with on protocol questions.
- **Recommendation:** Either add a mesh-community partner category to §8.6 with the same "candidate, not committed" framing, or move v3 to the v4+ "longer-term horizon" framing where partner relationships are explicitly aspirational.

## Patterns

**P1: Calendar language stamped on volunteer-baseline reality.** Every release header in §7.1 carries a "target ~X months post-v1" window. §10.1 explicitly disavows this kind of timing language for the same work. The pattern suggests §7 was written before §10 was tightened and was not updated when §10's "as available" framing was committed. The fix is mechanical (replace each window with a phase-gate reference) but the framing in §7 currently undermines §10's careful funding-stance honesty.

**P2: Funding gates documented in §10 are missing from §6/§7.** Multiple §6/§7 commitments (pilot deployment, v1.5 transition, v2 team growth, v3 mesh partnerships) have funding gates documented in §10 that §6/§7 do not reference. A reader who reads §6/§7 in isolation gets a more concrete project than the brief actually commits to.

**P3: Architectural readiness conflated with delivery readiness.** §6.4 and §7.2 are strong on architectural forward-compatibility — the protocol-version fields, capability-token scope vocabulary, multi-device schema slot, build pipeline for multiple targets are well-designed. The brief then uses this architectural readiness to imply delivery readiness for v1.5/v2/v3. Forward-compatible architecture is a precondition for v1.5+, not a substitute for funding, team, and partnership commitments §10 and §8 say are not in place.

**P4: v4+ gets the honest framing; v1.5/v2/v3 do not.** §7.1 explicitly says v4 is conditional on "the project will reach v4 only if the prior versions have delivered enough operational value to attract the funding and organizational commitment." The same logic applies to v1.5/v2/v3 (Phase B, C, D respectively per §10), but §7 only attaches the framing to v4. The asymmetry is not defended anywhere and reads as the brief being honest about the far-future release and aspirational about the near-future ones.
