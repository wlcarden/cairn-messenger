# §10 — Sophisticated Funder Honest-Disclosure Lens

## Summary

§10.8 is a competent set of disclaimers covering the dollar/timeline/phase-reachability triad and the open-question items (fiscal sponsor, audit firm, jurisdiction). For a sophisticated funder reading the brief in 2026, however, §10.8's disclaim-set is materially narrower than the implicit-promise set §10.1–§10.6 actually generates. The most consequential omissions are: (1) the assumption that named external subsidy programs (OTF Secure Audit, Cure53 mission rates, Mozilla OSA, NLnet NGI Zero Trust) will exist and be open when Cairn applies, (2) the BYOD pilot model's assumption that pilot users can source their own GrapheneOS-Pixel hardware — which directly contradicts §6.3, (3) the unstated assumption that partner co-funding conversations will yield partners, and (4) the absence of the developer's effective self-funding runway in calendar terms that §9.1 explicitly promised §10 would deliver.

The pattern is that §10.8 disclaims first-order outcomes ("amounts may not close") but leaves the second-order infrastructure on which those outcomes depend (subsidy programs exist, partners convert, hardware is available, rates stay roughly stable) implicit and therefore implicitly promised. A sophisticated funder reads this as "the brief is honest about the things it knows it cannot promise and silent about the things it has not yet noticed it cannot promise" — which is a different posture than the brief's own framing claims.

## Critical findings

### F1: Subsidy-program existence and openness are load-bearing but not disclaimed

- **Evidence:**
  - §10.2 line 1063: pre-pilot audit floor of $15-30K depends on "subsidy-tier rates (Open Tech Fund Secure Audit program, Cure53 mission-org rates)."
  - §10.2 line 1071: "A single subsidy-program close (OTF Secure Audit, NLnet NGI Zero Trust, Mozilla Open Source Audit Awards, or a Cure53 mission-rate engagement) at the lower end of its typical range covers Phase B and unlocks the pilot."
  - §10.3 line 1085: Phase C floor of $60K likewise conditional on "OTF Secure Audit at the audit-grant tier, Cure53 mission-org rates extended from the pre-pilot engagement, Trail of Bits civic-tech rates."
  - §10.5 lines 1124-1128: the four named subsidy programs are listed as "the first route for audit funding."
  - §10.6 line 1147: "Subsidy programs are pursued first for audit funding."
  - §10.8 (lines 1164-1170): disclaims that specific amounts will close and that the project reaches Phase C or D, but does **not** disclaim that the named subsidy programs will continue to exist, accept new applications, or maintain the rate tiers cited.
- **Impact:** OTF's Secure Audit program, Cure53 mission rates, Mozilla OSA, and NLnet NGI Zero Trust are program lines whose existence is shaped by their funders' political/strategic choices and donor cycles. A sophisticated funder knows that program lines at this category come and go — OTF's funding was directly contested in 2024-2025; Mozilla's open-source funding programs have been repeatedly restructured; NLnet NGI funding cycles depend on EU programmatic continuation. The brief implicitly claims a funding route exists and will be available 6-24 months out. §10.8 does not flag this.
- **Recommendation:** Add to §10.8: "That the named subsidy programs (OTF Secure Audit, Cure53 mission-org rates, Mozilla Open Source Audit Awards, NLnet NGI Zero Trust) will be open, accepting applications, or operating at the rate tiers cited in §10.2 and §10.3 when Cairn applies. Subsidy-program landscape changes are tracked but not controlled by the project; Phase B and Phase C floors are stated against the program landscape as of brief publication."

### F2: BYOD pilot model contradicts §6.3 and is not disclaimed

- **Evidence:**
  - §10.1 line 1042: "The bulk of pilot deployment is BYOD: pilot users source their own GrapheneOS-capable Pixel devices through the standard channels documented in Section 5 and the user-onboarding documentation." Project pool: 2-4 devices at $1,500-3,000.
  - §10.3 line 1089: "Pilot deployment hardware: minimal incremental cost under the BYOD pilot model. Pilot users source their own GrapheneOS-capable Pixel devices."
  - §6.3 line 630: "The project provides devices for pilot users: GrapheneOS-installed Pixel hardware with the Cairn application pre-installed."
  - §6.3 line 638: "Estimated pilot hardware cost: $5-12K (10-15 Pixel devices at current market prices). Consistent with the project's self-funded-MVP posture, the developer covers pilot hardware out of pocket through v1 launch."
  - §3.3 line 168: "In the v1 pilot model, the developer purchases Pixel devices, installs GrapheneOS, installs the application, and provisions identities for users — meaning the developer becomes the supply chain for the pilot."
  - §10.8 does not address the BYOD assumption at all.
- **Impact:** A sophisticated funder reading §10 alongside §6.3 sees a direct internal contradiction: §6.3 (and §3.3) put the developer in the supply chain, including hardware purchase, as a core architectural property of pilot trust; §10.1 inverts this to BYOD to keep the Phase A absorbed cost at $1,500-3,500. The brief's argument that "Phase A is what the project delivers at the volunteer baseline" implicitly relies on a pilot-hardware model the brief elsewhere treats as a security commitment. Either §10 silently relaxes a §3.3/§6.3 commitment to reduce Phase A cost, or §6.3 will be revised but §10 has run ahead. The funder discounts both: §10's cost floor (likely understated by $5-9K) and the project's narrative coherence.
- **Recommendation:** Either reconcile §10.1 with §6.3 (state explicitly that the pilot model has moved from project-provisioned to BYOD, and update §3.3's supply-chain analysis accordingly), or restate §10.1 to match the §6.3 commitment (~$5-12K project-absorbed hardware). Add to §10.8 a disclaimer specifically about hardware-availability assumptions: "That GrapheneOS-Pixel hardware will remain available through the standard channels at prices and supply consistent with pilot deployment. Hardware-supply disruption (Google Pixel withdrawal from market, GrapheneOS-Pixel compatibility loss per §9.2) shifts the cost picture in §10.1 and §10.3 materially."

### F3: Partner co-funding is named as a source but conversion is fully unverified

- **Evidence:**
  - §10.5 line 1137: "Partner co-funding. Where Cairn integration with a partner organization's tooling benefits both projects, partner organizations may co-fund the integration work. Co-funding arrangements emerge from Section 8.6 partnership conversations and are not assumed in the brief's budget."
  - §10.6 line 1145: "Partner-organization outreach precedes formal grant applications. Per Section 8.6, the partnership picture depends on conversations that have not yet been held; partner endorsement strengthens grant applications."
  - §10.1 line 1034: Phase A includes "Partner-organization outreach (Section 8.6): conversations leading toward pilot facilitation, threat intelligence, and localization arrangements. No funding required for conversations themselves."
  - §10.8 disclaims reaching Phase C/D, but does not specifically disclaim that partner conversations will yield (a) co-funding, (b) endorsement that strengthens grant applications, or (c) facilitation, threat intel, and localization that §10.1 lists as Phase A deliverables.
- **Impact:** §10.5's "not assumed in the brief's budget" is a partial disclaimer for the co-funding line item but does not address the broader load-bearing role partner conversations play across Phase A (deliverables that depend on them), Phase B (endorsement strengthens audit-subsidy applications), and Phase C/D (partner-organization advisory authority per §8.4). The sophisticated funder notices: §10.1 lists partner-arranged pilot facilitation, threat intelligence, and localization as Phase A deliverables, but these are not unilateral. If zero partner conversations convert, the Phase A deliverable set is materially smaller than §10.1 describes.
- **Recommendation:** Add to §10.8: "That partner-organization conversations will convert to active partnerships at the categories listed in §8.6 (reviewers, witnesses, pilot facilitators, threat-intel sources, localization partners) or to co-funding arrangements. Phase A's partner-dependent deliverables (pilot facilitation, threat-intel access, localization arrangements) and Phase B/C funding-strengthening benefits from partner endorsement are conditional on conversations the project does not control."

### F4: §10 does not deliver the self-funding runway §9.1 commits §10 will state

- **Evidence:**
  - §9.1 line 857: "The brief does not state a specific calendar floor in this section because the floor depends on the developer's personal financial situation and on the cost of v1 hardware acquisition for the pilot. **Section 10 (when drafted) will state the developer's effective self-funding runway in calendar terms — the number of months the developer can sustain v1 development plus pilot operations under self-funded posture with no audit, no honoraria, and no team scaling.** A program officer evaluating timeline risk needs that number; the project commits to providing it as the financial floor of all v1 funding-related risk discussions, rather than leaving it implicit."
  - §10.1 line 1043: "The developer's time is the dominant resource, and the brief does not assign a dollar figure to it because the project's posture is that the developer's contribution is volunteer until grant funding makes a maintainer-compensation question concrete."
  - §10.4 line 1117: states FTE figures ($150-250K/yr) for aspirational maintainer comp but no runway figure.
  - §10.8 disclaims "specific maintainer compensation arrangement" but not the missing runway disclosure §9.1 explicitly committed.
- **Impact:** A program officer at a foundation read §9.1's commitment and turns to §10 expecting the runway number. It is not there. §10.8 does not acknowledge the gap. The sophisticated funder reads this as a breach of an in-document commitment — a credibility marker more damaging than an honest "we are not yet prepared to state the runway" would be. §9.1 framed the runway as "the financial floor of all v1 funding-related risk discussions"; §10's silence on it propagates an unbounded financial floor to every Phase A and B argument.
- **Recommendation:** Either add the runway figure to §10.1 (months sustainable under the §9.1 framing) or explicitly acknowledge in §10.8 that the runway commitment from §9.1 has not been resolved in §10 and that this gap is itself a disclosure: "The §9.1-committed self-funding runway in calendar terms is not stated in §10. Funders evaluating Phase A duration risk and Phase B funding-window timing should request this figure directly from the developer; the brief does not promise the runway is long enough to bridge to Phase B funding closing on any specific cycle."

## Significant findings

### F5: Foundation incorporation timing ("18-24 months post-v1") is repeated as if scheduled

- **Evidence:**
  - §3.4 line 210: "the project intends to incorporate as a non-profit foundation approximately 18-24 months post-v1."
  - §8.4 line 766: "Intent: incorporate as a non-profit foundation approximately 18-24 months post-v1 launch."
  - §8.4 line 777: "The project anticipates an 18-24 month interval between brief completion and foundation incorporation."
  - §8.4 line 796: "Selection criteria when incorporation approaches (~18-24 months post-v1)."
  - §10.2 line 1075: "Foundation incorporation work begins in earnest" upon Phase B funding close.
  - §10.3 line 1087: foundation incorporation is a Phase C line item.
  - §10.8 line 1167: disclaims "specific timelines tied to funding events," and line 1168 says reaching Phase C depends on funding decisions, but does not specifically disclaim the 18-24-month timing claim repeated throughout the brief.
- **Impact:** A sophisticated funder reading §8.4 sees a precise timing claim ("approximately 18-24 months post-v1") repeated four times. Because §10.8 disclaims only "timelines tied to funding events" generically, the 18-24-month figure escapes the disclaim net and reads as a commitment. In practice, v1 ship date is itself contingent on grant timing (Phase A "as available" cadence), and incorporation depends on Phase C closing — so the 18-24-month figure compounds two contingencies. The brief implicitly promises that the compound (brief completion → v1 ship → 18-24 months → incorporation) is roughly 2.5-4 years total. That number drives funders' multi-year program planning.
- **Recommendation:** Add to §10.8: "The 18-24-month foundation-incorporation timing referenced in §3.4, §8.4, and §10.2/§10.3 is a planning anchor, not a schedule. It compounds the Phase A 'as available' cadence (§10.1, D0008) and Phase C funding closure; either extending materially shifts the incorporation timeline. The brief does not promise foundation incorporation within a specific calendar window."

### F6: Reviewer-pool size and recruitment success are assumed

- **Evidence:**
  - §10.1 line 1033: Phase A includes "Reviewer-pool recruitment outreach (Section 8.2 volunteer-attestation baseline): conversations, candidate evaluation, onboarding through the documented reviewer toolkit."
  - §10.3 line 1086: Phase C honoraria are calculated "multiplied across the five-reviewer pool and the release cadence the funded operational model supports."
  - §8.2 line 744: "Rotation is conditional on the reviewer pool being recruitable; if the recruited pool is smaller than 5+ or rotation is impractical, the project commits to making the constraint visible rather than silently shipping with degraded review properties."
  - §10.8 disclaims funding closing but does not disclaim reviewer-pool recruitment to the size that release-cadence and honoraria estimates require.
- **Impact:** Phase C honoraria projections ($40-100K/yr) are sized to a 5-reviewer pool. If recruitment yields 3 reviewers (the architectural threshold from §5.5, but below the rotation-supporting size), the operational picture changes — emergency-release path becomes the primary path, rotation is suspended, and the volunteer-baseline cadence persists post-honoraria. The funder is not warned in §10.
- **Recommendation:** Add to §10.8: "That a 5+ reviewer pool will be recruited and retained at the institutional and geographic diversity §8.2 targets. Phase C honoraria projections in §10.3 are sized to that pool; smaller recruited pools shift the cadence and honoraria picture per §8.2's surfacing commitment."

### F7: Phase A timeline implications are not disclaimed

- **Evidence:**
  - §10.1 line 1024: "The brief does not commit to a calendar schedule for Phase A completion" and "Phase A completes when it completes."
  - §6.4 line 666: "v1 (target 9-12 months from start of full-time development). Scope per Section 6.1."
  - §9.1 line 869: "Section 10.4 estimates roughly 6 months from brief completion to funded development."
  - §10.8 line 1167: "Specific timelines tied to funding events. The phase descriptions are 'what unlocks what,' not 'by when.'"
- **Impact:** §10.1's "completes when it completes" is honest framing of Phase A, but other parts of the brief carry specific Phase A timing implications (9-12 months for v1, 6 months brief-to-funded). A sophisticated funder reading §6.4 and §9.1 alongside §10.1 sees a tension: Phase A is allegedly schedule-free but its v1-release deliverable carries a "9-12 months" target. §10.8 disclaims timelines tied to funding events but not the cross-section v1 target. The funder cannot tell whether the 9-12-month figure is a forecast or a commitment.
- **Recommendation:** Either reconcile §6.4's "9-12 months from start of full-time development" with §10.1's volunteer-cadence framing (the §6.4 figure presumes full-time, which §10.1 does not promise), or add to §10.8: "That v1 ships within the §6.4-estimated 9-12 months from start of development. §6.4's figure presumes full-time development, which the volunteer-baseline cadence in §10.1 does not guarantee; brief readers should treat §6.4 as a full-time-funded scenario estimate rather than a volunteer-baseline commitment."

### F8: Audit market-rate stability is assumed

- **Evidence:**
  - §10.2 line 1063: pre-pilot audit at "$15-30K at subsidy-tier rates… $30-50K at unsubsidized small-engagement rates."
  - §10.3 line 1085: pre-beta full audit at "$60,000-150,000 reflecting market rates at named firms (Trail of Bits, NCC Group, Cure53, Quarkslab)."
  - §10.4 line 1106: recurring audit "$40,000-100,000 per year."
  - D0011 references "public audit-report engagement summaries from the named firms across 2023-2025" for industry-rate sourcing.
  - §10.8 disclaims dollar amounts closing but does not disclaim rate-card movement at the named firms over the 2-5 year horizon Phase B-D covers.
- **Impact:** A funder evaluating Phase D sustainability over a 5-year window knows that security-engineering rates moved materially 2020-2025 (multiple firms doubled rate cards). The brief presents 2023-2025 rate ranges as forward-applicable. §10.8 doesn't surface this as a disclaimer, so the budget figures read as static.
- **Recommendation:** Add to §10.8: "That audit-firm rate cards remain stable at the 2023-2025 ranges cited in §10.2, §10.3, and §10.4. Security-engineering market rates moved materially during 2020-2025; the figures cited are honest as of brief publication and require re-baselining at each application cycle."

### F9: Fiscal-sponsor fee impact on net grant value is partially disclaimed

- **Evidence:**
  - §10.2 line 1062: "fiscal-sponsorship fees (typically 5-15% of routed grants) are paid as a percentage of subsequent grants rather than as an up-front cost."
  - §10.5 line 1138: "Pre-incorporation: routed through the fiscal sponsor if the sponsor's structure supports individual contributions in addition to grants."
  - §10.3 Phase C totals: floor $105K, ceiling $335K. These are stated gross, not net of fiscal-sponsor fees.
  - §10.4 Phase D totals: floor $90-100K, ceiling $250K. Same — gross figures.
  - §10.8 does not disclaim that Phase B-D figures are pre-fiscal-sponsor-fee, materially overstating effective project receipt.
- **Impact:** At 5-15% fiscal-sponsor fees, Phase C floor effectively becomes $89-99K net (not $105K), and Phase C ceiling becomes $285-318K net (not $335K). A sophisticated funder notices the figures are gross and adjusts; less sophisticated funders may not. §10.4's Phase D figures similarly read as net-to-project but are routed through a fiscal sponsor during the pre-incorporation window §8.4 says is 18-24 months — which spans most of Phase C and possibly early Phase D.
- **Recommendation:** Add to §10.8: "That fiscal-sponsor fees (5-15% per §10.2) are absorbed in the Phase B-C-D figures. Figures stated in §10.2-§10.4 are pre-fee at the gross-grant level; net-to-project receipt during the pre-incorporation window is reduced by the routing fee. Post-incorporation (Phase D steady state) the fee is replaced by foundation overhead (§10.4)."

### F10: Funder-source roster (§10.5) implies access not yet established

- **Evidence:**
  - §10.5 lines 1129-1136 list direct grant programs: Open Tech Fund main grants, Ford Foundation, Open Society Foundations, Mozilla MOSS, European democracy and digital-rights instruments (SIDA, GIZ, EIDHR, Dutch Ministry of Foreign Affairs human-rights funds), NLnet main funded calls, Knight Foundation.
  - §10.6 line 1148: "Direct grants are pursued in parallel for broader Phase C and Phase D funding."
  - §9.1 line 861: "The Open Technology Fund (primary candidate), foundation backups (Ford, Open Society, Mozilla, Knight, Omidyar), and European democracy funds (SIDA, GIZ, EIDHR, Dutch Foreign Ministry, NLnet NGI Zero, Internet Society Foundation) are the routes."
  - §10.8 disclaims "specific dollar amounts of funding will close" but does not disclaim that the listed programs (a) have program lines matching Cairn's profile, (b) are accepting new grantees at the relevant scale, or (c) align with their stated priorities to fund a pre-incorporation natural-person-led security tool.
- **Impact:** Several of these programs have narrowed civic-tech / security-tool funding over 2023-2025 (Mozilla restructured MOSS multiple times; Ford's digital civil-rights portfolio shifted; OSF's program structure changed materially in 2023). Listing a program roster of this depth implies a viable funding landscape at the application scale Cairn needs — a sophisticated funder knows this is a moving target.
- **Recommendation:** Add to §10.8: "That the funder roster in §10.5 reflects program lines that will be open, sized to Cairn's request scale, and aligned with Cairn's pre-incorporation natural-person-led posture when application cycles open. The roster is the project's current understanding; specific program eligibility, scale, and timing require re-confirmation at each application cycle."

## Minor findings

### F11: Aspirational rolling crypto consulting is partially disclaimed

§10.2 line 1073 disclaims the consulting as "Phase B aspiration rather than Phase B commitment" and §8.1 disclaims at the team-scaling level. §10.8 does not reinforce. Recommendation: minor — a single line in §10.8 cross-referencing §10.2's framing would close the loop ("That rolling cryptographic consulting (§10.2, §8.1) is engaged. It is identified as an aspiration; only the pre-pilot audit is the Phase B commitment.").

### F12: Phase C "optional" UX engineer reads as conditionally-not-optional

§10.3 line 1088: "The item is optional in the sense that the developer can complete the work solo at slower cadence; it is not optional in the sense that the work itself is in scope." This is honest framing inside §10.3 but is not surfaced in §10.8. A funder reading only §10.8 sees Phase C as Phase B + reviewer honoraria + foundation + audit; the UX engineer's funding implications (the engagement accelerates broader release by reducing solo-developer effort on a 30-50% surface) are not in the disclaim set. Recommendation: clarify in §10.8 that "Phase C broader release without UX-engineer funding shifts to slower solo-developer cadence on the §5.6 surface; the timing-to-broader-release implication is not explicitly stated in §10."

### F13: Localization honoraria treated as recurring Phase D operational cost without partner-side disclaimer

§10.4 line 1110: "Localization and translation honoraria… $5,000-20,000 per year for a small number of target languages with native-speaker security-trainer translators." §10.8 does not disclaim that native-speaker security-trainer translators in the target languages will be (a) recruitable, (b) available at the rates assumed, or (c) sustainable as recurring contributors. Cross-references §8 partner-org dependence (Tactical Tech, EFF, AccessNow named as roles partners may fill). Recommendation: a sentence in §10.8 acknowledging that localization is contingent on partner-recruited translators, not separately purchased professional services.

### F14: Phase A "small infrastructure" is not currency-adjusted

§10.1 line 1041: "Small infrastructure: domain registration (~$15-50/year), GitHub free tier… free-tier static documentation hosting." GitHub free tier and Microsoft (its parent) policy are not within project control; CI minute caps have shifted in the past. §10.8 does not disclaim Phase A reliance on free-tier infrastructure. Minor because the costs are small if free tiers go away, but worth a sentence. Recommendation: low-priority.

## Patterns

1. **First-order vs second-order disclaim asymmetry.** §10.8 disclaims first-order outcomes (amounts, timelines, reaching phases) but not the second-order infrastructure those outcomes depend on (subsidy programs exist, partners convert, rates stay stable, hardware remains available, fiscal-sponsor fees absorbed in figures, free-tier infrastructure persists). The brief's framing claim — "an honest map of what dollars do for the project" — would benefit from extending the disclaim set down one level.

2. **§9.1 → §10 broken contract.** §9.1 explicitly commits §10 to deliver the self-funding runway in calendar months. §10 does not deliver it. §10.8 does not flag the omission. This is a self-contained internal coherence failure; a careful funder reads it as a credibility signal larger than the missing number itself.

3. **Cross-section consistency on hardware-supply assumptions.** §3.3, §6.3, and §10.1/§10.3 carry different positions on whether the developer or pilot users source pilot hardware. The brief's threat-model commitments (§3.3 supply-chain surface) and pilot-trust commitments (§6.3 developer-as-facilitator) presume developer-sourced hardware; §10's BYOD framing reduces the Phase A cost figure but breaks the §3.3/§6.3 architecture. Either §10 silently relaxes a security commitment or §3.3/§6.3 will be revised; the discrepancy itself is the disclosure issue.

4. **Implicit promises clustered around partner-org conversations.** Across §10.1, §10.3, §10.5, §10.6, partner organizations carry significant load: pilot facilitation, threat intelligence, localization, reviewer pool, co-funding, grant-application endorsement. §10.8 disclaims none of this at the partner-conversation-may-not-convert level. The project's stated approach (§10.6) puts partner outreach first; the brief's disclaim set should mirror this prominence.

5. **Currency and rate stability assumed across multi-year horizons.** Phase B/C/D figures are USD-denominated 2023-2025 market rates carried forward 2-5 years without disclaim. A sophisticated funder discounts the figures by their own assumed rate-trajectory; the brief implicitly promises rate stability it cannot guarantee.

6. **Disclaimers that exist in body text don't propagate to §10.8.** Several careful disclaimers appear in subsections (rolling crypto consulting as "aspiration not commitment" in §10.2; UX engineer "optional in one sense, in scope in another" in §10.3; partner co-funding "not assumed in the brief's budget" in §10.5). §10.8 is the canonical disclaim section a funder may consult standalone; its compact form leaves these body-text disclaimers unreflected, weakening the brief's own honesty posture rather than strengthening it.
