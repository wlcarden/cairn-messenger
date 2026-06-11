# Section 2 Adversarial Review — Consolidated Findings

**Date:** 2026-05-28
**Source:** Five parallel sub-agent reviews, distinct lenses (civil-society security practitioner; existing-product team; foundation programme officer; pilot user candidate; internal consistency).
**Raw findings:** 47 across reviewers (Critical 13, Significant 22, Minor 12). After deduplication and theming: 24 consolidated findings below.
**Companion to:** [design-brief.md](design-brief.md) §2 (lines 32–103), with cross-references to §§3–10 and the decision documents.

---

## Executive summary

§2 occupies a load-bearing position: it is the door funders, partners, and pilot candidates walk through before reaching the architecture and operational sections. The five lenses converge on a single posture: §2.1's threat-tier framing is competent but unevidenced; §2.2's audience taxonomy overclaims breadth its own pilot scope cannot deliver; §2.3's competitive landscape is calendar-dated to 2021–2022 product states and curated to a comparator subset where Cairn looks distinctive; and §2 as a whole carries language that has not been updated to reflect the §§7–10 revisions the §§8/9 review already absorbed (volunteer baseline, BYOD pilot, original cryptographic engineering, v1.5/v1.6 split).

The strongest cross-lens consensus is structural rather than rhetorical. Four of five lenses (practitioner, funder, pilot user, consistency) independently flag the same gap: §2.2 lists five communities as v1 audience sources, then collapses them into a single intersection on three preconditions (GrapheneOS-Pixel, viable peer-recovery network, in-person facilitation) that empirically very few users in any of the five communities satisfy simultaneously. The actual v1 audience is the developer's existing local social network. The brief does not say this clearly. The practitioner lens further identifies that the populations most acutely in the §2.1 threat tier — co-located-adversary cases, sex workers under criminalization, abuse survivors, undocumented organizers, isolated dissidents — are exactly the populations §2.2's preconditions exclude.

Divergence is interesting where it shows reviewers reading the same text and registering different stakes. The practitioner reads "operational discipline" as user-blaming language partner organizations will not endorse; the pilot user reads it as undefined cognitive overhead that assumes class-coded support infrastructure they do not have; the consistency reviewer reads it as a forward reference to a partner network §6.3/§8.6 explicitly say is not yet committed. All three are right, and the converging implication is that "operational discipline" is doing too much rhetorical work for an undefined concept whose support model is aspirational. The existing-product lens, by contrast, is the most localized: it has specific factual corrections (Signal usernames, Wickr Me sunset, Session protocol migration, Matrix MLS, Briar Mailbox) that strengthen rather than undermine Cairn's positioning if absorbed. Across all lenses, the brief's "honest about limits" principle (§4.2) is consistently named as a discipline §2 does not maintain at parity with later sections.

---

## Consolidated findings table

| ID  | Severity    | Lens(es)                                      | Title                                                                                                                                                 | Citation                        |
| --- | ----------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| F1  | Critical    | Practitioner, Funder, Pilot user, Consistency | Five audience subgroups collapsed into a non-existent intersection; v1 audience is the developer's local network                                      | §2.2 lines 56–62                |
| F2  | Critical    | Funder, Practitioner                          | Differentiation argument asserted, not evidenced; collapses against Briar/SimpleX as funded portfolio peers                                           | §2.1 line 46; §2.3 lines 83–100 |
| F3  | Critical    | Practitioner, Pilot user                      | Co-located adversary and most-acute-user populations absent from audience construction                                                                | §2.2 line 52                    |
| F4  | Critical    | Funder                                        | §2.3 landscape omits Tails, SecureDrop, OnionShare, CalyxOS — the funded portfolio peers                                                              | §2.3 lines 75–100               |
| F5  | Critical    | Practitioner, Pilot user                      | "Operational discipline" framing moves user-borne cost into architectural commitment; partner-endorsable language drifts toward user-blaming          | §2.1 line 42; §2.2 line 71      |
| F6  | Critical    | Consistency                                   | §2.1 "integration of existing primitives" contradicts §9.3 / §8.1 acknowledgment of substantial original cryptographic engineering                    | §2.1 line 46; §2.3 line 100     |
| F7  | Critical    | Existing-product                              | Wickr characterization is to a product line AWS discontinued for non-enterprise users in December 2023                                                | §2.3 line 81                    |
| F8  | Critical    | Existing-product                              | Signal paragraph predates the Feb 2024 username feature; treats documented tradeoff as gap                                                            | §2.3 line 77                    |
| F9  | Critical    | Funder                                        | "Just-below-state-classified" framing is off-register for civil-society funders; defense subcontractor inclusion is disqualifying for some portfolios | §2.1 line 36; §2.2 line 59      |
| F10 | Critical    | Consistency                                   | "9–12 months to ship soundly" and single v1.5 envelope contradict v1.5/v1.6 split and D0008 volunteer cadence                                         | §2.2 lines 64, 66               |
| F11 | Critical    | Pilot user, Practitioner, Consistency         | In-person facilitator requirement collapses §2.2's stated audience to "people the developer can drive to"                                             | §2.2 lines 52, 62               |
| F12 | Significant | Pilot user, Practitioner                      | "Trusted peer network of 5" is an unmet precondition for the most acute users; recovery defense requires absence of the failure mode it addresses     | §2.2 lines 52, 58, 62           |
| F13 | Significant | Funder                                        | §2.1 problem framing is rhetorical, lacks citations and quantified evidence                                                                           | §2.1 lines 36–46                |
| F14 | Significant | Funder, Consistency                           | Audience-expansion roadmap (v1.5/v2/v3/v4+) reads as scope-creep against §10 funding posture and §7.1 split                                           | §2.2 lines 64–69                |
| F15 | Significant | Existing-product                              | Session paragraph attributes wrong cryptographic stack; Session migrated off Signal Protocol in 2023                                                  | §2.3 line 87                    |
| F16 | Significant | Existing-product                              | Matrix paragraph elides MLS migration and Element/MAS metadata work                                                                                   | §2.3 line 79                    |
| F17 | Significant | Existing-product                              | Briar paragraph understates Briar Mailbox, which addresses one of the named gaps                                                                      | §2.3 line 85                    |
| F18 | Significant | Existing-product, Funder                      | Comparator set omits Threema, Wire, Keet, Olvid — products audience actually uses today                                                               | §2.3 lines 73–89                |
| F19 | Significant | Practitioner                                  | Pilot recruitment from developer's social network elides consent-exit dynamics IRB-equivalent protocols require                                       | §2.2 line 62                    |
| F20 | Significant | Consistency                                   | §2.2 "supplied with GrapheneOS-Pixel hardware" contradicts §10.1 BYOD posture                                                                         | §2.2 line 62; §10.1 line 1042   |
| F21 | Significant | Consistency, Funder                           | §2 introduces solo-developer / single-foundation aspiration that contradicts §4.3 multi-party commitments                                             | §2.1 line 46; §4.3 line 287     |
| F22 | Significant | Practitioner, Pilot user, Consistency         | English-only / professional-category framing leaves language scope and non-institutional populations implicit                                         | §2.2 lines 56–60                |
| F23 | Significant | Consistency                                   | §2.3 "defeats impersonation attacks" overstates §9.3 "principal defense" / residual surface                                                           | §2.3 line 95; §9.3 line 931     |
| F24 | Significant | Pilot user, Consistency                       | §2.2 says "security-conscious-device-choice is itself a tell — out of scope" while v1.5 ships duress-wipe for exactly that case                       | §2.2 lines 52, 66               |
| F25 | Minor       | Practitioner                                  | "Authoritarian contexts" reproduces Western-threat-is-elsewhere framing                                                                               | §2.1 line 36                    |
| F26 | Minor       | Practitioner                                  | "Intellectual property is itself a target" imports corporate-security frame into civil-society section                                                | §2.1 line 44                    |
| F27 | Minor       | Practitioner                                  | Threat-tier-to-onboarding mismatch: in-person provisioning is itself a casework risk event for highest-tier users                                     | §2.2 line 52                    |
| F28 | Minor       | Existing-product                              | "Signal Foundation" implied but not named while §2.3 names AWS — inconsistency                                                                        | §2.3 lines 77, 81               |
| F29 | Minor       | Existing-product                              | SimpleX paragraph describes SimpleX Chat circa 2022, not current product                                                                              | §2.3 line 83                    |
| F30 | Minor       | Existing-product                              | Cwtch paragraph is generic; does not engage with untrusted-group-server pattern                                                                       | §2.3 line 89                    |
| F31 | Minor       | Pilot user                                    | "Trained facilitator" is undefined; no forward reference to training spec                                                                             | §2.2 line 52                    |
| F32 | Minor       | Pilot user                                    | "Civil-society researcher" subgroup conflates Citizen Lab–type researchers with their analyzed subjects                                               | §2.2 line 60                    |
| F33 | Minor       | Funder                                        | "Identifier-as-vulnerability" is the standard SimpleX/Briar pitch; adds nothing committee hasn't heard                                                | §2.1 line 40                    |
| F34 | Minor       | Funder                                        | "Calibrated language" commitment claimed elsewhere is itself absolute-sounding in §2                                                                  | §2.1 line 36                    |
| F35 | Minor       | Pilot user                                    | "Honest"/"honestly" appears three times in §2.2 — protesting too much                                                                                 | §2.2 lines 50, 52, 71           |
| F36 | Minor       | Consistency                                   | Civil-society researcher subgroup conflicts with §8.6 framing them as research collaborators, not v1 users                                            | §2.2 line 60; §8.6 line 831     |

---

# Critical findings detail

## F1. Five audience subgroups collapsed into a non-existent intersection; v1 audience is the developer's local network

**Lenses:** Practitioner (F1), Funder (F2), Pilot user (F2, Pattern 2), Consistency (F4)

**Problem.** §2.2 enumerates five overlapping community categories (journalists in contested-press environments; NGO field staff; organizers in active dissent; dual-use tech workers; civil-society researchers), then at line 62 collapses them into "the intersection of these communities where users (a) have access to or can be supplied with GrapheneOS-Pixel hardware, (b) operate in trust networks where social recovery is viable, and (c) can be onboarded in person by a facilitator." Four independent lenses identify that this intersection is empirically very small and that the actual v1 audience is what §2.2 line 62 admits parenthetically: "groups the developer has direct relationships with."

**Evidence.**

- Practitioner F1: each of the five subgroups has incompatible threat models, device-custody patterns, and institutional support relationships; the brief names all five to imply breadth while v1 architecturally fits only the researcher subgroup and a slice of the organizer subgroup.
- Funder F2: cross-referenced with §10.2 (Phase B floor ~$17K, ceiling ~$60K), "10–15 users in groups already known to the developer" reads as personal-project pilot, not fundable population. No population-size estimate appears anywhere in §2.
- Pilot user F2: the in-person facilitator requirement means the audience reduces to "people the developer can drive to," which contradicts the global reach §2.1 invokes (Hungary, Mexico, Philippines, India, Egypt, Belarus).
- Consistency F4: §2.2's five-community enumeration is a population description while §6.3 narrows pilot to 10–15 users in 1–2 local groups not yet committed (Q4 in open-questions.md). The brief reads as describing post-v1.5 audience as if it were v1 audience.

**Impact.** Funders cross-checking §2 against §6.3 and §10 see the same gap independently. Practitioners reviewing the brief for partner-facilitation see breadth claims they would not endorse. Pilot candidates outside the developer's geography read §2.2 and cannot locate themselves in the audience description even when they fit the §2.1 threat tier. The audience description is currently load-bearing for §4.3's differentiation claim ("no current product…makes [these commitments] together for this audience"); the audience claim's overreach weakens the differentiation argument.

**Recommendation.** Restructure §2.2 to separate three distinct questions:

1. **The threat tier the architecture is designed against** (current §2.1 substance; broad and properly named).
2. **The long-term addressable population** (the five-community enumeration, framed as the populations the architecture aims to serve over its lifecycle, with explicit acknowledgment that v1 reaches a subset).
3. **The v1 pilot audience** — explicitly "10–15 users in 1–2 groups the developer has existing relationships with; the specific groups are pending per Q4." Add a population-size estimate (caveated) for the four-precondition intersection. If the honest estimate is "low hundreds globally," say so and reframe v1 as research-pilot funding (different grant category) per Funder F2.

---

## F2. Differentiation argument asserted, not evidenced; collapses against Briar/SimpleX as funded portfolio peers

**Lenses:** Funder (F1), Practitioner (P1)

**Problem.** §2.1 line 46 frames Cairn as "an integration of cryptographic primitives that already exist"; §2.3 line 100 concludes "Cairn's contribution is the layer above the protocols rather than a new protocol." Then §2.3 concedes that Briar is "refined through years of use by journalists and activists in hostile environments" (line 85) and that SimpleX is "one of the right tools for this threat tier" (line 83). The differentiation claim — that Briar/SimpleX ship protocols-as-products while Cairn ships integrated-product — is unsupported by user research, field interviews, or documented adoption-failure data.

**Evidence.**

- Funder F1: no citations, no field interviews, no quantified adoption-failure data. A committee that already funds Briar reads "Briar's protocol is correct; Briar's product is wrong" and asks why the right grant is not a Briar UX track. The brief gives no answer.
- Practitioner P1: the architectural-honesty discipline §2.1 applies to threats is not applied to audience or differentiation claims.
- §2.1 line 46 and §2.3 line 100 are also load-bearing for §4.3's competitive differentiation; if the differentiation reduces to "I will do an integration the existing project has not done," the grant case becomes an argument for funding the existing project's roadmap.

**Impact.** This is the central grant case. A program officer at OTF, Ford, or NLnet reading §2 against their existing portfolio finds the brief gives them no reason to fund Cairn over a renewal grant to a portfolio incumbent. The Cairn-vs-Briar comparison is the realistic counterfactual and the brief does not engage it.

**Recommendation.** Either (a) cite specific evidence — field interviews, named operational failures of Briar/SimpleX/Cwtch in deployments to the target population, documented partner-organization complaints — that demonstrates integration-as-product is the binding constraint and that existing projects have declined or failed to address it; or (b) reframe Cairn as a contribution to one of the existing ecosystems (a Briar UX track, a SimpleX integration shell). Without (a) or (b), the committee discussion ends at F2.

---

## F3. Co-located adversary and most-acute-user populations absent from audience construction

**Lenses:** Practitioner (F2), Pilot user (F1, Pattern 3)

**Problem.** §2 describes external adversaries and the peer-recovery network as a designated trust circle, but the user's intimate network (family, household, employer, partner) is absent. §2.2 line 52 acknowledges "users in environments where security-conscious-device-choice is itself a tell" as out of scope, but treats this as exclusion rather than the dominant compromise vector for several of the named subgroups.

**Evidence.**

- Practitioner F2: in Helpline and Front Line Defenders casework, an enormous share of mobile-device compromise of civil-society targets — particularly women journalists, women human-rights defenders, and LGBTQ+ organizers in jurisdictions where their identity is criminalized — involves a co-located adversary. The GrapheneOS-Pixel posture, the in-person provisioning ceremony, and the recovery-peer designation conversation are all visible to a co-located adversary. None of this appears in §2.
- Pilot user F1: sex workers under criminalization, domestic-abuse survivors leaving traffickers or state-protected partners, undocumented organizers, religious minorities under family surveillance, queer people in jurisdictions where queerness is criminalized, prisoners' families — all face the §2.1 threat tier and all are excluded by the §2.2 audience construction. Each lacks the peer-network precondition not as a configuration choice but as the operating condition of the abuse pattern.
- Pilot user F5: §2.2 line 66 ships v1.5 duress-wipe explicitly for the case §2.2 line 52 names as out of scope — internal contradiction.

**Impact.** §2 currently recruits users into a product that may make their situation worse (Practitioner F2: "the failure mode trainers most want to avoid endorsing"). The brief's audience construction is class-coded toward institutionally-supported, geographically-stable, network-stable users — which is the smallest subset of the §2.1 threat tier and not where its most acute cases live.

**Recommendation.** Add to §2.2 an explicit subsection — "Who this tool is and is not for when the adversary is in the room" — that:

1. Names co-located adversary as a casework-dominant pattern documented by the same organizations §2 already cites.
2. Acknowledges that v1's posture (visible distinct device, facilitator meeting, recovery-peer ceremony) is high-friction in this scenario.
3. States honestly that v1 is appropriate for users whose primary adversary is remote.
4. Names explicitly the excluded subgroups (sex workers under criminalization, abuse survivors, isolated dissidents, undocumented organizers).
5. Reconciles with §2.2 line 66 (v1.5 duress-wipe) — either the audience is in scope from v1.5 onward or duress-wipe is for a different population.

---

## F4. §2.3 landscape omits Tails, SecureDrop, OnionShare, CalyxOS — the funded portfolio peers

**Lenses:** Funder (F3)

**Problem.** §2.3 surveys Signal, Matrix/Element, Wickr, SimpleX, Briar, Session, Cwtch. Conspicuously absent: Tails (OTF / Mullvad / Tor Project portfolio; serves overlapping journalist/activist population); SecureDrop (Freedom of the Press Foundation; canonical funded tool for journalist source protection); OnionShare; CalyxOS (alternate Android-hardening platform competing for the v1 device-baseline argument).

**Evidence.** Funder F3: the omissions are the exact tools the relevant funders already fund for this audience. A committee asks "we already fund Tails for the journalist use case — why a separate messaging-only product?" and the brief has no answer because the comparison is not made. The omission also weakens §4.3's differentiation claim ("no current product…makes [these four commitments] together") — SecureDrop and Tails together make a meaningful subset of those commitments for the same audience.

**Impact.** §2.3 reads as drawn from the FOSS-secure-messaging ecosystem (the subset where Cairn looks distinctive) rather than from the funder portfolio. The differentiation argument has not been tested against the harder comparators.

**Recommendation.** Add Tails, SecureDrop, OnionShare, and CalyxOS to §2.3 with the same Problem / Where-it-falls-short structure. If the comparison is honestly favorable on specific axes, the brief is strengthened; if it is not, the brief needs to know that before committee review. This is the same discipline §2.3 already applies to the messaging-tool subset, extended to the audience's actual portfolio context.

---

## F5. "Operational discipline" framing moves user-borne cost into architectural commitment; partner-endorsable language drifts toward user-blaming

**Lenses:** Practitioner (F3, P3), Pilot user (F3, Pattern 4)

**Problem.** §2.1 line 42 names "operational discipline absent from the design" as a categorical gap; §2.2 line 71 names "the operational discipline the design assumes a support network provides" as a v1 architectural cost; §2.2 line 50 names "honestly naming the audience" as architectural commitment. The framing is technically defensible but, read from the practitioner and pilot-user side, it (a) moves a real user-borne cost into architectural language, (b) leaves "operational discipline" undefined as a concrete set of behaviors with quantified cognitive/time cost, and (c) assumes a support network that §6.3 and §8.6 explicitly do not commit (see F7 in Consistency review).

**Evidence.**

- Practitioner F3: "users who must think about it constantly" is, in casework, often a user already in trauma response. Partner organizations whose endorsement v1 needs for pilot facilitation will be sensitive to language that sounds like "if compromise happens, the user did not sustain the discipline."
- Pilot user F3: "operational discipline" is undefined; the brief lets the developer not look at what they are asking for. If the discipline genuinely requires a support network, §2.2 should say "users without a support network are not served by v1" the same way it names GrapheneOS-Pixel as a precondition.
- Pilot user Pattern 4: time, fluency, and cognitive bandwidth are treated as unconstrained; the brief assumes capacity the threat-tier population has by definition exhausted.

**Impact.** This is a posture problem with operational consequences. The language is the language partner organizations read when deciding whether to facilitate; it is the language pilot users read when deciding whether they fit the audience. The current phrasing makes Cairn's commitment harder to obtain and Cairn's audience harder to recruit honestly.

**Recommendation.** Three coordinated edits:

1. Define "operational discipline" concretely in §2.2 — a named list of behaviors with estimated cognitive/time cost per behavior — or remove the phrase and substitute what is actually being asked of the user.
2. Reframe §2.1 line 42 and §2.2 line 71 so the cost is named as the project's cost: the project commits to structural support that reduces discipline burden where it can; the residual discipline is acknowledged as a cost users absorb in exchange for the threat tier. Avoid language that positions the user as accountable for sustaining the architecture.
3. Reconcile with §6.3 and §8.6: the "support network" at v1 is the pilot user group plus the developer-as-facilitator; partner-supported operational discipline is a v1.5+ aspiration contingent on partnership outreach (Q5).

---

## F6. §2.1 "integration of existing primitives" contradicts §9.3 / §8.1 acknowledgment of substantial original cryptographic engineering

**Lenses:** Consistency (F2)

**Problem.** §2.1 line 46 frames Cairn as "an integration of cryptographic primitives that already exist." §2.3 line 100 concludes "the protocols themselves are correctly delegated." §9.3 line 962 and §8.1 line 724 explicitly acknowledge that "v1 ships substantial original cryptographic engineering (capability tokens, trust-graph operation envelope, share format per D0006, recovery-flow memory hygiene per D0003) performed without rolling external cryptographic consultation."

**Evidence.** §2.1 line 46; §2.3 line 100; §9.3 lines 960, 962; §8.1 line 724. The §§8/9 review already identified this gap; §2 has not been updated to match.

**Impact.** A program officer or technical reviewer reading §2 first builds the wrong threat model about what is audited and what is novel. The audit-budget conversation (§8.5) and the pilot-as-pre-audit risk (§9.3) both depend on a correct framing of how much original cryptographic engineering Cairn ships. §2's framing currently papers over a real engineering and audit risk the brief acknowledges elsewhere.

**Recommendation.** Revise §2.1 line 46 and §2.3 lines 91–100 to acknowledge that Cairn ships original cryptographic engineering at the integration layer — capability tokens, trust-graph operation envelope, share format, recovery-flow primitives — even though the underlying protocols (SimpleX, Briar, Tor, Sigstore, Sigsum) are delegated. The honest framing is "integration plus operational discipline plus original construction at the integration boundary." This mirrors §8.1's framing and removes the cross-section inconsistency.

---

## F7. Wickr characterization is to a product line AWS discontinued for non-enterprise users in December 2023

**Lenses:** Existing-product (F1)

**Problem.** §2.3 line 81 characterizes Wickr as a current consumer/grassroots-relevant comparator and critiques its "enterprise focus" as making it "operationally heavy for grassroots users." AWS sunset Wickr Me (the only non-enterprise tier) on December 31, 2023. The only remaining Wickr products are AWS Wickr (paid enterprise) and AWS Wickr for Government.

**Evidence.** Existing-product F1: the "enterprise focus" critique is no longer a critique — it is a description of the only Wickr that exists. The paragraph reads as drafted from a 2021 landscape snapshot.

**Impact.** A Wickr team member reads this paragraph as criticizing a product unavailable to Cairn's audience for ~2.5 years. The more interesting question — whether Wickr Me's discontinuation itself validates Cairn's "centralized service operation by a single foundation is a pressure point" thesis (the same thesis §2.3 line 77 makes about Signal) — is left on the table.

**Recommendation.** Either remove Wickr from the comparator list (it no longer competes for the audience) or rewrite the paragraph to engage with the Wickr Me sunset as evidence for the centralized-service-risk thesis. The current text criticizes a product already removed from this audience's option set.

---

## F8. Signal paragraph predates the Feb 2024 username feature; treats documented tradeoff as gap

**Lenses:** Existing-product (F2)

**Problem.** §2.3 line 77 says "phone-number identity is a tracking vector and a forcing function for telco-infrastructure dependence." Signal shipped username support stable in February 2024. The phone-number-at-registration requirement persists but has been publicly defended by Signal as a documented anti-abuse tradeoff, not an unaddressed gap.

**Evidence.** Existing-product F2: Cairn's actual differentiation — no phone number at any layer including registration — is stronger than the brief makes it sound. The current framing elides what Signal has shipped and undermines its own credibility.

**Impact.** A Signal team member reads this as a 2022 characterization. More importantly for Cairn's grant case, the differentiation argument is weakened because the brief does not engage with Signal's actual posture. The Briar and SimpleX paragraphs use a stronger framing ("correctly chosen for what it does") that the Signal paragraph would benefit from.

**Recommendation.** Update line 77 to (a) acknowledge Signal usernames and Sealed Sender, (b) note that phone-number-at-registration is a documented tradeoff Signal has defended rather than an unaddressed gap, and (c) make the Cairn differentiation explicit: no phone number at any layer, including registration. This is a stronger argument than the current text and one a Signal maintainer would recognize as fair.

---

## F9. "Just-below-state-classified" framing is off-register for civil-society funders; defense subcontractor inclusion is disqualifying for some portfolios

**Lenses:** Funder (F4)

**Problem.** §2.1 line 36 anchors the two-tier framing on "national-security tooling — the systems classified-cleared workers use for classified work" as the upper reference point. §2.2 line 59 includes "defense subcontractors in vulnerable jurisdictions" in the audience.

**Evidence.** Funder F4: the funder audience for this brief (per §10.5: OTF, Ford, OSF, MOSS, NLnet, Knight) funds civil-society and digital-rights work. The "approaching classified-tier security" frame reads as (a) market-positioning bravado triggering committee skepticism about over-claiming, or (b) defense-or-intelligence-adjacent framing actively off-mission for several named funders. "Defense subcontractors" deepens the off-register problem for foundations whose programme criteria explicitly exclude defense-adjacent work.

**Impact.** A program officer reads §2.1 and triggers a categorical concern before reaching §2.3. The framing is solvable; the consequence of not solving it is that several named funders may deprioritize before substantive review.

**Recommendation.** Reposition the upper tier in language native to civil-society funding: "tools that civil-society organizations cannot procure, operate, or audit" rather than "tools classified-cleared workers use." Reconsider whether "defense subcontractors" belongs in the v1 audience list; if the population is genuinely target-relevant, segment it explicitly and note it is out of scope for civil-society grant routing. The pilot-user lens (F9) and consistency lens both also flag this subgroup as a poor fit for the audience.

---

## F10. "9–12 months to ship soundly" and single v1.5 envelope contradict v1.5/v1.6 split and D0008 volunteer cadence

**Lenses:** Consistency (F1)

**Problem.** §2.2 line 64 says "the v1 architecture can ship soundly in 9–12 months." Line 66 collapses v1.5 into a single envelope containing Briar + post-coercion recovery flow + multi-profile UX + reproducible builds + duress-wipe. §7.1 lines 668–670 have already split this into v1.5 (architecture completeness, ~6–9 months post-v1) and v1.6 (deferred UX, ~12–15 months post-v1) per the §§8/9 review F9 and D0008's volunteer-baseline cadence (4–6 months between releases, implying v1.5 at 10–18 months).

**Evidence.** §2.2 lines 64, 66; §7.1 lines 668–670; D0008 lines 34–36. The §§8/9 review already absorbed this; §2 has not been updated.

**Impact.** Any partner or funder cross-referencing §2 against §7 sees a roadmap promise the rest of the brief has revised. Credibility cost is concrete and identical to the gap the §§8/9 review flagged as F9.

**Recommendation.** Revise §2.2 line 66 to enumerate v1.5 and v1.6 separately, mirroring §7.1's split. Either name v1.6 as the second architecture-completeness release, or restate the bullet as "v1.5 + v1.6 complete the v1 architecture in two releases — v1.5 architecture-completeness (~6–9 months post-v1), v1.6 deferred-UX (~12–15 months post-v1)." Also revise "9–12 months" if the volunteer baseline now means v1 itself slips against that target.

---

## F11. In-person facilitator requirement collapses §2.2's stated audience to "people the developer can drive to"

**Lenses:** Pilot user (F2), Practitioner (F6), Consistency (F4)

**Problem.** §2.2 line 52 requires "onboarded in person by a trained facilitator (the developer in the v1 pilot)." Line 62 conditions audience membership on "(c) can be onboarded in person by a facilitator." The roadmap (lines 64–69) addresses platform expansion (USB, iOS, mesh) but does not address facilitation-model expansion. §8.6 line 833 explicitly says "broader deployment depends on partner organizations operating as facilitator networks" — uncommitted.

**Evidence.**

- Pilot user F2: a journalist in Hungary, Mexico, the Philippines, India is not geographically reachable; a human-rights lawyer in Egypt or Belarus is not flying to meet the facilitator. The disconnect between "the population the v1 architecture is designed against" and "people the developer can meet for coffee" is left for the reader to notice.
- Practitioner F6: for the highest-threat-tier user, the in-person provisioning event is itself a casework risk event the user may not be able to absorb (observed meetings, follow-on inquiries, pressure on facilitator).
- Consistency F6: §2.2's audience-expansion framing names architectural additions as the gating variable, not facilitator capacity — but §8.6 says facilitator capacity is the dominant constraint.

**Impact.** §2.2 currently describes an audience for whom no operational path exists to becoming a user. The brief needs the reader to be able to see at a glance: "the architecture is designed for X; the v1 pilot serves Y, a small subset of X; the path to expanding from Y to X is Z."

**Recommendation.** Separate three things cleanly in §2.2: (1) what threat tier the architecture is designed for; (2) who the v1 pilot can actually onboard; (3) the path to broader audience reach. Add to the audience-expansion framing (lines 64–71) that broader-than-pilot reach depends on partner-organization facilitator networks per §8.6, not just on architectural additions. Acknowledge — per Practitioner F6 — that v1's audience is the subset of the threat tier for whom the provisioning event is operationally absorbable.

---

# Significant findings detail

## F12. "Trusted peer network of 5" is an unmet precondition for the most acute users; recovery defense requires absence of the failure mode it addresses

**Lenses:** Pilot user (F1, F6), Practitioner (F7)

**Problem.** §2.2 line 52 names "users without a peer network capable of holding recovery shares responsibly" as out of scope. Line 58 says the Recovery network surface "directly addresses the failure mode that dominates this population: peer compromise as the proximate path to user compromise." §9.2 line 881 confirms the model requires "five people they trust to act as recovery peers — geographically distributed, socially distant from each other, capable of refusing coercion under pressure."

**Evidence.** The architecture's response to peer compromise is a model that requires absence of peer compromise. Practitioner F7 documents that the "peer network capable" assumption maps poorly onto organizers (movement composition turns over rapidly), humanitarian field staff (most trusted peers are colleagues in the same operational area), and others. Pilot user F1 documents that the same precondition systematically excludes journalists whose sources are the recovery-peer-equivalent population, abuse survivors with severed networks, and queer people in criminalizing jurisdictions whose peers face the same prosecution.

**Impact.** §2.3 line 95 elevates social recovery "without centralized trustees" to a defining property; for several major subgroups in §2.2's audience, the property is undeliverable as designed. The brief currently does not acknowledge the circularity.

**Recommendation.** §2.2 should either (a) describe the conditions under which social recovery actually defends against peer compromise (peer-graph size, stability over time, independence from the user's primary adversary), or (b) commit to a v1.x non-peer recovery path (printed paper shares held by self, time-locked self-recovery, single-trustee with attorney-client privilege) and surface it in the roadmap. Differentiate the recovery-peer-feasibility assumption across the named subgroups: for whom it is straightforward, for whom it requires care, for whom it may not be viable at v1.

---

## F13. §2.1 problem framing is rhetorical, lacks citations and quantified evidence

**Lenses:** Funder (F5)

**Problem.** §2.1 lines 36–46 are composed of categorical claims without a single citation, field interview, incident report, or quantified data point. The brief elsewhere uses ID-tagged Decision Records and Open Questions; §2 does not adopt the same evidence discipline.

**Evidence.** Funder F5: grant reviewers comparing §2 against the application materials of Citizen Lab, Access Now, EFF, or Front Line Defenders see a gap in evidentiary discipline. The threat tier is real, but a committee weighting briefs that cite their evidence higher will discount §2 against competing proposals.

**Impact.** The differentiation argument depends on the threat being correctly characterized; uncited characterizations are easier to challenge than cited ones. The brief's evidentiary posture in §2 is materially weaker than in §§3, 5, and 9.

**Recommendation.** Cite specific incidents (Pegasus targets identified by Citizen Lab; Predator deployments documented by Amnesty Security Lab; specific journalist/activist arrest cases where communications were the proximate cause) with footnotes. Even three to five concrete citations transform the section's evidentiary posture. The cited incidents already exist in the public record §2's prose paraphrases.

---

## F14. Audience-expansion roadmap reads as scope-creep against §10 funding posture and §7.1 split

**Lenses:** Funder (F6), Consistency (F1)

**Problem.** §2.2 lines 64–69 lay out v1.5 / v2 / v3 / v4+, each materially expanding addressable audience. §10.1 Phase A "completes when it completes" with no committed timeline (line 1024). §10's funding ranges extrapolate to multi-million-dollar program runway. The roadmap weakens the v1 grant case by anchoring committee expectations at a scope the funding model does not support.

**Evidence.** Funder F6: the implied program runway is many years; the implied team is not on the developer's solo trajectory. Programme officers see this pattern frequently and discount accordingly. Consistency F1 separately flags the v1.5/v1.6 split issue.

**Impact.** The roadmap tries to be both ambitious (audience expansion) and humble (architectural honesty) and lands as neither.

**Recommendation.** Either (a) cut the roadmap to v1 and v1.5/v1.6 with explicit "post-v1.6 scope deferred pending funded operations" framing matching §10.4's posture, or (b) reframe v2/v3/v4 as research directions whose funding case is separate, not committed-product roadmap items.

---

## F15. Session paragraph attributes wrong cryptographic stack

**Lenses:** Existing-product (F3)

**Problem.** §2.3 line 87 says Session is "built on a derivative of the Signal Protocol." Session migrated off the Signal Protocol to its own session protocol in 2023, motivated by the multi-device problem Session's onion-routed delivery created for Signal Protocol's ratchet state.

**Evidence.** Existing-product F3: the migration itself supports Cairn's claim that Session's roadmap is set by Session and may not align with what high-threat-tier users need. The factual error is a credibility hit without strengthening the argument.

**Impact.** A Session team member flags this as factual error; a careful reviewer notes the brief is calendar-dated.

**Recommendation.** Change "derivative of the Signal Protocol" to "its own session protocol (migrated off Signal Protocol in 2023)" and note that the migration itself illustrates the dependency-trajectory concern the paragraph already raises.

---

## F16. Matrix paragraph elides MLS migration and Element/MAS metadata work

**Lenses:** Existing-product (F4)

**Problem.** §2.3 line 79 critiques Matrix's "many ways for clients to disagree about state" — a class of bugs MLS migration is designed to eliminate. Matrix has been actively migrating to MLS (RFC 9420) with implementations shipping in Element X through 2024–2025.

**Evidence.** Existing-product F4: the substantive critique (federation pushes metadata problem to the homeserver) remains accurate, but the encryption-protocol-state critique targets a deprecated class.

**Impact.** Citing a known-deprecated problem weakens the credibility of the paragraph's stronger structural critique.

**Recommendation.** Update line 79 to acknowledge the MLS migration and confine the complexity critique to the federation surface (which remains accurate) rather than the encryption-protocol-state surface (which is being addressed).

---

## F17. Briar paragraph understates Briar Mailbox, which addresses one of the named gaps

**Lenses:** Existing-product (F5)

**Problem.** §2.3 line 85 says Briar has "no integrated recovery model beyond Briar-specific account export." Briar Mailbox (released stable 2023) materially changes this framing.

**Evidence.** Existing-product F5: Briar Mailbox is not full social recovery in Cairn's sense, but it extends the integration surface in ways relevant to Cairn's argument.

**Impact.** A Briar maintainer would note the paragraph characterizes Briar by what it lacked at v1.0, not what it ships today.

**Recommendation.** Update line 85 to acknowledge Briar Mailbox specifically and distinguish "Briar lacks integrated social recovery as Cairn defines it" (true and fair) from "Briar's recovery model is account export only" (no longer accurate).

---

## F18. Comparator set omits Threema, Wire, Keet, Olvid — products audience actually uses today

**Lenses:** Existing-product (F6), Funder (F10)

**Problem.** §2.3 covers Signal, Matrix/Element, Wickr, SimpleX, Briar, Session, Cwtch. Threema (Swiss-jurisdictional, ID-not-phone-number, paid product, used by Swiss government and several European militaries for unclassified comms) is the closest existing analogue to Cairn's "identifier-less, jurisdiction-aware, paid-and-deliberate" positioning. Wire (Swiss/German, used by EU institutions), Keet (Holepunch P2P), and Olvid (no-identifier French messaging used by parts of French government) are also relevant.

**Evidence.**

- Existing-product F6: their absence is a tell that the comparator set was drawn from the FOSS-secure-messaging ecosystem rather than from the audience's actual option set. Funders and partners reading §2.3 will know Threema (it is what several named target audiences actually use today as their non-Signal option).
- Funder F10: Threema and Olvid intersect Cairn's identifier-less and trust-graph claims; their absence reads as incomplete landscape work.

**Impact.** The unstated answer to "why not Threema?" (centralized, paid, Swiss-jurisdictional company) is exactly the structural critique §2.3 is otherwise good at making — Cairn loses an argument it would win.

**Recommendation.** Add Threema specifically. Wire and Olvid optional but recommended; Keet is the closest non-Tor P2P comparator to Briar/Cwtch. The critique writes itself.

---

## F19. Pilot recruitment from developer's social network elides consent-exit dynamics IRB-equivalent protocols require

**Lenses:** Practitioner (F4)

**Problem.** §2.2 line 62 says the pilot draws from "groups the developer has direct relationships with so the facilitator role can be sustained at pilot scale." When the population is in social relationship with the developer, refusal of any pilot element (device, identity provisioning, recovery-peer designation, feedback channels) carries social cost. §2 contains no language on how the pilot handles a user who wants to leave, refuse a feature, or report that the tool made their situation worse without that report carrying friction with their social relationship to the developer.

**Evidence.** Practitioner F4: this dynamic is standard practice in academic IRB-reviewed protective-tech studies; Front Line Defenders' own protection-work guidance specifically flags it. Partner organizations may require it explicitly before facilitating.

**Impact.** Pilot reports of negative outcomes are filtered through social cost the brief does not acknowledge. The "evidence" the pilot generates may be biased toward favorable feedback by exactly the mechanism the practitioner community most distrusts.

**Recommendation.** Add a short paragraph (in §2.2 or referenced from it) on pilot consent and exit: how informed consent is obtained when the recruiter is also the facilitator and a member of the social network; how a pilot user reports negative outcomes through a channel that is not the developer; what happens if a pilot user wants to stop using the tool mid-pilot.

---

## F20. §2.2 "supplied with GrapheneOS-Pixel hardware" contradicts §10.1 BYOD posture

**Lenses:** Consistency (F5)

**Problem.** §2.2 line 62 says v1 users "have access to or can be supplied with GrapheneOS-Pixel hardware." §10.1 line 1042 explicitly says "the bulk of pilot deployment is BYOD: pilot users source their own GrapheneOS-capable Pixel devices."

**Evidence.** Consistency F5: the "supplied with" framing was correct under a pre-D0008/§10 funding posture; it does not match the volunteer baseline.

**Impact.** Users who cannot acquire a Pixel themselves are not part of the v1 audience under §10.1 BYOD posture, but §2.2 implies they are.

**Recommendation.** Revise §2.2 line 62 to "have access to GrapheneOS-Pixel hardware" without the "or can be supplied with" clause. Alternatively, narrow the v1 audience definition to BYOD-capable users in §2.2 matching §10.1.

---

## F21. §2 introduces solo-developer / single-foundation aspiration that contradicts §4.3 multi-party commitments

**Lenses:** Consistency (implied via §10 cross-references), Funder (F8)

**Problem.** §2.1 line 46 commits to integration plus operational discipline. §4.3 line 287 commits to multi-party release security with 5+ external reviewer pool and 3-of-5 attestation. §10.1 line 1024 commits Phase A to developer's "as available" cadence. §10.3 line 1086 funds reviewer-pool honoraria only at Phase C.

**Evidence.** Funder F8: the architectural commitment that distinguishes Cairn from Signal et al. is multi-party release security; the funding posture is solo-volunteer until Phase C closes. If Phase C does not close, the multi-party reviewer pool reverts to volunteer-attestation, and §4.3 weakens correspondingly.

**Impact.** §2 does not surface this dependency, so a sophisticated committee finds it themselves and asks an uncomfortable question.

**Recommendation.** In §2.3 or §2.2, name the dependency between the differentiation claims and the funding sequence honestly: "the multi-party release-security commitment is structurally dependent on Phase C honoraria funding; the volunteer-attestation baseline (§8.2) is the operational fallback." This honesty is consistent with the brief's overall posture and pre-empts the harder version of the same question.

---

## F22. English-only / professional-category framing leaves language scope and non-institutional populations implicit

**Lenses:** Practitioner (F10), Pilot user (F4)

**Problem.** §2.2 enumerates audience subgroups by professional category (journalists, NGO staff, organizers, defense subcontractors, civil-society researchers) — institutionally-defined categories. The brief is written in English and assumes English-speaking professional categories. §2.2 never names language localization as an audience question.

**Evidence.**

- Practitioner F10: v1 likely ships English-only; the populations §2.2 names operate in dozens of languages where security-tool localization is the operational gate.
- Pilot user F4: a Tigrinya-speaking dissident in the Eritrean diaspora, a Dari-speaking journalist in Afghanistan, a Uyghur diaspora organizer — exactly the §2.1 threat tier — do not appear in §2.2's enumeration except by implication.
- Pilot user Pattern 3: populations the threat tier centrally includes (sex workers, abuse survivors, undocumented organizers, queer people in criminalizing jurisdictions, religious minorities under family surveillance, low-income tenant organizers, prisoners' families) face the threat but lack the institutional channels through which the brief recruited its understanding of the audience.

**Impact.** §2's audience description is class- and institution-coded; from inside the threat tier, the population recognized as itself is small.

**Recommendation.** §2.2 should name language scope honestly ("v1 ships in English; the audience is therefore limited to English-comprehending users in the threat tier") and acknowledge non-institutional populations as in-scope-for-the-threat-tier-but-out-of-scope-for-v1-pilot. Acknowledging localization as a v1.5 or v2 commitment, with implications for primary audiences in non-English-dominant jurisdictions, lets users see whether they are in scope.

---

## F23. §2.3 "defeats impersonation attacks" overstates §9.3 "principal defense" / residual surface

**Lenses:** Consistency (F8)

**Problem.** §2.3 line 95 says peer verification "defeats" impersonation attacks. §9.3 line 931 says peer verification is "the principal defense" — not a defeat. "Defeats" implies the attack class is closed; "principal defense" acknowledges residual surface.

**Evidence.** §2.3 line 95; §9.3 line 931; §9.2 line 881. The §4.2 "honest about limits" principle and §5.6 "calibrated language" principle apply to §2.

**Impact.** §2 promises a closure §9 explicitly names as residual. Reviewers cross-checking the two find a calibration drift toward overclaim in the audience-facing section.

**Recommendation.** Revise §2.3 line 95 to "with peer-verification mechanisms that raise the cost of impersonation attacks (D0005)" or similar calibrated language. "Defeats" conflicts with §9.3's residual-surface acknowledgment.

---

## F24. §2.2 names "security-conscious-device-choice as a tell" as out of scope while v1.5 ships duress-wipe for exactly that case

**Lenses:** Pilot user (F5), Consistency (related to F4)

**Problem.** §2.2 line 52 names users "in environments where security-conscious-device-choice is itself a tell beyond what they can absorb" as out of scope. §2.2 line 66 says v1.5 ships the duress-wipe pattern, which explicitly serves exactly that case.

**Evidence.** Pilot user F5: the duress-wipe roadmap item shows the developer has been thinking about this population, but §2.2 still names them as out of audience.

**Impact.** Internal contradiction visible to any reader of §2.2 alone; partner-organization reviewers reading both lines see the brief contradicting itself within ten lines.

**Recommendation.** Reconcile §2.2 line 52 with §2.2 line 66. Either the audience is in scope from v1.5 onward and §2.2 should name them, or duress-wipe is for a different population and §2.2 should clarify which.

---

# Minor findings

- **F25.** Practitioner F8: "authoritarian contexts" is the only national-political-system descriptor used; reproduces Western-threat-is-elsewhere framing. Pegasus targets in EU member states (Greece, Hungary, Poland, Spain) and US targeting of environmental/Indigenous organizers do not fit. Replace with "organizers whose coordination activity is itself the subject of state interest" (§2.2 line 58 already uses this).
- **F26.** Practitioner F9: §2.1 line 44 "intellectual property is itself a target" imports corporate-security frame; reframe as "work adjacent to national-security material their employers cannot fully protect them on."
- **F27.** Practitioner F6: in-person provisioning is itself a casework risk event for highest-tier users; acknowledge that pilot audience is the subset of the threat tier for whom the provisioning event is operationally absorbable.
- **F28.** Existing-product F7: §2.3 line 77 names "a single foundation" but does not name Signal Foundation; line 81 names AWS by name. Make consistent.
- **F29.** Existing-product F8: SimpleX paragraph describes SimpleX Chat circa 2022; current product has shipped contact/group/profile model and preset-server UX. Either tighten the critique to what is still fair (no integrated identity model that propagates trust across the user's social network) or acknowledge what SimpleX Chat has shipped.
- **F30.** Existing-product F9: Cwtch paragraph is generic; engage with untrusted-group-server pattern as distinct from Briar's P2P-over-Tor approach, or note explicitly that §2.3 defers protocol-level distinction to §5.4.
- **F31.** Pilot user F7: "trained facilitator" is undefined; add forward reference to §6.3 or §8.6 where training is specified.
- **F32.** Pilot user F8: civil-society researcher subgroup conflates Citizen Lab–type researchers (institutional support, mature OPSEC) with their analyzed subjects (whose architecture-appropriateness differs). Separate.
- **F33.** Funder F9: "Identifier-as-vulnerability" critique adds nothing the committee has not heard from existing SimpleX/Briar grantees. Compress and reframe as "Cairn inherits SimpleX's identifier-less queue model; the contribution is the operational discipline above it."
- **F34.** Funder F11: §4.2 "calibrated language" commitment claimed elsewhere is itself absolute-sounding in §2 ("full state capability," "the upper end," "torture or death in custody"). Apply calibration discipline retroactively.
- **F35.** Pilot user F10: "honest"/"honestly" appears three times in §2.2 (lines 50, 52, 71). Cut the rhetorical claim; let the structural choices speak.
- **F36.** Consistency F10: §2.2 places civil-society researchers in the user category; §8.6 places them primarily in the threat-intel collaborator category. The local-pilot constraint (§6.3) and §8.6 framing suggest they are more naturally a research-collaboration relationship than a v1 user population. Clarify.

---

# Pattern observations

Eight patterns recur across these findings:

**P1. Architectural honesty extends to threats but not to user populations.** §2.1's threat description is properly hedged ("varies sharply by jurisdiction," "casual-privacy use cases where its operational discipline would be friction"). §2.2's audience description is not similarly hedged. Caught by Practitioner P1 directly; F1, F3, F11, F12 all manifest this. The honesty discipline applied to the threat tier should be applied to the audience taxonomy.

**P2. The user's intimate network is missing from §2.** §2 describes external adversaries, network adversaries, and the peer-recovery network as a designated trust circle. The user's family, household, employer, romantic relationships, and the social proximity of the developer-as-facilitator to the pilot population are absent. In casework these are first-order determinants of whether a tool can be safely adopted. Findings F3, F12, F19 all manifest this. Caught directly by Practitioner P2.

**P3. "Architectural commitment" language compresses costs the user pays into features the project ships.** §2.1's "operational discipline" framing and §2.2's "architectural cost… justifiable for that population" framing name real properties but in language that moves the cost into the architecture and out of the user's lived experience. Practitioner P3 and Pilot user Pattern 4 catch this independently. F5 is the central manifestation; F11, F22 show the pattern propagating.

**P4. §2 carries language predating the §§8/9 review and the D0008/D0010/D0011 / §10 revisions.** F6 (integration vs. original cryptographic engineering), F10 (9–12 months and v1.5 envelope), F14 (roadmap vs. funding posture), F20 (project-supplied hardware vs. BYOD), and the support-network framing in F5 all read as §2 language predating later sections' revisions. §2 is the door the reader walks through; it should reflect the brief the reader is about to read. Caught directly by Consistency Pattern 1.

**P5. §2 drifts toward closure language §9 explicitly names as residual.** F23 ("defeats impersonation" vs. "principal defense"), F11 (in-person provisioning as security property without acknowledging it is also a casework risk), F5 (architectural commitment vs. user-borne cost) all reduce qualifications later sections preserve. The §5.6 "calibrated language" commitment is a UX commitment; §2 should hold the same calibration with funders and reviewers as the UI holds with users. Caught directly by Consistency Pattern 2.

**P6. §2.3 is calendar-dated to 2021–2022 product states.** F7 (Wickr Me sunset Dec 2023), F8 (Signal usernames Feb 2024), F15 (Session protocol migration 2023), F16 (Matrix MLS 2024–2025), F17 (Briar Mailbox 2023), F29 (SimpleX Chat current product) all show the same pattern. A maintainer of any of these products would notice. The fix is a calendar pass: for each comparator, what has shipped in the last 24 months that touches the specific critique the brief makes? Caught directly by Existing-product Pattern 1.

**P7. §2 treats documented design tradeoffs as gaps.** F8 (Signal phone-number-at-registration), F16 (Matrix federation choice) treat tradeoffs as unaddressed gaps. The Briar and SimpleX paragraphs already use a stronger framing ("correctly chosen for what it does"); the Signal and Matrix paragraphs would be stronger if they used it too. Caught directly by Existing-product Pattern 2.

**P8. Comparator-set and audience-set selection bias produces the same effect twice.** §2.3 is drawn from the FOSS-secure-messaging ecosystem; §2.2 is drawn from professional categories with institutional backing. Both omit the harder comparisons (Tails / SecureDrop / Threema for §2.3; co-located-adversary populations, non-institutional populations, non-English-language populations for §2.2). The differentiation argument and the audience argument both have not been tested against the harder cases. F4, F18, F22, and Pilot user Pattern 3 all manifest this.

---

# Action plan

Findings break into four action categories. The pattern from the §§8/9 review holds here: §2's design discipline at the threat-tier level is strong; the gaps cluster at the level of specific commitments not living up to the section-level posture. Closing them does not require revising the strategy, only the prose — with two exceptions noted below.

## A. Prose edits to §2 — surgical, straightforward.

Findings amenable to direct prose application without further decision-making:

- **F1** — restructure §2.2 audience description into three layers (threat tier / long-term population / v1 pilot specifically); add population-size estimate.
- **F3** — add "Who this tool is and is not for when the adversary is in the room" subsection to §2.2.
- **F4** — add Tails, SecureDrop, OnionShare, CalyxOS to §2.3 with Problem/Where-it-falls-short structure.
- **F5** — reframe "operational discipline" as project-borne where structural support reduces it; define remaining cost concretely; reconcile with §6.3/§8.6.
- **F6** — revise §2.1 line 46 and §2.3 line 100 to acknowledge original cryptographic engineering at the integration boundary, mirroring §8.1 framing.
- **F7** — remove or rewrite Wickr paragraph engaging with Wickr Me sunset.
- **F8** — update Signal paragraph for usernames + Sealed Sender; reframe phone-number-at-registration as documented tradeoff.
- **F9** — reposition upper tier away from "classified-cleared workers" framing; address defense subcontractor inclusion.
- **F10** — split v1.5 / v1.6 in §2.2; revise "9–12 months" against volunteer baseline.
- **F11** — separate architecture-designed-for vs. v1-pilot-actually-serves in §2.2; name facilitator capacity as expansion bottleneck per §8.6.
- **F13** — add 3–5 specific citations (Pegasus, Predator, named casework) to §2.1.
- **F15–F18** — Session protocol migration; Matrix MLS; Briar Mailbox; Threema/Wire/Olvid additions to §2.3.
- **F20** — revise "supplied with" hardware language to match §10.1 BYOD.
- **F21** — name multi-party-release-security / funding-sequence dependency in §2.3.
- **F22** — name language scope; acknowledge non-institutional populations as in-scope-threat-tier-but-out-of-scope-v1.
- **F23** — calibrate "defeats" → "raises the cost of."
- **F24** — reconcile §2.2 line 52 with line 66 (duress-wipe audience).
- **F25–F36** — minor wording, calibration, and consistency fixes per the minor-findings list.

Total: ~24 prose edits, most surgical, several requiring 1–3 paragraphs of new text.

## B. New decision documents — judgment calls required.

- **D0013 — Pilot consent and exit protocol** (F19). When the recruiter is also the facilitator and a member of the social network, what informed-consent process applies; how pilot users report negative outcomes through non-developer channels; what happens if a pilot user wants to stop using the tool mid-pilot. References standard IRB-equivalent protective-tech-study practice. Likely required by partner organizations before facilitating.
- **D0014 — Non-peer recovery path policy** (F12). The architectural decision about whether the most acute users (no peer network, severed network, peer network = adversary network) are addressed at v1, v1.x, or are honestly named as out-of-scope. Options to consider: printed paper shares held by self; time-locked self-recovery; single-trustee with attorney-client privilege; explicit no-recovery option with documented user consent. The current implicit posture (out of scope for v1) is not consistent with §2.1's threat-tier claim.

These two decisions cannot be made by prose edit alone because they have architectural implications.

## C. Architectural-claim reframing — register adjustments.

- **F2** — the differentiation argument needs evidence (field interviews, named operational failures of Briar/SimpleX in target deployments) or the project needs to reframe as a contribution to an existing ecosystem. This is the central grant case; it cannot be solved by prose alone. The author should decide between (a) commissioning the evidence — likely 4–8 weeks of interviews with practitioners and partner organizations — or (b) reframing toward an existing ecosystem. Until this is resolved, §2's grant-case credibility is structurally limited.
- **F14** — audience-expansion roadmap needs to either cut to v1/v1.5/v1.6 with explicit post-v1.6 deferral framing, or reframe v2/v3/v4 as research directions with separate funding cases. Trying to be both ambitious and humble fails both registers.

## D. New open questions.

- **Q17** — Population-size estimate for the four-precondition v1 intersection across the five named communities (input to F1). If this is "low hundreds globally," v1 is research-pilot funding; if materially larger, the basis needs citing.
- **Q18** — Evidence basis for the integration-as-product differentiation argument (input to F2). What field interviews, partner consultations, or documented operational failures will be commissioned to support the claim before grant submission?
- **Q19** — Localization and non-English-language audience scope by version (input to F22). When does v1.x acknowledge non-English-dominant populations as in-scope?
- **Q20** — Pilot consent / exit protocol (input to D0013). What IRB-equivalent process applies; what partner-mediated reporting channel exists?

## E. Items to reject with rationale.

- **None** of the lens findings warrant rejection. The 47 raw findings (24 consolidated) all identify real gaps; the question for each is whether the gap is addressed by prose edit, decision document, or open question — not whether the gap is real.
- One framing in the practitioner lens (F8: "authoritarian contexts" → use Western-jurisdictions-too phrasing) should be applied as a minor edit rather than triggering a broader scope review; the brief's §2.2 line 58 already uses the better phrasing the practitioner recommends, so the fix is internal consistency rather than scope expansion.

---

# Strategic note

This review is smaller in volume than the §§8/9 review (24 consolidated findings vs. 30) but more concentrated in critical-severity findings (11 vs. 12 against fewer total findings). The reason is that §2 is shorter than §§8/9 combined but more load-bearing per word: every claim in §2 is the first claim the reader meets about Cairn, and every framing decision in §2 is the framing that propagates through how funders, partners, and pilot candidates read the rest of the brief.

The most actionable single edit is the §2.2 restructure in F1 — separating threat tier / long-term population / v1 pilot — because it addresses F1, F3, F11, F12, F20, F22, and partially F14 simultaneously. The single highest-leverage decision document is D0014 (non-peer recovery path), because it determines whether §2.1's threat-tier claim is delivered to its most acute users by v1, v1.x, or never. The single most consequential unresolved question is F2 — whether Cairn's differentiation can be evidenced as a separate project vs. a Briar UX track — because if the answer is "this is a Briar UX track," the rest of §2's prose-edit work matters less.

The brief's overall §2 posture — architecturally honest about threat, narrow at v1, intentional about audience — is the right posture for the threat tier described. The gaps are at the level of specific commitments not living up to the section-level posture; closing them does not require revising the strategy, only the prose and two architectural decisions.
