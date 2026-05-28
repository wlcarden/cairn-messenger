# Section 10 Adversarial Review — Consolidated Findings

**Date:** 2026-05-28
**Source:** Five parallel sub-agent reviews, distinct lenses (grantmaker actionability, audit-budget defensibility, phase-boundary discipline, sophisticated funder honest-disclosure, sustainability vs maintainer-comp aspiration).
**Raw findings:** 51 across reviewers (Critical 17, Significant 18, Minor 16). After deduplication and theming: 26 consolidated findings below.
**Companion to:** [design-brief.md](design-brief.md) §10, with cross-references to §6.3, §8, §9.1, and the decision documents D0008–D0012.

§10 was drafted in the current revision cycle and has not been audited against the rest of the brief. Several of the findings below are internal contradictions between §10's new phase-gated model and earlier sections that the drafting cycle has not yet reconciled.

---

## Executive summary

Across five lenses the consolidated posture is consistent: §10's phase-gated model is the right structural substrate but is administratively under-actionable, financially understated at multiple bound calculations, internally inconsistent with §6.3 and §8.2, and silent on the sustainability question its own Phase D framing makes load-bearing. The §10.8 "what this section does not promise" set disclaims first-order outcomes but not the second-order infrastructure (subsidy programs existing, partners converting, hardware availability, rate-card stability, fiscal-sponsor fee absorption) on which the first-order numbers depend. The §9.1-committed self-funding runway in calendar months — explicitly named by §9.1 as the financial floor of all v1 funding-related risk discussions and as a thing §10 would deliver — does not appear in §10 and is not flagged as omitted.

The most consequential single class of findings is the cluster of internal contradictions §10 has introduced since drafting: the BYOD pilot model (§10.1, §10.3) directly contradicts §3.3 and §6.3, which place the developer in the supply chain with $5-12K project-absorbed pilot hardware; reviewer honoraria are placed in Phase C while §8.2 names Phase B grant-closing as the trigger; foundation incorporation is placed in Phase C with a budget that assumes Phase B legal-consultation work has already happened; and rolling cryptographic consulting is filed as a Phase B aspiration to cover what §10.1's own definition calls Phase A "design-and-implementation" work. These are not stylistic discrepancies — they break the phase model's central promise that "what does my dollar unlock?" has a clean answer per phase.

The most consequential single finding by impact is the unnamed sustainability cliff at Phase D: §10.4 budgets every contributor in the foundation's workflow (auditors, reviewers, accountants, board, translators) except its primary engineer-operator, and §10.5/§10.6 contain no source category that routinely funds multi-year engineering salary at security-engineering market rates. The brief presents Phase D as steady-state and names maintainer comp as "aspirational" without bounding the volunteer-time horizon, which makes the most likely Phase D trajectory — uncompensated developer continuing to absorb foundation operations indefinitely — look like the plan rather than the structural cliff it is. The brief's honest-disclosure posture, rigorous everywhere else, softens at exactly this seam.

---

## Severity Distribution

- **Critical (F1–F8):** 8 findings. Internal contradictions, structurally false bounds, breach of §9.1 commitment, sustainability cliff not named, subsidy-route conflation, BYOD/§6.3 contradiction. These materially mislead funders or break the phase model.
- **Significant (F9–F19):** 11 findings. Unstated dependencies, missing disclaimers, arithmetic-bound understatements, phase-boundary leaks with operational consequences.
- **Minor (F20–F26):** 7 findings. Prose-level imprecision, line items that are padding or cleanup, narrow disclaimer gaps.

---

## Consolidated findings table

| ID  | Severity    | Lens(es)               | Short title                                                                                                                                                                                         | Primary citation                                              |
| --- | ----------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| F1  | Critical    | D, all others adjacent | BYOD pilot model directly contradicts §3.3/§6.3 developer-in-supply-chain commitment                                                                                                                | §10.1:1042; §10.3:1089; §6.3:630; §6.3:638; §3.3:168          |
| F2  | Critical    | A, B                   | $17K Phase B floor is arithmetic, not addressable by any named instrument; $15K subsidized audit floor inconsistent with 1-2 person-week scope                                                      | §10.2:1063; §10.2:1068; §10.2:1071; D0011:10                  |
| F3  | Critical    | E                      | Phase D sustainability cliff — labor that operates the foundation is unfunded and unnamed in source roster                                                                                          | §10.4:1106-1115; §10.4:1117; §10.5:1119-1140; §10.6:1141-1149 |
| F4  | Critical    | D                      | §10 does not deliver the self-funding runway §9.1 explicitly committed §10 would deliver                                                                                                            | §9.1:857; §10.1:1043; §10.8:1162-1172                         |
| F5  | Critical    | A, B, D                | Four "subsidy programs" conflate grant programs, vendor discounts, and integrated-dev-grant audit allocations; OTF entity-eligibility prerequisite interacts with Phase B fiscal-sponsor sequencing | §10.5:1124-1128; §10.2:1063; §10.2:1071; §10.6:1147; §10.8    |
| F6  | Critical    | C                      | Reviewer honoraria placed in Phase C contradict §8.2's Phase B grant-closing trigger                                                                                                                | §10.3:1086; §8.2:740; §10.1:1049                              |
| F7  | Critical    | C                      | Foundation incorporation (Phase C) has unstated dependency on Phase B legal-consultation completion                                                                                                 | §10.3:1087; §10.2:1061; §8.4:787-794                          |
| F8  | Critical    | A                      | No named ask, no deliverable schedule tied to tranches, no reporting cadence — §10 produces no artifact a grant committee can act on                                                                | §10 throughout; §10.8:1172                                    |
| F9  | Significant | C, D, B                | Pre-incorporation legal consultation straddles Phase A/B with no resolution rule and breaks the floor calculation                                                                                   | §10.2:1061; §10.1:1043; §10.5:1123; §10.6:1146; §10.2:1068    |
| F10 | Significant | B                      | $150K Phase C pre-beta ceiling sized only for Cure53/Quarkslab; Trail of Bits / NCC Group at stated scope is $180-240K                                                                              | §10.3:1085; §8.5:809; D0011:10,38                             |
| F11 | Significant | C                      | "Rolling cryptographic consulting" filed as Phase B aspiration covers Phase A work; leverage window may close before Phase B funding lands                                                          | §10.2:1073; §10.1:1029; §8.1:724; §8.5:804                    |
| F12 | Significant | D                      | Phase B-D figures are gross of fiscal-sponsor fees (5-15%); net-to-project receipt is materially smaller                                                                                            | §10.2:1062; §10.3:1093-1094; §10.4:1112-1115                  |
| F13 | Significant | A, D                   | Eleven-funder roster (§10.5) not mapped to phase items, instrument size, or current program-line viability                                                                                          | §10.5:1119-1140; §10.6:1147-1148                              |
| F14 | Significant | D                      | Subsidy-program existence and openness over Cairn's 6-24 month application horizon not disclaimed                                                                                                   | §10.2:1063,1071; §10.3:1085; §10.5:1124-1128; §10.8           |
| F15 | Significant | A, D                   | Fiscal-sponsor onboarding timing (2-6 months) understated; figures conflate cycle calendar with fee absorption                                                                                      | §10.2:1062; §10.6:1146                                        |
| F16 | Significant | E                      | $150-250K/FTE figure under-states actual labor scope (engineering + operations + governance interface = 1.5-2.0 FTE)                                                                                | §10.4:1117; §8.1:722-727; §8.4:798; D0009                     |
| F17 | Significant | C, D                   | Phase D foundation overhead presupposes Phase C incorporation closed; no scenario branch for foundation-failed case                                                                                 | §10.4:1108; §10.3:1087; §10.7:1160; §10.4:1112                |
| F18 | Significant | C                      | Phase D "recurring audit cycle" amortization hides a Phase-E-like discrete gate ($60-150K at month 18-24)                                                                                           | §10.4:1106; §8.5:815; §10.3:1085                              |
| F19 | Significant | C, D                   | UX engineer "optional in one sense, in-scope in another" framing returns work to Phase A's open-ended cadence under Phase C-floor outcomes; §10.8 silent                                            | §10.3:1088; §10.3:1093; §10.3:1098; §10.1:1024                |
| F20 | Minor       | B                      | Reviewer honoraria arithmetic ($2,000-5,000 × 5 × 4) implies per-hour rates below or above stated $150-300/hr market band at floor/ceiling                                                          | §10.3:1086; §8.2:740                                          |
| F21 | Minor       | B                      | UK CIC $5K incorporation floor optimistic when IP-assignment-transfer counsel time is included                                                                                                      | §10.3:1087                                                    |
| F22 | Minor       | A, E                   | Maintainer-comp $150-250K stated as US-equivalent without EU jurisdiction range; foundation overhead $10-30K low for security-critical product foundation                                           | §10.4:1117; §10.4:1108                                        |
| F23 | Minor       | D                      | 18-24 month foundation-incorporation timing repeated four times in brief, escapes §10.8 timeline-disclaim net                                                                                       | §3.4:210; §8.4:766,777,796; §10.2:1075; §10.8:1167            |
| F24 | Minor       | C                      | Phase A "2-4 Pixel devices" includes loaner-pool pre-positioning for Phase B work                                                                                                                   | §10.1:1042; §10.1:1051                                        |
| F25 | Minor       | C                      | Phase B $0-500/yr infrastructure line and Phase C "minimal incremental cost" hardware line are inventory padding                                                                                    | §10.2:1064; §10.3:1089                                        |
| F26 | Minor       | A, B                   | Vocabulary and roster: "subsidy programs close" misvocabulary; Trail of Bits "civic-tech rates" framing overstates as program; Internews and Digital Defenders Partnership omitted                  | §10.2:1063; §10.5:1119-1140; §10.7                            |

---

# Critical Findings

## F1. BYOD pilot model contradicts §3.3/§6.3 developer-in-supply-chain commitment

**Category:** Cross-section internal contradiction
**Location:** §10.1:1042 ($1,500-3,000 project pool, BYOD bulk); §10.3:1089 (BYOD pilot model continues); §6.3:630 (project provides devices); §6.3:638 ($5-12K pilot hardware out-of-pocket); §3.3:168 (developer becomes the supply chain)
**Reviewers:** Lens D F2 (primary); cross-noted by Lens C in pattern P3 and Lens A as undisclosed cost shift.

**Issue.** §10.1 commits Phase A to a 2-4 Pixel device project pool with "the bulk of pilot deployment is BYOD: pilot users source their own GrapheneOS-capable Pixel devices." §10.3 reinforces this for Phase C: "minimal incremental cost under the BYOD pilot model." But §6.3 line 630 commits "The project provides devices for pilot users: GrapheneOS-installed Pixel hardware with the Cairn application pre-installed," and §6.3 line 638 budgets $5-12K (10-15 Pixel devices) "out of pocket through v1 launch." §3.3 line 168 frames the developer-as-supply-chain as a core architectural property of pilot trust: "the developer purchases Pixel devices, installs GrapheneOS, installs the application, and provisions identities for users — meaning the developer becomes the supply chain for the pilot." §10.1 inverts the model to reduce the Phase A absorbed cost from $5-12K (per §6.3) to $1,500-3,500 (per §10.1).

**Why it matters.** A funder reading §10 alongside §6.3 sees a direct internal contradiction. Either §10 silently relaxes the §3.3/§6.3 commitment to make the Phase A volunteer-baseline figure look manageable, or §6.3 will be revised but §10 has run ahead without the revision landing. The threat-model implication is non-trivial — §3.3's supply-chain analysis treats developer-sourced hardware as a documented and analyzed trust placement; BYOD shifts that placement to pilot users sourcing through "standard channels" without analyzing what those channels mean for the supply-chain surface. The Phase A absorbed-cost figure is understated by $5-9K either way: if §6.3 holds, the figure is wrong; if §10.1 holds, §6.3 needs revision and §3.3's supply-chain analysis needs updating.

**Recommendation.** Decide which model holds and propagate. Either:

- (a) Reconcile §10.1/§10.3 with §6.3: state explicitly in §10 that the pilot model has moved from project-provisioned to BYOD; update §6.3 and §3.3 accordingly; document the supply-chain analysis change (BYOD shifts the surface from "developer-curated" to "pilot-user-curated through documented channels," with different residual exposure); and add to §10.8 a hardware-availability disclaimer for the BYOD assumption.
- (b) Restate §10.1 to match §6.3: $5-12K project-absorbed hardware in Phase A, with the Phase A absorbed total rising to roughly $6.5-15K.

Whichever model is chosen, §3.3, §6.3, and §10 must all carry the same model. The current state — three sections describing three different supply-chain postures — is the disclosure issue regardless of which is right.

---

## F2. Phase B $17K floor is arithmetic, not addressable; $15K subsidized audit floor inconsistent with 1-2 person-week scope

**Category:** Bound calculation / funder credibility
**Location:** §10.2:1063 ($15-30K subsidized pre-pilot audit); §10.2:1068 ($17K Phase B floor); §10.2:1071 (single subsidy close covers Phase B); §8.5:808 / D0011:27 (1-2 person-week scope); D0011:10 ($15-40K/wk at named firms)
**Reviewers:** Lens A F7; Lens B F1; mutually reinforcing.

**Issue.** Two independent reviewers identified the same structural problem from different directions. Lens A: no named instrument exists that writes a $17K grant doing what §10.2:1071 implies — OTF Secure Audit awards do not size at $17K, NLnet NGI Zero Trust small grants are €50K, Cure53 mission engagements are scoped per audit not per dollar. The $17K figure is the arithmetic sum of independently-funded items ($1,500 absorbable legal + $15K subsidized audit + $500 infrastructure), not an addressable grant request. Lens B: the $15K subsidized audit floor for 1-2 person-weeks of senior auditor time is inconsistent with the named subsidy programs' actual effective rates. Cure53 mission rates with the typical 30-50% civil-society discount land one week at ~$10-20K and two weeks at $20-40K; OTF Secure Audit historical awards for comparable scope cluster at $20-40K. A $15K floor implies either ~0.75 person-week (insufficient for the four scope items D0011 names) or a subsidy depth no public engagement summary corroborates.

**Why it matters.** "Phase B floor" is the figure funders cite as "smallest grant that materially advances the project." If the addressable floor is $25-30K (Cure53 mission-rate small engagement with developer-absorbed legal consultation) or €50K (NLnet NGI Zero Trust small grant), the brief's framing that "a single subsidy-program close at the lower end covers Phase B" is structurally false for every named instrument except possibly OTF at its larger award tier. A program officer reading "$17K floor" against their own instrument's typical award range cannot tell which is operative; a developer using the figure as a pursuit anchor cannot tell what minimum award size to pursue.

**Recommendation.** Reframe §10.2 totals as "addressable grant ranges by named instrument" rather than independent-item arithmetic. Example structure:

- "OTF Secure Audit at $30-60K covers full Phase B (audit + legal consultation absorbed or grant-included). Cycle: ~6 months."
- "NLnet NGI Zero Trust small grant at €50K covers full Phase B including legal consultation. Cycle: ~3 months."
- "Cure53 mission-rate engagement at $20-30K covers audit only; legal consultation absorbed or separately funded. No grant cycle — vendor discretion."

Additionally, either tighten the audit lower bound to $20-25K (matching realistic Cure53/OTF effective rates for the stated scope), or narrow the lower-bound scope to a single primitive (e.g., COSE_Sign1 envelope) with the scope reduction documented. The current $15K-at-1-2-weeks framing is internally inconsistent.

---

## F3. Phase D sustainability cliff — the labor that operates the foundation is unfunded and unnamed in the source roster

**Category:** Structural sustainability / honest disclosure
**Location:** §10.4:1106-1115 (Phase D line items); §10.4:1117 (maintainer comp aspirational); §10.5:1119-1140 (source roster); §10.6:1141-1149 (funding strategy); §8.1:720 (v1 solo); D0008 (volunteer cadence); §9.1:861 (long-horizon risk)
**Reviewers:** Lens E F1, F2, F3, F6, F8, F9 (full lens primary); Lens A F1 adjacent (no maintainer line in named asks).

**Issue.** §10.4 budgets recurring audit ($40-100K/yr), reviewer honoraria ($40-100K/yr), foundation overhead ($10-30K/yr), infrastructure ($1-3K/yr), and localization honoraria ($5-20K/yr) — but no line for the labor that orchestrates audits, manages the reviewer pool, runs board governance interface, coordinates partner relationships, manages release engineering, executes the D0009 dead-man's-switch monthly check-in, maintains the §9.4 trust-roots health report, processes incident reports, and administers the foundation's day-to-day operations. The §10.4:1117 paragraph frames maintainer comp as "the project's aspiration rather than its plan" and excludes it from the floor/ceiling. The $90-100K floor and $250K ceiling describe a foundation paying every contributor in its workflow except its primary engineer-and-administrator.

Two structural problems compound:

- **§10.5 and §10.6 contain no source category that routinely funds multi-year engineering salary.** Subsidy programs (OTF Secure Audit, Cure53 mission rates, Mozilla OSAA, NLnet NGI Zero Trust) are audit-funding. Direct grants (OTF main, Ford, OSF, Mozilla MOSS, EU instruments, Knight) can include personnel costs but rarely cover full security-engineering FTE at $150-250K/yr multi-year. The brief states the maintainer-comp cost with appropriate specificity and is vague about how it would be paid for the same line item — the inverse asymmetry from the audit-funding treatment.
- **§9.1 enumerates project risks (solo SPOF, funding non-materialization in two horizons, pilot non-validation, architectural mistakes, reviewer pool erosion) but does not enumerate "no maintainer-comp grant closes; developer cannot sustain Phase D indefinitely" as a long-horizon failure mode.** The brief takes reviewer-pool sustainability seriously enough to surface the volunteer-to-honoraria-to-volunteer trajectory in §8.2:740 as a recruitment-disclosure requirement; the equivalent maintainer trajectory is absent. The honest-disclosure posture breaks down at exactly this seam.

**Why it matters.** Two failure modes converge: (a) the developer becomes uncompensated labor cross-subsidizing a foundation that pays everyone else, which §10.4 does not acknowledge as the unusual posture it is among open-source security non-profits at this operational scale; (b) over a multi-year horizon, the developer's self-funding floor (§9.1:857 acknowledges this is finite) is exhausted, and Phase D collapses into D0009's sudden-unavailability contingency or §9.4's sunset — outcomes the brief reserves for catastrophe, not for the predictable consequence of indefinite uncompensated operations. A program officer doing due diligence on a Phase C or Phase D ask notices that the multi-year sustainability story rests on a single uncompensated person, and §9.1's risk register does not surface it. Phase D as written looks like a steady state; it is structurally a transition awaiting a funding event the brief does not commit to pursuing.

**Recommendation.** Three coordinated changes:

- Add §10.4.1 "Phase D sustainability horizon without maintainer compensation" naming a numerical volunteer-time horizon (e.g., "Phase D operations are sustainable at the developer's volunteer baseline for N years post-Phase-C transition; beyond N, Phase D either secures multi-year maintainer-comp funding or sunsets per §9.4"). Either commit to N as a public timeline funders can act against, or qualify the Phase D ceiling as "conditional on indefinite developer volunteer time, which the project does not unilaterally commit to."
- Add a §10.5 category "Multi-year operational grants for engineering capacity" naming actual program structures relevant (Sloan Foundation open-source program; CZI Essential Open Source Software where applicable; Internet Society Foundation organizational grants; sustained engineering grants from European NGI consortia at the project-not-task tier). State the pursuit difficulty honestly: these grants are larger, slower (12-24 month cycles), more competitive, and rarely cover a full FTE at security-engineering market rates. Add to §10.6 a sequencing step naming "engineering-capacity grant pursuit" as a distinct, lower-probability long-horizon activity. If no such category exists at scale for the project's threat tier, name that absence as the structural finding rather than leaving it implicit.
- Add a §9.1 bullet symmetric to the reviewer-honoraria trajectory: "Maintainer-comp non-materialization at Phase D scale." Add a §10.7 bullet of the same shape covering operational-degradation paths (foundation administration, audit-cycle execution, partner coordination, release engineering, dead-man's-switch operational continuity).

Pair with F22's recommendation that the §10.4:1117 figure be broken into engineering + fractional operations/program-management role to reflect actual labor scope.

---

## F4. §10 does not deliver the self-funding runway §9.1 explicitly committed §10 would deliver

**Category:** Internal-contract breach / honest disclosure
**Location:** §9.1:857 (explicit commitment that §10 states the runway); §10.1:1043 (developer time unvalued); §10.4:1117 (FTE figure stated, no runway); §10.8:1162-1172 (gap not flagged)
**Reviewers:** Lens D F4 (sole owner); referenced by Lens E in pattern P2 (steady-state without horizon).

**Issue.** §9.1 line 857 states verbatim: "Section 10 (when drafted) will state the developer's effective self-funding runway in calendar terms — the number of months the developer can sustain v1 development plus pilot operations under self-funded posture with no audit, no honoraria, and no team scaling. A program officer evaluating timeline risk needs that number; the project commits to providing it as the financial floor of all v1 funding-related risk discussions, rather than leaving it implicit." §10 as drafted does not contain this figure. §10.8 disclaims "a specific maintainer compensation arrangement" but does not acknowledge the runway commitment from §9.1 and does not flag the gap.

**Why it matters.** A program officer at a foundation reads §9.1's explicit commitment ("the project commits to providing it") and turns to §10 expecting the number. It is not there, and §10.8's "what this section does not promise" set does not acknowledge the omission. §9.1 framed the runway as "the financial floor of all v1 funding-related risk discussions"; §10's silence on it propagates an unbounded financial floor to every Phase A and B argument. A sophisticated funder reads this as a breach of an in-document commitment — a credibility marker more damaging than an honest "we are not yet prepared to state the runway" would be. The brief's own honest-disclosure posture relies on §9.1-style explicit commitments being honored when §10 is drafted; this one was not.

**Recommendation.** Choose one of two paths, neither of which is silent:

- (a) Add the runway figure to §10.1, framed per §9.1: "Under self-funded posture, with no audit funding closing, no honoraria, and no team scaling, the developer's effective runway is approximately N months from brief publication. This is the floor against which Phase A duration risk and Phase B funding-window timing should be evaluated. Phase A continues at the volunteer-baseline cadence for the duration of the runway; if Phase B funding does not close within that window, the §9.4 sunset path is the honest contingency."
- (b) Acknowledge in §10.8 that the §9.1 commitment has not been resolved in §10, and that this gap is itself a disclosure: "The §9.1-committed self-funding runway in calendar terms is not stated in §10. Funders evaluating Phase A duration risk and Phase B funding-window timing should request this figure directly from the developer; the brief does not promise the runway is long enough to bridge to Phase B funding closing on any specific cycle."

Path (a) is materially stronger but requires the developer to publish a personal financial-floor estimate. Path (b) is the honest fallback that preserves the §9.1-to-§10 contract by acknowledging the breach rather than leaving it as silence.

---

## F5. Four "subsidy programs" conflate grant programs, vendor discounts, and integrated-dev-grant audit allocations; OTF entity-eligibility prerequisite is not surfaced

**Category:** Funder/partner credibility / honest disclosure
**Location:** §10.2:1063,1071 ($15-30K subsidized rates assume four named programs); §10.3:1085 (Phase C subsidized floor assumes same); §10.5:1124-1128 (four-program list); §10.6:1147 (parallel application strategy); §10.8 (existence not disclaimed)
**Reviewers:** Lens B F3 (detailed mechanism analysis); Lens A F2 (instrument-fit mapping absent); Lens D F1 (program existence not disclaimed).

**Issue.** §10.5:1124-1128 lists OTF Secure Audit, Cure53 mission rates, Mozilla Open Source Audit Awards, and NLnet NGI Zero Trust as four routes "for audit funding." Lens B identifies four structural problems with treating these as substitutable:

- **OTF Secure Audit** requires the applicant to be a fiscal-sponsored or incorporated entity per OTF's published program criteria. Phase A operates as a natural person, and §10.2 lists fiscal-sponsor setup as a Phase B item. There is a chicken-and-egg dependency the brief does not surface: the pre-pilot audit subsidy needs fiscal sponsorship, but the fiscal sponsorship arrangement is itself a Phase B item with its own 2-6 month onboarding cycle (F15).
- **Mozilla OSAA** has been on irregular cycles since 2021 and may not run during Cairn's Phase B window. As of brief publication, the most recent Mozilla open-source security funding has been MOSS-routed rather than OSAA-named.
- **Cure53 mission-org rates** are not a grant program — they are a discount Cure53 applies at their discretion to engagements they accept. There is no application cycle; the project still needs the engagement budget on its own side, the discount changes the size of the engagement budget required.
- **NLnet NGI Zero Trust** has audit allocations only when an audit is part of a development grant the project has already received; NLnet does not typically fund standalone audits.

Lens D adds: the brief implicitly claims a funding route exists and will be available 6-24 months out, but program lines at this category are shaped by their funders' political/strategic choices — OTF's funding was contested 2024-2025; Mozilla's open-source funding programs have been repeatedly restructured; NLnet NGI funding cycles depend on EU programmatic continuation. §10.8 does not disclaim subsidy-program existence or openness.

**Why it matters.** Funders or partners familiar with these programs will note that the brief lists four "subsidy programs" of which one is a discount mechanism (Cure53), one does not fund standalone audits (NLnet NGI Zero Trust), one may not have an active cycle (Mozilla OSAA), and one has an entity-eligibility prerequisite the project's own Phase B sequencing creates a circular dependency for (OTF Secure Audit). The "apply to multiple in parallel" strategy in §10.6:1147 is weaker than presented because the four routes have non-overlapping mechanisms and one of them is partially incompatible with the project's own pre-incorporation posture. The credibility cost compounds with F2's $17K-floor problem: the floor depends on the same conflated set being substitutable, which they are not.

**Recommendation.** Restructure §10.5 to distinguish three categories:

- **Grant programs with application cycles:** OTF Secure Audit (with entity-eligibility prerequisite acknowledged); Mozilla OSAA (with cycle-uncertainty acknowledged).
- **Integrated-dev-grant audit allocations:** NLnet NGI Zero Trust (audit funded only as part of development grant the project has received).
- **Vendor discount mechanisms:** Cure53 mission rates; Trail of Bits civic-tech discretionary rates (per F26).

For each, state envelope range, cycle length, eligibility prerequisites, and which §10.1-§10.4 line items it fits (per F13). Acknowledge the OTF entity-eligibility prerequisite explicitly in §10.6's sequencing — the fiscal-sponsor arrangement (Phase B) gates OTF Secure Audit application, which inverts the brief's "fiscal-sponsor setup is itself a Phase B item" framing. Add to §10.8: "That the named subsidy programs will be open, accepting applications, or operating at the rate tiers cited when Cairn applies. Subsidy-program landscape changes are tracked but not controlled by the project; Phase B and Phase C floors are stated against the program landscape as of brief publication and require re-baselining at each application cycle."

---

## F6. Reviewer honoraria placed in Phase C contradict §8.2's Phase B grant-closing trigger

**Category:** Cross-section internal contradiction / phase boundary
**Location:** §10.3:1086 (Phase C, $40-100K/yr, "post-pilot operational period"); §8.2:740 ("Honoraria become the operational model once partnership or grant funding closes (Q3)"); §10.1:1049 (Phase A says honoraria "require grant funding (Phase B/C)" — itself ambiguous)
**Reviewers:** Lens C F3 (sole owner with detailed mechanism); Lens E F8 adjacent (reviewer-honoraria failure mode enumerated in §10.7 but maintainer not).

**Issue.** §10.3 places reviewer honoraria as a Phase C item for the "post-pilot operational period," at $40-100K/yr scaled across a five-reviewer pool and quarterly cadence. §8.2 line 740 names the volunteer-to-honoraria transition trigger as "partnership or grant funding closes (Q3)" — which in §10's framing is Phase B (the first grant intake). §8.2 line 736 describes "partner-funded honoraria operations" as targeting quarterly cadence during the pilot period. §10.1 line 1049 says honoraria "require grant funding (Phase B/C)" — itself ambiguous between the two phases.

**Why it matters.** §8.2 makes honoraria a recruitment-disclosure issue: reviewers are recruited at the volunteer-attestation baseline with an explicit project commitment that honoraria become the operational model when funding closes. If §10's placement is operative (honoraria are Phase C only), reviewers recruited at volunteer baseline who expected the §8.2 transition on Phase B grant-closing would find themselves still on volunteer attestation after pilot deployment lands with Phase B funding. The brief's "volunteer-to-honoraria-to-volunteer possible trajectory" (§8.2:740) becomes incoherent if Phase B closes (some reviewers expect honoraria per §8.2) but Phase C does not (no honoraria line item budgeted). The §8.2 surfacing commitment requires phase clarity that the current placement undermines.

**Recommendation.** Pick one of two reconciliations:

- (a) Split reviewer honoraria into "Phase B: pilot-period honoraria for the duration of pilot operations, sized at pilot scale (perhaps $5-20K total for one release cycle)" and "Phase C: full operational-model honoraria ($40-100K/yr, post-pilot quarterly cadence)." This matches §8.2's framing that honoraria begin when Phase B grant funding closes and scale up with Phase C operational funding.
- (b) If the intent is that pilot reviewers remain on volunteer attestation throughout pilot regardless of Phase B funding (i.e., Phase B's audit-funding does not unlock honoraria; reviewer honoraria are a Phase C-specific item), state this explicitly in §10.2 and reconcile §8.2:740 to match. The §8.2 sentence "Honoraria become the operational model once partnership or grant funding closes" would need to be revised to "once Phase C operational funding closes."

Either reconciliation requires an edit; the current state is two sections saying different things.

---

## F7. Foundation incorporation (Phase C) has unstated dependency on Phase B legal-consultation completion

**Category:** Phase boundary / dependency graph
**Location:** §10.3:1087 (Phase C foundation incorporation, $5-25K); §10.2:1061 (Phase B legal consultation covers jurisdictional shortlist evaluation and IP-assignment considerations); §8.4:787-794 (the diligence considerations live in legal consultation)
**Reviewers:** Lens C F2 (sole owner); Lens D F5 adjacent (18-24 month timing compounds with this dependency).

**Issue.** §10.3:1087 budgets foundation incorporation at $5-25K including "legal counsel for the incorporation filing, registration fees, initial board-governance documents, and IP-assignment transfer mechanics." But the substantive work for incorporation — jurisdictional selection, fiscal-sponsor selection, IP-ownership and assignment mechanics for the natural-person-to-foundation transition — lives in the Phase B legal consultation (§10.2:1061) and §8.4:787-794. Without the Phase B consultation, there is no incorporation target to file for; the Phase C $5-25K cannot fund "incorporation" because the prerequisite work has not been done. §10.6:1146 makes Phase B legal consultation either self-absorbed or grant-funded, which compounds the dependency: if Phase B legal consultation is not completed (because the developer cannot self-absorb and no smaller flexible grant closes), Phase C foundation incorporation cannot execute even if Phase C funding lands.

**Why it matters.** If Phase B closes but Phase C does not, the project has paid for consultation that produces no artifact. If Phase C closes but Phase B did not (or the consultation was self-absorbed and the work scoped to "what the developer could afford"), the Phase C dollars cannot buy incorporation at the depth the brief describes. The two items are sequentially dependent in a way the phase split obscures. The Phase C floor ($105K) silently assumes Phase B legal consultation has happened; this assumption needs to be stated. A funder considering a Phase C grant should know that incorporation requires Phase B work to have already landed.

**Recommendation.** Either:

- (a) Split foundation incorporation into "Phase B+: jurisdictional evaluation (subsumed in legal consultation, no incremental cost)" and "Phase C: filing and transfer mechanics ($5-25K)" with the sequencing made explicit.
- (b) Reframe Phase C's foundation incorporation line as "requires Phase B legal consultation to have completed" so the dependency is on-page. State in §10.6 that the Phase B legal consultation must complete (whether self-absorbed or grant-funded) before Phase C foundation incorporation can be pursued.

Pair with F9's recommendation that the Phase A/B straddle for legal consultation be resolved — the dependency chain from F7 is broken at its root if the consultation's phase placement remains ambiguous.

---

## F8. No named ask, no deliverable schedule, no reporting cadence — §10 produces no artifact a grant committee can act on

**Category:** Grant-administration actionability
**Location:** §10 throughout; §10.2:1071 (closest to an ask, but a sufficiency condition); §10.8:1172 (explicit disclaim of fundraising-target framing)
**Reviewers:** Lens A F1, F3, F5 (primary, cluster of three findings consolidated here).

**Issue.** §10 characterizes phases, totals, and contingencies but never states a request. §10.2:1071 ("a single subsidy-program close at the lower end of its typical range covers Phase B") is a sufficiency condition, not an ask. §10.8:1172 explicitly disclaims: "it is not a fundraising target with a deadline attached." No section frames a sentence of the form "the project is requesting $X from a funder in category Y to fund deliverables Z by date W." §10.1-§10.4 list deliverables and costs separately within each phase but do not tie funding tranches to milestone schedules. §10 is silent on reporting cadence, format, or content; §8.5:817 covers audit-report publication and §8.4:798 covers post-incorporation board composition, but §10 itself does not specify what a funded project would report back to a funder.

**Why it matters.** Programme officers read briefs to determine whether to invite an application. Without a named ask, the reader cannot tell whether Cairn is currently fundraising, in what amount, against what instrument, or whether the document is the application itself, a precursor, or context for a future application. Committee paperwork requires a request line and a deliverables-and-reporting schedule. Grant agreements at OTF Secure Audit and NLnet NGI Zero Trust specifically require milestone-based deliverables in their standard contracts. The phase-gated model is well-suited to milestone structure — Phase B has natural milestones (audit firm engaged, audit kickoff, audit report received, audit findings remediated) — but §10 does not surface them. The brief's honest framing (§10.8) makes structural-actionability easier rather than impossible; the §10.8 disclaimer precludes a fake ask, not a structured one.

**Recommendation.** Add §10.9 "Current funding requests and post-award commitments" enumerating:

- **The project's actual pursuit posture at brief publication.** Example: "The project is currently approaching: (a) OTF Secure Audit programme for $25-30K covering the pre-pilot audit (Phase B item); (b) NLnet NGI Zero Trust call for €50K covering pre-incorporation legal consultation plus initial honoraria; (c) deferring direct large-grant applications until partner-organization outreach (§8.6) produces co-applicants." If the project is not yet ready to ask, state that explicitly with a target date.
- **Per-phase deliverables and reporting schedule.** Phase B example: M1 audit firm engagement (within 60 days of award); M2 audit kickoff (within 90 days); M3 draft report (within 180 days); M4 remediation status report (within 240 days); M5 pilot kickoff.
- **Reporting cadence and format.** Quarterly progress notes, milestone-triggered reports, annual financial-and-impact summary post-incorporation. Tie to the transparency-log architecture in §5.5 where public-vs-funder-private boundaries can be drawn cleanly.

Pair with F13's phase-to-funder matrix: F8 specifies the project's current ask state; F13 specifies the funder-roster mapping that the ask state references.

---

# Significant Findings

## F9. Pre-incorporation legal consultation straddles Phase A/B with no resolution rule and breaks the Phase B floor calculation

**Category:** Phase boundary
**Location:** §10.2:1061 (Phase B item, $1,500-9,000, developer may absorb); §10.1:1043 (absorbed total excludes consultation); §10.5:1123 (Phase B if absorbed); §10.6:1146 (either route); §10.2:1068 (floor includes consultation lower bound)
**Reviewers:** Lens C F1 (primary); Lens D in pattern P1 (dual-state items); Lens B F5 adjacent (incorporation costs build on consultation).

**Issue.** §10.2 places "pre-incorporation legal consultation" as a Phase B line item at $1,500-9,000, but the same sentence states "the developer may absorb it personally if grant timing requires." §10.5:1123 reinforces the ambiguity: "Self/personal. Phase A and as long as feasible into Phase B if the developer can absorb the initial legal consultation." §10.6:1146 sequencing rule #2 compounds: "The legal consultation may be self-absorbed if the developer can sustain the cost, or grant-funded if a smaller flexible grant closes first." A funder asking "does my Phase B grant pay for legal consultation?" gets no clean answer. If the developer absorbs it, it is implicitly Phase A but §10.1:1043's $1,500-3,500 absorbed total excludes it. If grant-funded, it is Phase B but the floor calculation at §10.2:1068 assumes it is included ($1,500 lower bound).

**Why it matters.** The brief cannot have it both ways: either Phase A's absorbed total is wrong (~$3-13K, including consultation) or Phase B's floor is contingent on the developer choosing not to absorb. The phase model's promise of "Phase A = unilateral commitment, Phase B = first conditional" is broken at the seam. The dependency chain F7 builds on this seam is broken at its root.

**Recommendation.** Pick one of:

- (a) Make legal consultation Phase A with $1,500-9,000 added to the absorbed total and an honest note that the developer's self-funding capacity governs whether it happens.
- (b) Make it Phase B and remove the "developer may absorb" escape clause.
- (c) Introduce a "Phase A/B straddle" or "developer-absorbed-fallback" category for items that genuinely live between gates, with explicit dual phase-placement and a stated resolution rule.

A funder needs to know whether a $5K flexible grant unlocks anything material; the current framing makes it impossible to answer.

---

## F10. Phase C pre-beta $150K ceiling is sized only for Cure53/Quarkslab; Trail of Bits / NCC Group at stated scope is $180-240K

**Category:** Audit budget defensibility
**Location:** §10.3:1085; §8.5:809 (pre-beta scope); D0011:10,38 (rate band, 4-6 week engagement)
**Reviewers:** Lens B F2 (sole owner with detailed mechanism).

**Issue.** §8.5 line 809 lists the pre-beta scope as full cryptographic-primitive review, full trust-graph operation handling, full recovery flow, capability-token construction, release-security stack including Sigstore and Sigsum integrations, UnifiedPush if push is enabled. D0011 line 10 states $15-40K per week at named firms; line 38 states "4-6 week engagement" for the upper bound. Six weeks at Trail of Bits' upper rate ($40K/wk) is $240K, and the stated six-area scope realistically lands at 6-8 person-weeks rather than 4-6 when broken into actual review threads. Public ToB engagement summaries for comparable scope land $200-400K; NCC Group cryptography practice engagement letters in the same band. Cure53 at extended mission rates and Quarkslab are the only firms where $150K plausibly closes a 6-week engagement of this scope.

**Why it matters.** Phase C ceiling ($335K, §10.3:1094) understates realistic exposure if the project lands at ToB or NCC Group rather than Cure53. A funder reading "we will engage one of [ToB, NCC, Cure53, Quarkslab]" framing in §8.5/D0011 will note the upper-bound budget is sized only for the Cure53 case. The asymmetry compounds with F5: three of the four named "subsidy programs" do not in fact deliver the rate that makes the lower bound work either.

**Recommendation.** Three options:

- (a) Raise the unsubsidized upper bound to $180-220K to reflect ToB/NCC Group market rates honestly.
- (b) Explicitly state that the $150K ceiling assumes Cure53 or Quarkslab and that engaging ToB or NCC Group requires additional funding.
- (c) Narrow the stated scope to drop Sigstore/Sigsum integration review (which has upstream audit history per the §8.5 line "explicitly does not duplicate upstream-project audits") and document the scope reduction.

Add to §10.8 the audit-firm rate-card stability disclaimer per F14's mechanism — Lens D notes that security-engineering rates moved materially 2020-2025 and the 2023-2025 figures cited require re-baselining at each application cycle.

---

## F11. "Rolling cryptographic consulting" filed as Phase B aspiration covers Phase A work; leverage window may close before Phase B funding lands

**Category:** Phase boundary / timing
**Location:** §10.2:1073 (Phase B aspiration, $5-10K/month for 3-6 months of "design-and-implementation phase"); §10.1:1029 (Phase A includes cryptographic implementation); §8.1:724 (rolling consulting during "design-and-implementation"); §8.5:804 (consultant reviews decisions as they are made)
**Reviewers:** Lens C F4 (primary); Lens B F6 adjacent (engagement intensity unstated); Lens D F11 (aspiration partially disclaimed).

**Issue.** §10.2 names rolling cryptographic consulting at $5-10K/month for 3-6 months of "design-and-implementation phase" as a Phase B aspiration. But "design-and-implementation phase" is Phase A by §10.1's definition. §8.1:724 and §8.5:804 confirm the intent: rolling consulting reviews design decisions as they are made, which is Phase A work. If Phase B funding closes after substantial Phase A implementation is complete (the brief does not commit to a Phase A calendar, §10.1:1024), the rolling-consulting window has already largely closed and the funding event misses its leverage point. The brief at §10.2:1073 frames this as "Phase B aspiration rather than Phase B commitment" but the framing does not resolve the timing problem — by the time a grant cycle (3-9 months per §10.6:1147) closes, the cryptographic primitives are likely already implemented and the consultant reviews completed code, which §8.5:804 identifies as the wrong leverage point.

Lens B adds: the $5-10K/month figure does not state implied engagement intensity. Independent senior cryptographic consultants charge $250-400/hour; $5K/month at $300/hour is ~4 hours/week, $10K/month is ~8 hours/week. Without the intensity stated, a candidate may decline (interpreting $5K/month as below minimum engagement) or accept and underdeliver (interpreting as half-time rather than quarter-time).

**Why it matters.** The Phase B framing implies rolling consulting is unlockable by Phase B funding outcomes, but the value of this funding diminishes as Phase A implementation proceeds. The honest framing is that rolling consulting is a Phase A item that can only be funded if Phase B-style funding closes before Phase A's design-implementation work substantially completes — a timing-conditional Phase A item, not a Phase B aspiration.

**Recommendation.** Rename this item "Phase A consulting aspiration, fundable via early-closing Phase B grant," and acknowledge explicitly that the value of this funding diminishes as Phase A implementation proceeds. Alternatively, reframe Phase B to include "review of completed-but-not-yet-audited cryptographic implementation" as a distinct deliverable from "rolling review during design" — but the brief currently conflates them. State the implied engagement intensity (e.g., "4-8 hours/week at $250-400/hour") so the consulting offer is unambiguous to candidates.

---

## F12. Phase B-D figures are gross of fiscal-sponsor fees; net-to-project receipt is materially smaller

**Category:** Honest disclosure / arithmetic floor accuracy
**Location:** §10.2:1062 (fiscal-sponsorship fees 5-15% of routed grants); §10.5:1138 (pre-incorporation routing); §10.3:1093-1094 (Phase C floor/ceiling); §10.4:1112-1115 (Phase D floor/ceiling)
**Reviewers:** Lens D F9 (primary mechanism); Lens A F6 adjacent (fee range understated).

**Issue.** §10.2:1062 acknowledges fiscal-sponsor fees as 5-15% of routed grants. §10.5:1138 commits pre-incorporation grant routing through the fiscal sponsor. Phase B-D totals are stated gross of these fees: Phase B floor $17K, Phase B ceiling $60K, Phase C floor $105K, Phase C ceiling $335K, Phase D floor $90-100K/yr, Phase D ceiling $250K/yr. At 5-15% fees, Phase C floor effectively becomes $89-99K net (not $105K) and Phase C ceiling becomes $285-318K net (not $335K). Phase D figures similarly read as net-to-project but are routed through a fiscal sponsor during the pre-incorporation window §8.4 estimates at 18-24 months — spanning most of Phase C and possibly early Phase D. §10.8 does not disclaim that Phase B-D figures are pre-fee. Lens A adds: the 5-15% range understates current OSC/SFC published rates, which sit at 10-15% standard with reduced rates negotiable for established projects.

**Why it matters.** A sophisticated funder notices the figures are gross and adjusts; less sophisticated funders may not. The arithmetic problem compounds with F2's $17K floor: if the addressable Phase B floor is $25-30K at the named instrument, fiscal-sponsor fees reduce net-to-project receipt by another $1.5-4.5K, pushing the realistic net floor closer to $22-28K. Phase D figures' apparent stability hides a fee discontinuity at the foundation-incorporation event (the routing fee is replaced by foundation overhead, with different cost structure).

**Recommendation.** Add to §10.8: "That fiscal-sponsor fees (5-15% per §10.2) are absorbed in the Phase B-C-D figures. Figures stated in §10.2-§10.4 are pre-fee at the gross-grant level; net-to-project receipt during the pre-incorporation window is reduced by the routing fee. Post-incorporation (Phase D steady state) the fee is replaced by foundation overhead (§10.4)." Tighten the fee range to "5-15% typical, often 10-15% at established sponsors" per F15. Optionally restate Phase B-D totals as net-of-fee with the gross figure noted in parentheses.

---

## F13. Eleven-funder roster (§10.5) is not mapped to phase items, instrument size, or current program-line viability

**Category:** Grant-administration actionability / honest disclosure
**Location:** §10.5:1119-1140 (eleven funder categories); §10.6:1147-1148 (parallel pursuit strategy); §10.8 (program-line viability not disclaimed)
**Reviewers:** Lens A F2 (primary, instrument-fit mapping); Lens D F10 (program-line viability); related to F5 (subsidy-program conflation specifically).

**Issue.** §10.5 lists eleven funder categories without naming typical grant envelopes, cycle lengths, or which §10.1-§10.4 line items each funder fits. §10.6:1147 says "multiple programs in parallel; grant cycles vary from 3-9 months" but does not break this down per programme. Lens A: OTF Secure Audit subsidizes Phase B audit; OTF main grants are sized for Phase C operational support; NLnet NGI Zero Trust at the €50K small-grant tier matches different items than NGI Zero Trust at the €300K large tier; Ford and OSF run multi-year operational grants that fit Phase D, not Phase B. Lumping these in a flat list forces every reader to redo the mapping. Lens D: several of these programs have narrowed civic-tech / security-tool funding over 2023-2025 — Mozilla restructured MOSS multiple times; Ford's digital civil-rights portfolio shifted; OSF's program structure changed materially in 2023. The roster implies a viable funding landscape at the application scale Cairn needs; this is a moving target the brief does not disclaim.

**Why it matters.** A programme officer evaluating fit against their own instrument cannot tell from §10.5 whether the project is a candidate for them specifically. A developer using §10.5 as a pursuit map cannot prioritize without doing per-programme research per cycle. The brief amortizes neither, doing the same work the developer would otherwise do per reader.

**Recommendation.** Restructure §10.5 as a phase-to-funder matrix. For each named funder, state: typical grant envelope range, typical cycle length, which §10.1-§10.4 line items it fits, and whether the project considers it a primary or secondary route. Example row:

> "OTF Secure Audit — $30-150K per award, ~6 month cycle, fits Phase B pre-pilot audit (primary route) and Phase C pre-beta audit (primary route). Entity-eligibility prerequisite: requires fiscal sponsorship or incorporation."

Add per F5 the three-category structure (grant programs, integrated-dev-grant audit allocations, vendor discount mechanisms). Add to §10.8: "That the funder roster in §10.5 reflects program lines that will be open, sized to Cairn's request scale, and aligned with Cairn's pre-incorporation natural-person-led posture when application cycles open. The roster is the project's current understanding; specific program eligibility, scale, and timing require re-confirmation at each application cycle."

Pair with F26's recommendation to add Internews and Digital Defenders Partnership; pair with F3's recommendation to add a multi-year operational engineering-capacity grant category.

---

## F14. Subsidy-program existence and openness over Cairn's application horizon not disclaimed; audit market-rate stability assumed

**Category:** Honest disclosure
**Location:** §10.2:1063,1071; §10.3:1085; §10.4:1106; §10.5:1124-1128; §10.8
**Reviewers:** Lens D F1 (program existence); Lens D F8 (rate-card stability); merged because of overlapping disclaim-target.

**Issue.** §10's Phase B/C/D figures are USD-denominated 2023-2025 market rates and 2023-2025 program-line existence projected forward 2-5 years without explicit disclaim. Lens D identifies that §10.8 disclaims first-order outcomes (amounts close, timelines hit, phases reached) but not the second-order infrastructure on which those outcomes depend. Subsidy programs come and go (OTF's funding contested 2024-2025; Mozilla MOSS restructured multiple times; NLnet NGI cycles depend on EU programmatic continuation). Audit-firm rate cards moved materially 2020-2025; multiple firms doubled rate cards. The brief presents 2023-2025 rate ranges and 2023-2025 program landscape as forward-applicable for 2-5 years.

**Why it matters.** A funder evaluating Phase D sustainability over a 5-year window will discount the figures by assumed rate-trajectory and program-attrition assumptions of their own. The brief's silence on this propagates an implicit promise of stability it cannot guarantee. The §10.8 list is the canonical disclaim set funders consult standalone; its compact form leaves second-order assumptions unreflected, which weakens the brief's own honesty posture rather than strengthens it.

**Recommendation.** Add to §10.8 two related disclaim items:

- "That the named subsidy programs (OTF Secure Audit, Cure53 mission-org rates, Mozilla Open Source Audit Awards, NLnet NGI Zero Trust) will be open, accepting applications, or operating at the rate tiers cited in §10.2 and §10.3 when Cairn applies. Subsidy-program landscape changes are tracked but not controlled by the project; floors are stated against the program landscape as of brief publication."
- "That audit-firm rate cards remain stable at the 2023-2025 ranges cited in §10.2, §10.3, and §10.4. Security-engineering market rates moved materially during 2020-2025; the figures cited are honest as of brief publication and require re-baselining at each application cycle."

---

## F15. Fiscal-sponsor onboarding timing (2-6 months) understated; cycle calendar conflated with fee absorption

**Category:** Operational realism / grant-administration timing
**Location:** §10.2:1062 (free-to-low, 5-15% fees); §10.6:1146 (sequencing)
**Reviewers:** Lens A F6 (primary, cycle calendar); Lens D F9 partial (fee absorption per F12); merged due to shared §10.2:1062 anchor.

**Issue.** §10.2:1062 describes fiscal-sponsor setup as "typically free-to-low" with fees "typically 5-15% of routed grants." Lens A: this conflates two different operational realities. Fiscal-sponsor application-to-onboarding cycles at SFC, OCF, and CS&S typically run 2-6 months (SFC's published process; OCF's project-onboarding timeline; CS&S's typical 3-month evaluation cycle), often with a queue. The 5-15% fee range is also lower than current OSC/SFC published rates, which sit at 10-15% standard with reduced rates negotiable for established projects. §10.6:1146 commits the project to engaging the fiscal-sponsor question before first grant intake but does not address the calendar friction.

**Why it matters.** A programme officer willing to fund Cairn at Phase B may discover the project cannot accept funds for 3-6 months after award notification because fiscal-sponsor onboarding has not started. This is recoverable but signals operational immaturity. NLnet handles this internally (it sponsors its own grantees), so NLnet routes avoid the issue; OTF, Ford, OSF do not. The brief's optimistic framing understates the calendar friction and compounds with F5's OTF entity-eligibility prerequisite — the OTF application requires a fiscal sponsor in place, and the fiscal sponsor takes 2-6 months to onboard.

**Recommendation.** Update §10.2:1062 to state typical fiscal-sponsor onboarding cycle length (2-6 months) and recommend the developer initiate sponsor onboarding before first grant award, not after. Tighten the fee range to "5-15% typical, often 10-15% at established sponsors." Note explicitly that NLnet's grantee-sponsorship model avoids this gap and is therefore the lowest-friction first route. Update §10.6 sequencing rule #2 to make fiscal-sponsor onboarding a Phase A deliverable that precedes Phase B grant intake.

---

## F16. $150-250K/FTE figure under-states actual labor scope; engineering + operations + governance = 1.5-2.0 FTE

**Category:** Maintainer-comp gap sizing
**Location:** §10.4:1117 (single FTE framing); §8.1:722-727 (anticipated roles); §8.4:798 (board interface); D0009 (dead-man's-switch operation); §9.4 (trust-roots health report)
**Reviewers:** Lens E F4 (primary, sole owner).

**Issue.** §10.4:1117 frames maintainer comp as "$150-250K/year per FTE" — single engineer, single rate. The Phase D operational scope per §10.4 line items plus the unenumerated operational load (board interface §8.4:798; partner coordination §8.6; reviewer-pool management §8.2; release engineering §8.2; audit coordination §8.5; D0009 dead-man's-switch operation; §9.4 trust-roots health report; localization coordination §10.4:1110; incident response §9.4:990) corresponds to at least 1.0 engineering FTE plus 0.3-0.5 of operations/program-management FTE for a foundation-governed security product. §8.1:722-727 anticipates "Part-time cryptographic consulting," "UX-focused engineer," and "Documentation and community-management role" as funded additions — but these are framed as Phase B-C aspirations, not as Phase D steady-state team composition.

**Why it matters.** A funder reading "$150-250K/year per FTE would close the maintainer-comp gap" sees a manageable single-engineer ask. The actual minimum-viable Phase D team composition implied by §8's operational commitments is closer to 1.5-2.0 FTE total ($225-500K/year fully loaded). The understatement makes the maintainer-comp gap look smaller than it is, and a funder closing a single-FTE grant would still leave the foundation operationally under-resourced.

**Recommendation.** Revise §10.4:1117 to specify "engineering FTE plus a fractional operations/program-management role" with separate range estimates. Cross-reference §8.1's anticipated roles (cryptographic consulting, UX engineer, documentation/community-management) and clarify which persist into Phase D steady-state versus which are Phase B/C-bound implementation roles that conclude when v1.5 ships. State the Phase D minimum-viable team composition explicitly. Combine with F3's recommendation that §10.5 add a multi-year operational engineering-capacity grant category — F3 names the source side; F16 names the cost side.

---

## F17. Phase D foundation overhead presupposes Phase C incorporation closed; no scenario branch for foundation-failed case

**Category:** Phase dependency / scenario coverage
**Location:** §10.4:1108 (Phase D foundation overhead, $10-30K/yr); §10.3:1087 (Phase C foundation incorporation); §10.7:1160 (foundation incorporation may not close); §10.4:1112 (Phase D totals without scenario flag)
**Reviewers:** Lens C F6 (primary); Lens D adjacent.

**Issue.** §10.4:1108 lists "Foundation overhead: $10,000-30,000 per year" as a Phase D recurring cost. But foundation incorporation is in Phase C, and §10.7:1160 explicitly contemplates a scenario where "Foundation incorporation funding does not close." In that case, Phase D's "foundation overhead" line does not exist — the natural-person-operated structure continues with different (probably lower or different in kind) overhead. Phase D's $90-250K range silently assumes Phase C succeeded at the foundation-incorporation component.

**Why it matters.** Phase D as written is one scenario among several depending on which Phase C components closed. A funder cannot tell whether the $90K floor includes or excludes foundation overhead when the foundation did not incorporate. The phase model promised a clean "what unlocks what" mapping; Phase D is conditionally defined on Phase C outcomes the brief does not enumerate.

**Recommendation.** Add a Phase D scenario branch: "Phase D (foundation-operating)" with the $90-250K range, and "Phase D (natural-person continuing)" with the foundation-overhead line replaced by the residual self-funded posture cost. The §10.7 risk notes the scenario but Phase D's totals do not reflect it.

---

## F18. Phase D "recurring audit cycle" amortization hides a Phase-E-like discrete gate ($60-150K at month 18-24)

**Category:** Phase boundary / cash-flow honesty
**Location:** §10.4:1106 (Phase D amortization $40-100K/yr); §8.5:815 (second audit 18-24 months after first); §10.3:1085 (pre-beta audit market rates)
**Reviewers:** Lens C F5 (primary); Lens B F7 adjacent (subsidy continuity).

**Issue.** §10.4:1106 lists "recurring audit cycle" as a Phase D annual line item, "amortized to roughly $40,000-100,000 per year depending on the rate of cryptographic-relevant changes." The audit itself is a discrete event 18-24 months after the first (§8.5:815); the actual funding requirement is a lump sum of $60-150K (per §10.3:1085, since this is functionally a re-run of the pre-beta full audit at scope-adjusted depth) at a specific gate, not $40-100K/year continuous. Lens B adds: the $40K/year floor implies a $60-80K audit every 18-24 months at the subsidized rate, which assumes the project sustains Cure53 mission rates or OTF Secure Audit awards repeatedly. Subsidy programs typically do not fund the same project's recurring audits at the same rate indefinitely — OTF's program criteria favor projects that have not yet been audited; Cure53 mission rates are at firm discretion per engagement.

**Why it matters.** A funder evaluating Phase D sustainability sees $90-250K/year and reads it as smooth recurring expense. The actual cash flow has a $60-150K bolus at month 18-24. If the project cannot raise that bolus, Phase D's recurring audit line collapses and §8.5:813's no-skip-the-audit posture interacts with this. The amortization framing is misleading when the underlying cash flow is bursty and subsidy access is not durable.

**Recommendation.** Either:

- (a) Introduce Phase D's recurring audit as a "Phase D event, year 2" line with the full $60-150K figure stated as a discrete gate.
- (b) Introduce a Phase E label for the second audit cycle and structure ongoing operations as "Phase D between Phase E events."

Add to §10.4 the subsidy-continuity caveat: "the recurring-audit floor assumes continued subsidy access; Phase D sustainability at the floor depends on either subsidy continuity or direct-grant operational funding scaled to cover the unsubsidized recurring audit ($60-100K every 18-24 months → $30-65K/year amortized at the upper end of the recurring band)."

---

## F19. UX engineer optionality returns work to Phase A's open-ended cadence under Phase C-floor outcomes; §10.8 silent

**Category:** Phase boundary / honest disclosure
**Location:** §10.3:1088 (optional/not-optional framing); §10.3:1093 (Phase C floor excludes UX engineer); §10.3:1098 (contingency); §10.1:1024 (Phase A no calendar)
**Reviewers:** Lens C F7 (primary); Lens D F12 (§10.8 silent on implications).

**Issue.** §10.3:1088 describes the UX engineer as "optional in the sense that the developer can complete the work solo at slower cadence; it is not optional in the sense that the work itself is in scope." This straddles Phase C (Phase C funding can hire one) and Phase A (developer-solo completes the work). If Phase C closes only at floor ($105K), the UX engineer is not engaged (§10.3:1098) and the work falls back to developer-solo, which means it is back in Phase A — but Phase A's open-ended timeline means it never had a calendar floor for this work. The §5.6 implementation surface (30-50% of v1 effort per the engineering review) is the largest single uncertainty under the Phase C-floor scenario. §10.8 is silent on the timing-to-broader-release implication.

**Why it matters.** Under Phase C-floor outcomes, broader release is gated on Phase A's volunteer-baseline cadence completing the largest piece of UI work, which the brief never committed to. A funder reading §10.8 sees Phase C as Phase B + reviewer honoraria + foundation + audit; the UX engineer's funding implications are not in the disclaim set.

**Recommendation.** Add to Phase C contingency: "Without UX engineer funding, the UX work returns to Phase A's open-ended cadence; broader release is gated on the developer completing this work at volunteer-baseline pace." Add to §10.8: "Phase C broader release without UX-engineer funding shifts to slower solo-developer cadence on the §5.6 surface; the timing-to-broader-release implication is not explicitly stated in the phase totals."

---

# Minor Findings

## F20. Reviewer honoraria arithmetic implies per-hour rates outside stated $150-300/hr band at floor/ceiling

**Location:** §10.3:1086.
$2,000-5,000 per reviewer × 5 reviewers × 4 releases gives $40-100K. But at 8-20 hours of review per release: floor implies $2,000/20h = $100/hour (below stated $150-300 market band); ceiling implies $5,000/8h = $625/hour (above stated band). Defensible mid-band; arithmetic should be shown to avoid funders doing it themselves. Recommendation: tighten honoraria range so implied per-hour rate stays within $150-300; for 8-20 hours at $150-300/hr, realistic per-reviewer-per-release is $1,200-6,000.

## F21. UK CIC $5K incorporation floor optimistic when IP-assignment counsel time included

**Location:** §10.3:1087.
Companies House CIC registration fee is ~£35; actual cost driver is counsel fees for CIC36 form, asset lock provisions, board governance documents, and IP-assignment transfer mechanics. UK non-profit counsel rates for clean CIC incorporation with these elements: £4,000-8,000 ($5-10K). Adding the natural-person-to-entity IP transfer mechanics (5-10 hours of IP-specialist time) pushes realistic UK CIC total to $8-15K. The Phase C floor of $105K assumes the $5K lower bound. Recommendation: raise lower bound to $8-10K reflecting realistic counsel fees including IP-assignment mechanics, or document explicitly which sub-items the $5K does and does not include.

## F22. Maintainer-comp $150-250K stated as US-equivalent without EU range; foundation overhead $10-30K low for security-critical product foundation

**Location:** §10.4:1117 (maintainer comp); §10.4:1108 (foundation overhead).
Lens A: §10.4:1117 acknowledges "US-equivalent rates; jurisdiction-dependent" but does not characterize the European, UK, or Dutch security-engineering ranges (~€80-130K/yr at senior security-engineering rates). Given §10.4:1108 contemplates non-U.S. incorporation (D0010), European funders may misread the range as the project's actual aspiration rather than a U.S.-benchmark anchor.
Lens E: $10-30K foundation overhead is plausible for a small grantmaking shell entity; it is low for a foundation that operates a security-critical product, holds custody of pilot-user encrypted contact rosters (D0009), maintains signing identity infrastructure with documented compromise plans, and administers researcher safe-harbor commitments (D0012). Realistic range $30-60K/year — board operations, D&O insurance, accounting + annual financial audit, regulatory filings, counsel retainer, jurisdiction-specific compliance. Recommendation: note EU-equivalent maintainer range; disaggregate foundation overhead into components; either acknowledge figures as pre-consultation estimates or revise the range.

## F23. 18-24 month foundation-incorporation timing repeated four times; escapes §10.8 timeline-disclaim net

**Location:** §3.4:210; §8.4:766,777,796; §10.2:1075; §10.8:1167.
Sophisticated funder reads §8.4's repeated "approximately 18-24 months post-v1" as a commitment. §10.8 disclaims "specific timelines tied to funding events" generically; the 18-24-month figure escapes. In practice it compounds v1 ship date (contingent on grant timing, Phase A "as available") with Phase C closing — implying brief completion → v1 ship → 18-24 months → incorporation is roughly 2.5-4 years total. Recommendation: add to §10.8: "The 18-24-month foundation-incorporation timing referenced in §3.4, §8.4, and §10.2/§10.3 is a planning anchor, not a schedule. It compounds the Phase A 'as available' cadence and Phase C funding closure; either extending materially shifts the incorporation timeline."

## F24. Phase A 2-4 Pixel devices includes loaner-pool pre-positioning for Phase B work

**Location:** §10.1:1042; §10.1:1051.
Pilot training is Phase B work (post-audit). At Phase A, only developer-testing devices (1-2) are required; loaner-pool devices (2-3) are pre-positioned for an event Phase A is not committed to reach. Minor cost leak from Phase B into Phase A (~$1-2K of Phase A absorbed budget is functionally Phase B pre-positioning). Note: this finding is partially subsumed by F1's larger BYOD-vs-developer-provisioned contradiction. Recommendation: either justify the loaner-pool acquisition as Phase A insurance, or move 2-3 of the 4 devices to Phase B's incremental cost line. Resolve in conjunction with F1.

## F25. Phase B $0-500/yr infrastructure line and Phase C "minimal incremental cost" hardware line are inventory padding

**Location:** §10.2:1064 (Phase B infrastructure); §10.3:1089 (Phase C hardware).
§10.2:1064 lists infrastructure where every item is free or already-in-Phase-A; the entire line is $0. §10.3:1089 lists pilot deployment hardware as Phase C with "minimal incremental cost," but the BYOD model and 2-4 device project pool are Phase A. Both lines create the impression Phase B/C include funding for items they do not. Recommendation: remove or move to a "Phase B/C does not require additional funding for X" subsection to keep inventory honest.

## F26. Vocabulary and roster minor items

**Location:** §10.2:1063 ("subsidy programs close"); §10.5:1119-1140 (roster); §10.7.
(a) "Subsidy programs close" / "subsidy close" used throughout §10 is M&A/sales vocabulary; programme officers say "awarded," "approved," "funded." Replace globally. (b) Trail of Bits is not a named program comparable to OTF Secure Audit or Cure53 mission rates; ToB extends discretionary reduced rates per engagement. Reframe as "Trail of Bits engagements at the firm's discretionary reduced rate for civic-tech projects." (c) Funder roster omits Internews (digital-rights infrastructure funding; active programme for civil-society security tooling) and Digital Defenders Partnership (rapid-response and capacity-building, Hivos-run). Add both with programme-fit notes.

---

# Pattern observations

Eight patterns emerge across the findings, more than any single finding signals individually:

**P1. §10 was drafted independent of the rest of the brief; the cycle did not include cross-section reconciliation.** Most visible at F1 (BYOD pilot model contradicts §3.3/§6.3), F4 (§9.1's runway commitment not honored by §10), F6 (reviewer honoraria phase placement contradicts §8.2). Three direct contradictions with three different earlier sections, none of which §10 acknowledges. The pattern suggests §10 was drafted to its own internal logic and the rest of the brief was not audited against the new model. A targeted cross-section reconciliation pass — F1, F4, F6 specifically — would close most of the critical contradiction surface.

**P2. The phase model is honest at the macro level but leaks at the seam.** Multiple findings (F7, F9, F11, F17, F18, F19) identify items whose phase placement either depends on an unstated earlier-phase prerequisite (F7, F11, F17), straddles phase boundaries with no resolution rule (F9, F19), or smooths discrete gates into continuous expense (F18). The pattern is that the phase model's central promise — "what does my dollar unlock per phase?" — works at the phase-totals level but breaks when a reader traces individual items. The phase-gated model is the right substrate; it needs a discipline pass at the line-item level to preserve the cleanliness at scale.

**P3. Floors and ceilings are derived from single-firm or single-instrument pricing models.** F2 ($17K floor at Cure53/OTF effective rates), F10 ($150K ceiling at Cure53/Quarkslab rates), F12 (gross-of-fee figures), F18 (subsidized recurring audit) all share the property that the named bound is the right number for one specific pricing model but not for the full named candidate set the brief commits to engaging. The brief names four firms in §8.5/D0011 and four subsidy programs in §10.5; the budget figures are sized for one of each. The "we will engage whichever closes" framing is at structural tension with budget ranges that only one combination makes coherent.

**P4. First-order outcomes are disclaimed; second-order infrastructure on which they depend is not.** F1 (BYOD assumes hardware availability), F5/F13/F14 (subsidy programs assumed to exist), F12 (fiscal-sponsor fees assumed absorbed), F14 (rate-card stability assumed), F16 (5+ reviewer pool assumed recruited) all share the property that §10.8 disclaims "amounts close" but not "the infrastructure that makes the amounts meaningful." The §10.8 disclaim set is materially narrower than §10.1-§10.6's implicit-promise set. Extending §10.8 down one level closes most of the honest-disclosure gap.

**P5. Honest disclosure is rigorous everywhere except at the maintainer line.** §10 and §8 collectively make multiple honest-disclosure moves — volunteer-attestation surfacing in §8.2:740, audit-budget bound dependency in §8.5:813, jurisdictional depth caveat in D0010, "what this section does not promise" in §10.8, §9.1 enumeration of project risks. Each surfaces an uncomfortable truth. F3 (sustainability cliff), F4 (broken runway commitment), F6 (honoraria asymmetry), and the §10.4:1117 framing of maintainer comp as "aspirational" do not get the same treatment. The brief's honest-disclosure posture is asymmetric — rigorous when the disclosure concerns other parties (reviewers, partners, auditors, jurisdictions); softer when it concerns the project's own financial fragility at the maintainer line.

**P6. Cost-side specificity without strategy-side specificity on the same line item.** Most visible at the maintainer-comp gap (F3, F16): §10.4:1117 names the cost ($150-250K/year per FTE) with appropriate specificity; §10.5/§10.6 do not name the funding strategy that closes that cost with comparable specificity. This is the inverse of the audit-funding treatment, where the strategy is precise (named subsidy programs, parallel applications, named cycles) and the cost matches (D0011's specific subsidy-tier vs. market-rate bands). The asymmetry between specificity on the cost and vagueness on the strategy for the same line item is itself a signal that the line item does not have a real funding path in the brief's own model. The same pattern appears more subtly at F11 (rolling consulting cost stated, leverage window unstated) and F15 (fiscal-sponsor fee stated, onboarding cycle unstated).

**P7. Arithmetic-floor framing does not align with how funders size instruments.** F2 ($17K Phase B floor), F10 ($150K Phase C ceiling), F12 (gross-of-fee figures) all share the property that the brief presents independent-item sums or gross figures, while funders evaluate against named-instrument envelopes and net-to-project receipt. The structural fix is consistent across these findings: an "addressable asks by instrument" supplement that maps each phase to named-funder asks with envelope ranges and fee/net adjustments, complementing the existing item-by-item totals.

**P8. Phase D is framed as steady-state but is structurally a transition awaiting another funding event.** F3 (sustainability cliff), F17 (foundation-incorporation prerequisite), F18 (recurring audit lumpy gate) each independently identify that Phase D is bounded — by the developer's self-funding floor, by Phase C outcomes, by the discrete second-audit gate. The phase-gate model is rigorous for A→B→C transitions but treats D as a destination. A complete phase-gated model would name Phase D as bounded — either bounded by maintainer-comp funding closing (Phase D→E with funded steady-state), or bounded by sunset.

---

# Action plan

Findings break into four categories.

## A. Prose edits to §10 — surgical, straightforward

These are revisions that can be made directly to §10 (and adjacent earlier sections where contradictions exist) without requiring new decision documents or open-questions entries.

- **F1** (BYOD contradiction with §3.3/§6.3): pick one model and reconcile across §3.3, §6.3, and §10. Add §10.8 hardware-availability disclaimer.
- **F2** (Phase B $17K floor): reframe totals as addressable grant ranges by named instrument; tighten audit lower bound or narrow stated scope.
- **F4** (broken §9.1 runway commitment): either add runway figure to §10.1 or acknowledge gap in §10.8.
- **F5** (subsidy-program conflation): restructure §10.5 into three categories; acknowledge OTF entity-eligibility prerequisite; add §10.8 program-existence disclaimer.
- **F6** (honoraria phase placement vs §8.2): split honoraria into Phase B pilot-period and Phase C operational-model, or reconcile §8.2 to Phase C-only framing.
- **F7** (foundation incorporation dependency on Phase B legal consult): make dependency explicit in §10.3 or split incorporation across Phase B+ and Phase C.
- **F9** (legal consultation Phase A/B straddle): pick one phase or introduce explicit straddle category.
- **F10** (Phase C $150K ceiling): raise to $180-220K, or scope to Cure53/Quarkslab explicitly, or narrow scope.
- **F11** (rolling consulting Phase A/B): rename as Phase A item fundable via early-closing Phase B grant; state engagement intensity.
- **F12** (gross-of-fee figures): add §10.8 fiscal-sponsor-fee absorption disclaimer; consider restating totals as net.
- **F13** (funder roster matrix): restructure §10.5 as phase-to-funder matrix with envelope, cycle, instrument-fit per row.
- **F14** (subsidy/rate-card stability): add two §10.8 disclaim items.
- **F15** (fiscal-sponsor cycle): update §10.2:1062 to state 2-6 month onboarding; tighten fee range to 5-15% (10-15% typical); update §10.6 sequencing.
- **F17** (Phase D scenario branch): add foundation-operating vs natural-person-continuing branches.
- **F18** (recurring audit gate vs amortization): introduce Phase D year-2 event or Phase E label.
- **F19** (UX engineer Phase A fallback): add to §10.3 contingency and §10.8.
- **F20-F26** (minor items): direct edits per individual recommendations.

## B. New decision documents / structural additions

These require judgment calls and net new policy.

- **§10.4.1 "Phase D sustainability horizon without maintainer compensation"** (F3, F16). Name a numerical volunteer-time horizon N for Phase D operations at developer volunteer baseline. Either commit to N as a public timeline funders can act against, or qualify the Phase D ceiling as conditional on indefinite developer volunteer time the project does not commit to. Pair with §9.1 bullet for maintainer-comp non-materialization risk and §10.7 bullet for operational degradation paths. Specify Phase D minimum-viable team composition (engineering + fractional operations/PM role) explicitly.
- **§10.5 multi-year operational engineering-capacity grant category** (F3). Name actual program structures (Sloan, CZI EOSS, ISOC Foundation, NGI consortia project-tier). State pursuit difficulty honestly. Add §10.6 sequencing step for engineering-capacity grant pursuit.
- **§10.9 current funding requests and post-award commitments** (F8). Enumerate project's current pursuit posture (which programmes, what envelopes, what timing) or state explicitly the project is not yet ready to ask with a target date. Add per-phase deliverables-and-reporting schedule with milestones. Add reporting cadence and format commitment tying to §5.5 transparency log where applicable.

## C. Open-questions additions

These are items where the resolution requires consultation or external information the project does not currently have.

- **Q17** (current ask state): when does the project commit to publishing a named ask per F8?
- **Q18** (volunteer-time horizon N): what is the developer's effective self-funding runway in calendar months per F4 and F3?
- **Q19** (fiscal-sponsor pre-Phase-B onboarding): which sponsor, on what cycle, before Phase B grant intake? Resolves F5 entity-eligibility chicken-and-egg and F15 cycle timing.
- **Q20** (multi-year operational grant route): which engineering-capacity grant programmes does the project consider primary for maintainer-comp closure per F3?

## D. Items to reject or defer

- The arithmetic-floor framing (F2, F10, F12) does not need to be replaced wholesale — it can coexist with the addressable-instrument matrix (F13). Reject any recommendation that requires deleting the item-by-item totals; they are useful for project-internal planning even when not useful for grant-administration.
- The Phase A 2-4 Pixel devices loaner-pool item (F24) is a minor leak that gets subsumed by F1's BYOD reconciliation; defer until F1 is resolved.
- The Phase B $0-500/yr infrastructure padding (F25) is cosmetic; address only if §10 receives a structural rewrite.

---

# Strategic note

This review is comparable in volume to the §8/§9 review (30 findings; this review 26). The §8/§9 review surfaced commitment-credibility issues; this review surfaces a mix of internal-contradiction (F1, F4, F6, F7), arithmetic-defensibility (F2, F10, F12, F20, F21), structural-sustainability (F3, F16), and administrative-actionability (F8, F13) issues. The most consequential single edit is the cluster F1/F4/F6/F7 — these are direct internal contradictions between §10 and earlier sections that a careful funder finds on first cross-read. Fixing them is mechanical once the decisions are made.

The next-highest leverage is the F3 cluster (sustainability cliff, source-roster gap, §9.1 risk-register gap, §10.7 funding-risk-register gap, §10.8 disclaim gap) — these are the single largest credibility issue in §10 because they describe the project's most likely long-term state as the aspirational case. Closing F3 honestly does not require committing to maintainer comp; it requires naming the volunteer-time horizon and the absence of a routine funding route for engineering capacity, and treating the asymmetry as the structural finding it is.

The brief's overall §10 posture — phase-gated rather than flat-budget, honest about contingency, conditional register — is the right posture for an unfunded design brief. The remaining gaps are at the line-item level not living up to the section-level posture; closing them does not require revising the strategy, only the prose and the decisions that underwrite it.
