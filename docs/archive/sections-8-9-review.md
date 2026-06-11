# Sections 8 and 9 Adversarial Review — Consolidated Findings

**Date:** 2026-05-28
**Source:** Five parallel sub-agent reviews, distinct lenses (operational realism, funder/partner perspective, threat-model consistency, engineering feasibility, honest skeptic / red team).
**Raw findings:** 61 across reviewers (Critical 15, Significant 36, Minor 10). After deduplication and theming: 30 consolidated findings below.
**Companion to:** [design-brief.md](design-brief.md) Sections 8 and 9, with cross-references to Sections 2–7 and the decision documents.

---

## Patterns

Ten patterns emerge that span multiple reviewers and matter more than any single finding:

**P1. The "unconditional" framing in Section 8 is rhetorical, not load-bearing.** Caught independently by Red Team, Operational, and Threat-Model lenses. The "no-skip-the-audit" commitment in 8.5, the "honoraria as ongoing operational cost" commitment in 8.2/8.6/9.4, the "external review mandatory even under deadline pressure" commitment in 8.3, and the Section 8 introduction's register distinction all imply unilateral project commitment but actually depend on external outcomes the brief acknowledges elsewhere. This is the same overreach pattern the review was designed to catch, and the review caught it.

**P2. Volunteer-reviewer-baseline cannot sustain the claimed cadence + pool size + rotation + toolkit-maintenance commitments.** Caught by Operational, Engineering, Funder, and Red Team lenses. Quarterly cadence × 5+ pool × 18-month rotation × per-release toolkit maintenance × per-release coordination = workload sized for a funded org with a coordinator role, run on volunteer time by a solo developer. The volunteer-to-honoraria transition is named (8.2) but its timing (when funding closes) is itself the variable the brief cannot pin.

**P3. Section 9.3 omits significant Section 3.3 surfaces and Section 3.4 trust roots.** Caught by Threat-Model, Funder, Red Team lenses. 9.3 enumerates 8 trust-root compromises against 3.4's 11 trust roots; 9.3 covers about 9 of 15 surfaces from 3.3. Notable omissions: Network surface, Endpoint as distinct from evil-maid, Update channel as a surface (not just APK-key compromise), Identity surface broadly, Provisioning ceremony surface, general Metadata surface (only trust-graph and transparency-log subsets are named), Group membership and association surface, the in-person facilitator as a trust root, Tor/SimpleX/Briar protocols as compromise scenarios, and cryptographic primitives compromise outside the post-quantum framing.

**P4. Section 8 introduces new trust placements that neither 3.4 nor 9.3 acknowledges.** Caught by Threat-Model lens. The reviewer-pool toolkit (8.2), the out-of-band incident-response channel and verification key (8.2/5.5), the foundation jurisdiction once incorporated (8.4), and cross-functional partner concentration across role categories (8.6) are all new trust placements. The brief's "honest about limits" principle (4.2, 9.3) is not maintained for these.

**P5. The sunset plan addresses graceful shutdown but not sudden developer unavailability.** Caught by Red Team, Operational, Engineering lenses. 9.4 presumes the developer is alive, lucid, available, and acting in coordination with successor organizations. Coercion, illness, detention, or asset seizure — each of which the brief takes seriously for _users_ (Section 3) — is not addressed for the _developer_. Given the threat tier the product targets, this gap is structurally inconsistent with the rest of the design.

**P6. Foundation jurisdiction analysis is below diligence floor.** Caught by Funder, Engineering, Red Team lenses. Specific factual errors (Signal Foundation is Delaware 501(c)(3), not Dutch Stichting; Briar Project's commercial entity was a German UG/GmbH, not Swiss Verein). Missing fiscal-sponsor stage for pre-incorporation grant intake; missing tax-treaty implications, donor-disclosure regimes, banking access considerations, EAR/Dual-Use export considerations. The depth gap is visible in one careful read.

**P7. Audit budget $20-50K is below market rates for the named firms at the described scope.** Caught by Funder, Engineering lenses. Realistic engagement at the scope described (cryptographic primitives, trust-graph operation handling, recovery flow, capability-token construction, release-security stack) is $60-150K at Trail of Bits / NCC Group / Cure53 rates. The $20-50K floor is viable only with explicit auditor-subsidy programs that should be named.

**P8. Cross-functional partner concentration creates multi-surface compromise risk that 3.4 doesn't acknowledge.** Caught by Threat-Model lens. The same candidate organizations (Tactical Tech, Front Line Defenders, Access Now, Citizen Lab) appear across multiple Cairn role categories — reviewers, witnesses, pilot facilitation, threat intel, localization, training. Compromise of a single partner has multi-surface impact that the witness-pool-independence note in 3.4 acknowledges only for one cross-function pair.

**P9. v1.5 timing (6 months post-v1) is not credible against the deferred items.** Caught by Engineering lens. Briar integration + reproducible builds + local caching + in-app post-coercion + multi-profile UX + duress-wipe + possible voice/video + possible localization is realistically 9-15 months on solo-developer time per the prior Section 5 review estimates.

**P10. Partner commitments are made on partners' behalf despite Section 8.6's explicit principle against it.** Caught by Red Team, Funder lenses. 9.4 lists "partner-organization debriefs at 3-month and 6-month marks" as a mitigation; 8.6 says explicitly the brief makes no commitments on behalf of unconsulted partners. Direct cross-section contradiction. 9.4 also lists partner-supplied reviewer replacement candidates as defense, which assumes partner capacity the project does not control.

---

## Severity Distribution

- **Critical (F1–F12):** 12 findings. Commitments that are materially false on close reading, or limits the brief should name but doesn't.
- **Significant (F13–F25):** 13 findings. Unstated assumptions, missing acknowledgments, mechanisms specified but not budgeted.
- **Minor (F26–F30):** 5 findings. Prose-level imprecision, smaller gaps in honesty.

---

# Critical Findings

## F1. "Unconditional" framing in Section 8 is rhetorical, not load-bearing

**Category:** Architectural claim / Register
**Location:** Section 8 introduction; 8.2 honoraria; 8.3 external review; 8.5 no-skip-audit
**Reviewers:** Red Team #1, #2, #3, #4, #8; Operational P1, F11; Threat-Model F6

**Issue.** Section 8's introduction commits to a "conditional and honest" register where "the project commits to what it unilaterally controls" and "states intent subject to conditions for items dependent on funding, partner outreach, or external grant cycles." The subsections do not maintain the distinction. Several commitments labeled as project commitments are in fact conditional:

- **8.5 "no-skip-the-audit commitment is unconditional"** — depends on audit funding closing eventually; if it doesn't, the project is structurally bound to indefinite uncompensated pilot operation (per Red Team F1's attack chain).
- **8.2 "Honoraria are budgeted as ongoing operational cost"** — assumes grant funding renews across cycles in perpetuity; grant funding does not arrive in perpetuity.
- **8.3 "External-reviewer-pool review is required... even under deadline pressure; this is one of the few commitments in Section 8 that is unconditional"** — depends on reviewer pool existing and being available.
- **Section 8 introduction's general register claim** — same issue at the framing level.

**Why it matters.** The introduction's claim of register-of-honesty discipline is load-bearing for funder and partner trust. When the subsections do not maintain it, the discipline becomes a credibility liability rather than an asset. Future contributors and partners will hold the project to the published language.

**Recommendation.** Audit every "commits" instance in Section 8. Reclassify commitments that depend on (a) reviewer pool existing, (b) external review process functioning, (c) partner participation, or (d) sustained funded developer time as "intent subject to..." rather than "commits." Reframe the no-skip-the-audit and honoraria commitments to acknowledge their conditionality. The Section 8 introduction should acknowledge that "commits" includes some commitments that degrade gracefully if the project's ability to operate at scale does not materialize; name the degradation explicitly.

---

## F2. Volunteer-reviewer-baseline cannot sustain claimed cadence + pool size + rotation + toolkit-maintenance commitments

**Category:** Operational scope / Engineering feasibility
**Location:** Section 8.2 throughout; 5.5 references; cross-checks 8.1, 9.1
**Reviewers:** Operational F1, F2, F3, F4, F11; Engineering F1, F2, F9; Funder F2; Red Team F2

**Issue.** The combined operational commitments in 8.2 require, sustained on the volunteer baseline:

- Quarterly release cadence (8.2), with per-release operational pipeline (build, sign Sigstore, log Rekor, coordinate 3-of-5 reviewer attestations, anchor in Sigsum, multi-channel distribution) at 4-8 developer-days each release.
- 5+ reviewer pool with 3-of-5 attestation threshold per release. At quarterly cadence, ~4 attestation cycles per reviewer per year, with source review of a Rust core + Kotlin UI codebase = 1-2 reviewer-days per attestation per release.
- 18-month rotation cadence with overlap; in a 5-person pool this implies roughly one rotation every 3.6 months.
- Reviewer onboarding toolkit (Docker/Nix-pinned environment) maintained current with every release — Rust toolchain churn (6-week cycles), AGP/NDK updates, dependency-tree CVE responses — 1-3 days per release.
- Emergency-release path requiring 2-of-5 reviewer availability on short notice.

The "developer time" line in 8.1 absorbs all of this without explicit budget. Funded organizations doing equivalent operations have a dedicated release-coordinator role; the brief does not.

**Why it matters.** If the volunteer pool cannot sustain the cadence, releases block until quorum forms, security-critical patches wait, the reviewer pool itself erodes from burnout (the risk 9.1 names), and the v1.5 development timeline slips because the developer is absorbing coordination work that scales with release cadence. The "honoraria when funding closes" transition (8.2) does not solve this for the volunteer-baseline period, which is the entire pilot and possibly longer.

**Recommendation.** Pick one of three remediations or articulate a documented alternative:

- **(a) Extend cadence to semi-annual** for the volunteer baseline, with explicit acknowledgment that quarterly is the post-honoraria target.
- **(b) Reduce attestation threshold to 2-of-N** at the volunteer baseline with explicit risk acknowledgment.
- **(c) Name release slippage as the expected behavior of the volunteer baseline** and document a tolerance window (e.g., "releases ship when quorum forms; expected median 4-6 months at volunteer baseline, target quarterly once honoraria fund").

Additionally: defer the published reviewer toolkit to v1.5, or commit it only at the level of "reviewers run their own environments and the project documents build commands" — much lighter contract than "maintain current with every release."

---

## F3. Section 9.3 omits major Section 3.3 surfaces

**Category:** Threat-model consistency
**Location:** Section 9.3 "Residual attack surfaces"; cross-check Section 3.3
**Reviewers:** Threat-Model F1; Funder F10; Red Team F10

**Issue.** Section 3.3 enumerates 15 distinct surfaces. Section 9.3's residual-surfaces list omits roughly half:

- **Network surface** (deep packet inspection, IMSI catchers, BGP manipulation, TLS interception, traffic correlation) — not acknowledged.
- **Endpoint surface** (zero-click spyware on a running device) — only the evil-maid subset is named.
- **Returned-after-seizure surface** — referenced as parent of "reconstruction window" but not named distinctly as a surface.
- **Update channel surface** — covered partially under "Long-lived APK signing key" compromise but not as a surface category.
- **Identity surface** (compelled disclosure, SIM swap, phishing, key theft) — not acknowledged.
- **Provisioning ceremony surface** (observation in surveilled spaces, ceremony substitution) — not named.
- **General Metadata surface** — only trust-graph-metadata and transparency-log-metadata subsets are listed.
- **Group membership and association surface** — entirely absent.

**Why it matters.** 9.3 frames itself as the consolidated reference for what the architecture does not protect against. A reader auditing 9.3 against 3.3 finds nearly half of the named surfaces missing. The "Honest about limits" principle (4.2) is the project's stated framing; the missing surfaces are the principal target of that principle. Group membership and the general Metadata surface in particular are load-bearing for the audience.

**Recommendation.** Extend 9.3's "Residual attack surfaces" enumeration to include all 15 surfaces from 3.3. For each, name in one sentence what residual exposure remains after the architecture's defenses. Either restructure 9.3 to cross-reference 3.3 by name (making 3.3 the authoritative enumeration with 9.3 elaborating residual scenarios), or duplicate the enumeration with elaboration.

---

## F4. Section 9.3 omits Section 3.4 trust roots

**Category:** Threat-model consistency
**Location:** Section 9.3 "Trust-root compromises"; cross-check Section 3.4
**Reviewers:** Threat-Model F2; Funder F10

**Issue.** Section 3.4 enumerates eleven explicit trust roots plus the post-quantum note. 9.3's trust-root compromise list covers eight. Omitted:

- **Cryptographic primitives** (Ed25519, Curve25519, ChaCha20-Poly1305) — addressed only under post-quantum out-of-scope, not as a classical-cryptanalytic compromise scenario.
- **Tor network** — no compromise scenario discussed; the entire transport layer depends on this trust root.
- **SimpleX and Briar protocols** — 3.4 explicitly names "implementation flaws are possible," but 9.3 has no protocol-level compromise scenario.
- **Sigsum protocol** as a separate trust root — the witness pool is named, but the protocol itself is not.
- **In-person facilitator** — 3.4 names this as a v1-pilot trust root; 9.3 references it only obliquely under Distribution and supply-chain.

Conversely, 9.3 introduces the **long-lived APK signing key** as a trust-root compromise scenario, but 3.4 does not enumerate it as a trust root. The asymmetry runs both ways.

**Why it matters.** Missing the in-person facilitator from 9.3 is the most consequential omission — it is the most concentrated trust placement in the pilot model per the Section 5 review F14. Missing Tor and SimpleX/Briar means the entire transport and communications layer's risks are unaddressed. Adding the APK key in 9.3 but not 3.4 means a reviewer cross-checking the two finds an unanchored item.

**Recommendation.** (a) Add the missing 3.4 trust roots to 9.3 with one-sentence compromise scenarios for each. (b) Move the long-lived APK signing key into 3.4 as a named trust root (currently in 5.5 only), then reference 3.4 from 9.3 rather than introducing it cold in 9.3.

---

## F5. Section 8 introduces new trust placements not in 3.4 or 9.3

**Category:** Threat-model consistency / New trust placements
**Location:** Section 8.2 (reviewer toolkit, out-of-band channel), 8.4 (foundation jurisdiction), 8.6 (cross-functional partner concentration)
**Reviewers:** Threat-Model F3, F4, F7, F9

**Issue.** Four trust placements introduced or expanded by Section 8 commitments, none of which 3.4 or 9.3 names:

- **Reviewer toolkit** (8.2). Project-operated infrastructure that reviewers depend on; a compromised toolkit yields false attestation capacity that defeats the multi-party verification stack.
- **Out-of-band incident response channel** (5.5/8.2). Pre-staged communication channel with separately-held verification key; if compromised at the moment of incident response, the entire compromise-response plan collapses.
- **Foundation jurisdiction once incorporated** (8.4). The foundation becomes a new legal entity in the trust path; the jurisdiction's legal process directly affects what compromise scenarios the project must defend against.
- **Cross-functional partner concentration** (8.6). The same candidate organizations across multiple Cairn functions (reviewer + witness + facilitator + threat-intel + localization) means compromise of a single partner has multi-surface impact. 3.4's "witness-pool independence" note covers only one such cross-function pair.

**Why it matters.** The project's "honest about limits" principle (4.2) commits to naming new trust placements explicitly. Section 8 introduces all four without acknowledgment in 3.4 or 9.3. A reviewer cross-checking the threat model and the operational plan finds the gap.

**Recommendation.** Add each to 3.4 as an explicit trust root (with the same framing as the build supply chain — open-source and reviewable, but a trust nonetheless), or add corresponding compromise scenarios to 9.3. For the foundation jurisdiction specifically, the addition is forward-looking ("foundation incorporation per 8.4 will introduce an additional jurisdictional trust placement once it occurs"). For cross-functional partner concentration, name it explicitly in 3.4 alongside the witness-pool independence note.

---

## F6. Sudden-developer-unavailability scenario not addressed by sunset plan

**Category:** Operational mitigation gap
**Location:** Section 9.4 sunset plan; cross-check 9.1 SPOF
**Reviewers:** Red Team F6; Operational F9; Engineering F8

**Issue.** Every commitment in the sunset plan presupposes the developer is alive, lucid, available, and acting in coordination with successor organizations. The plan does not address:

- Sudden developer death or incapacitation (the 6-month announcement cannot be made).
- Developer coercion (the developer may be compelled to issue false sunset or continuation statements).
- Developer prolonged incommunicado (border detention, medical emergency, disappearance — risks the brief takes seriously for users in Section 3 but not for the developer).
- Developer asset seizure that includes project infrastructure (signing keys, hosting accounts, domain registrations).

  9.1 names the solo-developer SPOF risk. 9.4's sunset mitigation does not actually mitigate it for the worst-case version of the risk. The Section 5 review (P1, F2) identified that the developer is themselves a target at this threat tier. The product targets users who face this risk; the project ships with no plan for the same risk applied to the project itself.

**Why it matters.** "Sunset is the worst case; the commitment is that the worst case is not silent" (9.4) is operationally void if the conditions for sunset trigger the conditions for sunset failure. Pilot users in active use of Cairn when the developer becomes unavailable are silently stranded — no public announcement, no migration guidance, no final advisory. This is the failure mode the sunset plan was supposed to prevent, and at the threat tier this product targets, it is the realistic case.

**Recommendation.** Add a "Sudden-unavailability contingency" subsection to 9.4 covering:

- A pre-staged "dead man's switch" attesting project state to specified partners on developer non-response (monthly or quarterly check-in mechanism).
- Pre-staged successor-handover documentation accessible to a named partner organization without developer action.
- Pre-staged advisory text for the case where the developer is non-responsive after some specific interval.
- A published policy on what users should treat as authentic project communications versus impersonation if developer status is ambiguous.
- A named partner organization that has out-of-band agreed (or that the project commits to obtaining such agreement from) to issue the sunset advisory if the developer becomes unavailable for > N months.

The current sunset plan covers a much narrower scenario than the term "sunset" implies.

---

## F7. Foundation jurisdiction analysis is below diligence floor; specific factual errors

**Category:** Funder/partner credibility
**Location:** Section 8.4
**Reviewers:** Funder F1; Engineering F4; Red Team F9

**Issue.** The four-jurisdiction analysis (US 501(c)(3), Dutch Stichting, Swiss Verein, UK CIC) has specific factual errors and structural omissions:

- **Factual errors.** "Dutch Stichting (Signal Foundation precedent)" — Signal Foundation is Delaware-incorporated as a 501(c)(3), not a Dutch Stichting. "Swiss Verein or non-profit Aktiengesellschaft (Briar Project AG model)" — Briar's commercial entity was a German UG/GmbH operating alongside a UK CIC, not a Swiss Verein. These are the kind of errors a partner organization's legal advisor catches in minutes.
- **Structural omissions.** No fiscal-sponsor stage for the 18-24 month pre-incorporation window (NumFOCUS, Open Collective, Software Freedom Conservancy, Code for Science & Society) — but OTF cannot grant directly to a natural person in most program structures, so the project needs a fiscal sponsor or partner-routed grant intake from the start. Missing: tax-treaty implications for international donors; specific case law on encryption product distribution (EAR/ITAR, EU Dual Use Regulation, Wassenaar Arrangement); donor-identity disclosure regimes (US Form 990, Swiss strong-protection norms, Dutch/UK intermediate regimes); asset seizure and litigation venue per jurisdiction; banking access for privacy-tech non-profits.

**Why it matters.** A program officer at OTF asks: "Who is the grantee for the first $50-150K?" If the answer is "the developer personally for 18-24 months, then a foundation TBD," that's a non-starter. The brief's analysis being at brand-recognition depth rather than legal-structure depth signals that the project has not engaged with the actual question funders ask. The factual errors compound the credibility cost.

**Recommendation.** (a) Correct the factual errors (Signal Foundation as US 501(c)(3); Briar's UG/CIC structure rather than Swiss). (b) Add a "Pre-incorporation grant-receipt structure" subsection naming fiscal-sponsor candidates and acknowledging that grant intake during the 18-24 month pre-incorporation window requires either a fiscal sponsor or routing through a partner. (c) Acknowledge explicitly that the jurisdictional analysis is a placeholder pending legal consultation that the project will commission before incorporation; the criteria currently listed are the project's understanding and will be revised based on counsel guidance. (d) Add the omitted structural considerations (tax treaty, export regulation, donor disclosure, banking) at least as named items even if not analyzed in depth.

---

## F8. Audit budget $20-50K is below market rates for the named firms at the described scope

**Category:** Funder/partner credibility / Engineering budget
**Location:** Section 8.5
**Reviewers:** Funder F7; Engineering F5

**Issue.** The scope as described in 8.5 — cryptographic primitives, trust-graph operation handling, recovery flow, capability-token construction, release-security stack — is realistically 3-6 person-weeks of senior auditor time. Industry rates at the named firms: Trail of Bits $20-40K/week, NCC Group $15-30K/week, Cure53 $15-25K/week, Quarkslab $10-25K/week. A 3-6 week engagement at the scope named lands $60-240K. The brief's $20-50K range is plausibly the lower-bound for an Open Tech Fund-mediated audit with grant subsidy and a mission-rates audit shop, but the brief presents the figure as a market estimate.

Separately, the audit-after-pilot timing means 10-15 users have used the unaudited implementation under real adversarial conditions for six months. At the threat tier Section 3 names, this is a posture funders will question — Briar audited multiple times before broad use; Signal's audit posture is regular; Wickr's pre-deployment audits are precedents.

"Open Tech Audit Working Group" listed as a candidate firm is not, to the reviewer's knowledge, an actual named auditor; verify the reference.

**Why it matters.** A funder reading $20-50K plans against that range. $20-50K buys roughly 1-2 weeks of senior auditor time at the named firms — a light-cryptanalysis review, not a threat-tier audit. If the post-pilot broader release is gated on "audit" per the unconditional commitment (8.5), the gate fails when the audit budget exhausts before the audit completes the work the threat tier requires. The credibility damage is compounded by the audit-after-pilot timing question.

**Recommendation.** (a) Widen the budget range to $60-150K reflecting current market rates and the described scope; acknowledge that the lower bound depends on auditor-subsidy programs (Open Tech Fund's secure-audit grants, Cure53's mission-org rate) and name the subsidy program. (b) Address the audit-timing question explicitly: either defend post-pilot audit timing on grounds that pilot users are explicitly informed they are using a pre-audit implementation and consent on that basis, or move a more limited cryptographic-primitives-only audit before pilot. (c) Verify "Open Tech Audit Working Group" — likely intended to reference OTF's audit subsidy program, but the name is non-standard.

---

## F9. v1.5 6-month timeline is not credible given deferred-item engineering scope

**Category:** Roadmap timing / Engineering feasibility
**Location:** Section 7.1 v1.5; cross-check 8.1, 6.2, prior section-5-review.md F7
**Reviewers:** Engineering F12

**Issue.** The Section 5 review (F7) estimated v1 at the original scope at 18-30 months; D0004 cut to 9-12 by deferring Briar (saving 2-3 months), reproducible builds (1-2 months), local CRDT (now permanently dropped), and four UX items (1-2 months). v1.5 brings back: Briar integration (2-3 months on its own per F8/F9 of section-5-review — the bramble-core fork alone is multi-month), reproducible builds (1-2 months), local trust-graph caching (multi-week — schema, sync semantics), in-app post-coercion flow (multi-week), multi-profile UX (multi-week), duress-wipe (multi-week), optionally voice/video (months on its own), optionally localization. Sum: realistically 9-15 months for the v1.5 scope, before adding per-quarter release overhead and trust-roots health-report cycles. The brief assumes developer productivity in v1.5 matches v1; D0004's compression of v1 to 9-12 months presumed deferred scope returns at v1.5 with its own time budget, but v1.5's budget is named at 6 months, not 9-15.

**Why it matters.** v1.5 is the release that "completes the architecture." If v1.5 slips from 6 to 12+ months or is itself cut, the project's published roadmap loses the architectural-completeness commitment that distinguishes Cairn from a SimpleX wrapper. Partner organizations evaluating partnership terms in Q5 see a roadmap promise the engineering does not support.

**Recommendation.** Either (a) extend v1.5 to ~12 months post-v1 with explicit acknowledgment that this is when team scale grows (if grant funding closes per 10.4 timing); or (b) split v1.5 into v1.5 (Briar + reproducible builds; the architecture-completeness subset) at ~6 months and v1.6 (in-app post-coercion, multi-profile, duress-wipe, local caching) at ~12 months post-v1. The current v1.5 entry combines architecture-completeness with substantial UX work — the same compression failure that drove the original v1 scope-cut decision.

---

## F10. Pilot scope (10-15 users) does not validate the broader audience claim

**Category:** Funder/partner credibility
**Location:** Section 6.3 vs Section 2.2
**Reviewers:** Funder F9; Operational F5 (partial)

**Issue.** 10-15 users in 1-2 local groups is defensible _as a pilot_. The gap is between that scope and the audience claim in 2.2 (journalists in contested-press environments globally; NGO field staff across regions; organizers in active dissent; dual-use tech workers; civil-society researchers). A pilot in 1-2 local groups known to the developer cannot generate evidence about whether the architecture works for that broader audience; it generates evidence about whether it works for 1-2 specific communities the developer has access to. The brief addresses this partly by acknowledging the pilot draws from the developer's relationships, but does not connect that to what the pilot does and does not validate.

**Why it matters.** A program officer asks: "What does the pilot evidence let me conclude about broader deployment?" The current pilot scope answers a narrower question than 2.2's audience implies. This is solvable through framing — explicitly stating what the pilot validates and what it does not — but the brief does not currently do this.

**Recommendation.** Add a "what the pilot validates and does not validate" paragraph to 6.3 or 9.1. Acknowledge that v2+ deployment to the broader audience in 2.2 requires partner-organization-led pilot expansion (3-5 additional cohorts across regions, the helpline-channel question that 8.6 raises) and that v1 pilot does not substitute for that work. This is honesty about the limit and reads as project maturity.

---

## F11. Developer-as-facilitator time budget is unstated and likely exceeds part-time availability

**Category:** Operational realism
**Location:** Section 6.3 pilot deployment plan; Section 8.6 partner roles
**Reviewers:** Operational F5

**Issue.** Per-user facilitation is not a brief exchange. For 10-15 users with 5 recovery peers each (50-75 peer slots): per-user ceremony (3-6 hours synchronous), per-peer onboarding (~2 hours each, asynchronous), ongoing support across 6-month pilot (~2 hours/user/month), partner debriefs at 3 and 6 months. Conservative total: 350-400 hours over the 6-month pilot, on top of v1.5 implementation work that is the developer's stated post-MVP focus.

**Why it matters.** The pilot is the only direct evidence the architecture works (9.1). If the developer cannot sustain the facilitation, either pilot quality degrades (rushed ceremonies, peer onboarding skipped) or v1.5 implementation slips. The 3.4 trust-root entry for the facilitator says "the trust is bounded by pilot scope where the facilitator's operational discipline can be sustained directly" — this finding says the discipline at pilot scale is itself a multi-hundred-hour commitment.

**Recommendation.** Add an explicit time-budget paragraph to 6.3 or 8.6: per-user facilitation budget, per-peer onboarding budget, ongoing support budget, partner-debrief budget. Either confirm the developer's stated availability accommodates this (with what gives — likely v1.5 work slips), reduce pilot scale to 5-8 users to bring the time budget into a sustainable range, or acknowledge that v1.5 timing depends on pilot completion freeing developer capacity.

---

## F12. "No legal action against good-faith researchers" commitment is not enforceable as written

**Category:** Architectural claim / Governance
**Location:** Section 8.5; 9.4
**Reviewers:** Red Team F3

**Issue.** The "project" in v1 is a natural person (the developer). A natural person cannot bind themselves not to pursue legal action against a third party — they can publicly state intent, but the commitment is unilaterally revocable (by the developer changing their mind), survives only as long as the developer remains the project's legal identity, and does not bind successors. If the developer becomes coerced, incapacitated, bankrupt with creditors who can compel litigation as an asset, or replaced by a successor who declines to honor the policy, the commitment evaporates.

The enforceable mechanisms — Safe Harbor agreements, formal researcher-protection document, foundation-bound policy — are not invoked. The brief lists this as a commitment alongside operational architecture and license choice when it is in fact a personal preference of one individual.

**Why it matters.** Security researchers evaluating whether to disclose against this product are being asked to trust a natural person's published preference against legal action that is not legally binding on either that person or their successors. The brief's commitment is materially weaker than what reviewers familiar with the disclosure landscape will assume from the phrasing.

**Recommendation.** Either (a) downgrade to "the project's stated intent is not to pursue legal action against good-faith research; this intent will be formalized through a Safe Harbor commitment when the foundation is incorporated (8.4)"; or (b) commit _now_ to specific Safe Harbor language with reference to a public template (Bugcrowd's standard text, disclose.io). Acknowledge in 9.4 that until foundation incorporation, the commitment is a published preference rather than a legal protection.

---

# Significant Findings

## F13. "Honoraria as ongoing operational cost" commits to a multi-grant-cycle model

**Category:** Operational claim / Sustainability
**Location:** 8.2, 8.6, 9.4; cross-check Section 10 placeholder
**Reviewers:** Red Team F2; Funder F12

**Issue.** Honoraria committed as _ongoing_ operational cost in three places; grant funding does not arrive in perpetuity. OTF, Ford, Mozilla cycles are 12-24 months. Multi-year ongoing honoraria across a 5+ reviewer pool plus partner network does not map to one-shot grant instruments. Section 10 placeholder (External reviewer compensation: nominal) contradicts the commitment.

**Recommendation.** Reframe to "honoraria committed for the duration of the grant cycle from which they are funded, with project intent (not commitment) to renew in subsequent cycles." Acknowledge the volunteer-to-compensated-to-volunteer trajectory as a possible reviewer-pool experience. Revise Section 10 placeholder.

---

## F14. Two-horizon funding-risk framing doesn't answer "what if OTF says no?"

**Category:** Funder credibility
**Location:** 9.1
**Reviewers:** Funder F3

**Issue.** "Sustain the pilot indefinitely" is presented as graceful degradation. From a funder's perspective this is the failure case, not the mitigation. The brief never names the developer's self-funding floor in months, which is the number a program officer needs. OTF cycles are 4-6 months each, with backup cycles overlapping; first-rejection-to-decision can be 12+ months. Named-funder diversification is overlapping (OTF/Ford/OSF have similar evaluation criteria).

**Recommendation.** Add a "Financial floor" paragraph to 9.1: explicit calendar-month statement of how long the developer can sustain v1 development and pilot under self-funding, with stated assumptions (no audit, no honoraria, no team scaling). Diversify the named-funders list to include non-overlapping funders (NLnet, Internet Society Foundation, Reset Tech, NGI Zero Core/Entrust calls). Replace "parallel grant applications" with an actual sequencing plan.

---

## F15. Sunset plan named successors are wrong; technical scope underspecified

**Category:** Operational mitigation gap
**Location:** 9.4
**Reviewers:** Funder F4; Engineering F8

**Issue.** Three problems: (a) OTF is a _funder_, not a successor adopter; naming it inverts OTF's role. (b) Tor Project Foundation does not adopt orphaned messaging projects as policy. (c) "Partner NGO depending on circumstances" requires partner board approval — not a routine operation. Additionally, the technical scope of preservation is underspecified: Rekor entries depend on Sigstore operator persistence; Sigsum entries depend on witness participation; release artifacts depend on F-Droid/GitHub; trust graph state needs Sigsum entries to verify; the final security advisory requires the developer to be available to write it. User-data migration (10-15 pilot users with established identities, recovery peer networks, trust graphs tied to a signing identity) is not addressed.

**Recommendation.** Remove OTF from the successor-candidate list. Replace Tor Project Foundation with successor candidates that do adopt orphaned security-tooling projects — Software Freedom Conservancy, NLnet, Calyx Institute, or a fiscal sponsor maintaining the codebase. State explicitly that successor adoption is conditional on the candidate organization's agreement, which the project does not currently have. Add a "Pilot user migration" paragraph addressing how identities, trust graphs, and recovery peer networks are handled at sunset.

---

## F16. Multi-channel distribution in tension with 4.2 minimal-infrastructure principle

**Category:** Architectural claim
**Location:** 5.5/8.2 vs 4.2
**Reviewers:** Engineering F3

**Issue.** F-Droid, Accrescent, GitHub releases are straightforward. The Tor onion service is project-operated user-facing infrastructure with continuous availability requirements ($5-15/month VPS, ops time, security surface). Offline signed images is sneakernet logistics with no documented process. 4.2's "minimal project-operated infrastructure" claim is in tension with both Tor onion and offline images.

**Recommendation.** Either drop the Tor onion and offline-images channels from v1 distribution (rely on F-Droid + Accrescent + GitHub through v1, add Tor in v1.5 when funded ops capacity exists), or acknowledge in 4.2 that the project operates user-facing distribution infrastructure and revise the minimal-infrastructure principle.

---

## F17. Partner debrief cadence commits partner time without consultation

**Category:** Cross-section contradiction
**Location:** 9.4 vs 8.6
**Reviewers:** Red Team F5

**Issue.** 9.4 lists "partner-organization debriefs at 3-month and 6-month marks" as a project mitigation. 8.6 says explicitly "The brief makes no commitments on behalf of partner organizations that have not been consulted." Direct contradiction between sections.

**Recommendation.** Reframe 9.4 to "the project will seek partner-organization debriefs at intervals appropriate to partner capacity and pilot evolution, with the project's intent being approximately 3- and 6-month cadence subject to partner availability." Identify cadence as something to negotiate during Q5 outreach.

---

## F18. Reviewer toolkit "current with every release" is unscoped multi-day-per-release engineering

**Category:** Engineering scope
**Location:** 8.2
**Reviewers:** Engineering F2; Operational F2

**Issue.** Docker/Nix-pinned environment current with Rust toolchain updates (6-week cycles), AGP/NDK updates (quarterly with episodic regressions), every transitive crate CVE response, SimpleX integration dependency tree evolution, UniFFI version bumps. Realistic cost: 1-3 days per release minimum.

**Recommendation.** Either commit to LTS-class pins refreshed semi-annually (some reviewers work with slightly stale toolchains), or state explicitly that toolkit maintenance is budget-line item funded engineering covers, or commit only to "reviewers run their own environments and the project documents build commands" — much lighter contract.

---

## F19. Bug bounty deferral missing the broker-market dynamic at this threat tier

**Category:** Funder credibility
**Location:** 8.5
**Reviewers:** Funder F6

**Issue.** The funding/triage argument for v2+ bounty deferral is correct but incomplete. At the threat tier Section 3 describes, a $100K bounty pool is below adversaries' pricing through Zerodium-equivalent brokers ($1-2.5M for Android one-click chains). A bounty program at any realistic funded level cannot solve the market-position problem; the v1 deferral cannot be solved by "v2+ funding" alone.

**Recommendation.** Reframe v2+ bounty discussion to acknowledge broker-market dynamic. Pair with what v1 _does_ offer: vulnerability disclosure policy plus coordinated-disclosure relationships with research labs (Citizen Lab, Amnesty Security Lab) operating in disclose-not-sell models — the realistic threat-tier answer.

---

## F20. Audit-after-pilot timing creates pilot-specific cryptographic-correctness exposure

**Category:** Threat-model consistency
**Location:** 8.5 audit timing vs 9.3
**Reviewers:** Funder F7; Threat-Model F6

**Issue.** Pilot users receive quarterly releases that have not been through the pre-beta cryptographic audit. Broader-release users get audited releases. 9.3 does not acknowledge this pilot-specific exposure. 9.2 frames pilot users as the narrow v1 audience but does not say their release stream lacks audit coverage.

**Recommendation.** Add to 9.3 or 9.2 a specific acknowledgment: pilot users receive releases that have not been through the pre-beta cryptographic audit, and this represents residual cryptographic-correctness risk specific to the pilot user population. Pilot-user-facing documentation should name this explicitly so users can evaluate consent.

---

## F21. v2 iOS support framed as "mitigation" elides different security baseline

**Category:** Threat-model consistency
**Location:** 9.4 mitigations vs 2.2, 3.4
**Reviewers:** Threat-Model F8

**Issue.** 9.4 frames v2 iOS as the mitigation for GrapheneOS-Pixel-only without acknowledging that iOS users would be operating under a different trust-root baseline. iOS replaces GrapheneOS+Titan M2 with Apple iOS + Secure Enclave + Apple supply chain — not a like-for-like substitution. Apple is a different trust placement with different jurisdictional exposure, different update channel, different forensic-extraction posture. 2.2 acknowledges "bounded by the security baseline iOS allows" but does not specify; 9.4 does not acknowledge at all.

**Recommendation.** Revise 9.4 to acknowledge that v2 iOS extends audience but with a different security baseline. Either commit to a 3.4 update at v2 timing or acknowledge in 9.3 that v2 iOS audiences would receive a different residual-surface profile than v1 GrapheneOS-Pixel users.

---

## F22. Documentation effort 9-14 weeks unbudgeted; partner co-production not arranged

**Category:** Engineering scope
**Location:** 5.7, 6.1, 8.5 references
**Reviewers:** Engineering F11; Operational F6

**Issue.** Six distinct documentation artifacts (user guide, facilitator handbook, peer-recovery handbook, post-coercion guidance, troubleshooting, security model overview) total ~9-14 weeks of solo-developer time. The brief notes partner organizations as "natural collaborators" but Q5 is open and partnerships have not been arranged. If partnerships don't form by v1 alpha, the developer writes all six docs on top of v1 implementation.

**Recommendation.** Add a documentation timeline to v1 scope explicitly. Identify which docs ship at v1 alpha (minimum subset for pilot facilitator and peer enablement), which ship by v1 release, which can lag into v1.x. State explicitly what happens if partner co-production does not materialize.

---

## F23. Emergency-release 2-of-5 path contradicts 8.3's "external review unconditional"

**Category:** Cross-section contradiction
**Location:** 8.2 emergency path vs 8.3 unconditional review
**Reviewers:** Threat-Model F10; Red Team F4

**Issue.** 8.3 commits external review as unconditional for security-critical commits "even under deadline pressure." 8.2 emergency-release path relaxes the 3-of-5 release-attestation threshold to 2-of-5. The brief does not explicitly distinguish pre-merge review from release attestation; reviewers do both, and the relationship under deadline pressure is ambiguous.

**Recommendation.** Revise 8.3 to "External reviewer review (3-of-5 attestation by default, 2-of-5 for documented emergencies per 8.2) is required for security-critical changes." Drop the "unconditional" framing. Add explicit language in 8.2 covering the scenario where fewer than 2 reviewers are reachable: ship with one-attestation labeled, hold the patch, or specified delegation pathway.

---

## F24. v2/v3 timing assumes team growth not committed in 8.1

**Category:** Roadmap timing
**Location:** 7.1 v2/v3 vs 8.1 team scaling
**Reviewers:** Engineering F13

**Issue.** v2 (12-18 months) + v3 (18-24 months) named work totals 16-32 months on solo-developer time. Achievable in calendar window only if team growth happens around v1.5/v2 transition. 8.1 names team scaling as funding-conditional (Q3); the brief does not connect 8.1 to 7.1 timing.

**Recommendation.** Annotate each post-v1 release in 7.1 with explicit team-scale assumptions — e.g., "v2 timing assumes 2-3 FTE engineering by month 12 post-v1, contingent on Q3 grant outcomes per 8.1." Without annotation, timing reads as solo-developer commitment the engineering cost does not support.

---

## F25. Trust-roots health report scope is narrower than 3.4 trust roots list

**Category:** Mitigation gap
**Location:** 9.4 vs 3.4
**Reviewers:** Threat-Model F5; Engineering F7

**Issue.** 3.4 enumerates 11 explicit trust roots. 9.4 commits to monitoring 4 (GrapheneOS, Pixel hardware, Sigstore/Sigsum, reviewer pool). Omitted: cryptographic primitives, Tor, SimpleX/Briar protocols, build supply chain, in-person facilitator, OIDC provider separately, witness-pool independence, the user. Annual cadence by solo developer with 9.1 SPOF risk is itself unsustainable as scoped.

**Recommendation.** Either expand the report scope to cover all 3.4 trust roots, or explicitly scope to the subset and acknowledge other roots are not monitored. Condition cadence on team scale. Define "health" measurably for each named root.

---

# Minor Findings

## F26. 9.3 omits side-channel, supply-chain depth, Sigstore operational risk, project legal jurisdiction

**Severity:** Minor
**Location:** 9.3 threat-model out-of-scope items
**Reviewers:** Red Team F11

Add: side-channel attacks against TEE and secure element; supply-chain attacks against Rust crate tree (named mitigations: cargo-vet, cargo-crev); Sigstore-specific operational risks; the project's own legal jurisdiction (whatever it is) as a trust-root exposure; classical cryptanalytic advances against chosen primitives.

---

## F27. Apache 2.0 + DCO defense is one sentence each; multiple alternatives uncontested

**Severity:** Minor
**Location:** 8.3
**Reviewers:** Red Team F7

Expand 8.3 license-and-DCO discussion to address: AGPL alternative for any present or future server-side component; DCO over minimal CLA given the established-org tier and AI-attribution concerns; project policy on dual-licensing if v4+ tier requires it; acknowledgment that license decision is harder to reverse than most other commitments.

---

## F28. Partner candidate-listing crosses to overreach in specific places

**Severity:** Minor
**Location:** 8.6 specific candidate characterizations
**Reviewers:** Funder F5

Specific overreach: Access Now Helpline as "natural channel" for facilitating pilot users via the helpline's existing user base; "EFF Threat Lab" as reviewer candidate (Threat Lab does threat-actor research, not third-party project source-review attestation); "Citizen Lab's technical staff" listed under both reviewer pool and threat intelligence with implied institutional commitment.

Rewrite to remove project-side framing of partner capacity; acknowledge institutional process required.

---

## F29. Section 10 placeholder content contradicts Section 8 honoraria commitments

**Severity:** Minor
**Location:** Section 10 placeholder
**Reviewers:** Funder F12

Section 10 placeholder shows "External reviewer compensation: nominal (in-kind for many, small honoraria for some)" — contradicts Section 8 ongoing-honoraria commitments. Cross-reference inconsistency. Either revise Section 10 placeholder or annotate Section 8 cross-references to acknowledge Section 10 revision pending.

---

## F30. Foundation board composition omits financial governance

**Severity:** Minor
**Location:** 8.4 board composition criteria
**Reviewers:** Funder F11

Missing: treasurer or audit-committee chair with non-profit financial-governance background. Add to composition criteria.

---

# Recommended action plan

Findings break into four action categories:

**A. Prose edits to Sections 3, 8, 9 — surgical, straightforward.**
F3 (add omitted surfaces to 9.3), F4 (add omitted trust roots to 9.3), F5 (add new trust placements to 3.4/9.3), F10 (pilot scope vs audience), F11 (facilitator time budget), F14 (financial floor in 9.1), F17 (partner debrief cadence reframing), F19 (bug bounty broker-market acknowledgment), F20 (pilot audit exposure acknowledgment), F21 (v2 iOS baseline), F22 (documentation timeline), F23 (8.3 conditional review framing), F24 (v2/v3 team-growth annotation), F25 (trust-roots health scope), F26-F30 (minor additions and acknowledgments).

**B. New decision documents — judgment calls required.**

- **D0008 — Volunteer-to-honoraria operational policy** (F2, F13). Cadence, threshold, rotation, and toolkit-maintenance commitments scaled to volunteer baseline with explicit transition to funded state. Possibly the single highest-leverage decision in this review.
- **D0009 — Sudden-developer-unavailability contingency** (F6). Dead-man's-switch mechanism, pre-staged successor handoff, pre-arranged partner advisory authority. Addresses the gap the Section 5 review flagged at the developer-as-target level.
- **D0010 — Foundation jurisdiction analysis with legal-consultation commitment** (F7). Either commit to specific fiscal-sponsor stage and named legal counsel for incorporation, or restructure 8.4 as placeholder pending consultation.
- **D0011 — Audit budget and timing decision** (F8, F20). Revise budget to market range with named subsidy-program dependencies; address audit-timing question (post-pilot vs pre-pilot for cryptographic-primitives subset).
- **D0012 — Researcher Safe Harbor commitment** (F12). Either formalize through Bugcrowd/disclose.io template now, or commit to formalization at foundation incorporation with clear acknowledgment of current limit.

**C. Architectural-claim reframing — register adjustments.**

- F1 — Audit Section 8 "commits" instances; reclassify conditional ones; tighten introduction's register claim.
- F2 — Acknowledge volunteer-baseline operational ceiling honestly; scale Section 8 commitments to fit (or commit to honest slippage).
- F9 — Either extend v1.5 timeline or split into v1.5/v1.6.
- F15 — Sunset plan successor list correction and technical scope expansion.
- F16 — Multi-channel distribution vs 4.2 principle: drop channels or revise principle.

**D. New open questions.**

- Q13: Volunteer-baseline operational ceiling and explicit slippage tolerance.
- Q14: Pre-staged developer-unavailability mechanisms (signatories, partners, dead-man's-switch infrastructure).
- Q15: Fiscal sponsor selection for pre-incorporation grant intake.
- Q16: Researcher Safe Harbor template selection and timing.

---

# Strategic note

This review is comparable in volume to the Section 5 review (32 consolidated findings; Section 5 produced 32). The key difference is the _kind_ of finding: Section 5's review surfaced architectural and engineering issues; Sections 8/9 review surfaces commitment-credibility issues. The brief's design discipline is strong; the brief's operational-commitment discipline has not yet been audited at the same depth, and this review is that audit.

The most actionable single edit is the reframing in F1 — the Section 8 introduction's register claim either holds across the section or doesn't, and currently it doesn't. Fixing the introduction without fixing the subsections it claims to govern is a worse outcome than either fix alone; the edit needs to span both. After F1 the next-highest leverage is F2 + D0008 (volunteer-baseline scaling) and F6 + D0009 (sudden-unavailability mechanism), which together resolve the operational-realism / sustainability gap that funders and partners will read this section for.

The brief's overall posture — self-funded MVP, conditional register, honest about limits — is the right posture for an unfunded design brief. The remaining gaps are at the level of specific commitments not living up to the section-level posture; closing them does not require revising the strategy, only the prose.
