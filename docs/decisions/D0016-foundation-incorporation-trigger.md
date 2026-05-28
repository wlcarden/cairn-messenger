# D0016 — Foundation incorporation deferred with v1.5 broader-release evaluation trigger

**Status:** Accepted
**Date:** 2026-05-28

## Context

The architecture-simplification adversarial review surfaced F6: the foundation-incorporation pathway is the largest single recurring-coordination commitment in the brief outside of release engineering. The multi-year-solo-developer-feasibility lens (Lens E) identified that foundation administration imposes ongoing operational load — board interface, jurisdictional compliance, regulatory filings, fiscal infrastructure, IP-assignment maintenance — that compounds with every other Phase D operational commitment in §10.4. The lens recommended reframing foundation incorporation from "approximately 18–24 months post-v1 milestone" (the [D0010](D0010-foundation-jurisdiction.md) placeholder posture) to "conditional, indefinite — pursued only if project reaches operational scale that supports the foundation overhead."

The decision space for the project was:

- **Option A — Defer indefinitely.** Foundation incorporation becomes out-of-scope-indefinitely framing. Fiscal sponsor becomes the permanent grant-receipt structure. D0009 partner advisory authority becomes the permanent governance scaffold. D0012 Safe Harbor remains published preference indefinitely. Simplifies §10.3 Phase C and §10.4 Phase D scope materially.
- **Option B — Defer with trigger.** Foundation incorporation reframed as conditional, with the decision revisited at v1.5 broader-release planning when pilot evidence and Phase B/C funding scale are concrete and partner-organization conversations have matured. Captures the v1 and Phase C simplification benefits without permanently foreclosing the incorporation pathway. Preserves the optionality the project does not yet have evidence to resolve.
- **Option C — Keep current.** D0010's "placeholder pending legal consultation, ~18-24 months post-v1" framing maintained. Phase C and Phase D continue to carry the incorporation work; structural mitigations (Safe Harbor formalization, board-bound governance, formal partner advisory authority) land at incorporation as currently committed.

The project chose Option B — defer with trigger — as the cleanest framing for an undecided question. The structural mitigations Cairn currently commits to land at incorporation (D0012 Safe Harbor formalization, board-bound governance, formal partner advisory authority per D0009) may matter operationally for broader-release credibility, but the brief does not yet have the evidence to determine whether they matter enough to justify the recurring foundation-administration overhead at the project's actual operational scale. The trigger-based approach pushes that decision to the point at which the evidence exists.

## Decision

**Foundation incorporation is deferred from the v1 / Phase C / Phase D operational scope, with the decision revisited at the v1.5 broader-release planning window.** D0010's jurisdictional analysis and legal-consultation framework persist as the substrate the project acts on _if_ the trigger activates; D0009's partner advisory authority persists as the governance scaffold _whether or not_ the trigger activates. Fiscal sponsor arrangement per [D0010](D0010-foundation-jurisdiction.md) becomes the operational grant-receipt structure for the duration of the deferral, with the explicit acknowledgment that it may be permanent rather than transitional.

### The v1.5 broader-release evaluation trigger

At v1.5 broader-release planning, the project evaluates foundation incorporation against the following criteria. If two or more activate, the project proceeds with incorporation per D0010's framework; if fewer than two activate, incorporation remains deferred and the project continues operating under fiscal-sponsor arrangement with D0009 partner advisory authority as governance scaffold.

**Trigger criterion 1 — Pilot evidence indicates structural mitigation needs.** Pilot users, partner organizations facilitating the pilot, or pilot debrief evidence specifically identify that "stated intent" Safe Harbor (D0012 published preference) is insufficient for their operational needs, or that the lack of board-bound governance per §8.4 is a deployment barrier for them. The criterion activates if at least one partner organization the project has substantive Q5 engagement with names this requirement explicitly.

**Trigger criterion 2 — Funding scale.** Cumulative grant intake reaches a threshold where foundation overhead ($10–30K/year per §10.4) is materially cheaper than continued fiscal-sponsor fees (5–15% of routed grants per §10.2). At ~$300K/year sustained grant intake, fiscal-sponsor fees of ~$30–45K/year materially exceed the foundation-overhead ceiling; the breakeven point is approximately $200K/year sustained grant intake at the higher end of the fee range or $400K/year at the lower end. The criterion activates if the project's sustained grant intake at v1.5 broader-release planning has reached or trends toward the relevant threshold.

**Trigger criterion 3 — Funder requirement.** A funder the project depends on for sustained operations explicitly requires incorporation as a condition of continued funding (rather than fiscal sponsorship). Some larger foundations (per §10.5 direct grants category) have eligibility constraints that prefer or require incorporated grantees past a scale threshold; the criterion activates if at least one such funder Cairn has substantive relationship with names this requirement before grant award.

**Trigger criterion 4 — Personal liability exposure.** Pilot operations, broader-release operations, or specific incidents (security disclosure handling, partner-organization disputes, regulatory inquiries) create personal-liability exposure for the developer that the fiscal-sponsor arrangement does not adequately address. The criterion activates if legal consultation specifically identifies a personal-liability scenario that incorporation would mitigate. This criterion is consultation-mediated; the developer engages D0010-style non-profit legal counsel to evaluate whether liability exposure justifies incorporation.

**Trigger criterion 5 — Structural-mitigation cascade.** Multiple D-series decisions (D0012 Safe Harbor, D0009 partner advisory authority formalization, §8.2 reviewer-honoraria foundation legal structure) reach a point where each of their "incorporation lands the formal version" framings is operationally needed simultaneously. The criterion activates if at least three of these structural mitigations are independently named as needing formalization at v1.5 broader-release planning.

The "two or more activate" threshold reflects that any single trigger by itself may be addressable through alternative means (Safe Harbor partnership letter; partner advisory authority renewal cycle; etc.); two activating simultaneously indicates the cumulative case has become operational.

### Permanent fiscal-sponsor arrangement framing

The fiscal-sponsor arrangement per [D0010](D0010-foundation-jurisdiction.md) is reframed from "pre-incorporation 18–24-month transition stage" to "operational grant-receipt structure for the duration of the deferral, which may be permanent." Section 10.5 funding-source roster surfaces this as the working assumption: fiscal sponsor is the route through which all grants are received until and unless the trigger activates. The 5–15% fee per §10.2 / §10.8 is permanent operational overhead under this framing, not transitional.

NLnet's grantee-sponsorship model continues to be the lowest-friction route per §10.2 — NLnet sponsors its own grantees without the 5–15% routing fee, making NLnet-routed grants the financially preferable path within the fiscal-sponsor framing. Section 10.6 sequencing strategy commits the project to prioritizing NLnet (when fit) over fiscal-sponsor-routed alternatives.

### Governance scaffold under permanent-deferral framing

D0009 partner advisory authority (currently named as the pre-incorporation transition state with the foundation board taking over at incorporation) becomes the permanent governance scaffold under the deferral. The project commits to:

- Maintaining the D0009 monthly dead-man's-switch check-in indefinitely (not transitioning to foundation governance at the 18–24-month mark).
- Renewing the partner advisory authority arrangement per its multi-year cycle indefinitely (per the Q14 partner-organization conversation outcomes; the renewal cadence becomes a permanent operational commitment rather than a transition state).
- Surfacing the governance posture transparently in §8.4 and §9.4 so partners and pilot users understand that the partner-arranged advisory authority is the project's permanent governance commitment rather than a placeholder.

D0012 Safe Harbor under permanent-deferral framing remains published preference indefinitely. The brief commits in §8.5 / D0012 to:

- Maintaining the published disclosure policy, PGP-encrypted contact, 90-day disclosure timeline, public acknowledgment of good-faith researchers, and stated intent not to pursue legal action — indefinitely under the natural-person-operated structure.
- Surfacing the legal-non-enforceability honestly as a structural property of the deferral, not as a temporary state pending incorporation.
- If the trigger activates and incorporation proceeds, D0012's Safe Harbor template selection (Q16) becomes operationally relevant; until then, Q16 remains deferred indefinitely as well.

## Alternatives considered

**Option A — Defer indefinitely.** _(Considered, partially adopted.)_ Cleaner simplification but forecloses the incorporation pathway entirely. The trigger-based approach (Option B) captures the same v1 and Phase C simplification benefits while preserving incorporation as a possible future state. The "permanent fiscal sponsor" framing of Option A is preserved in the description of the deferral period — fiscal sponsor is operationally permanent unless the trigger activates — without committing the project to never incorporating.

**Option C — Keep current D0010 framing.** _(Considered, rejected.)_ Maintains the §10.3 Phase C incorporation budget and §10.4 Phase D foundation-overhead line items, carrying the §10.4 Phase D sustainability cliff arithmetic that the simplification review identified as the central long-horizon problem. The D0010 18–24-month timeline is currently asserted without the evidence base to justify it as a specific operational commitment.

**Defer to v1.5 commit; incorporate immediately when first criterion activates.** _(Considered, rejected.)_ Single-criterion activation is too sensitive — a single partner organization naming Safe Harbor formalization could trigger incorporation when alternative arrangements (Safe Harbor partnership letter; specific dispute-resolution process) might address the underlying concern without the recurring foundation-administration overhead. The two-of-five threshold reflects that single-criterion concerns are usually addressable; cumulative-criterion concerns are usually structural.

**Permanent fiscal sponsorship with explicit out-of-scope-indefinitely framing.** _(Considered, rejected as primary framing.)_ The brief's honest-disclosure posture is undermined if the project commits to "foundation incorporation is out-of-scope-indefinitely" without the evidence to support that commitment. The trigger framing captures the same operational outcome (fiscal sponsor permanent unless evidence justifies change) while honestly acknowledging that the decision depends on evidence the brief does not yet have.

## Consequences

### Brief sections affected

- **§1.4 v1.5 ship-conditions and §1.5 operational posture.** "Foundation incorporation materially in progress" removes from the v1.5 broader-release gate; replaced by "v1.5 broader-release planning includes the D0016 trigger evaluation." Operational posture acknowledges fiscal-sponsor arrangement as the project's operational grant-receipt structure for the duration of the deferral.
- **§3.4 Trust roots, Q14 partner advisory authority.** Becomes "permanent governance scaffold under D0016 deferral" framing rather than "pre-incorporation transition state."
- **§7.1 v1.5 ship-conditions.** Condition (d) "foundation incorporation per §8.4 / D0010 is materially in progress" replaced with "the D0016 trigger evaluation is complete (whether the outcome is to incorporate, to defer further, or to commit to indefinite fiscal-sponsor operation, the decision is on the record at v1.5 broader-release planning)."
- **§7.2 Governance and assurance milestones.** Foundation incorporation milestone reframed as "evaluated at v1.5 per D0016 trigger criteria; if criteria activate, foundation work commences per D0010 framework."
- **§8.4 Path to foundation.** Substantial rewrite. The "intent: incorporate as a non-profit foundation approximately 18–24 months post-v1 launch" commitment reframes to "the project's intent is to evaluate foundation incorporation at v1.5 broader-release planning against the D0016 trigger criteria; if the criteria activate, the D0010 jurisdictional analysis and legal-consultation framework apply." The jurisdictional analysis stays in D0010 as the substrate the project acts on if the trigger activates; §8.4 surfaces the deferred-with-trigger posture rather than the 18–24-month-incorporation framing.
- **§8.5 Audit and assurance.** Researcher Safe Harbor reference updates: "formalization at foundation incorporation per D0012" reframes as "formalization at foundation incorporation if D0016 trigger activates; otherwise published preference indefinitely." The pre-beta full audit scope at v1.5 (per D0011) is unaffected.
- **§9.1 Project risks.** "Foundation incorporation funding does not close" risk becomes "Foundation incorporation trigger does not activate" — qualitatively different framing. The project does not view trigger non-activation as a failure mode if pilot scale and funding outcomes do not justify incorporation; it is the expected outcome under that scenario.
- **§9.4 Mitigations and monitoring, sunset plan.** D0009 partner advisory authority reframed as permanent governance scaffold; the "foundation incorporation provides the structural mitigations" framing reframes to "if D0016 trigger activates, the foundation provides the structural mitigations; otherwise D0009 partner advisory authority is the permanent scaffold."
- **§10.3 Phase C unlock scope.** Foundation incorporation budget ($5–25K) and reviewer-honoraria operating model both remove as Phase C strict gates. Phase C scope narrows to: pre-beta full audit ($60–220K); optional UX engineer ($30–60K); optional reviewer honoraria pilot-period allocation if Q3 closes at right scale. Phase C floor reduces accordingly; Phase C ceiling also reduces.
- **§10.4 Phase D operations.** Foundation overhead ($10–30K/year) reframes as conditional: budgeted only if D0016 trigger activates. Default Phase D scope under deferral: recurring audit cycle + reviewer honoraria + infrastructure + localization (no foundation overhead line item). Phase D floor at deferral: approximately $85K/year (audit amortization + minimum honoraria + infrastructure + minimum localization, no foundation overhead). Phase D ceiling at deferral: approximately $220K/year. Fiscal-sponsor fees become a permanent operational pass-through reducing net grant receipts rather than a transitional cost.
- **§10.5 Funding sources.** Fiscal sponsor category reframes as permanent grant-receipt structure for the duration of the D0016 deferral. NLnet grantee-sponsorship route surfaces as the financially-preferable path within the fiscal-sponsor framing.
- **§10.6 Funding strategy and sequencing.** NLnet routes prioritized over fiscal-sponsor-routed alternatives where mission fit allows; fiscal-sponsor selection (Q15) becomes a permanent operational decision rather than a transitional one.
- **§10.7 Funding risks.** "Foundation incorporation funding does not close" failure mode reframes to "D0016 trigger does not activate; project continues under fiscal-sponsor operation indefinitely" — a normal operational state rather than a failure mode. "Maintainer compensation at Phase D scale does not materialize" failure mode persists; D0016 deferral reduces the Phase D sustainability cliff but does not eliminate it.
- **§10.8 What this section does not promise.** Updates to acknowledge that the brief does not promise foundation incorporation will happen at any specific point; the D0016 trigger framework is the commitment, and trigger non-activation is the expected outcome under several plausible operational trajectories.

### Decision documents affected

- **D0009 (sudden-developer-unavailability contingency).** Partner advisory authority framing reframes from "pre-incorporation transition state; foundation board takes over at incorporation" to "permanent governance scaffold for the duration of the D0016 deferral; if trigger activates and foundation incorporates, the foundation board takes over from the partner-arranged advisory authority at that point." Renewal cadence becomes a permanent operational commitment.
- **D0010 (foundation jurisdiction handling).** Status updates to reflect the D0016 deferral. The jurisdictional analysis and legal-consultation framework persist as the substrate the project acts on _if_ the trigger activates. The "approximately 18–24 months post-v1" timeline references remove. The fiscal-sponsor candidates list (Q15) becomes permanent grant-receipt structure rather than pre-incorporation transition.
- **D0012 (researcher Safe Harbor).** Formalization timing reframes from "at foundation incorporation (~18–24 months post-v1)" to "at foundation incorporation _if_ D0016 trigger activates; otherwise the project continues operating under published-preference Safe Harbor indefinitely." The Q16 template-selection question is partially deferred along with the trigger — Q16 is operationally relevant only if the trigger activates.

### Open questions affected

- **Q14 (partner advisory authority).** Partner-organization selection becomes more important — the partner advisory authority is the permanent governance scaffold under the deferral, not a pre-incorporation transition placeholder.
- **Q15 (fiscal sponsor selection).** Becomes a permanent operational decision rather than transitional. The selection criteria emphasize sustainability (multi-year operational reliability; consistent fee structures; established track record) over transition-state suitability.
- **Q16 (Safe Harbor template selection).** Partially deferred along with the D0016 trigger — operationally relevant only if the trigger activates.

### What the brief does not commit to

- A specific calendar timeline for foundation incorporation. The trigger framework is the commitment; trigger activation depends on evidence the brief does not yet have.
- That the trigger will activate. Trigger non-activation is the expected outcome under several plausible operational trajectories (low sustained grant intake; no partner-organization requirements for formal Safe Harbor; no personal liability incidents requiring incorporation mitigation).
- A specific fiscal sponsor for the permanent grant-receipt structure. Q15 remains open; the operational reframing is that fiscal-sponsor selection should be made on permanent-operational-fit criteria rather than transitional-suitability criteria.
- That structural mitigations (formalized Safe Harbor, board-bound governance, formal partner advisory authority) will land at any specific point. They remain at "stated intent" posture indefinitely unless the trigger activates.

### Reversibility

The decision is reversible in two directions:

- _Toward incorporation:_ if any individual trigger criterion activates with operational urgency before v1.5 broader-release planning, the project can initiate incorporation work without waiting for the planned evaluation cycle. The D0010 framework is the substrate; legal consultation per D0010 is the first step.
- _Toward indefinite deferral:_ if v1.5 broader-release planning evaluates the trigger criteria and none activate, the project can subsequently re-evaluate at later release planning cycles (v1.6, v2 broader-release planning). The deferral is not one-time; it is the ongoing operational state until a trigger evaluation activates incorporation work.

The structural-mitigation framing in §10.7 (mitigations remain at stated-intent posture) persists under the deferral; if the trigger never activates, the project operates under that framing indefinitely. This is the honest framing the brief commits to rather than the placeholder "incorporation eventually" pattern the deferral replaces.

## References

- [docs/architecture-simplification-review.md](../architecture-simplification-review.md) — F6 (the foundation-incorporation deferral case).
- [docs/decisions/D0009-sudden-unavailability.md](D0009-sudden-unavailability.md) — partner advisory authority becomes permanent governance scaffold.
- [docs/decisions/D0010-foundation-jurisdiction.md](D0010-foundation-jurisdiction.md) — jurisdictional analysis substrate the project acts on if trigger activates.
- [docs/decisions/D0012-researcher-safe-harbor.md](D0012-researcher-safe-harbor.md) — Safe Harbor formalization timing reframes.
- [docs/decisions/D0015-v1-release-security-posture.md](D0015-v1-release-security-posture.md) — release-security architectural target (v1.5) interacts with this decision via the v1.5 broader-release planning window.
