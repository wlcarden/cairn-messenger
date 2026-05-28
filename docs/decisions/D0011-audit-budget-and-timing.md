# D0011 — Audit budget and timing: widen budget to market range, add pre-pilot primitives-only audit

**Status:** Accepted
**Date:** 2026-05-28

## Context

The Sections 8/9 adversarial review surfaced finding F8 (audit budget $20-50K is below market rates for the named scope) and finding F20 (audit-after-pilot timing means pilot users carry residual cryptographic-correctness risk that broader-release users do not). Two reviewers identified each issue independently.

The budget question: industry rates at the named candidate firms — Trail of Bits, NCC Group, Cure53, Quarkslab — are $15-40K per week of engagement. The scope described in 8.5 (cryptographic primitives, trust-graph operation handling, recovery flow, capability-token construction, release-security stack) is realistically 3-6 person-weeks of senior auditor time. The brief's $20-50K range is plausibly the lower bound for an auditor-subsidy-mediated engagement but is presented as a market estimate.

The timing question: pilot users (10-15 users at the threat tier Section 3 describes) use the unaudited cryptographic implementation under real adversarial conditions for six months before the pre-beta audit. This is a posture funders at this threat tier question — Briar audited multiple times before broad use; Signal's audit cadence is regular through development; Wickr's pre-deployment audits are precedents.

## Decision

**Two-stage audit approach: pre-pilot cryptographic-primitives audit (limited scope, smaller budget) plus pre-beta full audit (broader scope, market-range budget) post-pilot.**

### Pre-pilot cryptographic-primitives audit

Before pilot deployment, the project commissions a limited-scope audit covering:

- The capability-token COSE_Sign1 envelope construction and verification (per [D0006](D0006-cryptographic-envelope.md)).
- The Shamir Secret Sharing reconstruction code, including memory-hygiene properties (per [D0003](D0003-implementation-language.md)).
- The trust-graph operation envelope's nine-field schema and signature chain, including the issuer-cert-hash binding (per D0006).
- The recovery-flow cryptographic operations (peer-challenge verification, master reconstruction, re-split, zeroize).

**Budget: $15-30K** at the lower auditor-subsidy tier, or $30-50K at the unsubsidized small-engagement tier. Realistic 1-2 person-weeks at Cure53 mission rates or Open Tech Fund audit-grant rates.

**Purpose:** Pilot users receive an implementation whose cryptographic core has been externally reviewed, even if the broader integration has not. The audit-after-pilot exposure that F20 identifies is bounded to the integration boundary rather than to the cryptographic primitives.

**Auditor candidate priorities for this engagement:** Cure53 (operational track record with mission-rate engagements; specific competence in messaging-product audits); Open Tech Fund audit-grant program (specifically designed for this stage of project); Trail of Bits cryptographic-primitives review (higher rate but most senior cryptographic specialization).

### Pre-beta full audit

After pilot completion, before broader-than-pilot release, the project commissions the full pre-beta audit at scope and budget consistent with the audit landscape:

- **Scope:** Full cryptographic-primitive review (re-confirming the pre-pilot audit findings against any v1.5 changes); full trust-graph operation handling; full recovery flow; capability-token construction; release-security stack including Sigstore and Sigsum integrations; UnifiedPush push-notification implementation if push is enabled by default in v1.5.
- **Budget: $60-150K** reflecting market rates at the named firms. Lower bound depends on auditor-subsidy programs (Open Tech Fund audit grants; Cure53 mission-org rates; Trail of Bits civic-tech engagements at reduced rate). Upper bound covers unsubsidized engagement at standard rates for a 4-6 week engagement.

**Auditor candidate priorities for this engagement:** Trail of Bits or NCC Group for breadth and depth (higher cost; correspondingly broader scope); Cure53 if mission-rate engagement extends from the pre-pilot audit; Quarkslab as a non-U.S.-jurisdiction option (relevant if the project incorporates outside the U.S. per D0010).

### Named subsidy programs

The project commits to applying to the following subsidy programs as the first funding route for both audit stages:

- **Open Tech Fund Secure Audit program** — subsidizes external audits for projects meeting OTF's mission criteria; Cairn's audience and threat-model alignment with OTF's program are strong.
- **Cure53 mission-org rates** — applies to civil-society security tools at reduced rates relative to commercial engagement.
- **Mozilla Open Source Audit Awards** — periodic funding for open-source security audits.
- **NLnet NGI Zero Trust calls** — European funding instrument that includes audit allocations.

The brief states that the lower bound of each audit-budget range depends on one or more of these subsidy programs closing for Cairn; the upper bound is the unsubsidized market rate.

## Alternatives considered

**Widen budget; defend post-pilot timing on informed-consent grounds.** _(Considered, rejected.)_ Pilot users could be informed they are using a pre-audit implementation and consent on that basis. Rejected because the consent framing places the risk-evaluation burden on users who are by 3.1 audience note specifically the population whose support network — not themselves — understands threat-model tradeoffs. Asking pilot users to consent to unaudited crypto is asking them to evaluate something the brief elsewhere says they cannot evaluate. The pre-pilot primitives audit shifts the consent burden to "informed about the audit scope and what it does and doesn't cover," which is a meaningfully different ask.

**Keep $20-50K as subsidy-conditional with named programs.** _(Considered, rejected.)_ Doesn't address the timing question (F20). The audit budget is the smaller of the two issues; the timing of when audits land relative to pilot deployment is the larger one, and a budget-only adjustment leaves the timing concern unaddressed.

## Consequences

### Section 8.5 updates

The "Pre-beta external cryptographic review" paragraph is rewritten to describe the two-stage approach: pre-pilot primitives audit (named scope and budget); pre-beta full audit (named scope and budget). Both budget ranges are stated with the upper bound (unsubsidized) and lower bound (subsidized) explicit, plus the named subsidy programs the project will apply to first.

The "Bug bounty: v2+ candidate" paragraph is unchanged.

### Section 10 budget implications

Section 10 (when drafted) gains two audit line items:

- Pre-pilot primitives audit: $15-30K subsidized, $30-50K unsubsidized.
- Pre-beta full audit: $60-150K split similarly.

Total audit budget across v1 and pre-broader-release: $75-200K. This is materially higher than the brief currently implies and meaningfully changes Section 10's overall budget picture. The brief commits to applying to subsidy programs as the first route; the higher bounds are stated as honest market rates rather than as immediate budget requests.

### Pilot deployment plan implications

Section 6.3 pilot deployment gains a sentence that pilot users receive an implementation whose cryptographic primitives have been externally audited prior to pilot; the integration boundary (trust-graph state handling, recovery-flow orchestration, release-security stack as integrated) carries residual audit-not-complete risk until the pre-beta audit. This is the consent framing pilot users receive at provisioning.

### Open question

Q7 (External cryptographic audit firm) in [open-questions.md](../open-questions.md) is updated to reflect the two-stage approach. The pre-pilot audit timing accelerates the Q7 firm-selection question from "~12 months out" to "pre-pilot, ~6-9 months from brief completion."

### Reversibility

The two-stage approach is reversible at low cost. If pre-pilot audit funding does not close, the project either reduces pre-pilot scope further (e.g., capability-token construction only) or defers to post-pilot single-audit timing with explicit acknowledgment that pilot users carry the residual risk. The decision is structurally about audit _staging_ rather than _commitment_ — the no-skip-the-audit commitment from the funding-stance touch-ups still applies, and the staging only changes when audits land, not whether they land.

The pre-beta audit budget at the upper bound ($150K) is conditional on funding closing at that scale; if only the lower-bound subsidy is available, the audit scope is correspondingly narrower with explicit acknowledgment.

## References

- [docs/sections-8-9-review.md](../sections-8-9-review.md) — F8, F20.
- [docs/open-questions.md](../open-questions.md) — Q7 (audit firm selection; updated by this decision).
- Open Tech Fund Secure Audit program: https://www.opentech.fund/funds/secure-audit/
- Cure53 audit history and engagement model: https://cure53.de
- Trail of Bits civic-tech engagement: https://www.trailofbits.com
- Industry-rate references: public audit-report engagement summaries from the named firms across 2023-2025.
