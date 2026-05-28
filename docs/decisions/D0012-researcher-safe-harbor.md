# D0012 — Researcher Safe Harbor: stated intent until foundation incorporation, formalized at incorporation

**Status:** Accepted
**Date:** 2026-05-28

## Context

The Sections 8/9 adversarial review surfaced finding F12: the "project does not pursue legal action against good-faith researchers" commitment in 8.5 and 9.4 is not enforceable as written. The "project" in v1 is a natural person (the developer). A natural person cannot bind themselves not to pursue legal action against third parties in a way that survives:

- The developer changing their mind (the commitment is unilaterally revocable as a published preference).
- Developer coercion (the developer may be compelled to issue legal threats against researchers).
- Developer bankruptcy with creditors who can compel litigation as an asset.
- Successor takeover that declines to honor the policy.

The enforceable mechanisms — Safe Harbor agreements anchored in a foundation entity, formal researcher-protection documents, board-bound policies — are not invoked because they require the foundation that 8.4 defers to ~18-24 months post-v1. The brief currently presents this commitment alongside operational architecture and license choice when it is in fact a personal preference of one individual.

Security researchers evaluating whether to disclose against this product face the question: "what protections do I actually have?" The brief's current text answers that question with language stronger than the legal protections actually provide.

## Decision

**Downgrade the researcher-protection commitment to stated intent until foundation incorporation; commit to formalization through a Safe Harbor template (disclose.io or equivalent) at incorporation.**

### v1 pilot-phase posture

The brief commits in 8.5 to the following:

- A published security disclosure policy with PGP-encrypted contact, 90-day default disclosure timeline, public acknowledgment of good-faith researchers.
- The developer's _stated intent_ not to pursue legal action against researchers disclosing in good faith.
- Explicit acknowledgment that until foundation incorporation (per [D0010](D0010-foundation-jurisdiction.md) and Section 8.4), this commitment is a published preference rather than a legal protection. The developer is a natural person and cannot bind themselves or successors in a legally enforceable way.

The acknowledgment is named in the brief so researchers evaluating disclosure can make an informed decision about what protections they actually have at the v1 phase.

### Post-incorporation formalization

When the foundation is incorporated (~18-24 months post-v1, per D0010 and Section 8.4), the project formalizes researcher protection through a published Safe Harbor commitment based on a standard template. Candidate templates to evaluate:

- **disclose.io.** Industry-standard Safe Harbor template; widely adopted across security-tools projects; reviewable language for researchers.
- **Bugcrowd "We Will Not Sue" template.** Similar legal protections; established in commercial bug-bounty practice.
- **EFF Coders' Rights Project model language.** Particularly aligned with the civil-society audience and partner organizations.

Template selection is named as Q16 in [open-questions.md](../open-questions.md), to be resolved during foundation incorporation. The Safe Harbor commitment is one of the items the foundation board adopts as part of its initial governance package.

## Alternatives considered

**Commit to formal Bugcrowd/disclose.io template now (pre-incorporation).** _(Considered, rejected.)_ The disclose.io template is designed for organizational entities (companies, foundations) committing organizational legal protection. A natural-person commitment to the template would amount to the developer pledging not to sue researchers — which the F12 finding identified as not actually binding on the developer, successors, or coercion-induced exceptions. The template's protection only works when there is an organizational entity holding the commitment. Committing now would be theatrically stronger than the v1 reality justifies.

**Both: stated intent now, formal template later.** _(Considered, partially adopted.)_ The "stated intent" framing for v1 is essentially the downgrade option; the "formal template later" is essentially the post-incorporation commitment. The decision adopts both timing components but as a single layered posture rather than as two independent commitments. The distinction matters because pretending the v1 commitment is partial coverage rather than acknowledging it is preference would maintain some of the rhetorical overreach F12 identified.

## Consequences

### Section 8.5 updates

The "Bug bounty: v2+ candidate" paragraph (which currently contains the legal-action commitment text) is updated:

- Retains: PGP-encrypted contact, 90-day disclosure timeline, public acknowledgment.
- Revised: "The project's stated intent is not to pursue legal action against research disclosed in good faith. Until foundation incorporation (Section 8.4), this is a published preference rather than a legal protection — the project is operated by a natural person (the developer) whose commitment is not enforceable against future personal action, successors, or coercion-induced exceptions. At foundation incorporation, the project will formalize researcher protection through a Safe Harbor commitment based on a standard template (candidate templates: disclose.io, Bugcrowd 'We Will Not Sue', EFF Coders' Rights Project). The current absence of formal Safe Harbor is acknowledged here so researchers can make an informed decision about disclosure to v1 pilot-phase Cairn."

### Section 9.4 updates

The "Vulnerability disclosure" mitigation paragraph in 9.4 is updated to cross-reference D0012 and acknowledge that the legal-protection mechanism strengthens at foundation incorporation rather than being fixed at v1.

### Open question

Q16 added to [open-questions.md](../open-questions.md): Safe Harbor template selection (disclose.io vs. Bugcrowd vs. EFF Coders' Rights, plus jurisdictional adaptation to the foundation's incorporation jurisdiction).

### Operational implications

The downgrade reduces the apparent strength of v1's researcher-protection posture. The mitigation is the explicit acknowledgment, which most researchers familiar with the disclosure landscape will find more credible than the original overstatement.

The post-incorporation formalization requires the foundation board to adopt the Safe Harbor commitment as part of initial governance — adds an item to the incorporation checklist but does not delay incorporation.

### Reversibility

The decision is fully reversible at foundation incorporation. If the project chooses a different formalization mechanism (foundation bylaws containing the protection rather than a separate Safe Harbor document, for example), the choice is foundation-level governance and does not require revisiting the v1 phase.

## References

- [docs/sections-8-9-review.md](../sections-8-9-review.md) — F12.
- [docs/decisions/D0010-foundation-jurisdiction.md](D0010-foundation-jurisdiction.md) — foundation incorporation timeline that this decision interlocks with.
- disclose.io Safe Harbor template: https://disclose.io
- Bugcrowd "We Will Not Sue" model: https://www.bugcrowd.com/resources/levelup/standard-disclosure-terms/
- EFF Coders' Rights Project: https://www.eff.org/issues/coders/legal-defense-toolkit
