# D0010 — Foundation jurisdiction handling: placeholder pending legal consultation, with fiscal-sponsor stage and factual corrections

**Status:** Accepted
**Date:** 2026-05-28

## Context

The Sections 8/9 adversarial review surfaced pattern P6 and finding F7: the foundation-jurisdiction analysis in Section 8.4 is below the diligence floor a foundation lawyer expects. Three reviewers independently identified the gap. Specific issues:

- **Factual errors.** "Dutch Stichting (Signal Foundation precedent)" — Signal Foundation is Delaware-incorporated as a 501(c)(3), not a Dutch Stichting. "Swiss Verein... Briar Project AG model" — Briar's commercial entity was a German UG/GmbH operating alongside a UK CIC, not a Swiss Verein.
- **Structural omissions.** No fiscal-sponsor stage for the 18-24 month pre-incorporation grant-intake window. The brief jumps from "developer as natural person" to "non-profit foundation TBD" with no bridge structure for receiving the OTF, Ford, Mozilla, or similar grants the project anticipates.
- **Missing diligence considerations.** Tax-treaty implications for international donors, specific case law on encryption product distribution (EAR/Dual Use Regulation, Wassenaar), donor-identity disclosure regimes, banking access for privacy-tech non-profits, IP-ownership and assignment mechanics in the natural-person-to-foundation transition.

The depth gap is visible to any partner organization's legal advisor on first read. The choice is between fixing the analysis at the right depth (which requires legal expertise the project does not have) or honestly reframing the section to acknowledge its current depth and commit to closing the gap before incorporation.

## Decision

**Restructure Section 8.4 as a placeholder pending legal consultation, with three substantive additions:** (a) named fiscal-sponsor candidates for grant-intake under the deferral window (which may be permanent per D0016); (b) factual corrections to the Signal Foundation and Briar references; (c) explicit acknowledgment of the diligence considerations the current text omits, named as items to be addressed during legal consultation if the [D0016](D0016-foundation-incorporation-trigger.md) trigger activates.

**Update (per [D0016](D0016-foundation-incorporation-trigger.md)):** the "before incorporation" framing in this decision is superseded by the D0016 deferral. Foundation incorporation is deferred from v1 / Phase C scope with a v1.5 broader-release evaluation trigger; legal consultation per this decision is required _if_ the trigger activates. Under the D0016 deferral, the fiscal-sponsor arrangement is the permanent grant-receipt structure for the duration of the deferral, which may be permanent if the trigger does not activate. The jurisdictional analysis below remains the substrate the project would act on if incorporation proceeds; the "approximately 18-24 months post-v1" timeline references that appeared in earlier drafts of this decision are superseded by the trigger-based framing.

The brief commits to engaging specialized non-profit counsel before incorporation if D0016 trigger activates; the jurisdictional analysis this decision contains is preserved as the project's working understanding pending that consultation, not as a settled evaluation.

### Fiscal-sponsor stage (pre-incorporation)

The brief introduces a pre-incorporation grant-receipt structure named explicitly. Candidate fiscal sponsors to evaluate during the design-brief phase:

- **Software Freedom Conservancy.** Established 501(c)(3) hosting security and free-software projects; experienced with project-sponsorship agreements that preserve maintainer autonomy; existing relationships with OTF and similar funders.
- **Open Collective Foundation / Open Source Collective.** Lower-overhead fiscal sponsorship; more appropriate for smaller initial grants; supports cryptocurrency-adjacent and privacy-tech projects.
- **Code for Science & Society.** Mission-aligned for civil-society security tools; has experience with grants from OTF, Ford Foundation, Mozilla.
- **NumFOCUS.** Established sponsor for scientific and security computing projects; geographic concentration in the U.S. is a constraint.
- **NLnet Foundation** (Netherlands-based). Operates funded calls (NGI Zero) that can serve as both grantmaker and de facto fiscal sponsor for European-jurisdiction-friendly arrangements.

Fiscal-sponsor selection is named as Q15 in [open-questions.md](../open-questions.md). The brief does not commit to a specific sponsor pre-consultation but commits to engaging the fiscal-sponsor question as a precondition of any first grant intake.

### Factual corrections

- Signal Foundation is incorporated as a Delaware 501(c)(3) (not a Dutch Stichting). The "Dutch Stichting" candidate is described without precedent attribution.
- Briar's commercial entity was a German UG (later GmbH) operating alongside the UK-based Briar Project CIC (not a Swiss Verein or Aktiengesellschaft). The "Swiss Verein" candidate is described on its own merits without precedent attribution to Briar.

The factual corrections are applied to 8.4 directly.

### Diligence considerations named as items for legal consultation

Section 8.4 lists the following as items to be evaluated during pre-incorporation legal consultation; the brief does not analyze them at depth pre-consultation:

- Tax-treaty implications for international donor base across candidate jurisdictions.
- Specific case law on encryption product distribution from the candidate jurisdiction (US EAR/ITAR, EU Dual Use Regulation, Wassenaar Arrangement adherence).
- Donor-identity disclosure regimes (US Form 990, Swiss strong-protection norms, Dutch and UK intermediate regimes); particularly relevant for donors whose identity disclosure is itself a security risk.
- Asset seizure and litigation venue standards per jurisdiction.
- Banking access for privacy-tech non-profits in the candidate jurisdiction (historical de-risking by US banks; mixed track record in Swiss jurisdiction).
- IP-ownership and assignment mechanics for the natural-person-to-foundation transition; specifically how project IP transitions to foundation custody, how contributor commits from the natural-person period are handled, and how signing identities transfer.

## Alternatives considered

**Commit now to specific fiscal sponsor and legal counsel.** _(Considered, rejected.)_ Higher specificity makes the brief more concrete for funder conversations, but requires relationships the project does not have. Specifically: fiscal-sponsor agreements are negotiations that take weeks-to-months; committing to a specific candidate pre-conversation could close off better options that emerge during outreach. Legal counsel selection similarly depends on conversations and budget the project has not yet established. The placeholder approach acknowledges the dependency without falsely concretizing it.

**Keep current scope; fix factual errors; add missing considerations only.** _(Considered, rejected.)_ Addresses the surface findings but not the structural one. The current text reads as project-side analysis at brand-recognition depth; correcting facts and adding more items doesn't change the depth. The placeholder restructuring is what acknowledges that the analysis is not at the right depth for incorporation decision and that the project will engage counsel to close the gap.

## Consequences

### Section 8.4 updates

The "Candidate jurisdictions" subsection is restructured:

- Opens with explicit acknowledgment that the analysis is the project's working understanding pending legal consultation.
- Lists the four candidate jurisdictions with corrected precedent references (Signal Foundation as Delaware 501(c)(3); Briar as German UG/UK CIC).
- Adds a "Pre-incorporation grant-receipt structure" subsection naming fiscal-sponsor candidates.
- Adds a "Diligence considerations for legal consultation" list naming the items to address.
- Reframes the "Selection criteria when incorporation approaches" subsection as the criteria legal consultation will use, not as criteria the project has already evaluated.

### Open questions

Q15 added to [open-questions.md](../open-questions.md): fiscal-sponsor selection for pre-incorporation grant intake.

### Operational implications

The project commits to engaging non-profit legal counsel before any first grant intake routed through a fiscal sponsor. Initial consultation is estimated 5-15 hours of counsel time (at $300-600/hour for non-profit specialist) — $1,500-9,000. This is the first significant external cost in the project's pre-funded operations and is budgeted in Section 10 when drafted.

The project's intent is to engage counsel in the candidate jurisdiction shortlisted for incorporation rather than counsel general to non-profit law — jurisdictional specialization matters more for this decision than non-profit-law generalism.

### Reversibility

The placeholder structure is reversible at any time the project has consulted counsel; the brief can replace the placeholder with the consultation outcome and revise factual content as needed. The fiscal-sponsor selection is reversible until first grant arrives; once a grant is routed through a specific sponsor, switching sponsors is operationally heavy (subgrant restructuring, board notification, sponsor exit fees).

## References

- [docs/sections-8-9-review.md](../archive/sections-8-9-review.md) — F7, pattern P6; multi-reviewer convergence on the depth gap.
- Software Freedom Conservancy: https://sfconservancy.org
- Open Collective Foundation: https://opencollective.com
- Code for Science & Society: https://codeforscience.org
- NumFOCUS: https://numfocus.org
- NLnet Foundation: https://nlnet.nl
- Signal Foundation factual reference: Delaware 501(c)(3) per public filings.
- Briar Project structural reference: UK Community Interest Company; German UG was the related commercial entity.
