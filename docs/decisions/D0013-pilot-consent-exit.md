# D0013 — Pilot consent and exit protocol

**Status:** Accepted
**Date:** 2026-05-28

## Context

The Section 2 adversarial review surfaced finding §2 F19 (the practitioner lens): §6.3 commits the pilot to recruitment from "groups the developer has direct relationships with so the facilitator role can be sustained at pilot scale," with the developer serving simultaneously as recruiter, facilitator, and member of the social network the pilot draws from. The brief contains no protocol for how the pilot handles:

- Informed consent obtained from candidates whose social relationship to the developer makes refusal socially costly.
- A pilot user who wants to refuse a feature, leave the pilot, or report that the tool made their situation worse, through a channel that does not require communicating that report to the developer who is also their social contact.
- The asymmetric power dynamic when the recruiter is also the facilitator and the holder of the social relationship.

This dynamic is standard concern in academic IRB-reviewed protective-technology studies; Front Line Defenders' own protection-work guidance specifically flags the pattern. Partner organizations the brief names as potential pilot facilitators in §8.6 — Tactical Tech, Front Line Defenders, Access Now Digital Security Helpline — may require an informed-consent and exit-protocol document as a precondition of partner facilitation.

The reviewer-attestation pilot data the brief intends to surface depends on pilot reports being honest. Reports filtered through social cost (a pilot user reluctant to disappoint the developer, or reluctant to break the social relationship, or unable to report through any channel that doesn't reach the developer) are biased toward favorable feedback by the exact mechanism the practitioner community most distrusts.

## Decision

**Adopt a pilot consent and exit protocol, modeled on IRB-equivalent protective-technology study practice, before pilot deployment commences.** The protocol is published as a standalone document referenced from §2.2 and §6.3, and serves as the consent baseline for every pilot user.

### Required protocol elements

The protocol must address, at minimum:

1. **Pre-pilot informed consent.** Written consent obtained at pilot enrollment covering: what the pilot involves (provisioning ceremony, recovery-peer designation, feedback channels, pilot duration); what data the project collects about the pilot (per the architecturally-specified privacy boundaries — no message content, no contact lists, no usage telemetry beyond what the user explicitly opts into per §5.7's crash-reporting model); what is asked of the user during the pilot (facilitator meetings, recovery-flow walkthroughs, partner debriefs); the user's right to refuse any element without affecting their participation in other elements; the user's right to exit at any time.

2. **Recruitment disclosure of the developer-as-facilitator role.** The pilot user is told explicitly that the developer is simultaneously (a) the researcher whose work the pilot supports, (b) the facilitator they will interact with during onboarding, (c) the holder of the social relationship through which they were recruited. The implication for the user is made explicit: refusal of pilot participation, or any pilot element, does not affect the social relationship. This sentence appears in the consent document, not as a separable disclaimer.

3. **Partner-mediated reporting channel.** Pilot users have access to a feedback channel that does not require reaching the developer. The brief commits to negotiating partner-organization mediation as a pilot precondition: a partner organization (candidate organizations per §8.6: Front Line Defenders, Tactical Tech, Access Now Digital Security Helpline) operates a contact point pilot users can use for any of: reporting negative outcomes; refusing a pilot element; requesting exit; reporting tool-mediated harm. The partner-mediation arrangement is in place before pilot enrollment begins, not after.

4. **Mid-pilot exit protocol.** A pilot user who wants to stop using Cairn during the pilot has a documented path: revoke their pilot enrollment via the partner channel, with the project committing to honor exit without follow-up pressure from the developer. The user retains the device (under BYOD posture per [D0010 cascade] and §10.1) and the data on it; account/identity wind-down follows standard Cairn key-rotation and revocation procedures per §5.1.

5. **Tool-mediated harm reporting.** Pilot users who experience a security incident, social consequence, or operational compromise they attribute (partially or fully) to Cairn use can report through the partner channel. The project commits to surfacing all such reports through aggregated reporting consistent with partner-organization expectations and §9.4's transparency obligations, without identifying the reporting user without explicit consent.

6. **Pilot exit debrief.** At pilot completion (six months per §6.3, or earlier exit), users are offered a debrief through the partner channel, not through the developer directly. Debrief content informs the pre-broader-release decision per §6.3 and §10.3 Phase C. Refusal of debrief does not affect any other element of the user's continuing relationship with Cairn or with the developer.

### Operational implications

- **Pilot enrollment cannot begin until the partner-mediation arrangement is in place.** This is a Phase B precondition adjacent to the pre-pilot audit (per [D0011](D0011-audit-budget-and-timing.md)). The brief commits to engaging partner organizations on this arrangement as part of Q5 (NGO partner outreach).
- **Consent and exit-protocol documentation is reviewable by partner organizations before pilot enrollment.** If a partner organization's protection-work guidance requires modifications to the protocol (additional disclosures, different reporting cadence, specific data-retention boundaries), the project commits to incorporating those modifications and acknowledges that the protocol is partner-co-developed rather than project-unilaterally-designed.
- **Pilot data quality depends on protocol effectiveness.** The project surfaces pilot-feedback bias as a known limitation of v1 pilot data per §9.1 and §9.3; the protocol is the mitigation, but the brief does not claim the mitigation is complete. Partner-mediated reporting reduces but does not eliminate the social-cost-of-honest-feedback dynamic.

## Alternatives considered

**Developer-only feedback channel with informed consent disclaimer.** _(Considered, rejected.)_ A consent disclaimer naming the developer-recruiter-facilitator triple role addresses the disclosure half of the issue but not the operational half (the channel through which a user reports problems is still the developer). Standard protective-technology study practice rejects this configuration because the disclosure does not reduce the social cost of honest reporting; the cost is structural, not informational.

**Defer pilot consent protocol to v1.5.** _(Considered, rejected.)_ Deferral makes v1 pilot enrollment unprotected on the dimension §2.2's audience description (organizations who facilitate pilots) is most likely to require. Several partner organizations will not facilitate without a protocol document; deferring the protocol defers the partnerships that depend on it.

**Adopt an existing IRB protocol verbatim.** _(Considered, partially adopted.)_ Several civil-society security organizations have IRB-equivalent protocols for protective-technology studies (Citizen Lab's research-ethics framework; Internews's protection-tech evaluation framework). The project's intent is to adapt one of these frameworks rather than writing from scratch; selection is named as Q22 in [open-questions.md](../open-questions.md). The decision here commits to the adoption; specific framework selection emerges from Q5 partner conversations.

## Consequences

### Section 2.2 updates

The §2.2 audience description is revised to acknowledge:

- The developer-as-recruiter role and its implications for pilot feedback quality.
- The partner-mediation requirement for the pilot to proceed.
- Cross-reference to this decision and to §6.3 pilot scope.

### Section 6.3 updates

The §6.3 pilot deployment paragraphs are expanded to include:

- The consent and exit protocol as a Phase B precondition.
- The partner-mediation arrangement as a precondition.
- Mid-pilot exit and tool-mediated harm reporting paths.
- Pilot debrief through the partner channel.

### Section 8.6 updates

The §8.6 partnership-roles enumeration adds "pilot consent and partner-mediated reporting" as a distinct role category, candidate organizations same as the pilot-facilitation category but with a specific protocol-development scope rather than facilitation throughput.

### Section 9.1 updates

The §9.1 risk register adds:

- Pilot-feedback bias as a v1 risk with the consent and exit protocol as the named mitigation.
- Partner-organization-decline-to-mediate as a pilot-deferral failure mode.

### Open question

Q22 added to [open-questions.md](../open-questions.md): Pilot consent protocol framework selection (Citizen Lab research-ethics framework; Internews protection-tech framework; Front Line Defenders protection-work guidance adaptation; project-developed framework reviewed by partner organizations).

### Reversibility

The decision is reversible at low cost before pilot deployment; partner-organization conversations may surface protocol modifications the project incorporates. After pilot enrollment begins, modifications are heavier — pilot users who consented under one protocol cannot be retroactively moved to another without re-consent. Protocol stability through pilot duration is the operational commitment.

## References

- [docs/section-2-review.md](../section-2-review.md) — §2 F19; pattern P3 ("architectural commitment" language compressing user-borne cost).
- [docs/sections-8-9-review.md](../sections-8-9-review.md) — F17 partner-availability-without-consultation cluster.
- [docs/decisions/D0009-sudden-unavailability.md](D0009-sudden-unavailability.md) — partner advisory authority infrastructure that the partner-mediation channel parallels.
- [docs/decisions/D0011-audit-budget-and-timing.md](D0011-audit-budget-and-timing.md) — pre-pilot audit as parallel Phase B precondition.
- Citizen Lab research-ethics framework: https://citizenlab.ca
- Internews protection-tech evaluation guidance: https://internews.org
- Front Line Defenders protection-work guidance: https://www.frontlinedefenders.org
