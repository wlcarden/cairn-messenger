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

- **Pilot enrollment cannot begin until the partner-mediation arrangement is in place.** This is a Phase B precondition adjacent to the pre-pilot audit (per [D0011](D0011-audit-budget-and-timing.md)). The brief commits to engaging partner organizations on this arrangement as part of Q5 (NGO partner outreach). Pilot enrollment also cannot begin until the partner-mediated channel is **demonstrably operational** (per consolidated external-reads triage P5): the partner organization has been identified and named, channel operating procedures are in place, partner-side staff are trained, and the channel has been tested with at least one round-trip simulation. Naming a candidate partner is not equivalent to operational arrangement.
- **Consent and exit-protocol documentation is reviewable by partner organizations before pilot enrollment.** If a partner organization's protection-work guidance requires modifications to the protocol (additional disclosures, different reporting cadence, specific data-retention boundaries), the project commits to incorporating those modifications and acknowledges that the protocol is partner-co-developed rather than project-unilaterally-designed.
- **Pilot data quality depends on protocol effectiveness.** The project surfaces pilot-feedback bias as a known limitation of v1 pilot data per §9.1 and §9.3; the protocol is the mitigation, but the brief does not claim the mitigation is complete. Partner-mediated reporting reduces but does not eliminate the social-cost-of-honest-feedback dynamic.

### Additional protocol requirements per consolidated external-reads triage

The following requirements are added to D0013 per the consolidated external-reads triage findings (P6, P19, P26, E13, X11, X3):

**Weekend / off-hours crisis escalation path (P6).** D0013 specifies what the partner-mediated channel does between the time a pilot user reports tool-mediated harm and the time the developer can be reached, including for cases the partner cannot resolve without developer involvement. The partner-side escalation path includes: (a) the partner's normal-hours communication channel as primary; (b) a pre-arranged pager-equivalent escalation for after-hours cases the partner classifies as crisis (specific criteria: tool-mediated harm in progress; pilot user in active key-rotation flow needing developer help; CVE-class issue affecting pilot users); (c) the "honor exit without follow-up pressure" commitment is preserved with an explicit exception for "user is in active crisis and needs the project's incident-response capability" — the exception is invoked by the partner organization based on their assessment, documented in partner records, and does not violate the structural consent commitment because the user remains in control of whether to engage developer involvement at the next escalation step.

**Tool-mediated harm coordination protocol (P19).** When a pilot user reports a security incident attributed (partially or fully) to Cairn use, the protocol specifies: (a) **attribution control**: the partner organization controls public attribution language with project sign-off; the project does not unilaterally publish attribution that could damage the partner's ongoing casework with the affected user; (b) **timeline**: 24 hours for initial partner-project coordination call; 48 hours for joint response plan; 72 hours for incident classification (Cairn-attributable / partial-attribution / not-Cairn-attributable); 168 hours (1 week) for first public communication if any. The timeline is flexible based on incident severity but never compressed below 24 hours for initial response; (c) **partner-side veto**: the partner organization can veto public attribution if their assessment of partner-casework consequences for the affected user warrants delay or non-publication; (d) **coordination with partner's own protection-casework response**: the partner's protection-work response (Front Line Defenders' protection desk operational procedures; Access Now Helpline incident-response protocols) takes precedence over the project's response in matters affecting the user directly; the project supports the partner's response rather than driving its own response that would conflict.

**v1 supply-chain gap disclosure (X11, P26).** The pilot consent document must include an explicit disclosure that v1 ships under the developer-source-review baseline without the v1.5+ recruited reviewer pool's binary-equivalence multi-party verification (per Section 5.5 / D0015). The disclosure language: "Cairn v1 is shipped under the developer's source review attestation; a compromised build pipeline producing a malicious binary from clean source would not be detected by source review alone. The pilot user is informed of this gap; v1.5 closes the gap with reproducible builds + the recruited reviewer pool. By participating in the pilot, the user acknowledges this v1-specific supply-chain exposure and the partner-mediated channel through which they would be notified of any incident affecting the supply chain during the pilot." Partner organizations evaluating facilitation should treat this disclosure as a required element rather than negotiable.

**Partner-mediated support SLA (E13).** D0013 specifies the expected response cadence for the partner-mediated channel during the pilot: (a) acknowledgment of incoming reports within 1 business day of partner-organization business hours; (b) initial response (triage + next-step communication) within 3 business days; (c) escalation to developer involvement (where required) within 5 business days; (d) language: reports in the user's native language are accepted; the partner organization translates to English for developer involvement as needed. The SLA is operationally negotiated with the partner organization per their normal helpline cadence; the brief specifies the framework rather than imposing project-defined timing on the partner.

**CVE-disclosure protocol specifically for pilot users (X3 cross-reference).** When a CVE is found that affects pilot users, the protocol specifies what pilot users are told, in what language, with what urgency, and what they are asked to do. Specifically: (a) initial notification through the partner-mediated channel in the user's native language; (b) clear classification of severity (critical / high / medium / low) per the CVE-response runbook in `docs/runbooks/cve-response.md`; (c) specific action the user is asked to take (patch + verify; patch + recover; migrate-off; wait-for-further-instructions); (d) timeline expectations (when the patched release will be available; what the user does in the interim); (e) opt-in detailed technical explanation for users who request it. Pilot users are informed at consent that this CVE-disclosure protocol exists; they are not informed of specific CVEs preemptively.

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
