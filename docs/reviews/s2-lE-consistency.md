# §2 — Internal Consistency Lens

## Summary

§2 mostly survives a consistency check against §§5, 6, 8, and 9, but it carries several inherited overcommitments that the later sections have already walked back without updating §2's framing. The strongest pattern: §2 still speaks in language calibrated to the pre-D0008/D0011/D0010 draft — "an integration of cryptographic primitives" and "the v1 architecture can ship soundly in 9-12 months" — while the later sections have absorbed slippage acceptance, audit gating, foundation-as-placeholder, and a v1.5/v1.6 split that re-shape what v1 actually ships and when.

The audience framing in §2.2 also carries an unresolved tension with §5.6/§6.3/§8.6: §2.2 lists five overlapping community categories as "where the v1 audience comes from," but v1 deployment is 10-15 users in 1-2 local groups already known to the developer, onboarded in person, on BYOD GrapheneOS-Pixel — a population that §2.2's framing implies is broader than the pilot can actually reach. None of the findings below are fatal, but they cluster around §2 making promises the rest of the brief has quietly reduced.

## Critical findings

### F1: §2.2's "9-12 months to ship soundly" claim conflicts with the v1.5/v1.6 split and D0008 cadence

- **Evidence:**
  - §2.2 line 64: "the v1 architecture can ship soundly in 9-12 months."
  - §2.2 line 66: "v1.5 adds Briar as the highest-sensitivity tier, the in-app post-coercion recovery flow, multi-profile UX, reproducible builds, and the duress-wipe pattern."
  - §7.1 line 668-670: v1.5 has been split into v1.5 (architecture completeness, target ~6-9 months post-v1) and v1.6 (deferred UX, ~12-15 months post-v1) per the §8/§9 review and D0008's volunteer-baseline cadence.
  - §7.1 line 670: "The split assumes the volunteer-baseline release cadence per D0008."
  - D0008 line 34-36: "If volunteer-baseline cadence is 4-6 months between releases, v1.5 is operationally one to two release cycles after v1 alpha — implying v1.5 ships at 10-18 months post-v1 launch rather than the 6 months the brief currently states."
- **Impact:** §2.2 collapses what is now a v1.5 + v1.6 sequence into a single "v1.5" envelope that includes everything §7.1 has explicitly split apart. A reader landing on §2 reads a roadmap promise the rest of the brief has revised. Credibility cost is concrete: any partner or funder cross-referencing §2 against §7 sees the same gap the §8/§9 review flagged as F9.
- **Recommendation:** Revise §2.2 line 66 to enumerate v1.5 and v1.6 separately, mirroring §7.1's split. Either name v1.6 as the second architecture-completeness release, or restate the bullet as "v1.5 + v1.6 complete the v1 architecture in two releases — v1.5 architecture-completeness (~6-9 months post-v1), v1.6 deferred-UX (~12-15 months post-v1)." Also revise the "9-12 months" framing if the volunteer baseline now means v1 itself slips against that target — but at minimum the v1.5 bullet must match §7.1.

### F2: §2.1 frames Cairn as "an integration of cryptographic primitives that already exist" — §9.3 documents substantial original cryptographic engineering

- **Evidence:**
  - §2.1 line 46: "It is an attempt to make available, to users at this specific threat tier, an integration of cryptographic primitives that already exist — SimpleX's identifier-less protocol, Briar's peer-to-peer-over-Tor design (v1.5 per D0004), social recovery via Shamir, transparency-log-anchored trust graph — with the operational discipline that makes the integration usable for non-expert users."
  - §2.3 line 100: "Cairn's contribution is the layer above the protocols rather than a new protocol. The protocols themselves are correctly delegated to projects (SimpleX, Briar, Tor, Sigstore, Sigsum) whose mission is to build and maintain them."
  - §9.3 line 962: "v1 ships substantial original cryptographic engineering (capability tokens, trust-graph operation envelope, share format per D0006, recovery-flow memory hygiene per D0003) performed without rolling external cryptographic consultation under the self-funded-MVP posture (Section 8.1)."
  - §9.3 line 960: "Pilot users... receive a Cairn implementation whose cryptographic core has been externally reviewed only at the limited pre-pilot audit scope... The integration boundary — trust-graph state handling, recovery-flow orchestration, release-security stack as integrated — carries audit-not-yet-complete risk."
  - §8.1 line 724: "The Section 5 adversarial review surfaced the gap that v1 ships substantial original cryptographic engineering..."
- **Impact:** §2 sells a project that integrates existing primitives; §9.3 and §8.1 admit Cairn ships substantial original cryptographic engineering. A program officer or technical reviewer reading §2 first builds the wrong threat model about what's audited and what's novel. The integration framing is partly true (the protocols themselves are reused), but the trust-graph envelope, capability-token construction, share format, and recovery-flow memory hygiene are not "primitives that already exist" — they are project-original constructions. §2 papers over a real engineering and audit risk the brief acknowledges elsewhere.
- **Recommendation:** Revise §2.1 line 46 and §2.3 lines 91-100 to acknowledge that Cairn ships original cryptographic engineering at the integration layer — capability tokens, trust-graph operation envelope, share format, recovery-flow primitives — even though the underlying protocols (SimpleX, Briar, Tor, Sigstore, Sigsum) are delegated. The honest framing is "integration plus the operational discipline plus an original construction at the integration boundary" rather than "integration of existing primitives." This is the same gap §8.1 already names; §2 should mirror that framing.

### F3: §2.2's audience expansion through v2 includes iOS — §9.3's "Pixel hardware" trust root and §6.2's iOS deferral imply a security baseline §2 doesn't qualify

- **Evidence:**
  - §2.2 line 67: "v2 adds the USB-bootable form factor and iOS support (per Section 6.2). USB opens the borrowed-laptop scenario for users without dedicated trusted hardware; iOS opens the platform to users who cannot or will not move to GrapheneOS-Pixel. The audience expansion is meaningful but bounded by the security baseline iOS allows the product to maintain."
  - §6.2 line 601: "iOS support, opening the platform to users who cannot or will not move to GrapheneOS-Pixel."
  - §9.3 line 910: "A device with a compromised secure element... collapses the operational-identity tier's protection (Section 5.1). The hardware element holds the operational key, and if its policy enforcement can be bypassed the key is extractable."
  - §5.1 (implied by §2.2's reference): hardware-backed key storage, verified boot, tier-separated identity model "depend on the platform" (§2.2 line 52).
- **Impact:** §2.2 says "the audience expansion is meaningful but bounded by the security baseline iOS allows the product to maintain" — a qualified gesture, but §9.3 and §5.1 make clear the platform requirement is load-bearing for the entire identity model. iOS-on-Cairn is a substantially weaker security posture than GrapheneOS-Pixel, and §2 does not say which architectural commitments survive the iOS migration. A reader could fairly conclude that v2 Cairn-on-iOS provides comparable protection to v1, which §6.2 line 601 and §9.3's hardware-root framing do not support. The "audience expansion" framing minimizes a tier change.
- **Recommendation:** Either (a) revise §2.2 line 67 to name what specifically iOS support sacrifices relative to GrapheneOS-Pixel — hardware-backed key storage in a comparable form, verified boot guarantees, the threat-tier baseline — and treat v2 iOS as a different security tier rather than a same-tier expansion; or (b) defer the iOS expansion claim out of §2.2 entirely and treat iOS as out-of-scope-for-the-original-audience in v2, addressed in a separate section. The current framing implies parity §6.2/§9.3 do not support.

## Significant findings

### F4: §2.2's "v1 audience" is described in five overlapping community categories, but §6.3's pilot composition is "1-2 local groups already known to the developer"

- **Evidence:**
  - §2.2 lines 56-60: enumerates journalists in contested-press environments, NGO field staff and humanitarian workers, organizers in active dissent, dual-use technology workers and defense subcontractors, civil-society researchers as the "overlapping communities" the v1 audience comes from.
  - §2.2 line 62: "The pilot deployment specifically draws from groups the developer has direct relationships with so the facilitator role can be sustained at pilot scale."
  - §6.3 line 628: "The pilot targets 10–15 users in one or two local groups already known to the developer."
  - §6.3 line 628: "identification and final commitment depends on conversations the developer holds with candidate communities during the design-brief phase (tracked as Q4 in open-questions.md)."
- **Impact:** §2.2's audience framing is a population description ("the v1 audience"). §6.3 narrows that to 10-15 users in 1-2 groups the developer already knows, with the specific groups not yet committed. The gap between §2's "v1 audience" and §6.3's actual pilot is large enough that a careful reader might infer §2 is describing the post-v1.5 or v2 audience rather than v1. §2.2 line 64 partially acknowledges this ("the audience for whom the v1 architecture can ship soundly"), but the five-community enumeration at lines 56-60 reads as the v1 audience composition rather than the broader-target population. The framing risks overstating the pilot's reach against the populations §2 names.
- **Recommendation:** Clarify in §2.2 that the five-community enumeration describes the long-term addressable population, with v1 pilot reaching a subset constrained by the developer's existing relationships. The current phrasing "the v1 audience comes from" implies the pilot will draw across all five categories; §6.3 says one or two local groups.

### F5: §2.2 says the v1 audience can be "supplied with GrapheneOS-Pixel hardware" — §6.3's BYOD pilot model and §10.1's hardware budget contradict this

- **Evidence:**
  - §2.2 line 62: "The v1 architecture targets the intersection of these communities where users (a) have access to or can be supplied with GrapheneOS-Pixel hardware..."
  - §6.3 line 630 (original): "The project provides devices for pilot users: GrapheneOS-installed Pixel hardware with the Cairn application pre-installed and the identity not yet provisioned..."
  - §10.1 line 1042: "Two to four GrapheneOS-capable Pixel devices retained by the project for developer testing and a small loaner pool for partner-facilitated pilot training (~$1,500-3,000 one-time). The bulk of pilot deployment is BYOD: pilot users source their own GrapheneOS-capable Pixel devices through the standard channels documented in Section 5 and the user-onboarding documentation."
- **Impact:** §2.2 implies devices can be supplied; §10.1 explicitly says the bulk of the pilot is BYOD with only a 2-4 device loaner pool. §6.3 still reads "the project provides devices" — there is a separate inconsistency between §6.3 and §10.1 that this lens does not own — but for §2 specifically, the "supplied with" phrasing overstates the project's hardware-provisioning capacity. Users who cannot acquire a Pixel themselves are not part of the v1 audience under the §10.1 BYOD posture, but §2.2 implies they are. Funders reading §2 against §10.1 see the same gap.
- **Recommendation:** Revise §2.2 line 62 (a) to "have access to GrapheneOS-Pixel hardware" without the "or can be supplied with" clause, given §10.1's BYOD posture. Alternatively, narrow the v1 audience definition to BYOD-capable users in §2.2, matching §10.1. The "supplied with" framing was likely correct under a pre-D0008/§10 funding posture; it does not match the volunteer baseline.

### F6: §2.2 implies pilot facilitator support from partner organizations that §6.3 reserves for the developer alone

- **Evidence:**
  - §2.2 line 52: "Users running GrapheneOS on a Pixel device, onboarded in person by a trained facilitator (the developer in the v1 pilot)..."
  - §2.2 line 62: "(c) can be onboarded in person by a facilitator. The pilot deployment specifically draws from groups the developer has direct relationships with so the facilitator role can be sustained at pilot scale."
  - §6.3 line 632: "Conducted in person by the developer for each pilot user."
  - §8.6 line 833: "v1 pilot facilitator is the developer; broader deployment depends on partner organizations operating as facilitator networks."
  - §9.3 line 921: "A compromised or coerced facilitator gains visibility into multiple users' identity material... the operational mitigation is the pilot's small-scope developer-only facilitator model, with broader-deployment ceremony design yet to be specified."
- **Impact:** §2.2's reference to "a trained facilitator (the developer in the v1 pilot)" is consistent with §6.3 and §8.6 — the parenthetical does the work. But §2.2's broader audience-expansion framing ("audience expansion through the roadmap" lines 64-69) does not name when partner facilitator networks come online, even though §8.6 makes clear broader deployment depends on partner facilitators and §6.3 makes clear the v1 ceiling is one-developer facilitator. A reader inferring the v1.5 expansion includes any growth in addressable audience misses that broader-than-pilot deployment is the gating bottleneck §8.6 identifies. This is closer to an omission than a contradiction, but §2.2 frames audience expansion as a function of architectural additions (Briar, USB, iOS, mesh) rather than partner-facilitator availability, which §8.6 says is the dominant constraint.
- **Recommendation:** Add to §2.2's audience-expansion framing (lines 64-71) that broader-than-pilot audience reach depends on partner-organization facilitator networks per §8.6, not just on architectural additions. The current framing implies architecture is the gating variable; §6.3 and §8.6 say facilitator capacity is.

### F7: §2.2's "GrapheneOS dependency in v1, in-person provisioning, peer-based recovery, the operational discipline the design assumes a support network provides" implies a support network §6.3 does not specify

- **Evidence:**
  - §2.2 line 71: "...the architectural cost of meeting that threat tier — GrapheneOS dependency in v1, in-person provisioning, peer-based recovery, the operational discipline the design assumes a support network provides — is justifiable for that population and disproportionate for users at lower threat tiers."
  - §6.3 line 626-638: pilot scale 10-15 users, in-app support channel, partner debriefs at 3- and 6-month marks (per §9.4 line 972: "intent is approximately 3-month and 6-month cadence subject to partner availability... not published as a unilateral commitment").
  - §8.6 lines 833-836: pilot facilitation, threat intelligence, user training and onboarding are role categories the project "seeks partners for" — not committed partner relationships.
  - §9.4 line 972: "The project will seek partner-organization debriefs at intervals appropriate to partner capacity and pilot evolution; the project's intent is approximately 3-month and 6-month cadence subject to partner availability..."
- **Impact:** §2.2 claims "the operational discipline the design assumes a support network provides" — implying the support network exists at v1 to provide that discipline. §6.3/§8.6/§9.4 make clear partner-organization relationships are aspirational, not committed: facilitator networks are v2+, partner debriefs are subject to partner availability, training infrastructure is sought rather than secured. The v1 "support network" is the developer plus whatever pilot users self-organize among themselves — not the partner ecosystem §2.2 implies.
- **Recommendation:** Revise §2.2 line 71 to acknowledge that the "support network" at v1 is the pilot user group and the developer-as-facilitator, with broader partner-supported operational discipline as a v1.5+ aspiration contingent on partnership outreach (per §8.6 and Q5). The current framing implies the support network exists; §8.6 says the project is seeking it.

### F8: §2.3 lists "social-recovery flow that works without centralized trustees, with peer-verification mechanisms that defeat impersonation attacks" as a gap Cairn fills — §9.3's "recovery network surface" and §5.3 honestly limit this

- **Evidence:**
  - §2.3 line 95: "A social-recovery flow that works without centralized trustees, with peer-verification mechanisms that defeat impersonation attacks (D0005)."
  - §9.3 line 931: "Recovery network surface. An adversary who identifies and compromises three of five recovery peers, plus obtains the peer challenges, can reach the master. The peer-verification mechanism (D0005) is the principal defense; the surface is acknowledged as the architectural cost of refusing centralized trustees."
  - §9.2 line 881: "Social recovery depends on the user's peer network having specific properties. The Shamir-3-of-5 model assumes the user has at least five people they trust to act as recovery peers — geographically distributed, socially distant from each other, capable of refusing coercion under pressure. Users without such a network can still use the product but cannot use the recovery mechanism in its intended form."
  - §9.3 line 937: "Coercion during the rotation flow. A sophisticated adversary can compel the user to initiate rotation, exposing the master during reconstruction."
- **Impact:** §2.3 line 95 says peer verification "defeats" impersonation attacks. §9.3 line 931 says peer verification is "the principal defense" — not a defeat. "Defeats" implies the attack class is closed; "principal defense" acknowledges residual surface. §9.2 line 881 further qualifies that the mechanism requires peer-network properties many target users may lack. §2.3's language is stronger than the rest of the brief supports — it promises a closure §9 explicitly names as residual.
- **Recommendation:** Revise §2.3 line 95 to "with peer-verification mechanisms that raise the cost of impersonation attacks (D0005)" or similar calibrated language. "Defeats" conflicts with §9.3's residual-surface acknowledgment. The §4.2 "honest about limits" principle and §5.6 "calibrated language" principle apply to §2 as much as to the UI.

## Minor findings

### F9: §2.2 says the master "is not present on the device" — §9.3 acknowledges a reconstruction-window surface where it is

- **Evidence:**
  - §2.2 (implied via §5.1 reference): the three-tier identity model in which the master is Shamir-split among recovery peers.
  - §2.3 line 93: "A coherent identity model across protocols, with tier separation that bounds compromise (Section 5.1)."
  - §5.6 line 522: "the master identity is Shamir-split among recovery peers and is not present on the device, so even full coerced unlock does not yield the master..."
  - §9.3 line 936: "Reconstruction window during recovery and provisioning. The master seed exists in active memory during these moments; an implant resident on the device can capture it."
- **Impact:** This is more a §5.6/§9.3 tension than a §2 tension, but §2's "tier separation that bounds compromise" framing benefits from the same calibration. The bound is real but conditional on the reconstruction window. §2.3 line 93 does not need to enumerate this — the §5.1 cross-reference handles it — but the framing should not imply the bound is absolute either.
- **Recommendation:** No change required at §2 level if §5.1 carries the calibration; flag for §2-author awareness when reviewing the §2 ↔ §5 cross-reference. If §2.3 line 93 is revised for other reasons, "bounds compromise across the device's normal operation" (matching §4.1 line 252) is the precise framing.

### F10: §2.2 audience text mentions "civil-society researchers studying targeted surveillance" — §2.1 also mentions them as "what's at stake" exemplars but they may be poorly served by the in-person-pilot model

- **Evidence:**
  - §2.1 line 36: "civil-society researchers studying targeted surveillance" listed in the threat-tier audience.
  - §2.2 line 60: "Civil-society researchers. Studying targeted surveillance, documenting incident chains, analyzing forensic-extraction artifacts. Frequently themselves targets of the systems they study (Citizen Lab and Amnesty Security Lab staff have been targeted by spyware in documented cases)."
  - §6.3 line 628: pilot is "1-2 local groups already known to the developer." Civil-society research staff are typically distributed across multiple institutions (Citizen Lab in Toronto, Amnesty Security Lab in Berlin, etc.) and unlikely to fit the "1-2 local groups" model.
  - §8.6 line 831: "Citizen Lab and similar academic research centers operate under university research governance; participation in third-party project release attestation is not their standard collaboration model, and the brief identifies Citizen Lab primarily as a potential research collaborator under the threat-intelligence category below rather than as a routine reviewer."
- **Impact:** §2.2's enumeration of civil-society researchers as a v1 audience source is consistent with §2.1 but does not match §6.3's local-pilot model or §8.6's framing of these organizations as research collaborators (threat intel) rather than user populations. The brief is internally inconsistent on whether civil-society research labs are users, reviewers, or partners. §2 places them in the user category; §8.6 places them primarily in the threat-intel collaborator category.
- **Recommendation:** Clarify in §2.2 line 60 whether civil-society researchers are addressed as users in v1 or in later versions. The local-pilot constraint and §8.6's framing suggest they are more naturally a research-collaboration relationship than a v1 user population. If they are intended as v1 users, §6.3's pilot model needs to accommodate distributed-across-institutions users; the current 1-2-local-groups framing does not.

## Patterns

Two patterns recur across these findings. The first is **stale §2 framing carrying forward language from an earlier brief draft that the later sections have revised**. F1 (9-12 months and v1.5 envelope), F2 (integration framing vs. original cryptographic engineering), F5 (project-supplied hardware vs. BYOD), and F7 (support-network availability) all read as §2 language predating the §8/§9 adversarial review, the D0008/D0010/D0011 decisions, and the §10 funding posture revision. §2 is the door the reader walks through; it should reflect the brief the reader is about to read, not the brief the project was a draft cycle ago.

The second pattern is **§2's calibration drift toward closure language that §9 explicitly names as residual**. F3 (iOS "audience expansion" minimizing tier change), F6 (operational discipline framing minimizing facilitator-capacity bottleneck), and F8 ("defeats impersonation attacks" vs. "principal defense") all reduce qualifications that §9 explicitly preserves. §4.2's "honest about limits" principle applies to §2 as much as to §5 and §9. The calibrated-language commitment in §5.6 is a UX commitment; §2 should hold the same calibration with funders and reviewers as the UI holds with users.
