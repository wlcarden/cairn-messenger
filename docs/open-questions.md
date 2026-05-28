# Open Questions

Tracker for decisions deferred or unresolved. Each entry: the question, why it's open, what it blocks, and candidate resolutions. Resolved questions move to `decisions/` with full rationale.

---

## Q1. Is the duress profile in v1 scope?

**Status:** Resolved 2026-05-27. No duress-profile concealment in v1 or any planned version; duress-wipe pattern deferred to v1.5; tier-separated identity model documented as the architectural answer to compelled unlock. See [decisions/D0002-duress-profile.md](decisions/D0002-duress-profile.md).

**Resolution summary.** Section 3.5 of the design brief now includes a "Bounded exposure under compelled unlock" paragraph articulating the architectural answer (master Shamir-split off-device; operational identity exposed but revocable; post-coercion recovery via the social-recovery process). Section 5.6 replaces the duress-profile bullet with a compelled-unlock guidance bullet. Sections 6.2 and 7.1 include the v1.5 duress-wipe commitment. Indefinite out-of-scope language explains why concealment-style duress profiles cannot be made undetectable against the threat tier this product addresses, and why detected concealment carries its own legal risks in some jurisdictions.

---

## Q2. Project working name

**Status:** Resolved 2026-05-27. Working name: **Cairn**. See [decisions/D0001-project-name.md](decisions/D0001-project-name.md).

**Outstanding follow-ups** (separate from the working-name decision):

- Domain availability check (.org, .com).
- Package-namespace check (npm, PyPI, Maven, F-Droid).
- GitHub organization name availability.
- USPTO and EUIPO trademark search before any public launch.

These checks gate the transition from working name to committed name, not from placeholder to working name.

---

## Q3. Funding strategy: primary vs. blended sources

**Status:** Open. Targets identified; sequencing not decided.

**Context.** Open Technology Fund is the primary candidate ($50-150K range, has funded Signal and Tor). Secondary candidates: Ford, Open Society, Mozilla, Knight, Omidyar; European democracy funds (SIDA, GIZ, EIDHR, Dutch Foreign Ministry); self-funded through pilot.

**What it blocks.**

- Section 10 (Funding) of the design brief beyond placeholder numbers.
- Timing of approach to partner NGOs (some partners are easier to engage when funding is locked).
- Pilot start date (depends on hardware budget availability).

**Next step.** Map application windows and grant cycles for OTF and 2-3 backup foundations. Decide whether to pursue serially or in parallel. Decide whether to self-fund through brief completion before any application.

---

## Q4. Pilot user community identification

**Status:** Open. Developer has groups in mind; not documented or committed.

**Context.** v1 pilot plan calls for 10-15 users in 1-2 local groups already known to the developer. Specific groups not named in the briefing materials; pilot start timing unclear; evaluation criteria for the pilot not yet defined.

**What it blocks.**

- Pilot hardware purchase (need user count to budget Pixel hardware: $5-12K range).
- Pilot timing in the project roadmap.
- Per-jurisdiction profile feed content (v1 ships 2-3 profiles based on pilot context — which jurisdictions?).
- Localization priority (if pilot users are predominantly one language other than English, v1.x localization picks itself).

**Next step.** Begin informal validation conversations with candidate communities during documentation phase (handoff.md:329 recommends parallel outreach). Document candidates here once identified; pilot scope ceases to be hypothetical at that point.

---

## Q5. NGO partner outreach: roles and sequencing

**Status:** Open. Targets identified; roles partners would play not defined.

**Context.** Candidate partners: Tactical Tech, Front Line Defenders, Access Now, Citizen Lab, Open Technology Fund. Possible roles for v1: witness pool (release log + trust-graph audit), pilot facilitation, threat intel, localization, end-user training, partner-mediated pilot consent and exit channel per [D0013](decisions/D0013-pilot-consent-exit.md). Reviewer-pool recruitment proceeds in parallel for v1.5 architectural-target activation per [D0015](decisions/D0015-v1-release-security-posture.md) — but is not on the v1 critical path. Outreach not begun.

**What it blocks.**

- Section 8.6 (Partnership Approach) beyond placeholder list.
- Whether the witness pool for the v1 release log + trust-graph audit draws from these partners or is recruited separately. Witness recruitment is on the v1 critical path.
- Reviewer-pool recruitment for v1.5 architectural target activation (not blocking v1 ship per D0015; the recruited pool soft-ships against v1 releases if willing reviewers join during v1 outreach, but v1 release is not gated on pool formation).
- Pilot consent and partner-mediated reporting channel per D0013 — this is on the v1 critical path; partner organization must be willing to operate the mediation channel.
- Localization partnerships specifically — translation work likely runs through one of these.

**Next step.** Decide on a primary partner candidate for each role before outreach. Defer outreach until design brief is shareable.

---

## Q6. Localization priority post-v1

**Status:** Open. English-only v1; expansion sequence not decided.

**Context.** v1 launches English-only. Post-pilot expansion candidates depend on pilot user demographics, partner NGO geographic coverage, and target deployment regions.

**What it blocks.**

- v1.x roadmap commitments.
- Recruitment of native-speaker security trainers as translators.

**Next step.** Becomes answerable once Q4 (pilot communities) resolves.

---

## Q7. External cryptographic audit firm

**Status:** Open. Need known but firm not selected.

**Context.** Audit before broad release (post-pilot). Budget estimate $20-50K. Firm not identified.

**What it blocks.**

- Section 10 budget breakdown precision.
- Audit timing in the roadmap.
- Implementation choices that affect auditability (some firms prefer specific languages, dependency tree shapes, etc., though this is a weak constraint).

**Next step.** Candidate firms list: Trail of Bits, NCC Group, Cure53, Quarkslab, Open Tech Audit Working Group. Defer engagement until v1 is feature-complete enough to be auditable (~12 months out).

---

## Q8. Specific technical library / approach choices

**Status:** Partially resolved. Architectural shape decided across D0003 (language stack), D0004 (scope cuts), D0006 (cryptographic envelope). Remaining items are library-selection within the decided architecture, deferred to system design spec.

**Resolved at the architectural level.**

- ~~Android codebase architecture~~ → Rust core + Kotlin UI per [D0003](decisions/D0003-implementation-language.md). UniFFI for bindings.
- ~~CRDT library for trust graph operations~~ → Not needed; v1 queries Sigsum directly, v1.5 adds caching, full CRDT not planned per [D0004](decisions/D0004-v1-scope-cuts.md).
- ~~COSE structure choice~~ → `COSE_Sign1` with deterministic CBOR encoding per [D0006](decisions/D0006-cryptographic-envelope.md); Rust reference uses [`coset`](https://crates.io/crates/coset).
- ~~Push notification on/off default posture~~ → Default off in v1 per Section 5.4 (polling at user-configurable intervals); UnifiedPush as the architectural commitment for users who opt in.

**Still deferred to system design spec (library-level choices, not architectural).**

- Specific Sigsum client implementation in Rust (reference architecture from `sigsum-go`; primitives from RustCrypto ecosystem).
- Tor on Android approach (`arti` Rust-native preferred per [D0003](decisions/D0003-implementation-language.md), with embedded C `tor` and Orbot coupling as fallback options).
- Persistent storage library (Room vs. SQLDelight vs. direct SQLite via Rust; see Section 5.7 for architecture-level commitments).
- UnifiedPush distributor recommendation for users who opt in (NTFY self-hosted, NTFY.sh public instance, or alternative).
- Specific Shamir Secret Sharing implementation (`vsss-rs` is a candidate; SLIP-39 adaptation is the alternative if a standard share format is preferred).

**What it blocks.** Full system design spec; specific engineering work in each affected subsystem.

**Next step.** Each remaining item is resolved when the system design spec for the relevant subsystem is drafted. Significant choices become decision documents in `decisions/`.

---

## Q9. Voice/video call support in v1

**Status:** Open. SimpleX supports it but adds complexity.

**Context.** Defer to v1.x or v2 depending on time. SimpleX has the capability; integrating it into the v1 app adds UI surface, codec considerations, NAT-traversal complexity.

**What it blocks.** v1 scope finalization in Section 6. v1.x roadmap commitments in Section 7.

**Next step.** Make explicit go/no-go decision when Section 6 is being finalized. Default toward deferral unless pilot users push strongly for it.

---

## Q10. Witness pool and reviewer pool composition

**Status:** Partially resolved (architectural target for reviewer pool deferred to v1.5 per [D0015](decisions/D0015-v1-release-security-posture.md); witness pool remains a v1 commitment). Specific organizations and individuals not yet identified for either pool.

**Context.** Two distinct pools with different version commitments:

- **Sigsum witnesses (v1 commitment).** Section 5.2 trust-graph audit + Section 5.5 release audit, with the shared-witness-pool concentration acknowledged in 3.4. Witnesses cosign log state so log tampering is detectable. Candidate pool draws from NGO and academic partners (Citizen Lab, Tactical Tech, Front Line Defenders, Access Now, EFF, plus academic security-research groups). Recruitment is a v1 commitment via Q5 outreach.
- **External reviewer pool (v1.5 commitment per D0015).** 5+ reviewers, 3-of-5 attestation threshold, geographic/institutional diversity required. At v1.5 they verify binary equivalence against reproducible builds. Recruitment work proceeds at v1 through Q5 outreach; willing reviewers identified during v1 may soft-ship attestations against v1 releases, but v1 release shipping is not gated on pool formation. The recruited pool's role as a trust root activates at v1.5.

**What it blocks.**

- Section 3.4's trust-root commitments for the witness pool cannot be fully concrete until specific organizations are named.
- For the v1 stack, witness-pool recruitment gates v1 release log cosignatures; v1 ship is conditional on at least basic witness participation.
- Section 5.5/8.2 reviewer-pool commitments cannot move from v1.5 architectural target to v1.5 operational reality without identified reviewers; recruitment work occupies Q5 outreach at v1.

**Next step.** Witness-pool recruitment begins immediately after Q5 (NGO partner outreach) opens partnership conversations — this is on the v1 critical path. Reviewer-pool recruitment can proceed in parallel; given the v1.5 architectural-target framing, the reviewer-pool ask of partners is decoupled from any v1 ship-date pressure. Recruit witnesses and reviewers from non-overlapping subsets of partner organizations where possible to reduce the correlation acknowledged in 3.4. Reviewer-pool honoraria operations (Q3-conditional) become relevant for v1.5+ broader-release cadence; v1.5 ships with whatever volunteer-attestation pool has formed if honoraria funding does not close.

---

## Q11. OIDC provider for Sigstore identity binding

**Status:** Open. Architectural commitment made (use an OIDC provider for Sigstore release attestation); specific provider choice for v1 pilot deferred with provisional preference for a U.S.-based provider in pilot per Section 5.5.

**Context.** Sigstore's Fulcio binds each release signing certificate to a verified OIDC identity. The OIDC provider becomes a trust root (named explicitly in Section 3.4). The provider's jurisdiction matters: a U.S.-based provider is reachable by U.S. legal process; a provider in another jurisdiction shifts the trust placement accordingly.

**What it blocks.**

- Section 3.4 trust-root entry for the OIDC provider remains generic.
- Operational defenses (hardware-security-key requirement on the OIDC provider, alerts on token issuance, Rekor audit cadence) cannot be fully operationalized until a specific provider is chosen.
- Partner organizations and pilot users in jurisdictions where the chosen provider's home jurisdiction is itself an adversary need to be informed of the trust placement; the user-facing documentation depends on knowing which provider.

**Next step.** Choose a v1 pilot OIDC provider (U.S.-based: Google, GitHub, Microsoft are candidates; non-U.S.: limited options in 2026, mostly self-hosted Keycloak-style deployments). Acknowledge the jurisdiction in partner conversations. v1.5 may transition if pilot experience or partner feedback indicates the v1 jurisdiction choice is operationally inappropriate.

---

## Q12. Pilot-feedback-tunable parameters

**Status:** Open by design. Several v1 parameters are set conservatively for pilot release with the explicit understanding that pilot evidence will revisit them.

**Context.** Parameters chosen with stated rationale but not validated against real-world pilot use:

- **Recovery cooling-off window** (48 hours per [D0005](decisions/D0005-peer-verification.md)). May prove too long if recovery delays significantly degrade user trust, or too short against determined adversaries.
- **Stale-flag escalation period** (90 days per [D0006](decisions/D0006-cryptographic-envelope.md)). May prove too long if cascade quarantines linger past their useful signal, or too short if users need more time to triage.
- **Push notification default** (off per Section 5.4). May prove too restrictive if polling latency makes the app operationally unusable for the pilot audience.
- **Polling interval** (default 15 minutes per Section 5.4). Same tunability concern.
- **Shamir threshold** (3-of-5 default per Section 5.3). User-configurable at provisioning; the default may need adjustment based on pilot peer-network properties.
- **Token validity period** (hours to days per Section 5.1). Specific value not pinned; the tradeoff is passphrase-reprompt frequency vs. post-revocation compromise window.

**What it blocks.** Nothing in v1 launch; these are tunable post-pilot via release updates.

**Next step.** Capture pilot feedback systematically against each parameter; revisit in v1.5 with explicit decisions for any that pilot evidence justifies changing. Section 6.3 (pilot deployment plan) should specify how this feedback is collected.

---

## Q13. Volunteer-baseline operational ceiling and slippage tolerance

**Status:** Open by design (informed by pilot feedback).

**Context.** [D0008](decisions/D0008-volunteer-baseline-cadence.md) accepts release slippage as the expected behavior of the volunteer baseline (expected median 4-6 months between releases vs. target quarterly post-honoraria). The actual ceiling — how long a release can wait while remaining acceptable to pilot users and reviewers — is empirically determined and not specified in the brief.

**What it blocks.** Operational policy on when slippage becomes "the project is too slow" and triggers either a cadence redesign, scope cut, or partner-organization escalation for reviewer recruitment. Pilot user expectations on operational rhythm.

**Next step.** Track release intervals during the v1 pilot. If median sustainably exceeds 6 months for non-security-critical releases or 4 weeks for security-critical releases, revisit either the cadence assumption (D0008) or the reviewer-pool size assumption (Section 8.6 / Q10).

---

## Q14. Partner advisory authority for sudden-developer-unavailability contingency

**Status:** Open. Mechanism committed via [D0009](decisions/D0009-sudden-unavailability.md); specific partner identity deferred.

**Context.** A named partner organization holds pre-arranged authority to publish a project status advisory if the developer's dead-man's-switch check-in misses by 60 days. Selection criteria: organizational stability over years; institutional independence from the developer; operational capacity for short-notice public advisory; jurisdictional placement that does not concentrate advisory authority in the developer's own legal-process exposure.

**What it blocks.** Section 3.4's named trust placement for the partner advisory authority cannot be concrete until selection happens. The pre-staged advisory script cannot be partner-rehearsed.

**Next step.** Q5 outreach. Candidate organizations to evaluate: Software Freedom Conservancy, Open Tech Fund (as notification recipient and channel rather than as advisory holder per Section 9.4 successor list correction), Front Line Defenders, Tactical Tech. The role is meaningful and requires explicit partner agreement; the conversation belongs in initial partnership outreach rather than as a downstream task.

---

## Q15. Fiscal sponsor for pre-incorporation grant intake

**Status:** Open. Mechanism committed via [D0010](decisions/D0010-foundation-jurisdiction.md); specific sponsor deferred.

**Context.** The 18-24 month interval between brief completion and foundation incorporation requires a fiscal sponsor for grant intake (OTF and similar funders cannot grant directly to a natural person under most program structures). Candidate fiscal sponsors:

- Software Freedom Conservancy (established 501(c)(3); maintainer-autonomy preserving)
- Open Collective Foundation / Open Source Collective (lower overhead; smaller initial grants)
- Code for Science & Society (mission-aligned for civil-society security tools)
- NumFOCUS (security and scientific computing focus)
- NLnet Foundation (Netherlands-based; serves as both grantmaker and de facto sponsor for European arrangements)

**What it blocks.** Grant intake from any funder during the pre-incorporation window. The fiscal-sponsor question is a precondition for OTF or backup-foundation grant applications.

**Next step.** Initial conversations with 2-3 candidate fiscal sponsors during Q5 outreach phase. Selection criteria: alignment with project mission, overhead structure, prior experience with the funders the project intends to apply to, jurisdictional considerations matching the eventual foundation jurisdiction (per D0010 placeholder).

---

## Q16. Safe Harbor template selection (post-incorporation)

**Status:** Open. Mechanism committed via [D0012](decisions/D0012-researcher-safe-harbor.md); template selection deferred to foundation incorporation.

**Context.** At foundation incorporation (~18-24 months post-v1), the project formalizes researcher protection through a Safe Harbor commitment based on a standard template. Candidate templates:

- **disclose.io** — industry-standard Safe Harbor template; widely adopted across security-tools projects; reviewable language for researchers.
- **Bugcrowd "We Will Not Sue" template** — established in commercial bug-bounty practice.
- **EFF Coders' Rights Project model language** — aligned with civil-society audience.

**What it blocks.** Formal researcher legal protection. v1 pilot phase operates on stated intent (per D0012); formalization lands at incorporation.

**Next step.** Template selection during foundation governance setup. Coordination with foundation legal counsel (per Q15 fiscal-sponsor and D0010 jurisdiction work). Template adaptation to the chosen foundation jurisdiction's legal framework.

---

## Q17. Population-size estimate for the four-precondition v1 intersection

**Status:** Open. Surfaced by the §2 adversarial review (F1, multiple lenses converged).

**Context.** Section 2.2 currently estimates the four-precondition v1 audience intersection — threat-tier population, GrapheneOS-Pixel-capable, viable peer-recovery network, in-person facilitator reachable — at "low hundreds globally." The number is the project's working estimate based on aggregating practitioner-organization casework knowledge across the named partner-candidate organizations (Front Line Defenders, Tactical Tech, Access Now Helpline, EFF Threat Lab); it has not been validated against any rigorous population analysis.

**What it blocks.**

- §2 audience honesty: if the estimate is materially smaller (low tens globally), v1 is a personal-project pilot rather than a population-scale pilot, and the grant framing should match.
- §10 funder pursuit: programme officers benchmark per-user cost-of-pilot against estimated addressable population; an unstated or low estimate weakens the grant case.
- D0014 non-peer recovery prioritization: if the v1 four-precondition intersection is "low hundreds" globally and the populations D0014 names as excluded (sex workers under criminalization, abuse survivors, etc.) are materially larger, non-peer recovery's v1.x/v2 priority increases.

**Next step.** Through Q5 partner-organization outreach, request rough population-size estimates from each candidate partner for their casework. Aggregate the estimates with appropriate uncertainty bounds. Document the refined estimate in §2.2; revise grant framing accordingly. Defer specific population modeling until partner conversations have happened.

---

## Q18. Differentiation evidence basis — field interviews vs reframe

**Status:** Open. Surfaced by the §2 adversarial review (F2, the central grant case finding).

**Context.** Section 2.3 asserts that the integration is what existing projects (most acutely Briar and SimpleX) do not deliver for this audience. The §2 review's funder lens identified that this assertion is not currently evidenced — no field interviews, no documented operational failures of Briar or SimpleX in target deployments, no partner-organization complaints recorded. A committee that already funds Briar reads §2.3 against §10 and concludes the realistic counterfactual is a Briar UX grant, not a Cairn grant.

**What it blocks.**

- The central grant case. Without evidence, §2.3's differentiation argument collapses against the realistic funder counterfactual.
- The §4.3 differentiation framing inherits §2.3's posture; weakening §2.3 weakens §4.3.
- The project's decision whether to pursue Cairn as a separate project or reframe as a contribution to an existing ecosystem (Briar UX track; SimpleX integration shell).

**Next step.** Two paths:

- (a) Commission field-interview evidence: ~4–8 weeks of conversations with practitioner staff at the partner organizations (Front Line Defenders, Tactical Tech, Access Now Helpline, EFF Threat Lab) plus selected pilot-candidate users about specific deployments of Briar/SimpleX where the integration gap caused operational failures. Document findings before grant submission. Cost is developer time at the volunteer baseline plus possibly a small partner honorarium budget.
- (b) Reframe Cairn as a contribution to an existing ecosystem (Briar UX track or SimpleX integration shell) with the engineering work re-scoped accordingly.

The choice between (a) and (b) is itself the open question. The project's working preference is (a) — but committing to (a) requires conversations the project has not yet held. Resolution likely emerges from early Q5 partner conversations.

---

## Q19. Localization and audience-expansion scope by version

**Status:** Open. Extends Q6 (which is about prioritization) into version-by-version scope. Surfaced by the §2 review (F22).

**Context.** v1 ships in English. Section 2.2 names non-English-language populations as in-scope for the threat tier and architectural-commitments scope but out of scope for v1 pilot. Localization is the audience-expansion lever, but localization at the threat tier has irreducible cost: security-critical UI text requires native-speaker security-trainer translators (not generic translation services) because mistranslation of compelled-unlock warnings, recovery-flow guidance, or attestation-chain language has security consequences.

**What it blocks.**

- v1.5 / v1.6 scope commitment to specific language additions.
- §10.4 Phase D localization honoraria budgeting against specific languages.
- Partner-organization conversations for translator recruitment.

**Next step.** Through Q4 pilot-user identification and Q5 partner outreach, identify the languages whose populations are most underserved by existing tools at this threat tier. Document version-by-version localization commitments in §7.1 once 2–3 priority languages have been identified. Defer specific translator-recruitment work until language priorities resolve.

---

## Q20. Self-funding runway disclosure (resolution of §9.1's commitment)

**Status:** Open. §9.1 explicitly commits §10 to deliver a runway figure; §10 currently does not. Surfaced by the §10 review (F4) as breach of an in-document commitment.

**Context.** Section 9.1 states "Section 10 (when drafted) will state the developer's effective self-funding runway in calendar terms — the number of months the developer can sustain v1 development plus pilot operations under self-funded posture with no audit, no honoraria, and no team scaling." The current §10 draft does not deliver the figure; §10.8 acknowledges the gap honestly rather than letting it remain silent.

**What it blocks.**

- The financial floor of all v1 funding-related risk discussions (per §9.1's framing).
- Phase A duration risk analysis for funders evaluating §10.1.
- Phase B funding-window timing — whether the runway permits waiting through a 6-month subsidy-grant cycle or whether earlier funding is essential.

**Next step.** The developer either commits to a public runway figure (option a in §10.8 disclaimer) or maintains the honest-gap acknowledgment indefinitely (option b). The choice has personal-finance-disclosure implications the developer is best positioned to evaluate. Possible intermediate path: provide the runway figure under grant-agreement confidentiality to funders evaluating Phase B applications rather than in the public brief. Resolution depends on developer comfort and funder conventions.

---

## Q21. Subsidy-program eligibility and viability across application horizon

**Status:** Open. Surfaced by the §10 review (F5, F14) as compound dependency.

**Context.** Section 10.5 names OTF Secure Audit, Mozilla OSAA, NLnet NGI Zero Trust, Cure53 mission rates, and Trail of Bits civic-tech rates as primary routes for audit funding. The §10 review identified that (a) OTF Secure Audit has an entity-eligibility prerequisite (fiscal-sponsored or incorporated) that interacts with the §10.6 fiscal-sponsor sequencing; (b) Mozilla OSAA has been on irregular cycles since 2021; (c) Cure53 mission rates are vendor discretion, not a grant program; (d) NLnet NGI Zero Trust does not fund standalone audits, only audit allocations within development grants; (e) the program landscape itself shifts on multi-year horizons (OTF funding was contested 2024–2025; Mozilla restructured open-source funding multiple times).

**What it blocks.**

- §10.2 Phase B floor figure depends on subsidy programs being available at the cited rate tiers when Cairn applies.
- §10.6 sequencing strategy (parallel applications) assumes the named routes are functionally substitutable; the F5 finding establishes they are not.
- Pursuit prioritization: which instrument the project applies to first depends on which has an open call and which fits the fiscal-sponsor sequencing.

**Next step.** Quarterly re-check of program-line status: which named programs have open application cycles, which are accepting Cairn-fit projects, which have published rate-band updates. Track in this question rather than re-baselining §10.2 every cycle. Resolution is ongoing rather than one-time.

---

## Q22. Pilot consent and exit protocol framework selection

**Status:** Open. Mechanism committed via [D0013](decisions/D0013-pilot-consent-exit.md); framework selection deferred to partner-organization conversations.

**Context.** D0013 commits the project to adopting a pilot consent and exit protocol modeled on IRB-equivalent protective-technology study practice. Candidate frameworks to adapt:

- **Citizen Lab research-ethics framework** — academic-research origin; established treatment of subjects in adversarial-research contexts.
- **Internews protection-tech evaluation framework** — civil-society-tooling-specific protocol structure.
- **Front Line Defenders protection-work guidance** — partner-organization-developed; closest to Cairn's specific facilitator-and-recruiter dynamic.
- **Project-developed framework reviewed by partner organizations** — synthesizes elements of the above with project-specific accommodations.

**What it blocks.** Pilot enrollment cannot begin until the consent protocol is documented, partner-organization-reviewed, and the partner-mediated reporting channel is operational. Pilot deployment timing depends on this resolving.

**Next step.** During Q5 partner-organization outreach, request review of the candidate frameworks from candidate partner organizations (Front Line Defenders specifically; Tactical Tech, Access Now Digital Security Helpline secondarily). Selection emerges from partner feedback. Acknowledge the protocol as partner-co-developed rather than project-unilateral.

---

## Q23. Non-peer recovery path selection for v1.x/v2

**Status:** Open. Mechanism committed via [D0014](decisions/D0014-non-peer-recovery.md); path selection deferred.

**Context.** D0014 acknowledges v1 recovery as architecturally inappropriate for populations whose threat condition is the absence or compromise of a peer network. The v1.x or v2 candidate paths to evaluate (full description in D0014):

- Printed paper shares held by self (closest to v1 architecture; likely first candidate).
- Time-locked self-recovery (server-mediated or co-operating partner organization).
- Single-trustee with attorney-client privilege.
- Explicit no-recovery option with documented user consent.

Selection requires engagement with partner organizations who facilitate the excluded populations.

**What it blocks.** D0014's v1.x/v2 commitment to ship a non-peer recovery path. Audience expansion to the excluded populations.

**Next step.** During Q5 partner-organization outreach with organizations serving the excluded populations (sex-worker rights organizations; domestic-violence support organizations; immigrant-rights organizations; queer-rights organizations in criminalizing jurisdictions; religious-minority rights organizations; prisoner-family support organizations), request input on which candidate paths fit the operational reality of their populations. Resolution likely combines multiple paths (paper shares + explicit no-recovery; paper shares + time-locked) rather than a single selection.

---

## Q24. (Reserved — duplicates Q11 OIDC provider jurisdiction)

**Status:** The OIDC provider jurisdiction question is tracked in Q11; the §4 adversarial review's "Q-§4.1" suggestion is the same question. No separate tracking is created.

---

## Q25. v3 mesh radio hardware partnership timing (§6.2 vs §10.5 inconsistency)

**Status:** Open. Surfaced by the §§6/7 review (F6, F18) as cross-section inconsistency.

**Context.** Section 6.2 lists hardware partnerships as v4+; Section 10.5 lists them as v3+ aspiration; Section 7.1 commits a v3 mesh-radio release that needs the hardware path resolved. The boundary between v3 and v4+ for hardware-partnership work is unsettled.

**What it blocks.**

- §7.1 v3 ship-conditions cannot fully specify "hardware partnership in place" if the brief does not commit to whether hardware partnerships are in v3 or v4+.
- Partner-organization outreach for mesh-radio communities (Meshtastic, MeshCore communities) — the partnership shape depends on whether Cairn is asking for community-protocol-stability partnership (v3) or hardware-distribution partnership (v3 or v4+).
- §10.5 funding-source roster for hardware partnerships — v3 vs v4+ timing affects when this category becomes active.

**Next step.** Decision document to resolve, likely at the time §7.1 v3 work approaches (Phase D timing per §10.4). Defer until v1.5/v1.6 ship and v2 begins to firm up; the mesh-radio question is genuinely v3-timing-or-later, and earlier resolution may be premature.

---

## Q26. GrapheneOS-only requirement vs CalyxOS inclusion in v1.x

**Status:** Open. Surfaced by the §2 adversarial review (§2.3 update; CalyxOS as Tails/SecureDrop adjacent comparator).

**Context.** Section 2.2 and Section 5 commit v1 to GrapheneOS-on-Pixel hardware as the security baseline. CalyxOS is an alternative Android-hardening distribution that some users in some jurisdictions adopt instead of GrapheneOS, particularly where GrapheneOS adoption is operationally riskier (more identifiable security choice; smaller user base; specific national-software-availability conditions). Adding CalyxOS as an acceptable v1.x baseline would expand the addressable audience meaningfully.

**What it blocks.**

- §2.2 audience scope for v1.x.
- §5 architectural-commitments evaluation: does the tier-separated identity model assume specific GrapheneOS hardening properties CalyxOS does not provide?
- §3.4 trust roots: GrapheneOS-and-CalyxOS as trust roots would need separate enumeration.

**Next step.** Defer to v1.x scope evaluation after v1 pilot. Pilot feedback may indicate whether CalyxOS inclusion is operationally valuable for the populations the v1 pilot reaches. If pilot users include candidates in jurisdictions where GrapheneOS is operationally constrained, the question becomes active; otherwise it remains deferred.

---

## Conventions

- New questions append to the bottom with the next sequential ID.
- Resolved questions move to `decisions/` (one file per decision) with full rationale, alternatives considered, and references. A short note links from here.
- Questions that turn out to be malformed or duplicated get marked **withdrawn** with a note, not deleted, to preserve provenance.
