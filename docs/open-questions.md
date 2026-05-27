# Open Questions

Tracker for decisions deferred or unresolved. Each entry: the question, why it's open, what it blocks, and candidate resolutions. Resolved questions move to `decisions/` with full rationale.

---

## Q1. Is the duress profile in v1 scope?

**Status:** Open. Flagged for deferred resolution.

**Context.** Section 3.5 of the design brief (in-scope mitigations) claimed "Duress profile support for compelled-unlock scenarios" as a v1 feature, and Section 5.6 (UX Principles) repeats the claim. The architectural decisions captured in handoff.md (Key Architectural Decisions Made) do not include duress profile as a designed feature. The adversarial review on Section 3 flagged this inconsistency.

**What it blocks.**

- Section 5 (Architecture Detail) drafting: 5.6 currently restates the duress claim. If duress is in v1, the section must specify the mechanism (separate keystore? alternate passphrase opens an alternate identity? what's visible to the adversary?). If duress is out, the claim must be removed.
- Pilot user expectations: telling pilots they have duress protection when the architecture doesn't deliver it is worse than not offering it.
- Threat model honesty: 3.5 currently lists duress as covered.

**Architectural questions that resolving this raises.**

- Does the duress unlock present a fake/empty trust graph view, or a separately provisioned innocuous-looking identity?
- Does it require a separate cryptographic identity (with its own Shamir-split master)?
- How is the duress passphrase stored such that the primary unlock cannot reveal it (and vice versa)?
- What's the leak surface? Filesystem metadata, app-level storage size, network traffic patterns, hardware element occupancy — each can reveal that a duress profile exists.
- How does this interact with the multi-profile system already planned?

**Candidate resolutions.**

- **In-scope, fully designed.** Adds meaningful work to v1; needs explicit architecture spec; pilot users get the feature.
- **In-scope, minimal version.** A second passphrase opens a separately-provisioned profile with no trust graph view; full duress design deferred to v1.x. Risk: minimal duress is worse than none if it leaks.
- **Out of scope, v1.x or v2 candidate.** Removes the claim from 3.5 and 5.6; documented as planned but not delivered in v1. Honest with pilot users.
- **Out of scope, indefinitely.** Acknowledges that duress profiles are extremely hard to implement without observable leak surfaces, and that under real coercion the better answer is identity rotation post-event.

**Next step.** Decide before Section 5 drafting begins. Likely converges with broader discussion of what compelled-unlock realistically looks like in the target threat environments.

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

**Context.** Candidate partners: Tactical Tech, Front Line Defenders, Access Now, Citizen Lab, Open Technology Fund. Possible roles: technical review, pilot facilitation, threat intel, localization, end-user training. Outreach not begun.

**What it blocks.**

- Section 8.6 (Partnership Approach) beyond placeholder list.
- Whether the external reviewer pool for releases (Sigstore signing model needs 2-3 reviewers) draws from these partners or is recruited separately.
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

**Status:** Open. Deferred to architecture specification phase.

Captured here to remain visible:

- Android codebase architecture (Kotlin native is current preference; alternatives: Kotlin Multiplatform, Rust core + Kotlin UI).
- CRDT library for trust graph operations.
- COSE library (for capability tokens).
- Sigsum integration approach (direct integration vs. via a higher-level library).
- Push notification mechanism (GrapheneOS has no Google Play Services by default; UnifiedPush is the leading candidate, but server choice matters for metadata leakage).

**What it blocks.** Section 5 (Architecture Detail) beyond conceptual level; the full system design spec.

**Next step.** Resolve during Section 5 drafting on a per-subsystem basis. Each choice becomes a decision document in `decisions/`.

---

## Q9. Voice/video call support in v1

**Status:** Open. SimpleX supports it but adds complexity.

**Context.** Defer to v1.x or v2 depending on time. SimpleX has the capability; integrating it into the v1 app adds UI surface, codec considerations, NAT-traversal complexity.

**What it blocks.** v1 scope finalization in Section 6. v1.x roadmap commitments in Section 7.

**Next step.** Make explicit go/no-go decision when Section 6 is being finalized. Default toward deferral unless pilot users push strongly for it.

---

## Conventions

- New questions append to the bottom with the next sequential ID.
- Resolved questions move to `decisions/` (one file per decision) with full rationale, alternatives considered, and references. A short note links from here.
- Questions that turn out to be malformed or duplicated get marked **withdrawn** with a note, not deleted, to preserve provenance.
