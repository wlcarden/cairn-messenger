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

**Status:** Partially resolved. Language stack decided ([D0003](decisions/D0003-implementation-language.md) — Rust core + Kotlin UI). v1 scope cuts decided ([D0004](decisions/D0004-v1-scope-cuts.md)) — local CRDT permanently dropped; Sigsum integration shape now constrained by Rust-core decision. Remaining technical choices still deferred to system design spec.

**Resolved.**

- ~~Android codebase architecture~~ → Rust core + Kotlin UI per [D0003](decisions/D0003-implementation-language.md). UniFFI for bindings.
- ~~CRDT library for trust graph operations~~ → Not needed; v1 queries Sigsum directly, v1.5 adds caching, full CRDT not planned per [D0004](decisions/D0004-v1-scope-cuts.md).

**Still deferred to system design spec.**

- COSE library (Rust: [`coset`](https://crates.io/crates/coset) is the leading candidate; specific structure choice — `COSE_Sign1` vs `COSE_Sign` — to be locked down with the eight-field schema specification).
- Sigsum client implementation (Rust-native build using existing Merkle and signature primitives; reference architecture from `sigsum-go`).
- Push notification mechanism (UnifiedPush is the leading candidate; specific distributor selection and on/off default posture for v1 deferred — see Section 5 review finding F25).
- Tor on Android approach (`arti` Rust-native vs. embedded C `tor` vs. Orbot coupling).
- Persistent storage architecture and migration framework (see Section 5 review finding F24).

**What it blocks.** Full system design spec; specific engineering work in each affected subsystem.

**Next step.** Each remaining item is resolved when the system design spec for the relevant subsystem is drafted. Significant choices become decision documents in `decisions/`.

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
