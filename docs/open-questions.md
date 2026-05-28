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

**Status:** Open. Pools enumerated as trust roots in Section 3.4; specific organizations and individuals not yet identified.

**Context.** Two distinct pools recruited from a partially overlapping set of partner organizations:

- **Sigsum witnesses** (Section 5.2 trust-graph audit + Section 5.5 release audit, with the shared-witness-pool concentration acknowledged in 3.4): cosign log state so log tampering is detectable. The candidate pool draws from NGO and academic partners (Citizen Lab, Tactical Tech, Front Line Defenders, Access Now, EFF, plus academic security-research groups).
- **External reviewer pool** (Section 5.5): 5+ reviewers, 3-of-5 attestation threshold, geographic/institutional diversity required. In v1 they read source for each release; in v1.5 they verify binary equivalence.

**What it blocks.**

- Section 3.4's trust-root commitments cannot be fully concrete until specific organizations are named.
- Section 5.5's "recruitment criteria, threshold for shipping, rotation, and compensation" cannot move from policy to practice without identified people.
- v1 release cadence (releases wait for 3-of-5 attestation) depends on the pool being recruited and operationally available.

**Next step.** Begins after Q3 (funding) provides enough certainty to offer reviewer honoraria, and after Q5 (NGO partner outreach) opens the partnership conversation. Recruit witnesses and reviewers from non-overlapping subsets of partner organizations where possible to reduce the correlation acknowledged in 3.4.

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

## Conventions

- New questions append to the bottom with the next sequential ID.
- Resolved questions move to `decisions/` (one file per decision) with full rationale, alternatives considered, and references. A short note links from here.
- Questions that turn out to be malformed or duplicated get marked **withdrawn** with a note, not deleted, to preserve provenance.
