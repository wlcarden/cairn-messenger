# §§6/7 — Scope Discipline Lens

## Summary

§6 reads as a scope-discipline narrative — Briar deferred, CRDT dropped, UX narrowed, single-platform — but cross-checked against §5 it under-names the v1 surface area in load-bearing ways. Multiple §5 architectural elements that v1 cannot ship without are absent from the §6.1 enumeration (COSE_Sign1 envelope work, Sigsum commitment-only logging, rollback-resistance, Tor pluggable-transport tracking, push polling default, anti-equivocation prior-hash chains, key-rotation flow, three persistent stores with property-based migration tests). Worse, several §6.1 commitments are presented as v1 deliverables while §8.2/§8.5/§8.6 simultaneously frame their underlying machinery (reviewer recruitment, honoraria budgets, OIDC operational defenses, witness pool) as "intent subject to" partner outreach (Q5) and funding (Q3) that have not closed.

The pattern is not scope creep against §5 — it is the opposite. §6.1 is a tidy press-release summary; §5 specifies a substantially larger v1 product. Either §6 needs to enumerate the surface honestly (and re-evaluate the 9–12 month timeline against it), or §5 elements presented as v1 commitments need to be moved to v1.5 with the architectural-slot framing already used for Briar.

## Critical findings

### F1: §6.1 silently omits the entire COSE_Sign1 / CBOR cryptographic envelope as a v1 deliverable

- **Evidence:** §5.1 specifies capability tokens as `COSE_Sign1` structures with deterministic CBOR encoding (RFC 9052, RFC 8949 §4.2.1) using the `coset` crate (line 317). §5.2 specifies every trust-graph operation as the same `COSE_Sign1` envelope with a nine-field schema (lines 354–364), with the prior-hash chain, the issuer-cert-hash binding, and the per-(issuer, subject) equivocation detection all described as v1. §6.1's "Identity, trust, and recovery" paragraph (line 573) says "COSE-formatted capability tokens" once but never names the envelope as a v1 cryptographic engineering deliverable for the trust-graph operations side, never names deterministic CBOR as a v1 requirement, and never lists the prior-hash chain / issuer-cert-hash anti-equivocation work. D0004 §43–46 confirms the eight/nine-field schema and prior-hash chain are v1.
- **Impact:** This is multi-month original cryptographic engineering (per §9.1 "v1 ships substantial original cryptographic engineering (capability tokens, trust-graph operation envelope, share format, recovery-flow memory hygiene)" — line 724). Hiding it inside one phrase in §6.1 understates the v1 surface to funders and partners reading §6 in isolation. The 9–12 month claim was supposedly rebudgeted around D0004's cuts, but D0004 didn't cut this work — it preserved it and §6.1 doesn't surface it.
- **Recommendation:** Add an explicit "Cryptographic envelopes and anti-equivocation" v1 deliverable line to §6.1 enumerating: COSE_Sign1 + deterministic CBOR for both capability tokens and trust-graph operations; the nine-field signed-operation schema per D0006; prior-hash chain implementation; issuer-cert-hash binding. Either keep it in v1 honestly or move the equivocation-detection portion to v1.5 with an explicit architectural-slot framing.

### F2: Sigsum integration is a v1 commitment with no v1 deliverable line and no acknowledgment that the witness pool doesn't yet exist

- **Evidence:** §6.1 line 573 says "trust evaluation queries Sigsum directly in v1." §5.2 lines 366–372 commit v1 to: per-operation submission to Sigsum at issuance, on-demand client query of the log, commitment-only logging (hash submission, not content), per-(issuer, subject) prior-hash chains computable from commitments, and a witness pool of NGO partners and academic auditors cosigning the log state. §5.5 line 490 adds that the same witnesses cosign the release log. §8.6 line 832 lists Sigsum witnesses as a partner role the project "seeks partners for" with recruitment "contingent on Q3 (funding for honoraria) and Q5 (NGO partner outreach) resolving" per §9.1 line 867. §8.6 line 827 states explicitly: "they are not confirmed partnership arrangements."
- **Impact:** §6.1 commits v1 to an architecture whose operating substrate (the witness pool) §8.6 and §9.1 simultaneously describe as conditional intent. A reader of §6 in isolation receives a v1 commitment that §8/§9 contradict. The witness pool is not a release-engineering convenience; trust-graph evaluation in v1 literally cannot run without it.
- **Recommendation:** §6.1 must either (a) name witness-pool recruitment as a v1 precondition with a target completion date before v1 launch, with the conditional partner-outreach dependency surfaced inline rather than hidden in §8.6; or (b) demote Sigsum integration to v1.5 with v1 shipping operations as locally-signed-and-cached only. Status quo is incompatible with D0004's "honest scope" framing.

### F3: External reviewer pool is a v1 commitment whose recruitment §8.2 explicitly does not commit to

- **Evidence:** §6.1 line 579: "External source-code review by a recruited reviewer pool with the 5+ membership and 3-of-5 attestation threshold targets specified in 5.5 and 8.6." §5.5 line 486 makes the reviewer attestation gate explicit: "the project does not ship below 3-of-5 attestation; releases wait for quorum." §8.2 line 740 (volunteer-baseline cadence) says reviewers are "volunteer-attestation basis — reviewers contribute time because the project's mission aligns with their own work, with public acknowledgment in release notes as the recognition mechanism" and that honoraria "become the operational model once partnership or grant funding closes (Q3)." §9.1 line 867 states the pools "may not form or may erode" and recruitment is "contingent on Q3 (funding for honoraria) and Q5 (NGO partner outreach) resolving."
- **Impact:** Releases cannot ship until 3-of-5 attestations form. If the volunteer pool doesn't form, v1 doesn't ship — full stop. §6.1 presents this as a v1 commitment; §8.2 and §9.1 present pool formation as conditional intent. A funder reading §6 sees deliverable; reading §8/§9 sees risk. Per D0008 (volunteer baseline cadence), median release interval is 4–6 months as quorum forms. That is not a v1 timeline property surfaced in §6.
- **Recommendation:** Move reviewer-pool recruitment to a "v1 preconditions" subsection in §6.1 with explicit dependency on Q3 and Q5, and revise the §6.1 release-security paragraph to state that v1 launch is gated on first-quorum attestation. Acknowledge inline that absent recruitment, v1 launches without external attestation or does not launch.

### F4: §6.4 forward-compatibility commitments smuggle multi-month engineering into v1 that §6.1 doesn't acknowledge

- **Evidence:** §6.4 line 644: "Protocol versioning fields in all signed messages from day one." Line 646: "Capability tokens with arbitrary scope strings." Line 652: "Trust graph operation types designed for extension." Line 654: "Storage schemas with version fields and migration framework" with "explicit schema versioning with migration tests that round-trip data through each migration step." §5.7 line 552 makes the migration framework concrete: "SQLite with explicit schema versioning and migration tests using property-based round-trip verification through each migration step." Line 656 adds: "Build system designed to produce multiple artifacts" with "keeping cross-compilation paths clean from day one." None of this appears in the §6.1 v1-deliverable enumeration; it lives in §6.4 framed as design choices rather than as engineering work.
- **Impact:** Property-based migration tests, multi-artifact build infrastructure, and protocol versioning enforcement across every signed message are real engineering line-items, not free design choices. §6.4 reads as "things v1 chooses for free." They are not free. The 9–12 month estimate, post-D0004 cuts, has to absorb this work.
- **Recommendation:** Restructure §6.4 to explicitly distinguish "v1 architectural commitments that require no additional engineering" from "v1 forward-compatibility deliverables that require dedicated v1 engineering effort." Move the property-based migration test framework, the multi-target build pipeline, and protocol-version enforcement into the latter category and surface them in the §6.1 v1 scope enumeration.

## Significant findings

### F5: Rollback resistance is in §5.5 as v1 but not in §6.1

- **Evidence:** §5.5 line 492: "Version numbers in signed release metadata are monotonic, and the client refuses to install a release whose version is lower than the highest version it has previously installed." This is described as a v1 client-side enforcement mechanism. §6.1's release-security paragraph (line 579) names "Two-layer signing... External source-code review" but omits rollback resistance entirely.
- **Impact:** Rollback resistance requires persistent client state ("highest version it has previously installed") that survives reinstall/wipe, plus signed release metadata format work, plus client install-time enforcement. Modest scope but real. Silent inclusion means it doesn't get budgeted.
- **Recommendation:** Add rollback resistance as an explicit v1 client-side mechanism in §6.1.

### F6: Multi-channel distribution claims in §5.5 conflict with §4.2-aligned v1 distribution scope

- **Evidence:** §5.5 line 494 commits v1 to multi-channel distribution including "a Tor onion service operated by the project, and offline signed images suitable for hand-delivery." §4.2 (line 263) — the principles section — states explicitly: "v1 distribution covers F-Droid, Accrescent, and GitHub releases; the Tor onion service and offline signed-image channels are deferred to v1.5/v2 when funded operations capacity exists." §6.1 does not name the v1 distribution channels at all.
- **Impact:** Direct intra-§5 contradiction with §4.2, and §6.1 is silent on which version is correct. A reader checking what v1 ships for distribution gets different answers depending on which section they read.
- **Recommendation:** §6.1 should explicitly name the v1 distribution channels (per §4.2's stricter scope) and §5.5 should be revised to match. Pick one — §4.2 reads more honest for the volunteer baseline.

### F7: Push-notification UnifiedPush integration and 15-min polling default are v1 but not in §6.1

- **Evidence:** §5.4 line 456: "UnifiedPush is the architectural choice." Line 458: "v1 ships with push notifications off by default. The client polls at user-configurable intervals (default 15 minutes)." This requires: UnifiedPush distributor selection UX, polling-loop implementation with battery-aware behavior, user-configurable interval setting, opt-in flow during provisioning with consent walkthrough. §6.1 names none of it; closest is "Signal-familiar messaging surface" (line 577).
- **Impact:** Polling-default + opt-in UnifiedPush flow is meaningful UX and protocol-integration work that the §6.1 enumeration skips. Adds to the v1 surface area without budget acknowledgment.
- **Recommendation:** Add push-notification posture to §6.1's UI-surface paragraph or as a separate notification-architecture line.

### F8: Crash-reporting infrastructure is specified as a v1 deliverable in §5.7 with no §6.1 acknowledgment

- **Evidence:** §5.7 line 558: "Crash reporting and feedback. Opt-in only, end-to-end encrypted, delivered through the existing messaging layer to a Cairn-team-controlled SimpleX queue rather than a separate analytics endpoint." This requires: a project-operated SimpleX queue, consent flow at provisioning, encrypted report delivery, intake/triage infrastructure on the receiving side. §6.1 makes no mention.
- **Impact:** Project-operated infrastructure adds operational cost (queue maintenance, intake handling) that §4.2's "minimal project-operated infrastructure" principle and §8 don't budget. Silent inclusion.
- **Recommendation:** Either name crash reporting as a v1 deliverable with its operational implications in §6.1, or defer to v1.5 with documented-only "report via partner channel" as the v1 substitute.

### F9: §6.1 commits v1 to documentation that §8.6 makes conditional on partners

- **Evidence:** §6.1 line 581: "Documentation. User guide, facilitator handbook for the in-person provisioning ceremony, peer-recovery handbook for share-holders, written post-coercion recovery guidance, troubleshooting reference, and a security-model overview suitable for technically literate users. Partner organizations are natural collaborators for the user-facing and facilitator documentation (Section 8.6)." §8.6 line 836 lists user training as a partner role and line 833 specifies pilot facilitation partner organizations as candidates whose participation "would be negotiated with the organization's program leadership." §5.7 line 557 adds that partner organizations (Tactical Tech, EFF SSD, Front Line Defenders) "are candidates for co-producing the user-facing and facilitator documentation."
- **Impact:** Six distinct documentation artifacts are committed as v1 deliverables, several of which §5.7 and §8.6 explicitly frame as partner-collaborative — meaning their completion depends on partners that have not yet been recruited (Q5). If partners don't engage, either the developer writes all six himself (adding multiple developer-months to v1) or v1 ships without complete docs.
- **Recommendation:** Distinguish in §6.1 between documentation the developer can solo and documentation that requires partner collaboration; for the latter, frame as "intent subject to partner outreach Q5" consistent with §8.6's framing.

### F10: Key-rotation flow is v1 in §5.1 but not in §6.1

- **Evidence:** §5.1 lines 309–311 commit v1 to operational-key rotation: "Rotation requires the master and is performed at three predictable moments: at provisioning... after a coercion event... and proactively." This includes: rotation UI flow, master reconstruction during rotation, new operational key generation, signing the new operational key with the master, trust-graph key-rotation operation issuance, revocation of prior operational identity. §6.1 mentions "five operation types (attestation, attestation withdrawal, key compromise revocation, introduction, key rotation)" (line 573) — so the operation type is named, but the UX flow and the master-reconstruction-for-routine-rotation case isn't enumerated as v1 work.
- **Impact:** Rotation under coercion (which §5.1 line 311 calls "itself a vulnerable moment") requires peer-coordinated master reconstruction — the same 48-hour cooling-off flow as recovery. v1 must ship both flows or one. §6.1 leaves it ambiguous.
- **Recommendation:** Either explicitly name "operational-identity rotation flow (provisioning, recovery, proactive)" as a v1 UX/protocol deliverable in §6.1, or defer proactive rotation to v1.5 with the architectural slot preserved.

### F11: §6.1 commits to "five operation types" but the cascade quarantine semantics are an v1 implementation

- **Evidence:** §6.1 line 573: "the trust graph from Section 5.2 ships with five operation types... and commitment-only Sigsum anchoring." §5.2 lines 374–380 specify the cascade quarantine on revocation: attestation withdrawal soft-flags downstream attestations from the withdrawal date forward; key compromise revocation hard-suspends post-`revoked_as_of` attestations and soft-flags prior ones; 90-day stale-flag auto-quarantine escalation; per-attestation timer that resets on user touch. This is the load-bearing v1 trust-graph behavior. §6.1 names the operation types but not the cascade semantics or the stale-flag escalation logic as v1 deliverables.
- **Impact:** Cascade-quarantine + stale-flag-escalation is the substantive trust-graph computation v1 must ship. Naming the operation types without naming the cascade logic makes v1 sound like a CRUD-of-signed-claims feature when in fact it's the original adversarial-design work D0006 records.
- **Recommendation:** Add explicit "cascade quarantine semantics per D0006 and 90-day stale-flag escalation" to the §6.1 trust-graph commitment.

### F12: §7.1 v1.5/v1.6 split adds v1-affecting forward-compatibility work that §6 doesn't acknowledge

- **Evidence:** §7.1 line 670 introduces a v1.5/v1.6 split (architecture-completeness vs deferred-UX) that wasn't present in D0004's framing (D0004 §65–67 still names v1.5 as a single release covering all deferrals). The split assumes the volunteer-baseline cadence per D0008. §7.2 line 682 specifies what v1 must do to enable v1.5: "The Briar integration in v1.5 reuses the v1 identity model, capability-token format, and trust-graph operation envelope" — meaning the v1 capability-token format must be Briar-ready in advance.
- **Impact:** The v1/v1.5/v1.6 boundary is sliding without re-baselining §6. Specifically, "Briar-ready in advance" is a real v1 design constraint that §6 should name as a v1 architectural deliverable rather than leaving as an implicit precondition for v1.5. The split also moves duress-wipe to v1.6 (per §7.1) while D0002 and §6.2 still list it as v1.5.
- **Recommendation:** Reconcile the v1.5 contents listed in §6.2 with the v1.5/v1.6 contents listed in §7.1; either §6.2 needs the same split or §7.1 needs to roll back to the single v1.5 commitment. Acknowledge the implicit v1 design constraint that Briar-readiness imposes.

## Minor findings

### F13: Pluggable-transport tracking is a continuing v1 commitment hidden in §5.4 prose

- **Evidence:** §5.4 line 454: "transport choices appropriate at v1 release may be blocked by v2... The project commits to tracking Tor Project transport guidance and prioritizing transport-update releases when active blocking is observed." This is an operational v1 commitment with sustained engineering cost (release-engineering responsiveness to upstream transport changes). §6.1 says nothing about transport layer.
- **Impact:** Sustained operational commitment that affects release cadence (per D0008). Not catastrophic but unbudgeted.
- **Recommendation:** Acknowledge transport-tracking as an operational commitment in §6.1 release-security paragraph or in §8.2.

### F14: §6.3 pilot scope adds developer-side operational work not enumerated in §6.1

- **Evidence:** §6.3 lines 630–632: "The project provides devices for pilot users: GrapheneOS-installed Pixel hardware with the Cairn application pre-installed." This requires: device sourcing, GrapheneOS install pipeline for 10–15 devices, app pre-install workflow, identity-not-yet-provisioned state preparation, in-person provisioning facilitation per user (10–15 ceremonies). Plus the §6.3 line 636 "dedicated in-app support channel" plus the 3-month/6-month partner debriefs (line 636).
- **Impact:** §6.3's pilot operations are significant developer time across the 6-month pilot window that runs concurrent with v1.5 design. Not v1-build scope strictly, but in the v1 timeline budget.
- **Recommendation:** Either acknowledge in §6.1 that the developer's v1 engineering time excludes pilot operations time, or budget the pilot operations work as a §6.1/§6.3 line item.

### F15: §6.4 "Build system designed to produce multiple artifacts" is silent inclusion

- **Evidence:** §6.4 line 656: "The same pipeline is designed to accept additional targets... without restructuring. This is mostly engineering hygiene rather than a feature commitment."
- **Impact:** "Engineering hygiene" framing is doing too much work. Cross-compilation discipline for Rust core targeting Android in v1 + USB/iOS in v2 + embedded in v3 is real architectural constraint on v1 build system design. Framing it as "mostly hygiene" minimizes the v1 work.
- **Recommendation:** Re-frame as "v1 build-system architectural commitment: cross-compilation paths kept clean from day one to support v2/v3 targets without restructuring."

## Patterns

**P1: §6.1 reads as a press-release summary; §5 is the actual v1 spec.** The recurring pattern is that §5 commits multi-month engineering for v1, §6.1 either names it in one phrase or omits it. The discipline §6 advertises (Briar deferred, CRDT dropped, UX narrowed) is real, but the resulting v1 is still substantially larger than §6.1's bulleted scope suggests. Findings F1, F4, F5, F7, F8, F10, F11, F13, F15 all instances.

**P2: §6 commits to what §8 frames as conditional.** Reviewer pool, Sigsum witnesses, partner documentation collaboration, and the OIDC-provider operational defenses are presented as v1 commitments in §6 while §8.2, §8.6, and §9.1 frame them as conditional on Q3 (funding) and Q5 (partner outreach) that have not closed. A funder reading §6 sees deliverables; the same funder reading §8/§9 sees risks. Findings F2, F3, F9.

**P3: §6.4 forward-compatibility framing hides v1 engineering as "design choices."** Several items in §6.4 read as zero-cost architectural commitments when they are in fact dedicated v1 engineering line-items (protocol versioning enforcement, migration framework, multi-artifact build pipeline). Findings F4, F15.

**P4: §6.1/§6.2/§7.1 do not agree on what's in v1.5.** §6.2 lists v1.5 contents per D0004; §7.1 splits v1.5 into v1.5/v1.6 with duress-wipe in v1.6 contrary to D0002/§6.2; D0004 §65–67 still describes v1.5 as a single release. The boundary is sliding. Finding F12.
