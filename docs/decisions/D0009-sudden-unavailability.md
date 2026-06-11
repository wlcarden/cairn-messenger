# D0009 — Sudden-developer-unavailability contingency: dead-man's-switch plus pre-arranged partner advisory authority

**Status:** Accepted
**Date:** 2026-05-28

## Context

The Sections 8/9 adversarial review surfaced pattern P5 and finding F6: the Section 9.4 sunset plan addresses graceful developer-initiated shutdown but does not address sudden developer unavailability — coercion, illness, detention, asset seizure. The brief takes these risks seriously for _users_ in Section 3 (border seizure, compelled unlock, off-the-books detention are explicitly named) but does not take them seriously for the _developer_, even though the Section 5 review (P1, F2) identified that the developer is themselves a target at this threat tier.

The risk is structural: the conditions that trigger sunset (developer unavailable per 9.4) also trigger sunset failure (no one to execute the six-month announcement, the successor handover, the final security advisory). The brief's existing mitigation — "the project state is recoverable by any successor" via documentation discipline — addresses static project state but not active operations.

## Decision

**Adopt a layered contingency: dead-man's-switch monthly check-in plus pre-arranged partner advisory authority, plus pre-staged successor documentation accessible without developer action.**

### Dead-man's-switch monthly check-in

The developer performs a monthly check-in to a pre-arranged signal — a signed status message published to the project's transparency log on a fixed monthly schedule. The check-in mechanism is simple (signed message, cron-scheduled human action) and verifiable (the signing identity is the developer's Sigstore identity, anchored in Rekor). A missed check-in is the trigger for advisory authority below.

### Pre-arranged partner advisory authority (30-day first-contact + 60-day public advisory per consolidated external-reads triage X5)

A named partner organization is pre-arranged with two trigger thresholds (revised from prior single 60-day threshold per the consolidated triage finding that the §3 threat tier requires earlier detection):

- **30-day first-contact threshold.** If the developer's monthly check-in misses by 30 days (one consecutive missed cycle), the partner advisory authority initiates first contact through pre-arranged direct channels — out-of-band PGP-encrypted email, partner-organization-mediated phone call, or other private channel established at partner-recruitment time. The goal is to confirm the developer's status without escalating to public advisory; many missed-check-in cases at this threshold are recoverable (developer traveling, sick, or with administrative delay). The 30-day threshold catches the 14–45 day "something is wrong" cases without immediately escalating.
- **60-day public-advisory threshold.** If first-contact attempts at the 30-day threshold fail to confirm developer status, and the check-in remains missed at 60 days (two consecutive missed cycles), the partner advisory authority publishes a project status advisory.

The advisory states the developer's last verified status, names known-good alternatives for users to migrate to, and either declares the project temporarily suspended (if recovery is anticipated) or initiates the sunset process (if no recovery is anticipated).

### Per-state response plan for in-flight users at trigger fire (per consolidated external-reads triage P18)

Some pilot users may be in mid-recovery, mid-rotation, or have just initiated a partner-challenge cycle at the moment the trigger fires. Their operational state depends on the project's continued operation through the next 24–96 hours. The advisory authority's announcement that the project is suspended is operationally too coarse for those users — they need specific guidance about what to do with in-flight operations. The pre-staged successor documentation (below) includes runbooks for in-flight cases:

- **User mid-recovery (peers contacted, cooling-off window active).** Recovery flow continues unaffected by trigger fire — peer-side enforcement of the 48h window means shares release through peer devices, not project infrastructure; reconstruction proceeds normally on the recovering device. Successor runbook: "Recovery does not require project intervention; complete the flow as normal; if recovery requires verification through the project that is not available, the advisory authority's communication identifies the partner who can confirm recovery legitimacy in lieu of the developer."
- **User mid-rotation (proactive key rotation in progress).** Rotation requires the master, which is on the user's recovering device, not in project infrastructure. Successor runbook: "Complete rotation as normal; the operational identity rotation is a user-local cryptographic operation that does not require project intervention."
- **User mid-partner-challenge (recovery initiated; peer challenges in progress).** Peer challenges run between user and peers, not through project infrastructure. Successor runbook: same as mid-recovery above.
- **User awaiting CVE patch.** If a CVE is in disclosure-and-patch cycle when the trigger fires, the multi-party APK signing-key custody (below; trustees can initiate APK rotation) is the response path. Successor runbook: identifies the trustees and the procedure for initiating emergency-patch release without developer involvement.

### Duress-canary mechanism (per consolidated external-reads triage X5, M18)

The dead-man's-switch monthly check-in message includes a structured affirmation that the developer is acting freely. **Absence of the affirmation triggers the partner advisory regardless of timing**, addressing the coercion-induced-false-continuation residual (a developer compelled to issue continuation signals indefinitely is detected because the affirmation is omitted by an adversary unaware of its load-bearing role, or the developer can omit it under coercion as a quiet signal).

The affirmation is structured as a small constant phrase or token included in the signed check-in message; the partner advisory authority verifies its presence as part of normal check-in processing. The phrase is not secret (the partner knows what to look for), but its omission is not trivially distinguishable from a typo or formatting error — the partner verifies through the established direct-channel confirmation before publishing the advisory, applying the same 30-day-first-contact discipline. The mechanism is adapted from the warrant-canary pattern (used by Tor Project, ISP transparency reports, and others) to the dead-man's-switch flow.

Implementation cost: 1–2 hrs/month additional developer time (composing the affirmation as part of the check-in message); partner-side check-in-parsing infrastructure ~20 hrs one-time setup.

### Multi-party APK signing-key custody (per consolidated external-reads triage X4)

The APK signing token is held under an **N-of-M trustee arrangement with 2-of-3 access threshold at v1 ship** (specified in Section 5.5; cross-referenced here as the technical-execution capability the partner advisory authority can invoke). Trustees: developer, partner advisory authority partner, one additional named individual. The arrangement allows APK Signature Scheme v3 key rotation to be initiated by 2-of-3 trustees if the developer becomes unavailable. **This is the mechanism that lets the partner advisory authority's public announcement be paired with a patched release when sudden unavailability coincides with a CVE in disclosure** — closing the failure mode where the advisory publishes "the project is in crisis" simultaneously with "and here's an unpatched vulnerability that cannot be patched without developer access to signing material."

Trustee identities are named in the successor-handover documentation. Trustee renewal is on the same cadence as Q14 partner advisory authority renewal.

Selection of the partner organization is deferred to Q5 outreach but constrained by criteria: (a) organizational stability sufficient to maintain the role over years; (b) institutional independence from the developer; (c) operational capacity to issue a public advisory on short notice; (d) jurisdictional placement that does not concentrate the advisory authority in the same legal process the developer's primary jurisdiction is exposed to. Candidate organizations to approach: Software Freedom Conservancy, Open Tech Fund (as a notification recipient and channel), Front Line Defenders, Tactical Tech. The advisory authority is unconditional within the partner's own operational tempo — the partner does not require further developer authorization once the 60-day trigger fires.

### Pre-staged successor documentation

Successor-handover documentation lives in the project's public repository from v1 alpha, structured so that a successor organization can pick up project operations without developer involvement. Contents: current architectural state (the design brief is the authoritative reference), open-questions tracker, decision documents, pilot-user contact roster (encrypted; decryption-key custody arranged with the partner advisory authority), reviewer-pool roster and onboarding state, witness-pool roster, signing-identity-recovery procedure (per Section 5.5 compromise plan extended to the unavailable-developer case), Sigstore/Sigsum operational state. The documentation is updated on the same monthly cadence as the dead-man's-switch check-in.

### Sunset advisory under sudden unavailability

When the 60-day trigger fires, the partner advisory authority follows a pre-staged advisory script: the public announcement states the developer status, points pilot users to migration paths, identifies whether the project is suspended (recovery anticipated) or initiating sunset (recovery not anticipated), and links to the successor-documentation repository. If sunset is initiated, the six-month sunset window (per 9.4 existing) begins from the partner's advisory publication, not from a developer-issued statement that cannot be produced.

## Alternatives considered

**Pre-staged successor documentation only (no active mechanism).** _(Considered, rejected.)_ The brief currently approximates this — "the project state is recoverable by any successor." The review found it insufficient because it requires the partner to detect developer unavailability and decide to act, neither of which the brief has arranged. For a product targeting users at this threat tier, the project itself cannot rely on passive successor detection when active mechanisms are achievable.

**Both mechanisms but partner identity deferred to Q5.** _(Considered, partially adopted.)_ The selection of the specific partner organization is deferred to Q5 outreach — that part of this alternative is incorporated. What is _not_ deferred is the architectural commitment to the mechanism: the project commits to the dead-man's-switch + advisory authority architecture regardless of which partner ultimately holds the role. Deferring both the architecture and the partner would leave the gap open; deferring only the partner-selection preserves the architectural commitment.

## Consequences

### Section 9.4 updates

A new "Sudden-unavailability contingency" subsection is added to 9.4, distinct from the existing sunset plan. It describes the dead-man's-switch check-in cadence, the partner advisory authority's role and trigger, the pre-staged successor documentation, and the sunset advisory script. The existing sunset-plan paragraph is retained for the developer-initiated case but explicitly framed as the planned-shutdown variant.

### Section 8.4 board composition addition

If the [D0016](D0016-foundation-incorporation-trigger.md) foundation-incorporation trigger activates and the project incorporates per Section 8.4, the board takes over the partner advisory authority role (or formally appoints it). The board composition criteria gain a note that one role of the board after incorporation is to hold the advisory authority that the partner arrangement establishes. **If the D0016 trigger does not activate, the partner advisory authority remains the permanent governance scaffold** rather than a transitional state — the project commits to renewing the partner arrangement per its multi-year cycle indefinitely; the monthly dead-man's-switch check-in operates indefinitely; the pre-staged successor documentation remains the project's permanent successor-recoverability commitment. Q14 partner-organization selection criteria emphasize permanent-operational-fit (multi-year reliability; institutional stability; willingness to renew the arrangement over indefinite horizons) under the D0016 deferral framing.

### Section 3.4 trust roots

The partner advisory authority becomes a named trust placement. The pre-arrangement assumes the partner will act in the user's interest, will hold the advisory script and documentation custody securely, and will not itself be compromised at the same time as the developer. Add the partner advisory authority to 3.4 trust roots once a specific partner is named (Q5/Q10 tracks recruitment).

### Operational cost

The dead-man's-switch check-in is approximately 15-30 minutes per month (signed message authoring, transparency-log submission, brief status writeup) plus the cost of maintaining successor documentation current (estimated 1-2 hours per month, overlapping with documentation work the project does anyway). Total: 2-3 hours per month sustained. The partner advisory authority has effectively zero ongoing cost until the trigger fires; the cost is preparatory (the advisory script must be drafted and partner-rehearsed once, with annual review).

### What the contingency does and does not address

**Addressed:** Sudden developer unavailability lasting more than 60 days, of any cause (accident, illness, detention, coercion that prevents project communication, asset seizure that includes signing infrastructure). Pilot users receive a status advisory rather than silent abandonment.

**Not fully addressed:** Sudden unavailability lasting less than 60 days — the project's release cadence and pilot facilitation continue to depend on the developer in that window. Coercion that compels the developer to issue false continuation statements through the dead-man's-switch mechanism — the advisory authority does not have a way to detect coercion-under-duress within the developer's own check-ins. These are residual exposures named in 9.3 as part of the broader sunset and SPOF discussion.

### Reversibility

The mechanism is reversible at low cost. If pilot evidence shows the dead-man's-switch trigger is too sensitive (false positives from missed check-ins for benign reasons) or too insensitive (the 60-day window allows damage during unavailability), the parameters can be tuned in v1.x releases. The partner advisory authority role is itself a partnership that can be renegotiated.

## References

- [docs/sections-8-9-review.md](../archive/sections-8-9-review.md) — F6, pattern P5; multi-reviewer convergence.
- [docs/section-5-review.md](../archive/section-5-review.md) — P1, F2; the developer as a target at this threat tier.
- Section 9.4 sunset plan — existing framework this decision extends.
- Section 5.5 signing identity compromise plan — pre-staged response that this decision extends to the unavailable-developer case.
