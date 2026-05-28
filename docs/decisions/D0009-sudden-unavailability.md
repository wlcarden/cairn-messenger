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

### Pre-arranged partner advisory authority

A named partner organization is pre-arranged with the authority to publish a project status advisory if the developer's monthly check-in misses by **60 days** (two consecutive missed cycles). The advisory states the developer's last verified status, names known-good alternatives for users to migrate to, and either declares the project temporarily suspended (if recovery is anticipated) or initiates the sunset process (if no recovery is anticipated).

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

When the foundation is incorporated (per 8.4), the board takes over the partner advisory authority role (or formally appoints it). The board composition criteria (per F33 minor finding) gain a note that one role of the board post-incorporation is to hold the advisory authority that v1 partner arrangement establishes.

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

- [docs/sections-8-9-review.md](../sections-8-9-review.md) — F6, pattern P5; multi-reviewer convergence.
- [docs/section-5-review.md](../section-5-review.md) — P1, F2; the developer as a target at this threat tier.
- Section 9.4 sunset plan — existing framework this decision extends.
- Section 5.5 signing identity compromise plan — pre-staged response that this decision extends to the unavailable-developer case.
