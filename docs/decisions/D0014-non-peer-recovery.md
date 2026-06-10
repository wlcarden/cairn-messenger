# D0014 — Non-peer recovery path policy: out of scope for v1 with explicit acknowledgment; named v1.5+ candidate paths

**Status:** Accepted
**Date:** 2026-05-28

## Context

The Section 2 adversarial review surfaced finding §2 F12 (the pilot-user and practitioner lenses): §2.2 names "users without a peer network capable of holding recovery shares responsibly" as out of scope. §2.2 line 58 simultaneously names the Recovery surface as "directly addressing the failure mode that dominates this population: peer compromise as the proximate path to user compromise." The architecture's response to peer compromise is a model that requires absence of peer compromise. For the populations §2.1's threat tier centrally includes — sex workers under criminalization, abuse survivors with severed networks, isolated dissidents, undocumented organizers, queer people in criminalizing jurisdictions whose peers face the same prosecution — the precondition (a trusted, geographically-distributed, socially-distant peer network of ~5) cannot be satisfied because the operating condition of the threat is the absence or compromise of exactly that network.

The §2 review identifies this as the most acute audience-architecture gap in the brief: §2.1 names a threat tier the recovery architecture cannot serve for several of its most-acute subgroups, and §2.2 currently lists those subgroups as "out of scope" without naming them as the central population the architecture's social-recovery commitment systematically excludes.

The §5 adversarial review (sections-5-review.md, applied via [D0005](D0005-peer-verification.md)) addressed the peer-verification mechanism but left the peer-network-existence assumption unaddressed. The §§8/9 review made conditional posture explicit but did not raise the non-peer recovery question because the architecture-vs-audience gap is a §2 issue.

## Decision

**Updated 2026-05-29 per consolidated external-reads triage (X9 / E11): Paper shares are accepted as a v1 alternative recovery path alongside peer recovery.** The earlier framing — non-peer recovery as v1.x/v2 candidate — is updated to ship paper shares at v1 as an alternative path users can choose at provisioning instead of (or alongside) the peer-recovery path. Remaining candidate paths (time-locked self-recovery; single-trustee with attorney-client privilege; explicit no-recovery option) remain v1.x/v2 evaluation candidates as the prior decision named.

**Acknowledge time-locked self-recovery, single-trustee with attorney-client privilege, and explicit no-recovery as v1.x or v2 candidates with explicit framing; surface the architecture-vs-audience gap honestly in §2.2 and §9.2 rather than leaving it implicit.**

### Paper shares: v1 alternative recovery path

Multi-persona convergence across the consolidated external-reads triage (partner P8/X9 on recovery operational tempo; end-user E11 on paper shares being the realistic recovery path for working journalists) supports adding paper shares as a v1 first-class alternative recovery path. The reasoning:

- **Eliminates the recovery-network surface.** Paper shares do not require a peer network the user can trust to refuse coercion; the security property rests on the user's physical-storage security rather than on peers' coercion-resistance.
- **Eliminates the peer-maintenance burden.** Users do not need to coordinate share renewal with peers (single-use phrases per D0005); the user holds their own shares.
- **Closes the recovery-tempo gap for journalists and time-critical users.** The 48–96 hour peer-recovery window is incompatible with journalism workflows where a source's situation escalates in hours; paper-share recovery can complete in the time it takes the user to physically retrieve their stored shares.
- **Serves part of the v1.x non-peer recovery exclusion set.** While paper shares do not serve all the populations §2.2 names as v1 audience exclusions (sex workers under criminalization whose physical environment is itself surveilled; abuse survivors whose physical home is the threat environment; prisoners' families whose mobility is constrained), it does serve the subset of those populations who have access to off-environment storage (work locations, partner-organization offices, trusted attorney offices, safe-deposit boxes) — a non-trivial expansion of the v1 addressable audience without the full v1.x non-peer-recovery candidate set.

**Engineering scope at v1:** ~40–80 hours absorbed into v1's working set. Implementation: at provisioning, the user generates Shamir 3-of-5 shares using the same scheme as peer recovery (per [D0006](D0006-cryptographic-envelope.md) and [D0005](D0005-peer-verification.md)). Shares are printed (or formatted as QR codes for camera-based recovery on a fresh device) in a format suitable for physical distribution; the user stores them in physically-distributed locations of their choosing. Recovery on a fresh device requires reassembling 3 of 5 physical shares (camera-scanned QR or manual entry). The 48-hour cooling-off window does not apply to paper-share recovery — there is no peer to enforce it, and the threat model the cooling-off window addresses (peer impersonation; coerced peer cooperation) does not apply to user-held physical shares. **Coercion resistance for paper shares rests on physical-storage security**, which the user controls and the provisioning ceremony walks through.

**User-facing framing at v1:** the in-app post-coercion recovery flow (per consolidated triage E3) presents both paths at provisioning. The provisioning ceremony walks the user through the tradeoffs:

- **Peer recovery:** stronger cryptographic protection against impersonation (the peers verify the user is who they claim to be); 48-hour cooling-off provides cancel window against adversary-initiated recovery; requires peer network that can refuse coercion; recovery takes 48–96 hours.
- **Paper shares:** no peer dependency; recovery completes in hours rather than days; depends on physical-storage security the user controls; no built-in cancel window against an adversary who has gathered the physical shares (the user's primary defense is keeping the shares physically dispersed and themselves secured).

The user can choose either path, or both (peer recovery + paper shares can coexist; the user has two ways to recover, each with different threat-model characteristics). The provisioning ceremony surfaces the choice rather than imposing a default.

**Pilot evidence input.** Paper-share adoption rates and operational success patterns in the v1 pilot inform whether paper shares should become the default, an explicit user-selected alternative, or revert to v1.x candidate-only status. The pilot specifically tests whether paper-share users can store and retrieve their shares operationally across the 6-month pilot window without loss or compromise events.

### v1 posture: explicit acknowledgment, not silent exclusion

The brief commits in §2.2 and §9.2 to the following:

- Users without a peer network capable of holding recovery shares responsibly are out of scope for v1 recovery as architecturally designed.
- The architecture's response to peer compromise (3-of-5 Shamir reconstruction with pre-shared peer challenges and 48-hour delay-and-confirm per [D0005](D0005-peer-verification.md)) requires the existence of a peer network the threat condition itself often precludes.
- This exclusion is named — the brief lists the populations who face the §2.1 threat tier but cannot use v1 recovery: sex workers in jurisdictions where peer networks are co-criminalized, domestic-abuse survivors with severed or hostile networks, undocumented organizers, queer people in jurisdictions criminalizing queerness whose peers face the same prosecution, religious minorities under family surveillance, prisoners' families.
- For these users at v1, the honest acknowledgment is that Cairn v1 is an inappropriate tool because recovery cannot be designed against their threat condition. The brief does not recruit users into a product whose central recovery mechanism cannot serve them.

This acknowledgment is named in §2.2 (audience description), §6.3 (pilot scope — these populations are explicitly named as out of pilot scope by name, not by abstraction), and §9.2 (recovery risk register).

### Post-v1 candidate paths

The project commits in §7 (Roadmap) and Q23 (open-questions.md) to evaluating non-peer recovery paths for v1.x or v2 deployment. The candidate paths to evaluate include:

- **Printed paper shares held by self.** The user generates Shamir shares at provisioning and prints them (or writes them on durable media — laminated cards, microfilm, etc.) for storage in geographically-distributed self-held locations (safe deposit boxes, trusted lawyer custody, attorney-client-privilege documents). No social network required. Recovery requires re-entry of shares from physically-retrieved media. Failure modes: physical security of the printed material; loss; coercion to produce stored materials (mitigated by D0005-style pre-shared challenges with self-generated answers stored separately). This is the option closest to v1's architecture and likely to be the v1.x candidate.

- **Time-locked self-recovery.** The user's master is split into shares, some held on-device and some held by a time-lock mechanism (a server that releases its share only after a configurable delay; a cryptocurrency-style time-lock contract; a co-operating partner organization holding a share with a documented release condition). Recovery requires waiting out the time-lock. Failure modes: server availability; partner organization's continued operation; the time-lock window itself being a coercion-tolerable window. Operationally heavier than paper shares but eliminates the physical-storage problem.

- **Single-trustee with attorney-client privilege.** The user designates a single licensed attorney holding a Shamir share under attorney-client privilege, with the privilege itself acting as the coercion-resistance mechanism. The attorney's release condition is the user's authentication (per D0005-equivalent peer-challenge mechanism). Failure modes: jurisdiction-specific attorney-client privilege scope; cost of attorney engagement; attorney's continued availability and competence. Best-suited for users with existing legal-counsel relationships.

- **Explicit no-recovery option with documented user consent.** The user provisions Cairn with explicit acknowledgment that they accept the no-recovery posture: if they lose their device, they lose their identity and must re-enroll under a new identity. The user is informed at provisioning of this choice's irreversibility and of the implications for their established trust-graph relationships (peer attestations must be re-established). Operationally simplest. Best-suited for users in operational contexts where re-enrollment is cheap and recovery infrastructure is itself a coercion vector.

Selection of which path(s) Cairn implements is deferred to v1.x scope discussion; candidate-path enumeration in this decision is intentionally non-prescriptive about which to build.

### What this decision does not commit to

The decision does not commit to:

- A specific timeline for non-peer recovery shipping (v1.x or v2 is the framing; specific timing depends on Phase C funding and engineering capacity per §10.3).
- A specific selection among the candidate paths.
- That all non-peer-recovery candidate paths will be shipped — the brief may select one path that serves the largest subset of the excluded populations and defer others.
- That Cairn will become the right tool for all of the v1-excluded populations — some operational contexts (most acute survivor cases, deepest-undercover dissidents) may remain inappropriate fits for Cairn regardless of recovery path. The post-v1 paths broaden the audience; they do not promise universality.

## Alternatives considered

**Ship v1 with no acknowledgment of the excluded populations.** _(Considered, rejected.)_ The status quo. The Section 2 review identifies this as the most acute audience-architecture gap; leaving it implicit means the brief recruits users from §2.1's threat tier into a product that cannot serve their central need. Practitioner-lens framing is that this is "the failure mode trainers most want to avoid endorsing."

**Ship v1 with a non-peer recovery path already.** _(Considered, rejected.)_ Adding paper-shares recovery, time-locked recovery, or attorney-trustee recovery to v1 expands v1 scope significantly past what D0004's v1 scope cuts established. The volunteer baseline cannot absorb the additional engineering, UX work, and documentation. Honest deferral with explicit naming is preferable to ambitious scope creep that may not ship.

**Defer the question entirely to v2.** _(Considered, rejected.)_ §2.1's threat tier includes these populations centrally; deferring without acknowledgment leaves the v1 brief silently misaligned with its own threat-tier framing. The v1.x framing in this decision keeps the post-v1 candidate paths plausible at v1.5/v1.6 timing if engineering capacity and partner relationships emerge, without overcommitting v1.

## Consequences

### Section 2.2 updates

The §2.2 audience description is restructured (per Section 2 review F1, F3, F12) to:

- Name explicitly the populations who face the §2.1 threat tier but for whom v1 recovery is architecturally inappropriate: sex workers in jurisdictions where peer networks are co-criminalized, domestic-abuse survivors with severed networks, undocumented organizers, queer people in criminalizing jurisdictions, religious minorities under family surveillance, prisoners' families.
- State that v1 Cairn is an inappropriate tool for these users until non-peer recovery ships.
- Cross-reference D0014 and the v1.x/v2 candidate-path commitment.
- Cross-reference D0013 (pilot consent and exit) for the broader honest-disclosure posture.

### Section 6.3 updates

The §6.3 pilot scope is updated to explicitly state these populations are out of pilot scope as a recovery-architecture consequence (not as a recruitment-network limitation). This distinguishes "the pilot does not reach you because the facilitator is in another city" from "the pilot does not reach you because the architecture's recovery model is wrong for your threat condition."

### Section 7 updates

§7 (Roadmap) gains a v1.x or v2 commitment to evaluate non-peer recovery candidate paths per this decision, with the candidate paths listed.

### Section 9.2 updates

§9.2 (recovery risks) gains:

- The peer-network-existence assumption as an explicit architectural assumption, with the audiences for whom it holds and the audiences for whom it does not.
- The architectural-vs-audience gap as a v1 limitation with named v1.x/v2 mitigation.
- Cross-reference to D0014.

### Open question

Q23 added to [open-questions.md](../open-questions.md): Non-peer recovery path selection for v1.x/v2 (paper shares; time-locked; single-trustee attorney-privilege; explicit no-recovery option; combination). Selection requires engagement with partner organizations who facilitate the excluded populations.

### Architecture-vs-audience honesty propagation

The §4.2 calibration principle ("calibrated language replaces absolute-sounding claims") is extended to §2.2's audience claims via this decision. The architecture commits to what its components actually support; the audience description commits to who those components actually serve. The two should not drift.

### Reversibility

Fully reversible. If v1.x non-peer recovery ships, the v1-out-of-scope acknowledgment in §2.2 can be revised to reflect the expanded audience. If partner-organization conversations or pilot evidence reveal that the candidate paths are wrong, the decision can be revised at low cost — the v1 architecture is not changed by this decision; only the audience description and the v1.x roadmap commitment.

## References

- [docs/section-2-review.md](../section-2-review.md) — §2 F12, F3; pattern P2 (intimate network missing from §2).
- [docs/decisions/D0005-peer-verification.md](D0005-peer-verification.md) — peer-verification mechanism this decision does not modify.
- [docs/decisions/D0013-pilot-consent-exit.md](D0013-pilot-consent-exit.md) — pilot consent protocol that the architecture-vs-audience honesty commitment parallels.
- [docs/sections-8-9-review.md](../sections-8-9-review.md) — F12 limit-acknowledgment posture (Safe Harbor).
- Research-ethics literature on protective-technology evaluation among populations whose threat condition is the absence of trusted networks.
