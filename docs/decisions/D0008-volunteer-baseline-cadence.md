# D0008 — Volunteer-baseline release cadence: slippage acceptance with quarterly as post-honoraria target

**Status:** Accepted
**Date:** 2026-05-28

## Context

The Sections 8/9 adversarial review surfaced pattern P2 and finding F2: the combined operational commitments in Section 8 — quarterly release cadence, 5+ reviewer pool with 3-of-5 attestation threshold, 18-month reviewer rotation, per-release toolkit maintenance, per-release coordination — are sized for a funded organization with a dedicated release-coordinator role, but the v1 self-funded-MVP posture runs them on volunteer time with the developer absorbing what would normally be coordinator work. Four reviewers independently identified the gap.

The brief commits in 8.2 to "quarterly cadence matching reasonable reviewer-pool availability for volunteer reviewers"; the review showed the cadence does not match volunteer availability. The decision is how to reconcile the commitment with the operational reality without abandoning the multi-party-attestation property the cadence supports.

## Decision

**Accept release slippage as the expected behavior of the volunteer baseline.** The expected median release interval at volunteer baseline is 4-6 months; quarterly remains the target cadence once honoraria fund.

**Update (per [D0015](D0015-v1-release-security-posture.md)):** the recruited 5+/3-of-5 reviewer pool defers from v1 critical path to v1.5. At v1, release cadence is governed by engineering scope completion plus pre-pilot audit closing plus the partner-mediated pilot consent and exit protocol landing — not by reviewer-pool quorum formation. At v1.5 onward, releases ship when 3-of-5 reviewer attestations form (the architectural threshold from Section 5.5, activated at v1.5 when the recruited pool ships alongside reproducible builds). The 4-6 month median interval applies at both v1 (developer engineering + audit cycle) and v1.5+ (volunteer-attestation pool "as-quorum-forms" pattern) — the underlying operational reality is the same volunteer cadence; only the proximate cause shifts.

This is the honest answer for the volunteer baseline. It does not change the security property the multi-party attestation provides at v1.5+ (the threshold is preserved). It does change what users and partners expect about release frequency, both at v1 and at v1.5 onward.

## Alternatives considered

**Extend cadence to semi-annual for the volunteer baseline.** _(Considered, rejected.)_ Cleaner explanation, but conflates two separate concerns: cadence (how often releases happen) and threshold (how many reviewers attest each release). Slippage acceptance preserves the threshold's stated purpose; semi-annual cadence implies the project has decided semi-annual is the right rhythm rather than the rhythm that happens. The former is honest about what the project does; the latter implies a choice the volunteer baseline doesn't actually offer.

**Lower attestation threshold to 2-of-N for volunteer baseline.** _(Considered, rejected.)_ Preserves quarterly cadence at the cost of security margin. The 3-of-5 threshold was chosen specifically to provide margin against single-reviewer compromise (Section 5.5); reducing to 2-of-N defeats that property. The project commits to threshold preservation as the load-bearing security property rather than cadence preservation as the operational-comfort property.

## Consequences

### Section 8.2 updates

The "Release cadence" paragraph is rewritten to reflect the volunteer-baseline expectation. The current text reads "roughly quarterly cadence"; the revised text reads approximately:

> "The v1 release cadence depends on reviewer-pool engagement. Releases ship when 3-of-5 reviewer attestations form (the architectural threshold from Section 5.5). At the v1 self-funded-MVP volunteer baseline, the expected median interval between releases is 4-6 months; partner-funded honoraria operations (per Q3) would target quarterly cadence. Security-critical patches use the emergency-release path (below) when median timing is operationally inappropriate. Users and partners should plan against the actual cadence pattern: as-quorum-forms in volunteer baseline, target quarterly post-honoraria."

The "Emergency-release path" paragraph remains unchanged; the 2-of-5 threshold for documented emergencies provides the fast-path for security-critical patches that cannot wait for the median interval.

### Section 7.1 v1.5 timing implications

If volunteer-baseline cadence is 4-6 months between releases, v1.5 is operationally one to two release cycles after v1 alpha — implying v1.5 ships at 10-18 months post-v1 launch rather than the 6 months the brief currently states. This combines with F9 (v1.5 timeline credibility) to argue for the v1.5/v1.6 split, which is captured separately in this commit's broader Section 7 edits.

### Pilot user expectations

Pilot user documentation (Section 5.7, 6.3) names the actual release cadence honestly: "you can expect security-critical patches via the emergency-release process; routine releases ship as the reviewer pool can sustain, typically every 4-6 months at the v1 pilot baseline." The documentation does not promise quarterly cadence the project cannot reliably deliver.

### Honoraria transition

Per [D0004](D0004-v1-scope-cuts.md) and Section 8.2 as touched up in this session's funding-stance edits, honoraria become the operational model once partnership or grant funding closes. Post-honoraria cadence target is quarterly; the project commits to revisiting cadence at the honoraria transition point rather than holding cadence fixed regardless of resource state.

## Reversibility

The decision is fully reversible at the honoraria transition. The architectural threshold (3-of-5) does not change; only the cadence assumption changes. If the volunteer baseline turns out to sustain quarterly rhythm without the predicted slippage, the brief can adjust its language in v1.5+ updates with no architectural rework.

## References

- [docs/sections-8-9-review.md](../archive/sections-8-9-review.md) — F2, pattern P2; multi-reviewer convergence on the volunteer-baseline gap.
- [docs/decisions/D0004-v1-scope-cuts.md](D0004-v1-scope-cuts.md) — establishes the self-funded-MVP posture this decision operates within.
- Section 5.5 — three-of-five attestation threshold is preserved by this decision; only cadence assumption changes.
