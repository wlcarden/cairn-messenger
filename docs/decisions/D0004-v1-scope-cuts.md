# D0004 — v1 scope cuts: defer Briar and reproducible builds to v1.5; drop local CRDT permanently; narrow v1 UX

**Status:** Accepted
**Date:** 2026-05-27

## Context

The Section 5 adversarial review (see [section-5-review.md](../archive/section-5-review.md), pattern P3 and finding F7) identified that v1 architecture as drafted exceeds what a solo developer can produce in the stated 9-12 month timeline. The engineering-feasibility lens estimated 18-30 months at the current scope.

The estimate is LLM-generated and carries uncertainty; the project treats it as directionally correct (the underlying engineering is real) but not literally precise. The directional message is unambiguous: scope cuts are needed if v1 is to ship in the original window.

The options were: cut scope, extend timeline, or hybrid. Funder timing and pilot timing argue for keeping the 9-12 month window if achievable; the conservative-cuts option preserves it.

This decision interacts directly with [D0003 (Rust core + Kotlin UI)](D0003-implementation-language.md), which was made at the same session. D0003 reduces the engineering cost of some items (Sigsum client, Tor integration) and increases it slightly for others (UniFFI binding layer); the net effect makes the scope cuts below sufficient for the 9-12 month target.

## Decision

Apply four scope changes:

1. **Briar deferred to v1.5.** v1 ships SimpleX-only. The Briar architectural slot is preserved (protocol versioning, capability tokens with extensible scopes — see Section 6.4). No Briar integration is built in v1; the "extra-private mode" toggle in v1 UX is removed.

2. **Local CRDT for trust graph dropped permanently from the v1.5 roadmap.** v1 anchors the trust graph in Sigsum directly: trust evaluation queries the log rather than computing against a local CRDT view. v1.5 adds local caching for offline-tolerance (so users can see cached attestations without network) but does not add a full CRDT. The CRDT becomes a v2+ candidate to be reconsidered only if pilot evidence shows that offline trust-path computation is operationally required — a property the project no longer commits to as a roadmap deliverable.

3. **Reproducible builds deferred to v1.5; recruited reviewer pool also deferred to v1.5 (per [D0015](D0015-v1-release-security-posture.md)).** v1 ships with Sigstore identity-based signing + Rekor transparency log + Sigsum-anchored release log with witness cosignatures + multi-channel distribution + developer source review. The recruited 5+/3-of-5 external reviewer pool defers to v1.5 alongside reproducible builds; the combination delivers binary-equivalence multi-party verification. Recruitment work proceeds at v1 through Q5 outreach but v1 ship is not gated on pool formation. The v1 supply-chain gap (developer source review does not detect a compromised build pipeline producing a malicious binary from clean source) is acknowledged and incorporated into [D0013](D0013-pilot-consent-exit.md) pilot consent.

4. **UX surface narrowed for v1.** Three specific deferrals:
   - Per-conversation extra-private-mode toggle removed (irrelevant without Briar in v1; restored when Briar lands in v1.5).
   - Multi-profile compartmentation UX deferred (v1 ships single-profile-only; the architectural slot is preserved but no profile-switcher chrome ships in v1).
   - In-app post-coercion recovery flow becomes documentation-only in v1; the in-app first-class action lands in v1.5.

### Update (architecture-simplification review consensus cuts)

Per the architecture-simplification adversarial review's Section A consensus cuts (F1, F2, F3, F12), four additional v1 scope reductions:

5. **Project-operated SimpleX crash-reporting queue cut from v1 (F1).** Pilot crash reports and feedback flow through the partner-mediated reporting channel per [D0013](D0013-pilot-consent-exit.md). The §4.2 minimal-project-operated-infrastructure principle ships without exception at v1. v1.5+ may add an in-app encrypted crash-reporting flow if pilot evidence demonstrates the partner channel does not capture the operational data the project needs.

6. **Multi-target build pipeline cut from v1 (F2).** v1 build pipeline produces the GrapheneOS-Pixel APK only; cross-compilation scaffolding for v2 USB images, v2 iOS bundles, or v3 mesh-node firmware is deferred to v2 when funding for platform-expansion engineering work closes. UniFFI binding maintenance for the Rust↔Kotlin v1 boundary remains a v1 working-set component per D0003.

7. **Property-based migration test framework deferred to v1.5 (F3).** Schema-versioning _fields_ ship from v1 onward; the property-based migration test framework lands at v1.5 alongside the first real schema migration. v1 has one schema, so no migration-framework target exists at v1; basic forward/backward round-trip tests cover the single schema until v1.5.

8. **UnifiedPush distributor-selection UX deferred to v1.5 (F12).** v1 ships polling-only with no in-app distributor-selection UX. The architectural slot for UnifiedPush integration is preserved per §6.4. The v1.5 revisitation of push-default plus distributor-selection UX depends on pilot feedback — distributor selection becomes operationally relevant when polling-vs-push becomes a user choice rather than a project default.

### Update (architecture-simplification review Section B split-lens recommendations)

Per the project's adoption of three Section B split-lens recommendations, three additional roadmap-level adjustments:

9. **90-day stale-flag auto-escalation timer deferred to v1.5 (F9 partial).** Stale-flag _visibility_ ships at v1 — the trust-graph evaluation exposes stale-attestation state and the developer-as-facilitator surfaces stale attestations during partner debriefs per §6.3. The dedicated 90-day auto-escalation timer (the logic that promotes stale-flags to hard-quarantine after the timer fires) defers to v1.5 alongside the deferred-UX work. No schema change is required for the deferral; v1's stale-flag state is preserved and v1.5 adds the timer over it. Cascade quarantine semantics (the five operation types and the withdrawal-vs-compromise split that closes the cascade-laundering attack) are NOT deferred — they remain v1 commitments per D0006.

10. **iOS support split from v2 to v3 (F8c).** v2 was previously committed as USB form-factor + iOS support together. The iOS upstream-dependency surface (Apple App Store policies; iOS code-signing posture; Briar iOS unavailability) is meaningfully separate from USB form-factor work; the brief now commits v2 as USB-only and v3 as iOS. v2 ask becomes cleaner; v3 inherits the iOS-specific dependency framing.

11. **Mesh radio integration moved from v3 to v4+ candidate (F8a).** Previously committed as v3 (Meshtastic + MeshCore protocol-agnostic integration), mesh integration becomes a v4+ candidate evaluated when v2 ships. The deferral reflects Meshtastic/MeshCore upstream stability (both communities have made breaking changes within 18-month windows), the partner-organization outreach extension that mesh-radio communities would require, and the hardware-partnership question (previously tracked as Q25; now subsumed into the v4+ candidacy framing). The §10.4 Phase D upstream-roadmap-tracking estimate is reduced accordingly (~30-80 hrs/yr from earlier 40-100 hrs/yr).

12. **Pre-pilot audit scope narrowed to two surfaces (F5).** Per [D0011](D0011-audit-budget-and-timing.md) update, the pre-pilot audit narrows from four components (COSE_Sign1 envelope; Shamir SSS reconstruction with memory hygiene; trust-graph operation envelope nine-field schema; recovery-flow crypto) to two (COSE_Sign1 envelope construction including the nine-field schema; recovery-flow crypto). The two surfaces removed (Shamir primitive itself; trust-graph schema-as-such) move to Rust-core property tests + §5.5 source review — the Shamir GF(256) byte-wise threshold scheme is a well-understood primitive; the schema is a closed-form data layout source-review reviewers see directly. The two surfaces retained are where Cairn does original construction no upstream audit covers. Same $15-30K subsidized budget; the narrower scope concentrates auditor attention on the original-construction surfaces rather than reducing overall audit cost.

## Alternatives considered

**Option B — Moderate cuts (2 cuts).** Defer two of the four candidates. Rejected because the engineering review's pattern was that the four together close the gap; partial cuts likely leave a residual 3-5 month overrun that surfaces under deadline pressure when scope has lost its margin.

**Option D — Extend timeline to 18-24 months, no cuts.** Rejected. Maintains the v1 architecture but delays funder conversations, pilot start, and partner outreach. The honest case for the longer timeline is real, but the cost in elapsed time before any user benefit is high.

**Option E — Hybrid: 3 cuts + extend to 14-16 months.** Rejected. The compounding effect of "we cut scope AND we slipped timeline" is harder to message to funders than either alone. If the scope cuts are right, the timeline holds; if they aren't, they can be revisited.

**Keeping the CRDT as a v1.5 commitment (not dropping permanently).** Considered. Reviewers' technical case for the CRDT (offline trust path computation, no log-availability dependency for trust evaluation) is real. Rejected because (a) the CRDT is novel cryptographic engineering with significant convergence-property complexity even in Rust core, (b) pilot evidence has not been collected on whether offline trust evaluation is a real operational requirement for the target audience, and (c) the local-caching enhancement planned for v1.5 covers the most common case (users who occasionally lose connectivity but rejoin within hours) without the full CRDT. The CRDT is the right tool only if pilot evidence shows users experience long-duration disconnection during which they need to evaluate new attestations they have not yet synced. That evidence does not yet exist.

## Consequences

### Section 5 (Architecture Detail) updates

- **5.2 (Trust Graph)** rewritten for v1: trust evaluation queries Sigsum directly rather than computing against a local CRDT view. The four operation types remain. The eight-field schema remains (with additions per F5/F23 from review). What changes is how clients evaluate trust paths — they fetch operations from the log on demand rather than computing against a local replicated state. v1.5 adds local caching; no CRDT in any planned version.

- **5.4 (Communications Protocols)** rewritten as SimpleX-primary-only for v1, with Briar's architectural slot acknowledged for v1.5. The "extra-private mode" toggle is removed from v1 UX. The conversation-tier mental model in v1 is "SimpleX with operational discipline"; the Briar tier returns in v1.5.

- **5.5 (Updates and Release Security)** updated: Sigstore identity-based signing and external source-code review in v1; reproducible builds added in v1.5. The reviewer pool reviews source in v1 (their attestation states they have read and reviewed the source corresponding to a release commit) rather than binary equivalence. Reviewer attestations remain Sigsum-anchored.

- **5.6 (UX Principles)** updated: extra-private toggle removed; profile compartmentation UX deferred; in-app post-coercion guidance becomes documentation-only in v1 (the flow exists as a written guide users and facilitators reference; the in-app first-class action lands in v1.5).

- **5.7 (or appropriate placement) Implementation language and build tooling** added — a short subsection pointing at [D0003](D0003-implementation-language.md) as the architectural reference for the Rust core + Kotlin UI split.

### Section 3.5 (Threat Model) updates

The "in-scope" paragraph adjusts to acknowledge that v1's highest-sensitivity tier is SimpleX with operational discipline (not Briar pure peer-to-peer); the compelled-unlock answer per [D0002](D0002-duress-profile.md) still holds (tier separation is architectural, not Briar-specific). The "explicitly out of scope" paragraph adds Briar-tier P2P messaging as a v1.5 deliverable.

### Section 6 (v1 Scope) updates

- **6.1 (What ships in v1):** Briar integration removed; trust graph implementation note changed to "transparency-log-anchored (Sigsum); local caching deferred to v1.5; CRDT not planned"; reproducible builds replaced with "external source-code review and Sigstore-anchored signing"; UX scope explicitly noted as tight (no extra-private toggle, no profile compartmentation UI, no in-app compelled-unlock flow).

- **6.2 (What's explicitly deferred):** Briar (v1.5), reproducible builds (v1.5), local trust-graph caching (v1.5), in-app post-coercion recovery flow (v1.5), per-conversation extra-private toggle (v1.5), multi-profile UX (v1.5). Local CRDT for trust graph: not planned; revisitation contingent on pilot evidence.

### Section 7 (Roadmap) updates

**7.1 v1.5 entry** expanded to be the "complete the v1 architecture" release: Briar integration, reproducible builds, local trust-graph caching, in-app post-coercion recovery UX, per-conversation extra-private toggle, profile compartmentation UX, duress-wipe (already in v1.5 per [D0002](D0002-duress-profile.md)).

### Funding and pilot implications

- Funder ask in Section 10 remains in the same range; the v1 deliverable shape is different but the resourcing is the same.
- Pilot users receive SimpleX-only messaging with the full identity-and-trust-graph layer. The "highest-sensitivity tier" (Briar) is a v1.5 enhancement rather than a v1 commitment. The compelled-unlock recovery flow is in documentation rather than in-app.
- Partner conversations need to be honest about the v1.5 reliance: the partner organizations recruited for facilitation, reviewer pool, and Sigsum witnessing should understand that v1 is a deliberately scoped baseline and v1.5 completes the architecture.

### Architectural property implications

- **Forward-compatibility (Section 6.4) intact.** Protocol versioning, capability token extensibility, multi-device awareness — to the extent F11 from review is addressed in a separate decision — remain. v1.5 additions are non-breaking for v1 clients.
- **Trust-graph availability tradeoff** explicit and accepted. Trust evaluation requires online access to Sigsum (v1) or local cache (v1.5). Users in fully-offline conditions cannot evaluate trust on attestations they have not seen. This is a real availability cost the project explicitly accepts in exchange for not building the CRDT.
- **No-CRDT decision is permanent** until pilot evidence revisits it. v2+ planning should not assume a CRDT will exist; features that would have depended on it must be redesigned against the log-anchored model.

## Reversibility

- **Briar deferral.** Reversible at v1.5; the architectural slot is preserved. No v1 client breaks when v1.5 adds Briar.
- **Reproducible-builds deferral.** Reversible at v1.5; reviewer attestations shift from source-review to binary-equivalence verification without breaking the verification chain.
- **CRDT permanent drop.** Reversible at v2+ but only if pilot evidence justifies the engineering investment. The decision intent is "do not plan on it"; reopening it requires explicit evidence, not the default assumption.
- **UX narrowing.** Most reversible cut. If pilot feedback indicates users want any of the deferred UX before v1.5 lands, the project can ship it in a v1.x point release without architectural change.

## References

- [docs/section-5-review.md](../archive/section-5-review.md) — adversarial review findings F7, F8, F9, F10, F11; pattern P3.
- [docs/decisions/D0003-implementation-language.md](D0003-implementation-language.md) — language stack decision; precondition for the engineering-cost recalculation that justifies these specific cuts.
- [docs/decisions/D0002-duress-profile.md](D0002-duress-profile.md) — establishes the pattern of "deferred to v1.5 with architectural answer in v1"; duress-wipe deferral in v1.5 is now collected with the cuts above.
- Engineering reviewer's recommendation list specifically (within the engineering-feasibility section of the consolidated review).
