# Architecture Simplification — Multi-Year Solo-Developer Feasibility Lens

**Lens:** §§6/7-E (multi-year). Extends §§6/7-E F3 (specialist-role absorption at v1) and F6 (v2/v3 declarative framing) by asking: across v1 → v1.5 → v1.6 → v2 → v3, what compounds into recurring solo-developer scope that has no graceful exit at the volunteer baseline §10.1 commits to and no successor takeover viability under D0009?

Throughout this lens, "compounding" means the work doesn't end at v1 ship — it returns every release cycle (release coordination), every audit cycle (D0011 ~18-24 months), every upstream-protocol release (SimpleX, Briar, Tor pluggable transports, GrapheneOS-Pixel), every grant cycle (3-9 months per §10.5), every partner-retention cycle (§8.6, §8.2 18-month reviewer rotation), or every check-in cycle (D0009 monthly).

## Summary

The §§6/7-E lens identified that v1's solo absorption of three §8.1 specialist roles is unsustainable. This lens identifies the deeper problem: v1's architectural commitments install **recurring coordination loops** that operate independently of v1 ship state. Each loop — audit cycle, upstream-protocol tracking, reviewer-pool rotation, witness-pool maintenance, partner advisory authority, fiscal-sponsor relationship, dead-man's-switch check-in, Sigsum operator participation, multi-channel distribution, trust-roots health reporting — runs on a clock the developer does not control and cannot pause. The compounded annual coordination load (F1-F6 below) is the structural commitment that v1's "9-12 person-month" framing hides; §10.4's "every contributor except the engineer-operator" framing names the funding consequence but does not name the architectural choices that produced it.

The cuts that materially relieve the Phase D sustainability cliff are specifically those that remove **recurring** rather than **one-time** scope: deferring v3 mesh integration indefinitely (eliminates a third upstream-protocol-tracking commitment and a new partner category); deferring iOS to v3+ rather than v2 (eliminates a parallel platform-coordination commitment one release earlier); collapsing v1.6 into v1.5 or v2 (eliminates a distinct release-engineering-and-attestation cycle); replacing self-operated Sigsum witness participation with sole reliance on third-party witnesses (eliminates an infrastructure-coordination commitment that §10.4 explicitly budgets in the higher infrastructure tier); deferring multi-channel distribution to F-Droid + Accrescent only (eliminates GitHub-and-Tor-onion + offline-image channels as recurring distribution surfaces). With these cuts, Phase D's maintainer-comp aspiration shifts from "load-bearing for survival" to "preference for higher throughput" because the recurring-coordination floor drops below the bandwidth a self-funded solo developer can sustain without compensation.

Without these cuts, the brief's multi-year horizon is credibly v1-ship-able but not v1.6-or-v2-survivable at the volunteer baseline. D0009's successor-takeover assumption (per Section 9.4: "the project state is recoverable by any successor") fails empirically against the recurring-coordination loops, because successor cold pickup requires not just architectural documentation but the relationship state of every recurring loop — and §8.6 acknowledges these are the developer's relationships.

## Critical findings (commitments that don't survive multi-year solo)

### F1: Recurring external audit cycle (D0011, §8.5, §10.4)

**Commitment:** §8.5 commits to a second external cryptographic audit "approximately 18-24 months after the first." §10.4 amortizes this to $40-100K/year and frames it as a Phase D line item. §7.2 acknowledges recurring audits land between v2 and v3 timing under Phase D projection and may trigger architectural-revisitation work.

**Multi-year solo cost:** Audit-cycle execution is not a one-time engagement; it is a **recurring** coordination commitment. Per-cycle: subsidy-program application (3-9 month cycle per §10.5); audit firm engagement scoping; auditor onboarding to current architecture state (Rust core + Kotlin UI per D0003, current trust-graph schema, current envelope per D0006, etc.); auditor question-and-answer cycle during 4-6 week engagement (§10.3); draft report receipt; remediation engineering (D0011's scope spans capability tokens, Shamir, trust-graph envelope, recovery flow, release-security stack — every audit touches the full surface); re-audit verification of remediation; audit-report publication per §8.5; release-engineering cycle to ship the remediated build. Realistic developer load per audit cycle: 80-200 hours over 3-6 elapsed months, distributed across application, scoping, engagement-Q&A, remediation, re-verification, and publication. At 18-24 month cadence this is **40-100 hours of recurring coordination per year baseline**, before any audit-finding-driven architectural revisitation work.

§7.2 explicitly states: "audit findings may trigger architectural-revisitation work the roadmap does not currently plan for." This is honest framing but it is also a recurring uncovered scope: the developer absorbs whatever the audit finds, on top of the audit-coordination cycle. The §§6/7-E F3 lens addressed v1-ship absorption; this lens identifies that audit-driven revisitation is a Phase D scope that compounds with every cycle and that §10.4's per-year cost estimate covers the **engagement** but not the **engineering remediation**.

**Successor-takeover viability:** Low. D0009 documents pre-staged successor docs (architectural state, decisions, rosters). It does not document the **active state of in-flight audit cycles**: which subsidy program is mid-application, which firm has accepted scope, which findings are mid-remediation, who is the auditor contact. A successor picking up cold mid-audit-cycle would need to either restart the cycle (losing 3-6 months and potentially refunding) or reconstruct the relationship state from email archives — which D0009 does not address as a successor handoff artifact. The 60-day D0009 trigger is shorter than typical audit cycles, meaning sudden unavailability can fire **during** an audit and leave the partner advisory authority publishing an advisory while an audit firm waits for response.

**Recommendation:** Phase D recurring audit cycle is **accept as Phase C-funding-required**; if Phase C funding does not close, §8.5's "no-skip-the-audit" posture means broader release is gated, and the volunteer baseline cannot sustain the 18-24 month recurring cycle indefinitely. The brief should additionally acknowledge that audit-finding remediation is uncovered solo scope on top of the engagement budget; current §10.4 framing budgets the engagement but not the engineering response. Consider explicitly framing the recurring audit cycle as the **first** Phase D commitment to lapse if Phase D funding fails — gracefully sliding the second audit to 36+ months rather than 18-24 months — and document this slippage as the expected behavior at volunteer baseline, mirroring D0008's slippage-acceptance posture for release cadence.

---

### F2: Upstream-protocol tracking across three pluggable transports plus two messaging protocols plus a hardware platform

**Commitment:** §5.4 commits to tracking Tor Project pluggable-transport guidance and prioritizing transport-update releases when blocking is observed. v1 SimpleX-only; v1.5 Briar joins. v3 adds Meshtastic and MeshCore. All run over GrapheneOS-Pixel hardware whose roadmap §9.2 acknowledges Google controls. §5.5 commits to tracking PQ standardization and "harvest now" capability emergence.

**Multi-year solo cost:** Each upstream is a continuous attention loop with no end state:

- **SimpleX upstream tracking** (v1+): protocol version changes; double-ratchet derivative updates; queue-server protocol changes; SimpleX project release cadence (~4-8 weeks for major releases at current cadence). Per-cycle developer load: 4-12 hours of compatibility review per upstream release; longer when protocol-version changes require Cairn-side schema or wire-format updates.
- **Briar upstream tracking** (v1.5+): BTP/BSP protocol updates; `bramble-core` API changes; Briar's release cadence (slower than SimpleX historically but irregular). §5.4 acknowledges the integration "relies on these properties as published by the Briar project and named as a trust root in Section 3.4." §6.2 acknowledges v1.5 Briar is "conditional on Briar's continued upstream maintenance." Briar's maintainer pool is itself small; §10.7 does not name this as a funding-failure mode but the brief's posture means a Briar maintainer-pool degradation event lands directly on Cairn's v1.5 deliverable.
- **Tor pluggable-transport tracking** (v1+): obfs4, meek, webtunnel, snowflake — §5.4 frames this as "an ongoing engineering commitment, not a one-time decision: transport choices appropriate at v1 release may be blocked by v2." This is honest, and it is **a multi-year recurring engineering commitment** by the developer's own admission. Per-cycle load varies by blocking event; the brief commits to prioritizing transport-update releases when blocking is observed, which competes against every other release commitment.
- **GrapheneOS-Pixel platform tracking** (v1+): GrapheneOS release cadence (~monthly); Pixel hardware generation changes (annual); secure-element capability changes across Pixel generations (StrongBox vs TEE-backed per §5.1 already requires generation-by-generation handling); Pixel device availability in target deployment regions (§9.2 acknowledges as out-of-project-control). Per-cycle load: 4-8 hours per GrapheneOS release for compatibility review; multi-week effort per Pixel generation that introduces a secure-element change.
- **Meshtastic and MeshCore upstream tracking** (v3+): §7.1 acknowledges "both communities have made breaking changes within 18-month windows." Adding v3 adds two parallel upstream tracking loops on top of SimpleX + Briar + Tor + GrapheneOS.
- **PQ standardization tracking** (v1+): §5.5 commits to tracking. Lower-frequency, but every NIST PQ standard change requires evaluating implications for Cairn's COSE_Sign1 envelope and Ed25519 dependence.

Compounded annual upstream-tracking load by v3 ship: SimpleX (~60-100 hours/yr) + Briar (~30-60 hours/yr) + Tor PT (~20-60 hours/yr depending on blocking events) + GrapheneOS-Pixel (~50-100 hours/yr) + Meshtastic + MeshCore (~40-80 hours/yr) + PQ monitoring (~10-20 hours/yr) = **210-420 hours/year** of recurring upstream-tracking coordination, before any one upstream's breaking change consumes a release cycle.

**Successor-takeover viability:** Very low for the relationship-state portion. Technical upstream-tracking is documentation-discoverable from the public projects' own release notes. What is **not** discoverable cold is the developer's accumulated context on each upstream's maintainer style, deprecation patterns, and historical breaking-change recovery moves. A successor picking up v1.5-with-Briar cold without that context faces a significantly steeper learning curve than the v1.5 ship work itself.

**Recommendation:** **Cut v3 from the roadmap** (or defer to v4+ as a project-survives-to-then question) to eliminate Meshtastic + MeshCore as two parallel ongoing upstream-tracking loops. §6.2 already lists v3 as "addressing internet-shutdown scenarios" with v3's audience-relevance acknowledged in §9.2. Cutting v3 reduces compounded upstream-tracking load by ~40-80 hours/year recurring. **Additionally simplify v1.5 Briar to "conditional, deferred indefinitely if Briar maintainer-pool degrades"** (§6.2 already states the condition; the brief should be more aggressive about reframing v1.5 as ship-without-Briar-if-Briar-not-available rather than ship-when-Briar-lands). Briar's small maintainer pool is itself an unnamed solo-cliff exposure for Cairn.

---

### F3: Reviewer-pool recruitment, rotation, and honoraria coordination as a recurring partner-coordination loop (§8.2, §5.5)

**Commitment:** §5.5 commits to 5+ reviewer pool with 3-of-5 attestation threshold. §8.2 commits to 18-month reviewer rotation cadence with overlap. §8.2 commits to honoraria budgeting when funding closes ($40-100K/year per §10.3) with pool-recruitment cycles ongoing. §10.7 acknowledges "reviewer-pool erosion risk increases during grant-cycle transitions" and the "volunteer-to-honoraria-to-volunteer trajectory is a real possibility."

**Multi-year solo cost:** Reviewer-pool maintenance is a **continuous** partner-coordination loop, not a one-time recruitment event. Per-cycle:

- Initial recruitment (~Phase A): 5+ reviewers identified, evaluated, onboarded through reviewer toolkit (§8.2). Per-reviewer outreach + evaluation + onboarding: 8-20 hours.
- Per-release coordination: §8.2 commits to 3-of-5 attestation per release. Each release requires reviewer notification, toolkit access, reviewer-side question handling, attestation collection, Sigsum entry coordination. Per-release load: 8-20 hours at the median 4-6 month cadence per D0008, scaling to per-quarter at the post-honoraria target.
- 18-month rotation: outgoing reviewer offboarding + incoming reviewer recruitment, evaluation, onboarding. At 5+ pool and 18-month rotation, **at least one reviewer transition per 3-4 months on average**, plus overlap onboarding time. Per-transition load: 12-30 hours.
- Honoraria operations (Phase C+): grant-cycle-bound honoraria require per-reviewer agreement maintenance, per-release payment processing, fiscal-sponsor or foundation administrative coordination. Per-reviewer-per-cycle: 2-4 hours.
- Volunteer-baseline state (Phase A/B): pool engagement maintenance without honoraria is materially harder; reviewers depart for compensated work and re-recruitment runs continuously.

§§6/7-E F4 noted that reviewer-pool and witness-pool commitments contradict §8's conditional framing. This lens adds: **reviewer-pool coordination is itself a recurring solo commitment** that compounds across the multi-year horizon. Compounded annual reviewer-pool coordination load: **80-200 hours/year** at the steady state, more during pool-formation and rotation-cluster periods.

**Successor-takeover viability:** Very low. Reviewer-pool composition is exactly the kind of relationship state D0009 does not capture in handover documentation. D0009 lists "reviewer-pool roster and onboarding state" but this is a roster, not the working relationships, trust-calibration history, and individual reviewer preferences that determine pool function. A successor picking up cold would inherit a roster but not the operating relationships; reviewers who attested for the developer may not attest for an unknown successor, and the 18-month rotation cadence means much of the pool would be in transition during successor handover.

**Recommendation:** **Simplify the multi-party-attestation property** by reducing the pool size to 3-of-3 (requiring all three reviewers) rather than 5+ with 3-of-5 threshold. This trades margin against single-reviewer compromise for substantial reduction in pool-coordination scope. The 3-of-5 framing exists explicitly to mirror Shamir parameters (§5.5) — but the design rationale at §5.5 for 5+ rests on "margin against single-reviewer compromise, attrition, and unavailability." A 3-of-3 pool with explicit acknowledgment that attestation can pause for replacement (mirroring D0008's slippage-acceptance posture for cadence) preserves the multi-party property while reducing coordination load by ~40%. Alternative: keep 5+ pool but reduce rotation cadence to 36 months from 18, halving rotation-cycle coordination load. The brief should explicitly model the reviewer-pool coordination floor as a Phase D **operational** cost (currently §10.4 budgets honoraria but not coordination), so the load is visible.

---

### F4: Sigsum witness pool + Sigsum log-operator commitments as additional partner-coordination surface (§5.2, §5.5, §10.4)

**Commitment:** §5.2 commits to NGO/academic Sigsum witnesses for trust-graph commitment-only logging. §5.5 commits to the same partner pool cosigning the release log state. §10.4 includes "log-operator participation" infrastructure cost and frames it as low-to-mid range ($1,000-3,000/year). §3.4 acknowledges the shared-witness-pool concentration risk.

**Multi-year solo cost:** Witness-pool coordination is a parallel recurring loop alongside reviewer-pool coordination, with similar per-cycle costs. Per-cycle: witness recruitment (5+ candidates per §8.6); per-release log-state cosignature coordination; witness-side technical-issue support; witness rotation as organizations shift priorities. The witness pool overlaps with reviewer pool by §8.6's framing — partner organizations contributing as both — but the brief acknowledges the intent to assemble non-overlapping subsets for risk mitigation, which **doubles** the partner-coordination surface relative to a single pool.

§10.4 infrastructure line items include "log-operator participation (if the project operates its own Sigsum log, the higher end; if the project participates in public logs, the lower end)." The brief leaves this as a v1+ decision but the higher-end path adds Sigsum log operation as recurring infrastructure work the developer absorbs.

**Successor-takeover viability:** Very low for the same reasons as F3. Witness relationships are partner-organization relationships; successor handover transfers the roster, not the operating relationships.

**Recommendation:** **Commit explicitly to participation in third-party Sigsum logs only**, never operating a self-hosted Sigsum log. This eliminates the higher-end infrastructure cost and the recurring log-operator coordination work. **Additionally explicitly accept witness-pool overlap with reviewer pool** as an acknowledged correlation risk (§3.4 already names it; the brief should treat it as the Phase D position rather than as a v1-temporary state with v1.5+ separation as goal). This collapses two partner-coordination loops into one. Cost: §3.4's "shared-witness-pool concentration" becomes structural rather than temporary; benefit: solo coordination load drops by approximately half on partner-pool axis (~40-100 hours/year recurring).

---

### F5: Foundation incorporation + fiscal-sponsor + board governance + partner advisory authority as a perpetually-deferred precondition (§8.4, §10.2, §10.3, D0010, D0009)

**Commitment:** §8.4 intends foundation incorporation 18-24 months post-v1. D0010 names it as placeholder pending legal consultation. §10.2 frames pre-incorporation legal consultation as Phase A/B straddle ($1,500-9,000). §10.3 frames incorporation itself at $5-25K. §10.4 frames foundation overhead at $10-30K/year recurring. D0009 names a partner advisory authority for sudden-unavailability handling; the foundation board takes over this role post-incorporation per §8.4.

**Multi-year solo cost:** The foundation pathway is structured so that **every structural mitigation in the brief is conditional on it landing**: formalized Safe Harbor (D0012), board-bound governance, formal partner advisory authority (D0009), reviewer-honoraria operating model (§8.2). Until foundation incorporation, all of these remain at the "stated intent" posture (§10.7 explicitly names this). At the volunteer baseline this is a multi-year deferred coordination commitment with:

- Pre-incorporation legal consultation: 5-15 hours of counsel time but also the developer's own time to scope the consultation, evaluate the jurisdictional shortlist (§8.4 lists US 501(c)(3), Dutch Stichting, Swiss Verein, UK CIC), and respond to counsel's findings.
- Fiscal-sponsor selection and onboarding: 2-6 months (§10.2 acknowledges). Per-sponsor evaluation, application, onboarding, grant-routing setup. Per-grant routing administrative work.
- Foundation incorporation work itself: §10.3 frames at $5-25K and Phase C-funded; the developer-side load includes IP-assignment evaluation, board recruitment (§8.4 lists five role categories), governance-document review, jurisdiction-specific filing coordination.
- Foundation overhead post-incorporation: §10.4 budgets $10-30K/year but **does not budget developer time** for board-interface coordination, accounting oversight, regulatory-compliance review, fiscal-infrastructure operation.
- D0009 partner advisory authority operation: until foundation incorporation, this is a partner-arranged role requiring annual review per D0009's "drafted once at v1 alpha, partner-rehearsed, annual review." Per-cycle load: 4-8 hours of developer + partner coordination.

**Successor-takeover viability:** Very low. Foundation incorporation is by definition a state transition that has not yet happened; D0009 successor handoff inherits an unincorporated entity. The successor would inherit the same multi-year incorporation work plus the partner-advisory-authority relationship's renewal cycle.

**Recommendation:** **Defer foundation incorporation indefinitely** rather than treating it as an 18-24 month milestone. The brief should reframe foundation incorporation as "conditional on project reaching operational scale that supports the foundation overhead" rather than as an aspirational milestone the project commits to pursue. This relieves §10.4's compounded foundation-overhead-without-maintainer-comp posture and removes the multi-year deferred-coordination commitment. Alternative: explicitly commit to operating under a fiscal sponsor **indefinitely**, with foundation incorporation as out-of-scope-indefinitely (§6.2 pattern) rather than as a 18-24 month commitment. This collapses §8.4's selection-criteria scope, eliminates D0010's placeholder commitments, simplifies §10.3's Phase C unlock to "audit + honoraria" without foundation-incorporation costs, and clarifies §10.4 by removing foundation-overhead line items. Cost: §10.7's "structural mitigations remain at stated-intent posture" persists indefinitely rather than ending at incorporation; benefit: Phase D maintainer-comp aspiration moves substantially closer to "preference" rather than "load-bearing for survival."

---

### F6: Multi-channel distribution as four parallel recurring release-engineering surfaces (§5.5)

**Commitment:** §5.5 commits to distribution through F-Droid, Accrescent, GitHub releases, a Tor onion service operated by the project, and offline signed images suitable for hand-delivery. §6.1 commits to F-Droid, Accrescent, and direct download.

**Multi-year solo cost:** Each distribution channel has channel-specific release engineering, policy compliance, and ongoing-operation requirements:

- F-Droid: F-Droid's reproducible-build requirements (post-v1.5), F-Droid metadata format, F-Droid review cycle for new releases (variable; §§6/7-E F22 noted this distribution-policy dependency is unacknowledged). Per-release load: 4-8 hours.
- Accrescent: emerging platform; Accrescent-specific package format and signing. Per-release load: 2-6 hours during emergence; potentially stabilizes.
- GitHub releases: GitHub release-tagging, asset upload, release notes. Per-release load: 1-2 hours, low.
- Tor onion service: §5.5 commits to a "Tor onion service operated by the project" as a recurring infrastructure commitment. Per-cycle: hidden-service key management, onion-address rotation policy, uptime monitoring, on-call when service degrades. **Recurring** infrastructure operations the developer cannot pause.
- Offline signed images: image-build pipeline for offline distribution, per-region image preparation, distribution-partner coordination. Per-cycle load: 4-12 hours per offline-image release; partner-mediated distribution requires partner-coordination beyond engineering.

Compounded across the multi-year horizon, multi-channel distribution adds **~50-150 hours/year of recurring release-engineering and infrastructure coordination**, including a self-operated Tor onion service that exists outside the §4.2 "minimal-project-operated-infrastructure" framing the brief otherwise commits to. §6.1 actually narrows to three channels but §5.5 commits to five — this is itself an inconsistency the brief should resolve toward the §6.1 narrower set.

**Successor-takeover viability:** Low for self-operated Tor onion (operational keys and ongoing uptime monitoring don't transfer cleanly); medium for F-Droid/Accrescent (relationship state with the platforms transfers via documentation); high for GitHub (no platform relationship to inherit). Offline-image distribution requires partner relationships that don't transfer.

**Recommendation:** **Reduce to F-Droid + Accrescent only** (matching §6.1) and **explicitly cut self-operated Tor onion and offline-signed-image distribution**. F-Droid + Accrescent is sufficient for the §5.5 "multi-channel cross-check" property because the two platforms have independent infrastructure. Tor onion adds self-operated infrastructure inconsistent with §4.2; offline signed images require partner-mediated distribution scope that compounds with §8.6. Cost: users in jurisdictions where F-Droid + Accrescent are blocked have a worse distribution surface; benefit: ~50-100 hours/year recurring release-engineering load eliminated; consistency with §4.2 restored.

---

## Significant findings

### F7: D0009 dead-man's-switch monthly check-in plus annual partner-advisory-authority rehearsal as recurring solo work

**Commitment:** D0009 commits to monthly signed status-message check-ins to the transparency log and annual partner-advisory-authority script rehearsal. §9.4 names approximately "2-3 hours per month" cost.

**Multi-year solo cost:** Multi-year cost: ~24-36 hours/year recurring, plus partner-coordination overhead per annual review. This is a small recurring commitment but it is **the floor below which D0009 stops functioning**. A missed monthly check-in is by design a trigger — meaning the developer cannot drop this loop without the partner advisory authority firing. Over a multi-year horizon this is approximately 200-300 hours of cumulative solo time on what is itself a sustainability-mitigation mechanism rather than user-value work.

**Successor-takeover viability:** N/A — this commitment is structurally about handling sudden unavailability and cannot be transferred without defeating its own purpose.

**Recommendation:** Accept as Phase A-baseline cost; the recommendation is not to cut D0009 but to acknowledge that the recurring 2-3 hours/month is **uncovered** in §10.1's Phase A absorption framing and should be explicitly named there. Alternative: relax the cadence to quarterly check-ins with 180-day trigger rather than monthly check-ins with 60-day trigger, reducing recurring load by ~75%. The trade is delayed sunset trigger; given §10.4's projected Phase D collapse trajectory, a longer trigger is consistent with the brief's own honesty about how Phase D ends.

---

### F8: Trust-roots health reporting commits to biennial-then-annual public artifact as recurring documentation work

**Commitment:** §9.4 commits to "trust-roots health report — biennial at the v1 self-funded-MVP baseline, transitioning to annual once funding closes." Covers 14+ trust-root categories including GrapheneOS, Pixel forensic developments, cryptographic primitives, Tor, SimpleX/Briar, Sigstore/Sigsum incidents, build supply chain, OIDC provider, reviewer-pool composition, witness-pool independence assessment, foundation jurisdiction.

**Multi-year solo cost:** Each trust-root category requires monitoring and synthesis over the reporting period. §9.4 acknowledges "multi-day-per-cycle production cost." Realistically, biennial production cost is 80-160 hours of solo work (research, drafting, partner consultation, publication); annual cadence doubles this to 160-320 hours **before** any incident-driven interim advisory work.

**Successor-takeover viability:** Medium — the report format is documentable but the synthesis judgment is the developer's accumulated context. The report itself is a successor-readable artifact if produced; but a successor inheriting mid-cycle would need to either restart or accept a gap in the public record.

**Recommendation:** Reduce scope. The 14+ trust-root coverage is comprehensive but is itself a Phase D-class commitment. **Cut to 5-6 highest-criticality trust roots** (GrapheneOS-Pixel, SimpleX, Sigstore, Sigsum, reviewer-pool composition) at biennial cadence permanent (not transitioning to annual). The committed scope can re-expand under Phase C-or-D funded operations; the volunteer-baseline commitment should match volunteer-baseline capacity. Cost: less complete public-trust-root posture visibility; benefit: ~40-100 hours/year recurring documentation work eliminated at Phase D scale.

---

### F9: v1.6 as a distinct release introduces an additional full release-engineering-and-attestation cycle

**Commitment:** §7.1 splits v1.5 and v1.6 with v1.6 covering deferred UX (multi-profile, in-app compelled-unlock flow, duress-wipe, §5.6 UX polish, voice/video, localization). §§6/7-E F9 noted the v1.5/v1.6 split reflects honest engineering scope.

**Multi-year solo cost:** Each release engineering cycle has fixed overhead independent of scope: reviewer pool engagement (F3 above); audit-coordination-window adjustment (if findings outstanding); release-engineering automation per-channel (F6); release notes and CHANGELOG (§8.2); transparency-log entry publication; pilot-or-user notification cycle. Per-release overhead floor: ~80-160 hours regardless of scope. The v1.5/v1.6 split adds one full release cycle to the multi-year roadmap (~80-160 hours one-time-but-recurring-coordination).

**Successor-takeover viability:** Medium for engineering scope; low for relationship state at the cycle boundary.

**Recommendation:** **Collapse v1.6 deferred UX into v1.5 or push to v2** rather than treating it as a distinct release. The argument for the split (§§6/7-E F9) is honest engineering scope; the argument against the split is that release-cycle overhead is fixed per cycle and v1.6 adds it for a scope cut that could be absorbed into the adjacent cycle. The brief should explicitly evaluate the trade — fewer releases at larger scope vs. more releases at smaller scope — against the recurring-coordination load rather than against engineering-scope evenness alone.

---

### F10: §8.4 board composition requires five role categories including compensated executive director

**Commitment:** §8.4 board composition criteria: technical advisor, partner-organization representative, community representative from pilot users, executive director or equivalent operational role (compensated when funded), treasurer or audit-committee chair.

**Multi-year solo cost:** Board recruitment + maintenance is itself a partner-coordination loop the developer drives until foundation incorporation; post-incorporation the board itself becomes the partner-coordination layer but board-meeting cadence (typical 4 meetings/year), executive-director recruitment (compensated), and board-member turnover all compound into Phase D operational scope §10.4 budgets as "foundation overhead" without sizing developer time.

**Recommendation:** Linked to F5 — if foundation incorporation is deferred indefinitely (F5 recommendation), board composition is moot. Otherwise: simplify to 3-member board (technical advisor, partner representative, developer-as-chair) with the executive-director and treasurer roles deferred to scale.

---

### F11: Per-release reviewer toolkit maintenance at LTS-pinned semi-annual cadence is itself a Phase A recurring commitment

**Commitment:** §8.2 commits to Docker/Nix-pinned reviewer toolkit "refreshed semi-annually" at the volunteer baseline, transitioning to per-release at honoraria-funded operations.

**Multi-year solo cost:** Semi-annual toolkit refresh: per-cycle ~12-24 hours of developer time on toolchain-pinning, dependency-update review, reviewer-side compatibility verification. Annual recurring: ~24-48 hours. Per-release transition at Phase C: ~8-16 hours per release at quarterly cadence = ~32-64 hours/year.

**Recommendation:** Accept the semi-annual cadence permanently rather than as volunteer-baseline-temporary. The brief frames per-release toolkit maintenance as the "post-honoraria target" but does not name the developer-time cost; permanent semi-annual cadence is sustainable and the per-release upgrade should be evaluated as a discretionary Phase D improvement rather than a Phase C commitment.

---

## Minor findings

### F12: §5.5 commits to APK Signature Scheme v3 key-rotation flow as recovery path for long-lived APK key compromise

The long-lived APK key compromise is a multi-release recovery process per §5.5. This is a real commitment but is **once-per-incident** rather than recurring. Successor-takeover viability is low for the hardware-token key custody itself (per §5.5 "ideally with multi-party access procedures"). Recommendation: explicitly commit to hardware-token custody with at least one partner co-custodian as Phase A baseline, so successor takeover does not depend on single-developer key custody.

### F13: Multi-target build pipeline cross-compilation surface (§6.4)

§6.4 commits to v1's build pipeline accepting future targets without restructuring. The cross-compilation paths for v2 USB image, v2 iOS bundle, v3 mesh-node firmware are real recurring CI maintenance. §§6/7-E F11 noted this. Multi-year: ~20-40 hours/year CI maintenance per additional target enabled. Recommendation tied to v3 cut (F2): if v3 is cut, mesh-node firmware target is cut; if iOS is deferred to v3+ (F2 alternative), iOS bundle target is deferred.

### F14: Localization coordination as recurring partner-coordination loop (§5.7, §10.4)

§10.4 budgets $5-20K/year for localization and translation honoraria. The developer-time coordination cost (recruitment, security-critical-string review, per-update translation re-review) is uncovered. Multi-year: ~30-60 hours/year per language. Recommendation: defer localization to Phase D-funded only; do not absorb localization coordination at volunteer baseline.

### F15: Pilot-consent + exit protocol partner mediation per D0013 as ongoing partner relationship

D0013 frames pilot consent-and-exit as a Phase B precondition. The mediation relationship itself is **ongoing** through pilot duration (6 months per §6.3) and into v1.5 broader release. Partner-mediation coordination is uncovered in §10 cost framing. Recommendation: explicitly time-bound the pilot-consent-mediation arrangement to pilot duration only, with explicit re-negotiation gate for v1.5 broader release rather than implied continuity.

### F16: Self-funded runway disclosure gap (§10.8)

§10.8 explicitly names that §10 does not deliver the §9.1-committed self-funding runway in calendar terms. This lens identifies that the runway disclosure is precisely the variable Phase D sustainability depends on: §10.4 acknowledges the Phase D horizon "without maintainer compensation is finite, not indefinite." Until the runway is named, partners and funders cannot evaluate the Phase D collapse trajectory. Recommendation (already named in §10.8 but worth emphasizing): close the runway-disclosure gap as a §10 revision before §10's funding-pursuit-posture (§10.9) becomes the project's external-facing position.

---

## Patterns

**P1: One-time scope vs. recurring scope is the structural fault line.** The brief consistently estimates one-time engineering cost (9-12 person-months for v1, 6-9 for v1.5, etc.) but does not aggregate **recurring coordination cost**. The findings above (F1-F11) sum to approximately **400-1,000 hours/year of recurring solo coordination** at Phase D steady state — independent of any engineering work. At a sustainable volunteer-baseline of ~15-20 hours/week the developer can sustain alongside other work, this leaves **0-500 hours/year for engineering**. The brief's Phase D framing as "steady-state operations" assumes engineering capacity that the recurring coordination load consumes. §10.4's "every contributor except the engineer-operator" framing is the funding-side symptom; the architectural-side cause is the recurring-coordination floor.

**P2: D0009 successor-takeover viability assumes static project state, not active operating loops.** Every recurring coordination loop (audit cycle, upstream tracking, reviewer-pool rotation, witness-pool maintenance, partner-advisory-authority renewal, foundation-incorporation work, multi-channel distribution) has **operating state** the developer holds — relationships, in-flight cycles, accumulated context — that D0009's pre-staged successor documentation does not capture. D0009's commitment that "the project state is recoverable by any successor" is true for **architectural state** and false for **operational state**. Successor takeover would not pick up where the developer left off; it would restart most loops from scratch, at substantial loss.

**P3: "Conditional on X funding" appears throughout the brief but does not propagate to the scope side.** When funding does not close, the brief commits to "Phase A continues at volunteer baseline" (§10.7). But Phase A absorption of Phase B/C/D operational scope is precisely what generates the F1-F11 compounding load. The honest framing would be that "Phase A continues at volunteer baseline" means the project sustains a subset of the operational commitments; the brief should explicitly identify which Phase D commitments lapse first when funding stalls (audit cycle? reviewer rotation? trust-roots health report?), so the lapse is structured rather than ad-hoc.

**P4: Cuts that relieve Phase D sustainability are specifically those that remove recurring loops, not those that reduce v1 engineering scope.** The §§6/7-E F3 lens identified solo absorption of specialist roles as a v1 problem; D0004's scope cuts (Briar to v1.5, reproducible builds to v1.5, CRDT dropped, narrow v1 UX) address this. But D0004 cuts **one-time** v1 engineering; the multi-year survival cliff is **recurring** coordination. The cuts that materially change Phase D survivability are F1-F6 recommendations: cut v3 mesh integration; defer iOS to v3+ rather than v2; collapse v1.6 into v1.5; reduce reviewer pool to 3-of-3 or extend rotation to 36 months; participate in third-party Sigsum logs only; defer foundation incorporation indefinitely; reduce distribution channels to F-Droid + Accrescent. These cuts reduce the recurring-coordination floor by an estimated 150-400 hours/year, shifting the Phase D maintainer-comp question from load-bearing to preference.

**P5: The brief is honest about funding-side fragility (§10.7) but applies the same honesty inconsistently to scope-side fragility.** §10.7 names the failure modes funder-side: "developer absorbs Phase D operational scope as uncompensated labor beyond self-funding horizon" as the long-horizon failure mode. The brief does not currently name the architectural choices that produced the scope §10.4 budgets. This lens's contribution is to name them: every recurring loop is an architectural commitment, and the cumulative recurring load is the variable Phase D sustainability hinges on. The brief should pair §10.7's failure-mode honesty with §6/§7's scope honesty — explicitly framing each multi-year commitment as a recurring solo coordination load with named cost, so cuts can be evaluated against the sustainability cliff rather than against ship dates.

---

## Would a 25-50% scope cut change Phase D maintainer-comp aspiration from "load-bearing" to "preference"?

**Yes, if and only if the cuts are recurring-load-targeted (F1-F6) rather than one-time-engineering-targeted (D0004-style).**

A 25-50% cut to v1 engineering scope (additional D0004-style scope cuts) does not change Phase D survivability because Phase D operational load is independent of v1 engineering scope.

A 25-50% cut to **recurring-load commitments** (F1-F6 recommendations: cut v3, defer iOS, collapse v1.6, simplify reviewer pool, third-party-Sigsum-only, defer foundation indefinitely, reduce distribution channels) reduces the recurring-coordination floor from ~400-1,000 hours/year to ~200-600 hours/year. At the lower end, this is within the bandwidth a solo developer can sustain at 15-20 hours/week alongside other employment, **converting the maintainer-comp aspiration from load-bearing-for-survival to preference-for-higher-throughput**.

The §10.4 framing — that Phase D "budgets every contributor except the engineer-operator who runs everything" — is currently load-bearing because the engineer-operator's coordination load is unsustainable without compensation. Cuts F1-F6 change the equation: the engineer-operator runs **less**, and the runs-less scope is sustainable at the volunteer baseline. Phase D maintainer-comp becomes a quality-and-throughput question (faster releases, more comprehensive trust-roots reports, more languages, more channels) rather than a survival question.

This is the architectural argument for the cuts. The product-side cost is real (no v3 internet-shutdown response, slower iOS arrival, fewer distribution channels, less complete trust-roots reporting). Those costs are visible to users and partners. The Phase D collapse cost is currently invisible to users and partners and emerges as silent project decay. The brief's own posture (§10.4 honesty about Phase D's finite horizon) suggests the visible-product-cost path is the more honest trade.
