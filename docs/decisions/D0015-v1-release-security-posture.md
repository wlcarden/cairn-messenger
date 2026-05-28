# D0015 — v1 release-security posture: developer-signed + public log + multi-channel distribution; recruited reviewer pool deferred to v1.5

**Status:** Accepted
**Date:** 2026-05-28

## Context

The architecture-simplification adversarial review (5 lenses) surfaced F4 as the single highest-leverage simplification this review identified: defer the recruited 5+/3-of-5 reviewer pool from v1 critical path to v1.5. Two lenses (comparable-products and multi-year-solo-feasibility) pushed hard for deferral; one lens (component-necessity) softened to a 3+/2-of-3 v1 alternative; one lens (YAGNI) supported partial cuts; one lens (operational maintenance cost) recommended deferring the rotation cadence and the audit-cycle pressure around the pool but stopped short of full v1 deferral.

The structural arguments for deferral are:

- **Comparable-products precedent.** Briar — §2.3's closest threat-tier comparator — ships through F-Droid's rebuild/resign pipeline without recruiting a parallel reviewer pool, serving an audience substantially overlapping Cairn's. Signal Android publishes reproducible builds with the F-Droid rebuild posture. GrapheneOS uses a multi-signer release process at the OS layer; for the application layer, F-Droid + reproducible builds is the path comparable products take. The recruited pool's marginal property at v1 (jurisdictional diversity at source-review attestation prior to reproducible builds landing) is narrower than §4.3's framing implies.
- **v1 source-review vs v1.5 binary-equivalence honesty.** v1 reviewers attest _source_, not binaries. §5.5:496 already names the v1 supply-chain gap: a compromised build pipeline producing a malicious binary from clean source would not be detected by source-review alone. F-Droid's rebuild pipeline at v1.5 (when reproducible builds land per D0004) closes this gap. The recruited pool at v1 catches a smaller class of compromises than the v1.5 rebuild pipeline will. Source review at v1 is operationally useful but architecturally incomplete; the recruited pool's strongest value lands at v1.5 alongside reproducible builds, not at v1 alone.
- **Pilot scale.** v1 pilot is 10–15 users in one or two local groups already known to the developer (§6.3). The multi-party verification's primary security value lands at broader-than-pilot release where the recruited pool defends against developer compromise across a larger user base; at pilot scale with developer-as-facilitator, the developer-supply-chain trust placement §3.3 names is already concentrated in one person regardless of the release-security stack's distribution.
- **Recurring partner-coordination load.** Reviewer-pool coordination is a continuous partner-coordination loop. Per-release: 8–20 hours (3-of-5 attestation collection, Sigsum entry). 18-month rotation per §8.2: at least one reviewer transition per 3–4 months on average. Compounded annual recurring coordination: ~80–200 hrs/year at steady state. Q3 (honoraria funding) and Q5 (NGO partner outreach) gates make recruitment dependent on outcomes outside the project's unilateral control. The §10.4 Phase D sustainability cliff arithmetic absorbs this load if it stays.
- **Volunteer-to-honoraria-to-volunteer trajectory honesty.** Per §8.2, if Q3 honoraria funding does not close before pilot launch, the pool degrades to volunteer-attestation regardless of the architectural commitment. v1 may operationally ship with whatever pool forms at the volunteer baseline rather than the committed 5+ pool. The deferral aligns the commitment with the operational reality.

The structural arguments against deferral are:

- **§4.3 differentiation.** The recruited pool is one of four architectural commitments §4.3 names as the integration's differentiator. Deferring it reframes the four-commitment integration as three commitments plus the standard open-source-security-tool release-security posture. The "substitutes a distributed trust set for the developer's single signing identity" framing loses force at v1.
- **v1 audience.** Pilot users are at the §3 threat tier. They specifically benefit from multi-party verification of source; concentrating release attestation in the developer at v1 leaves the developer's single-signing-identity surface uncovered until v1.5.
- **Recruitment risk.** Deferring "until v1.5 funding closes" is operationally indistinguishable from deferring indefinitely if Phase C does not close. The recruited pool may never form if the deferral is treated as discretionary rather than committed.

## Decision

**Defer the recruited 5+/3-of-5 reviewer pool from v1 critical path to v1.5.** v1 ships with developer-signed releases plus public log audit plus multi-channel distribution. v1.5 adds the recruited pool alongside reproducible builds + F-Droid rebuild integration, with the combination forming the binary-equivalence multi-party verification pattern.

### v1 release-security stack (post-decision)

- **Developer-held long-lived APK signing key.** Residual single-credential surface per §5.5; rotation via APK Signature Scheme v3 if a future compromise requires.
- **Per-release Sigstore identity-based signing** on top of the APK key. OIDC provider is a retained trust placement (U.S.-based in v1 per §5.5, §3.4; Q11/Q24), not a removed one.
- **Rekor transparency log entries** for all release signatures (Sigstore's standard).
- **Sigsum-anchored release log.** Witness cosignatures via the same witness pool that anchors the trust graph; witness-pool recruitment conditional on Q5 (NGO partner outreach) per §8.6 — _the witness pool is preserved as a v1 commitment_ even as the recruited reviewer pool defers.
- **Multi-channel distribution.** F-Droid (primary; community rebuild/resign provides independent attestation precedent at v1.5 onward), Accrescent, project-controlled direct download from a project domain. The F-Droid presence is the v1 substrate that v1.5's reproducible-builds-plus-rebuild attestation activates against.

### v1.5 expansion (the deferral target)

- **Reproducible Android builds** (per D0004); F-Droid rebuild verification activates as the binary-equivalence attestation pattern.
- **Recruited 5+/3-of-5 reviewer pool.** Recruitment work proceeds through Q5 outreach in parallel with v1 engineering; the recruited pool's v1.5 ship target is the 5+ pool with 3-of-5 threshold. If Q5 outreach produces willing reviewers earlier than v1.5 ships, v1 may "soft-ship" with whatever pool forms — but v1 ship is not gated on pool formation.
- **Optional intermediate posture at v1.5.** If Phase C honoraria funding closes only at the lower bound, v1.5 may ship with a smaller pool (3+ recruited at lower bound; 5+ as the architectural target across subsequent releases). The v1.5 commitment is the architectural property, not a specific minimum count at first v1.5 release.

### What Cairn's v1 release-security posture is and is not

- **Distinct from Signal Foundation's posture.** Signal Foundation operates one signing identity; Cairn pairs developer signing with public log audit (Rekor + Sigsum) and multi-channel rebuild attestation from day one (F-Droid is the v1 substrate; the rebuild attestation lands at v1.5).
- **Not distinct from GrapheneOS's posture** at the OS layer (Cairn rides on GrapheneOS, which already implements multi-signer release for the platform).
- **Not distinct from Briar's posture** at the application layer in v1 (developer-signed APK + F-Droid distribution + reproducible builds upcoming = Briar's pattern).
- **Becomes distinct from Briar in v1.5** with the recruited pool addition combined with reproducible-builds-plus-rebuild attestation.

Cairn's v1 distinction lives in the integration plus the three remaining architectural commitments (identity tiers, trust graph, social recovery), not in the release-security stack. The brief frames this honestly per §4.3 update.

## Alternatives considered

**Option B — Soften to 3+/2-of-3 at v1, tighten to 5+/3-of-5 at v1.5.** _(Considered, rejected.)_ Preserves the differentiation framing but introduces a softer pool size that the brief must explain ("v1 ships smaller pool; v1.5 tightens"). Recruitment risk at v1 remains. The volunteer-to-honoraria trajectory still applies. The simplification value is partial (recruitment-coordination load reduces but does not disappear); the operational benefit (no v1 recruitment gate) is not realized. The intermediate posture does not eliminate the §10.4 Phase D sustainability cliff that drives the simplification case.

**Option C — Keep current 5+/3-of-5 as v1 critical path.** _(Considered, rejected.)_ Carries the recruitment risk §9.1 names: "Reviewer and witness pools may not form or may erode." v1 ship becomes operationally dependent on Q5 outreach producing recruited reviewers (which itself depends on Q3 honoraria funding through §8.2's volunteer-to-honoraria transition). The risk of v1 ship being indefinitely deferred on a Q5/Q3 contingency is real. If pool fails to form, the brief reverts to volunteer-attestation per §8.2 — so v1 may operationally be a smaller pool regardless. Maintaining the commitment without operational alignment is the kind of register failure the §§8/9 review F-finding cluster identified.

**Defer indefinitely.** _(Considered, rejected.)_ The deferral commits to v1.5 as the recruited-pool ship target with recruitment work continuing through Q5 outreach in parallel. Indefinite deferral risks the pool never forming. The "v1.5 critical path" framing is the meaningful commitment.

## Consequences

### Brief sections affected

- **§1 Executive Summary.** §1.3 architectural commitments reframes: the fourth commitment (release security as distributed trust substitution) revises to acknowledge v1's developer-signed + public log + multi-channel posture as the v1 commitment, with the recruited pool deferring to v1.5. §1.5 operational posture: reviewer-pool recruitment moves from v1-ship-gate to v1.5 commitment. §1.7 reader navigation: technical reviewers evaluating release-security architecture pointed at §5.5's v1 stack rather than at §8.2's recruited-pool operations.
- **§3.4 Trust roots.** Reviewer pool removed from v1 trust roots; F-Droid surfaces more prominently as the v1 application-layer rebuild attestation pattern.
- **§4.3 Differentiation.** The four-commitment framing reframes to three architectural commitments (identity tiers, trust graph, social recovery) + a release-security posture honestly described as distinct from Signal Foundation's but not distinct from GrapheneOS or Briar at v1; the v1.5 expansion is named.
- **§5.5 Updates and Release Security.** Rewritten to reflect v1's developer-signed + Sigstore + Rekor + Sigsum log + F-Droid multi-channel posture. The recruited pool moves to v1.5 alongside reproducible builds; ship-quorum framing removes from v1 release shipping.
- **§6.1 v1 scope.** Release-security paragraph rewritten; "first-quorum reviewer attestation forming" removed from v1 ship-conditions. v1 ship-gate becomes engineering scope + pre-pilot audit + partner-mediated consent protocol.
- **§6.2 v1.5 deferral list.** Adds recruited reviewer pool with 5+/3-of-5 architectural target.
- **§7.1 Release sequence.** v1 ship-conditions updated; v1.5 ship-conditions now reflect reviewer-pool commitment as v1.5 architectural target with the soft-ship caveat if Phase C honoraria funding closes only at lower bound.
- **§8.2 Release security operational policy.** v1 cadence framing decouples from quorum formation. Recruited pool becomes v1.5 commitment with Q5 outreach proceeding in parallel; volunteer-to-honoraria transition trajectory is preserved at v1.5 onward.
- **§8.5 Audit and assurance.** Pre-pilot audit scope narrows (release-security stack removes from v1 audit scope per D0011 update; lands in the pre-beta audit at v1.5 when the recruited pool joins).
- **§8.6 Partnership approach.** Technical-reviewer role for release attestation moves from v1 to v1.5; Q5 outreach focuses on facilitator, witness, threat intel, localization at v1.
- **§9.1 Project risks.** "Reviewer pool may not form" risk softens at v1 (no v1 ship-gate); persists as v1.5 risk. The "pilot deferral if pool fails to form" failure mode removes from v1 risk register.
- **§10.3 Phase C.** Reviewer-honoraria operating model removes as Phase C unlock condition for v1.5 broader-than-pilot release; remains as Phase C aspiration if pool recruitment produces willing reviewers in v1.5 timeframe.
- **§10.4 Phase D.** Recurring-coordination floor drops materially. Maintainer-comp aspiration moves closer to "preference" per the simplification review's materiality assessment.
- **§10.7 Funding risks.** "Reviewer honoraria cannot be funded indefinitely" failure mode revises: at v1, no operational ceiling on volunteer baseline because the v1 ship is not pool-gated; at v1.5+, the recruited pool either forms with honoraria support or operates at the volunteer baseline per §8.2's transition trajectory.

### Decision documents affected

- **D0004 (v1 scope cuts).** Adds reviewer-pool deferral to v1.5 commitments list; minor revision.
- **D0008 (volunteer-baseline cadence).** Cadence framing decouples from quorum formation at v1; the median-4-to-6-month interval still applies but for a different operational reason (developer release engineering plus self-audit cadence). Minor revision.
- **D0011 (audit budget and timing).** Pre-pilot audit scope narrows: release-security stack removes from v1 pre-pilot audit. The pre-beta audit at v1.5 expands scope to include the recruited reviewer-pool operational verification when the pool ships. Moderate revision.

### Open questions affected

- **Q3 (funding strategy).** Reviewer-honoraria removes from Phase C unlock conditions for v1.5 broader-release; Phase C now funds audit + foundation incorporation + (optionally) UX engineer + (optionally) recruited pool honoraria if pool forms in v1.5 timeframe. Q3 framing tightens.
- **Q5 (NGO partner outreach).** Reviewer recruitment removes from v1 outreach scope; v1 Q5 focuses on facilitator, witness pool, threat intel, localization. Reviewer recruitment becomes v1.5 outreach scope.
- **Q10 (witness pool and reviewer pool composition).** Reviewer pool partially resolved as v1.5 commitment; witness pool remains as v1 commitment per the §5.5 release log and §5.2 trust graph audit substrate. Q10 framing splits the two pools by version.
- **Q13 (volunteer-baseline operational ceiling).** Reduced recurring-coordination floor materially affects the ceiling analysis; Q13 framing tightens.

### What the brief does not commit to

- A specific v1.5 reviewer pool size if Phase C honoraria funding closes only at the lower bound. v1.5 ships with the architectural property (recruited pool with 3-of-5 threshold) and a target of 5+; the operational first-v1.5-release pool count may be smaller.
- A specific timeline for the v1.5 reviewer pool to reach the 5+ architectural target.
- That v1.5 ship is hard-gated on 5+ pool formation; v1.5 may ship with the pool that has formed at v1.5-engineering-complete time.

### Reversibility

The deferral is reversible at any time Q5 outreach produces willing reviewers in time for v1 ship. The v1 release-security stack supports adding pool attestations as additional Sigsum log entries without protocol changes. The architectural commitment at v1.5 is the cleanest framing if v1 ship lands without a recruited pool; if v1 ship lands with a partial pool, the pool grows from there into the v1.5 target.

If subsequent evidence (pilot feedback, partner-organization conversations during Q5 outreach, audit findings) indicates v1 source-review by a recruited pool is operationally needed before v1.5 ships, the decision is reversible at low cost — the engineering work to integrate pool attestations is the same regardless of the version it ships in.

## References

- [docs/architecture-simplification-review.md](../architecture-simplification-review.md) — F4 (the single highest-leverage cut surfaced).
- [docs/decisions/D0004-v1-scope-cuts.md](D0004-v1-scope-cuts.md) — v1 scope cuts this decision extends.
- [docs/decisions/D0008-volunteer-baseline-cadence.md](D0008-volunteer-baseline-cadence.md) — cadence decoupling from quorum formation.
- [docs/decisions/D0011-audit-budget-and-timing.md](D0011-audit-budget-and-timing.md) — audit scope revision following this decision.
- F-Droid distribution and rebuild pipeline: https://f-droid.org
- Briar release process and reproducible builds: https://code.briarproject.org/briar/briar-reproducer
- GrapheneOS multi-signer release process: https://grapheneos.org/build
- Sigstore identity-based signing: https://www.sigstore.dev
- Sigsum minimal transparency log: https://www.sigsum.org
