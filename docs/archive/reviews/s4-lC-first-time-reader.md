# §4 — First-Time Reader Lens

## Summary

§4 reads as a confident, well-integrated commitment to a working v1 product. A first-time reader closing the brief at line 294 would leave with an inflated picture along four dimensions: (1) what ships in v1 vs. v1.5 (Briar tiering, reproducible builds, in-app post-coercion flow, local trust-graph state, multi-profile), (2) what is operationally guaranteed vs. funding-conditional (release cadence, reviewer compensation/independence, audit posture, distribution channels), (3) what the architecture protects vs. what is upstream-dependent (forward secrecy, anonymity, hardware-key extraction), and (4) what project capacity has been demonstrated vs. aspired to (reviewer pool exists, partnerships exist, foundation exists, audits are scheduled).

The pattern is not isolated misstatements — §4's diction is systematically present-tense and unqualified ("Cairn ships," "the trust graph propagates," "external reviewer pool of 5+ with 3-of-5 attestation threshold"), while §6, §8, §9, and §10 use qualified ("intent subject to," "conditional on Q3," "shipping at the volunteer baseline," "if partner-organization availability allows," "deferred to v1.5"). The result is a §4 that promises the v1.5/Phase-C end state and a remainder of the brief that walks that promise back.

## Critical findings

### F1: §4.1 describes Briar as part of the integrated stack without surfacing the v1 deferral with equal weight

- **Evidence:**
  - §4.1 line 248: "v1 ships SimpleX messaging over Tor; v1.5 adds Briar (peer-to-peer over Tor) as the highest-sensitivity tier"
  - §4.1 line 250: "SimpleX is the v1 messaging substrate ... Briar joins as the highest-sensitivity tier in v1.5."
  - §4.3 line 281 ("The protocol layer is delegated; the discipline layer is built"): lists "SimpleX, Briar, Tor, Sigstore, and Sigsum" as the substrates Cairn integrates, with no v1/v1.5 split.
  - §6.1 line 571: "Briar is deferred to v1.5 per D0004; v1 sensitivity tiering is operational (user discipline over what is sent through SimpleX) rather than mechanical (protocol selection)."
  - §5.4 line 448: "In v1, sensitivity tiering is operational rather than mechanical."
  - §9.2 line 875: "v1 and v1.5 require functional internet access — without it, neither SimpleX nor Briar (v1.5) can operate."
- **Impact:** A first-time reader sees Cairn as "SimpleX + Briar + Tor" — a two-tier messaging product with mechanical tier separation. §6 reveals v1 is single-protocol and tiering is operational user discipline. The shipped v1 product is meaningfully less than what §4.1 and §4.3 frame as "the integration."
- **Recommendation:** In §4.1, mark every Briar mention with "(v1.5)" inline rather than only on the first occurrence. In §4.3's first commitment, explicitly state that v1 ships with one of the two protocols and that the two-tier mechanical property arrives in v1.5. The "integration that is the product" claim should be qualified as the v1.5 integration; v1 is the foundation cut.

### F2: §4.3 frames reviewer pool, witness pool, and partnerships as existing facts; §8/§9 reveal all three are conditional on outreach that has not yet happened

- **Evidence:**
  - §4.1 line 255: "external reviewer pool of 5+ with 3-of-5 attestation threshold, multi-channel distribution" — present tense, part of "the release-security stack (Section 5.5)."
  - §4.3 line 287: "external reviewer pool of 5+ with 3-of-5 attestation threshold, Sigsum-anchored attestations, multi-channel distribution — exposes provenance to multiple independent verifiers."
  - §4.3 line 283: "Cairn's trust graph is signed-operation-based with public auditability via Sigsum commitments and witness cosignatures."
  - §8.2 line 736: release cadence "depends on reviewer-pool engagement ... median interval between releases is 4-6 months" at the volunteer baseline.
  - §8.2 line 740: "the reviewer pool operates on a volunteer-attestation basis" at v1; honoraria are conditional on Q3 funding.
  - §8.6 line 827: "they are not confirmed partnership arrangements. Q5 (NGO partner outreach) tracks the conversations that will turn these intentions into agreements."
  - §8.6 line 831: reviewer recruitment is from candidate sources "contingent on each organization's institutional process for cross-project review participation, which Cairn does not presume."
  - §9.1 line 867: "Reviewer and witness pools may not form or may erode."
- **Impact:** §4 reads as if the multi-party verification machinery is operational. §8/§9 reveal the pools do not yet exist as identified individuals, recruitment depends on conversations not yet held, and the 3-of-5 threshold is an architectural target that may translate into 4-6 month median release intervals when the pool engages at volunteer baseline. A funder reading §4.3 alone may believe the release-security claim is currently verifiable; it is currently a commitment to a recruitment process.
- **Recommendation:** §4.3 should state "Cairn's release stack — Sigstore identity-based signing ... a reviewer pool the project commits to recruiting at 5+ with a 3-of-5 attestation threshold ..." — explicitly grammatically marking the pool as future. Similarly for partner-cosigned witnesses.

### F3: §4.2 frames distribution as honoring the "minimal project-operated infrastructure" principle while §6.1 / §10 reveal v1 ships with the project running supply-chain trust concentration

- **Evidence:**
  - §4.2 line 263: "v1 distribution covers F-Droid, Accrescent, and GitHub releases; the Tor onion service and offline signed-image channels are deferred to v1.5/v2 when funded operations capacity exists to run them sustainably."
  - §4.2 line 263: "the project does not claim to have eliminated its own role from the user's trust placement, only to have constrained that role to specific, named, audit-friendly surfaces."
  - §6.3 line 630: "The project provides devices for pilot users: GrapheneOS-installed Pixel hardware with the Cairn application pre-installed and the identity not yet provisioned ... The device-preparation workflow concentrates trust in the developer per the Distribution and supply-chain surface in Section 3.3."
  - §5.5 line 496: "The pilot's device-preparation workflow — the developer installing GrapheneOS and the application before handing over the device — remains a trust placement separate from the release-security stack, narrowed but not eliminated by these mechanisms."
  - §9.3 line 921: "In-person facilitator (v1 pilot model). The facilitator concentrates trust during provisioning."
  - §10.1 line 1042 (later revision): "The bulk of pilot deployment is BYOD: pilot users source their own GrapheneOS-capable Pixel devices."
- **Impact:** §4.2's principle reads as substantially honored ("minimal" with deferrals named). What §6.3 reveals is that v1 pilot operates with the developer in three concentrated trust roles simultaneously: image preparer, application installer, and provisioning facilitator. The §4.2 framing ("audit-friendly surfaces") understates the v1 pilot's actual trust concentration. The recent §10.1 BYOD reframing partially addresses this but §4 has not been updated to match.
- **Recommendation:** §4.2's "minimal project-operated infrastructure" paragraph should add a sentence acknowledging that v1 pilot operations specifically concentrate trust in the developer-as-facilitator for the duration of the pilot, with the principle's full posture taking effect post-pilot when partner-facilitated provisioning lands.

### F4: §4.2 "bounded compromise" framing implies the tier model defends compelled-unlock scenarios that §5.1/§9.3 explicitly do not

- **Evidence:**
  - §4.2 line 269: "Bounded compromise through tier separation. No single credential gives an adversary access to everything ... Compromise at one tier bounds rather than collapses the user's cryptographic position. The honest framing is 'bounded-window exposure, not zero exposure' — specific about what the design protects, specific about what it does not."
  - §5.1 line 305: "the seed exists in active memory during provisioning and recovery, and any forensic implant resident on the device at those moments can capture it."
  - §5.1 line 311: "Rotation under coercion is itself a vulnerable moment ... the master is reconstructed in active memory on the device under coercion."
  - §5.1 line 313: "Evil-maid scenarios are not defended by the tier model."
  - §9.3 line 939: "Endpoint surface (zero-click spyware on running device) ... the operational identity, on-device message history, and contact list are exposed under successful zero-click compromise."
- **Impact:** §4.2's "bounded-window exposure, not zero exposure" framing gestures at the limit honestly. But it does not name that the master is exposed during recovery and rotation (the operations the bounded-compromise model relies on), nor that evil-maid is undefended, nor that endpoint compromise yields the full operational + history + contact + recovery-peer surface. A reader leaves §4 believing the tier model is the architectural answer to seizure; §5.1 reveals it is the answer to one specific class of seizure (no implant present at provisioning/recovery, no evil-maid, no zero-click).
- **Recommendation:** §4.2's bounded-compromise paragraph should add one sentence naming that the model defends "the master across routine device operation; compromise during the reconstruction window (provisioning, recovery, rotation) and compromise of a device with a resident implant are addressed in §5.1 as residual surfaces."

### F5: §4.3 "Release security is multi-party and publicly verifiable" implies an operational practice §8.5 reveals as audit-funding-conditional

- **Evidence:**
  - §4.3 line 287: "Cairn's release stack — Sigstore identity-based per-release signing on top of the long-lived APK key, an external reviewer pool of 5+ with 3-of-5 attestation threshold, Sigsum-anchored attestations, multi-channel distribution — exposes provenance to multiple independent verifiers. The user does not have to trust the developer's word that a release is genuine; the user (or anyone) can check the public record."
  - §6.1 line 579: "in v1 reviewers review source rather than verify binary equivalence (reproducible builds are v1.5 work)."
  - §8.5 line 808-813: Pre-pilot cryptographic-primitives audit ($15-30K subsidized) and pre-beta full audit ($60-150K subsidized) are both gated on subsidy programs closing.
  - §9.3 line 960: "Pilot users (10-15 users at the threat tier Section 3 describes) receive a Cairn implementation whose cryptographic core has been externally reviewed only at the limited pre-pilot audit scope."
  - §10.2 line 1077: "If Phase B funding does not close, Phase A continues. The project does not deploy a pilot without the pre-pilot audit, per D0011's no-skip-the-audit posture. The honest consequence is pilot deferral, not pilot-without-audit."
- **Impact:** §4.3 frames release security as a working multi-party check. A first-time reader does not learn that (a) v1 reviewers verify source rather than binary equivalence — meaning a compromised build pipeline goes undetected per §5.5 line 496; (b) the cryptographic primitives that generate the signed artifacts have not been externally audited and that audit is funding-gated; (c) pilot deployment itself is contingent on the Phase B audit closing; (d) reviewer attestation cadence at volunteer baseline is 4-6 months, not the implied per-release pattern.
- **Recommendation:** §4.3's release-security paragraph should add the v1 source-vs-binary qualification and reference the §8.5 audit-funding gate as a precondition for pilot release. The "the user can check the public record" claim is true post-pilot; pre-pilot the record is the developer's own.

## Significant findings

### F6: §4.2 "release-security stack ... partner-cosigned witness set ... remain project-coordinated, with their consequences acknowledged in Section 3.4 trust roots rather than denied" implies witness-pool independence that §3.4/§5.2/§5.5 acknowledge is currently shared

- **Evidence:**
  - §4.2 line 263: "The release-security stack, partner-cosigned witness set, and a subset of distribution channels remain project-coordinated, with their consequences acknowledged in Section 3.4 trust roots rather than denied."
  - §5.5 line 490: "The shared witness pool is acknowledged as a correlation risk in Section 3.4: compromise of enough witnesses to break log integrity defeats both the trust-graph audit and the release-binary audit at once. The project accepts this correlation in v1 (operational cost of two independent witness pools is high at current scale) and revisits the separation in v1.5 or later."
  - §9.3 line 914: "Sigsum witness pool. Compromise of the witness pool, or systemic cosignature collusion, defeats the log-state integrity check that supports both the trust-graph audit (Section 5.2) and the release-binary audit (Section 5.5)."
- **Impact:** §4.2's "consequences acknowledged" gestures at honesty but does not name the specific consequence: in v1, the same partner-cosigned witness set guards both the release-security log and the trust-graph audit log. A single witness-pool compromise defeats both surfaces simultaneously. A first-time reader hears "two independent surfaces"; §5.5/§9.3 reveal one shared pool.
- **Recommendation:** §4.2 should name the shared-witness-pool concentration as the specific consequence accepted in v1 — one of the named, audit-friendly surfaces, not a residual cost hidden under the generic acknowledgment.

### F7: §4.3 "Recovery is social without being centralized" omits that v1 recovery requires online connectivity to Sigsum

- **Evidence:**
  - §4.3 line 285: "Shamir-among-peers is the architectural answer to the user populations Cairn targets ... The peer-verification mechanism (D0005) defeats the attack chain that compelled unlock would otherwise open: unlock → peer enumeration → impersonation."
  - §9.2 line 883: "Recovery requires online connectivity to Sigsum in v1. The v1 trust-graph evaluation queries Sigsum directly (per D0004); a user offline at the moment of recovery cannot evaluate new attestations they have not yet seen. v1.5 adds local caching that mitigates the most common case but does not address full-offline recovery."
- **Impact:** §4.3's recovery framing implies a peer-only operation. §9.2 reveals v1 recovery additionally requires Sigsum connectivity and that this is a v1-specific limitation that v1.5 partially addresses. For the audiences §2.2 names (organizers in jurisdictions with active internet disruption), this is a meaningful gap §4.3 does not surface.
- **Recommendation:** §4.3's recovery paragraph should add that v1 recovery requires online Sigsum access in addition to peer reach, with v1.5 adding offline-tolerant caching.

### F8: §4.2 "Forward secrecy where the protocol permits, named where it doesn't" understates the at-rest reality

- **Evidence:**
  - §4.2 line 271: "On-wire message content is forward-secret via SimpleX's double-ratchet derivative (and Briar's BTP/BSP in v1.5). At-rest message history on the device remains decryptable under unlock; the distinction is named in Section 3.5 and Section 5.4 rather than papered over."
  - §5.4 line 438: "The on-device message store, however, is decryptable under unlock regardless of ratchet state; forward secrecy is a wire-level property, not an at-rest property."
  - §9.3 line 939 (endpoint surface): "the operational identity, on-device message history, and contact list are exposed under successful zero-click compromise."
- **Impact:** §4.2 does name the at-rest limit explicitly, which is better than most. However, the placement is mid-sentence after a longer forward-secrecy claim, and a first-time reader will likely take the headline ("Forward secrecy ... named where it doesn't") at face value. The §5.4/§9.3 combined picture is that successful unlock — whether by coercion, by zero-click, or by evil-maid implant — yields the full conversation history. This is the largest single operational property the v1 product is exposed on, and §4.2's framing gives it half a clause.
- **Recommendation:** Promote the at-rest limit to its own sentence or a dedicated bullet. The clarity of the limit is the calibration §4.2 claims to value.

### F9: §4.3 "no single signing identity" frames the v1 release as multi-party while v1 ships with a long-lived APK key held by the developer alone

- **Evidence:**
  - §4.3 line 287: "Most consumer messaging tools rely on a single signing identity (the developer's private key) whose compromise affects every release indefinitely. Cairn's release stack ... exposes provenance to multiple independent verifiers."
  - §5.5 line 480: "The project must therefore hold a long-lived Android signing identity for APK signature continuity ... That key is protected as carefully as the threat model demands — held in a hardware security token, with rotation supported via APK Signature Scheme v3 key rotation if a future compromise requires it."
  - §5.5 line 498: "Long-lived APK key compromise (the harder scenario): the response uses APK Signature Scheme v3 key rotation. All installed clients must process the rotation in an update before subsequent updates can be signed by the new key. This is a multi-release recovery process."
  - §9.3 line 911: "A compromise of this key, held in a hardware security token by the developer, lets the adversary sign releases the client cannot distinguish from legitimate."
- **Impact:** §4.3 contrasts Cairn with "tools rely on a single signing identity ... whose compromise affects every release indefinitely." The §5.5 reality is that Cairn does have a long-lived signing identity (the APK key) whose compromise has indefinite effect modulo a heavyweight rotation procedure. Sigstore is layered on top, but the APK key remains the structural reality Android imposes. §4.3's contrast oversells the difference from the comparison set.
- **Recommendation:** §4.3 should acknowledge the APK-signing-key reality and frame the multi-party property as additional verification atop the platform-required signing layer, not as elimination of the single-signing-identity surface.

### F10: §4.2 "calibrated language replaces absolute-sounding claims" — §4 itself uses present-tense unqualified language for funding-conditional commitments

- **Evidence:**
  - §4.2 line 273: "Calibrated language replaces absolute-sounding claims ('verified through chain of attestations' rather than 'secure')."
  - §4.1 line 246: "The product is structured as three layers" — present tense, implies shipping product.
  - §4.1 line 257: "The layers compose into a product whose security properties are visible at the architectural level: the user's master identity is never on the device in routine operation; the operational identity is hardware-gated and rotatable; messaging metadata is minimized at the protocol layer; release integrity is verified at the user's client."
  - §6.1 line 567: "v1 is not the architectural endpoint; it is the smallest cut of the architecture that delivers a defensible product to the v1 audience."
  - §10.1 line 1024: "The work proceeds as the developer's time allows; the brief does not commit to a calendar schedule for Phase A completion."
- **Impact:** §4 applies its own UX principle inconsistently. The §4.2 paragraph endorses calibration for user-facing language; §4 itself uses uncalibrated present-tense framing for an architecture that is, at brief-publication, designed and partially implemented but unaudited, unfunded, and not yet shipped. A first-time reader will not parse "is structured as three layers" as "is designed to be structured" — they will parse it as "ships as." The brief's own principle would have §4 use "the v1 design specifies" rather than "the product is."
- **Recommendation:** Audit §4 for present-tense unqualified verbs and convert each to "the v1 design specifies," "the architecture commits to," or "v1 ships," matching the qualification each claim actually carries. The §4.2 calibration principle should be visibly honored in the surrounding text.

## Minor findings

### F11: §4.1 hardware-key location qualification is correct but easy to miss

- **Evidence:** §4.1 line 246: "in the device's StrongBox-backed hardware element where Ed25519 is supported on the target Pixel generation, TEE-backed otherwise." §5.1 line 307 carries the same qualification.
- **Impact:** A first-time reader will likely read this as "StrongBox" and miss the TEE fallback. The "TEE-backed otherwise" condition is a meaningful security-tier reduction (TEE compromises have a different research literature than StrongBox compromises).
- **Recommendation:** Either inline a single phrase ("with a TEE fallback where StrongBox does not support Ed25519, a reduction acknowledged in §5.1") or simplify §4.1 to "hardware-backed keystore" and leave the StrongBox/TEE distinction to §5.1.

### F12: §4.3 "no current product in the landscape makes together" — verifiable only against §2.3, not §4

- **Evidence:** §4.3 line 279 claims four commitments "no current product in the landscape makes together"; references §2.3 (landscape) and §5.4 (protocols).
- **Impact:** A first-time reader cannot evaluate this claim from §4 alone and must trust the §2.3 survey. This is structurally fine but worth naming as a load-bearing dependency on a section the reader may not have read.
- **Recommendation:** Cross-reference §2.3 by section title at line 279, not just by number, so the reader knows what they are deferring to.

### F13: §4.1 "Pluggable-transport selection is an ongoing engineering commitment" reads as project capacity §10 reveals as conditional

- **Evidence:** §4.1 line 248: "Pluggable-transport selection is an ongoing engineering commitment rather than a one-time decision — DPI evasion is a continuously-being-solved problem (Section 5.4)."
- §5.4 line 454: "users in DPI jurisdictions are offline when an active transport is blocked, until an updated transport propagates through reviewer attestation and installation."
- §8.2 line 736: release cadence at volunteer baseline is "median interval between releases is 4-6 months."
- **Impact:** §4.1 implies active transport-update capability. §5.4 + §8.2 combined reveals transport updates ship at the volunteer-baseline release cadence — a user blocked between releases is offline for the median 4-6 month interval. The "ongoing engineering commitment" framing reads as capacity that does not exist at volunteer baseline.
- **Recommendation:** §4.1 should add that transport updates ship at the §8.2 cadence — the architectural slot is preserved, the operational responsiveness is funding-gated.

## Patterns

Three patterns characterize §4's expectation gaps:

1. **Present-tense framing of design-stage architecture.** §4 describes the design as if it ships. §6, §8, §9, §10 reveal what ships in v1 vs. v1.5 vs. v2, what is funded vs. aspirational, and what is committed vs. conditional. The diction does most of the misleading; converting present-tense unqualified verbs to v1-specific framing would close most of the gap without changing substance.

2. **Multi-party properties stated as operational while pools/partnerships are unrecruited.** The reviewer pool, witness pool, partner organizations, and audit firms are all framed in §4 as operational architecture components. §8.6 line 827 is explicit that these are intentions pending Q5 outreach. §4 does not signal this conditionality.

3. **Architectural claims that conflate v1 with v1.5/v2.** Briar tiering, reproducible builds, in-app post-coercion flow, multi-profile, local caching, and offline trust evaluation are all described as part of the integration's structural properties in §4 but are explicitly v1.5+ in §6.2. A first-time reader cannot tell which architectural commitments are v1 commitments and which are roadmap.

The remediation is consistent across all three: §4 needs explicit v1 vs. design-stage scoping, with "v1 ships," "v1.5 adds," and "the project commits to recruiting" replacing the present-tense "Cairn does."
