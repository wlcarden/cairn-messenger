# Section 5 Adversarial Review — Consolidated Findings

**Date:** 2026-05-27
**Source:** Five parallel sub-agent reviews, distinct lenses (cryptographic correctness, operational reality, threat-model consistency, engineering feasibility, red team).
**Raw findings:** ~88 across reviewers. After deduplication and theming: 32 consolidated findings below.
**Companion to:** [design-brief.md](design-brief.md) Section 5.

---

## Patterns

Six patterns emerge that span multiple reviewers and matter more than any single finding:

**P1. The compelled-unlock answer is weaker than the brief claims.** Four reviewers (cryptography, operational, threat-model, red team) independently identified that the architectural argument "the master is not on the device" survives compelled unlock only if (a) the reconstruction window during recovery is defended, and (b) recovery peers refuse share-release under impersonation. Neither is specified at mechanism level. The recovery-peer verification — load-bearing across D0002, 5.1, 5.3, and 5.6 — is currently "peers are expected to verify out of band," with no enforcement protocol. The reconstruction window is acknowledged in 5.3 but framed as "erased from active memory" without specifying memory hygiene.

**P2. "No project-operated infrastructure" is materially false on close reading.** The 4.2 principle is cited as anchoring 5.2's propagation design, but the brief depends on a reviewer pool, Sigsum witness set, Tor onion service for distribution, UnifiedPush distributor recommendation, Sigstore OIDC provider, and per-jurisdiction profile feed — each project-coordinated. The principle should be retitled "minimal project-operated infrastructure" and the dependencies acknowledged.

**P3. Engineering scope materially exceeds the 9-12 month solo-developer timeline.** The engineering reviewer's bottom line: "this is an 18-30 month project for one developer, not 9-12." The largest specific underestimates: SimpleX embedding (no Kotlin SDK; Haskell-on-Android pipeline), Briar identity-binding fork (Briar's library doesn't accept external identity), the custom CRDT (no off-the-shelf library fits the construction), reproducible Android builds (achievable but 4-8 weeks of toolchain wrangling plus ongoing maintenance), Sigsum client tooling (alpha-state, no Kotlin client), and UX implementation (30-50% of total v1 effort). The brief presents each as integration; in reality each is original engineering.

**P4. Section 5 introduces new attack surfaces and trust roots that Section 3 does not enumerate.** Trust-graph propagation via the messaging layer (5.2) creates a metadata side channel a SimpleX server can fingerprint. Sigsum's public log of attestations is itself a public social-graph reconstruction surface. The in-person facilitator (5.3, 5.6) is a high-value trust placement not in 3.4. The reviewer pool (5.5) is structurally a trust root. The shared Sigsum witness pool concentrates risk across two security functions. The OIDC provider for Sigstore signing is an unnamed trust root with its own jurisdiction.

**P5. UX claims assume user capabilities Section 3.1 explicitly disclaims.** Several Section 5.6 mechanisms (subtle trust badges, cascade-quarantine triage, extra-private mode tooltip-based decisions, calibrated security labels) rely on users engaging with information the 3.1 audience note says they typically do not. The v1 pilot's facilitator presence covers most of this; the brief commits to extending beyond facilitator-present onboarding without specifying how.

**P6. Cryptographic envelope and protocol versioning are incomplete.** The eight-field operation schema does not bind the operational key to its master attestation (the certification chain is not in the signed payload), does not carry an algorithm identifier (no PQ-migration affordance), does not specify revocation time semantics, and does not specify the strength-composition function for trust-path computation. These are application-layer cryptographic specifications that need to be made before implementation begins, not after.

---

## Severity Distribution

- **Critical:** F1–F11 (11 findings). Architectural claims that are false or imprecise, mechanism specifications that are load-bearing but absent, and engineering commitments that cannot be met in the stated timeline without scope cuts.
- **Significant:** F12–F25 (14 findings). Unstated assumptions, new surfaces and trust roots, mechanisms that work but aren't specified, and engineering details that materially affect the project shape.
- **Minor:** F26–F32 (7 findings). Prose tightening, missing acknowledgments, clarifications that improve precision without changing substance.

---

# Critical Findings

## F1. Recovery-peer verification is the load-bearing element of the compelled-unlock answer and is unspecified

**Category:** Mechanism spec / Architectural claim
**Location:** Section 5.3 ("Recovery flow"), D0002, Section 5.6 ("Compelled-unlock guidance")
**Reviewers:** Op #1, Red Team #5/6, Threat-Model #11

**Issue.** The recovery flow specifies that peers "are expected to" verify out-of-band before releasing shares — a voice call, face-to-face meeting, known-good account. No enforcement mechanism is described. Under stress, peers will release shares to whoever can place a phone call with credible voice and context (voice cloning is off-the-shelf in 2026; contextual material is exfiltrated from a seized device). The brief presents out-of-band verification as a security property; the actual property is "whatever peers happen to do under social pressure."

**Why it matters.** This is the single most cited gap across reviewers. The recovery flow is the operational response to compelled unlock per D0002. If peer verification fails in practice, the architectural "master is not on the device" property collapses to "master is one phone call away from any adversary holding a seized device."

**Recommendation.** Specify a verification mechanism. Three options worth presenting in a new decision document:

- **Pre-shared peer challenges** set at provisioning: each peer holds a unique secret phrase the user must repeat for share release. Voice cloning does not yield the phrase.
- **Delay-and-confirm protocol:** share release held for mandatory 24–48h cooling-off period, during which legitimate user can cancel via any of their channels.
- **Two-peer cross-validation:** peers see who else has been contacted for the same recovery, can compare notes through a separate channel before releasing.

The choice should be made and recorded in a decision document (proposed D0003); 5.3 should be revised to specify the chosen mechanism rather than "expected to."

---

## F2. "Master is not on the device" overstates — reconstruction window is an exposed surface

**Category:** Architectural claim / Mechanism spec
**Location:** Section 5.1 ("Master identity"), Section 5.3 ("Recovery flow")
**Reviewers:** Crypto #9, Red Team #2

**Issue.** Section 5.1 frames the master as categorically not present on the device. Section 5.3 acknowledges in passing that the master is "reconstructed in local memory on the fresh device" and "erased from active memory" — but does not specify the memory-hygiene mechanisms (mlock against swap, explicit zeroization, off-heap allocation in Kotlin, protected allocators, no GC residue). The reconstruction window is the master's exposure surface and is acknowledged only obliquely. A device with a forensic implant (3.3 Returned-after-seizure surface, or a compromised fresh device per the pilot model) sees the master in memory at recovery.

**Why it matters.** Multiple reviewers identified this as a categorical-vs-conditional mismatch. The architectural argument for tier separation rests on the master being uncapturable; the actual property is "uncapturable except during provisioning and recovery." Users repeatedly cycling through device loss face master capture at non-trivial probability per cycle.

**Recommendation.** Revise 5.1 to acknowledge the reconstruction window as the master's exposure surface, cross-reference 5.3 and 3.3 (Returned-after-seizure surface), and add to 5.3 a paragraph specifying the memory-hygiene requirements (mlock, explicit zeroization, no swap, off-heap or platform-specific protected memory). Explicitly state that recovery on a returned-after-seizure device is contraindicated for this reason.

---

## F3. Compelled-unlock → peer-HUMINT yields the master; "bounded exposure" framing is misleading

**Category:** Architectural claim
**Location:** Section 5.6 ("Compelled-unlock guidance"), D0002, Section 3.5 ("Bounded exposure under compelled unlock")
**Reviewers:** Red Team #6

**Issue.** Unlock yields the operational identity, contact list, message history, **and the trust-graph view that identifies recovery peers** (5.3 explicitly says recovery peers are visible in the graph). Combined with F1 (peer verification unspecified), the attack chain is short: unlock → identify peers → contact three with impersonation material → reconstruct master. The compromise is bounded only by whether the adversary can reach three peers within their detention window.

**Why it matters.** D0002 selected "no duress profile" on the explicit argument that "the tier-separated identity model already does the work that a duress profile aspires to do, at a lower architectural layer: even full coerced unlock does not yield the master identity." This is true cryptographically (unlock yields no key material) and operationally questionable (unlock yields the material needed to attack the peers who hold the master). The decision is still defensible, but the framing of why misrepresents the actual protection chain.

**Recommendation.** Revise the "bounded exposure" framing in 5.6, D0002, and Section 3.5 to acknowledge the peer-HUMINT attack chain explicitly. The architectural protection of the master is conditional on recovery peers individually refusing to release shares to an adversary with impersonation material. F1's verification mechanism is the load-bearing element of the compelled-unlock answer.

---

## F4. Cascade quarantine soft-flag enables attestation laundering

**Category:** Architectural claim / Mechanism spec
**Location:** Section 5.2 ("Cascade quarantine on revocation")
**Reviewers:** Crypto #6, Red Team #3

**Issue.** A compromised peer issues many adversary-introducing attestations before discovery. After revocation, those attestations are soft-flagged but remain in the graph. The user is told they can "re-attest the affected subject directly" — but their basis is rapport with subjects who may have been adversary plants for months. The likely user behavior: re-attest the ones they "remember and trust," which converts flagged paths into clean paths anchored in the user's own operational signature. The revocation **promotes** the adversary's foothold by laundering it through the user.

**Why it matters.** This is the central attack on the trust graph. The Section 3.3 HUMINT discussion identifies exactly this pattern ("new contacts are introduced to the target's social circle who report back") as the dominant compromise vector, and 5.2's cascade behavior improves the attacker's position post-detection rather than hurting it. The revocation also has no time semantics — the brief doesn't specify whether revocation is retroactive, prospective, or per-attestation, which affects what malicious-during-compromise attestations remain valid.

**Recommendation.** (a) Specify revocation time semantics in 5.2 — likely two distinct operation types: "attestation withdrawal" (soft-flag downstream) and "key compromise revocation" (hard-suspend all attestations from a `revoked-as-of` timestamp). (b) Add a defensive behavior for re-attestation of subjects whose only path was through a now-revoked issuer: require either fresh in-person verification with strength/context recording it, or two independent attestations from other un-flagged issuers. (c) Add stale-flag escalation: a flag present for N days without explicit user action auto-quarantines.

---

## F5. Eight-field operation schema does not cryptographically bind the operational key to its master attestation

**Category:** Mechanism spec / Cryptographic correctness
**Location:** Section 5.2 ("Signed-operation schema")
**Reviewers:** Crypto #5

**Issue.** The operation's signature commits to the seven preceding fields, but no field references the specific master-signed certification of the operational key being used. A verifier locates "the master-signed operational key recorded elsewhere in the graph" by implicit lookup. If a master has signed multiple operational keys (rotation overlap, bug, or compromise that issued duplicates), the verifier cannot tell from the operation alone which master attestation was intended.

**Why it matters.** The trust graph's signature chain is incomplete. The cryptographic backbone — "this operation was signed by the operational key, which was master-signed" — does not chain in the signed payload. A targeted attacker who controls one of two master-issued operational keys could potentially make a different key's signature verify against the wrong certification under certain implementation choices.

**Recommendation.** Add a field `issuer_cert_hash` (a hash of the master attestation certifying the operational key being used to sign) to the schema. The signature then commits to the operation, the issuer key, and the specific master certification. For key-rotation operations specifically, include the master's signature over the new operational key (or its hash) as a field so the rotation is cryptographically anchored to the master, not merely asserted by the previous operational key.

---

## F6. "No project-operated infrastructure" claim is materially false

**Category:** Architectural claim
**Location:** Section 5.2 ("Propagation via the messaging layer"), Section 4.2 (referenced principle)
**Reviewers:** Red Team #1, Threat-Model #5/8/13

**Issue.** The 4.2 principle is invoked to anchor 5.2's propagation design ("nothing in the trust graph depends on the project being present"). But the brief depends on: the reviewer pool (clients refuse releases without their attestations), the Sigsum witness set populated by project-recruited NGO/academic partners, the Tor onion service for distribution, the UnifiedPush distributor recommendation, the Sigstore OIDC identity, and the per-jurisdiction profile feed. If the project disappears, the trust-graph CRDT may keep replicating but the release-security and trust-anchoring stacks collapse.

**Why it matters.** Funders and partners reading 5.2 conclude the design meets the 4.2 principle. It has not — it has redistributed project-coordinated infrastructure across the security stack rather than eliminated it. This is rhetorical overreach that erodes reviewer trust when noticed.

**Recommendation.** Retitle the 4.2 principle "Minimal project-operated infrastructure" or "No project-operated _user-facing_ infrastructure." Revise 5.2 to scope the claim: "The trust-graph propagation path itself does not depend on project-operated infrastructure; the release-security stack (5.5), the partner-cosigned witness set, and the project-coordinated distribution channels retain project dependencies that are addressed by structural defenses in 5.5 rather than eliminated."

---

## F7. Engineering scope materially exceeds 9-12 months — concrete cuts needed

**Category:** Engineering scope / Timeline
**Location:** Section 5 broadly; Section 6 (v1 scope); Section 7 (roadmap)
**Reviewers:** Engineering #1–#24 (entire engineering review)

**Issue.** The engineering reviewer's bottom line: "this is an 18-30 month project for one developer, not 9-12." The largest specific underestimates:

- **SimpleX integration** has no Kotlin SDK. The official client uses Haskell-on-Android via JNI. Options: replicate the Haskell-on-Android pipeline (multi-month effort), reimplement SMP in Kotlin/Rust, or shell out to the daemon. Each is a project on its own.
- **Briar integration** publishes JVM libraries but is designed for sole ownership of identity, Tor lifecycle, storage, and contact flow. Embedding into Cairn requires either forking `bramble-core` to accept Cairn's operational identity (2-3 months plus ongoing rebase cost), accepting dual-identity reality (breaks the "one identity across protocols" property), or deferring Briar.
- **CRDT for trust graph** has no off-the-shelf library matching the construction (signed operations, prior-hash chains, soft-cascade quarantine, Sigsum anchoring). This is several months of original cryptographic engineering.
- **Sigsum client tooling** is alpha-state; the reference client is Go. No mature Kotlin client. Building one puts a cryptographic verification client in the trusted path.
- **Reproducible Android builds** are achievable but require 4-8 weeks of toolchain wrangling plus ongoing maintenance against AGP/NDK updates.
- **UX implementation** is realistically 30-50% of total v1 effort (Signal-familiar surface, trust badges, profile compartmentation, extra-private mode, recovery flows, calibrated security communication).
- **Sigstore on Android** is not the established pattern — APKs must still be signed with a long-lived APK signing key; Sigstore is a per-release attestation layer on top.

**Why it matters.** The 9-12 month commitment in 7.1 is a confidence claim, not an engineering claim. Funders evaluating budget and timeline are seeing a target that engineering review says will slip 100-200%.

**Recommendation.** Make explicit scope cuts in Section 6. Likely candidates with rough time savings each:

- **Defer Briar to v1.5** (–2 to –3 months). Ship v1 SimpleX-only with the Briar architectural slot reserved.
- **Defer local CRDT to v1.5** (–2 to –3 months). Ship v1 with trust graph anchored in Sigsum directly (query-the-log for trust evaluation rather than local CRDT view). Add CRDT in v1.5 once a working baseline exists.
- **Defer reproducible builds to v1.5** (–1 to –2 months). Ship v1 with Sigstore + external source-code review of the source rather than binary reproducibility. Add binary reproducibility in v1.5.
- **Narrow UX surface for v1** (–1 to –2 months). Defer per-conversation extra-private toggle (bind protocol at conversation creation), defer profile compartmentation UI (single-profile-only), defer in-app post-coercion flow to documentation.

Each cut buys real time at known cost. Without cuts of approximately this scale, v1 in 9-12 months is bounded only by what the developer is willing to ship under deadline. This needs to be a decision document (proposed D0004) before funding conversations close.

---

## F8. SimpleX integration shape is unspecified and the choice is multi-month work

**Category:** Engineering scope
**Location:** Section 5.4 ("SimpleX as the primary spine")
**Reviewers:** Engineering #1

**Issue.** SimpleX Chat is Haskell-based; the Android client uses Haskell-on-Android cross-compilation and JNI. There is no documented third-party-embeddable Kotlin/Java SDK. The brief treats "integration" as if a library import. The actual options are (a) replicate the Haskell-on-Android pipeline, (b) reimplement SMP in Kotlin or Rust from spec, or (c) embed and shell out to the `simplex-chat` daemon via its control interface. Each is multi-month work and has different security and operational properties.

**Why it matters.** This is the single largest unstated implementation risk. If the developer discovers in month 2 they must take on the Haskell pipeline, v1 loses 3-6 months and may not ship at all. SimpleX is also making protocol-level changes faster than a 9-12 month implementation window absorbs.

**Recommendation.** Add a subsection to 5.4 ("SimpleX integration shape") naming the three approaches with costs, picking one, and committing scope accordingly. Coordinate directly with the SimpleX team — they may be willing to harden their embedding story for a partner project. If no embedding story exists by funding close, the project may need to drop SimpleX (replace with a custom or alternative), drop Briar, or extend v1 to 15-18 months.

---

## F9. Briar identity model is incompatible with single-Cairn-identity-across-protocols claim

**Category:** Engineering scope / Architectural claim
**Location:** Section 5.2, 5.4, 5.6
**Reviewers:** Engineering #2

**Issue.** Briar's library architecture assumes ownership of identity (Briar `LocalAuthor`), Tor lifecycle, storage, and contact flow. Embedding Briar into Cairn requires either (a) carrying two parallel identities — Briar's and Cairn's master/operational — with the Cairn trust graph having no native way to attest to a Briar identity, (b) forking `bramble-core` to accept Cairn's operational identity (2-3 months plus ongoing rebase), or (c) using Briar only through its transport plumbing. The brief's design assumes one Cairn identity signs across both protocols; none of these paths delivers that without substantial work.

**Why it matters.** The trust graph in 5.2 assumes one operational identity per user across both protocols. The "extra-private mode toggle" in 5.6 assumes the same contact identity carries across protocol switches. If Briar carries its own identity that Cairn cannot bind cryptographically, the toggle is not a toggle but a separate contact-establishment ceremony, and verification badges on SimpleX contacts don't carry to Briar contacts.

**Recommendation.** Decide one of (a) fork `bramble-core` and budget the time, (b) accept dual-identity reality and revise 5.2, 5.6 to reflect that Briar contacts are a separate trust universe, or (c) defer Briar to v1.5. Current text is incompatible with all three; pick one before funding conversations.

---

## F10. Sigstore on Android does not replace the long-lived APK signing key

**Category:** Engineering scope / Architectural claim
**Location:** Section 5.5 ("Sigstore identity-based signing")
**Reviewers:** Engineering #9

**Issue.** Sigstore is mature for containers, packages, attestations. There is no established pattern for Sigstore as the primary signing identity for Android APKs. Android requires APKs to be signed with the APK Signing Scheme (v2/v3/v4 block); Android does not consult Sigstore or Rekor at install. The developer must hold a long-lived Android signing identity for APK signature continuity (required for update-over-prior-version). Sigstore can attest to releases on top of that, but does not replace it.

**Why it matters.** The brief's claim that "there is no master signing key for an adversary to steal" is materially incorrect for Android. The realistic model is: long-lived APK signing key + per-release Sigstore attestation + reviewer Sigsum attestations. This is defensible but is not "no signing key to steal."

**Recommendation.** Revise 5.5 to acknowledge the long-lived APK signing key, specify its protection (hardware token, threshold scheme via FROST, etc.), and reframe Sigstore as the per-release attestation layer rather than the primary signing identity. Distinguish in the compromise-recovery plan between Sigstore-identity compromise (easier to recover) and APK-key compromise (requires APK Signature Scheme v3 key rotation).

---

## F11. Multi-device awareness is claimed in 6.4 but not specified in Section 5

**Category:** Forward-compatibility / Architectural claim
**Location:** Section 6.4 ("Forward-compatibility design choices"); absence in 5.1 and 5.4
**Reviewers:** Engineering #12, Threat-Model #6 (related)

**Issue.** Section 6.4 promises "multi-device awareness in the protocol layer even though v1 ships only phones" as forward-compatibility. Section 5 does not specify what this means: how multiple device keys for one operational identity are advertised in the trust graph, how peers reason about same-identity-multi-device scenarios, how cascade quarantine handles multi-device, how Sigsum entries scope per-device vs per-identity. SimpleX and Briar both have multi-device stories that do not compose with capability tokens naturally.

**Why it matters.** Funders read 6.4 as a roadmap commitment. If multi-device is unspecified in Section 5, the developer discovers during v2 that the protocol-level affordances don't exist and faces either breaking changes (which 6.4 promises won't be needed) or a constrained v2 design.

**Recommendation.** Either (a) add a subsection to 5.1 or 5.4 specifying the multi-device model — minimally, how device keys link to operational identity in the trust graph, how peers handle multi-device subjects — or (b) demote the 6.4 claim to "multi-device pairing flow specified for v2 but not built in v1" and acknowledge that protocol extension may be needed. Honest acknowledgment of (b) is better than a forward-compat claim that doesn't survive contact with implementation.

---

# Significant Findings

## F12. Trust-graph propagation via messaging layer introduces unacknowledged metadata side channel

**Category:** New surface
**Location:** Section 5.2 ("Propagation via the messaging layer"), Section 3.3 (Metadata surface)
**Reviewers:** Threat-Model #3, Red Team #4

**Issue.** A SimpleX server sees graph deltas as encrypted blobs but with characteristic size distributions (signed eight-field operations have a stereotyped envelope) and propagation fan-out timing (revocations propagate to many queues within a short window; rotations after coercion produce distinctive fan-out signatures). A compromised relay can fingerprint "this queue carried a graph delta" and "this user just rotated" without decrypting content.

**Recommendation.** Add to 5.2: "Trust graph deltas have size and propagation patterns distinguishable from message content at server-level observation. Mitigations: padding graph deltas to message-size bins, cover-traffic for fan-out events, and routing rotation-related deltas through Briar during high-sensitivity periods rather than the user's existing SimpleX queues." Cross-reference Section 3.3 Metadata surface and extend it to enumerate trust-graph deltas as a distinct exposure category.

---

## F13. Sigsum log is itself a public metadata channel for social-graph reconstruction

**Category:** New surface
**Location:** Section 5.2 (Sigsum integration), Section 3.3 (Metadata surface), Section 3.4 (Sigsum trust root)
**Reviewers:** Threat-Model #4

**Issue.** Sigsum's design point is public auditability — anyone can read it. If the log contains full operations, every public-key pair that has ever been attested, revoked, or introduced is publicly enumerable. The "social graph inference from contact lists and group memberships" target in 3.3 Metadata surface is placed directly in a public log by 5.2 as currently written.

**Recommendation.** Specify in 5.2 what is logged in Sigsum versus what is held locally. Two viable patterns: (a) only Merkle commitments / roots are logged, with operations held locally and verifiable against the root; (b) public keys in the log are pseudonymous identifiers rotated per operation. If full operations are logged, 3.3 should explicitly enumerate Sigsum as a public metadata channel and 3.4 should call out the privacy-vs-auditability tradeoff.

---

## F14. In-person facilitator is a high-value trust root not named in Section 3.4

**Category:** Trust root / Unstated assumption
**Location:** Section 5.3, 5.6, Section 6.3; absence in 3.4
**Reviewers:** Threat-Model #5, Red Team #14, Op #11

**Issue.** The facilitator provides the device, conducts the QR exchange, walks through recovery peer selection, mediates first attestation, and (in pilot) is the developer. A compromised or coerced facilitator gains visibility into multiple users' identity material and influences peer designation. The brief rejected centralized trustees in 5.3 because users in adversarial jurisdictions cannot rely on institutions they can't reach — but substitutes one person (the developer) as a de facto trustee with weaker accountability than a foundation.

**Recommendation.** Add the facilitator to 3.4 as an explicit trust root with bounded scope. Add a paragraph to 5.6 or 6.3 naming the facilitator-as-trust-placement: "The pilot's in-person provisioning concentrates significant trust in the facilitator — typically the developer for v1. This concentration is the structural cost of the pilot model. Broader deployments must address it through mechanisms not yet specified: rotation of facilitator role, independent witness to provisioning ceremonies, post-provisioning audit of attestations against expected patterns. The honest framing is that v1 trusts the facilitator; v2+ must define how that trust is bounded as the user base grows."

---

## F15. Reviewer pool is structurally a trust root and a small attack surface

**Category:** Trust root
**Location:** Section 5.5 ("External reviewer pool"), Section 3.4
**Reviewers:** Threat-Model #8, Red Team #8

**Issue.** Two to three reviewers, "independent of the developer and of each other," attest binary equivalence. Adversary compromise of two of three produces concurring false attestations. Independence is asserted but not specified (no shared employer? jurisdiction? funder?). Recruitment criteria, vetting, rotation, and incentive analysis are absent.

**Recommendation.** (a) Specify recruitment criteria in 5.5 or 8.2: geographic diversity, institutional diversity, demonstrated independence. (b) Increase to 5+ reviewers with 3-of-5 attestation threshold, mirroring the recovery model and providing margin against single-reviewer compromise. (c) Specify reviewer audit: random-sample testing with known-divergent builds, rotation requirement, public attestation records. (d) Add the reviewer pool to 3.4 as an explicit trust root.

---

## F16. Sigstore OIDC provider is an unnamed trust root with its own jurisdiction

**Category:** Trust root
**Location:** Section 5.5 ("Sigstore identity-based signing"), Section 3.4
**Reviewers:** Red Team #7

**Issue.** Sigstore Fulcio binds to an OIDC identity, meaning a specific provider (Google, GitHub, Microsoft) attested to an identifier. The provider can — under U.S. legal process, court order, or coercion — issue an OIDC token for the developer's identity to a party that is not the developer. The email account or OIDC identity itself becomes a long-lived authentication credential, replacing the long-lived signing key the brief says it does not want.

**Recommendation.** Specify which OIDC provider Cairn uses. Add it to 3.4 as an explicit trust root with residual-risk discussion. Acknowledge the provider's jurisdiction matters (U.S.-based OIDC provider is reachable by U.S. legal process). Specify operational defenses: hardware-security-key requirement on the OIDC provider, alerts on token issuance, regular Rekor audit against out-of-band log of when the developer actually signed.

---

## F17. Shared Sigsum witness pool concentrates risk across two security functions

**Category:** Trust root concentration
**Location:** Section 5.2 (trust-graph anchoring), Section 5.5 (release log), Section 3.4
**Reviewers:** Threat-Model #13, Red Team #9

**Issue.** Section 5.5 deliberately reuses the same Sigsum infrastructure and witness partners for trust-graph attestations and release-binary attestations. Compromise of the witness set affects both surfaces simultaneously. Citizen Lab and Access Now staff (named candidates for the partner pool) have themselves been targeted by spyware per the threat model.

**Recommendation.** Either (a) commit to architecturally separate witness sets for the two logs, accepting the operational cost; (b) acknowledge in 3.4 that the witness pools overlap and compromise consequences are correlated. Specify witness threshold and recruitment criteria explicitly.

---

## F18. Recovery peer designation is not encoded as a trust-graph operation; visibility-as-mitigation claim is unsupported

**Category:** Mechanism spec
**Location:** Section 5.3 ("Recovery network surface"), Section 5.2 (operation enumeration)
**Reviewers:** Threat-Model #14

**Issue.** Section 5.3 claims recovery peers are "visible in the trust graph as a structural relationship" so the broader network can notice anomalies. Section 5.2's four operation types (attest, revoke, introduce, rotate) don't include a recovery-peer-designation operation. Either (a) recovery-peer designation is a missing fifth operation type, or (b) the relationship is inferred from other operations in an unspecified way, or (c) the claim in 5.3 is unsupported by 5.2's data model.

**Recommendation.** Section 5.2 must either add recovery-peer designation to the operation enumeration (and specify visibility scope — broader network vs. peers only), or 5.3 must withdraw the structural-visibility mitigation claim. If recovery-peer designations ARE visible in the graph, F13 / Section 3.3 should acknowledge that this also makes them publicly enumerable target lists.

---

## F19. Endpoint surface — evil-maid is named in 3.3 but undefended in Section 5

**Category:** Threat-model consistency
**Location:** Section 5.1, Section 3.3 (Endpoint surface)
**Reviewers:** Threat-Model #1

**Issue.** Section 3.3 enumerates evil-maid attacks (device left unattended). Section 5's defenses are framed around seizure/coerced unlock — the tier model bounds compromise post-event. Evil-maid is qualitatively different: device returned unobserved, user keeps using it, no event triggers operational-key rotation, no recovery is initiated. Hardware element does not defend against an implant that captures the passphrase the next time the user enters it.

**Recommendation.** Either (a) extend "considered burned" operational guidance from the Returned-after-seizure surface to evil-maid scenarios, leveraging GrapheneOS verified-boot attestation surfacing; or (b) acknowledge in 5.1 that the tier model does not defend evil-maid and that this surface relies on the user noticing tampering, citing dependence on the GrapheneOS trust root for boot integrity.

---

## F20. Burned-device cascade semantics are unspecified

**Category:** Mechanism spec / Threat-model consistency
**Location:** Section 5.1 (rotation), Section 5.2 (cascade), Section 3.3 (Returned-after-seizure)
**Reviewers:** Threat-Model #2

**Issue.** Section 3.3 directs that a seized device "should be considered burned": revoke the cryptographic identity, recover on a fresh device. Section 5.2's cascade specifies behavior for revoking attestations issued by a suspect peer. The brief never specifies what happens to attestations the user themselves issued from a compromised operational key. Two readings: (a) revocation cascades against the user's own downstream attestations (large self-inflicted blast radius), or (b) the prior operational key's attestations survive revocation (compromised key's attestations remain valid). Neither is stated.

**Recommendation.** Specify in 5.1 or 5.2 the semantics of self-issued key rotation following suspected compromise: whether attestations previously issued by the revoked key are soft-quarantined in viewers' graphs, and how peers re-attest the new operational key without re-attesting every prior subject.

---

## F21. Operational identity rotation is itself a coercion vector

**Category:** Threat-model consistency / New attack vector
**Location:** Section 5.1 ("Operational identity"), Section 3.3 (Identity surface)
**Reviewers:** Threat-Model #6

**Issue.** Rotation requires reconstructing the master, which requires three Shamir shares from peers. An adversary holding the user under coercion who understands the architecture can compel the user to initiate rotation, at which point the master is reconstructed in active memory on the device under coercion. The brief's framing implies rotation happens after coercion ends; nothing enforces this.

**Recommendation.** Section 5.1 or 5.3 should acknowledge that the recovery/rotation flow itself is a coercion-vulnerable surface. Specify what defends against it: peer out-of-band verification (F1), time delays, ceremonial gates. Section 3.3 should add coerced-rotation as a sub-case of compelled disclosure.

---

## F22. Extra-private mode toggle is itself a side-channel signal

**Category:** UX-architecture gap / New surface
**Location:** Section 5.4 ("When each tier applies"), Section 5.6 ("Extra-private mode")
**Reviewers:** Op #6, Red Team #11

**Issue.** Selecting Briar generates observable signals: network traffic shape changes, device-state stores which conversations were elevated, behavioral pattern indicates this-conversation-is-sensitive. A traffic-analysis adversary or forensic examiner sees the user flagging specific conversations as sensitive. The protection the toggle provides (no server in path) is real; the metadata it creates (this conversation is flagged) is also real, and not acknowledged.

**Recommendation.** Add to 5.4: "Selecting the highest-sensitivity tier is itself a metadata signal — network-level observers see traffic-shape changes correlated with the toggle; forensic examination reveals which conversations used the elevated tier. For users facing traffic-analysis-capable adversaries, the operational practice is either to route all sensitive conversations through Briar uniformly (eliminating the differential signal) or to accept that the toggle's choice is itself observable." Update the 5.6 tooltip to acknowledge this.

---

## F23. Cryptographic vocabulary precision: Shamir input, COSE structure, FS scope

**Category:** Cryptographic correctness
**Location:** Section 5.1, 5.2, 5.4
**Reviewers:** Crypto #1, #3, #4

**Issue.** Three related imprecisions:

- **Shamir input:** The brief says "the private key is split." Ed25519 private keys are 32-byte seeds (RFC 8032 §5.1.5); splitting the seed is correct, splitting the derived scalar would break Ed25519 nonce determinism. Field choice (GF(2^8) byte-wise vs prime field) also matters.
- **COSE structure:** "COSE-formatted" doesn't name which structure (COSE_Sign1 vs COSE_Sign). The eight-field schema in 5.2 lists application claims, not COSE structure — the envelope (COSE) and claim set (application fields) aren't distinguished. CBOR canonicalization for signature reproducibility is unspecified.
- **Forward secrecy scope:** Section 3.5's "Forward secrecy via per-conversation session key rotation" is weaker than the SimpleX double-ratchet provides. The brief conflates forward secrecy with post-compromise security and doesn't distinguish on-wire FS from at-rest persistence (the on-device store remains decryptable under unlock regardless of ratchet state).

**Recommendation.** (a) Specify in 5.1: "The 32-byte Ed25519 seed (RFC 8032 §5.1.5) is split using Shamir Secret Sharing over [GF(2^8) byte-wise / GF(p)]; reconstruction yields the seed and standard Ed25519 key expansion regenerates the signing key." (b) Specify COSE structure (COSE_Sign1 most likely), reference CWT (RFC 8392) if the claim pattern follows it, commit to deterministic CBOR (RFC 8949 §4.2.1) for signed content. Distinguish envelope from claims. (c) Tighten 3.5 to: "Forward secrecy of on-wire message content via the SimpleX double-ratchet derivative; at-rest message history on the device remains decryptable under unlock."

---

## F24. Storage architecture is absent from Section 5

**Category:** Engineering scope / Forward-compatibility
**Location:** Section 5 entirely; Section 6.4 ("migration framework")
**Reviewers:** Engineering #13, #21

**Issue.** Section 5 doesn't specify persistent storage: SQLite vs key-value vs document store; one store per protocol or unified; schema versioning approach; migration testing strategy. v1 has at least three persistent stores (SimpleX's internal, Briar's H2-encrypted, Cairn's own). Cross-store consistency under crash, migration, and recovery is non-trivial. The 6.4 "migration framework" claim is unanchored in Section 5.

**Recommendation.** Add a subsection (5.7 or paragraph in 5.1/5.2) on persistent storage: what stores exist, their relationships, schema versioning approach, migration testing. A half-page commitment (e.g., "Cairn uses Room with explicit migrations and per-table version columns; migrations tested with Room migration-test infrastructure plus property-based tests round-tripping data through each step") closes the gap and gives 6.4's claim an architectural anchor.

---

## F25. Push-notification default posture is undefined; UnifiedPush adds onboarding friction

**Category:** Engineering scope / UX-architecture gap / Trust root
**Location:** Section 5.4 ("Push notifications")
**Reviewers:** Op #9, Engineering #11, Threat-Model #7

**Issue.** UnifiedPush requires a separate distributor app (NTFY, NextPush). For v1's audience this adds onboarding friction. The push-server timing metadata reintroduces a per-user persistent signal that SimpleX's queues are designed to avoid. The brief defers distributor selection but doesn't specify the default posture (push on/off) or characterize what "polling" looks like as the alternative.

**Recommendation.** Revise 5.4 to commit to one of: (a) UnifiedPush with a named recommended distributor and acknowledged second-app onboarding step; (b) poll-only as v1 default with UnifiedPush as v1.x enhancement; (c) project-operated UnifiedPush distributor with explicit acknowledgment that this partially walks back 4.2's no-project-infrastructure principle. Add the push distributor to 3.4's trust roots or extend 3.3's Metadata surface to enumerate it.

---

# Minor Findings

## F26. Partial-share leak metadata is real even when secret material is not

**Severity:** Minor
**Location:** Section 5.3 ("Fail-closed behavior")
**Reviewers:** Crypto #2

Shares below threshold leak no secret material (Shamir's information-theoretic guarantee). They do leak which peers responded, when, through which channels — falling under 3.3 Metadata surface and Recovery network surface. The current paragraph in 5.3 can be read in isolation as an overclaim.

**Fix:** "Nothing about the master secret is computable from fewer than three shares; this is Shamir's information-theoretic guarantee. The recovery attempt itself, however, produces observable metadata — which peers responded, when, through which channels — covered separately by Section 3.3 Recovery network surface."

---

## F27. Pluggable transports framing in 5.4 overstates Tor's defense against Tool-use surface

**Severity:** Minor
**Location:** Section 5.4 ("Tor as transport for both"), Section 3.3 (Tool-use surface)
**Reviewers:** Threat-Model #12, Red Team #10

Section 3.3 says Tool-use surface "cannot be meaningfully mitigated." Section 5.4 implies partial mitigation via pluggable transports. The framings are inconsistent. Additionally, DPI evasion is an ongoing arms race the brief frames as a single decision.

**Fix:** Downgrade 5.4 framing to acknowledge that pluggable transports bound but do not close the Tool-use surface, cross-reference 3.3. Add commitment: "Transport selection is an ongoing engineering commitment, not a one-time decision; the project commits to tracking Tor Project guidance and prioritizing transport-update releases when active blocking is observed."

---

## F28. Briar's specific forward-secrecy properties differ from SimpleX's; conflated in 3.5

**Severity:** Minor
**Location:** Section 3.5 (in-scope), Section 5.4 (Briar paragraph)
**Reviewers:** Crypto #11

Briar uses BTP/BSP with different ratchet characteristics from SimpleX's double-ratchet derivative. The Section 3.5 in-scope statement applies forward-secrecy uniformly across both.

**Fix:** Add one sentence to 5.4 Briar paragraph: "Briar's Bramble Transport and Synchronisation Protocols provide forward secrecy with characteristics specific to their design; the integration relies on these properties as published by the Briar project and named as a trust root in Section 3.4."

---

## F29. Strength field has no specified composition algebra

**Severity:** Minor
**Location:** Section 5.2 ("Signed-operation schema")
**Reviewers:** Crypto #12

Strength is described as ordinal but the brief doesn't specify how strength composes across a trust path (min, weighted sum, multiplicative). Different clients with different algebra produce divergent path computations — undermining 5.6's UX consistency claim.

**Fix:** Either specify a canonical strength-composition function in 5.2 (or defer to spec while noting user-facing consequences), or acknowledge that strength is advisory-only with trust paths as binary (attested-or-not).

---

## F30. Recovery flow timing under stress not specified

**Severity:** Minor
**Location:** Section 5.3 ("Recovery flow")
**Reviewers:** Op #12

Recovery is presented as binary (complete or not). In practice it's a multi-day stateful process — peer verification takes hours to days; the user is in a partial state where the prior operational identity hasn't been revoked yet. The brief doesn't specify what the user does during the wait or what the UI shows.

**Fix:** Specify expected timing envelope (24h typical, up to N days, timeout after M days reverting to fresh-identity), what the in-progress UI shows, whether the user should remain offline during recovery.

---

## F31. Sticky-flag escalation for cascade quarantine

**Severity:** Minor
**Location:** Section 5.2 ("Cascade quarantine")
**Reviewers:** Red Team #17

Soft flags that remain visibly-flagged-but-active indefinitely train users to ignore them (warning fatigue, which 5.6 itself argues against). A flag present for N days without explicit user action should auto-quarantine.

**Fix:** Add stale-flag escalation timer to the cascade-quarantine mechanism, pair with F4's re-attestation requirement.

---

## F32. v1 source localization slot, test infrastructure, documentation effort, crash reporting

**Severity:** Minor (collected)
**Location:** Section 5.6, Section 6, Section 8 placeholders
**Reviewers:** Engineering #14, #15, #16, #17, #18, #19

Smaller engineering items that need acknowledgment but not full edits:

- **Test infrastructure** is unmentioned. Add brief subsection committing to property-based testing for CRDT, fuzzing for parsers, known-answer tests for crypto primitives.
- **Documentation effort** is ~1.5-2.5 person-months and unbudgeted in the v1 timeline. Section 6.1 should acknowledge scope.
- **Crash reporting** architecture is implied via "feedback channel within the product itself" but unspecified. Commit to opt-in, end-to-end encrypted via the messaging layer.
- **i18n architecture slot** must be present in v1 even though only English ships. Brief sentence commitment to Android string resources from day one.
- **Reviewer pool operational policy:** how many attestations to ship, cadence, compensation, onboarding.
- **Reviewer-level cryptographic review during implementation** is not in budget but is the position the project is implicitly relying on (the developer self-audits). Either budget rolling cryptographic review or descope original-cryptographic-engineering content.

---

# Recommended action plan

Findings break into four action categories:

**A. Prose edits to Section 5 (and Section 3) — straightforward.**
F2 (master reconstruction window), F3 (compelled-unlock chain), F6 (no-project-infra framing), F12 (trust-graph metadata side channel), F13 (Sigsum public log), F19 (evil-maid), F22 (extra-private toggle side channel), F23 (cryptographic vocabulary), F26-F30 (minor tightening). Apply directly.

**B. New decision documents — judgment calls required.**

- **D0003 — Recovery peer verification mechanism (F1).** Choose among pre-shared challenges, delay-and-confirm, two-peer cross-validation, or combination.
- **D0004 — v1 scope cuts to fit 9-12 month timeline (F7, F8, F9, F10).** Decide which of Briar / local CRDT / reproducible builds / UX scope to defer.
- **D0005 — Trust root enumeration update (F14, F15, F16, F17).** Add facilitator, reviewer pool, OIDC provider to 3.4 with bounded scope; commit witness-pool separation or accept overlap.
- **D0006 — Cryptographic envelope completion (F4, F5, F23, F29).** Specify revocation time semantics, issuer-cert-binding field, COSE structure, algorithm identifier, strength composition.
- **D0007 — Multi-device commitment (F11).** Specify multi-device model in Section 5, or demote 6.4 claim.

**C. New open questions to surface.**
F18 (recovery-peer designation as operation type), F20 (burned-device cascade), F21 (coerced rotation), F24 (storage architecture), F25 (push posture).

**D. Acknowledgments to add without committing further work.**
F27 (transport arms race), F28 (Briar FS), F31 (stale-flag escalation), F32 (testing/docs/crash/i18n).

---

# Strategic note

This review is substantially heavier than Section 3's was. Section 3 produced 12 findings; Section 5 produced ~88 raw / 32 consolidated, with engineering-feasibility alone showing the timeline is 100-200% off. This is not a defect of Section 5 — it reflects that Section 5 makes architectural commitments where Section 3 made surface claims, and architectural commitments expose more questions. The right response is to engage seriously with F7 (scope cuts) before applying any of A's prose edits, because the prose edits assume a v1 shape that may need to change.

The next decision is whether to:

1. Apply category A prose edits immediately (small, reversible, doesn't bind larger decisions).
2. Hold A until the larger decisions in B are made (avoids reworking prose after scope cuts).
3. Engage with F7 first as a focused decision (likely the most important single decision in the project).

The recommendation is option 3 — F7 first, then B decisions in order of dependency, then A prose edits, then C/D acknowledgments and open questions.
