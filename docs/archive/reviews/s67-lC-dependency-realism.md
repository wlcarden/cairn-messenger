# §§6/7 — Dependency Realism Lens

## Summary

§6 and §7 commit the project to a specific cross-version roadmap (v1, v1.5, v1.6, v2, v3, v4+) whose realization depends on (a) funding events §10 itself describes as conditional, (b) partner relationships §8.6 explicitly characterizes as "intent, not commitment," and (c) upstream actors (Google/Pixel, GrapheneOS, Briar, F-Droid, Apple, Meshtastic/MeshCore communities, hardware OEMs) over which the project has no influence. §9.2 names some of these dependencies as "product limitations" (GrapheneOS supply chain, Tor capacity), and §3.4 names some as "trust roots." §7 itself does not import or repeat those qualifications when describing release commitments: §7.2 reads as a straight "v1 enables v1.5 enables v2 enables v3" chain with §7's only acknowledged dependencies being internal architectural ones (capability-token schema, Sigsum logging, Rust core).

The result is that a reader of §7 alone sees a confident multi-year roadmap that, by §10/§8.6's own framing, is gated on events the project does not control. The credibility gap is not in §10 (which is explicit about phase-gating) or §8.6 (which is explicit about intent-vs-commitment); it is in §7 inheriting none of those qualifications inline.

## Critical findings

### F1: v2 iOS commitment lacks Apple-side feasibility acknowledgment

- **Evidence:** §6.2 defers iOS to v2; §7.1 ("v2 ... iOS support extends the platform to users who cannot or will not move to GrapheneOS-Pixel; the security baseline iOS allows is documented as part of v2 work") and §7.2 ("iOS support reuses the Rust core with a Swift UI replacing Kotlin") describe v2 iOS as an engineering-side substitution. §9.2 acknowledges "GrapheneOS supply-chain dependency" but does not mark iOS-specific risks. Nowhere in §§6/7 is App Store policy, code-signing/notarization, Sigstore-on-iOS verification posture, or background-networking-over-Tor feasibility named.
- **Impact:** A v2 iOS build is gated on Apple App Store policies (which routinely affect VPN/Tor/anonymity apps), iOS code-signing (Sigstore identity-based signing is not a native fit for App Store distribution), and the inability to ship Briar at all on iOS (Briar's Tor-over-LAN/Bluetooth model has no iOS port). v1.5 commits Briar; v2 claims iOS — the brief does not say how a v2 iOS user accesses the v1.5-promised highest-sensitivity tier, nor how the §5.5 release-security stack (APK signing key, Sigstore, reproducible builds → reviewer binary equivalence) maps onto iOS at all. The "security baseline iOS allows is documented" phrasing in §7.1 papers over a release-security stack that does not exist on iOS.
- **Recommendation:** §7.1 v2 paragraph should explicitly acknowledge (a) Apple distribution policy is an upstream dependency the project does not control, (b) Briar tier is unavailable on iOS (or document the alternative), and (c) the §5.5 release-security stack will require restatement for iOS — and that restatement is itself a design-brief-level commitment, not v2 implementation detail.

### F2: v3 mesh integration depends on radio-community protocol stability and hardware partnerships not named in §7

- **Evidence:** §7.1 v3 ("Mesh radio integration via Meshtastic and MeshCore ... protocol-agnostic — supporting both Meshtastic's flood-routing model and MeshCore's intelligent-routing model"). §7.2 v2-enables-v3 paragraph claims the v3 work reuses v2 multi-device extensions. §6.2 lists "Hardware partnerships for pre-keyed devices" as v4+. §10.5 lists "Hardware partnerships (v3+ aspiration per the roadmap): pre-keyed device distribution, mesh-radio integration kits" but calls them "out of scope for v1 funding decisions."
- **Impact:** Meshtastic and MeshCore are independent volunteer communities with protocol roadmaps the project does not control; both have made breaking changes within 18-month windows. v3 commits the project to tracking both. Mesh-radio integration also requires hardware (LoRa modules, Meshtastic-certified devices) the user must supply; §7 does not say whether v3 ships as software-only or requires the hardware partnership work §10.5 calls v3+ aspiration. There is internal inconsistency: §6.2 lists hardware partnerships as v4+, §10.5 lists them as v3+, and §7 commits a v3 mesh release without naming the hardware path at all.
- **Recommendation:** §7.1 v3 paragraph should name the upstream protocol dependency (Meshtastic + MeshCore protocol stability over multi-year windows) and resolve the v3-vs-v4 ambiguity about hardware partnerships. If mesh hardware is BYOD, say so; if hardware partnerships are required, move them into §7's v3 dependency list, not §6.2's v4+.

### F3: v1.5 Briar tier depends on Briar Android/protocol stability the project does not control

- **Evidence:** §6.2 defers Briar to v1.5 "(per [D0004])". §7.1 v1.5 ("Adds Briar as the highest-sensitivity tier and the per-conversation extra-private mode toggle that depends on it"). §7.2 v1-enables-v1.5 ("the operational identity signs Briar-channel attestations the same way it signs SimpleX-channel ones"). §3.4 lists Briar implicitly via its trust-root posture; §9.2 has no Briar-specific supply-chain note paralleling the GrapheneOS one.
- **Impact:** Briar's release cadence is sporadic, its primary maintainer pool is small, its Android Tor-bundling approach has changed in past years, and it has no published commitment to integrator API stability. v1.5 hinges on a substrate the brief treats as ambiently available; this is exactly the type of dependency §3.4 names for SimpleX, GrapheneOS, and Tor but does not name for Briar — and §7 does not name it either.
- **Recommendation:** §7.1 v1.5 paragraph should name Briar protocol stability and project-health as the upstream dependency analogous to the §9.2 GrapheneOS note, and §3.4 should be cross-referenced.

### F4: Reviewer-pool pre-condition for every release is not surfaced in §7

- **Evidence:** §6.1 "External source-code review by a recruited reviewer pool with the 5+ membership and 3-of-5 attestation threshold." §8.6 "Specific partner-role assignments emerge from outreach"; "depends on conversations the project has not yet held, on funding (Q3) that has not yet closed, and on partner organizations' own capacity and priorities, which the project does not control." §9.1 "Reviewer and witness pools may not form or may erode ... release-cadence dependence on 3-of-5 attestation means erosion translates directly to release delays." §7 makes no mention of the reviewer-pool gate on v1, v1.5, v1.6, v2, or v3 release.
- **Impact:** Every release in §7 is, per §5.5/§8.2/§8.6, gated on 3-of-5 reviewer attestation. The reviewer pool does not yet exist (§10.1 Phase A includes "Reviewer-pool recruitment outreach"). §7's release commitments are therefore conditional on a partner-recruitment outcome §7 does not name. A reader who reads §7 in isolation sees release dates without the reviewer-pool gating that §5.5 and §8.6 make explicit elsewhere.
- **Recommendation:** §7.1 or §7.2 should state once that every release is conditional on the 3-of-5 reviewer attestation per §5.5 — and that the reviewer pool itself is a §8.6/§10 conditional commitment. Currently this gate is invisible in §7.

### F5: §7.2 v1-enables-v1.5 silently assumes Sigsum witness pool exists across multi-year operation

- **Evidence:** §7.2 "The local trust-graph caching in v1.5 sits atop the Sigsum commitment-only logging already present in v1." §3.4 names Sigsum log operator and witness pool as trust roots. §8.6 lists Sigsum witnesses as a separate partner-role category requiring "operational capacity to maintain witness cosignature over multi-year timelines, alignment with the project's mission." §9.1: "Reviewer and witness pools may not form or may erode."
- **Impact:** v1 release security (§5.5 log cosignature) and v1's trust-graph audit substrate both require the witness pool. §7 commits to Sigsum-based functionality across v1, v1.5, v1.6, v2, v3 without naming witness-pool continuity as a multi-year dependency. If the witness pool erodes mid-roadmap, §7's release-security model degrades silently.
- **Recommendation:** §7 should reference §8.6's witness-pool dependency alongside the reviewer-pool gate in F4.

### F6: §7's "v4 and beyond" mixes architectural-revisitation work with foundation-existence prerequisites

- **Evidence:** §7.1 "v4 and beyond ... Established-organization tier with formal admin and governance controls"; §7.2 "v4's established-organization tier likely requires architectural extension for admin operations (organizational policies, audit logs of administrative actions, group governance)." §8.4 and D0010 make foundation incorporation a Phase C funding event ($5K-25K) ~18-24 months post-v1. §3.4 "Future foundation jurisdiction (v1.5+) ... activates at incorporation; v1 does not place trust in a foundation that does not yet exist."
- **Impact:** v4's established-organization tier presupposes (a) a foundation entity exists to govern organizational deployments, (b) the foundation has the legal/operational capacity to enter B2B-style relationships, and (c) the v3-to-v4 transition has resolved the §6.2-vs-§10.5 hardware-partnership ambiguity (F2). §7 commits to v4 work without naming the foundation-existence prerequisite — and foundation existence is itself conditional on Phase C funding closing.
- **Recommendation:** §7.1 v4 paragraph should name foundation incorporation (D0010) as a hard prerequisite, not just an organizational-design assumption.

## Significant findings

### F7: GrapheneOS-Pixel hardware availability dependency named in §9.2 but not in §7

- **Evidence:** §9.2 "Google can withdraw Pixel devices from market, modify Pixel firmware in ways that affect GrapheneOS compatibility ... Cairn's v1 platform requirement (Section 6.1) breaks if Google ceases shipping Pixel devices or restricts GrapheneOS-compatible firmware. Neither is within the project's influence." §7.3 lists "Broader hardware availability" under "Conditions outside the project's control" but only as it relates to addressable-audience expansion.
- **Impact:** §7's v1.5, v1.6, v2 commitments depend on GrapheneOS-Pixel continuing to be a viable platform; v2 partially addresses this via iOS support, but v1.5 and v1.6 do not. If Google withdraws Pixel-7 / Pixel-8-class devices from supported markets mid-v1.5, the v1.5 user base shrinks. §7.3's "addressable audience" framing addresses growth, not continuity-of-existing-deployment.
- **Recommendation:** §7.3 "Conditions outside the project's control" should explicitly cover continuity of GrapheneOS-Pixel availability, not just expansion of it.

### F8: F-Droid distribution dependency unacknowledged anywhere in §§6/7

- **Evidence:** §6.1 names "Distribution" through Sigstore/APK signing but does not name the distribution channel. The brief elsewhere references F-Droid distribution. §7 makes no F-Droid acknowledgment.
- **Impact:** F-Droid has its own inclusion criteria, anti-features policy, reproducible-build requirements, and review backlog (frequently multi-month). If v1 ships via F-Droid, every release in §7 is gated on F-Droid acceptance of the build. F-Droid is also subject to its own policy changes (e.g., recent debates about anti-features for Tor-bundled apps). If the distribution channel is direct-download-from-project, that creates a different trust-root surface §3.4 should address. The brief does not name the distribution path at the §7 release-commitment level.
- **Recommendation:** §6.1 or §7 should name the v1 distribution channel and the upstream policy dependency it creates.

### F9: UnifiedPush dependency named as product limit but not as roadmap dependency

- **Evidence:** §9.2 "UnifiedPush distributor metadata channel"; v1.5 may revisit the polling default (§9.2, per Q12). §7.1 v1.6 "May add voice and video calling (SimpleX supports them; depends on pilot priorities)." §7 makes no UnifiedPush mention.
- **Impact:** If v1.5/v1.6 revisits push notification defaults (named as a possibility), the implementation depends on UnifiedPush distributor availability and ecosystem maturity. UnifiedPush ecosystem is small and changes; its distributor pool in the GrapheneOS context is narrower still. The roadmap-level dependency is not named.
- **Recommendation:** If v1.5/v1.6 push-default revisitation is a roadmap item, §7 should name UnifiedPush as the upstream dependency.

### F10: Partner-network-for-broader-pilot dependency understated in §6.3 and absent from §7

- **Evidence:** §6.3 "v1 pilot facilitator is the developer; broader deployment depends on partner organizations operating as facilitator networks." §8.6 lists pilot facilitation as a partner role with named candidate organizations but "the brief does not characterize partner organizations' existing user relationships as available channels for Cairn pilot expansion." §10.1 Phase A "Pilot deployment at scale beyond the developer's own facilitation capacity. Broader pilot facilitation depends on partner-organization arrangements; the partner arrangements depend on partner-side funding evaluations the project does not control." §7 has no facilitator-network dependency reference.
- **Impact:** §7's v1.5 and v1.6 release windows assume the v1 pilot completes successfully and broader deployment becomes possible. §6.3's "broader-deployment provisioning models (facilitator networks, post-pilot remote onboarding) are not committed in v1" is honest, but §7's transition from v1 (10-15 pilot users) to v1.5/v1.6 (implicitly broader) does not name the facilitator-network dependency. If no partner takes the facilitator-network role, the v1.5 "completes the architecture" release ships into the same 10-15-user pool the v1 pilot served.
- **Recommendation:** §7 should distinguish architectural-completeness milestones (which proceed regardless of facilitator-network outcome) from user-base-growth milestones (which depend on facilitator-network arrangements).

### F11: v2 USB form factor depends on hardware availability and amnesic-OS substrate not named

- **Evidence:** §7.1 v2 "USB-bootable form factor and iOS support. The USB form factor provides portable cryptographic identity for borrowed-laptop scenarios, with the multi-device protocol extension from D0007 deployed at this version." §7.2 v1-and-v1.5-enable-v2 "The Rust core per D0003 cross-compiles to whatever platform the USB-bootable image targets; v1's Kotlin UI is replaced with a USB-environment-appropriate UI shell — likely a minimal terminal or framebuffer UI — without changing the core."
- **Impact:** A USB-bootable amnesic OS for cryptographic identity is not a standard target the Rust ecosystem cross-compiles to without significant integration effort (Tails is the existing prior art; building atop it creates a Tails-team dependency, building from scratch creates a multi-person-year project). §7 treats this as a cross-compilation exercise. The "likely a minimal terminal or framebuffer UI" is a hand-wave at one of the most complex deliverables on the roadmap.
- **Recommendation:** §7.1 v2 paragraph should name the upstream substrate dependency (Tails-derivative? Debian-live? from-scratch?) or downgrade the commitment to "design study" pending that determination.

## Minor findings

### F12: §6.3 facilitator-handbook deliverable does not name the partner co-author dependency

- **Evidence:** §6.1 "Partner organizations are natural collaborators for the user-facing and facilitator documentation (Section 8.6)." §6.3 lists "facilitator handbook for the in-person provisioning ceremony" as a v1 deliverable. §8.6 lists user training as a partner role.
- **Impact:** If partner organizations are "natural collaborators" but not committed, the v1 facilitator handbook may need to be authored solo. This is a small dependency but is named one place (§6.1) and not connected to the other (§6.3).
- **Recommendation:** §6.3 should clarify whether the v1 facilitator handbook ships partner-reviewed or developer-only.

### F13: §7.2 "What requires architectural revisitation" understates D0006/D0007 evidence

- **Evidence:** §7.2 "Through v3, no significant revisitation of v1 architecture is anticipated; the forward-compatibility design choices in Section 6.4 should bound the migration work to additive changes." §9.1 "the Section 5 adversarial review surfaced multiple cases where forward-compatibility claims required explicit decisions (D0007 demoted the multi-device claim; D0006 added schema fields that v1 deployments cannot retroactively gain). Another such case may emerge during implementation or pilot."
- **Impact:** §7.2's confident "no significant revisitation through v3" contradicts §9.1's "another such case may emerge." The §7 framing reads as more confident than the §9 framing supports.
- **Recommendation:** §7.2 should reference §9.1's acknowledgment that forward-compatibility revisitation has already occurred (D0006/D0007) and may recur.

## Patterns

**Pattern 1 — §7 inherits no qualifications from §§3.4, 8.6, 9.1, 9.2, or 10.** The brief makes its dependencies honest in those sections individually; §7 reads as if those qualifications did not apply. A reader of §7 in isolation cannot see (a) every release is reviewer-pool-gated (F4), (b) every release is witness-pool-gated (F5), (c) v1.5+ depends on Briar continuity (F3), (d) v1.5+ depends on GrapheneOS-Pixel continuity (F7), (e) every release depends on distribution-channel policy (F8). The fix is not relitigating those points in §7 but adding a single cross-reference paragraph at §7.2 or §7.3 importing them.

**Pattern 2 — Upstream-protocol dependencies named for SimpleX/Tor/GrapheneOS but not Briar/Meshtastic/MeshCore/UnifiedPush.** §3.4 and §9.2 selectively name some upstream substrates as dependencies. The mesh radio protocols (F2), Briar (F3), and UnifiedPush (F9) are roadmap-dependent substrates not given equivalent treatment.

**Pattern 3 — Hardware-partnership ambiguity across §6.2, §7, and §10.5.** §6.2 says v4+, §10.5 says v3+ aspiration, §7 commits a v3 mesh release. This is the internal inconsistency form of dependency under-acknowledgment — the brief is unsure whether v3 mesh is software-only or hardware-partnership-dependent, and §7 picks the lower-dependency interpretation.

**Pattern 4 — Foundation existence assumed without naming.** The foundation is the prerequisite for v4's organizational tier (F6), for honoraria-funded reviewer pool (Section 8.2/F4), for formalized Safe Harbor (D0012), and for partner advisory authority (D0009). The foundation itself is conditional on Phase C funding. §7 does not import this conditionality at any release boundary where it matters.
