# Section 4 Adversarial Review — Consolidated Findings

**Date:** 2026-05-28
**Source:** Five parallel sub-agent reviews, distinct lenses (architecture summary accuracy, comparative fairness, first-time reader, cryptographic architect, trust roots & dependency visibility).
**Raw findings:** 51 across reviewers (Critical 17, Significant 23, Minor 11). After deduplication and theming: 26 consolidated findings below.
**Companion to:** [design-brief.md](design-brief.md) Section 4 (lines 240–294), with cross-references to Sections 2.3, 3.3, 3.4, 5, 6, 8, 9.

---

## Executive summary

Section 4 is the brief's orientation level — the place a first-time reader, a funder skim-reading, or a partner-organization technologist forms a working mental model of the product. Across all five lenses, §4 is rhetorically clean and architecturally coherent, and across all five lenses, the cleanliness is bought at the cost of fidelity to what §5–§10 actually specify. The same prose strengths that make §4 readable — present-tense framing, four-commitments compression, layer-shaped narrative, confident "no current product makes these commitments together" framing — are the prose properties that produce the dominant defect pattern: §4 promises a v1.5-or-later end-state product, while §5–§10 describe the v1 product the project actually ships.

The defect is uniform across lenses. The architecture-accuracy lens catches v1/v1.5 elision and operation-count compression. The first-time-reader lens catches present-tense framing of design-stage commitments and pools/partnerships described as operational when §8/§9 reveal they are pending recruitment. The cryptographic-architect lens catches verb inflation ("defeats," "eliminates") where §5 carefully says "raises the cost," "bounds," "layered." The comparative-fairness lens catches framing-by-exhaustion that omits AKD/CKV, Keybase, GrapheneOS's own release model, and Tails/Qubes as OS-tier comparators. The trust-roots lens catches dependency invisibility — Tor, GrapheneOS, SimpleX, Sigsum, OIDC, UnifiedPush, Rekor, F-Droid, Accrescent presented as Cairn-stack features rather than as upstream-maintained dependencies whose continued operation Cairn does not control.

The remediation is overwhelmingly prose-level. None of the findings require architectural change; nearly all require diction tightening, v1-versus-roadmap scoping, or one-sentence additions naming dependencies and conditions §4 elides. The brief's own §4.2 calibration principle ("'verified through chain of attestations' rather than 'secure'") indicts §4's own prose where present-tense unqualified verbs replace the qualified vocabulary §5 uses consistently. The single most-leveraged edit is a present-tense-to-v1-scoped sweep across §4.1 and §4.3; after that, individual finding-level edits close the remaining gaps. The overall posture of §4 — "the integration is the product" — is the correct framing and should be preserved; the calibration of that framing to v1 reality is what needs work.

---

## Consolidated findings table

| ID  | Severity    | Lens(es) | Short title                                                                                                                          | Citation                                                |
| --- | ----------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------- |
| F1  | Critical    | A, C, D  | v1/v1.5 elision (Briar, reproducible builds, in-app post-coercion) framed as v1 architecture                                         | §4.1:248–250, §4.3:281; vs §5.4:436, §5.5:482, §6.1:571 |
| F2  | Critical    | A, D     | Present-tense unqualified framing of pools/partnerships not yet recruited                                                            | §4.1:255, §4.3:283, §4.3:287; vs §8.2:736, §8.6:827     |
| F3  | Critical    | A, C, D  | Verb inflation: "defeat," "eliminate," "no trust" overstate §5's calibrated claims                                                   | §4.3:285, §4.3:287, §4.1:253; vs §5.3:414, §5.5:484     |
| F4  | Critical    | A, C, D  | Trust substitution (reviewer pool + witness pool + OIDC) framed as trust elimination                                                 | §4.3:287; vs §5.5:484, §5.5:488, §5.5:490               |
| F5  | Critical    | B, E     | "No current product makes these commitments together" overstates novelty against AKD/CKV/Keybase/Sigstore/GrapheneOS prior art       | §4.3:279, §4.3:283, §4.3:287                            |
| F6  | Critical    | E        | Operational infrastructure dependencies (UnifiedPush, Rekor, F-Droid, Accrescent) absent from §4                                     | §4 lines 240–294; vs §5.4:456, §5.5:480, §5.5:494       |
| F7  | Critical    | A, C     | Trust-graph operations enumerated as four; §5.2 specifies five (withdrawal/compromise split closes cascade-laundering attack)        | §4.1:253; vs §5.2:345, §5.2:352                         |
| F8  | Critical    | A, C, D  | Source-review vs. reproducible-builds v1→v1.5 transition omitted from release-security summary                                       | §4.1:255; vs §5.5:482, §5.5:496                         |
| F9  | Critical    | C, D     | "Bounded compromise" framing implies master is never exposed; §5.1 specifies reconstruction-window exposure and undefended evil-maid | §4.2:269, §4.1:257; vs §5.1:305, §5.1:311, §5.1:313     |
| F10 | Significant | E        | "Minimal project-operated infrastructure" understates dependence on third-party-operated infrastructure                              | §4.2:263; vs §3.4 trust roots                           |
| F11 | Significant | B, E     | "The components are standard" framing understates upstream-maintainer concentration and dependency-substitutability                  | §4.3:281, §4.3:291                                      |
| F12 | Significant | B        | Tails/Qubes absent despite §4.1 introducing OS-tier comparison                                                                       | §4.1:246, §4.3:279                                      |
| F13 | Significant | C, D     | Forward secrecy named without post-compromise security; at-rest reality understated                                                  | §4.2:271; vs §5.4:438                                   |
| F14 | Significant | C, D     | Sigsum "anchoring" claims need commitment-only precision                                                                             | §4.1:253; vs §5.2:372                                   |
| F15 | Significant | C, D     | Long-lived APK key contradicts "no single signing identity" differentiation                                                          | §4.3:287; vs §5.5:480, §5.5:498                         |
| F16 | Significant | D        | Briar "trust nothing" understates Briar's actual introduction-graph trust model                                                      | §4.3:283; vs §2.3:85                                    |
| F17 | Significant | A, B, C  | Messaging metadata "minimized at the protocol layer" elides server-coercion, multi-device queue correlation, push timing             | §4.1:257, §4.3:283; vs §5.4:442, §5.4:456               |
| F18 | Significant | B, E     | OIDC-jurisdiction trust placement absent from §4.3 release-security framing                                                          | §4.1:255, §4.3:287; vs §3.4:196, §5.5:488               |
| F19 | Significant | A, B     | Hardware-anchoring qualification (StrongBox/TEE) flattened in summary and principles                                                 | §4.1:257, §4.2:269; vs §4.1:246, §5.1:307               |
| F20 | Significant | B        | Matrix reduced to "a homeserver" understates Matrix's ongoing metadata-mitigation work                                               | §4.3:283; vs §2.3:79                                    |
| F21 | Significant | E        | Witness-pool correlation risk (shared between trust-graph and release-binary audit) not surfaced in §4                               | §4.2:263; vs §5.5:490, §9.3:914                         |
| F22 | Significant | A, C     | v1 recovery requires online Sigsum connectivity; absent from §4.3's social-recovery framing                                          | §4.3:285; vs §9.2:883                                   |
| F23 | Minor       | A        | Hardware element specificity (Titan M2) lost in §4 generic phrasing                                                                  | §4.1:246; vs §5.1:307                                   |
| F24 | Minor       | A        | "Three-tier identity" framing treats device-capability tokens as a keypair tier                                                      | §4.1:252; vs §5.1:317                                   |
| F25 | Minor       | B, E     | Berty, Threema, Wire absent from §2.3 and thus from §4 inheritance                                                                   | §4.3:279 (inherits §2.3)                                |
| F26 | Minor       | A, C     | SimpleX "no persistent user identity" needs the multi-device caveat                                                                  | §4.1:250; vs §5.4:442                                   |

---

# Critical Findings

## F1. v1/v1.5 elision: §4 framed as v1.5-or-later architecture, while §5–§6 specify v1 as substantially less

**Category:** Architecture summary accuracy / Roadmap honesty
**Lens(es):** Architecture-Accuracy F1, F3; First-Time-Reader F1; Cryptographic-Architect (compression pattern)
**Location:** §4.1:248–250 (Briar in communications layer); §4.1:255 (release-security stack); §4.3:281 (four-commitment list); cross-checks §5.4:436, §5.5:482, §6.1:571.

**Problem.** §4 describes the v1.5 architecture as if it were the v1 architecture. Three concrete cases:

- **Briar.** §4.1:248–250 names Briar inside the v1 communications-layer mental model with a v1.5 qualifier that is easy to miss; §4.3:281 lists "SimpleX, Briar, Tor, Sigstore, and Sigsum" with no v1/v1.5 split. §5.4:436 is explicit: "v1 ships SimpleX-only…For v1, users have one messaging tier." A scanning reader leaves §4 with a two-tier-mechanical mental model; §5.4:448 reveals v1 tiering is operational, not mechanical.
- **Reproducible builds.** §4.1:255 names "two-layer signing (long-lived APK key plus per-release Sigstore attestation), external reviewer pool of 5+ with 3-of-5 attestation threshold" without naming what reviewers attest to. §5.5:482 specifies "v1 ships with external source-code review…Reproducible builds…are deferred to v1.5." §5.5:496 names the explicit v1 supply-chain gap: a compromised build pipeline producing a malicious binary from clean source is not detected by v1's source-review.
- **In-app post-coercion, local trust-graph caching, offline recovery.** §4.3:285 frames recovery as a peer-only operation; §9.2:883 specifies v1 recovery additionally requires online Sigsum access. §5.2:366 defers local caching to v1.5.

**Evidence concentrated:** §4.1:250 "Briar joins as the highest-sensitivity tier in v1.5" vs. §5.4:436 "v1 ships SimpleX-only;…For v1, users have one messaging tier." §4.1:255 vs. §5.5:482 "External source-code review in v1; reproducible builds in v1.5." §4.3:285 vs. §9.2:883 "Recovery requires online connectivity to Sigsum in v1."

**Impact.** A first-time reader using §4 as their architecture summary forms a v1.5-or-later mental model and then experiences §5–§6's v1 scope cuts as surprise restrictions rather than as the design's honest staging. Funders and partners evaluating against §4 will believe Cairn ships a multi-protocol product with binary-equivalence release security; the v1 reality is single-protocol with source-attestation release security. The brief's own §4.2:273 calibration principle is violated by §4's own scoping prose.

**Recommendation.** Audit every architectural property §4 names. For each: (a) state v1 ships X, (b) state v1.5 adds Y. Mark every Briar mention with "(v1.5)" inline rather than only the first occurrence. Rewrite the §4.3 four-commitment list with explicit v1 framing — "v1 ships one of the two protocols; the two-tier mechanical property arrives in v1.5." Add "v1 reviewers attest to source review; v1.5 transitions to reproducible-build binary equivalence" to the release-security bullet. Add the online-Sigsum dependency to the recovery commitment.

---

## F2. Present-tense framing of pools and partnerships not yet recruited

**Category:** Commitment register / First-time-reader expectation
**Lens(es):** First-Time-Reader F2, F10; Architecture-Accuracy F5
**Location:** §4.1:255 "external reviewer pool of 5+ with 3-of-5 attestation threshold"; §4.3:283 "Cairn's trust graph is signed-operation-based with public auditability via Sigsum commitments and witness cosignatures"; §4.3:287 "exposes provenance to multiple independent verifiers"; cross-checks §8.2:736, §8.2:740, §8.6:827, §8.6:831, §9.1:867.

**Problem.** §4 frames the multi-party verification machinery — the reviewer pool, the partner-cosigned witness pool, the partner organizations — as operational architecture. §8.6:827 is explicit that these "are not confirmed partnership arrangements. Q5 (NGO partner outreach) tracks the conversations that will turn these intentions into agreements." §8.2:736 names "median interval between releases is 4-6 months" at volunteer baseline; honoraria are conditional on Q3 funding. §9.1:867 acknowledges "Reviewer and witness pools may not form or may erode."

**Evidence concentrated:** §4 uses uncalibrated present-tense across the release-security and trust-graph discussions for components §8 catalogues as pending recruitment. The §4.2:273 calibration principle endorses calibration for user-facing language; §4 itself uses uncalibrated present-tense framing for funding-conditional and recruitment-conditional commitments.

**Impact.** A funder reading §4.3 alone may believe the release-security claim is currently verifiable; it is currently a commitment to a recruitment process. A partner organization technologist may believe the witness cosignature system is shipping; it is a target architecture pending Q5 outreach. The mismatch between §4's diction and §8's catalogued conditionality damages credibility on the parts of §4 that are accurate.

**Recommendation.** Scan §4 for present-tense unqualified verbs and convert each to v1-specific framing. Specifically:

- §4.1:255 "external reviewer pool of 5+ with 3-of-5 attestation threshold" → "a reviewer pool the project commits to recruiting at 5+ with a 3-of-5 attestation threshold."
- §4.3:283 "Cairn's trust graph is signed-operation-based with public auditability via Sigsum commitments and witness cosignatures" → grammatically mark witness-pool as pending recruitment.
- §4.1:246 "The product is structured as three layers" → "The v1 design specifies three layers."
- §4.1:257 layer-summary verbs ("is," "are") → "the v1 design commits to."

---

## F3. Verb inflation across §4 — "defeats," "eliminates," "no trust" overstate §5's calibrated claims

**Category:** Calibration / Cryptographic precision
**Lens(es):** Cryptographic-Architect F1, F2, F3; Architecture-Accuracy F7; First-Time-Reader F4
**Location:** §4.3:285 ("defeat the attack chain"); §4.3:287 ("the user does not have to trust the developer's word"); §4.1:253 ("revocations" as one category); §4.2:269 (bounded compromise framing).

**Problem.** §5 carefully phrases claims as "raises the cost of," "bounds," "complicates," "layered resistance"; §4 swaps these for "defeats," "eliminates," "the user does not have to trust." Five specific cases:

- **§4.3:285 "defeat the attack chain":** D0005 itself rejects each mechanism individually; §5.3:418 calls the combination "layered resistance," not defeat. The attack chain succeeds against a continuous-control adversary who can hold the user 48 hours and extract the per-peer challenge.
- **§4.3:285 attack-chain framing:** The chain "unlock → peer enumeration → impersonation" succeeds if challenges are stored on the seized device (D0005:18 and §5.3:404 permit on-device hardware-backed password manager storage); §5.2:382 only excludes peer relationships from the public trust graph, not from on-device state.
- **§4.3:287 "does not have to trust the developer's word":** §5.5 specifies developer trust is replaced by (a) honest-majority assumption over the 5+ reviewer pool, (b) honest-majority assumption over the witness pool, (c) OIDC provider integrity (§5.5:488 explicitly names U.S. legal process in the trust surface). Trust is substituted, not eliminated.
- **§4.2:269 "bounded compromise through tier separation":** §5.1:305 specifies bounded-_window_ exposure; the master is reconstructed in active memory during provisioning and recovery. §5.1:313 "Evil-maid scenarios are not defended by the tier model."
- **§4.1:253 "revocations":** §5.2:345 specifies five operations; §4 collapses attestation withdrawal and key-compromise revocation, which §5.2:352 explicitly splits to address the cascade-laundering attack.

**Evidence concentrated:** §4.2:273 endorses "Calibrated language replaces absolute-sounding claims" — the brief's own principle indicts §4's own prose.

**Impact.** A cryptographic reviewer reading §4 and then §5 will register the gap. The credibility-erosion failure mode for a brief at this threat tier is precisely this: strong §4 claims that soften to bounded-resistance by §5. Funders who skim §4 will form expectations §5 does not support; partners who read both will conclude §4 is the marketing register and §5 is the technical truth, which damages the brief's stated register-of-honesty discipline.

**Recommendation.** Mechanical sweep of §4 for verbs of complete elimination; swap for the §5 vocabulary that already exists:

- §4.3:285 "defeat the attack chain" → "raise the cost of the unlock → peer enumeration → impersonation chain, with residual surfaces in §3.3 and §5.3."
- §4.3:287 "does not have to trust the developer's word" → "the user trusts the honest majority of an enumerated reviewer and witness pool plus the OIDC provider's jurisdictional posture, rather than the developer's single signing identity."
- §4.1:253 trust-graph enumeration → five operations matching §5.2:345; half-sentence noting withdrawal/compromise split closes cascade-laundering attack per D0006.
- §4.2:269 lead sentence → restructure to lead with bounded-window framing; present tier separation as the mechanism that makes the window bounded.

---

## F4. Trust substitution framed as trust elimination

**Category:** Trust placement / Cryptographic precision
**Lens(es):** Cryptographic-Architect F3; Trust-Roots F5; First-Time-Reader F2
**Location:** §4.3:287; cross-checks §5.5:484 (reviewer threshold), §5.5:488 (OIDC jurisdiction), §5.5:490 (shared witness pool).

**Problem.** This is the cleanest case of F3's broader pattern and deserves dedicated treatment. §4.3:287 "the user does not have to trust the developer's word that a release is genuine; the user (or anyone) can check the public record" implies developer trust is _eliminated_. §5.5 specifies developer trust is _replaced with_ a distributed trust set: reviewer pool (honest-majority over 5+), witness pool (honest-majority, with §5.5:490 explicitly acknowledging shared witness pool as correlation risk affecting both trust-graph and release-binary integrity simultaneously), and OIDC provider integrity (§5.5:488 explicitly names U.S. legal process in the effective trust surface).

The trust-roots lens (F5, F6) connects this to broader §4 framing: §4.2:263 "minimal project-operated infrastructure" reads as low-dependency; §4.3:281 "the components are standard" reads as substitutable. The actual architecture distributes trust across a network of upstream projects whose continued operation Cairn does not control.

**Impact.** Funders and partner-organization technologists evaluating residual trust will form expectations that §5 does not support. The OIDC-jurisdiction question specifically is the kind partner organizations in EU jurisdictions may consider disqualifying. The framing is also strategically self-defeating: the actual distributed-trust architecture is more interesting and more defensible than the elimination framing claims.

**Recommendation.** Rephrase §4.3:287 to name the substitution: "the user trusts the honest majority of an enumerated reviewer and witness pool plus the OIDC provider's jurisdictional posture, rather than the developer's single signing identity. The trust is distributed and publicly auditable, not eliminated." Add parenthetical cross-reference to §3.4's OIDC trust-root entry at every §4 Sigstore mention (§4.1:255, §4.3:281, §4.3:287). For the witness-pool correlation, add a sentence to §4.2:263 naming the shared-witness-pool concentration as the specific consequence accepted in v1.

---

## F5. "No current product makes these commitments together" overstates novelty against existing prior art

**Category:** Comparative fairness / Differentiation framing
**Lens(es):** Comparative-Fairness F1, F2; Trust-Roots F7 (related)
**Location:** §4.3:279, §4.3:283, §4.3:287.

**Problem.** §4.3:279 frames four commitments "no current product in the landscape makes together." The framing depends on §2.3 as comparator survey, but several of the four commitments have closer prior art than §4 acknowledges:

- **Transparency-logged trust state** (§4.3:283): WhatsApp's Auditable Key Directory (shipped to billions since 2023) and iMessage Contact Key Verification (shipped since 2023) both use transparency logs to make key state publicly auditable. Keybase's signed-statement-chain model with public auditability is also prior art. CONIKS / Key Transparency is the academic origin. None is Cairn (no social attestation graph, no master-tier separation, different threat tier) but all are in the same architectural family.
- **Multi-party publicly-verifiable release security** (§4.3:287): GrapheneOS — which Cairn _runs on_ — uses a multi-signer release process with public verification and is the closest comparator for "multi-party publicly-verifiable Android release security." Briar has reproducible builds since 2017. Signal Android publishes reproducible builds. F-Droid (named as a v1 distribution channel in §4.2:263) is structurally a third-party rebuild/resign pipeline that is itself a form of independent attestation. Sigstore-style transparency-logged signing is increasingly standard in open-source supply chains.
- **"Most existing tools…" framing** (§4.3:283, §4.3:287): Lines 283 and 287 use "Most existing tools either X or Y or Z" framings where the three options are presented as exhaustive. The actual comparator set is broader.

**Evidence concentrated:** The genuinely-novel parts are the 5-of-N external reviewer attestation threshold and the integration with a social attestation graph. The supporting infrastructure (reproducible builds, transparency-logged signing, Sigsum anchoring) has prior art.

**Impact.** §4.3's strongest "no one else does this" framing rests on sentences that are partially inaccurate. Reviewers from GrapheneOS, Briar, or supply-chain-security communities will read these as either not knowing the comparator landscape or selectively presenting it. Either reading damages credibility on the other commitments, which are stronger. The trust-roots lens connects this to the F11 "components are standard" framing — the differentiation argument leans harder than §2.3's careful per-product framing supports.

**Recommendation.** Narrow each claim to what is actually distinct:

- §4.3:283 widen comparator set to include AKD/CKV/Keybase/CONIKS; distinguish Cairn within that family (Cairn attests _social structure_, AKD attests _key continuity_; Cairn anchors in Sigsum + witness cosignatures rather than a vendor-operated log). Or narrow the claim to "a transparency-logged _social_ trust graph available to clients facing this threat tier."
- §4.3:287 acknowledge GrapheneOS, Briar reproducible builds, and Sigstore prior art explicitly; narrow the distinct claim to the 5-of-N external reviewer attestation threshold _on top of_ standard reproducible-build/transparency-log practices.
- Replace "Most existing tools either X or Y or Z" framings with "no current product combines [specific Cairn-distinctive properties]" — which is what §4.3:279's framing was trying to do before lines 283 and 287 narrowed it.
- §4.3:283 Briar characterization: replace "trust nothing (Briar's pure peer-to-peer model)" with "trust a locally-rooted introduction graph without public auditability (Briar)" — accurate, preserves the differentiation, consistent with §2.3:85.

---

## F6. Operational dependencies (UnifiedPush, Rekor, F-Droid, Accrescent) absent from §4

**Category:** Trust placement / Dependency visibility
**Lens(es):** Trust-Roots F4, F6
**Location:** §4 lines 240–294 (search of section returns zero hits for UnifiedPush, Rekor; one-passing-mention each for F-Droid and Accrescent at §4.2:263); cross-checks §3.4:196, §5.4:456, §5.5:480, §5.5:494, §6:957.

**Problem.** §4 names architectural-layer dependencies (Tor, SimpleX, Briar, Sigstore, Sigsum, GrapheneOS-on-Pixel) but omits operational-infrastructure dependencies the brief elsewhere acknowledges:

- **UnifiedPush** — Cairn's push protocol per §5.4:456; named at §6 as a metadata-channel surface; absent from §4.
- **Rekor** — Sigstore's transparency log infrastructure per §5.5:480; named at §6:957 as a "Sigstore-specific operational risk" with single-operator log model; absent from §4.
- **F-Droid and Accrescent** — primary v1 distribution channels per §5.5:494; mentioned once at §4.2:263 in passing but not as dependencies whose compromise or discontinuation affects the architecture.
- **OIDC provider** — §3.4:196 names as a trust root with explicit jurisdictional implication; §4 references Sigstore three times (§4.1:255, §4.3:281, §4.3:287) and never cross-references the OIDC-jurisdiction trust placement.

The dependencies §4 omits are the ones that don't fit the architectural-layer model — they are operational infrastructure, not architectural layers. §4's layer-shaped narrative has no obvious slot for them, so they fall out.

**Impact.** §4 is the section that orients a reviewer to "what does this product look like." A reader who reads §4 and stops (which §4.1:244 invites: §4 is "the orientation level") leaves with no awareness of v1's dependency on (a) UnifiedPush distributor availability and the UnifiedPush protocol team's continued maintenance, (b) Rekor's single-operator transparency log model, (c) F-Droid's app-review pipeline and signing process, (d) Accrescent's continued development as a distribution channel, or (e) the OIDC provider's jurisdiction (which partner organizations may consider disqualifying). All five are v1-central; at least four add jurisdictional or maintainer-health exposure §3 touches.

**Recommendation.** Add a short "v1 external dependency surface" paragraph in §4.1 or §4.2 enumerating the dependencies beyond Tor/SimpleX/Briar/Sigstore/Sigsum/GrapheneOS — specifically: UnifiedPush (protocol + distributor), Rekor (Sigstore's log infrastructure), F-Droid and Accrescent (distribution channels), OIDC provider (jurisdiction). Cross-reference §3.4 for trust-root framing. The §4.2:263 "minimal project-operated infrastructure" paragraph is the most natural location.

---

## F7. Trust-graph operations enumerated as four; §5.2 specifies five (withdrawal/compromise split is load-bearing)

**Category:** Architecture summary accuracy / Cryptographic precision
**Lens(es):** Architecture-Accuracy F2; Cryptographic-Architect (compression pattern)
**Location:** §4.1:253; cross-checks §5.2:345, §5.2:352, §5.2:374.

**Problem.** §4.1:253 lists "attestations, revocations, introductions, and key rotations" — four operation types. §5.2:345 specifies five: attestation, attestation withdrawal, key compromise revocation, introduction, key rotation. §5.2:352 explicitly states "The split between withdrawal and compromise revocation is specified in D0006 and addresses the cascade-laundering attack identified in the Section 5 adversarial review."

**Evidence concentrated:** The split is not editorial — it is the architectural fix for the cascade-laundering attack and the basis of the soft-vs-hard quarantine semantics in §5.2:374–380.

**Impact.** A reader who internalizes §4's four-operation model will not understand why §5.2 has two distinct cascade behaviors. This is precisely the "claim invention vs. understatement" failure mode the architecture-accuracy lens is designed to catch: §4 understates what §5 actually does, eliminating an architectural decision that closes a named attack.

**Recommendation.** Rewrite §4.1:253's enumeration: "attestations, attestation withdrawals, key-compromise revocations, introductions, and key rotations" — five operations matching §5.2:345. Add a half-sentence noting the withdrawal/compromise split closes a specific cascade-laundering attack per D0006.

---

## F8. v1 source-review vs. v1.5 reproducible-builds transition omitted from release-security summary

**Category:** Architecture summary accuracy / Roadmap honesty
**Lens(es):** Architecture-Accuracy F3; First-Time-Reader F5; Cryptographic-Architect (compression pattern)
**Location:** §4.1:255; cross-checks §5.5:482, §5.5:496.

**Problem.** §4.1:255 names "two-layer signing (long-lived APK key plus per-release Sigstore attestation), external reviewer pool of 5+ with 3-of-5 attestation threshold, multi-channel distribution" without specifying _what_ reviewers attest to. §5.5:482 specifies "v1 ships with external source-code review…Reproducible builds…are deferred to v1.5." §5.5:496 names the explicit v1 supply-chain gap: "reviewer attestations are over source code, which means a compromised build pipeline that produced a malicious binary from the same source would not be detected by source-review alone."

**Evidence concentrated:** A first-time reader will assume reviewers verify binary/build artifacts (the modern default for projects that brand "reproducible builds"). §5.5 explicitly carves out a v1 supply-chain gap that v1.5 closes — a material limitation that affects how partners and pilot users evaluate v1 release security.

**Impact.** Pilot users are using a release stream whose build pipeline is not independently verified against source. §4.3:287's "the user does not have to trust the developer's word" framing depends on this verification, which v1 does not have. Combined with the audit-after-pilot timing (F4 of sections-8-9-review.md), v1 pilot deployment runs with two compounding release-security gaps not visible in §4.

**Recommendation.** Add "v1 reviewers attest to source review; v1.5 transitions to reproducible-build binary equivalence" to §4.1:255's release-security bullet. Add a sentence to §4.3:287 acknowledging that v1's "publicly verifiable" property is over source, with v1.5 extending to binary equivalence.

---

## F9. "Bounded compromise" framing implies master is never exposed; §5.1 specifies reconstruction-window exposure and undefended evil-maid

**Category:** Cryptographic precision / Threat-model honesty
**Lens(es):** Cryptographic-Architect F5; First-Time-Reader F4; Architecture-Accuracy F8
**Location:** §4.2:269 (bounded compromise paragraph); §4.1:257 ("master identity is never on the device in routine operation"); cross-checks §5.1:305, §5.1:311, §5.1:313, §9.3:939.

**Problem.** §4.2:269 leads with "No single credential gives an adversary access to everything…Compromise at one tier bounds rather than collapses the user's cryptographic position." §4.1:257 says "the user's master identity is never on the device in routine operation." Both framings imply the master is structurally separated. §5.1:305 explicitly names "Bounded-window exposure, not zero exposure. The reconstruction window itself is the master's exposure surface: the seed exists in active memory during provisioning and recovery." §5.1:311 names "Rotation under coercion is itself a vulnerable moment…the master is reconstructed in active memory on the device under coercion." §5.1:313 names "Evil-maid scenarios are not defended by the tier model." §9.3:939 names endpoint-surface compromise yielding "the operational identity, on-device message history, and contact list."

**Evidence concentrated:** §4.2:269 does close with "bounded-window exposure, not zero exposure" — but the lead sentence frames tier separation as the bounding mechanism, when in fact tier separation _plus operational discipline about when reconstruction happens_ is the bounding mechanism. The lead sentence is what readers retain; the closing qualifier is what §5.1 supports.

**Impact.** A first-time reader leaves §4 believing the tier model is the architectural answer to seizure; §5.1 reveals it is the answer to one specific class of seizure (no implant present at provisioning/recovery, no evil-maid, no zero-click). The framing optimizes the reader's takeaway toward a stronger claim than §5.1 supports. This is the single largest operational property the v1 product is exposed on, and §4 gives it less weight than §5.1 carries.

**Recommendation.** Restructure §4.2:269 to lead with the bounded-window framing: "Tier separation makes compromise _bounded in scope and time_ rather than total: outside the brief reconstruction windows at provisioning and recovery, the master is not on the device to extract." Add one sentence naming undefended cases: "The model defends the master across routine device operation; compromise during the reconstruction window (provisioning, recovery, rotation) and compromise of a device with a resident implant or evil-maid presence are addressed in §5.1 as residual surfaces." Append "(provisioning and recovery are bounded-window exposure moments; see §5.1)" to §4.1:257's master-not-on-device claim.

---

# Significant Findings

## F10. "Minimal project-operated infrastructure" understates dependence on third-party-operated infrastructure

**Lens(es):** Trust-Roots F6; First-Time-Reader F3 (related)
**Location:** §4.2:263; cross-checks §3.4 trust roots, §6.3:630.

**Problem.** §4.2:263 says "a Cairn deployment continues to function for its existing users if the project disappears." The statement is bounded to "project infrastructure" but a reader will hear "infrastructure." The principle's actual semantic content is that Cairn substitutes third-party-operated infrastructure (Tor relays, SimpleX servers, Sigsum witnesses, Sigstore/Rekor, UnifiedPush distributors, F-Droid mirrors) for project-operated infrastructure. "Continues to function if the project disappears" is true only if the third-party infrastructure continues to function. Additionally, §6.3:630 reveals v1 pilot operates with the developer concentrated in three trust roles simultaneously: image preparer, application installer, and provisioning facilitator — a concentration §4.2's "audit-friendly surfaces" framing understates.

**Recommendation.** Reframe the principle as "trust distributed across multiple third-party-operated infrastructures rather than concentrated in project-operated infrastructure" and explicitly name the third-party infrastructures the user depends on. Add a sentence acknowledging that v1 pilot operations specifically concentrate trust in the developer-as-facilitator for the duration of the pilot, with the principle's full posture taking effect post-pilot when partner-facilitated provisioning lands.

---

## F11. "The components are standard" understates upstream-maintainer concentration

**Lens(es):** Comparative-Fairness (related); Trust-Roots F7
**Location:** §4.3:291, §4.3:281.

**Problem.** §4.3:291 says "the components are standard." "Standard" suggests substitutable, broadly maintained, low-risk components. The upstream picture: SimpleX has a small core team; Briar's protocol work has narrow contributor depth; Sigsum is a small Swedish project; Tor's anti-censorship work is grant-funded with periodic continuity scares; GrapheneOS is a small team. The framing carries sustainability and substitutability connotations that don't match upstream reality.

**Recommendation.** Replace "the components are standard" with framing that names what Cairn is actually claiming — that the cryptographic primitives are standard and that the protocol substrates are externally maintained projects whose continued operation Cairn depends on. The §4.3:281 "delegated" framing is closer to honest but needs to land in the closing paragraph too.

---

## F12. Tails and Qubes absent despite §4.1 introducing OS-tier comparison

**Lens(es):** Comparative-Fairness S1
**Location:** §4.1:246 establishes endpoint layer as GrapheneOS-on-Pixel; §4.3:279 frames novelty without acknowledging OS-tier comparators.

**Problem.** §4.1:246 treats the OS as part of Cairn's trust placement, not just an environment. §4.3:279's "no current product in the landscape makes these four commitments together" implicitly defines "the landscape" as messaging-products-only, even though the brief's own architecture is a phone-OS-plus-messaging integration that overlaps materially with what Tails and Qubes do for the same audience. Tails is the canonical "operational-discipline-as-a-product" tool for the journalist/activist audience §2.2 names. Qubes is the canonical "compartmentation as a security property" tool. A reviewer asking "how is this different from a Tails-equivalent for messaging on a phone" gets no answer.

**Recommendation.** Add one paragraph in §4.3 explicitly distinguishing Cairn from Tails/Qubes: different threat surface (always-on messaging device vs. session-bounded amnesia OS vs. compartmented workstation), different operational unit (facilitator-supported individual vs. trained user vs. technical user), different trust placement (GrapheneOS + hardware vs. Debian + verified boot media vs. Xen + AEM).

---

## F13. Forward secrecy named without post-compromise security; at-rest reality understated

**Lens(es):** Cryptographic-Architect F4; First-Time-Reader F8
**Location:** §4.2:271; cross-check §5.4:438, §9.3:939.

**Problem.** §4.2:271 names FS via SimpleX's double-ratchet derivative. §5.4:438 specifies SimpleX provides "forward secrecy _and post-compromise security_…past traffic cannot be decrypted if a current session key is compromised, _and_ the protocol self-heals via the asymmetric ratchet step after compromise." §4.2 names only the FS half. PCS bounds forward damage of session-key compromise; FS bounds backward damage. For the state-actor / Pegasus tier, PCS is arguably the more operationally relevant property.

Separately: §4.2:271 names the at-rest limit but mid-sentence after a longer FS claim; §9.3:939 specifies endpoint compromise yields the full conversation history. The largest single operational property the v1 product is exposed on gets half a clause in §4.

**Recommendation.** Add PCS to §4.2:271: "On-wire message content is forward-secret _and post-compromise-secure_ via SimpleX's double-ratchet derivative." Promote the at-rest limit to its own sentence or dedicated bullet.

---

## F14. Sigsum "anchoring" needs commitment-only precision

**Lens(es):** Cryptographic-Architect F6; Architecture-Accuracy F12
**Location:** §4.1:253; cross-check §5.2:372.

**Problem.** §4.1:253 says trust graph is "anchored in Sigsum commitments." Technically correct but underspecifies: per §5.2:372, Sigsum holds _commitments_ (hashes) of operations, not operation content. A reader who skips §5.2 might infer Sigsum is the propagation channel, when propagation is via SimpleX user-to-user traffic (§5.2:368) and Sigsum is the audit anchor. The commitment-only property is also what addresses the "Public transparency-log metadata" surface, which §4 does not mention.

**Recommendation.** Inline "anchored in commitment-only entries in Sigsum (hashes of operations, not operation content, keeping issuer/subject/context out of public view, per §5.2)."

---

## F15. Long-lived APK key contradicts "no single signing identity" differentiation

**Lens(es):** First-Time-Reader F9; Cryptographic-Architect (related to F3)
**Location:** §4.3:287; cross-checks §5.5:480, §5.5:498, §9.3:911.

**Problem.** §4.3:287 contrasts Cairn with "tools rely on a single signing identity…whose compromise affects every release indefinitely." §5.5:480 specifies Cairn does hold a long-lived APK signing identity ("APK signature continuity"); §5.5:498 specifies compromise of the long-lived APK key requires "APK Signature Scheme v3 key rotation. All installed clients must process the rotation in an update before subsequent updates can be signed by the new key. This is a multi-release recovery process." §4.3 oversells the difference from the comparison set.

**Recommendation.** Acknowledge the APK-signing-key reality in §4.3:287 and frame the multi-party property as additional verification atop the platform-required signing layer, not as elimination of the single-signing-identity surface.

---

## F16. Briar "trust nothing" understates Briar's actual introduction-graph trust model

**Lens(es):** Comparative-Fairness S2
**Location:** §4.3:283; cross-check §2.3:85.

**Problem.** §4.3:283 characterizes Briar as "trust nothing…each pair of users handles verification themselves." Briar's actual trust model includes introduction protocol (mutual contact cryptographically introduces two users), BQP (Bramble Question Protocol) for shared-secret verification, and forums/private groups with membership cryptographically rooted in introducer signatures. This is not "trust nothing"; it is small-scale graph-shaped trust without a transparency log. §2.3:85 is more careful; §4.3 is not.

**Recommendation.** Replace "trust nothing (Briar's pure peer-to-peer model)" with "trust a locally-rooted introduction graph without public auditability (Briar)" — accurate, preserves the differentiation (Sigsum anchoring + witness cosignatures), consistent with §2.3:85.

---

## F17. Messaging metadata "minimized at the protocol layer" elides server-coercion, multi-device queue correlation, push timing

**Lens(es):** Architecture-Accuracy F7; Comparative-Fairness (related); Cryptographic-Architect F8
**Location:** §4.1:257, §4.3:283; cross-checks §5.4:442, §5.4:456.

**Problem.** §4.1:257 says "messaging metadata is minimized at the protocol layer." §5.4:442 specifies "SimpleX is not a complete answer. A user who connects multiple devices to the same set of queues creates correlatable activity at those queues…A server…can be coerced, compromised, or compelled to retain logs." §5.4:456 specifies "a push distributor…sees the timing of notifications delivered to a user even when it cannot see the content." Multiple residual leaks the protocol does not minimize.

§4.3:283 inherits the simplification by naming Matrix as "a homeserver" single-trust-point caricature without acknowledging Matrix's ongoing metadata-mitigation work (F20).

**Recommendation.** Soften §4.1:257 to "messaging metadata is minimized **at the protocol layer subject to specific residual leaks named in §5.4** (server coercion, multi-device queue correlation, push timing)." Matches §4.2's stated calibration principle.

---

## F18. OIDC-jurisdiction trust placement absent from §4.3 release-security framing

**Lens(es):** Trust-Roots F5; Comparative-Fairness (related)
**Location:** §4.1:255, §4.3:281, §4.3:287; cross-check §3.4:196, §5.5:488.

**Problem.** §4 references Sigstore three times and never cross-references the OIDC-jurisdiction trust placement. §3.4:196 names the OIDC identity provider as a trust root with explicit jurisdictional implication. §5.5:488 specifies the v1 OIDC provider is U.S.-based "with the explicit acknowledgment that this places U.S. legal process in the effective trust surface." A partner organization in an EU jurisdiction may consider this disqualifying; a reader of §4 alone will not surface this question.

**Recommendation.** Add parenthetical cross-reference to §3.4's OIDC trust-root entry at every §4 Sigstore mention. Specifically tag §4.3:287 with the OIDC-jurisdiction substitution per F4 above.

---

## F19. Hardware-anchoring qualification (StrongBox/TEE) flattened in summary and principles

**Lens(es):** Architecture-Accuracy F4; First-Time-Reader F11
**Location:** §4.1:257, §4.2:269; cross-check §4.1:246, §5.1:307.

**Problem.** §4.1:246 qualifies correctly ("StrongBox-backed where Ed25519 is supported, TEE-backed otherwise"). §4.2:269 and §4.1:257 collapse the qualification to "the operational identity is hardware-gated and rotatable." StrongBox (Titan M2, a discrete secure element) and TEE (in the application processor) have materially different threat properties. A reader who only reads the principles or summary will assume uniform StrongBox guarantees.

**Recommendation.** Either (a) add "where supported, otherwise TEE-backed" to §4.2:269's hardware-gated mention, or (b) at minimum make §4.1:257 read "the operational identity is hardware-element-gated (StrongBox where Ed25519-supported, TEE-backed otherwise)."

---

## F20. Matrix reduced to "a homeserver" understates ongoing metadata-mitigation work

**Lens(es):** Comparative-Fairness S4
**Location:** §4.3:283; cross-check §2.3:79.

**Problem.** §2.3:79 characterizes Matrix accurately as currently-deployed; §4.3:283 inherits "a Matrix homeserver" as the single-trust-point example. Matrix has shipped multiple protocol-level mitigations (Pinecone overlay, lower-metadata homeservers, MSC for low-bandwidth and decentralized account portability). The characterization is accurate as v1-current-deployment but elides that Matrix-the-project treats this as a known design problem with active mitigation work.

**Recommendation.** No change required in §4 itself; if §2.3 is revised, add "Matrix's ongoing protocol work explicitly addresses metadata exposure" so §4's compressed reference inherits a fairer framing.

---

## F21. Witness-pool correlation risk not surfaced in §4

**Lens(es):** First-Time-Reader F6; Trust-Roots (related to F5)
**Location:** §4.2:263; cross-checks §5.5:490, §9.3:914.

**Problem.** §4.2:263 says "The release-security stack, partner-cosigned witness set, and a subset of distribution channels remain project-coordinated, with their consequences acknowledged in Section 3.4 trust roots rather than denied." §5.5:490 specifies the specific consequence: "The shared witness pool is acknowledged as a correlation risk in Section 3.4: compromise of enough witnesses to break log integrity defeats both the trust-graph audit and the release-binary audit at once." §4.2's generic "consequences acknowledged" hides the specific shared-pool concentration.

**Recommendation.** §4.2 should name the shared-witness-pool concentration as the specific consequence accepted in v1 — one of the named, audit-friendly surfaces, not a residual cost hidden under generic acknowledgment.

---

## F22. v1 recovery requires online Sigsum connectivity; absent from §4.3 social-recovery framing

**Lens(es):** First-Time-Reader F7; Architecture-Accuracy (related to F1)
**Location:** §4.3:285; cross-check §9.2:883.

**Problem.** §4.3:285 frames recovery as a peer-only operation. §9.2:883 specifies "Recovery requires online connectivity to Sigsum in v1. The v1 trust-graph evaluation queries Sigsum directly (per D0004); a user offline at the moment of recovery cannot evaluate new attestations they have not yet seen. v1.5 adds local caching that mitigates the most common case but does not address full-offline recovery." For the audiences §2.2 names (organizers in jurisdictions with active internet disruption), this is a meaningful gap §4.3 does not surface.

**Recommendation.** Add to §4.3:285 that v1 recovery requires online Sigsum access in addition to peer reach, with v1.5 adding offline-tolerant caching.

---

# Minor Findings

- **F23.** §4.1:246 uses "StrongBox-backed hardware element"; §5.1:307 specifies "Titan M2 secure element." Specificity helps connect §4's Pixel-only constraint to a specific hardware property. Optional addition. (Architecture-Accuracy F10)

- **F24.** §4.1:252 names "three-tier identity model (master → operational → device)"; §5.1:317 treats the third tier as device-scoped capability tokens (signed delegations), not a third user-keypair. Consider "master identity → operational identity → device-scoped capability tokens" to mirror §5.1's structure. (Architecture-Accuracy F11)

- **F25.** Berty, Threema, Wire absent from §2.3 and thus inherited absence in §4. Berty is the closest current product to "messaging stack designed to survive infrastructure disruption" (§2.2's v3 audience). Threema (Swiss jurisdiction, identifier-less) and Wire (MLS-based) are reasonable comparators for "identity not tied to phone number" and "non-US jurisdiction matters." Fix in §2.3, not §4. (Comparative-Fairness S3, M2)

- **F26.** §4.1:250 SimpleX "no persistent user identity at the protocol level" needs multi-device caveat from §5.4:442. v1 is single-device per D0007, so the caveat doesn't apply at v1 — but §4 makes architectural commitments that read forward to v2 multi-device. Add "in the v1 single-device configuration." (Cryptographic-Architect F8)

---

# Patterns

**P1. v1-vs-v1.5 elision is §4's dominant defect.** Caught by Architecture-Accuracy, First-Time-Reader, and Cryptographic-Architect lenses. §5 stages many architectural properties as "v1 ships X, v1.5 adds Y": SimpleX-only vs. SimpleX+Briar (§5.4:436), source review vs. reproducible builds (§5.5:482), no local CRDT vs. cached operations (§5.2:366), no extra-private toggle vs. toggle with tooltip (§5.4:448–450), documentation-based vs. in-app post-coercion recovery (§5.6:522), online-Sigsum-only vs. cached offline recovery (§9.2:883). §4 treats most of these as if the v1.5 state is the architecture. A reader who takes §4 as the architectural summary forms a v1.5-or-later mental model and then encounters §5's v1 scope cuts as surprise restrictions rather than as the design's honest staging.

**P2. Verb inflation at the §4 layer.** Caught by Cryptographic-Architect, Architecture-Accuracy, First-Time-Reader lenses. Statements that §5 carefully phrases as "raises the cost of," "bounds," "complicates," or "layered resistance" become "defeats," "eliminates," or "the user does not have to trust" at §4. This is the inverse of the calibration §4.2:273 commits to ("Calibrated language replaces absolute-sounding claims"). The brief's own principle indicts its own §4 prose. Resolution is mechanical: scan §4 for verbs of complete elimination and swap them for the §5 vocabulary that already exists.

**P3. Trust-substitution framed as trust-elimination.** Caught by Cryptographic-Architect and Trust-Roots lenses. F4 is the clearest case (developer-trust replaced by reviewer + witness + OIDC trust, framed as eliminated). The integrated product replaces _one_ trust placement (developer signing identity, master-key custody) with _a distributed set_ of trust placements. The cryptographic and operational arguments for this substitution are strong — but §4 sometimes frames substitution as elimination, which is both less defensible and less interesting than the actual architectural commitment.

**P4. Present-tense framing of design-stage architecture.** Caught by First-Time-Reader, Architecture-Accuracy, Trust-Roots lenses. §4 describes the design as if it ships. §6, §8, §9, §10 reveal what ships in v1 vs. v1.5 vs. v2, what is funded vs. aspirational, what is committed vs. conditional. The diction does most of the misleading; converting present-tense unqualified verbs to v1-specific framing closes most of the gap without changing substance.

**P5. Dependency invisibility — Cairn properties framed as Cairn properties, not inherited properties.** Caught by Trust-Roots lens primarily, with cross-cuts from Comparative-Fairness. Tor's DPI-evasion roadmap, SimpleX's metadata-resistance roadmap, GrapheneOS's continued maintenance, Sigstore's OIDC chain — each is presented as a Cairn-stack feature rather than as an inherited dependency. Operational infrastructure (UnifiedPush, Rekor, F-Droid, Accrescent, OIDC) is absent from §4 entirely. A small linguistic shift (from "Cairn does X" to "Cairn integrates X's X") in §4.1 and §4.3 closes most of this gap without restructuring.

**P6. Operation/property compression that loses load-bearing distinctions.** Caught by Architecture-Accuracy and Cryptographic-Architect lenses. §4 names collective categories ("revocations," "two-layer signing," "metadata minimized") where §5 specifies a split that does load-bearing work — the withdrawal-vs-compromise-revocation split closes the cascade-laundering attack; the source-review-vs-reproducible-builds split is the v1 supply-chain gap; the FS-without-PCS naming omits the operationally-relevant self-healing property. The compression is editorially defensible at the §4 abstraction level, but readers who treat §4 as the architecture summary lose the distinctions §5 makes specifically because the design depends on them.

**P7. Framing-by-exhaustion in §4.3 comparator sentences.** Caught by Comparative-Fairness lens. Lines 283 and 287 both use "Most existing tools either X or Y or Z" framings where the three options are presented as covering the space. AKD/CKV (shipping to billions today), Keybase, GrapheneOS's own release model, F-Droid's resign pipeline, Briar's reproducible builds, and Sigstore-the-standard exist in the gap between the named options. The fix is uniform: replace "most existing tools either X or Y or Z" with "no current product combines [specific Cairn-distinctive properties]" — which is what §4.3:279's framing was trying to do before lines 283 and 287 narrowed it.

**P8. §3.4 → §4 asymmetry: §3.4 is more honest than §4.** Caught by Trust-Roots and First-Time-Reader lenses. Where §3.4 names the OIDC provider's jurisdiction as a trust placement, §4 mentions Sigstore three times without cross-referencing it. Where §3.4 acknowledges shared witness pool as correlated trust, §4.2 names witness sets as "consequences acknowledged in Section 3.4 trust roots" without naming the specific consequence. The reader who reads only §4 forms a less-honest picture of Cairn's trust placements than the reader who reads §3.4. §4 should not regress §3.4's honesty.

---

# Recommended action plan

Findings break into four action categories:

**A. Prose edits to §4 — surgical, straightforward.**

The single highest-leverage edit is a present-tense-to-v1-scoped sweep across §4.1 and §4.3. Most of P1, P2, P4 close with diction changes:

- F1 (v1/v1.5 explicit marking throughout §4.1, §4.3 four-commitment list, §4.3:285 recovery), F2 (reviewer/witness/partnership present-tense → "commits to recruiting"), F3 (verb-inflation sweep: "defeat" → "raise the cost of," "does not have to trust" → "trusts a distributed set"), F4 (trust substitution naming at §4.3:287 with §3.4 cross-reference), F7 (five operations at §4.1:253), F8 (source-review-vs-reproducible-builds qualifier at §4.1:255), F9 (bounded-window framing leads §4.2:269), F13 (PCS added at §4.2:271; at-rest limit promoted to dedicated sentence), F14 (commitment-only precision at §4.1:253), F15 (APK-key reality acknowledged at §4.3:287), F16 (Briar characterization corrected at §4.3:283), F17 (metadata residual leaks at §4.1:257), F18 (OIDC cross-reference at every Sigstore mention), F19 (StrongBox/TEE qualifier at §4.1:257 and §4.2:269), F21 (shared-witness-pool consequence named at §4.2:263), F22 (online-Sigsum-recovery noted at §4.3:285).

**B. Structural additions to §4 — small new content.**

- F6 (UnifiedPush/Rekor/F-Droid/Accrescent dependency paragraph in §4.1 or §4.2:263).
- F10 ("minimal project-operated" reframed as "trust distributed across third-party-operated infrastructures"; v1 pilot facilitator concentration acknowledged).
- F11 ("components are standard" reframed to name upstream-maintainer concentration).
- F12 (Tails/Qubes comparison paragraph in §4.3).

**C. Items needing decisions in §2.3 not §4.**

- F20 (Matrix mitigation work added in §2.3:79 to inherit fair framing).
- F25 (Berty, Threema, Wire added to §2.3 with rationale for setting aside).

**D. Items for open-questions or new decision documents.**

None of the §4 findings require new decision documents on the scale of D0008–D0012 from the §8–§9 review. The §4 defect is rhetorical, not architectural; the architectural decisions §4 should reflect are already made in §5 and the existing D-series. The one possible exception:

- **Open Question Q-§4.1: OIDC-provider jurisdiction selection.** §5.5:488 acknowledges U.S. legal process in the trust surface; partner-organization technologists in EU jurisdictions may consider this disqualifying. The decision is logically prior to §4.3:287's "publicly verifiable" framing. Possible open question for §10 cataloguing.

**E. Items to reject.**

- F25 (Berty/Threema/Wire) is a minor-severity finding; if §2.3 is not being revised, leaving §4 inheriting the current §2.3 set is defensible. The lens's own characterization treats this as "lower" severity.
- F23 (Titan M2 specificity) is optional per the lens's own framing.
- F24 (three-tier terminology) is optional per the lens's own framing.

---

# Strategic note

This review is smaller in volume than the §8–§9 review (26 consolidated findings vs. 30) but more uniform in defect type. The §8–§9 review surfaced commitment-credibility issues — specific assertions that depend on conditions §8 acknowledges elsewhere. The §4 review surfaces calibration issues — specific phrasings where §4's confident architectural prose runs ahead of §5's careful technical specification. The brief's design discipline (§5) and its operational-commitment discipline (§8 partially, after the prior review's remediations) are stronger than its orientation-prose discipline (§4).

The most actionable single edit is the present-tense-to-v1-scoped sweep covering F1, F2, F3 — the three Critical findings that span all five lenses. After that sweep, the remaining critical findings (F4–F9) close with specific prose additions §5 already specifies. The brief's overall posture in §4 — "the integration is the product" — is the right framing for the audience and should be preserved. The calibration of that framing to v1 reality, to inherited rather than owned properties, and to substituted rather than eliminated trust is what this review's findings address. None of these edits require revising the strategy; they require honoring §4.2:273's own calibration principle in §4's surrounding prose.
