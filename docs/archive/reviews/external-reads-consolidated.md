# External-reads consolidated triage

**Date:** 2026-05-28
**Brief version:** v0.7
**Sources:** Four agentic external reviews per `docs/reviews/external-read-prompts/`:

- `01-cryptographer-findings.md` — practitioner cryptographer / messaging-security engineer (H1-H6 high-confidence, M1-M6 medium, L1-L4 low)
- `02-civil-society-partner-findings.md` — digital-safety helpline practitioner (~16 findings grouped by section)
- `03-sustainability-skeptic-maintainer-findings.md` — sustainability-skeptic OSS security-tool maintainer (~24 findings across 7 thematic sections + failure-mode catalog + 4 pre-code recommendations)
- `04-prospective-end-user-findings.md` — freelance investigative journalist evaluating pilot participation (4 catastrophic abandonment triggers + 3 erosion patterns + 10 recommendations)

Total: ~75 distinct findings across four reviews. Many cross-cut; some refine on closer inspection of brief + adjacent-layer capabilities.

## TL;DR

The four reviews are high-quality and the prompt engineering worked: each persona produced evidence-grounded, distinctive findings with anti-sycophancy discipline intact. The reviews converge on three themes:

1. **Construction-level specification gaps** (cryptographer): nine-field schema documented two ways, prior-hash hash function unspecified, COSE_Sign1 `Sig_structure` unspecified, capability-token authority model ambiguous, 48-hour delay clock-source unbound. Six high-confidence findings, all pre-implementation specification work in D0006/D0005. Cheap to fix now, expensive after code exists.

2. **Sustainability and partnership-realism gaps** (partner + maintainer convergent): §10.4 understates Phase D operational load by ~350-1,300 hrs/yr in hidden categories; Q5 partner outreach should precede engineering (currently sequenced after); CVE-response runbook missing at v1; multi-party APK signing-key custody unspecified; D0009 60-day window too long for §3 threat tier; D0016 trigger has self-evaluation bias. Multiple findings frame these as project-posture issues, not documentation issues.

3. **End-user UX surfaces** (persona 04, with refinements): persona 04's four catastrophic abandonment triggers were calibrated against actual brief content and adjacent-layer capabilities. Three of four reduce to brief-clarity issues (latency applies only to background; GrapheneOS duress PIN addresses contact-list-read at v1; multi-device is tolerable at pilot scope). One remains a real v1 engineering gap (in-app post-coercion flow); **decision: accepted as v1 commitment**.

The compound strategic finding from the first synthesis — "v1 is operationally inadequate for the named audience" — is materially weakened by the calibration work. The corrected picture: v1 architectural decisions are sound; the brief under-surfaces operational mitigations at adjacent layers (GrapheneOS, SimpleX, Tor); real engineering gaps at v1 are narrower than the persona-04 flat read suggested.

What remains: a sustainability/partnership-posture question the partner and maintainer reviews both surface. This is not fully resolvable through tactical fixes. Q5 informal partner conversations are the evidence-gathering step before the structural decision.

## Decision summary

**Decided (this triage session):**

- ✅ In-app post-coercion recovery flow moved from v1.5/v1.6 to v1 commitment (subject to engineering feasibility; estimate 60-160 hrs UI work since cryptographic primitives are already v1 scope)
- ✅ Persona 04 catastrophic triggers #1, #2, #4 refined to brief-clarity fixes per analyses in conversation log
- ✅ Triage Option C (hybrid: tactical fixes + brief clarity, then Q5 informal conversations, then structural choice) — selected as path forward

**Pending application (cheap, deterministic — apply through normal review-application pattern):**

- All cryptographer H1-H6 + M1-M4 findings (pre-implementation specification work in D0006/D0005)
- All maintainer pre-code items: Q20 runway disclosure resolution, CVE-response runbook draft, multi-party APK custody specification, §10.4 hidden-overhead enumeration, D0009 duress-canary
- Brief-clarity edits surfaced by persona 04 calibrations: §5.4 foreground/background distinction, §3.5 GrapheneOS duress PIN as v1 operational guidance, §7.1 multi-device-broader-release-ceiling honesty, screenshot policy, disappearing-messages/search/archive commitments, partner-mediated support SLA in D0013

**Pending discussion (require strategic choice):**

- Partner reviewer's §10.4-disqualifies-vouching finding and maintainer reviewer's "bet against comparable-project record" finding — these converge on the project-posture question (paid product / contribute-to-existing / accept-sunset / multi-year-grant). Defer until after Q5 informal conversations produce evidence.
- Q5 partner outreach sequencing (partner says co-design before engineering; maintainer says recruitment before engineering). Both right; needs concrete plan.
- D0016 trigger framework — partner reviewer says framework should be replaced with committed posture; maintainer reviewer says triggers should be partner-mediated re-evaluation. Both have merit.
- §1.2 audience reframing (partner reviewer's strongest finding) — depends on outcome of Q5 conversations about whether to commit to the "low hundreds globally" v1 audience or reframe entirely.

## How to read this document

Findings are organized by source persona, then by section of the brief they affect. Each finding has:

- **Source(s):** which persona(s) raised it
- **Confidence:** HIGH / MEDIUM / LOW (per source review's calibration; cross-persona findings are HIGH by default)
- **Calibration:** whether subsequent analysis refined the finding's framing
- **Fix type:** BRIEF-CLARITY / V1-ENGINEERING / V1.5+ / STRUCTURAL / QUESTION
- **Priority:** P0 (apply before next outreach) / P1 (apply before v1 ship) / P2 (track for future)
- **Status:** ACCEPTED / ACCEPTED-WITH-MODIFICATION / NEEDS-DISCUSSION / REJECTED / DEFERRED
- **Affected sections:** brief / D-docs / open-questions

---

## Section 1: Cross-cutting findings (multi-persona convergence)

Findings raised by two or more reviewers from independent angles. Highest evidence-weight in the entire corpus.

### X1. §10.4 understates Phase D operational load

- **Sources:** Partner ("structural collapse most likely outcome" is disqualifying for vouching); Maintainer (~350-1,300 hrs/yr in hidden categories: CVE response, grant cycles, pilot support, health-report cycle, dependency tracking, doc drift)
- **Confidence:** HIGH (two-persona, independent evidence)
- **Calibration:** None — both framings stand.
- **Fix type:** BRIEF-CLARITY (enumerate) + STRUCTURAL (the underlying sustainability question)
- **Priority:** P0
- **Status:** ACCEPTED for the enumeration work; STRUCTURAL question NEEDS-DISCUSSION post-Q5
- **Affected sections:** §10.4, §10.7, §10.8

### X2. Q5 partner outreach should precede engineering

- **Sources:** Partner (don't approach with current form; co-design D0013 first); Maintainer (front-loads engineering enjoyment, defers operational stress); End-user (won't enroll without channel; brief commits to precondition it confirms is unmet)
- **Confidence:** HIGH (three-persona, independent evidence)
- **Calibration:** None.
- **Fix type:** STRUCTURAL (project sequencing decision)
- **Priority:** P0
- **Status:** NEEDS-DISCUSSION — informal Q5 conversations as evidence-gathering step is the path forward; full re-sequencing depends on what those conversations surface
- **Affected sections:** §10.1, §10.6, §10.9, D0013, §6.3, §8.6, Q5

### X3. CVE-response runbook missing at v1

- **Sources:** Partner (partner can't vouch for emergency patch verification); Maintainer (runbook should be v1 alpha prerequisite); End-user (pilot users not told what to do)
- **Confidence:** HIGH (three-persona, independent evidence)
- **Calibration:** None.
- **Fix type:** V1-ENGINEERING (runbook draft) + BRIEF-CLARITY (D0013 disclosure)
- **Priority:** P0
- **Status:** ACCEPTED — draft now per maintainer recommendation. 8-16 hours.
- **Affected sections:** §8.5, §9.4, D0013, new `docs/runbooks/cve-response.md`

### X4. Multi-party APK signing-key custody unspecified

- **Sources:** Partner (partner can't execute emergency response under D0009); Maintainer (sudden-unavailability sunset can't produce patched release without trustee arrangement)
- **Confidence:** HIGH
- **Calibration:** None.
- **Fix type:** V1-ENGINEERING (trustee arrangement) + BRIEF-CLARITY (D0009/§5.5 spec)
- **Priority:** P0
- **Status:** ACCEPTED — upgrade §5.5's "ideally with multi-party access procedures" to commitment with N-of-M trustee arrangement specification
- **Affected sections:** §5.5, D0009, successor-handover documentation

### X5. D0009 60-day window too long for §3 threat tier

- **Sources:** Partner (crisis-window timing mismatch); Maintainer (calibrated to illness/accident, not border seizure / short-term detention / asset seizure)
- **Confidence:** HIGH
- **Calibration:** None.
- **Fix type:** BRIEF-CLARITY (D0009 spec change)
- **Priority:** P1
- **Status:** ACCEPTED — adopt maintainer's recommendation: 30-day first-contact, 60-day public advisory. Add duress-canary mechanism (warrant-canary pattern adapted to dead-man's-switch flow) for coercion-induced-false-continuation residual.
- **Affected sections:** D0009

### X6. D0016 trigger has self-evaluation bias

- **Sources:** Partner (partner-facing posture problem; structural mitigations remain unenforceable indefinitely); Maintainer (maintainer in stressed state misses signal; triggers are detection-late)
- **Confidence:** HIGH
- **Calibration:** None.
- **Fix type:** BRIEF-CLARITY + STRUCTURAL (depends on Q5 outcomes whether to commit to incorporation at v1.5 or maintain deferral)
- **Priority:** P1
- **Status:** ACCEPTED for the partner-mediated re-evaluation addition (maintainer recommendation); NEEDS-DISCUSSION for the partner-vouching-requires-enforceable-commitments structural critique
- **Affected sections:** D0016, §10.7, §8.4

### X7. §3 audience description vs deployable population mismatch

- **Sources:** Partner (§1.2 vs §2.2 contradiction is disqualifying); Maintainer ("low hundreds globally" is the honest number); End-user ("I would not be invited — structurally excluded")
- **Confidence:** HIGH (three-persona convergence)
- **Calibration:** None.
- **Fix type:** BRIEF-CLARITY (lead with deployable population) + STRUCTURAL (project-posture implication)
- **Priority:** P0 for the clarity edit; NEEDS-DISCUSSION for the structural framing
- **Status:** ACCEPTED for §1.2 rewrite leading with four-precondition intersection per partner recommendation; full restructure depends on Q5 outcomes
- **Affected sections:** §1.2, §2.2, §3.2

### X8. Documentation drift / inconsistency

- **Sources:** Cryptographer (H1 nine-field schema documented two ways; H2 prior-hash chain scope contradicted across diagrams vs brief); Maintainer (glossary line 1568 still says pre-D0016 framing)
- **Confidence:** HIGH (independent evidence from different angles)
- **Calibration:** Two-pass reconciliation needed after all tactical fixes land; the cryptographer findings produce _more_ documentation surface, not less.
- **Fix type:** BRIEF-CLARITY (reconciliation pass)
- **Priority:** P1 (after other tactical work lands)
- **Status:** ACCEPTED — add reconciliation pass to triage execution sequence
- **Affected sections:** §5.2, D0006, architecture-diagrams.md, glossary

### X9. Recovery flow operational tempo (48-96h is too long)

- **Sources:** Partner (incompatible with "I need to alert my contacts now" crisis pattern); Maintainer (acknowledged); End-user (5 days minimum, fresh-identity is realistic path 60-70%)
- **Confidence:** HIGH (three-persona convergence)
- **Calibration:** End-user adds important nuance — fresh-identity path is the realistic recovery path for working journalists, not the peer-recovery path the brief presents as default.
- **Fix type:** BRIEF-CLARITY (§5.3 reframe fresh-identity as primary path; D0014 paper-shares candidate consideration) + V1-ENGINEERING (consider paper shares from D0014 candidate options at v1)
- **Priority:** P1
- **Status:** ACCEPTED for the §5.3 reframe; paper-shares-at-v1 NEEDS-DISCUSSION (engineering cost ~40-80 hrs; user-experience benefit substantial)
- **Affected sections:** §5.3, §5.6, D0005, D0014

### X10. BYOD-Pixel incompatible with named population

- **Sources:** Partner (Pixel = half-year income in target jurisdictions; 2-4 device loaner pool insufficient); End-user (would need import; loaner pool global, won't get one)
- **Confidence:** HIGH
- **Calibration:** Partner-organizational + end-user perspective converge. Resolution of Q26 (CalyxOS inclusion) may materially change addressable population.
- **Fix type:** BRIEF-CLARITY (name as audience precondition) + STRUCTURAL (loaner-pool budget commitment; Q26 resolution; Q10/Q11 hardware-partnerships timing)
- **Priority:** P1
- **Status:** ACCEPTED for §2.2 precondition acknowledgment; Q26 resolution NEEDS-DISCUSSION; loaner-pool scale STRUCTURAL
- **Affected sections:** §2.2, §3.3, §6.3, §10.1, Q26

### X11. Reviewer-pool absence at v1 consequential

- **Sources:** Partner ("cannot vouch for v1 pilot supply-chain gap"); Maintainer (F4 cost reduction is conditional on recruitment failure)
- **Confidence:** HIGH
- **Calibration:** Cryptographer L1 indirectly raises related concern about deterministic CBOR cross-implementer verification. v1.5 reviewer-pool formation is the load-bearing assumption.
- **Fix type:** BRIEF-CLARITY (D0013 supply-chain-gap disclosure) + STRUCTURAL (whether v1 should ship without external attestation given pilot users at §3 threat tier)
- **Priority:** P1
- **Status:** ACCEPTED for the D0013 explicit disclosure; v1-with-no-external-attestation NEEDS-DISCUSSION (partner reviewer says this is disqualifying; maintainer says deferral framing is honest)
- **Affected sections:** D0013, D0015, §5.5, §8.6

---

## Section 2: Cryptographer findings (construction-level)

Pre-implementation specification work. None blocked on partner conversations or structural decisions. All fixable in D0006/D0005 with documentation edits + test vectors. **Recommended apply-batch.**

### C1. Nine-field schema documented two ways (H1)

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (designate D0006 as canonical schema spec; reconcile architecture-diagrams.md:275 vs design-brief.md:457-465)
- **Priority:** P0
- **Status:** ACCEPTED
- **Affected sections:** D0006, design-brief.md §5.2, architecture-diagrams.md diagram 4

### C2. `prior_hash` hash function unspecified; chain scope contradicted (H2)

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (specify SHA-256 + byte-input definition; reconcile per-issuer vs per-(issuer,subject) chain scope — keep per-(issuer,subject) per §5.2; correct architecture diagram)
- **Priority:** P0
- **Status:** ACCEPTED
- **Affected sections:** D0006, design-brief.md §5.2, architecture-diagrams.md

### C3. COSE_Sign1 `Sig_structure` form unspecified (H3)

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (specify RFC 9052 §4.4 Sig_structure form including context constant + external_aad value + protected-header determinism + COSE-tagged vs untagged decision; add test vector)
- **Priority:** P0
- **Status:** ACCEPTED
- **Affected sections:** D0006

### C4. `issuer_cert_hash` byte input undefined (H4)

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (specify `issuer_cert_hash := SHA-256(deterministic_cbor_encoding(master_attestation.Sig_structure))` per cryptographer recommendation; add test vector)
- **Priority:** P0
- **Status:** ACCEPTED
- **Affected sections:** D0006

### C5. 48-hour delay clock-source unbound (H5)

- **Confidence:** HIGH
- **Calibration:** Cryptographer recommended peer-side enforcement (shares released only 48h after challenge verification, by peer device clock). Architecturally cleaner than Sigsum-anchored alternative.
- **Fix type:** V1-ENGINEERING (architectural change: peer-side enforcement) + BRIEF-CLARITY (update D0005 + architecture-diagrams.md diagram 5)
- **Priority:** P0
- **Status:** ACCEPTED — adopt peer-side enforcement. Engineering implication: peer-side state for tracking 48h timer + share-release scheduling.
- **Affected sections:** D0005, architecture-diagrams.md diagram 5, §5.3

### C6. Capability-token authority model ambiguous (H6)

- **Confidence:** HIGH
- **Calibration:** Cryptographer's Recommendation: Register 1 (cryptographic enforcement via device-key co-signature). Without this, design-brief.md:422's scope-bounding claim is false.
- **Fix type:** V1-ENGINEERING (specify device-key co-signature in envelope; device-key generation/storage/revocation flow) + BRIEF-CLARITY (D0006 expansion or new D0006b)
- **Priority:** P0
- **Status:** ACCEPTED — adopt Register 1. Engineering implication: device-key generation in hardware element; device-key signature in operation envelope; verifier chain device-key → capability-token → operational-identity → master-attestation.
- **Affected sections:** D0006 expansion, §5.1, §6.1

### C7. Cross-protocol signature confusion (M1)

- **Confidence:** MEDIUM
- **Fix type:** BRIEF-CLARITY (specify `external_aad := "cairn-v1-capability-token"` vs `"cairn-v1-trust-graph-operation"` in D0006)
- **Priority:** P0
- **Status:** ACCEPTED
- **Affected sections:** D0006

### C8. Pre-shared peer challenge replay protection unspecified (M2)

- **Confidence:** MEDIUM
- **Calibration:** Cryptographer recommends single-use phrases with out-of-band rotation. End-user finding (paper-in-notebook storage problem) intersects here.
- **Fix type:** BRIEF-CLARITY (D0005 spec) + V1-ENGINEERING (rotation mechanism)
- **Priority:** P1
- **Status:** ACCEPTED for single-use phrase commitment; rotation UX deferred to in-app post-coercion flow work
- **Affected sections:** D0005, §5.3

### C9. Sigsum witness threshold unspecified (M3)

- **Confidence:** MEDIUM
- **Fix type:** BRIEF-CLARITY (specify minimum witness count, threshold for acceptance, failure mode as architectural properties)
- **Priority:** P1
- **Status:** ACCEPTED — adopt cryptographer recommendation: minimum 3 witnesses, 2-of-3 threshold for acceptance, client rejects insufficiently-witnessed entries
- **Affected sections:** D0015, §5.5, Q10

### C10. Master re-split atomicity under interruption unspecified (M4)

- **Confidence:** MEDIUM
- **Fix type:** BRIEF-CLARITY (D0005 spec atomic-or-non-leaking semantics)
- **Priority:** P1
- **Status:** ACCEPTED — adopt cryptographer recommendation: all-shares-distributed-before-zeroize-or-all-shares-discarded
- **Affected sections:** D0005

### C11. Equivocation detection lacks operational infrastructure (M5)

- **Confidence:** MEDIUM
- **Calibration:** Cryptographer flagged that "external auditors" claim in §5.2 lacks operational implementation. Recommended honest downgrade or per-client lightweight detector.
- **Fix type:** BRIEF-CLARITY (downgrade claim) or V1-ENGINEERING (per-client detector)
- **Priority:** P1
- **Status:** ACCEPTED for the honest-downgrade option (cryptographer's option b); per-client detector deferred to v1.5+ candidate
- **Affected sections:** §5.2, D0006

### C12. Zeroize residual surfaces overstated (M6)

- **Confidence:** MEDIUM
- **Fix type:** BRIEF-CLARITY (tighten language; name residual classes [kernel access / hardware cache / forensic implant resident before scope] as not mitigated by zeroize)
- **Priority:** P1
- **Status:** ACCEPTED
- **Affected sections:** D0003, §5.1, §3.5

### C13. `coset` crate deterministic CBOR conformance unverified (L1)

- **Confidence:** LOW
- **Fix type:** V1-ENGINEERING (round-trip test against hand-constructed deterministic CBOR encoding; CI gate)
- **Priority:** P2 (move to v1 implementation prerequisites checklist)
- **Status:** ACCEPTED — add to pre-implementation checklist
- **Affected sections:** D0006, system design spec when written

### C14. COSE alg parameter forward-compatibility partial (L2)

- **Confidence:** LOW
- **Fix type:** BRIEF-CLARITY (adjust PQ-migration framing in design-brief.md:418 to acknowledge coordinated-update requirement)
- **Priority:** P2
- **Status:** ACCEPTED
- **Affected sections:** §5.1, §3.4 PQ note

### C15. Shamir library timing-safety verification (L3)

- **Confidence:** LOW
- **Calibration:** Cryptographer recommends re-adding Shamir timing-safety verification to pre-pilot audit scope, contesting F5 narrowing.
- **Fix type:** STRUCTURAL (audit-scope decision)
- **Priority:** P1
- **Status:** ACCEPTED — add Shamir-library-specific timing-safety verification to pre-pilot audit scope; this is small marginal scope addition that meaningfully closes a risk
- **Affected sections:** D0011, §8.5

### C16. Polling-pattern observability (L4)

- **Confidence:** LOW
- **Fix type:** BRIEF-CLARITY (§5.4 paragraph acknowledging coverage by Tor's threat model)
- **Priority:** P2
- **Status:** ACCEPTED
- **Affected sections:** §5.4

**Cryptographer-findings total apply-batch:** 16 findings; P0 = 7 items; P1 = 7 items; P2 = 2 items. Estimated brief-edit cost: 12-20 hours. Engineering implications: peer-side 48h enforcement (C5), device-key co-signature (C6), single-use peer phrases (C8). Each is a real implementation commitment but bounded to v1 scope.

---

## Section 3: Partner findings (deployment-level)

### P1. §1.2 audience description vs §2.2 exclusions contradiction

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X7. Partner says §1.2's threat-tier population list is "the dishonest one"; §2.2's four-precondition intersection is "the honest one."
- **Fix type:** BRIEF-CLARITY
- **Priority:** P0
- **Status:** ACCEPTED — rewrite §1.2 leading with four-precondition intersection
- **Affected sections:** §1.2, §2.2

### P2. §3.2 threat-model adversary list overweights spyware, underweights HUMINT and account takeover

- **Confidence:** HIGH (partner cites casework distribution: ~60% HUMINT/account takeover, 25% lawful-intercept/telecom, 10% forensic-extraction, 5% mercenary spyware)
- **Fix type:** BRIEF-CLARITY
- **Priority:** P1
- **Status:** ACCEPTED-WITH-MODIFICATION — restructure §3.2 to lead with HUMINT + account-and-identifier surface; demote spyware paragraph to one capability tier among several
- **Affected sections:** §3.2, §4.3

### P3. BYOD-with-GrapheneOS-on-Pixel operationally incompatible with most named threat-tier population

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X10. Q26 (CalyxOS) resolution affects addressable population materially.
- **Fix type:** BRIEF-CLARITY + STRUCTURAL
- **Priority:** P1
- **Status:** See X10
- **Affected sections:** §2.2, §3.3, §6.3, §10.1, Q26

### P4. §3.1 facilitator-model framing contradicts §2.2 individual-audience framing

- **Confidence:** MEDIUM
- **Fix type:** BRIEF-CLARITY (restructure §2.2 around three-tier audience: partner-org staff who mediate; end users; broader threat-tier population)
- **Priority:** P1
- **Status:** ACCEPTED
- **Affected sections:** §1.2, §2.2, §3.1

### P5. D0013 partner-mediated channel not co-designed with partners

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X2. Partner's sequencing recommendation: recruit 2 protection-program consultants → co-draft protocol → recruit partners.
- **Fix type:** STRUCTURAL (sequence + budget)
- **Priority:** P0
- **Status:** NEEDS-DISCUSSION (depends on whether to engage protection-program consultants at honoraria pre-Q5)
- **Affected sections:** D0013, Q22, Q5

### P6. D0013 / §6.3 weekend crisis-escalation path unspecified

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (D0013 spec partner-side escalation path for crisis cases requiring developer involvement)
- **Priority:** P1
- **Status:** ACCEPTED
- **Affected sections:** D0013, §6.3

### P7. Developer-as-facilitator concentrates HUMINT exposure across all pilot users

- **Confidence:** MEDIUM
- **Fix type:** BRIEF-CLARITY (specify developer's pilot-facilitation security posture; HUMINT-response plan; acknowledge if posture cannot match §3 threat tier)
- **Priority:** P1
- **Status:** ACCEPTED-WITH-MODIFICATION — honest framing in §6.3 that v1 pilot users are at the threat tier the developer's own security posture can survive in, not the §3 threat tier the architecture is designed for
- **Affected sections:** §6.3, §3.4

### P8. 48-96h recovery time incompatible with operational tempo

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X9 and persona 04 abandonment trigger #3.
- **Fix type:** BRIEF-CLARITY (user-facing language about friction-vs-survival tradeoff in §1.2 and §2.2) + V1-ENGINEERING (consider paper shares from D0014)
- **Priority:** P1
- **Status:** See X9
- **Affected sections:** §1.2, §2.2, §5.3, D0005

### P9. In-app support channel insufficient for §3 threat tier helpline-volume cases

- **Confidence:** HIGH
- **Fix type:** STRUCTURAL (Phase D partner-helpline-support line item) + BRIEF-CLARITY (§10.4 acknowledgment)
- **Priority:** P1
- **Status:** ACCEPTED for §10.4 acknowledgment as externalized cost; partner-honoraria budgeting NEEDS-DISCUSSION
- **Affected sections:** §10.4, §10.7, §8.6, §6.3

### P10. Provisioning ceremony is the Signal-equivalent moment that breaks adoption

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with persona 04 (peer-designation as the moment they will quietly compromise the design)
- **Fix type:** V1-ENGINEERING (5-10 user pre-pilot onboarding exercise with developer-known lower-threat users before partner-mediated consent protocol locks)
- **Priority:** P1
- **Status:** ACCEPTED
- **Affected sections:** §6.3, D0013, new pre-pilot exercise plan

### P11. Concurrent-use threat model (Cairn + Signal + WhatsApp) undocumented

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (add §3.6 or extend §3.5 addressing concurrent-use case)
- **Priority:** P1
- **Status:** ACCEPTED — also surfaced by persona 04 indirectly
- **Affected sections:** §3.5 or new §3.6

### P12. v1.5 reviewer-pool deferral leaves v1 pilot users on unattested supply chain

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X11.
- **Fix type:** BRIEF-CLARITY (D0013 supply-chain-gap disclosure) + STRUCTURAL (whether v1 should ship without reviewer-pool given §3 threat-tier framing)
- **Priority:** P1
- **Status:** See X11
- **Affected sections:** D0013, D0015, §5.5

### P13-P16. Partner-organization presumption pattern across D0009/D0013/D0015/§8.5/§8.6

- **Confidence:** HIGH (multiple findings in this group)
- **Fix type:** STRUCTURAL (Q5 sequencing + partner co-design + partner honoraria budgeting) + BRIEF-CLARITY (reframe candidate-language vs existing-relationship language across multiple sections)
- **Priority:** P0 for the BRIEF-CLARITY edits (rewrite §8.5 to name organizations as "candidate disclosure-relationship partners pending Q5 outreach" rather than as existing relationships); P1 for the STRUCTURAL work
- **Status:** ACCEPTED for BRIEF-CLARITY; STRUCTURAL portion NEEDS-DISCUSSION post-Q5
- **Affected sections:** §8.5, §8.6, D0009, D0013, D0015

### P17. CVE-class vulnerability response leaves partner without verification path

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X3.
- **Fix type:** V1-ENGINEERING (recruit at least one trusted external attestor before v1 pilot) or BRIEF-CLARITY (D0013 partner-can't-verify acknowledgment)
- **Priority:** P0
- **Status:** ACCEPTED — adopt cryptographer-recommended emergency-attestor recruitment as part of Q5; if not feasible, ACCEPTED for D0013 acknowledgment as fallback
- **Affected sections:** D0013, §5.5, Q5, §8.5

### P18. Sudden developer unavailability mid-pilot exposes partner without coordinated response

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (D0009 per-state response plan for in-flight users)
- **Priority:** P1
- **Status:** ACCEPTED
- **Affected sections:** D0009

### P19. Tool-mediated harm attribution-and-public-communication protocol unspecified

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (D0013 incident-response coordination protocol: attribution control, timeline, partner veto, coordination with partner casework)
- **Priority:** P1
- **Status:** ACCEPTED
- **Affected sections:** D0013, §9.4

### P20. §10.4 "structural collapse most likely outcome" is disqualifying for partner vouching

- **Confidence:** HIGH (partner reviewer's strongest finding)
- **Calibration:** Cross-cutting with X1 and maintainer "bet against comparable-project record"
- **Fix type:** STRUCTURAL (project-posture choice: paid product / contribute-to-existing / accept-sunset / multi-year-grant)
- **Priority:** P0 for the structural decision; NEEDS-DISCUSSION
- **Status:** NEEDS-DISCUSSION — defer until after Q5 informal conversations
- **Affected sections:** §10.4, §10.7, §1.2, §2.1, §2.3

### P21. D0016 deferral makes structural mitigations unenforceable indefinitely

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X6 and maintainer trigger-failure scenarios.
- **Fix type:** STRUCTURAL
- **Priority:** P1
- **Status:** See X6 — NEEDS-DISCUSSION post-Q5
- **Affected sections:** D0016, §8.4, §10.7

### P22-P23. Reviewer-pool volunteer-attestation model + Citizen Lab/Amnesty SecLab overstated existing-relationship framing

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (reframe §8.5 disclosure-partner candidates as Q5-pending; honest about volunteer-attestation realistic posture vs honoraria-conditional aspiration)
- **Priority:** P0 (cheap brief edits)
- **Status:** ACCEPTED
- **Affected sections:** §8.2, §8.5

### P24. §10.4 Phase D arithmetic excludes partner-helpline burden

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X1 hidden-overhead accounting.
- **Fix type:** BRIEF-CLARITY (§10.4 line item even if not budgeted)
- **Priority:** P0
- **Status:** ACCEPTED
- **Affected sections:** §10.4

### P25. Co-design honoraria not budgeted

- **Confidence:** HIGH
- **Fix type:** STRUCTURAL (Phase B line item for partner-co-design honoraria)
- **Priority:** P1
- **Status:** NEEDS-DISCUSSION
- **Affected sections:** §10.2, §10.3

### P26. v1 supply-chain gap disclosure obligation to pilot users

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X11.
- **Fix type:** BRIEF-CLARITY (D0013 disclosure requirement)
- **Priority:** P0
- **Status:** ACCEPTED
- **Affected sections:** D0013, §5.5

---

## Section 4: Maintainer findings (sustainability-level)

### M1. Year-three trajectory cliff at month 36

- **Confidence:** HIGH (concrete calendar mapping)
- **Fix type:** BRIEF-CLARITY (month-18 check-in commitment per maintainer recommendation)
- **Priority:** P1
- **Status:** ACCEPTED for month-18 check-in commitment; deeper restructuring NEEDS-DISCUSSION post-Q5
- **Affected sections:** §9.1, §10.7

### M2-M7. Hidden-overhead categories (CVE response, grant cycles, pilot user support, health-report cycle, partner recruitment, dependency tracking, doc drift)

- **Confidence:** HIGH (cross-cutting with X1)
- **Fix type:** BRIEF-CLARITY (§10.4 enumeration)
- **Priority:** P0
- **Status:** ACCEPTED — adopt maintainer's recommended line items with honest hours estimates
- **Affected sections:** §10.4

### M8. Recruited reviewer pool probably won't form at v1.5

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (reframe §4.3 so differentiation doesn't depend on pool forming; reframe v1.5 ship-conditions so pool formation is bonus not requirement)
- **Priority:** P1
- **Status:** ACCEPTED-WITH-MODIFICATION
- **Affected sections:** §4.3, §7.1, D0015

### M9. D0016 trigger probably won't activate

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X6 / P21.
- **Status:** See X6
- **Affected sections:** D0016, §10.7

### M10. Documentation-form post-coercion guidance probably remains documentation-form past v1.6

- **Confidence:** HIGH
- **Calibration:** **SUPERSEDED** by the v1-scope-expansion decision (in-app post-coercion flow added to v1)
- **Fix type:** V1-ENGINEERING (UI work; estimate 60-160 hours)
- **Priority:** P0
- **Status:** ACCEPTED — moved to v1 commitment
- **Affected sections:** §5.6, §6.1, §6.2, §7.1, D0002

### M11. v2 USB / v3 iOS probably won't ship under volunteer baseline

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (§7.1 reframe v2/v3 as candidate releases conditional on multi-year operational funding, matching F8a's "candidate" framing for v4+ mesh)
- **Priority:** P1
- **Status:** ACCEPTED
- **Affected sections:** §7.1

### M12. Localization remains English-only past v1.6

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (§1.6 audience framing acknowledges audience-expansion-lever requires Phase D funding)
- **Priority:** P1
- **Status:** ACCEPTED
- **Affected sections:** §1, §1.6, Q6, Q19

### M13. First-CVE walkthrough surfaces missing runbook + missing partner notification tree + missing signing-key custody + DMS-window CVE interaction

- **Confidence:** HIGH
- **Calibration:** Decomposes into X3 (runbook), X4 (custody), X5 (DMS window).
- **Status:** See X3, X4, X5

### M14. F4 cost reduction conditional on recruitment failure outcome

- **Confidence:** HIGH
- **Fix type:** STRUCTURAL (resolve recruitment question pre-v1 via Q5)
- **Priority:** P0
- **Status:** NEEDS-DISCUSSION (Q5 sequencing question)
- **Affected sections:** §10.1, D0015

### M15. F6 trigger evaluation has self-bias

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X6.
- **Status:** See X6 — partner-mediated re-evaluation accepted
- **Affected sections:** D0016

### M16. F6 trigger-to-foundation-operational lag (12-24 months) unspecified

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (D0016 broader-release sequencing during lag)
- **Priority:** P1
- **Status:** ACCEPTED — adopt maintainer-recommended honest framing: broader release waits until foundation is operational
- **Affected sections:** D0016

### M17. D0009 60-day window too long

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X5.
- **Status:** See X5 — 30-day first-contact + 60-day public advisory ACCEPTED; duress-canary mechanism ACCEPTED
- **Affected sections:** D0009

### M18. D0009 coercion-induced false continuation unsolved

- **Confidence:** HIGH
- **Fix type:** V1-ENGINEERING (duress-canary mechanism — warrant-canary pattern adapted to dead-man's-switch flow)
- **Priority:** P1
- **Status:** ACCEPTED
- **Affected sections:** D0009

### M19. Multi-party APK signing-key custody unspecified

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X4.
- **Status:** See X4
- **Affected sections:** §5.5, D0009

### M20. D0016 trigger criteria are detection-late

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (commit to trigger re-evaluation at every subsequent broader-release planning cycle)
- **Priority:** P1
- **Status:** ACCEPTED
- **Affected sections:** D0016

### M21. Engineering before partner outreach sequence wrong

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X2.
- **Status:** See X2 — informal Q5 conversations as evidence-gathering step accepted; full re-sequencing NEEDS-DISCUSSION
- **Affected sections:** §10.1, §10.6

### M22. Audit funding pursuit deferred until brief complete

- **Confidence:** HIGH
- **Fix type:** STRUCTURAL (begin audit-firm engagement conversations during Phase A, not after)
- **Priority:** P1
- **Status:** ACCEPTED — begin Cure53 mission-rate and Trail of Bits civic-tech engagement conversations during Phase A
- **Affected sections:** §10.2, §10.6, §10.9

### M23. v1.5 engineering timeline overlap with pilot unspecified

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (§7.1 commit to either v1.5 engineering during pilot or after pilot)
- **Priority:** P1
- **Status:** ACCEPTED — commit to: v1.5 engineering after pilot completion (~6 month calendar slip); pilot evidence informs v1.5 design
- **Affected sections:** §7.1, D0008

### M24. Contributor-attraction barriers unaddressed; absent from open-questions

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (add Q27; identify 3 first-PR-friendly surfaces; specify architectural-decision delegation path)
- **Priority:** P1
- **Status:** ACCEPTED — add Q27 to open-questions; identify test-infra, documentation, reviewer-toolkit as first-PR surfaces
- **Affected sections:** open-questions.md (Q27), §8.3, §9.1

### M25-M28. Failure-mode catalog: year-3 burnout, first-CVE-during-DMS-window, Phase B funding doesn't close, partner quiet de-prioritization, D0016 trigger never activates

- **Confidence:** HIGH
- **Fix type:** Each maps to specific BRIEF-CLARITY or STRUCTURAL items above
- **Priority:** Variable
- **Status:** See individual cross-references (X1, X3, X4, X5, X6, P20, etc.)

### M29-M32. Pre-code recommendations (Q20 runway disclosure, CVE runbook, multi-party signing custody, §10.4 enumeration)

- **Confidence:** HIGH
- **Status:** ACCEPTED — these are the four pre-code items the maintainer reviewer recommended; all map to X1, X3, X4 or are standalone
- **Affected sections:** §9.1, §10.4, §10.8 (Q20); X3 (CVE runbook); X4 (signing custody)

---

## Section 5: End-user findings (UX-level, with calibrations applied)

### E1. Catastrophic trigger #1: 15-minute push polling latency

- **Confidence:** HIGH for the finding; medium for "catastrophic across all use" framing
- **Calibration:** **REFINED** — applies to backgrounded-app incoming notification only; foreground (active conversation) is seconds via SimpleX-over-Tor. Brief should make this distinction explicit.
- **Fix type:** BRIEF-CLARITY (§5.4 foreground/background distinction) + STRUCTURAL (Q12 decision: push-on-by-default for opt-in users)
- **Priority:** P0
- **Status:** ACCEPTED for BRIEF-CLARITY; Q12 decision NEEDS-DISCUSSION (recommend push opt-in default for users who explicitly consent)
- **Affected sections:** §5.4, §6.1, Q12

### E2. Catastrophic trigger #2: no duress-wipe at v1 → contact list exposed

- **Confidence:** HIGH for the underlying concern
- **Calibration:** **REFINED** — GrapheneOS duress PIN at OS level addresses the specific "contact list being read" concern at v1. Cairn-specific v1.5 duress-wipe adds selective compliance (wipe Cairn only) but is not load-bearing for the catastrophic-trigger scenario.
- **Fix type:** BRIEF-CLARITY (§3.5, §5.6, §6.3 surface GrapheneOS duress PIN as v1 operational guidance + provisioning ceremony checklist)
- **Priority:** P0
- **Status:** ACCEPTED
- **Affected sections:** §3.5, §5.6, §6.3, D0002

### E3. Catastrophic trigger #3: no in-app post-coercion flow at v1

- **Confidence:** HIGH
- **Calibration:** **NOT REFINED** — genuine engineering gap; no platform-layer equivalent
- **Fix type:** V1-ENGINEERING (UI work; estimate 60-160 hours since cryptographic primitives are v1)
- **Priority:** P0
- **Status:** ✅ **ACCEPTED — moved to v1 commitment per user decision this session**
- **Affected sections:** §5.6, §6.1, §6.2, §7.1, D0002 — update to reflect v1 commitment

### E4. Catastrophic trigger #4: no multi-device / laptop workflow

- **Confidence:** HIGH for the concern at v1.5+ broader release
- **Calibration:** **REFINED** — architectural decision is sound per D0007 (single-device-per-identity; capability schema supports v2 extension); concern is tolerable at v1 pilot scope but real at v1.5+ broader release. Optional v1 partial answer: signed encrypted transcript export (~20-60 hours engineering) addresses journalism laptop-read workflow without breaking single-device commitment.
- **Fix type:** BRIEF-CLARITY (§7.1 acknowledge multi-device ceiling at v1.5+ broader release) + optionally V1-ENGINEERING (transcript export)
- **Priority:** P1 for BRIEF-CLARITY; transcript-export NEEDS-DISCUSSION
- **Status:** ACCEPTED for §7.1 clarification; transcript-export NEEDS-DISCUSSION (worth doing if pilot recruits laptop-workflow-critical users)
- **Affected sections:** §7.1, §6.1, possibly D0007 update

### E5. Peer designation impossibility at v1 pilot scope

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with P10. The 3-of-5 Shamir architecture is for a peer distribution that the v1 pilot scope (10-15 users in 1-2 local groups) structurally prevents.
- **Fix type:** BRIEF-CLARITY (acknowledge pilot will deploy 3-of-5 against a correlated peer set; pilot evidence about peer-designation-under-pilot-constraint will be a known limitation) + V1-ENGINEERING (paper shares per D0014 as v1 alternative recovery path)
- **Priority:** P0
- **Status:** ACCEPTED for BRIEF-CLARITY; paper-shares-at-v1 NEEDS-DISCUSSION (per X9)
- **Affected sections:** §5.3, §6.3, D0005, D0014

### E6. Identifier-less contact establishment breaks cold-source workflow

- **Confidence:** HIGH (journalism-specific)
- **Fix type:** BRIEF-CLARITY (acknowledge in §1.2 audience analysis or §3.5 explicit limitations)
- **Priority:** P1
- **Status:** ACCEPTED
- **Affected sections:** §1.2, §3.5

### E7. Off-device storage of pre-shared challenges (paper in interview notebook)

- **Confidence:** HIGH
- **Calibration:** Intersects with cryptographer C8 (single-use phrases) — different angle on the same problem.
- **Fix type:** BRIEF-CLARITY (operational guidance) + V1-ENGINEERING (consider hardware-backed alternatives in pilot)
- **Priority:** P1
- **Status:** ACCEPTED for BRIEF-CLARITY
- **Affected sections:** D0005, §5.3, §5.6, §6.3

### E8. Erosion patterns: passphrase prompt fatigue + stale-flag warning fatigue + "Cairn is for the slow stuff" mental model

- **Confidence:** HIGH (end-user pattern recognition from prior abandoned tools)
- **Fix type:** Mixed — varies per pattern
- **Priority:** P1
- **Status:** Each pattern needs separate treatment; recommend:
  - Passphrase fatigue: NEEDS-DISCUSSION (capability-token renewal frequency is architectural; can the renewal cycle be longer with device-key on-device retention?)
  - Stale-flag fatigue: ACCEPTED — adopt persona 04 + maintainer indirect recommendation: ship auto-escalation timer at v1 with stale-flag (so flags become actionable, not training-to-ignore)
  - "Slow stuff" mental model: depends on E1 push-default resolution
- **Affected sections:** §5.6, §6.1, Q12

### E9. Screenshots policy unaddressed in brief

- **Confidence:** HIGH (1-paragraph documentation gap)
- **Fix type:** BRIEF-CLARITY
- **Priority:** P0
- **Status:** NEEDS-DISCUSSION (decide policy: FLAG_SECURE blocks, allows with warning, allows silently; recommend allow-with-no-tracking for journalism workflow but flag in §5.6)
- **Affected sections:** §5.6, §6.1

### E10. Disappearing messages, archive, search not committed

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY
- **Priority:** P0
- **Status:** NEEDS-DISCUSSION (commit or non-commit each; disappearing messages are SimpleX-supported and should likely be v1; archive/search are UX work)
- **Affected sections:** §6.1

### E11. Paper shares per D0014 should ship at v1

- **Confidence:** HIGH (end-user specific recommendation)
- **Calibration:** Cross-cutting with X9, E5. Engineering cost ~40-80 hours.
- **Fix type:** V1-ENGINEERING + BRIEF-CLARITY
- **Priority:** P1
- **Status:** NEEDS-DISCUSSION — strong case given multi-persona convergence on recovery-flow problem; engineering scope manageable
- **Affected sections:** D0014, §5.3, §6.1

### E12. Localization for critical-UI strings at v1

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with M12. Persona 04 recommendation: at least post-coercion guidance, recovery flow text, trust-badge labels, consent document in target language at v1.
- **Fix type:** V1-ENGINEERING (translation infrastructure + critical-string scoping)
- **Priority:** P1
- **Status:** NEEDS-DISCUSSION (depends on Q4 pilot community identification; if pilot is in target-language jurisdiction, accept; if pilot is English-comprehending users only, defer)
- **Affected sections:** §6.1, Q4, Q6, Q19

### E13. SLA on support relationship during pilot

- **Confidence:** HIGH
- **Fix type:** BRIEF-CLARITY (D0013 SLA specification)
- **Priority:** P0
- **Status:** ACCEPTED
- **Affected sections:** D0013

### E14. CVE-disclosure protocol specifically for pilot users

- **Confidence:** HIGH
- **Calibration:** Cross-cutting with X3 (runbook) and P17 (partner verification gap)
- **Fix type:** Same as X3
- **Status:** See X3
- **Affected sections:** D0013, §8.5

---

## Section 6: Brief-clarity edits (consolidated apply-batch)

This is the consolidated list of BRIEF-CLARITY fixes that have NEEDS-DISCUSSION resolved (or don't need it). All can be applied in a single drafting pass, estimated 20-40 hours of focused work.

**§1.2 — audience-naming order:**

- Lead with four-precondition intersection (X7, P1)
- Demote threat-tier population list with named exclusions next to it (P1)
- Acknowledge friction-vs-survival tradeoff as user-borne cost (P8)
- Acknowledge identifier-less contact establishment breaks cold-source workflow (E6)
- Acknowledge audience-expansion lever requires Phase D funding (M12)

**§2.2 — audience analysis:**

- Restructure around three-tier audience: partner-org staff who mediate, end users, broader threat-tier population (P4)
- Name "Pixel-affording, GrapheneOS-tolerant, second-device-capable" as audience precondition (P3, X10) OR commit to loaner-pool scale
- Resolve Q26 (CalyxOS) before pilot recruitment (P3, X10)

**§3.2 — threat-model adversary list:**

- Lead with HUMINT + account-and-identifier surface; demote spyware paragraph (P2)
- Cite Access Now Helpline / FLD casework distribution if partners will share (P2)

**§3.5 — bounded exposure under compelled unlock:**

- Surface GrapheneOS duress PIN as v1 operational guidance (E2)
- Add §3.6 or extend §3.5 addressing concurrent-use case (P11)
- Tighten zeroize residual-surfaces language (C12)

**§5.2 — trust graph:**

- Honest downgrade of equivocation-detection-by-external-auditors claim (C11)
- Reconcile per-(issuer, subject) chain scope statement across §5.2 and architecture-diagrams.md (C2, X8)

**§5.3 — recovery flow:**

- Reframe fresh-identity path as primary path for working journalists; peer-recovery as slow path for users with intact peer networks (X9, E5)
- Acknowledge peer-designation under pilot-scope constraint as known limitation (E5)
- Operational guidance on pre-shared challenge storage (E7)

**§5.4 — communications protocols:**

- Add explicit foreground/background latency distinction (E1)
- Add polling-pattern-observability note covered by Tor threat model (C16)

**§5.5 — release security:**

- Specify multi-party APK signing-key custody as v1 commitment with N-of-M trustee arrangement (X4)
- Tighten witness-threshold specification: minimum 3 witnesses, 2-of-3 acceptance threshold (C9)

**§5.6 — UX principles:**

- Configure GrapheneOS duress PIN as v1 operational practice (E2)
- Decide screenshot policy and document (E9)
- Note: in-app post-coercion flow now v1 commitment (E3)

**§6.1 — v1 engineering surface:**

- Acknowledge single-device-per-identity per D0007 + workflow implications (E4)
- Decide disappearing-messages, archive, search commitments (E10)
- Note in-app post-coercion flow now v1 commitment (E3)
- Note Q12 push-default decision (E1)

**§6.3 — pilot deployment plan:**

- Add GrapheneOS duress PIN to provisioning ceremony checklist (E2)
- Specify developer's pilot-facilitation security posture (P7)
- Add weekend crisis-escalation path specification reference (P6)
- Add 5-10 user pre-pilot onboarding exercise commitment (P10)
- Honest framing: v1 pilot threat-tier is developer's-posture-can-survive tier, not §3 tier (P7)

**§7.1 — release sequence:**

- Reframe v2/v3 as candidate releases conditional on multi-year operational funding (M11)
- Acknowledge multi-device ceiling at v1.5+ broader release until v2 (E4)
- Commit v1.5 engineering after pilot completion (~6 month calendar slip) (M23)

**§8.5 — security disclosure:**

- Reframe disclosure-partner candidates as Q5-pending rather than existing relationships (P22)

**§8.6 — partner-organization roles:**

- Same anti-presumption pattern applied throughout (P22, P23)

**§9.4 — risks and mitigations:**

- Health-report cadence as conditional-on-capacity rather than unilateral commitment (per X1 enumeration)

**§10.4 — Phase D operational time:**

- Enumerate hidden-overhead line items: CVE response, grant cycles, pilot user support, health-report cycle, partner recruitment, dependency tracking, doc drift (X1, M2-M7)
- Add partner-helpline-support burden as externalized-cost line item (P9, P24)
- Honest accounting: 570-2,580 hrs/yr at upper bound vs 180-420 currently (X1)

**§10.6 — funding strategy:**

- Begin audit-firm engagement conversations during Phase A (M22)

**§10.8 — disclaimers:**

- Q20 runway figure resolution commitment (M29)

**D0002 — duress profile:**

- Update for v1.5 → v1 in-app post-coercion commitment (E3)
- Acknowledge GrapheneOS duress PIN as the v1 operational answer for OS-level wipe (E2)

**D0005 — peer verification:**

- Peer-side 48h enforcement (C5)
- Single-use phrase commitment (C8)
- Atomic-or-non-leaking re-split semantics (C10)

**D0006 — cryptographic envelope:**

- Designate canonical nine-field schema (C1)
- Specify prior_hash hash function and byte input (C2)
- Specify COSE_Sign1 Sig_structure form including external_aad domain separation (C3, C7)
- Specify issuer_cert_hash byte input (C4)
- Specify capability-token authority model (device-key co-signature) (C6)
- Add test vectors for each (C1-C4)

**D0009 — sudden unavailability:**

- 30-day first-contact + 60-day public advisory (X5)
- Duress-canary mechanism (X5, M18)
- Multi-party APK signing-key custody specification reference (X4)
- Per-state response plan for in-flight users at trigger fire (P18)

**D0013 — pilot consent and exit:**

- Weekend crisis-escalation path (P6)
- Tool-mediated harm coordination protocol (attribution, timeline, partner veto) (P19)
- v1 supply-chain gap disclosure requirement (P26, X11)
- SLA on partner-mediated support relationship (E13)
- Engineering-feasibility-check that partner-mediated channel exists before recruitment commences (P5)

**D0015 — v1 release-security posture:**

- Reframe so differentiation does not depend on v1.5 pool forming (M8)
- Specify Sigsum witness threshold (C9)

**D0016 — foundation incorporation deferral:**

- Commit to partner-mediated trigger re-evaluation (X6)
- Commit to trigger re-evaluation at every subsequent broader-release planning cycle (M20)
- Specify broader-release sequencing during trigger-to-foundation lag (M16)

**D0011 — audit budget:**

- Re-add Shamir-library timing-safety verification to pre-pilot audit scope (C15)

**open-questions.md:**

- Add Q27: contributor-attraction (M24)
- Update Q12 with push-default decision (E1)
- Update Q26 with CalyxOS-resolution-before-pilot commitment (P3, X10)

**architecture-diagrams.md:**

- Reconcile diagram 4 with §5.2 chain scope (C2, X8)
- Update diagram 5 with peer-side 48h enforcement (C5)

---

## Section 7: Engineering scope decisions

Items that require engineering commitment, not just brief edits. Each is bounded; each is justified by a specific finding.

| Item                                                        | Engineering cost                                                | Justification                                                               | Status              |
| ----------------------------------------------------------- | --------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------------- |
| **In-app post-coercion recovery flow at v1**                | 60-160 hours UI work                                            | E3 catastrophic trigger; user-decided this session                          | ✅ ACCEPTED         |
| Peer-side 48h enforcement (C5)                              | ~40-80 hours                                                    | Cryptographer H5 attack sketch                                              | ✅ ACCEPTED         |
| Device-key co-signature (C6)                                | ~80-160 hours                                                   | Cryptographer H6; required for design-brief.md:422 claim to hold            | ✅ ACCEPTED         |
| Single-use peer phrases + rotation (C8)                     | ~20-40 hours                                                    | Cryptographer M2 + persona 04 E7                                            | ✅ ACCEPTED         |
| Multi-party APK signing-key trustee arrangement (X4)        | One-time setup + trustee renewal                                | Cross-cutting X4                                                            | ✅ ACCEPTED         |
| Duress-canary mechanism for D0009 (M18)                     | 1-2 hrs/month developer + ~20 hrs one-time partner-side         | Maintainer M18                                                              | ✅ ACCEPTED         |
| CVE-response runbook (X3)                                   | 8-16 hours draft                                                | Cross-cutting X3                                                            | ✅ ACCEPTED         |
| Auto-escalation timer at v1 with stale-flag (E8 stale flag) | ~20-40 hours                                                    | Persona 04 erosion pattern + warning-fatigue literature                     | ✅ ACCEPTED         |
| Pre-pilot onboarding exercise (P10)                         | 5-10 sessions × ~2 hrs each + lessons-learned writeup           | Partner P10 + persona 04 E5                                                 | ✅ ACCEPTED         |
| **Paper shares as v1 alternative recovery path (E11, X9)**  | ~40-80 hours                                                    | Multi-persona convergence on recovery problem                               | 🔄 NEEDS-DISCUSSION |
| **Signed encrypted transcript export (E4)**                 | ~20-60 hours                                                    | Persona 04 laptop-workflow partial answer; not multi-device architecturally | 🔄 NEEDS-DISCUSSION |
| **Localization for critical-UI strings (E12)**              | ~40-80 hours infra + per-language translation cost              | Persona 04 E12; depends on Q4 pilot community                               | 🔄 NEEDS-DISCUSSION |
| **Push opt-in as default at v1 (E1, Q12)**                  | Minimal engineering; default-switch + provisioning conversation | Persona 04 catastrophic #1 refinement                                       | 🔄 NEEDS-DISCUSSION |

**Accepted-this-session engineering scope additions to v1: ~250-580 hours** (depending on UI polish level). At the volunteer-baseline 15-20 hrs/week cadence per D0008, this is 3-8 months of calendar time. This is meaningful slippage to the v1 ship date but is in service of closing real gaps the reviews surfaced.

**Pending-discussion engineering additions: ~100-220 hours additional** if all accepted. Decision points cluster on (a) whether the pilot community justifies localization at v1, (b) whether journalism-focused recruitment justifies transcript-export, (c) whether paper shares should be the v1 default recovery path.

---

## Section 8: Structural questions deferred to post-Q5

These are project-posture decisions that require evidence Q5 informal conversations are designed to provide. **Do not decide now; do not pretend the brief is publishable for formal partner outreach without them resolved.**

### S1. Phase D sustainability posture (P20, X1)

**Options:**

1. Re-scope to paid-product / fiscal-sponsor-supported model (Threema precedent; conflicts with §2.1 grassroots framing)
2. Re-scope as contribution to existing project (Briar UX / SimpleX integration shell)
3. Maintain current trajectory; accept broader release will not happen; honestly frame as project's actual goal
4. Secure multi-year operational engineering-capacity grant before pilot launch

**Evidence Q5 conversations should provide:** which framing partner organizations find credible; whether multi-year operational funding is realistic from named funders; whether the journalism audience the persona-04 review represents is actually addressable via the project's architecture at any scope.

### S2. Q5 sequencing (X2, P5)

**Options:**

1. Two-stage protection-program-consultant honoraria → co-draft D0013 → recruit pilot partners
2. Informal Q5 conversations directly with candidate partners; defer formal co-design until specific role asks
3. Both in parallel

**Evidence Q5 conversations should provide:** which partner organizations are willing to engage in protection-program-consultant honoraria for unpaid evaluation work; what their evaluation cycle looks like; whether they would prefer co-design before commitment or commitment before co-design.

### S3. D0016 framing (X6, P21)

**Options:**

1. Maintain current trigger-deferral framing with partner-mediated re-evaluation added
2. Commit to foundation incorporation at v1.5 broader release regardless of trigger criteria (partner-vouching requires enforceable structure)
3. Accept fiscal-sponsor-operated long-term scope; stop calling it "broader release"

**Evidence Q5 conversations should provide:** which partner organizations would require formalized Safe Harbor for broader-deployment engagement; whether named partner-candidates can engage at v1 pilot without formalized structure but require it at v1.5+ broader release.

### S4. Reviewer-pool v1 vs v1.5 (X11, P12, M14)

**Options:**

1. Maintain v1.5 deferral; ship v1 with developer-source-review baseline and explicit pilot-user disclosure (D0013)
2. Recruit smaller v1 reviewer-pool at honorarium scale before v1 ship (the rejected Option B in D0015)
3. Re-scope v1 pilot to lower-threat-tier population for which developer-source-review baseline is sufficient

**Evidence Q5 conversations should provide:** whether named partner-candidates can recruit reviewers from their staff at v1 pilot timing; whether the pilot population can be honestly described as lower-than-§3 threat tier; whether pilot users (when partner-mediated consent is given) can absorb the supply-chain-gap disclosure.

### S5. v1.2 audience framing (P1, X7, E5)

**Options:**

1. Lead with deployable population (four-precondition intersection; "low hundreds globally"); demote threat-tier population list with named exclusions
2. Reframe §3 around the population the architecture actually serves; the broader threat tier becomes "design target" rather than "audience"
3. Accept that §1.2 audience and v1 pilot population diverge; explicitly frame pilot as research instrument with named validity limitations

**Evidence Q5 conversations should provide:** whether partner organizations recognize the four-precondition intersection as the realistic audience or as too narrow to be worth their engagement; whether they would want broader-release scope to match v1 pilot scope or to expand the architecture toward serving more of the §3 threat tier.

---

## Recommended execution sequence

Based on what's decided (Section 0 / Section 7) and what's deferred (Section 8):

**Sprint 1 (now, ~20-40 hours focused work, brief-edit only):**

1. Apply all P0 BRIEF-CLARITY items from Section 6 in a single drafting pass
2. Update D-docs per their listed items in Section 6
3. Apply changelog entry to brief

**Sprint 2 (now-ish, ~30-60 hours focused work, maintainer pre-code items + open-questions):**

1. Draft CVE-response runbook (X3) — 8-16 hours
2. Specify multi-party APK signing custody trustee arrangement (X4) — design + brief edits
3. Q20 runway disclosure resolution (decide publish vs confidential-to-funder; update §10.8)
4. Add Q27 (contributor-attraction) to open-questions
5. Decide and document the four NEEDS-DISCUSSION engineering scope items (paper shares, transcript export, localization, push opt-in default)

**Sprint 3 (over 1-2 weeks, partner-conversation preparation):**

1. Reconciliation pass on brief documentation drift after Sprints 1-2 land
2. Draft one-page "what we're trying to decide" framing for Q5 conversations
3. Identify 2-3 specific named partner-candidate individuals to invite into informal Q5 conversations
4. Prepare four review documents + the v1-scope-expansion summary + the structural-questions-deferred summary as conversation materials

**Sprint 4 (after Q5 evidence lands):**

1. Make S1-S5 structural decisions based on Q5 evidence
2. Update brief accordingly
3. Begin formal partner outreach (now with co-designed substrate, not project-drafted document)
4. Begin v1 engineering against the now-final scope

---

## What this triage explicitly does not commit to

- Engineering work has not begun. The above scope additions are accepted in principle; whether each is feasible at the volunteer-baseline cadence within the v1 timeline is a question for system design when it is drafted.
- The structural decisions S1-S5 are deferred, not made. The brief as it will exist after Sprint 1-2 is publishable for _informal evidence-gathering conversations_ with named partner candidates; it is not yet publishable for _formal partner-recruitment outreach_ until structural questions are resolved.
- The recommended apply-batch is conservative on what counts as "brief-clarity vs structural" — when in doubt, items were left in the structural NEEDS-DISCUSSION column to avoid making decisions Q5 evidence should inform.
- Partner organizations named in the brief (FLD, Tactical Tech, Access Now Helpline, Citizen Lab, Amnesty SecLab, EFF, etc.) have not been consulted; mentions in the brief are candidate-language, not commitment-language. The brief edits in Sprint 1 enforce this distinction throughout.

---

## Document history

- **v1 (2026-05-28):** Initial consolidation from four external reviews. Triage decisions per conversation with maintainer:
  - In-app post-coercion flow moved to v1 commitment
  - Triage Option C (tactical fixes + brief clarity, then Q5 informal conversations, then structural choice) selected
  - Persona 04 catastrophic triggers #1, #2, #4 calibrated to brief-clarity fixes per spot-check analysis
- **v2 (2026-05-29):** Sprint 1 + Sprint 2 execution completed. **Sprint 1 (P0 brief-clarity + engineering-scope-decision documentation):** brief edits applied across 17 sections (§1.2, §2.2, §3.2, §3.5, §3.6 new, §5.1, §5.2, §5.3, §5.4, §5.5, §5.6, §6.1, §6.2, §6.3, §7.1, §8.5, §10.4); D-doc updates across 8 docs (D0002, D0005, D0006 §§4-9 added, D0009, D0011, D0013, D0015, D0016); open-questions Q27 added + Q26 timing + Q12 reframing; architecture-diagrams.md chain scope + peer-side 48h sequence diagram; brief v0.8 changelog entry. **Sprint 2 (maintainer pre-code items + four engineering scope NEEDS-DISCUSSION decisions + reconciliation):** CVE-response runbook drafted at `docs/runbooks/cve-response.md`; multi-party APK signing-key custody runbook drafted at `docs/runbooks/apk-signing-custody.md`; Q20 self-funding runway disclosure resolved as confidential-to-funder under grant-agreement confidentiality (§10.8); Q26 CalyxOS resolution as D0017 (v1 GrapheneOS-only baseline retained; CalyxOS deferred to v1.x); four engineering-scope decisions accepted as v1 commitments (paper-share recovery at v1; signed encrypted transcript export at v1; i18n infrastructure at v1; push opt-in default per Q12 resolution); documentation reconciliation pass through brief sweeping for stale references (in-app post-coercion v1.6 → v1; polling default → push opt-in default; v1.6 entry restructured); brief v0.9 changelog entry. **Triage execution status:** all Sprint 1 + Sprint 2 items applied; Sprint 3 (documentation drift reconciliation pass post-edits, Q5 conversation materials preparation) and Sprint 4 (structural decisions S1-S5 post-Q5 evidence) remain.
- **v3 (2026-05-29):** Sprint 3 execution completed under the **MDC pathway pivot** (user-directed strategic shift: working code before partner conversations; partner conversations against code-as-evidence per comparable-project precedent). **Sprint 3 scope evolved beyond original triage definition** from "documentation drift reconciliation + Q5 conversation materials" to **engineering-foundation decisions enabling Tier 1 MDC implementation start**. **Methodology**: seven parallel deep-research agents dispatched with web-search access on 2026-05-29 covering Rust cryptographic primitives, CBOR + COSE, Shamir Secret Sharing libraries, Tor + arti on Android, SimpleX integration approaches, Rust ecosystem cross-cutting, and UniFFI + Android crypto bindings. Research output synthesized into three new decision documents. **New deliverables**: [D0018](../decisions/D0018-engineering-foundation.md) — engineering foundation (library selections, Rust ecosystem discipline, Cargo workspace baseline, Android build/cross-compile, operational commitments; resolves Q8); [D0019](../decisions/D0019-license.md) — AGPL-3.0-only license decision; [D0020](../decisions/D0020-integration-architecture.md) — SimpleX + Tor + FFI hybrid integration architectures. **Empirical-metrics commitment**: user identified that prior calendar-time estimates were borrowed from non-agentic workflows and produced fanciful projections; Sprint 3 onwards uses surface-completion criteria + empirical cadence measurement starting from first commits rather than borrowed calendar projection. **Brief edits**: Appendix A decision index extended with D0018-D0019-D0020 + Sprint 3 cluster framing; brief v0.10 changelog entry. **Q8 resolution context**: Q8 marked resolved by D0018+D0019+D0020 trio. **Triage execution status post-Sprint-3**: Sprint 4 (informal Q5 partner conversations now possible with engineering-foundation specifications as substrate beyond brief alone) and Sprint 5 (structural decisions S1-S5 post-Q5 evidence) remain. The original Sprint 3 "documentation reconciliation pass" and "Q5 conversation materials" items are absorbed into the post-Tier-1-MDC sequence per the consolidated triage MDC pathway: implementation begins; ~2-4 weeks empirical cadence data accumulates; first Q5 informal conversations occur with both the brief corpus and the first crates.io publication as conversation substrate.
