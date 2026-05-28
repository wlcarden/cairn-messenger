# Section 1 Adversarial Review — Consolidated Findings

**Date:** 2026-05-28
**Source:** Five parallel sub-agent reviews, distinct lenses (cross-section consistency, first-impression reader, calibration discipline, navigation / what-to-do-next, honest non-promises).
**Raw findings:** 53 across reviewers (consistency 16, first-impression 13, calibration 7, navigation 9, non-promises 11). After deduplication and theming: 24 consolidated findings below.
**Companion to:** [design-brief.md](design-brief.md) Section 1 (lines 18–34), with cross-references to Sections 2–10 and the decision documents.

§1 is the most-quoted section of the brief. Whatever rhetorical move, factual claim, or framing posture appears here propagates into how funders, partner organizations, and reviewers describe Cairn in subsequent conversations. Findings here carry disproportionate weight: a quantitative slip in §1 is the parameter a peer-review email cites; an editorial tic in §1 is the verbal signature partners associate with the project; an omission in §1 is the surface a sophisticated funder discovers at §5 or §10 and then back-propagates as "the brief was optimistic."

---

## Executive summary

Across five lenses, §1 reads as a section that has inherited most of the calibration discipline of §§4–10 at the architectural-claim level but has not propagated that discipline cleanly to (a) compressed quantitative restatements, (b) editorial connective tissue, (c) reader-navigation scaffolding, or (d) the operating-figure altitudes funders actually plan against. Three lens-spanning failures dominate. First, §1 collapses load-bearing conditionals that §§5–10 specify explicitly: a "5-of-N" attestation parameter that conflicts with the "3-of-5 over 5+" architecture §5.5 stakes its security argument on (F1); Briar without its upstream-maintenance dependency (F5); foundation incorporation without §7.1's "materially in progress" softening (F6); recovery without the v1 online-Sigsum dependency §6.1/§9.2 name; OIDC provider reframed as a defensive component rather than a U.S.-jurisdiction trust placement (F2). Second, §1 fails the first-impression brief it sets for itself: seven dense 250–400-word paragraphs with no bullets, an opening sentence that catalogs six spyware vendors before saying what Cairn does, 25+ inline D/Q citations, cryptographic vocabulary without gloss, and a "Where to read next" paragraph that recites the table of contents rather than mapping reader intent to sections — leaving funders, partners, researchers, and pilot candidates with no answer to "what would I do next?" (F3, F4, F8). Third, §1 collapses three commitment framings — committed, intent-subject-to-conditions, aspirational — under the umbrella terms "phase-gated" and "conditional," disclaiming at the funding-event and roadmap-extension altitudes but not at the operating-figure altitudes (gross-of-fiscal-sponsor-fees, BYOD jurisdictional channel availability, person-month estimates, runway gap, landscape-dated subsidy rates), which is the altitude a program officer reads (F9, F10, F11).

A fourth pattern, less load-bearing but the most-quoted-back-by-third-parties of all of them, is the "honest/honestly" rhetorical pile-up — five occurrences across seven paragraphs — that performs calibration rather than performing it through the diction of specific claims (F7). The §2 review caught three occurrences of the same pattern at §2.2; §1 amplifies it at the section every downstream conversation references. Combined with the recursive self-critical framing ("audience-honesty extends to its own non-promises"; the working-name disclaimer in the first ten words; "What this brief is and is not" before the brief has said what it _is_), §1 reads as a project mid-self-critique rather than a project ready to be engaged with. A funder reading "honest map of architecture" reads not the integrity §1 intends to perform but the question "what was I going to be misled about?"

The remaining findings are noun-phrase calibration drift the §4 verb-sweep did not reach ("cascade-laundering attack closure," "OIDC provider integrity," "substantial original"), structural omissions from §1's non-promise list (four §10.8 disclaimers missing, including the load-bearing gross-of-fees and BYOD-channel ones), under-specified roadmap layering (v1.5/v1.6 not disclaimed where v2/v3 are), and §1's own internal navigability problems (bold lead-ins buried in prose blocks rather than promoted to subsection headers a returning reader can scan).

---

## Patterns

Ten patterns emerge across the five lenses; they matter more than any single finding because each pattern names a structural property of §1 rather than a single editable line.

**P1. Compression drops the load-bearing conditional.** Caught by Consistency (F3, F4, F8, F9, F10) and Non-Promises (F5, F6, F9). §1 consistently retains the architectural-commitment headline and drops the qualifier the deeper section preserves. Briar's upstream-maintenance dependency, foundation incorporation as "materially in progress," v1 online-Sigsum dependency for recovery, specialist-roles absorption into the solo developer, engineering scope completion as the Phase A volunteer-baseline contingency, reviewer-pool non-formation risk, and the 18–24-month foundation horizon as gated rather than scheduled — each is named in §§5–10 and lost in §1. The cumulative impact is that §1 reads as a more committed posture than the deeper sections actually specify.

**P2. "Honest" as rhetorical floor displaces calibration as diction.** Caught by Calibration (F7), First-Impression (F3), and reinforced by the §2 review F35 finding (same pattern at §2.2). Five occurrences of "honest/honestly" across roughly 1,100 words in §1. Calibration is performed by the diction of specific claims ("raises the cost of," "verified through chain of attestations," "structurally gated on Phase C"); §1 substitutes self-descriptions of honesty for the calibrated forms. The pattern is unfalsifiable — the prose asserting it is honest does not make a claim more verifiable — and reads to a sophisticated funder as the brief protesting its own integrity. This is the most-quoted-by-third-parties pattern in the section, because "honest" attaches to any context.

**P3. Self-critique displaces self-introduction.** Caught by First-Impression (F3, F10, F11, F12). §1 leads with disclaimers ("working name per D0001" in the first ten words), editorializes its own register in paragraph bold leads ("honest about what is committed vs conditional"), spends an entire paragraph on what the brief "is and is not" before the reader has formed a picture of what it _is_, and closes with a meta-sentence about §1's epistemics rather than a destination. A first-time reader is not yet skeptical enough for any of this to land as integrity — it lands as defensiveness.

**P4. Diction drift survives at noun-phrase level after the §4 verb-sweep.** Caught by Calibration (F8 — F2 + F3 + F6 themed). "Cascade-laundering attack closure" (nominalization of "defeats"), "OIDC provider integrity" (binary correctness reframing of a jurisdictional posture), "substantial original cryptographic engineering" (self-rating intensifier). The §4 verb-sweep targeted verbs ("defeats" → "raises the cost of") and reached §1 at the verb level; nominalizations carry the same un-calibrated claims through. A second sweep at noun-phrase level — explicitly looking for elimination-implying nouns ("closure," "integrity," "elimination," "completeness," "soundness") — closes the gap in three to five edits.

**P5. Quantitative restatement drift at the security-parameter altitude.** Caught by Consistency (F1 critical) and reinforced as the principal instance of a broader pattern. §1's reviewer-attestation parameter ("5-of-N") conflicts with §5.5's load-bearing "3-of-5 over a 5+ pool" — and §5.5 line 506 stakes the security argument on the specific compromise budget (two-reviewer compromise insufficient) that the "5-of-N" reframing erases. §1's other quantitative restatements (engineering scope, foundation timeline, Phase A/B/C/D dollar bands) match the deeper sections; the architectural-commitments paragraph (line 26) is the concentrated drift surface because it compresses §§4–5 across four bullets.

**P6. Density chosen over scannability.** Caught by First-Impression (F2, F6, F11) and Navigation (F6). §1 is written as if to be read end-to-end by a reader who will compare wording against §§2–10. The stated audience — busy programme officer, partner technologist, security researcher in triage — is a scanner, not a re-reader. Seven 250–400-word paragraphs with no bullets, the four architectural commitments delivered inline rather than as a list, Phase A/B/C/D figures crammed into a single run-on sentence, 25+ inline D/Q citations, no whitespace separation between thematic blocks — every formatting choice opposes the busy-reader use case §1 line 20 commits to.

**P7. Navigation paragraph recites the TOC instead of mapping reader intent.** Caught by Navigation (F1, F2, F3, F5). §1's closing paragraph (line 34) walks §2–§10 in serial order with one clause per section — the same information the table of contents carries — then appends generic pointers to `docs/decisions/` and `open-questions.md`. No reader intent is mapped. A funder, partner, researcher, and pilot candidate are all left to read top-to-bottom or guess. Decision documents are cited inline (good) but flattened at navigation; the open-questions tracker is described as a generic catalog despite §1 itself naming Q18 as "the central grant-case question." §1 has done the work of identifying what matters most; the navigation paragraph just doesn't surface it.

**P8. Selective disclaim by altitude.** Caught by Non-Promises (F1, F2, F3, F9, P1). §1's non-promise paragraph disclaims at the funding-event and roadmap-extension altitudes (specific dollar amounts close, v2/v3 timelines, audience-not-served-at-v1) but not at the operating-figure altitudes (gross-of-fiscal-sponsor-fees netting, BYOD jurisdictional channel availability, person-month estimates as developer working figures, runway gap as breached §9.1 commitment, landscape-dated subsidy rates, population estimate as pre-outreach working figure). §10.8 disclaims at both altitudes. Funders read the operating figures.

**P9. Ask is implicit.** Caught by First-Impression (F4, F7, F9) and Navigation (F4). §1 names three reader audiences (funders, partners, researchers) and the brief's purpose includes generating action from them, but §1 never converts that purpose into a per-audience next step. A program officer cannot tell whether they are being asked to fund Phase B, introduce the project to OTF, wait for v1, or do nothing yet. A partner technologist cannot tell whether the ask is "facilitate a pilot" or "review the architecture." A security researcher cannot tell whether the ask is "audit the cryptographic envelope" or "read and comment." §1 closes with structure, not a next step.

**P10. Granularity is uniform across audiences.** Caught by First-Impression (F6, F7, F13). §1 carries cryptographic-engineering vocabulary ("cascade-laundering attack closure," "commitment-only anchoring in Sigsum"), foundation-incorporation timing, person-month estimates, and dollar ranges in the same paragraphs. A multi-audience executive summary needs either one-pass-for-all-audiences plain language with depth in §§2–10, or audience-keyed sub-sections. §1 currently delivers depth uniformly and loses each audience at a different point.

---

## Severity Distribution

- **Critical (F1–F11):** 11 findings. Quantitative or factual claims that conflict with the deeper sections, register failures that propagate as the brief's verbal signature, structural omissions that mislead funders at the operating-figure altitude, and first-impression failures that cost §1 its stated job.
- **Significant (F12–F19):** 8 findings. Compression drops of load-bearing conditionals, noun-phrase calibration drift, non-promise list under-coverage, navigation gaps that survive top-level fixes.
- **Minor (F20–F24):** 5 findings. Register touch-ups, citation attribution corrections, optional enumerations.

---

## Consolidated findings table

| ID  | Severity    | Lens(es)                       | Short title                                                                                                    | Brief citation            |
| --- | ----------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------- | ------------------------- |
| F1  | Critical    | Consistency                    | "5-of-N" reviewer-attestation conflicts with §5.5's "3-of-5 over 5+"                                           | §1:26                     |
| F2  | Critical    | Consistency, Calibration       | OIDC provider reframed as "integrity" instead of U.S.-jurisdiction trust placement                             | §1:26                     |
| F3  | Critical    | First-Impression               | Opening sentence buries the "what" under a threat-actor catalog                                                | §1:22                     |
| F4  | Critical    | First-Impression, Navigation   | Density and length make §1 unskimmable; bold leads not promoted to headers                                     | §1:22, 24, 26, 28, 30, 32 |
| F5  | Critical    | Consistency, Non-Promises      | Briar v1.5 commitment omits upstream-maintenance dependency                                                    | §1:26                     |
| F6  | Critical    | Consistency                    | v1.5 ship-condition compresses "foundation incorporation materially in progress" to "foundation incorporation" | §1:28                     |
| F7  | Critical    | Calibration, First-Impression  | "Honest/honestly" pile-up (5 occurrences) protests too much                                                    | §1:26, 30, 32 (×2), 34    |
| F8  | Critical    | First-Impression, Navigation   | §1 fails to give any named audience a next step                                                                | §1:22, 34                 |
| F9  | Critical    | Non-Promises                   | Gross-of-fiscal-sponsor-fees disclaimer absent from §1                                                         | §1:30, 32                 |
| F10 | Critical    | Non-Promises                   | BYOD hardware-channel jurisdictional availability disclaimer absent                                            | §1:24, 32                 |
| F11 | Critical    | Non-Promises                   | Runway gap mis-framed as missing figure rather than as §9.1 commitment breach                                  | §1:32                     |
| F12 | Significant | Consistency, Non-Promises      | Reviewer-pool recruitment conflated with Q3 funding; §8.2 names it Q5-only at volunteer baseline               | §1:30                     |
| F13 | Significant | Consistency                    | OIDC provider framed as substituted trust component rather than residual surface adding U.S. legal process     | §1:26                     |
| F14 | Significant | Consistency                    | "v1 implementation is solo" omits §6.1 specialist-roles absorption                                             | §1:30                     |
| F15 | Significant | Consistency, Calibration       | Long-lived APK signing key omitted from release-security commitment                                            | §1:26                     |
| F16 | Significant | Calibration                    | "Cascade-laundering attack closure" implies complete defeat where §5.2 says "addresses"                        | §1:26                     |
| F17 | Significant | Navigation                     | Decision documents and open questions flattened at navigation despite §1 naming load-bearing instances inline  | §1:34                     |
| F18 | Significant | Non-Promises                   | Subsidy-program rate-card disclaim repeated but figures not timestamped to brief publication                   | §1:30, 32                 |
| F19 | Significant | First-Impression, Non-Promises | "Low hundreds globally" lands before broader-reach framing and without refinement-commitment epistemic status  | §1:24                     |
| F20 | Minor       | Consistency                    | v1 ship-conditions omit engineering scope completion (§7.1 condition (a))                                      | §1:28                     |
| F21 | Minor       | Consistency                    | "Phase D sustainability cliff" vs §10.4's "sustainability horizon"                                             | §1:30                     |
| F22 | Minor       | Consistency                    | [D0009] over-attribution for unilateral-commitment list                                                        | §1:30                     |
| F23 | Minor       | Non-Promises                   | Researcher Safe Harbor under-qualified relative to §8.5's "not legally enforceable"                            | §1:30                     |
| F24 | Minor       | First-Impression               | "Working name per D0001" in first ten words; cryptographic vocabulary without gloss                            | §1:22, 26                 |

---

# Critical findings

## F1. "5-of-N" reviewer attestation conflicts with §5.5's "3-of-5 over 5+" — the parameter §5.5 stakes the security argument on

**Category:** Quantitative restatement / Threat-model consistency
**Location:** §1:26
**Lenses:** Consistency F1
**Severity:** Critical

**Problem.** §1 line 26 introduces the reviewer-attestation parameter as "a 5-of-N reviewer attestation threshold" inside the four-architectural-commitments enumeration. §5.5 line 506 specifies the parameter as "a 5+ pool size... and a 3-of-5 threshold required for a release to be considered properly verified," with the specific compromise budget being two-reviewer compromise insufficient to issue a false-but-quorum-attested release. §1 itself names the correct parameter once at line 28 ("the 5+ membership and 3-of-5 attestation threshold targets specified in §5.5") — but only buried inside the v1 scope paragraph, not at the architecture-commitments paragraph where §1 first introduces the parameter.

**Evidence.** §1:26 "a 5-of-N reviewer attestation threshold." §5.5:506 "the reviewer pool ships with at least five recruited reviewers, with a threshold of three attestations required... the 5+ pool size provides margin against single-reviewer compromise, attrition, and unavailability; the 3-of-5 threshold mirrors the Shamir parameter in 5.3 and means the compromise of two reviewers is insufficient." §8.2:787 "releases ship when 3-of-5 reviewer attestations form (the architectural threshold from Section 5.5)."

**Impact.** "5-of-N" is a quorum-of-the-whole-pool framing that implies the pool itself is the threshold. The actual design is more permissive about pool size (5+ recruited) and more specific about the compromise budget (two-reviewer compromise insufficient). The technical-reviewer audience §1 names as a primary reader will notice the mismatch at §5.5 and discount §1's calibration accordingly. More damaging: this is the parameter cited in peer-review correspondence and grant applications quoting §1, and it is the parameter on which the security-properties story turns. §5.5's "the 3-of-5 threshold mirrors the Shamir parameter in 5.3" is the architectural-rhyme argument the §1 reframing erases.

**Recommendation.** Replace "a 5-of-N reviewer attestation threshold" in §1 line 26 with "a 3-of-5 reviewer attestation threshold over a 5+ recruited pool" to match §5.5:506 exactly. Alternatively: "a multi-reviewer attestation threshold (3-of-5 over a 5+ pool per §5.5)."

---

## F2. OIDC provider reframed as "integrity" instead of U.S.-jurisdiction trust placement — trust-substitution-framed-as-trust-elimination

**Category:** Calibration / Threat-model consistency
**Location:** §1:26
**Lenses:** Consistency F5, Calibration F3
**Severity:** Critical

**Problem.** §1 line 26 includes "OIDC provider integrity" inside the four-commitment enumeration of "release security that substitutes a distributed trust set... for the developer's single signing identity." Two §1-internal failures coincide: (a) "integrity" is a binary correctness property (provider operates correctly vs is compromised) that collapses the jurisdictional-posture trust placement §5.5:510 names ("the OIDC provider — chosen at project start and named in Section 3.4 trust roots — can issue OIDC tokens for the developer's identity under legal process in its jurisdiction or under coercion of its personnel... v1 uses a U.S.-based OIDC provider in pilot... with the explicit acknowledgment that this places U.S. legal process in the effective trust surface"); (b) the OIDC provider is framed as part of the _defense_ (substituted distributed trust set) when §5.5, §4.3:309, §4.1:275, and §3.4:214 frame it as a residual surface — a trust placement the multi-party stack accepts, not a layer of protection it adds.

**Evidence.** §1:26 "(4) release security that substitutes a distributed trust set — a 5-of-N reviewer attestation threshold, witness cosignatures, OIDC provider integrity — for the developer's single signing identity." §5.5:510 "v1 uses a U.S.-based OIDC provider in pilot... with the explicit acknowledgment that this places U.S. legal process in the effective trust surface." §4.3:309 "the OIDC provider's jurisdictional posture (§5.5:488 explicitly names U.S. legal process in the v1 effective trust surface; Q24)." §4.1:275 "Sigstore (signing infrastructure including OIDC chain; §5.5:488 places U.S. legal process in the effective trust surface via the v1 OIDC provider, Q24)."

**Impact.** A reader who anchors on §1 forms an inverted picture: §5.5 / §4.3 / §3.4 are saying the OIDC provider is a cost the multi-party stack accepts, not a layer of protection it adds. Partner organizations in non-U.S. jurisdictions reading §1 would not see the U.S. legal-process exposure §5.5 names explicitly. This is exactly the trust-substitution-framed-as-trust-elimination move §4 review F4 identified as critical and §4.3 was reworked to fix; §1 reintroduces it in the most-quoted enumeration of the four architectural commitments. The diction "integrity" is itself the calibration drift the §4 verb-sweep targeted but did not catch in noun form.

**Recommendation.** Match §4.3:309's calibrated form. Replace "OIDC provider integrity" with one of:

- "...the OIDC provider's jurisdictional posture (U.S.-based in v1 per §5.5 and §3.4)..." — preserving the trust-substitution honesty §4.2 commits to.
- Move the OIDC-provider clause out of the "substituted trust set" enumeration entirely and add a separate sentence: "The substitution explicitly retains the OIDC provider as a trust placement (U.S.-based in v1 per §5.5), not as a removed one."

---

## F3. Opening sentence buries the "what" under a threat-actor catalog

**Category:** First-impression / Ordering
**Location:** §1:22
**Lenses:** First-Impression F1
**Severity:** Critical

**Problem.** The "What this is" paragraph leads with a five-line sentence naming six commercial spyware products and four forensic-extraction vendors before disclosing what the product _does_ for users. The reader is positioned as a threat-tier analyst before being positioned as someone Cairn might help. The product description ("an integration of existing cryptographic primitives — SimpleX's identifier-less queue protocol, Briar's peer-to-peer-over-Tor design...") does not arrive until ~150 words in. A first-time reader cannot answer "what is this project?" from the opening sentence.

**Evidence.** §1:22 "Cairn (working name per [D0001]...) is a secure-communications product calibrated to users facing state-actor adversaries who deploy mercenary spyware (Pegasus, Predator, and similar commercial offerings), forensic-extraction operators (Cellebrite, MSAB, Magnet AXIOM, GrayKey), and traditional state intelligence services..."

**Impact.** Programme officers and partner technologists triaging briefs decide engagement on the first 30 seconds; this opening fails that test. The threat-actor name-drop reads as positioning ("we know who Pegasus is") rather than orientation ("here is what the tool does"). A reader who came expecting a fundable product is recalibrating downward before the product is described.

**Recommendation.** Lead with a one-sentence plain-English description of what Cairn is and does — e.g., "Cairn is a secure-messaging system for people whose adversaries are willing to spend tens of thousands of dollars to read their messages." Move the spyware/forensics catalog to the second sentence or to §2.1 where the catalog already lives in fuller form. The catalog stays load-bearing for threat-tier calibration; it does not need to be the opening sentence of the executive summary.

---

## F4. Density and length make §1 unskimmable; bold leads not promoted to headers

**Category:** First-impression / Navigation
**Location:** §1:22, 24, 26, 28, 30, 32
**Lenses:** First-Impression F2, Navigation F6, First-Impression F10
**Severity:** Critical

**Problem.** §1 runs seven paragraphs, six of which are single blocks of 250–400+ words with no bullets, no sub-headings within paragraphs, and no whitespace breaks. The "Architectural commitments" paragraph (line 26) is ~440 words and contains four numbered sub-commitments delivered inline rather than as a list. The "Operational and funding posture" paragraph (line 30) is ~370 words and crams Phase A/B/C/D dollar ranges into a single run-on sentence. The bold lead-ins are the only navigational scaffolding and they are not visually separated. §1's stated purpose ("a single-section orientation that lets a busy reader decide whether to engage") is undercut by formatting that resists the busy-reader use case. A returning reader looking for a specific claim ("what was the audience size estimate?" "what's the Phase B funding number?") has to scan ~13 lines of dense prose to find each anchor.

**Evidence.** §1:22, 24, 26, 28, 30, 32, 34 — seven body paragraphs, bold leads ("**What this is.**" "**The threat tier and audience.**" "**Architectural commitments at the orientation level.**" "**v1 scope and roadmap...**" "**Operational and funding posture...**" "**What this brief is and is not.**" "**Where to read next.**") buried at the start of each block rather than promoted to scannable subsection headers.

**Impact.** A reader scanning for "what does v1 deliver" or "what is being funded" cannot find anchor points; the eye slides off the page. Likely outcome: the brief is set aside in favor of one that can be scanned. The bold lead-ins are already structurally subsection-like; not promoting them to headers leaves §1 carrying TOC-level structure as inline prose.

**Recommendation.** Apply three structural changes:

1. Promote the bold lead-ins to numbered subsection headers (§1.1 What this is, §1.2 Threat tier and audience, §1.3 Architectural commitments, §1.4 v1 scope and roadmap, §1.5 Operational and funding posture, §1.6 Scope of this brief, §1.7 Where to read next). This formalizes what is already structurally there and makes §1 scannable from the table of contents alone.
2. Break each paragraph into a 2–3-line lead followed by bullets or short sub-paragraphs. The four numbered architectural commitments in line 26 become a bulleted list. Phase A/B/C/D figures in line 30 become a four-row table or list.
3. Target: any §1 paragraph readable in 15 seconds.

This finding combines and supersedes the originally separate First-Impression F2 (density), Navigation F6 (internal navigability), and First-Impression F10 (bold leads doing too much work) — they describe the same structural failure at different altitudes.

---

## F5. Briar v1.5 commitment omits upstream-maintenance dependency

**Category:** Compression drop / Roadmap conditional
**Location:** §1:26, 28
**Lenses:** Consistency F3
**Severity:** Critical

**Problem.** §1 line 26 describes the communications layer as "SimpleX in v1; Briar joins in v1.5" — unconditional. §1 line 28 names v1.5 ship-conditions and does not include a Briar-specific conditional. §7.1:709 specifies Briar as "subject to Briar's continued upstream maintenance and release cadence — a dependency the brief does not control." §6.2:623 names Briar integration "Conditional on Briar's continued upstream maintenance." §5.4:466 names the Briar protocol "as published by the Briar project and named as a trust root in Section 3.4." A reader of §1 alone sees Briar as a commitment the project controls.

**Evidence.** §1:26 "(SimpleX in v1; Briar joins in v1.5)." §1:28 "Subsequent releases (v1.5 architecture completeness; v1.6 deferred UX...)." §7.1:709 "Adds Briar as the highest-sensitivity tier (subject to Briar's continued upstream maintenance and release cadence — a dependency the brief does not control)." §6.2:623 "Briar integration as the highest-sensitivity tier (per [D0004]). Includes the per-conversation extra-private mode toggle that depends on Briar landing. Conditional on Briar's continued upstream maintenance."

**Impact.** A funder evaluating the roadmap's robustness reads §1 as if v1.5's highest-sensitivity tier is contingent only on Cairn's engineering capacity; the deeper sections name it as additionally contingent on an upstream project Cairn does not control — a dependency parallel to GrapheneOS's continued availability that §9.2:944 surfaces as a real risk. The compression is a clean instance of P1: the architectural-commitment headline retained, the load-bearing conditional dropped.

**Recommendation.** Qualify §1 line 26 as "communications (SimpleX in v1; Briar joins in v1.5, subject to upstream maintenance per §7.1)" — preserves the orientation-level register while pointing readers at the load-bearing conditional.

---

## F6. v1.5 ship-condition compresses "foundation incorporation materially in progress" to "foundation incorporation"

**Category:** Compression drop / Roadmap conditional
**Location:** §1:28
**Lenses:** Consistency F4
**Severity:** Critical

**Problem.** §1 line 28 lists v1.5 ship-conditions including "foundation incorporation per [D0010]." §7.1:709 specifies the actual condition as "(d) foundation incorporation per §8.4 / D0010 is **materially in progress**, such that the structural mitigations broader-release users receive (formalized Safe Harbor per D0012, board-bound governance, formal partner advisory authority per D0009) can be operative when broader release lands." §8.4:817 names the incorporation timeline as "approximately 18-24 months post-v1 launch." §1's compressed "foundation incorporation" reads as a binary precondition (incorporation complete before v1.5 ships) and implies v1.5 cannot ship for at least 18-24 months post-v1 even if all engineering and audit gates close — a timeline §7.1 does not actually require.

**Evidence.** §1:28 "v1.5 broader-than-pilot release is structurally gated on Phase C funding (pre-beta full audit per D0011; foundation incorporation per [D0010]; reviewer-honoraria operating model per Section 8.2)." §7.1:709 "(d) foundation incorporation per §8.4 / D0010 is materially in progress, such that the structural mitigations broader-release users receive... can be operative when broader release lands."

**Impact.** §1's binary-reading creates a v1.5 timeline interpretation tied to §8.4's 18-24-month foundation horizon rather than to §7.1's softer "materially in progress" threshold. A funder reads v1.5 as gated 18-24 months past v1, dampening the broader-reach signal §1 itself depends on for fundability. The deeper section permits earlier broader release.

**Recommendation.** §1 line 28: "...foundation incorporation **materially in progress** per [D0010]..." — single qualifier that preserves orientation register while matching §7.1's actual specification.

---

## F7. "Honest/honestly" pile-up (5 occurrences) — protests too much, amplified from §2

**Category:** Calibration / Editorial register
**Location:** §1:26, 30, 32 (×2), 34
**Lenses:** Calibration F1, First-Impression F3
**Severity:** Critical

**Problem.** §1 uses "honest" or "honestly" five times across roughly 1,100 words. The §2 review F35 flagged three occurrences in §2.2 as the same pattern; §1 is denser. §4.2:295 by contrast says "Calibrated language replaces absolute-sounding claims" — the principle is named without the prose calling itself honest. "Honest" is a self-claim about register, not a calibration mechanism. The pattern propagates: §1 is the section every downstream funder/partner conversation references, and "honest map of architecture" is the kind of phrase a third party quotes back.

**Evidence.**

- §1:26 "the reconstruction-window exposure and undefended evil-maid case acknowledged **honestly**"
- §1:30 paragraph header "**honest** about what is committed vs conditional"
- §1:32 "the project's **honest** map of architecture..."
- §1:32 "the brief's audience-**honesty** extends to its own non-promises"
- §1:34 "find their objection elaborated and addressed (or **honestly** acknowledged as a limit)"

**Impact.** A sophisticated funder reads repeated self-described honesty as a substitute for the calibration discipline §4.2 actually commits to. The pattern weakens §1 because: (a) it reads as the prose protesting its own integrity (Strunk: needless words); (b) it is unfalsifiable — the brief asserting it is honest does not make a claim more verifiable; (c) it imports a marketing register ("we'll be honest with you") at the highest-visibility section of a brief whose §4.2 differentiates Cairn by calibrated diction rather than by declarations of integrity. The §10 review's diction reset was specifically to remove this kind of self-laudatory register; §1 reintroduces it at the most-quoted section. Calibration is performed by saying "raises the cost of the unlock → peer enumeration → impersonation chain" — a verifiable claim. Calibration is not performed by saying "honest map." A funder repeating Cairn's framing in a peer conversation should be repeating propositions, not meta-claims about the prose that do not survive being quoted.

**Recommendation.** Reduce to at most one occurrence — and only where it carries semantic content the alternative wording would lose. Specific edits:

- §1:26 "acknowledged honestly" → "acknowledged" or "named explicitly."
- §1:30 paragraph header "(honest about what is committed vs conditional)" → "(committed vs conditional)." The header should describe content, not editorial posture.
- §1:32 "the project's honest map" → "the project's working map" or "the project's current map." Calibrated to draft status.
- §1:32 "the brief's audience-honesty" → "the brief's posture toward audience" or delete the clause; the substance is in the recommendation that follows ("readers should treat Phase A items as the project's unilateral commitments...").
- §1:34 "honestly acknowledged as a limit" → "explicitly acknowledged as a limit" or "named as a limit." The §10.8 register is declarative, not self-described.

---

## F8. §1 fails to give any named audience a next step

**Category:** Navigation / Actionability
**Location:** §1:22 (purpose claim); §1:34 (navigation paragraph)
**Lenses:** First-Impression F4, F9; Navigation F1, F4
**Severity:** Critical

**Problem.** §1 line 22 names the brief's purpose ("the basis for external review, partnership conversations, and funding discussions"). §1 line 14 (preamble) names three reader audiences; §2.2 adds a fourth (pilot candidates). The "Where to read next" paragraph (line 34) walks §2–§10 in serial order — the same information the table of contents carries — and appends generic pointers to `docs/decisions/` and `open-questions.md`. No reader intent is mapped to a section. A funder evaluating fit cannot tell whether they are being asked to fund Phase B ($20–60K), to introduce the project to OTF, to wait for v1, or to do nothing yet. A partner technologist cannot tell whether the ask is "facilitate a pilot in your community" or "review the architecture." A security researcher cannot tell whether the ask is "audit the cryptographic envelope" or "read and comment." A pilot candidate has to navigate to §2.2's exclusions and §6.3's pilot scope unguided.

**Evidence.** §1:34 "Section 2 establishes the problem, audience, and landscape. Section 3 specifies the threat model. Sections 4 and 5 cover the architecture at the orientation and detailed levels respectively. Sections 6 and 7 cover v1 scope and the roadmap. Section 8 covers operations and governance. Section 9 covers risks and limitations. Section 10 covers funding." This is the TOC in prose form. The closing meta-sentence about §1's working posture is navigationally inert; a reader who disagrees with §1's posture is not told _which section_ their disagreement will be addressed in.

**Impact.** §1 fails the job it explicitly sets itself in line 20 ("a single-section orientation that lets a busy reader decide whether to engage"). The brief's purpose includes generating action; §1 does not convert that purpose into a per-audience next step. Busy readers either give up or read linearly and lose the orientation §1 was meant to provide. §1 has done the work of identifying which decisions and questions matter most (D0006 cited at the cryptographic envelope, Q18 named as "the central grant-case question," Q5 named for partner outreach); the navigation paragraph just doesn't surface it.

**Recommendation.** Replace the serial enumeration with a reader-intent map, and distinguish "to read" from "to engage." Example structure:

- **Funders evaluating fit:** read §10 (phase-gated model), §8.5 (audit budget), §2.3 (differentiation caveat and Q18), §9 (risks). Engage at Q3 (honoraria), Q21 (funding sequence); current pursuit posture in §10.9.
- **Partner organizations evaluating facilitation:** read §2.2 (audience and exclusions), §8.6 (partnership approach), §6.3 (pilot deployment), D0013 (consent and exit). Engage at Q5 (partner outreach is open and the project is actively seeking conversations).
- **Technical reviewers and cryptographers:** read §3 (threat model), §4.3 (differentiation at the integration boundary), §5 (architecture detail), D0006 (cryptographic envelope), §8.5 (audit scope).
- **Pilot candidates and facilitators:** read §2.2 (audience and exclusions), §6.3 (pilot plan), §8.6 (facilitator model), D0013 (consent and exit).

Even acknowledging "no concrete ask at this draft, contact for engagement" would be more actionable than the current silence. Combine with F4's promotion of bold leads to headers so the reader-intent map sits at §1.7.

---

## F9. Gross-of-fiscal-sponsor-fees disclaimer absent from §1

**Category:** Non-promise / Operating-figure altitude
**Location:** §1:30 (figures), §1:32 (non-promise paragraph)
**Lenses:** Non-Promises F1
**Severity:** Critical

**Problem.** §1's Phase A–D dollar ranges (line 30: "~$1.5–3.5K… ~$20–60K… ~$105–405K… ~$90–250K/year") are stated without §10.8's explicit warning that Phase B–D figures are gross of fiscal-sponsor fees of 5–15% (often 10–15% at established sponsors). A program officer reading §1 alone takes "~$20–60K addressable through OTF Secure Audit" as the project's working budget envelope; the real planning figure is 85–95% of that during the pre-incorporation window.

**Evidence.** §10.8:1247 "That Phase B-D figures are net to the project. The figures are stated gross of fiscal-sponsor fees (5–15% per Section 10.2, often 10–15% at established sponsors)." §1:30 reproduces the ranges; §1:32's non-promise paragraph omits the netting caveat entirely.

**Impact.** The understated funding ask is a real number that materially affects "does this project's stated $X cover its stated audit at $Y" pencil-test reasoning at first read. A sophisticated funder who later finds the netting disclaimer in §10.8 will conclude §1 was optimistic to the point of marketing. The figure cannot be silently re-baselined in §10.8 if it has already anchored a funder's expectation in §1. This is the load-bearing instance of P8 (selective disclaim by altitude): §1 disclaims at the funding-event altitude (specific dollars close, specific timelines) but not at the operating-figure altitude funders read.

**Recommendation.** Add to §1's non-promise paragraph: "that the Phase B–D dollar ranges stated above are net to the project — they are gross of fiscal-sponsor fees per §10.8." One clause. Alternatively annotate the figures themselves at §1:30 with "(gross of fiscal-sponsor fees per §10.8)."

---

## F10. BYOD hardware-channel jurisdictional availability disclaimer absent from §1

**Category:** Non-promise / Audience-conditional
**Location:** §1:24 (audience scoping), §1:32 (non-promise paragraph)
**Lenses:** Non-Promises F2
**Severity:** Critical

**Problem.** §1 line 24 names "users without access to GrapheneOS-Pixel hardware through standard commercial channels" as out of scope but treats hardware-availability as a binary in/out-of-scope question. §10.8:1248 names the gradient explicitly: hardware availability is not consistent across jurisdictions, the project's loaner pool (2–4 devices) does not mitigate jurisdictional channel closures, and the BYOD posture per §10.1 depends on channel availability the project does not control. A partner organization in a jurisdiction where Pixel availability is unstable (sanctions environments; gray-market device-import regimes; jurisdictions where Google Play Services certification practices affect Pixel imports) reads §1 and treats their constituency as in-scope; learns at §10.8 that the BYOD model assumes channel availability they may not have.

**Evidence.** §10.8:1248 "That hardware availability for the BYOD pilot model will be consistent across all candidate-user jurisdictions… the project's small loaner pool (2–4 devices) is the operational mitigation for short-term availability gaps but not for jurisdictional channel closures." §1:24 treats hardware as binary in/out-of-scope without surfacing the gradient.

**Impact.** This is a partnership-conversation hazard the §1 audience description does not flag. A partner reading §1, identifying their constituency as in-scope, and entering the conversation expecting Cairn to serve them, finds at §10.8 that their jurisdiction's channel availability is the operative constraint. The §1 framing forecloses a productive Q5 outreach.

**Recommendation.** Add to §1's non-promise paragraph: "that GrapheneOS-Pixel hardware will be available through standard commercial channels in every candidate-user jurisdiction — the BYOD posture per §10.1 depends on channel availability the project does not control and the small loaner pool does not address closures at jurisdictional scale."

---

## F11. Runway gap mis-framed as missing figure rather than as §9.1 commitment breach

**Category:** Non-promise / Cross-section commitment breach
**Location:** §1:32
**Lenses:** Non-Promises F3
**Severity:** Critical

**Problem.** §1 line 32 acknowledges "the self-funding runway commitment Section 9.1 makes… is not delivered in this draft and is acknowledged as a §9.1-to-§10 gap in Section 10.8." This treats the gap as a missing data point. §10.8:1249 frames it more sharply as a documented breached cross-section commitment: §9.1 explicitly stated §10 would deliver this figure as "the financial floor of all v1 funding-related risk discussions," funders should request the runway figure directly from the developer, and §10.7's "All Phase B funding fails for an extended period" failure mode is bounded against an unstated rather than a stated horizon. §1's softening loses the discipline §10.8 is enforcing.

**Evidence.** §10.8:1249 "Funders evaluating Phase A duration risk and Phase B funding-window timing should request the runway figure directly from the developer; the brief does not currently commit a number, and Section 10.7's 'All Phase B funding fails for an extended period' failure mode is therefore bounded against an unstated rather than a stated horizon."

**Impact.** A funder reading only §1 sees an acknowledged gap and infers the project is working on it. A funder reading §10.8 sees an instruction to request the figure and a flagged structural weakness in §10.7's risk analysis. §1's compression converts a known-actionable disclosure into a vague known-incomplete disclosure, downgrading the discipline §9.1 and §10.8 jointly enforce. P3 instance: the runway gap is the most surfaced cross-section commitment breach in the brief; flattening it dampens the discipline.

**Recommendation.** Either match §10.8's framing in §1 ("funders should request the v1 self-funding runway figure directly from the developer; §10.7's Phase B funding-failure analysis is bounded against an unstated horizon") or trim the §1 reference to "see §10.8 for the §9.1-to-§10 runway disclosure gap" rather than half-restating it. The former preserves the actionability; the latter offloads cleanly.

---

# Significant findings

## F12. Reviewer-pool recruitment conflated with Q3 funding; §8.2 names it Q5-only at the volunteer baseline

**Category:** Cross-section consistency / Funding gate misattribution
**Location:** §1:30
**Lenses:** Consistency F2, Non-Promises F9 (partial)
**Severity:** Significant

**Problem.** §1 line 30 frames reviewer-pool recruitment as "conditional on Q3 (funding for honoraria) and Q5 (NGO partner outreach) per Section 8.6." §8.2:791 specifies that "the reviewer pool operates on a volunteer-attestation basis" at the v1 self-funded-MVP baseline; honoraria become the operational model "once partnership or grant funding closes (Q3)." §10.1:1084 lists "reviewer-pool recruitment outreach (Section 8.2 volunteer-attestation baseline)" as a Phase A item, explicitly not funding-gated. §7.1's v1 ship-condition (d) — first-quorum reviewer attestation forming — depends on the volunteer pool forming, not on honoraria funding closing.

**Evidence.** §8.2:791 "For the v1 self-funded-MVP baseline, the reviewer pool operates on a volunteer-attestation basis." §10.1:1084 lists reviewer-pool recruitment as a Phase A item. §1:30 lists Q3 + Q5 as joint conditions; Q10 itself drifts in the same direction but §8.2 / §10.1 are the load-bearing specs.

**Impact.** §1 implies the reviewer pool cannot form without funding. A funder reading §1 misreads the funding criticality of pool formation. A partner-organization reader misreads what the project is asking for at Q5 outreach (volunteer reviewer commitment, not paid reviewer slot). §9.1's "Reviewer and witness pools may not form or may erode" risk is a different and more severe framing the §1 compression elides.

**Recommendation.** Reframe §1:30 as: "Reviewer-pool recruitment is conditional on Q5 (NGO partner outreach) per §8.2 (volunteer-attestation baseline at Phase A); the volunteer-to-honoraria transition is conditional on Q3 (funding closes). Partner-organization arrangements and witness-pool composition are conditional on Q5." Separates the recruitment gate (Q5) from the compensation gate (Q3). Optionally reference §9.1 explicitly: "with pool-non-formation risk per §9.1."

---

## F13. OIDC provider framed as substituted trust component rather than residual surface

**Category:** Threat-model consistency
**Location:** §1:26
**Lenses:** Consistency F5
**Severity:** Significant (subsumed by F2 as the primary finding; this preserves the consistency-lens framing)

**Problem.** Companion to F2 above. The Consistency lens framed this as the OIDC provider being listed as a substituted-trust component in §1's enumeration while §3.4, §5.5, §4.3 name it as a residual trust placement adding U.S. legal process. F2 captures the Calibration-lens diction critique ("integrity"); this entry captures the Consistency-lens structural critique (wrong side of the substitution).

**Recommendation.** Resolved by the F2 fix if it addresses both the diction ("integrity" → "jurisdictional posture") and the structural placement (move out of the "substituted distributed trust set" enumeration into an explicit trust-placement-retained clause). If the F2 fix only addresses diction, this finding remains open.

---

## F14. "v1 implementation is solo" omits §6.1 specialist-roles absorption

**Category:** Cross-section compression / Operational scope
**Location:** §1:30
**Lenses:** Consistency F9
**Severity:** Significant

**Problem.** §1 line 30 names "v1 implementation is solo." §6.1:591 specifies that "solo" means absorbing three specialist roles (part-time cryptographic consulting, UX-focused engineer, documentation and community-management role) into one developer at the volunteer baseline. §8.1:775 frames rolling cryptographic consulting as the "aspirational addition when partnership or grant funding closes." §9.1:904 names this as "the most concentrated risk in the project's structure."

**Evidence.** §6.1:591 "Solo-developer absorption of §8.1 specialist roles. Section 8.1 identifies three specialist roles (part-time cryptographic consulting; UX-focused engineer; documentation and community-management role) as funding-gated additions, with §5.6 UX alone estimated at 30–50% of v1 implementation effort. v1 absorbs these specialist scopes into the solo developer's working set at the volunteer baseline."

**Impact.** §1's three-word framing is technically accurate but does not surface that "solo" means absorbing three specialist roles into one developer. A funder evaluating "is this fundable at the Phase A volunteer baseline?" needs to see that "solo" means more than headcount. P1 instance: architectural-commitment headline retained, load-bearing conditional (specialist-roles absorption) dropped.

**Recommendation.** §1:30 "v1 implementation is solo, with the §8.1 specialist roles (cryptographic consulting, UX engineering, documentation) absorbed into the developer's working set at the volunteer baseline per §6.1 — the concentration §9.1 names as the project's most concentrated risk."

---

## F15. Long-lived APK signing key omitted from release-security commitment

**Category:** Threat-model consistency / Compression drop
**Location:** §1:26
**Lenses:** Consistency F6
**Severity:** Significant

**Problem.** §1:26 framing "release security that substitutes a distributed trust set... for the developer's single signing identity" implies the developer's single signing identity has been fully replaced. §5.5:502 makes clear the long-lived APK key persists as a single-credential surface: "The project must therefore hold a long-lived Android signing identity for APK signature continuity (required for updates to install over prior versions). That key is protected as carefully as the threat model demands — held in a hardware security token, with rotation supported via APK Signature Scheme v3 key rotation if a future compromise requires it." §5.5:520 frames the long-lived APK key compromise as "the harder scenario" with multi-release rotation as the recovery process — the heaviest-recovery scenario in the brief. §9.3:962 lists it as a trust-root compromise scenario.

**Evidence.** §5.5:502, §5.5:520, §9.3:962 as cited.

**Impact.** A technical reviewer comparing §1 against §5.5 finds the §1 framing materially incomplete. The "substitutes for the developer's single signing identity" reads as complete substitution; the actual design retains the heaviest-recovery single-credential surface.

**Recommendation.** §1:26 "release security that substitutes a distributed trust set... for the developer's single **per-release** signing identity, retaining the long-lived APK signing key as the residual single-credential surface per §5.5." Two added words ("per-release") plus one clause.

---

## F16. "Cascade-laundering attack closure" implies complete defeat where §5.2 says "addresses"

**Category:** Calibration / Noun-phrase drift
**Location:** §1:26
**Lenses:** Calibration F2
**Severity:** Significant

**Problem.** §1:26 nominalizes "cascade-laundering attack closure" as a property of the system. §5.2:352 uses the verb form "addresses the cascade-laundering attack." §4.3:305 (post-review) uses "closes cascade-laundering attack" in verb form. §1 has nominalized into "closure" as if it were a system property — the diction drift §4's verb-sweep specifically targeted ("defeats" → "raises the cost of") but did not catch in noun form.

**Evidence.** §1:26 "cascade-laundering attack closure"; §5.2:352 "addresses the cascade-laundering attack identified in the Section 5 adversarial review"; §4.3:305 "half-sentence noting withdrawal/compromise split closes cascade-laundering attack."

**Impact.** "Closure" as a noun-phrase property reads to a cryptographer as "no longer an attack against the system" — a stronger claim than §5.2's "addresses." The nominalization is the diction drift §4's verb sweep targeted but did not reach in noun form. The closure claim is also the one most likely to be stress-tested in technical review: it depends on D0006's specific operation-type split, the soft-vs-hard quarantine semantics in §5.2:374–380, and on participants actually publishing withdrawal vs compromise correctly — none of which §1's bare "closure" surfaces. P4 instance.

**Recommendation.** Replace with the verb form §4.3 already uses: "...with the withdrawal/compromise revocation split that addresses the cascade-laundering attack (per [D0006] and §5.2)..." Bundle with a second noun-phrase sweep targeting elimination-implying nouns across §1 ("closure," "integrity," "elimination," "completeness," "soundness") — estimated three to five edits.

---

## F17. Decision documents and open questions flattened at navigation despite §1 naming load-bearing instances inline

**Category:** Navigation / Cross-document instruments
**Location:** §1:34
**Lenses:** Navigation F2, F3, F8, F9
**Severity:** Significant

**Problem.** §1 cites 11 of 14 decision documents inline at point-of-claim (D0001, D0003, D0004, D0005, D0006, D0008, D0009, D0010, D0011, D0012, D0013, D0014) and 5 open questions (Q3, Q5, Q17, Q18, Q19). At navigation, the closing paragraph (line 34) treats them as undifferentiated ranges: "Decision documents in `docs/decisions/` (D0001–D0014)... open questions in [open-questions.md] (Q1–Q26)." Appendix A.2 groups decisions thematically but §1 does not point to that grouping. The brief has done the work of identifying which decisions and questions are load-bearing (D0006 for cryptographic envelope, Q18 as "the central grant-case question," Q5 as the partner-engagement hook); the navigation paragraph just doesn't surface it. The open-questions filename is linked three times from §1 with mixed usage (active-engagement reference vs catalog browsing) and no signaling.

**Evidence.** §1:34 generic ranges; §1:32 "Q18... the central grant-case question"; §1:30 Q3, Q5; §1:24 Q17, Q19. Appendix A.2 thematic grouping not referenced from §1.

**Impact.** A sophisticated funder or researcher conditioned to read decision logs is not told the decision register exists as a coherent artifact. A partner organization that wants to engage at Q5 (NGO partner outreach) cannot tell from §1 that Q5 is the partner-engagement entry point — they would have to read §8.6 first. Funders evaluating "what is the project still working out" cannot tell which questions are central versus housekeeping — Q24 (reserved/duplicate) is in the same flat range as Q18.

**Recommendation.** Combine with F8's reader-intent map. Add to §1:34: "The most load-bearing decisions are D0006 (cryptographic envelope), D0008 (volunteer-baseline cadence), D0011 (audit budget and timing), and D0014 (non-peer recovery); Appendix A.2 organizes the full register by theme." Add a "Where the project is actively engaging" sub-section surfacing Q18 (differentiation evidence), Q5 (partner outreach), Q3 (funding), Q17 (audience size), Q20 (self-funding runway) as the open items with the highest grant-and-partner relevance.

---

## F18. Subsidy-program rate-card disclaim repeated but figures not timestamped to brief publication

**Category:** Non-promise / Landscape-dating
**Location:** §1:30, §1:32
**Lenses:** Non-Promises F7
**Severity:** Significant

**Problem.** §1:32 disclaims "that the named subsidy programs will be open at the rates cited when Cairn applies." §10.8:1246 frames the issue more broadly: "Subsidy-program landscape and audit-firm rate cards both shift on multi-year horizons (OTF's funding was contested in 2024-2025; Mozilla restructured its open-source funding repeatedly; security-engineering market rates moved materially during 2020-2025). Floors and ceilings are stated against the landscape as of brief publication and require re-baselining at each application cycle." §1 has the program-may-not-be-open disclaim but not the figures-are-landscape-dated framing. The figures themselves are not timestamped.

**Evidence.** §10.8:1246; §1:30 figures stated unconditionally; §1:32 disclaim names program availability but not rate-card dating.

**Impact.** A funder evaluating the brief six months after publication takes the §1 ranges at face value; the program landscape (especially OTF's funding contestation) may have shifted materially. P8 instance.

**Recommendation.** Add a parenthetical to §1's figure presentation: "Phase B ~$20–60K (rates and subsidy-program availability as of brief publication, per §10.8 re-baselining caveat)." Or extend the non-promise paragraph: "the dollar ranges above are stated against the subsidy and rate-card landscape as of brief publication and require re-baselining at each application cycle per §10.8."

---

## F19. "Low hundreds globally" lands before broader-reach framing and without refinement-commitment epistemic status

**Category:** First-impression / Non-promise compounding
**Location:** §1:24
**Lenses:** First-Impression F8, Non-Promises F8
**Severity:** Significant

**Problem.** Two related failures co-locate at the audience paragraph. (a) §1:24 names "low hundreds globally" as the v1 four-precondition population three paragraphs before §1:28 names the v1.5/v2/v3/v4+ expansion path. A first-impression reader hits "low hundreds" first and may mentally file the project as "too small to scale" before the roadmap arrives. (b) §1:24 reproduces the figure as a parenthetical "(Q17)" without the refinement-commitment framing §2.2:69 carries: "an estimated population size for the four-precondition v1 intersection… Q17 in open-questions.md commits the project to refining this estimate through partner-organization outreach." A program officer reads "low hundreds globally" as analytical assessment; it is the developer's pre-outreach working estimate the project explicitly intends to refine.

**Evidence.** §1:24 "the estimated population for the full four-precondition v1 intersection is on the order of low hundreds globally (Q17)." §1:28 v1.5/v2/v3/v4+ expansion several paragraphs later. §2.2:69 refinement-commitment framing.

**Impact.** First-impression reader forms the smallest-audience interpretation of v1 before encountering the architecture-expansion roadmap. Compounds with the "v2 USB and iOS; v3 mesh radio" phase-gate disclaim to dampen the broader-reach signal §1 itself depends on for fundability. The non-promise compounding fails to flag the epistemic status of the estimate.

**Recommendation.** Two-part fix:

- Co-locate the v1 numbers with the broader-reach framing: "v1 pilot is 10–15 users in a closed cohort; the v1 architecture serves a four-precondition population on the order of low hundreds globally; v1.5/v2 expansion paths lift the addressable audience to [magnitude]."
- Replace bare "(Q17)" with "(working estimate pending partner-outreach refinement per Q17)" so the reader sees the estimate's epistemic status without chasing to open-questions.md.

---

# Minor findings

## F20. v1 ship-conditions omit engineering scope completion (§7.1 condition (a))

**Category:** Compression drop / Roadmap conditional
**Location:** §1:28
**Lenses:** Consistency F10
**Severity:** Minor

§1 names three of four v1 ship-conditions and omits engineering scope completion. §7.1:707 lists engineering scope first because it carries the Phase A volunteer-baseline cadence dependency. A funder reading §1's three conditions infers a faster v1-launch path than §7.1 actually specifies. Fix: §1:28 add "pilot deployment is gated on engineering scope completion (~9-12 person-months at Phase A volunteer-baseline cadence per D0008), on the pre-pilot cryptographic-primitives audit..."

## F21. "Phase D sustainability cliff" vs §10.4's "sustainability horizon"

**Category:** Register drift
**Location:** §1:30
**Lenses:** Consistency F12
**Severity:** Minor

§1 calls it the "Phase D sustainability cliff"; §10.4:1181 uses "sustainability horizon." "Cliff" implies a sharp boundary; "horizon" implies a finite but extending range. Fix: replace "cliff" with "horizon" in §1:30 to match §10.4 register exactly. Note: this is also the "Phase D sustainability cliff" meta-commentary First-Impression F7 recommends cutting from §1 entirely; if cut, F21 resolves by deletion.

## F22. [D0009] over-attribution for unilateral-commitment list

**Category:** Citation attribution
**Location:** §1:30
**Lenses:** Consistency F13
**Severity:** Minor

§1:30 attributes "documentation discipline, license, release-mechanism architecture, disclosure policy, source-from-day-one" to D0009. D0009 covers sudden-developer-unavailability specifically. Source-from-day-one is §9.4:1058; disclosure policy is §8.5:874 / §9.4:1040; release-mechanism architecture is §5.5 / §8.2; license is §8.3:803. Fix: reframe §1:30 attribution: "documentation discipline (§9.4), license (§8.3), release-mechanism architecture (§5.5, §8.2), disclosure policy (§8.5, §9.4), source-from-day-one (§9.4 successor documentation)." Or move D0009 citation to attach specifically to the dead-man's-switch / partner-advisory aspects.

## F23. Researcher Safe Harbor under-qualified relative to §8.5's "not legally enforceable"

**Category:** Non-promise / Operational claim
**Location:** §1:30
**Lenses:** Non-Promises F10
**Severity:** Minor

§1:30 says "researcher Safe Harbor is the project's stated intent until incorporation." §8.5:874 sharpens: "this is a published preference rather than a legal protection — the project is operated by a natural person (the developer) whose commitment is not enforceable against future personal action, successors, or coercion-induced exceptions." Fix: add "(unenforceable against future personal action, successors, or coercion-induced exceptions per §8.5 until foundation incorporation)" — or relocate to non-promise paragraph: "researcher Safe Harbor is not legally enforceable until foundation incorporation per §8.5."

## F24. "Working name per D0001" in first ten words; cryptographic vocabulary without gloss

**Category:** First-impression / Density
**Location:** §1:22, §1:26
**Lenses:** First-Impression F11, F12, F6, F13
**Severity:** Minor (subsumed under F4's structural fix; preserved here for completeness)

(a) "(working name per [D0001])" appears in the first ten words of §1; the reader's first impression of the product name is "this is provisional." Fix: drop the parenthetical; note working-name status in the "About this document" preamble or in §2.
(b) Within §1:26 alone the reader encounters without definition: "three-tier identity model," "cryptographic trust graph," "cascade-laundering attack closure," "commitment-only anchoring in Sigsum," "Shamir-among-peers," "pre-shared peer challenges," "5-of-N reviewer attestation threshold," "OIDC provider integrity." A first-impression reader outside the cryptographic-protocol community sees jargon and infers "this is for someone else to evaluate." Fix: replace each term with plain-English gloss in §1, retaining precise terms at §§4–5, or add one-line parenthetical glosses on first occurrence.
(c) "9–12 person-months for v1" (§1:28) is engineering bookkeeping for a §10 reader, not orientation. Cut from §1; reference effort in §10 where cadence framing lives.
(d) 25+ inline D/Q citations interrupt reading flow. §1 should be readable without any D/Q citations; move citations to §§2–10 where they live in context.

These individually-minor items collectively belong to the F4 structural fix (subsection headers + bullets + scan-first formatting) and are listed here to ensure the prose edit pass catches each.

---

# Action plan

Findings break into four action categories.

## A. Prose edits to §1 — surgical, apply now to current draft

Straightforward textual edits the brief author can apply without architectural decisions. Order matters: F4 (structural promotion of bold leads to headers) should be applied first because subsequent prose edits land inside the new structure.

1. **F4** — Promote bold lead-ins to subsection headers (§1.1–§1.7); convert four numbered architectural commitments at line 26 to a bulleted list; convert Phase A/B/C/D figures at line 30 to a four-row table or list.
2. **F1** — Replace "5-of-N" with "3-of-5 over a 5+ pool" at §1:26.
3. **F2** — Replace "OIDC provider integrity" with "OIDC provider's jurisdictional posture (U.S.-based in v1 per §5.5 and §3.4)" and move out of the substituted-trust enumeration.
4. **F3** — Lead with plain-English one-sentence product description; move spyware/forensics catalog to second sentence.
5. **F5** — Add Briar upstream-maintenance qualifier at §1:26.
6. **F6** — Add "materially in progress" qualifier to foundation incorporation at §1:28.
7. **F7** — Reduce "honest/honestly" to at most one occurrence; apply the five specific edits listed in the finding.
8. **F8** — Replace serial TOC enumeration with reader-intent map (funders / partners / researchers / pilot candidates), distinguishing "to read" from "to engage."
9. **F9** — Add gross-of-fiscal-sponsor-fees disclaim to non-promise paragraph.
10. **F10** — Add BYOD jurisdictional-channel-availability disclaim to non-promise paragraph.
11. **F11** — Match §10.8's runway-gap framing or trim to clean cross-reference.
12. **F12** — Reframe reviewer-pool recruitment as Q5-conditional (not Q3+Q5).
13. **F14** — Add §6.1 specialist-roles absorption to "v1 implementation is solo."
14. **F15** — Add "per-release" qualifier and long-lived APK key residual surface acknowledgment.
15. **F16** — Replace "cascade-laundering attack closure" with verb form per §4.3.
16. **F17** — Add load-bearing decisions named + Appendix A.2 pointer + active-engagement Q-questions to navigation paragraph (combined with F8).
17. **F18** — Add landscape-dating parenthetical to figures or non-promise paragraph.
18. **F19** — Co-locate v1 audience numbers with broader-reach framing; replace bare (Q17) with refinement-commitment epistemic-status framing.
19. **F20–F23** — Apply minor prose edits as listed.
20. **F24** — Apply density/gloss/citation-removal edits as part of the F4 structural pass.

**Estimated effort:** All A-category edits are textual and can be applied to §1 in a single prose pass after F4's structural reorganization. No new decisions required.

## B. Structural changes requiring author decision

1. **F4 structural promotion** — Decision: promote bold leads to numbered subsection headers (§1.1–§1.7), or leave as bold leads inside paragraph blocks? Recommendation: promote. Rationale: §1's stated job is orientation for busy readers; bold leads buried in 250–400-word blocks fail the job. Promoting formalizes structure already implicit.
2. **F8 reader-intent map structure** — Decision: replace serial TOC enumeration with reader-intent map, or supplement it? Recommendation: replace. Rationale: the TOC carries the structural enumeration job at the top of the brief; §1's navigation paragraph duplicates that and fails the orientation job. Supplementing keeps both; replacing commits to orientation as §1's job.
3. **F7 register decision** — Decision: reduce "honest" to ≤1 occurrence, or revise §4.2's calibration principle to permit self-described honesty? Recommendation: reduce. Rationale: the §10 review's diction reset explicitly removed self-laudatory register; §1 reintroduces it at the most-quoted section. The asymmetric pattern is incoherent.

## C. Open-questions additions

Findings that surface questions the brief should track openly rather than resolve textually.

- **No new open questions are strictly required from §1 review.** F11 (runway gap) is already tracked as the §9.1-to-§10 disclosure gap in §10.8. F12 (reviewer-pool recruitment gate) clarifies an existing Q3/Q5 mapping rather than opening new territory. F18 (rate-card landscape-dating) is captured by §10.8's existing discipline.
- **Optional new open question** — should §1's brief-versioning policy be tracked openly (Non-Promises P5(d): no statement of whether the brief itself is versioned and how readers know which version a partner conversation referenced)? Author judgment.

## D. Findings to reject or defer

- **Non-Promises F11 ("Q5 partner outreach as concentrated dependency" surfaced explicitly in §1)** — Recommendation: defer. The dispersion is real (Q5 gates reviewer pool, deployment facilitation, differentiation-argument validation, direct-grant credibility) but surfacing this at §1 may overload the section. Better placed at §10.9 or as a cross-cutting note in §8.6. Author judgment.
- **Calibration F4 ("post-coercion guidance" calibrated)** — Positive control; no action.
- **Calibration F5 ("forming" present-tense)** — Positive control; no action.
- **Calibration F6 ("substantial" intensifier)** — Optional. Consistent with §4.3 which carries substantiation; cold-read funder risk is real but bounded.
- **Calibration F7 ("disproportionate for users at lower threat tiers" mirror)** — Optional. Would mirror §2.2's calibration into §1 but adds register without closing a specific gap.
- **Consistency F15 (D0014 candidate-paths enumeration)** — Optional. §1 length is binding; the four-path enumeration adds 12 words for partner-organization-reader benefit. Author judgment.

---

# Strategic note

This review is shorter in absolute terms than the §§8/9 review (24 findings vs 30) but covers a section roughly one-twentieth the length. The finding density is higher because §1 is a compression of §§2–10 and every compression decision is a calibration decision visible to a sophisticated reader.

The most actionable single edit is F4 (structural promotion of bold leads to subsection headers + scan-first formatting), because every other prose edit lands inside whatever structure §1 carries. Applying the prose-level fixes (F1–F3, F5–F19) to the current paragraph-block format addresses the textual problems but leaves the unskimmable-density problem (P6) and the navigation problem (P7) unresolved. Applying F4 first creates the scaffolding for the other edits to land cleanly.

After F4, the next-highest leverage are F7 (honest pile-up — propagates as the brief's verbal signature in third-party conversations), F1 + F2 (quantitative and calibration drift at the architectural-commitments paragraph — the load-bearing parameter and the trust-substitution honesty), and F8 + F17 (reader-intent map + load-bearing decision/question surfacing — the brief's intellectual investment in decision-document discipline becomes visible to readers who only read §1).

§1's overall posture — orientation-altitude executive summary mirroring §§2–10's calibration — is the right posture for the section. The remaining gaps are at the level of specific compressions not living up to the section-level posture; closing them does not require revising the strategy, only the prose plus a modest structural reorganization. The brief's design-discipline strength noted in the §§8/9 review applies to §1 as well; the calibration discipline has not yet been propagated cleanly to the editorial connective tissue, the navigation scaffolding, or the operating-figure altitudes funders read.
