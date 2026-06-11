# §1 — Calibration Discipline Lens

## Summary

§1 mostly honors §4.2's calibration commitment — bounded-window framing, phase-gate register, "raises the cost of," "substitutes a distributed trust set," "structurally gated on Phase C." The verb sweep §4 received reads as having propagated into §1 at the major architectural-summary verbs. The diction drift that remains is concentrated in two places: (1) noun phrases that bury elimination claims inside a benign-sounding word ("cascade-laundering attack closure," "OIDC provider integrity," "cleanly"), and (2) a "honest/honestly" rhetorical pile-up — five occurrences across seven paragraphs — that pattern-matches to the §2 review F35 finding ("protesting too much"), amplified in §1 to a level a funder will register as the brief's defining verbal tic.

The "honest" pile-up is the load-bearing finding. §1 is the section every downstream funder/partner conversation references; whatever rhetorical move appears here propagates into how the project is described by third parties. "Honest" is a self-claim, not a calibration mechanism — §4.2's calibration principle works because it specifies _what_ the calibrated claim is ("verified through chain of attestations"), not because the prose calls itself honest. F1 is the primary fix; F2–F3 are noun-phrase calibration drifts §4 already caught at verb level but did not reach in noun form.

## Critical findings

### F1: "Honest"/"honestly" used five times in §1 — protesting too much, amplified from §2

- **Evidence:**
  - §1:26 "the reconstruction-window exposure and undefended evil-maid case acknowledged **honestly**"
  - §1:30 "**honest** about what is committed vs conditional" (paragraph header)
  - §1:32 "the project's **honest** map of architecture..."
  - §1:32 "the brief's audience-**honesty** extends to its own non-promises"
  - §1:34 "find their objection elaborated and addressed (or **honestly** acknowledged as a limit)"

  Five occurrences across roughly 1,100 words. §2 review F35 flagged three occurrences in §2.2 as the same pattern. §1 is denser. §4.2:295 by contrast says "Calibrated language replaces absolute-sounding claims" — the principle is named without the prose calling itself honest.

- **Impact:** "Honest" is a self-claim about register, not a calibration mechanism. A sophisticated funder reads repeated self-described honesty as a substitute for the calibration discipline §4.2 actually commits to. The pattern weakens §1 because (a) it reads as the prose protesting its own integrity (Strunk: "needless words"); (b) it is unfalsifiable — the brief asserting it is honest does not make a claim more verifiable; (c) it imports a marketing register ("we'll be honest with you") at the highest-visibility section of a brief whose §4.2 differentiates Cairn by calibrated diction rather than by declarations of integrity. The §10 review's diction reset was specifically to remove this kind of self-laudatory register from §10; §1 reintroduces it at the most-quoted section.

- **Recommendation:** Reduce to at most one occurrence — and only where it carries semantic content the alternative wording would lose. Specific edits:
  - §1:26 "acknowledged honestly" → "acknowledged" or "named explicitly." The honesty is performed by naming the exposure; the adverb adds nothing the noun phrase does not already carry.
  - §1:30 paragraph header "(honest about what is committed vs conditional)" → "(committed vs conditional)." The header should describe content, not editorial posture.
  - §1:32 "the project's honest map" → "the project's working map" or "the project's current map." "Honest" reads as self-praise; "working/current" is calibrated to draft status.
  - §1:32 "the brief's audience-honesty" → "the brief's posture toward audience" or delete the clause; the substance is in the recommendation that follows ("readers should treat Phase A items as the project's unilateral commitments...").
  - §1:34 "honestly acknowledged as a limit" → "explicitly acknowledged as a limit" or "named as a limit." The §10.8 register is "the brief does not promise..." — declarative, not self-described as honest.

## Significant findings

### F2: "Cascade-laundering attack closure" implies complete defeat where §5.2 says "addresses"

- **Evidence:** §1:26 "a cryptographic trust graph with five operation types (...), **cascade-laundering attack closure**, and commitment-only anchoring in Sigsum..."

  §5.2:352 (per §4 review F7 evidence): "The split between withdrawal and compromise revocation is specified in D0006 and **addresses** the cascade-laundering attack identified in the Section 5 adversarial review." §4.3:305 (post-review): "five operations matching §5.2:345; half-sentence noting withdrawal/compromise split closes cascade-laundering attack." The verb in §4 is "closes [the attack]"; in §1 it has been nominalized into "closure" as if it were a property of the system.

- **Impact:** "Closure" as a noun-phrase property reads to a cryptographer as "no longer an attack against the system" — a stronger claim than §5.2's "addresses" or §4.3:305's verb form. The nominalization is the diction drift §4's verb sweep specifically targeted ("defeats" → "raises the cost of") but did not catch in noun form. A reviewer who reads §1's claim and §5.2's text against each other will notice the asymmetry; the reviewer who reads only §1 will carry forward a stronger claim than the brief defends. The cascade-laundering closure claim is also the one most likely to be stress-tested in technical review: it depends on D0006's specific operation-type split, on the soft-vs-hard quarantine semantics in §5.2:374–380, and on participants actually publishing withdrawal vs compromise correctly — none of which §1's bare "closure" surfaces.

- **Recommendation:** Replace "cascade-laundering attack closure" with the verb form §4.3 already uses: "...with the withdrawal/compromise revocation split that addresses the cascade-laundering attack (per [D0006](decisions/D0006-cryptographic-envelope.md) and §5.2)..." or simply "...closing the cascade-laundering attack identified in the §5 adversarial review per D0006..." — preserving the verb form that §5.2 itself uses and naming D0006 as the locus.

### F3: "OIDC provider integrity" is the un-calibrated form of §5.5's "U.S. legal process in v1 effective trust surface"

- **Evidence:** §1:26 "(4) release security that substitutes a distributed trust set — a 5-of-N reviewer attestation threshold, witness cosignatures, **OIDC provider integrity** — for the developer's single signing identity."

  §4 review F4 specifically: "§5.5:488 explicitly names U.S. legal process in the v1 effective trust surface; Q24"; the post-review §4.3:309 reads "...the OIDC provider's jurisdictional posture (§5.5:488 explicitly names U.S. legal process in the v1 effective trust surface; Q24)." §1 collapses "jurisdictional posture under U.S. legal process" into the bare noun "integrity."

- **Impact:** "Integrity" reads as a binary correctness property (the provider operates correctly vs is compromised). The actual claim §5.5:488 makes is that the OIDC provider's _jurisdictional posture_ — its susceptibility to U.S. legal process — is what the user trusts, alongside operational correctness. These are different trust placements. The diction collapse is exactly the trust-substitution-framed-as-trust-elimination move §4 review F4 identified as critical and §4.3 was reworked to fix. §1 reintroduces it in the most-quoted enumeration of the four architectural commitments.

- **Recommendation:** Match §4.3:309's calibrated form. Replace "OIDC provider integrity" with "the OIDC provider's jurisdictional posture (per §5.5 and §3.4)" or "OIDC provider operational and jurisdictional posture per §5.5:488." The phrase costs roughly four words and carries the trust-substitution honesty §4.2 commits to.

## Minor findings

### F4: "Past traffic cannot be decrypted" framing — not in §1 but §4.2 imports it; §1's "post-coercion guidance" framing parallel

- **Evidence:** §1:28 "documentation-form post-coercion guidance" — calibrated. No fix needed; flagging only as the positive-control case showing the verb sweep reached this scope.

- **Impact:** None — the diction is calibrated.

- **Recommendation:** None. Noted for pattern analysis below.

### F5: "Forming" vs present-tense reviewer attestation

- **Evidence:** §1:28 "pilot deployment is gated on (...) **first-quorum reviewer attestation forming** per Section 8.2."

  This is correctly conditional — "forming" not "formed." Confirms the §4 review F2 verb-deflation reached §1.

- **Impact:** None — correctly conditional.

- **Recommendation:** None. Noted as positive control.

### F6: "Substantial original cryptographic engineering" — promotional adjective intensifier

- **Evidence:** §1:22 "**substantial** original cryptographic engineering at the integration boundary"; §1:26 "Cairn's distinct contribution is the integration plus the original construction..."; §1:24 "**substantial** resources to compromise."

  "Substantial" is the kind of self-rating adjective §4.3 commits to narrowing ("each commitment below is narrowed to what is actually distinct rather than presented as exhaustive of the landscape"). §4.3:303 keeps the phrase "ships substantial original cryptographic engineering at this integration layer" — so §1 inherits it consistently. The phrase is defensible at §4.3 where the enumeration that follows substantiates it (capability tokens, trust-graph operation envelope, share format, recovery-flow memory hygiene). In §1 the enumeration is shorter and the adjective carries more weight per word.

- **Impact:** Low. The phrase is consistent with §4.3 and the §1 sentence enumerates the four specific items the adjective is summarizing. A funder reading §1 cold gets "substantial" as a self-rating word ("we did a lot"); a funder reading §1 after §4.3 reads it as a back-reference. The risk is the cold-read funder treats it as marketing.

- **Recommendation:** Optional. Either (a) keep both occurrences in §1 since §4.3 carries the substantiation, or (b) replace one of the two §1 uses with the concrete enumeration: "...plus original cryptographic engineering at the integration boundary (capability-token construction, trust-graph operation envelope with cascade quarantine semantics, share format, recovery-flow memory hygiene)..." — which §1:22 already does in the same paragraph, making the second "substantial" in the same paragraph redundant.

### F7: "Disproportionate for users at lower threat tiers" framing absent from §1

- **Evidence:** §1 does not include the §2.2:81 calibrated framing that the architecture is "disproportionate for users at lower threat tiers." §1:24 does say "The brief does not claim audience breadth v1 cannot deliver" — adjacent but not the same calibration.

- **Impact:** Minor. The §1 audience paragraph could borrow §2.2's "disproportionate for users at lower threat tiers" framing to make the architecture-cost honesty visible at the orientation level rather than only at §2.2's detail level. Without it, §1's audience paragraph reads as "we serve this population" without the symmetric "and we are wrong for this other population" calibration §2.2 carries.

- **Recommendation:** Optional. Consider adding a half-sentence to §1:24 of the form "...the architecture is calibrated to this threat tier and disproportionate for users at lower tiers." This would mirror §2.2's calibration into §1.

## Patterns

**P1. Diction drift survives at noun-phrase level even after the verb sweep.** F2 ("closure"), F3 ("integrity"), and the implicit pattern in F6 ("substantial") all show the same shape: §4's verb-deflation sweep targeted verbs ("defeats" → "raises the cost of") and §1 honors that at the verb level, but nominalizations carry the same un-calibrated claims through. "Cascade-laundering attack closure" is a noun phrase that means the same thing as "defeats the cascade-laundering attack." A second sweep at noun-phrase level — explicitly looking for elimination-implying nouns ("closure," "integrity," "elimination," "completeness," "soundness") and replacing them with verb forms or with explicit cross-references to where the property is qualified — would close this gap. Estimated three to five edits in §1.

**P2. "Honest" as rhetorical floor.** F1 is the headline pattern. The §2 review F35 caught three occurrences in §2.2; §10's review applied the calibration discipline that removed self-laudatory diction from §10. §1, written last to mirror §§2–10, has inherited "honest" as the connective tissue for the brief's calibration commitment. This is precisely backwards: calibration is performed by the diction of specific claims, not by the prose describing itself as honest. The single-most-quoted section of the brief is where this matters most. A funder repeating Cairn's framing in a peer conversation should be repeating "verified through chain of attestations" and "raises the cost of the unlock-to-impersonation chain," not "the brief honestly acknowledges..." — the former are propositions; the latter is a meta-claim about the prose that does not survive being quoted.

**P3. Calibrated forms are present at the architectural verbs but absent at the editorial connective tissue.** Where §1 says "raises the cost of the unlock → peer enumeration → impersonation chain" (§1:26), "substitutes a distributed trust set" (§1:26), "structurally gated on Phase C funding" (§1:28), the calibration is honored at the architectural-claim level. Where §1 says "honest map," "honestly," "honest about," the calibration breaks at the editorial-frame level. The fix is asymmetric: the architectural claims are well-calibrated; the editorial framing surrounding them is not. F1 closes most of the gap; F2 and F3 close the rest.
