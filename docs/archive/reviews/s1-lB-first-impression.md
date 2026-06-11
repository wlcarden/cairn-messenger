# §1 — First-Impression Lens

## Summary

A first-time reader — a programme officer triaging twenty briefs, a partner technologist deciding whether to facilitate a pilot, a security researcher deciding whether to spend an afternoon on the architecture — encounters §1 as an unbroken wall of dense paragraphs, each 250–400 words long, every other sentence pivoting through a parenthetical reference to a decision document (D0001–D0014), an open question (Q3, Q5, Q17, Q19), or a forward section pointer (§§2–10). The substantive content is there — what the project is, who it serves, what is being asked — but it is buried under qualification, cross-reference, and meta-commentary about the brief's own honesty posture. A skimming reader who gives §1 ninety seconds will likely come away knowing "secure messaging, very targeted users, very narrow pilot, hedged about funding" without forming a confident mental model of what to do next or what is concretely being asked.

The opening paragraph leads with a five-line sentence naming six commercial spyware products and four forensic-extraction vendors before disclosing what the product _does_ for users. The reader is positioned as a threat-tier analyst before being positioned as someone Cairn might help. By the time §1 says "10–15 user cohort … low hundreds globally," the reader who came expecting a fundable product is recalibrating downward and may stop reading. The closing paragraphs ("non-promises," "§9.1-to-§10 gap," "audience-honesty extends to its own non-promises") are admirable in a footnote and disorienting as a first impression — they signal a project mid-self-critique rather than a project ready to be engaged with.

## Critical findings

### F1: Opening sentence buries the "what" under a threat-actor catalog

- **Evidence:** Lines 22 — the "What this is" paragraph leads: "Cairn (working name per [D0001]…) is a secure-communications product calibrated to users facing state-actor adversaries who deploy mercenary spyware (Pegasus, Predator, and similar commercial offerings), forensic-extraction operators (Cellebrite, MSAB, Magnet AXIOM, GrayKey), and traditional state intelligence services…". The reader is 80 words in before the sentence completes its subject; the product description ("an integration of existing cryptographic primitives — SimpleX's identifier-less queue protocol, Briar's peer-to-peer-over-Tor design…") does not arrive until ~150 words in.
- **Impact:** A first-time reader cannot answer "what is this project?" from the opening sentence. The threat-actor name-drop reads as positioning ("we know who Pegasus is") rather than orientation ("here is what the tool does"). Programme officers and partner technologists triaging briefs decide engagement on the first 30 seconds; this opening fails that test.
- **Recommendation:** Lead with a one-sentence plain-English description of what Cairn is and does ("Cairn is a secure-messaging system for people whose adversaries are willing to spend tens of thousands of dollars to read their messages"). Move the spyware/forensics catalog to the second sentence or to §2.1 where the catalog already lives in fuller form.

### F2: Density and length make §1 unskimmable

- **Evidence:** Lines 22, 24, 26, 28, 30, 32 — seven paragraphs, six of which are single blocks of 250–400+ words with no bullets, no sub-headings within paragraphs, and no whitespace breaks. The "Architectural commitments" paragraph (line 26) is ~440 words and contains four numbered sub-commitments delivered inline rather than as a list. The "Operational and funding posture" paragraph (line 30) is ~370 words and crams Phase A/B/C/D dollar ranges into a single run-on sentence.
- **Impact:** §1's stated purpose ("a single-section orientation that lets a busy reader decide whether to engage") is undercut by formatting that resists the busy-reader use case. A reader scanning for "what does v1 deliver" or "what is being funded" cannot find anchor points; the eye slides off the page. Likely outcome: the brief is set aside in favor of one that can be scanned.
- **Recommendation:** Break each paragraph into a 2–3-line lead followed by bullets or short sub-paragraphs. The four numbered architectural commitments in line 26 should be a bulleted list. Phase A/B/C/D figures in line 30 should be a four-row table or list. Target: any §1 paragraph readable in 15 seconds.

### F3: §1 reads as the project critiquing itself, not introducing itself

- **Evidence:** Multiple instances:
  - Line 20: "_Purpose: a single-section orientation that lets a busy reader decide whether to engage with the rest of the brief. The summary mirrors the calibration of §§2–10 and does not promise capabilities the deeper sections qualify._"
  - Line 30 paragraph header: "**Operational and funding posture (honest about what is committed vs conditional).**"
  - Line 32 entire paragraph: "What this brief is and is not… It does not promise… It does not promise… is not delivered in this draft and is acknowledged as a §9.1-to-§10 gap…"
  - Line 32: "The brief's audience-honesty extends to its own non-promises…"
- **Impact:** A first-time reader has not yet formed a baseline expectation that Cairn is overpromising — so the constant self-disclaimer reads as defensive, as if responding to an unseen critic. The repeated invocation of "honesty" prompts the reader to wonder what they would otherwise have been misled about. Foundation officers reading "is not delivered in this draft" before having any picture of what _is_ delivered will assume the gap is more damaging than it is.
- **Recommendation:** §1 should state what the project is and what it does. Move "what this brief is and is not" framing to the "About this document" preamble (already exists, line 10–14) and trim it heavily. Strike the meta-sentence about audience-honesty extending to its own non-promises (line 32 final sentence) — it is recursive and unhelpful to a cold reader.

### F4: First-time reader cannot answer "what would I do next?"

- **Evidence:** Line 22 names the brief's purpose ("the basis for external review, partnership conversations, and funding discussions") but §1 never tells the three named audiences what next step is being requested. A programme officer cannot tell whether they are being asked to fund Phase B ($20–60K), to introduce the project to OTF, to wait for v1, or to do nothing yet. A partner technologist cannot tell whether the ask is "facilitate a pilot in your community" or "review the architecture." A security researcher cannot tell whether the ask is "audit the cryptographic envelope" or "read and comment."
- **Impact:** The brief's stated purpose includes generating action. §1 does not convert that purpose into a per-audience next step. The closing "Where to read next" paragraph (line 34) routes the reader through the brief, not to a contact or an action.
- **Recommendation:** Add a closing sub-section (3–5 lines) titled something like "What the brief asks of each reader," with one line per named audience: (a) funders — what phase/range is the immediate ask and what would unlock it; (b) partner organizations — what pilot facilitation involvement is being scoped; (c) security researchers — what review is sought before Phase B. Even acknowledging "no concrete ask at this draft, contact for engagement" would be more actionable than the current silence.

## Significant findings

### F5: Audience description lands as a list of vulnerable populations, not as "people like me/my grantees"

- **Evidence:** Line 24: "journalists, lawyers, organizers, dual-use technology workers, civil-society researchers, dissidents, undocumented organizers, abuse survivors with severed networks, queer and religious minorities in criminalizing jurisdictions, and others whose adversaries treat their communications as worth substantial resources to compromise."
- **Impact:** The list is comprehensive but abstract — a programme officer at, say, a press-freedom funder reads "journalists" but does not see "the kind of investigative reporter your portfolio supports in [country]." The list reads as taxonomic ("we are aware of these categories") rather than illustrative ("here is the journalist this would have helped last year"). For a first-impression read, one concrete scenario beats nine taxonomic labels.
- **Recommendation:** Either compress the list to three or four labels with a parenthetical concrete example, or add a single illustrative scenario after the list (one sentence: "Concretely: an investigative reporter in [jurisdiction] working a corruption story whose newsroom has already been targeted with Pegasus is the kind of user v1 serves.").

### F6: Vocabulary load assumes glossary access the first-time reader has not opened

- **Evidence:** Within line 26 alone, the reader encounters without definition or gloss: "three-tier identity model," "cryptographic trust graph," "cascade-laundering attack closure," "commitment-only anchoring in Sigsum," "Shamir-among-peers," "pre-shared peer challenges," "delay-and-confirm window," "5-of-N reviewer attestation threshold," "witness cosignatures," "OIDC provider integrity." Line 22 adds "capability-token construction," "trust-graph operation envelope," "cascade quarantine semantics," "recovery-flow memory hygiene." Line 26 also cites prior art ("Sigstore," "CONIKS," "Keybase") without context for a reader outside the transparency-log community.
- **Impact:** A security researcher in the cryptographic-protocol community will recognize most of these; a programme officer, a partner-organization operations lead, and a journalist-protection NGO program manager will not. A first-impression reader sees a wall of jargon and infers "this is for someone else to evaluate." The brief's stated tri-audience (technical, operational, funders) is undercut at §1 by single-audience vocabulary.
- **Recommendation:** §1 is the wrong place for the terminology. Either (a) replace each term with a plain-English gloss in §1 and let the precise term appear at §§4–5, or (b) add a one-line parenthetical gloss the first time each term appears. The numbered commitments at line 26 can be re-stated in user-facing language ("compromise of one device does not expose all communications," "lost devices can be recovered without the developer's involvement," "the release process does not depend on the developer's signing key alone") with the technical term retained as a cross-reference.

### F7: Phase A/B/C/D dollar ranges arrive without scaffolding

- **Evidence:** Line 30: "Phase A volunteer-baseline (the developer absorbs ~$1.5–3.5K of hardware, infrastructure, and time); Phase B first-dollar threshold for pilot readiness (~$20–60K…); Phase C pre-broader-release funding (~$105–405K…); Phase D steady-state operations (~$90–250K/year…)."
- **Impact:** A funder is the only one who reads §1 looking for these numbers, and the way they are presented — embedded in a 370-word paragraph, no comparison to peer-project costs, no statement of which phase the project is currently asking for — makes them hard to use. The reader's likely take: "low five figures to mid-six figures, hedged across four buckets" is not a fundable number. The maintainer-compensation aside ("the Phase D sustainability cliff the brief surfaces explicitly rather than assumes away") rings as another self-critique rather than a plan.
- **Recommendation:** Put the phase figures in a 4-row table. State which phase is the current ask. Cut the "Phase D sustainability cliff" meta-commentary from §1; let §10 own it.

### F8: "v1 pilot is closed, low hundreds globally" lands without the broader-reach framing it needs

- **Evidence:** Line 24: "The v1 pilot serves a specific 10–15 user cohort in one or two local groups already known to the developer; the estimated population for the full four-precondition v1 intersection is on the order of low hundreds globally (Q17)." This is followed three paragraphs later (line 28) by "Subsequent releases (v1.5 architecture completeness; v1.6 deferred UX; v2 USB and iOS; v3 mesh radio; v4+ established-organization tier)…"
- **Impact:** A first-impression reader hits "low hundreds globally" before the v1.5+/v2+ expansion framing arrives, and the gap is enough that the funder may have already mentally filed the project as "too small to scale." When the roadmap arrives, it is presented in phase-gate language ("not calendar windows") that further dampens the broader-reach signal. Net first impression: a project for hundreds of people, conditionally.
- **Recommendation:** Co-locate the v1 numbers with the broader-reach framing: "v1 pilot is 10–15 users in a closed cohort; the v1 architecture serves a four-precondition population on the order of low hundreds globally; v1.5/v2 expansion paths lift the addressable audience to [magnitude]." Even acknowledging "v2 USB and iOS expansion target a population orders of magnitude larger, gated on [conditions]" gives the reader a reason to keep reading.

### F9: "Where to read next" is structural, not motivational

- **Evidence:** Line 34: nine sentences, each routing the reader to a numbered section ("Section 2 establishes…; Section 3 specifies…; Sections 4 and 5 cover…"). The final two sentences are about decision documents and what a §1-only skimmer should do.
- **Impact:** A first-time reader who has just absorbed seven dense paragraphs needs a reason to read more, not a map. The current paragraph gives them a map without surfacing which section answers the question they likely have. A programme officer most likely wants "where do I look for the ask"; a partner technologist wants "where do I look for the pilot model"; a security researcher wants "where is the audit scope."
- **Recommendation:** Replace "Section N covers X" enumeration with question-keyed routing: "If you are evaluating fit for funding: §10 (funding model) and §2.2 (audience). If you are considering pilot facilitation: §6 (v1 scope), §8.6 (partner arrangements), D0013 (consent and exit). If you are evaluating the cryptographic design: §§4–5, §8.5 (audit), D0006 (envelope)."

## Minor findings

### F10: Bold paragraph leads are doing too much work

- **Evidence:** Lines 22, 24, 26, 28, 30, 32: each paragraph opens with a bold lead-phrase ("**What this is.**" "**The threat tier and audience.**" "**Architectural commitments at the orientation level.**" "**v1 scope and roadmap (phase-gate register, not calendar windows).**" "**Operational and funding posture (honest about what is committed vs conditional).**" "**What this brief is and is not.**").
- **Impact:** Some leads are crisp ("What this is."); others editorialize within the bold itself ("honest about what is committed vs conditional"; "phase-gate register, not calendar windows"). The latter pull the reader into a meta-frame before the paragraph content lands. They also add to the self-critical tone noted in F3.
- **Recommendation:** Standardize bold leads to short noun phrases: "What this is.", "Audience.", "Architecture.", "v1 scope and roadmap.", "Operations and funding.", "Scope of this brief."

### F11: D-number and Q-number citations interrupt reading flow

- **Evidence:** Line 22 alone contains seven cross-references: D0001, D0004, D0006, D0003. Line 24 contains D0014, Q19, Q17. Line 26 contains D0006, D0003 (and D0005, D0006 inside the numbered list). Line 28 contains D0011, D0013, D0010, D0008. Line 30 contains D0009, D0010, D0012. Line 32 contains a Q18 reference. Total in §1: 25+ inline citations.
- **Impact:** Each citation is a small attentional break. A first-time reader who has not yet learned the D-number convention reads "[D0001]" as an unexplained sigil. Cumulatively, the citations make §1 feel like a wiki cross-reference page rather than an executive summary.
- **Recommendation:** §1 should be readable without any D/Q citations. Move citations to §§2–10 where they live in context. If a §1 reader needs to know that the project name is provisional, say so in prose ("Cairn is a working name") without the bracket-citation.

### F12: "Working name" in the first 10 words

- **Evidence:** Line 22: "Cairn (working name per [D0001](decisions/D0001-project-name.md))…"
- **Impact:** The reader's first impression of the product name is "this is provisional." This is honest but premature — it costs the brand recognition the name was chosen to create, before the reader has any reason to care that it might change. Cf. F3 — this is another instance of self-critique displacing introduction.
- **Recommendation:** Drop "(working name per D0001)" from §1 entirely. Let the name stand. Note the working-name status in the "About this document" preamble or in §2.

### F13: "9–12 person-months for v1" lands as engineering bookkeeping, not orientation

- **Evidence:** Line 28: "The engineering scope estimate is approximately 9–12 person-months for v1; calendar-time-to-v1 depends on whether the developer is operating at 'as available' volunteer cadence (per [D0008](decisions/D0008-volunteer-baseline-cadence.md)) or whether grant funding has freed full-time engineering capacity."
- **Impact:** Useful detail for §10, not for §1. The first-time reader has no comparison class for "9–12 person-months" and the conditional cadence framing reinforces the funding-dependent narrative without adding clarity.
- **Recommendation:** Cut from §1. Reference effort in §10 where the cadence framing already lives.

## Patterns

1. **Self-critique displaces self-introduction.** F3, F10, F11, F12: §1 spends a disproportionate share of its words flagging what it does not promise, citing decision documents that disclose its own provisional status, and editorializing about its own honesty. A first-time reader is not yet skeptical enough for any of this to land as integrity — it lands as defensiveness or as a project mid-revision.

2. **Density chosen over scannability.** F2, F6, F11: §1 is written as if to be read end-to-end by a reader who will compare wording against §§2–10. The stated audience (busy programme officer, partner technologist, security researcher in triage) is not a re-reader; it is a scanner. Every formatting choice — long paragraphs, no bullets, inline citations, no whitespace — opposes the use case.

3. **Threat-tier vocabulary leads, user benefit lags.** F1, F5, F6: the opening lines name adversaries (spyware vendors, forensic vendors, intelligence services) before naming users; the audience paragraph lists population categories before describing what a user can do with Cairn that they cannot do today. The reader is positioned as analyst before being positioned as someone who might bring the project to a user.

4. **Ask is implicit.** F4, F7, F9: the brief's purpose includes generating action from named audiences but §1 never asks any of them for anything specific. A foundation officer reading §1 alone cannot tell whether to engage; a partner technologist cannot tell what role they would play; a researcher cannot tell what review is sought. The closing paragraph routes the reader through the document rather than to a next step.

5. **Granularity is uniform across audiences.** F6, F7, F13: §1 carries cryptographic-engineering vocabulary, foundation-incorporation timing, person-month estimates, and dollar ranges in the same paragraphs. A multi-audience executive summary needs either one-pass-for-all-audiences plain language with depth in §§2–10, or audience-keyed sub-sections. §1 currently delivers depth uniformly and loses each audience at a different point.

---

## 150-word summary

§1 fails the first-impression test on density, on ordering, and on actionability. The opening sentence catalogs six spyware vendors before saying what Cairn does; six 250–400-word paragraphs with no bullets resist the busy-reader scan §1 claims to serve; 25+ inline D/Q citations interrupt reading flow; recurring meta-commentary ("honest about what is committed vs conditional," "What this brief is and is not," "audience-honesty extends to its own non-promises") reads as defensive self-critique to a cold reader who has not yet formed a baseline expectation to defend against. Cryptographic vocabulary lands without glosses for the non-technical audiences §1 names. The "low hundreds globally" v1 number arrives before any broader-reach framing. And critically: no named audience (funder, partner, researcher) can answer "what would I do next?" from §1 alone. Lead with what Cairn is, scan-format the paragraphs, cut self-critique to §§9–10, and add a per-audience next-step closer.
