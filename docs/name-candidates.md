# Project Name Candidates

Working brainstorm against the constraints captured in handoff.md:173 — avoid telegraphing use case, work across languages, available domain/package, no collision with adjacent projects. Each candidate notes etymology, metaphorical fit, phonetic properties, and known-collision flags. Domain availability and trademark searches are deferred to a follow-up pass against a shortlisted top three.

## Constraint logic

**Avoid use-case telegraphs.** Names like Secure, Crypt, Shield, Vault, Haven, Cipher, Mask, Stealth, Anon mark a user as security-conscious before they speak. This product's threat model (Section 3.3, Tool-use surface) acknowledges this is partly unavoidable but the name should not contribute to it. Concrete-object names — particularly drawn from nature, architecture, maritime, and textile vocabularies — read as neutral.

**Cross-language workability.** The candidate set leans toward names with Latin/Romance roots, Old English/Germanic roots, or Old Norse roots — vocabularies that have neutral cognates or pronounceable equivalents in most European, and many non-European, languages. Avoided: puns, idiomatic English, brand-style portmanteaus.

**Collision-density tolerance.** Some collision is acceptable if the collision is in an unrelated category (e.g., a small geology project named Cairn does not preclude using Cairn for messaging). Hard exclusions are anything in messaging, security, identity, or developer tooling.

**Length and acoustics.** Short (4-7 chars), one or two syllables, no consonant clusters that are hard to pronounce outside English.

## Candidates

### 1. Coppice

**Meaning.** A small woodland actively managed by cutting trees down to stumps; the stumps regrow into multiple new stems. Coppicing has been continuously practiced in Europe for over a millennium.
**Metaphorical fit.** Strong. Resilience and regeneration after loss (recovery from device seizure; trust graph regrowth after a peer compromise). The botanical reference is quiet, not advocacy-coded.
**Phonetics.** /ˈkɒp.ɪs/ — two syllables, soft consonants, pronounceable across most languages.
**Known collisions.** Coppice (UK lender), Coppice (small game studios). No tech-stack collision known.
**Notes.** Distinctive without being affected. Slightly old-fashioned register, which suits a product that emphasizes operational discipline over novelty.

### 2. Cairn

**Meaning.** A pile of stones built by hand as a waypoint on a path, a summit marker, or a memorial. Used across Scotland, Scandinavia, the Andes, and the Himalayas.
**Metaphorical fit.** Strong. Peer attestations as path markers; a way the people who came before tell the next traveler "this is the way." Maps cleanly onto the trust-graph mental model.
**Phonetics.** /kɛərn/ — one syllable, easy across languages.
**Known collisions.** Cairn (Markdown editor by C. Hagberg — small project but in tooling space), Cairn Energy (oil company), Cairn Toolkit (R package). Moderate collision density; the Markdown editor is the closest concern but is small.
**Notes.** Recognizable but not so common as to feel generic. The Markdown-editor collision would warrant a closer look before commitment.

### 3. Skein

**Meaning.** A length of yarn loosely wound for storage; also a flock of geese in flight. Old Norse origin via Middle English.
**Metaphorical fit.** Strong. A skein is composed of one continuous thread looped many times — a distributed-but-connected structure, mirroring the trust graph. The flock-in-flight sense adds coordinated-but-not-rigidly-controlled connotations.
**Phonetics.** /skeɪn/ — one syllable, no consonant clusters that fail in major languages.
**Known collisions.** Skein hash function (Bruce Schneier et al., 2008) — a SHA-3 finalist, no longer in active development but still cited. This is the major concern: a cryptographic hash function is uncomfortably close to messaging. Skein Loyalty (small marketing tool).
**Notes.** Strong name but the hash-function collision is a meaningful problem. Possibly disqualifying.

### 4. Tessera

**Meaning.** A small tile in a Roman mosaic; in classical Rome, also a token of identity or passage carried by soldiers and officials. Latin root, plural _tesserae_.
**Metaphorical fit.** Strong and architecture-specific. The capability-token identity model (Section 5.1) is structurally analogous to Roman tesserae — small, signed tokens authorizing specific actions. The mosaic sense — many small tiles compose a larger pattern — applies to the trust graph itself.
**Phonetics.** /ˈtɛs.ər.ə/ — three syllables, Romance-language-friendly, recognizable in Spanish, Italian, French as cognates.
**Known collisions.** Tessera by Adyen (a payments hardware platform), Tessera (NFT fractionalization protocol — high profile in crypto). The crypto-adjacent project is a concern; even though that product domain is unrelated, the overlap might confuse search results.
**Notes.** Best conceptual fit of any candidate. Collision risk is moderate to high.

### 5. Quoin

**Meaning.** An exterior cornerstone in masonry architecture; structurally critical, dimensionally distinct from the surrounding stones. From Old French _coing_, ultimately from Latin _cuneus_ (wedge).
**Metaphorical fit.** Moderate. Foundation/load-bearing reference. The cornerstone metaphor is generic but the unusual word choice gives it specificity.
**Phonetics.** /kɔɪn/ — pronounced "coin." This homophony is the main concern: in voice contexts ("can you join the Quoin call") this could confuse with currency or onboarding language.
**Known collisions.** Quoin Inc. (small consultancy), Quoin (typography term). Low density in tech.
**Notes.** Distinctive and low-collision but the "coin" pronunciation is awkward for a non-financial product.

### 6. Withy

**Meaning.** A flexible willow stem, historically used for binding bundles, weaving baskets, and lashing structures together. Also _withe_ in some dialects.
**Metaphorical fit.** Strong. Binding-together-of-trust. Pliable but tensile, which mirrors the trust graph's combination of flexibility (operations are extensible) and integrity (attestations cryptographically bind).
**Phonetics.** /ˈwɪð.i/ or /ˈwɪθ.i/ — two syllables, voiced or unvoiced "th" depending on dialect. The "th" is a pronunciation challenge for speakers of many languages.
**Known collisions.** Very low. A few small craft businesses. No tech collision known.
**Notes.** Most distinctive of the candidate set, but the "th" sound is a real concern for cross-language workability. Consider this if pronunciation isn't a blocker for the target audiences.

### 7. Mooring

**Meaning.** A permanent anchorage; the act of securing a vessel to a fixed point. Maritime.
**Metaphorical fit.** Moderate. Anchored-identity (the master identity is the user's mooring; operational identity moves but stays tied). The maritime register is calming without being whimsical.
**Phonetics.** /ˈmʊər.ɪŋ/ — two syllables, clear consonants.
**Known collisions.** Common word, several small businesses. No major tech collision.
**Notes.** Solid but slightly generic. The maritime metaphor is intuitive but the name itself lacks specificity.

### 8. Lichen

**Meaning.** A symbiotic life form composed of fungus and algae living as a single organism; among the most resilient organisms on earth, surviving conditions hostile to nearly everything else.
**Metaphorical fit.** Strong. Symbiosis (SimpleX + Briar + Tor + trust graph as a composite organism). Resilience under hostile conditions is on the nose for the threat model.
**Phonetics.** /ˈlaɪ.kən/ in English; pronounced more like /ˈliç.ən/ in German and several other languages. Pronunciation drift across languages is a moderate concern.
**Known collisions.** Lichen (small audio/music software), Lichen Plant Project. Low tech density.
**Notes.** Strong conceptual fit; pronunciation variance is the main concern.

### 9. Tarn

**Meaning.** A small mountain lake, typically formed by glacial action and held in a high cirque. Northern English / Old Norse origin.
**Metaphorical fit.** Modest. Held-in-place, geographically isolated, fed by sources not from the dominant valley below. Indirect privacy metaphor.
**Phonetics.** /tɑːn/ — one syllable, clean, works in most languages.
**Known collisions.** Tarn (department of France — major name density there), Tarn (a few small projects).
**Notes.** Very short and easy. The French department name is a meaningful collision for any francophone outreach. Probably disqualifying for that reason.

### 10. Halyard

**Meaning.** The line used to hoist or lower a sail. Specific, working-language maritime term.
**Metaphorical fit.** Moderate. Operational, working-rope, mundane-but-critical. Doesn't telegraph at all.
**Phonetics.** /ˈhæl.jərd/ — two syllables, recognizable.
**Known collisions.** Halyard Health (medical devices — major company), Halyard (a few small projects). The Halyard Health collision is significant in name-recognition terms but is in an unrelated domain.
**Notes.** Operationally evocative but the medical-products collision is large.

## Quick assessment

**Strongest conceptual fits:** Coppice, Cairn, Tessera, Withy, Lichen.

**Lowest collision risk:** Coppice, Withy, Quoin.

**Best phonetics across languages:** Cairn, Skein, Tarn, Mooring.

**Likely disqualified:** Skein (hash function collision), Tarn (French department), Halyard (Halyard Health). Possibly Quoin (pronunciation).

**Most balanced:** Coppice and Cairn meet the most criteria with the fewest concerns. Tessera has the strongest conceptual fit but the highest collision risk; if that risk is acceptable, it's the most architecturally evocative name in the set.

## Outcome

**Selected (2026-05-27): Cairn.** Decision recorded in [decisions/D0001-project-name.md](decisions/D0001-project-name.md).

Coppice was the runner-up. Tessera was the strongest architectural fit but ruled out for collision with the Tessera NFT fractionalization protocol in a closely-adjacent identity-token space.

This file is retained as the rationale audit trail for the choice — useful if the working name needs to be revisited following collision verification or other downstream signals.
