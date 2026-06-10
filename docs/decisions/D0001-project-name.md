# D0001 — Project working name: Cairn

**Status:** Accepted
**Date:** 2026-05-27

## Context

The project needed a working name before further documentation, partner outreach, decision-file accumulation, or any code-naming work could proceed without placeholder churn. The placeholder `[Project Name TBD]` was propagating through working documents and was the highest-leverage small unblocking decision available.

Naming constraints captured in the prior conversation (handoff.md:214):

- Avoid telegraphing the use case (no Secure-, Crypt-, Shield-, Vault-, etc.).
- Work across languages — pronounceable, no English-only idioms or puns.
- Available domain and package namespaces.
- No collision with adjacent projects in messaging, security, identity, or developer tooling.

## Decision

Adopt **Cairn** as the project working name.

A cairn is a hand-built stack of stones marking a path, summit, or memorial — used across Scotland, Scandinavia, the Andes, and the Himalayas. Pronounced /kɛərn/ — one syllable, clean across most languages. Old Gaelic origin (_càrn_), recognizable across English-language readers without being saturated as a generic term.

The metaphorical fit is direct. The trust graph operates exactly as a chain of cairns operates: each peer who has traveled the path leaves a marker for the next traveler; the markers compose into a route that no single peer could establish alone; the marker is visible and verifiable by anyone who passes; and a missing or moved marker is itself a signal worth noticing. The architecture and the name reinforce each other without either requiring explanation in terms of the other.

## Alternatives considered

**Coppice** (runner-up). A small woodland actively managed by cutting trees to stumps; the stumps regrow into multiple new stems. Strong resilience-and-recovery metaphor mapping to device-loss recovery and post-revocation regrowth of trust paths. Lowest collision risk in the candidate set. Rejected as second-choice because the metaphor described a property of the product (regrowth after loss) without naming its central concept. Cairn names what the product _is_; Coppice names what the product _survives_.

**Tessera** (strongest conceptual fit; ruled out). Small tile in a Roman mosaic; in classical Rome, also a token of identity or passage carried by soldiers and officials authorizing specific actions. Architecturally near-perfect: the COSE capability-token model in Section 5.1 of the design brief is structurally analogous to Roman tesserae — small signed tokens authorizing specific actions. Rejected because of two real collisions: Tessera by Adyen (payments hardware) is a moderate concern, but the disqualifying collision is Tessera, the NFT fractionalization protocol — a high-profile crypto project in a closely-adjacent identity-token space. The collision would create persistent search-result confusion ("decentralized identity tokens" describes both projects until a reader engages closely), and the search-results cost compounds across funder, partner, and pilot conversations for the entire life of the product.

**Skein**. Distributed-network metaphor (a loosely-wound continuous thread, or a flock of geese in coordinated flight). Ruled out by collision with the Skein hash function (SHA-3 finalist, Schneier et al., 2008) — too close to cryptography for a security messaging product.

**Tarn**. Small mountain lake; held-in-place, isolated, fed by sources outside the dominant valley. Ruled out by collision with the Tarn department of France (~390K population, frequent in francophone search and conversation contexts).

**Halyard**. Maritime working line that hoists a sail; operational rather than declarative. Ruled out by collision with Halyard Health, a meaningful medical-products company.

**Quoin**. Masonry cornerstone; foundation/load-bearing reference. Ruled out primarily by the homophone with "coin" — for a product that has no financial function and operates in jurisdictions where security-software-as-currency-fraud confusion is non-zero, the voice-context confusion is uncomfortable.

**Withy / Withe**. Flexible willow stem used for binding. Strong metaphor for trust-as-binding, very low collision. Ruled out by the "th" sound being a cross-language pronunciation challenge — speakers of many target languages render it as /v/, /d/, /z/, or /t/, which produces inconsistent spoken-form recognition.

**Mooring**. Maritime anchorage; anchored-identity metaphor. Ruled out as too generic to compete with Cairn's more specific fit and Coppice's lower collision risk.

**Lichen**. Symbiotic organism, extreme resilience under hostile conditions. Strong metaphorical fit. Ruled out by pronunciation drift across languages (English /ˈlaɪ.kən/ vs. German /ˈliç.ən/ and several intermediate forms).

Full candidate analysis: [docs/name-candidates.md](../name-candidates.md).

## Consequences

**Renames performed.** [Project Name TBD] replaced in docs/design-brief.md title. Historical artifact in docs/handoff.md preserves the placeholder to maintain provenance of the conversation that established the constraint set.

**Open question Q2 closed.** docs/open-questions.md updated to reference this decision. The remaining items moved out of Q2 into a follow-up list: domain availability check (.org, .com), package-namespace check (npm, PyPI, Maven, F-Droid), GitHub organization name availability, USPTO and EUIPO trademark search before any public launch.

**Acknowledged collisions** (none in messaging, security, or identity space):

- Cairn Markdown editor (small developer-tooling project — closest adjacency; significantly smaller scale than this project would reach if it ships)
- Cairn Energy (oil and gas, UK)
- Cairn Therapeutics (biotech)
- Cairn Toolkit (R package for cognitive-modeling research)
- Cairn Indian (subsidiary of Vedanta Resources)

The dev-tooling collision is the only one in a domain that overlaps with this project's likely future audience. Mitigation: if the project ships and the Cairn Markdown editor remains active, the disambiguation will resolve naturally through scale differential. If both projects scale unexpectedly, the working name is reversible at low cost while documentation-only.

**Reversibility.** The decision is recorded as a working name. Domain, package, and trademark verification have not yet been performed. If a verification finds a hard blocker, this decision is reversible: the documentation rename is a single search-and-replace, the decisions/ folder retains the rationale, and the alternative candidates remain documented in name-candidates.md.

**Not addressed by this decision.** Pronunciation guidance for the design brief (whether to gloss the pronunciation parenthetically on first use), branding direction (typography, color palette), or any visual identity work. These are downstream and not gated by the working-name decision.

## References

- [docs/name-candidates.md](../name-candidates.md) — full candidate set with metaphorical fit, phonetics, and collision analysis
- [docs/open-questions.md](../open-questions.md) — Q2 (now resolved) and follow-up verification items
- handoff.md:214 — original naming constraints from prior conversation
