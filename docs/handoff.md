# Project Handoff Document

> [!IMPORTANT]
> **Historical snapshot — superseded.** This document captures the _initial_
> design conversation that started Cairn (2026-05-27), preserved for provenance
> and narrative context. It is **not** a current description of the project, and
> several specific statements below are now outdated. Do not rely on it for
> current facts — use the sources of truth instead.
>
> **Current sources of truth:**
>
> - [`../README.md`](../README.md) — what Cairn is now, honestly scoped
> - [`implementation-status.md`](implementation-status.md) — what is actually built vs. promised
> - [`design-brief.md`](design-brief.md) — the substantive design brief
> - [`decisions/`](decisions/) — every architectural decision, D0001–D0042
> - [`open-questions.md`](open-questions.md) — the live open-questions register
>
> **Specific facts below that have since changed:**
>
> - **Name:** "[Project Name TBD]" → **Cairn** ([D0001](decisions/D0001-project-name.md))
> - **License:** "Apache 2.0" → **AGPL-3.0-only** ([D0019](decisions/D0019-license.md))
> - **Status:** "pre-implementation" → **active v1 implementation**: a 15-crate Rust core plus a Kotlin/Compose Android app, with messaging validated end-to-end on two physical GrapheneOS Pixels over bundled Tor
> - **Briar:** listed as v1 scope → moved to **v1.5** ([D0004](decisions/D0004-v1-scope-cuts.md))
> - **Implementation language:** Kotlin-native (the prior preference) → **Rust** core + Kotlin/Compose shell ([D0003](decisions/D0003-implementation-language.md))
> - **Most "Open Questions / Still to Decide" below are resolved** — see [`open-questions.md`](open-questions.md) and [`decisions/`](decisions/); e.g. the duress-profile question and the project name were both resolved 2026-05-27
>
> The conversation journey, original rationale, and reference materials below
> remain useful as historical context.

**Purpose:** Capture the full context of design decisions, discussions, and open questions from the initial design conversation, for transfer to a Claude Code project where work can continue with better tooling (sub-agents for adversarial review, sustained project context, proper file management).

**Status:** Historical snapshot — superseded 2026-05-27 (see notice above)
**Source conversation:** Initial design discussion, Anthropic chat interface
**Companion file:** `design-brief.md` (the in-progress design brief, with Section 3 drafted)

---

## Quick Start

**What this project is:** A secure communications product for users facing serious adversarial threats — state actors with both legal and extralegal capability, criminal organizations with SIGINT, mercenary spyware operators, border forensic operations. Initial framing was "defense R&D operating in a hostile foreign country" but the design has evolved to serve a broader audience of users whose work makes them targets of disproportionate surveillance capability.

**v1 in one sentence:** An Android app for GrapheneOS Pixel devices, integrating SimpleX (everyday messaging) and Briar (highest-sensitivity peer-to-peer) over Tor, with capability-token identity, cryptographic trust graph for verified peer attestations, and social recovery via Shamir Secret Sharing.

**Roadmap in one sentence:** v1 phones-only → v2 adds USB bootable form factor and iOS → v3 adds mesh radio integration (Meshtastic/MeshCore) for internet-shutdown scenarios → v4+ adds established-org enterprise features.

**How to use this document:** Read the Conversation Journey section for narrative context, then jump to whichever section is most relevant to what you're picking up. The companion `design-brief.md` is the active working document; this file is the context that informed it.

---

## Conversation Journey

The discussion proceeded roughly in this order:

1. **Initial framing**: secure device communication for defense R&D contractors operating in hostile foreign jurisdictions. State and lower-level intrusion both in scope. Legal action, device seizure, corrupt courts all as risks.

2. **Threat model expansion**: target audience generalized from "defense R&D" to anyone facing similar adversarial capability — journalists, NGOs, activists, dual-use tech workers, defense subcontractors. Threats include nation-state SIGINT, mercenary spyware, criminal organizations with intercept gear, HUMINT operations.

3. **Architectural exploration**: started with friendly-jurisdiction infrastructure model (M-of-N trustees in Switzerland/Iceland), then pivoted when user pointed out that "friendly jurisdiction" can't be assumed for many target users (Myanmar resistance, Gaza activists, Iranian organizers). This led to trustless protocols and self-sovereign identity as the architectural baseline.

4. **Protocol selection**: evaluated Matrix (rejected as primary due to server burden and metadata exposure), Signal (rejected due to phone number requirement and centralization), Session (rejected due to Session Network dependency and crypto fork concerns), Wickr (rejected as enterprise-focused and AWS-owned). Settled on SimpleX + Briar over Tor as the primary stack, with Meshtastic/MeshCore as side-channel for v3.

5. **Cell architecture**: discussed cellular compartmentation with cutout/liaison roles for cross-cell collaboration, based on tradecraft patterns. Each cell has its own infrastructure where possible; cross-cell coordination happens through designated liaisons holding capability-scoped attestations.

6. **Device strategy evolution**: started with "phone + USB + laptop" multi-device model, narrowed to "phone + USB tied to same identity at provision time," then further narrowed to phones-only for v1, then GrapheneOS Pixels only as the v1 deployment target.

7. **Solo developer reality check**: acknowledged the full vision is a multi-year team-scale project. Narrowed to a phones-only Path A scope that's achievable in 9-12 months solo, with later versions adding USB, mesh, iOS, etc.

8. **Pilot deployment plan**: developer purchases GrapheneOS Pixels, pre-installs and pre-provisions devices for 10-15 users in 1-2 local groups the developer already knows. Solves the GrapheneOS-access problem for the pilot. Validates the product with real users at known stakes.

9. **Forward compatibility design**: identified specific v1 design choices (protocol versioning, capability token scope flexibility, multi-device protocol awareness, generic device-pairing flow, schema versioning) that protect future expansion to v2+ without forcing rewrites.

10. **Design brief outline**: created scaffolded outline of the 10-section design brief with appendices. Started drafting Section 3 (Threat Model) using the doc-coauthoring workflow (clarifying questions → brainstorming → curation → drafting → refinement).

11. **Adversarial review**: ran a simulated multi-perspective adversarial review of the Section 3 draft, identified ~12 issues to address (move vendor names to footnotes, add missing attack surfaces, soften editorializing, source capability claims, etc.).

12. **Environment switch**: recognized that Claude Code is the better environment for sustained engineering work and real sub-agent-based review, prompting this handoff document.

---

## Key Architectural Decisions Made

Each decision below was discussed in depth with alternatives considered. The rationale is summarized; the design brief Appendix A is intended to contain the full reasoning for each.

### Protocol stack

- **Primary messaging:** SimpleX (no persistent identifiers, queue-based servers that know minimum, self-hostable or use defaults)
- **Highest-sensitivity channel:** Briar (pure peer-to-peer over Tor, no servers at all, both-parties-online requirement accepted for metadata resistance)
- **Transport:** Tor with pluggable obfuscation transports as needed for jurisdiction-specific DPI
- **Side-channel (v3+):** Meshtastic and MeshCore, protocol-agnostic integration, deferred from v1

### Identity model

- **Three-tier capability tokens** (master / operational / device)
- **Master identity:** Ed25519 keypair, generated at provisioning, immediately Shamir-split among recovery peers, never stored after split
- **Operational identity:** Ed25519 keypair signed by master at provisioning, held in phone's Titan M2 hardware element, used for signing capability tokens and trust graph operations
- **Device capability tokens:** COSE-formatted signed delegations granting scoped permissions to specific device keys
- **Rationale:** capability tokens provide independent revocation, scope flexibility, and natural alignment with the trust graph; preferred over HD keys (which couple all derived keys to one secret) and threshold signatures (which are too operationally heavy for daily use)

### Trust graph

- **Data model:** signed operations (attest / revoke / introduce / rotate) with issuer, subject, context, strength, timestamp, expiry, prior-hash, signature fields
- **Propagation:** via the messaging layer itself, as metadata accompanying user-to-user traffic
- **Replication model:** operation-based CRDT, eventual consistency, conflicts resolved by signed timestamps and prior-hash chains
- **Transparency log:** Sigsum (specifically chosen for minimal-trust witness model)
- **Revocation behavior:** soft cascade quarantine (flag, don't lock out)

### Recovery

- **Model:** Shamir Secret Sharing of the master identity, default 3-of-5
- **Peer designation:** at provisioning time, by the user, from their contact list
- **Failure mode:** graceful (fewer than threshold available = recovery fails closed, no information leakage)
- **Alternative path:** fresh identity with in-person re-introduction by existing contact, accepting loss of historical state

### Hardware token role (v1 phones-only)

- **Phone:** signing keys live in Titan M2 hardware element, unlocked by passphrase. No external token required for daily use.
- **USB (v2+):** external token (NitroKey/YubiKey) OR hardware-encrypted USB drive (Apricorn Aegis/Kingston IronKey)
- **Master operations:** optional external token for the rare master-key ceremonies

### Updates and release security

- **Signing:** Sigstore identity-based signing (no long-lived signing keys)
- **Builds:** reproducible builds required (anyone can independently verify binaries match source)
- **External review:** 2-3 reviewers per release publishing signed attestations
- **Distribution:** F-Droid/Accrescent, GitHub releases, Tor onion service, optional offline images
- **Rollback resistance:** signed monotonic version numbers
- **Why not TUF:** overkill for solo-developer project scale; Sigstore + reproducible builds + external attestations gets most of the benefit

### Platform

- **v1 target:** GrapheneOS on Pixel only (no other Android, no iOS)
- **Rationale:** hardware attestation via Titan M2, reduced testing surface, security baseline guaranteed, simpler distribution
- **Tradeoff acknowledged:** meaningfully smaller addressable user base than full grassroots target audience

### Cell architecture (for future versions / sophisticated users)

- **Cellular compartmentation** with designated liaisons as cutouts
- **Cross-cell collaboration** via dedicated project infrastructure, not direct cell-to-cell federation
- **Double-wrapped sensitive content** at the project level
- **Roster compartmentalization** to limit what a captured device reveals about other cells
- **Note:** v1 doesn't implement formal cell structures — these are organizational patterns users adopt, supported by the underlying trust graph capabilities

### Open source license and governance

- **License:** Apache 2.0 (permissive, maximizes downstream reuse by allied projects)
- **Governance:** starts as project, foundation incorporation when funding/scale justifies (estimated 18-24 months out)
- **Reference models:** Signal Foundation, Tor Project, Briar Project trajectories

---

## v1 Scope (MVP)

### In scope

- Android app for GrapheneOS Pixel only
- SimpleX integration as primary messaging
- Briar integration for highest-sensitivity channel
- Trust graph with attestation, revocation, social recovery
- Provisioning ceremony via in-person QR pairing
- Profile management (multi-profile support)
- Per-jurisdiction profile feed (basic, 2-3 profiles)
- Sigstore-based update distribution
- Encrypted at-rest storage tied to passphrase and hardware element
- Documentation for users and pilot administrators
- _Open question: duress profile support — was claimed in Section 3 draft but needs verification it's actually in v1 plan_

### Explicitly deferred

- USB-bootable variant → v2
- iOS support → v2
- Non-Pixel Android → never (product remains anchored to GrapheneOS-Pixel)
- Mesh radio integration (Meshtastic/MeshCore) → v3
- Established-org enterprise tier → v4+
- Voice/video calling → v1.x if time, v2 if not
- Localization beyond English → v1.x post-pilot
- Group/cell formal infrastructure → v3+

### Pilot plan

- 10-15 users in 1-2 local groups identified by developer
- Devices provided: GrapheneOS pre-installed on Pixels (likely Pixel 8a for cost, possibly Pixel 9 for newer hardware)
- App pre-installed but identity not yet provisioned (user does that with developer present)
- In-person provisioning ceremony for initial users
- 6-month pilot before broader release
- Feedback channel within product itself
- Budget estimate: $5-12K hardware + developer time

### Forward-compatibility design choices in v1

1. Protocol versioning fields in all signed messages from day one
2. Capability tokens with arbitrary scope strings (not hardcoded permissions)
3. Multi-device awareness in the protocol even though v1 ships only phones
4. Device-to-device pairing flow specified generically (same flow used for v2 USB, v3 mesh)
5. Trust graph operation types designed for extension (new types ignored gracefully by v1 clients)
6. Storage schemas with version fields and migration framework
7. Build system designed to produce multiple artifacts even when v1 produces only one

---

## Roadmap

- **v1** (9-12 months full-time solo): scope per above
- **v1.5** (6 months post-v1): iteration on pilot feedback, UX refinements, possible voice/video, expanded localization
- **v2** (12-18 months post-v1): USB-bootable variant, iOS app
- **v3** (18-24 months post-v1): mesh radio integration (Meshtastic + MeshCore protocol-agnostic), addresses internet-shutdown threat
- **v4+**: established-org features, optional Matrix federation for enterprise users, hardware partnerships, broader localization

---

## Open Questions / Still to Decide

### Project identity

- **Name:** placeholder "[Project Name TBD]" — not yet chosen. Considerations: avoid telegraphing use case, work across languages, check domain/package availability, avoid collision with adjacent projects.

### Funding

- **Strategy:** OTF grant likely primary candidate ($50-150K range), supplemented by foundation grants (Ford, Open Society, Mozilla, Knight, Omidyar), self-funded development through pilot phase
- **Sustainability:** post-v1 includes established-org paid tier as subsidy mechanism

### Pilot specifics

- Specific local groups not yet identified in document (developer has them in mind)
- Pilot start timing unclear
- Pilot evaluation criteria not yet defined

### NGO partnerships

- Targets identified: Tactical Tech, Front Line Defenders, Access Now, Citizen Lab, OTF
- Outreach not yet begun
- Roles partners would play not yet defined (review? facilitation? threat intel? localization?)

### Localization

- v1 launches English-only
- Post-pilot expansion to which languages first? Considerations: pilot user demographics, partner NGO geographic coverage, target deployment regions
- Recruitment of native-speaker security trainers as translators

### Audit

- External cryptographic audit before broad release (post-pilot)
- Budget: $20-50K estimated
- Audit firm not yet identified

### Specific technical decisions deferred to architecture spec

- Exact Android codebase architecture (Kotlin native is current preference)
- Specific CRDT library choice for trust graph
- Specific COSE library
- Specific Sigsum integration approach
- Push notification mechanism (no Google Play Services in GrapheneOS by default)

### Voice/video calls

- SimpleX supports them but adds complexity
- Defer to v1.x or v2 depending on time

---

## Adversarial Review Findings to Apply to Section 3 Draft

The Section 3 (Threat Model) draft in `design-brief.md` was reviewed adversarially. Findings to apply before the section is considered final:

1. **Move specific vendor names (NSO, Paragon, Intellexa, Cellebrite) from main text to footnotes/appendix.** Reduces legal exposure (NSO has pursued legal action against critics) and editorial tone.

2. **Add missing attack surfaces to Section 3.3:**
   - Provisioning ceremony (QR exchange can be observed/intercepted)
   - Update channel (malicious update is a primary nation-state attack vector)
   - Pilot-deployment supply chain (developer becomes supply chain for provided devices)
   - Forced peer designation (user coerced at onboarding to designate adversary-controlled peers)
   - Returned-after-seizure devices (may have implants)
   - Group membership exposure (what's revealed when one group member is compromised)

3. **Add missing trust roots to Section 3.4:**
   - Sigsum transparency log itself
   - Build supply chain (Rust/Kotlin toolchain, dependencies)

4. **Address post-quantum considerations** even briefly (Shor's algorithm against Ed25519/Curve25519). Either acknowledge as out of scope or note as planned future concern.

5. **Remove or soften "morally and often legally legitimate" framing** in 3.1 opening. Reads as advocacy where technical analysis should be.

6. **Revise stakes comparison.** "Below the existential-survival tier that classified national-security work occupies" is inaccurate for many target users where prison can mean torture or death. Rephrase to acknowledge severity varies by jurisdiction.

7. **Verify duress profile is actually in v1 scope.** Was claimed in Section 3.5 in-scope mitigations but not specified in earlier architecture discussions. Either add to actual scope or remove the claim.

8. **Source or generalize capability tier numbers.** The "$1M-7M" range in 3.2 needs sourcing or should be generalized to qualitative description.

9. **Diversify threat intel sourcing beyond Citizen Lab.** Add references to Amnesty Security Lab, Access Now's Digital Security Helpline, CDT.

10. **Soften "protection against forensic examination"** in 3.5 in-scope. Cellebrite has gotten into modern devices in documented cases. Better phrasing: "significant resistance to forensic examination given strong passphrase and intact hardware element."

11. **Expand HUMINT surface coverage in 3.3.** Currently one paragraph; HUMINT is the most common compromise vector in real cases per operational reviewers. Should be expanded to match.

12. **Acknowledge user understanding as a variable.** The threat model implicitly assumes users can comprehend it. Many target users can't. Add note that the model is for whoever onboards the user, not necessarily the user themselves.

---

## Reference Materials

### Protocols and standards

- **SimpleX Chat** (https://simplex.chat/) — primary messaging spine, no-identifier architecture
- **Briar** (https://briarproject.org/) — peer-to-peer over Tor, highest-sensitivity tier
- **Tor** (https://torproject.org/) — transport anonymization layer
- **Meshtastic** (https://meshtastic.org/) — LoRa mesh, flood-routing model
- **MeshCore** (https://meshcore.io/) — LoRa mesh, intelligent routing, store-and-forward
- **Sigstore** (https://sigstore.dev/) — code signing and transparency
- **Sigsum** (https://sigsum.org/) — minimal-trust transparency log
- **COSE** (RFC 9052) — CBOR Object Signing and Encryption, for capability tokens
- **Ed25519, Curve25519, ChaCha20-Poly1305** — cryptographic primitives
- **Shamir Secret Sharing** — recovery key splitting
- **The Update Framework (TUF)** — referenced but rejected for v1 as overkill

### Existing products surveyed

- **Signal** — rejected as primary (phone number, centralized)
- **Matrix / Element** — rejected as primary (server burden, metadata exposure)
- **Wickr** — rejected (AWS-owned, enterprise focus)
- **Session** — rejected (Session Network dependency, fork from Signal protocol)
- **Veilid** — interesting reference architecture but earlier-stage
- **Cwtch** — alternative to Briar, similar properties
- **Wire** — security history has had bumps
- **Threema** — Swiss commercial, expensive at scale

### Hardware

- **Pixel devices** with GrapheneOS — v1 target platform
- **Titan M2 secure element** — hardware key storage
- **LoRa hardware** (for v3): Heltec WiFi LoRa 32 V3, LILYGO T-Beam, RAK WisBlock, Seeed SenseCAP
- **Hardware tokens** (for v2 USB): YubiKey 5, NitroKey 3, SoloKey
- **Hardware-encrypted USB** (alternative for v2): Apricorn Aegis Secure Key, Kingston IronKey D500S

### Community organizations

- **Citizen Lab** (Munk School, University of Toronto) — threat intelligence and forensic research
- **EFF Surveillance Self-Defense** — user education reference
- **Tactical Tech** + **Front Line Defenders** — Security in-a-Box, training and resources
- **Access Now Digital Security Helpline** — 24/7 in 9 languages, 2-hour response time, CiviCERT member
- **Open Technology Fund (OTF)** — primary funding target
- **Amnesty International Security Lab** — additional threat intel source

### Threat intelligence cases referenced

- **Paragon Graphite targeting European journalists** (Citizen Lab, June 2025, CVE-2025-43200)
- **Cellebrite extraction of Boniface Mwangi's phone** (Kenya, July 2025)
- **Jordan civil-society device-seizure cluster** (late 2023 to mid-2025)
- **Apple "advanced spyware" notifications** (April 29, 2025 cohort)

---

## Suggested Next Steps in Claude Code

1. **Set up project repository** with this handoff document and the design brief as initial documentation. Recommended structure:

   ```
   project-root/
     docs/
       handoff.md (this document)
       design-brief.md (the in-progress brief)
       decisions/ (one file per decision, expanded over time)
       open-questions.md
     specs/ (technical specifications as they develop)
     research/ (any source materials, threat intel, etc.)
   ```

2. **Apply adversarial review findings** to Section 3 of the design brief as the first concrete work. Each finding becomes either an edit or a documented decision not to apply.

3. **Continue drafting sections in this order:**
   - Section 5 (Architecture Detail) — most concrete decisions live here
   - Section 6 (v1 Scope) — forces clarity on what ships
   - Section 4 (Solution Overview) — needs Section 5 to be drafted first
   - Section 2 (Problem Statement) — including comparative threat models (item 15 from earlier brainstorm)
   - Section 7 (Roadmap) — extends naturally from Section 6
   - Section 8 (Operational/Governance) — solo-developer specifics
   - Section 9 (Risks and Limitations) — applies adversarial-review thinking systematically
   - Section 10 (Funding) — concrete numbers
   - Sections 1 (Executive Summary) and 3.1 framing tweaks — written last

4. **Use real adversarial review with sub-agents** in Claude Code at the end of each section, before moving to the next. The simulated review demonstrated value; real multi-agent review will be stronger.

5. **Establish technical reviewer pool early.** The Sigstore-based signing model relies on external reviewers per release. Identify and approach 2-3 candidates before code is written, so they're aware and committed.

6. **Begin informal validation conversations** with potential pilot users while drafting continues. Two to three weeks of part-time outreach in parallel with documentation work.

7. **Choose a project name** before approaching partner organizations or funders. Working title is fine internally but external conversations need something specific.

---

## Continuation Prompt for New Claude Code Session

Paste something like this at the start of the new session:

> I'm continuing work on a secure communications product designed for users facing serious adversarial threats — state actors with legal and extralegal capability, mercenary spyware operators, criminal organizations with SIGINT. The v1 target is a phones-only Android app on GrapheneOS Pixel, integrating SimpleX (primary messaging) and Briar (highest-sensitivity peer-to-peer) over Tor, with capability-token identity, cryptographic trust graph, and social recovery via Shamir Secret Sharing.
>
> Context from a prior design session is in `docs/handoff.md`. The in-progress design brief is `docs/design-brief.md` — Section 3 (Threat Model) has been drafted; adversarial review findings to apply are documented in the handoff.
>
> I'd like to [next step — e.g., "apply the adversarial review findings to Section 3" or "begin drafting Section 5 (Architecture Detail)"].
>
> Please read the handoff document first to establish full context before proceeding.

Adjust the next-step framing based on what you actually want to do first when you reopen.

---

## Notes on the Transition

A few things that work differently between this environment and Claude Code:

- **Sub-agents:** Claude Code supports launching sub-agents for parallel tasks (real adversarial review, drafting alternative versions, parallel research). Use these aggressively for the adversarial review pattern that was simulated here.

- **Persistent project context:** Claude Code maintains the project state across sessions. The handoff document becomes the always-loaded primary context rather than something pasted at the start of each conversation.

- **File handling:** Claude Code has better tooling for managing many files in a project structure. The single design brief can be split into smaller files (per-section), with cross-references, as it grows.

- **Code work:** when development starts, Claude Code's file editing, build integration, and test running become first-class. The architecture decisions in this document will be implemented there.

- **Adversarial review at scale:** the simulated five-reviewer panel here can be made real with sub-agents in Claude Code. Each reviewer perspective becomes a sub-agent with a specific role prompt; their outputs are then synthesized. This is genuinely stronger than what was done here.

---

_End of handoff document._
