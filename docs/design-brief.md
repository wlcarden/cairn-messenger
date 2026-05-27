# [Project Name TBD] — Design Brief

**Status:** Working draft
**Author:** [Author]
**Last updated:** [Date]
**Document version:** 0.1

---

## About this document

This brief describes the architecture, scope, and operational plan for a secure-communications project aimed at users facing adversarial network environments and serious personal-safety risks. It is intended as the basis for external review, partnership conversations, and funding discussions. A full technical specification will follow, informed by feedback on this document.

The brief is structured to be readable by technical reviewers (cryptographers, security researchers), operational reviewers (NGO security trainers, journalists' digital security staff), and potential funders. It is roughly 15-20 pages when complete.

---

## 1. Executive Summary

_Purpose: one-page summary that lets a busy reader decide whether to engage with the rest. Should answer: what is this, who is it for, why does it matter, what's being proposed, what's needed._

Contents to write:

- The problem in one paragraph (people doing dangerous work need comms tools their adversaries cannot defeat, existing tools don't fully meet this)
- The product in one paragraph (Android app on GrapheneOS Pixel, integrating SimpleX + Briar over Tor, with capability-token identity, cryptographic trust graph, and social recovery)
- The differentiator in one paragraph (integration and operational discipline that existing tools lack; designed for freedom-on-the-line threat tier specifically; extends to mesh radio and bootable USB in later releases)
- v1 scope and pilot plan summary
- Resource and timing summary

---

## 2. Problem Statement and Audience

_Purpose: ground the project in a real, specific problem and an identifiable audience. Avoid hand-waving._

Contents to write:

### 2.1 The problem

- The category of work this protects: organizing, journalism, documentation, technical work being done by people whose adversaries include state actors and unaccountable SIGINT operators
- The specific failure modes of existing tools (Signal centralization + phone number requirement; Matrix server burden + metadata exposure; Wickr/AWS ownership; SimpleX/Briar excellent protocols but lacking operational/integration layer)
- What's at stake: freedom, potentially years of imprisonment, in extreme cases life

### 2.2 The audience

- v1 audience (explicit and honest): users running GrapheneOS on Pixel devices, initially via direct provisioning to known pilot groups
- Longer-term audience (roadmap-dependent): broader grassroots usage as mesh and USB features extend the addressable use cases
- Where these audiences come from: defense subcontractors, journalists in hostile beats, NGO field staff, dual-use technology workers, security-conscious activists with hardware access

### 2.3 Gap in the existing landscape

- Brief survey: Signal, Element/Matrix, Wickr, SimpleX, Briar, Cwtch, Session
- Where each succeeds and where each falls short for the specific threat tier
- The integration/operational/trust-graph gap that no current tool fills

---

## 3. Threat Model

### 3.1 An illustrative framing

Consider a journalist documenting government misconduct in a country where the press has been increasingly targeted, who is detained at a border crossing and whose phone is held for forensic examination for several days before being returned. Consider an organizer whose colleague was arrested last week, whose own communications and social connections may now be subject to reconstruction. Consider a humanitarian worker whose laptop was briefly out of their direct control during a hotel stay, in a city where this is known to be how device tampering occurs.

These are not edge cases. They are the routine operational reality of work whose legal standing varies sharply across jurisdictions — and that adversaries treat as actionable regardless of that variation. The threat model that follows specifies what this product is designed to defend against in those moments, and equally importantly, what it is not.

A note on audience. This threat model is written for the people who deploy and support the product on behalf of users — pilot administrators, NGO security trainers, journalists' digital-security staff — and not, in most cases, for the end users themselves. Many of the users it ultimately protects will not read this document. The model assumes their support network understands these tradeoffs on their behalf, not that they personally do.

### 3.2 Adversary landscape

The product assumes adversaries from several overlapping categories. The categories are not mutually exclusive — a single user may face several simultaneously, sometimes in coordination.

**State actors operating with legal process.** Government agencies acting through formal channels: lawful intercept of telecommunications infrastructure, court-compelled disclosure of cloud-stored data, formal mutual legal assistance treaties. Threats from this category are bounded by what the legal system technically allows, which varies dramatically by jurisdiction. In some target deployment environments, legal process is effectively unbounded; in others it provides meaningful constraint.

**State actors operating outside legal process.** Intelligence services and police acting without formal authorization: off-the-books detention and interrogation, covert surveillance of individuals not formally under investigation, deployment of capability against journalists and dissidents both domestically and abroad. This category is documented extensively in the work of academic researchers including the Citizen Lab at the University of Toronto, along with the Amnesty International Security Lab and Access Now's Digital Security Helpline, whose forensic analyses have identified deployments of commercial mercenary spyware against journalists and civil-society members across multiple jurisdictions.[^spyware-vendors]

**Organized criminal entities with SIGINT capability.** Cartels and organized crime groups in some regions operate IMSI catchers, packet capture infrastructure, and bribe officials for telecom intercept access. The capability does not match well-resourced state services but is real and present in some operating environments. Journalists covering organized crime, NGO field staff in cartel-affected regions, and dual-use technology workers all face this threat tier.

**Commercial mercenary spyware operators.** Companies marketing offensive capability — zero-click exploit chains, persistent device implants, forensic extraction — to government and quasi-government customers. As documented by Citizen Lab in June 2025, commercial mercenary spyware was used against European journalists via a zero-click attack exploiting CVE-2025-43200, identified after Apple notifications alerted targeted users.[^paragon-2025] The economics of this market mean that even smaller states can rent capability that previously required nation-state intelligence resources.

**Border and customs forensic operations.** Devices seized at borders or during detention, examined with commercial forensic extraction tools, sometimes returned with implants installed. Such tools have been documented in use against civil society in multiple cases, including the 2025 case of Kenyan pro-democracy activist Boniface Mwangi, whose phone was forensically examined while in police custody, and an extended cluster of cases involving Jordan-based civil society between late 2023 and mid-2025.[^forensic-extraction]

**HUMINT against the user's network.** Pressure on family and colleagues, planted contacts inside organizations, social engineering of users and their associates. Best technical security does not address this category; the design assumes some level of HUMINT exposure exists and tries to limit blast radius.

**Capability tier assumed.** Across these categories, the design assumes adversaries with: operational budgets sufficient to acquire commercial mercenary spyware and commercial forensic extraction tooling, lawful or compelled access to telecom and cloud infrastructure in their operating jurisdiction, ability to detain individuals for hours to days and forensically examine their devices, ability to apply pressure to family and contacts within their reach, and time horizons measured in months rather than minutes. The design does not assume targeted nation-state SIGINT against the product itself (which would imply attacks against the development pipeline, signing infrastructure, or upstream protocols), but acknowledges this as a residual risk worth monitoring.

### 3.3 Attack surfaces and consequences

The product is exposed across several distinct surfaces. Each is described with how adversaries attack it and what is lost when they succeed.

**Network surface.** Communications cross networks the user does not control. Adversaries with network position can perform deep packet inspection and protocol fingerprinting, operate fake base stations (IMSI catchers) that intercept cellular traffic, compel cooperation from telcos and ISPs for lawful intercept, manipulate routing via BGP, intercept TLS through mandated local certificate authorities, and correlate traffic patterns across services. Successful attack yields metadata about whom the user contacts and when, content of unencrypted traffic, and in some cases the ability to inject traffic that compromises endpoints.

**Endpoint surface.** The user's device itself is exposed to zero-click mercenary spyware delivered through messaging apps or other software, forensic extraction tooling when seized, evil-maid attacks when left unattended in adversary-accessible locations, and physical seizure with indefinite retention. Successful attack yields complete access to data on the device, ongoing surveillance of the user, and in seizure cases, indefinite loss of the device itself even if no information is extracted. The consequence is not bounded by what was on the device at the moment of compromise — it includes everything that can be retroactively decrypted from message history, every contact that can be enumerated, every cryptographic capability that can be used to impersonate.

**Returned-after-seizure surface.** Devices returned to users after detention, border seizure, or any period of physical adversary control must be treated as potentially compromised. Forensic extraction tooling can be paired with implants installed in firmware, in the secure-element boot chain, or in user-space components, with varying levels of persistence and detectability. The product cannot reliably detect such implants from within the running system — implants designed to survive forensic examination are also designed to survive runtime introspection. The operational guidance is that a seized device should be considered burned: the cryptographic identity it held should be revoked, recovery should produce a fresh identity on a fresh device, and the seized device should not be returned to active use. This guidance is the mitigation; the underlying surface remains exposed for users who lack the resources to replace a seized device.

**Update channel surface.** Software updates are a primary nation-state attack vector against communications products. Adversaries can attempt to push a malicious update to a single targeted user, compromise the developer's signing identity to push a malicious update broadly, or coerce the developer or build infrastructure into producing a malicious build. The Sigstore-based signing model with reproducible builds and external reviewer attestations (Section 5.5) is the product's primary defense, but no defense reduces this surface to zero. Successful attack yields complete compromise of every user who installs the update; the consequence is bounded only by how many users install before the attack is detected and the update is revoked. The transparency log is the detection mechanism, not the prevention mechanism — broad attacks may be detected within hours, but a targeted attack against a single user may go unnoticed indefinitely.

**Identity surface.** The user's cryptographic identity can be attacked through compelled disclosure of credentials under legal or extralegal pressure, social engineering and phishing, account takeover via SIM swap or similar techniques, and outright key theft when devices are compromised. Successful attack yields the ability to impersonate the user, to issue attestations on their behalf, to receive messages intended for them, and to revoke their own legitimate access.

**Provisioning ceremony surface.** A user's cryptographic identity is established at the provisioning ceremony — in v1, typically an in-person QR-code exchange that seeds the trust graph and derives the initial attestations the user holds. The ceremony is exposed to adversarial observation if conducted in surveilled spaces (cameras, room audio, shoulder-surfing), to compelled or coerced participation by either party (the user is detained at the moment of provisioning; the provisioner is the adversary or under their control), and to ceremony substitution if the QR exchange occurs across an adversary-mediated channel rather than physically co-located. Successful attack against the ceremony yields the resulting identity and any attestations it carries — and because the trust graph anchors on these initial attestations, ceremony compromise has effects that persist through the entire lifetime of that identity. Mitigations include conducting the ceremony in private, in person, with both parties holding their own devices; the design assumes some users will accept higher ceremony risk in exchange for operational feasibility.

**Metadata surface.** Even when content is fully encrypted, who-talks-to-whom-when can be reconstructed through traffic correlation across services, location pattern analysis across devices and apps, timing correlation between messages and observable events, and social graph inference from contact lists and group memberships. Successful attack yields identification of the user's collaborative network, mapping of organizational structure even when individual content cannot be read, and targeting prioritization for further action.

**Group membership and association surface.** When users participate in groups — formal cells, project channels, community channels — group membership itself is a target distinct from individual metadata. An adversary who compromises one group member gains visibility into the group's membership list, the volume and timing of group communications, and in some configurations the content of group messages. Successful attack against group membership yields a list of users to target next, mapping of organizational structure across the group, and information for prioritizing further attacks against members who have not yet been directly compromised. The design minimizes group-level metadata where the protocols permit (per-message recipient resolution rather than persistent member rosters where possible), but groups remain inherently associational and cannot be made fully private without losing their utility. Users who participate in groups should understand that the compromise of any group member has consequences for every other member.

**HUMINT surface.** Across documented cases of journalist and civil-society compromise, the most common vector is not technical exploitation but human intelligence: pressure on family and colleagues, planting of contacts inside organizations, social engineering of users and their associates, and outright informant recruitment from within the user's network. Access Now's Digital Security Helpline incident data and Front Line Defenders' protection casework both reflect HUMINT as a leading category of compromise across the protected populations they serve, and operational reviewers at training organizations report the same pattern.

HUMINT against a target's network operates at multiple removes. At the closest range, family members are detained and questioned to extract information about the user's activities, location, and contacts. At one remove, colleagues at the user's organization or affiliated organizations are approached — sometimes with direct threats, sometimes with offers of money or relief from unrelated legal pressure, sometimes with appeals to ideology or grievance. At further remove, new contacts are introduced to the target's social circle who report back to the adversary — a slower attack but harder to detect, because the target trusts the introduction chain rather than evaluating each new contact in isolation.

The best technical security does not address this category of attack. The product assumes some level of HUMINT exposure exists for any user with stakes high enough to require the product in the first place, and is designed to limit the blast radius of any single HUMINT compromise. The trust graph's design contributes directly to this: attestations are scoped, revocable, and visible, so a compromised contact who begins issuing suspicious attestations or making suspicious introductions can be identified and quarantined rather than silently expanding the adversary's foothold. Cellular compartmentation patterns (formal in v3+, organizational in v1) further limit what any single HUMINT compromise can reach. Users and the people who train them should treat HUMINT as the dominant risk category at this threat tier, and treat the design's HUMINT-limiting features — scoped attestations, soft-cascade quarantine on revocation, compartmentalized rosters — as among the most operationally important security properties of the product, even though they are quieter and less visible than encryption.

**Forced peer designation surface.** At provisioning, the user designates recovery peers from their contact list. A user under coercion at the moment of provisioning may be forced to designate peers chosen by the adversary, or peers the adversary intends to compromise later. This surface is distinct from the Recovery network surface below: that surface concerns later compromise of legitimately-chosen peers, while this surface concerns adversary-influenced peer selection at the moment of identity establishment. Successful attack yields adversary access to the user's master identity, recoverable on demand. The mitigation is operational — provisioning should occur outside of adversary presence, with peer designation made under conditions the user controls — but the surface persists for users whose provisioning conditions are themselves compromised. The pilot's in-person provisioning by a known facilitator reduces this risk meaningfully but does not eliminate it; broader deployments without trusted facilitators will face it more directly.

**Recovery network surface.** The peer network designated for social recovery is itself a high-value target and worth calling out separately. An adversary who identifies a user's recovery peers and successfully compromises three of them gains the user's master cryptographic identity even if the user themselves is not directly compromised. This is an architectural tradeoff: social recovery makes the user's identity restorable without trustees in friendly jurisdictions, at the cost of distributing the identity's security across a small social network. Peer selection — geographic distribution, social distance, ability to refuse coercion — directly affects the security of this surface.

**Tool-use surface (acknowledged, not mitigated).** In some jurisdictions, the mere fact that an individual runs GrapheneOS, uses Tor, or installs identifiable security software is itself sufficient pretext for further scrutiny. The product cannot meaningfully mitigate this — by the time someone is using the product, they have accepted being identifiable as a user. The design minimizes how identifiable the product's traffic is on the network (Tor obfuscation, generic-looking encrypted blobs to network observers), but cannot eliminate the underlying signal that security-conscious behavior is itself observable. Users should understand this limitation explicitly.

**Distribution and supply-chain surface.** In the v1 pilot model, the developer purchases Pixel devices, installs GrapheneOS, installs the application, and provisions identities for users — meaning the developer becomes the supply chain for the pilot. An adversary who compromises the developer, the build pipeline, the hardware supplier, or any step of the device-preparation workflow can position malicious code or hardware before the user takes possession. Successful attack against this surface compromises pilot users without their knowledge and without any opportunity for them to independently verify the integrity of what they received. The mitigations are reproducible builds, transparency logging of release artifacts, external reviewer attestations of binaries, and operational discipline around device preparation — but the trust placed in the pilot-distribution channel is real and worth naming explicitly. Post-pilot, as the product moves to broader distribution via F-Droid/Accrescent and direct download, this surface narrows but does not disappear: it shifts from the developer's hands to the build and signing infrastructure.

**Stakes.** The consequences of successful attack on any of these surfaces are bounded by the stakes of the user's work, and those stakes vary sharply by jurisdiction. For some users in some jurisdictions the realistic worst case is a fine, professional sanction, or job loss. For others it is years of imprisonment, with credible risk of torture or death in custody. The product is designed toward the upper end of this range — well above the casual-privacy tier that most consumer messaging tools target, and in the most severe deployment environments approaching the existential-survival tier that classified national-security work occupies. Design decisions throughout the product reflect this positioning: aggressive forward secrecy, minimum on-device persistence, plausible deniability where achievable, social recovery rather than centralized trustees, transparency-log auditability rather than internal accountability.

### 3.4 Trust roots

For the threat model to be honest, the product must specify what it does _not_ try to protect against — the foundations it trusts to be uncompromised. If any of these trust roots are broken, the product's security guarantees do not hold. Naming them explicitly is a form of honesty that reviewers should be able to evaluate.

The product trusts:

**The GrapheneOS operating system.** The hardened Android distribution is assumed not to be backdoored, deliberately weakened, or compromised through upstream supply chain. The trust is justified by the project's open development, reproducible builds, and security track record, but it is a trust nonetheless.

**The Pixel hardware.** Specifically the Titan M2 secure element and the verified boot chain. Pixel devices have been examined by independent researchers, but supply-chain attacks against specific devices delivered to specific users remain a theoretical possibility. The product assumes that devices obtained through normal commercial channels (or through the pilot's curated distribution) are not individually compromised.

**The cryptographic primitives.** Ed25519 signatures, Curve25519 key agreement, ChaCha20-Poly1305 authenticated encryption, and the underlying mathematical assumptions of elliptic-curve cryptography. These are widely deployed and extensively analyzed; their failure would represent a fundamental break in modern cryptography rather than a product-specific vulnerability.

**The Tor network.** Not as an absolute guarantee of anonymity — Tor's threat model has well-understood limits against global passive adversaries — but as a transport layer that meaningfully complicates traffic analysis and network-level surveillance for the threat tier this product addresses.

**The SimpleX and Briar protocols.** Their core cryptographic constructions — including SimpleX's double-ratchet derivative and Briar's pairwise key exchange — are assumed correct. Both projects have undergone external review and both remain subject to ongoing scrutiny. Implementation flaws are possible and the integration must handle them defensively, but the underlying protocols are trusted.

**The Sigsum transparency log.** The trust-graph attestations and revocations are anchored in Sigsum, which provides public auditability and tamper-evidence through a minimal-trust witness-cosignature model. The product trusts that enough independent witnesses are operating and that systemic cosignature collusion is not occurring. Sigsum is explicitly designed to minimize the trust placed in any single party, but it is still a trust root: if all witnesses are compromised or collude, log tampering becomes undetectable from outside the log.

**The build supply chain.** The toolchain that compiles the application (Rust toolchain, Kotlin toolchain, the Android NDK and SDK) and the tree of third-party dependencies pulled in at build time are assumed not to contain deliberately introduced backdoors. Reproducible builds and external reviewer attestations of binaries are the primary defenses — multiple independent parties producing identical binaries from identical source raises the cost of supply-chain tampering — but the underlying trust in compilers, language runtimes, and the transitive dependency graph remains. The xz-utils backdoor identified in 2024 is a recent reminder that this trust root has been actively attacked.

**The user themselves, mostly.** The product cannot defend against a user who deliberately compromises themselves, who shares credentials voluntarily, or who acts as an active agent against their own network. It assumes users make basic operational decisions in good faith — not expert-level operational security, but not active sabotage either.

**A note on post-quantum cryptography.** The primitives the product relies on — Ed25519 signatures, Curve25519 key agreement, and the elliptic-curve assumptions underneath them — are vulnerable to a sufficiently capable quantum computer running Shor's algorithm. No such machine exists today, and the consensus timeline for one to exist is uncertain by at least a decade and likely more. The product does not include post-quantum primitives in v1; the protocol versioning fields specified throughout the design (Section 6.4) are intended to enable a future transition without breaking the trust graph or invalidating long-lived capability tokens. The realistic concern in the meantime is "harvest now, decrypt later" — adversaries archiving today's encrypted traffic for decryption when capability matures — which matters for users handling long-lived organizational secrets. Users whose secrecy requirements extend beyond the likely PQ-transition horizon should treat this product as a transitional solution and rotate sensitive material on a schedule aligned with their threat tolerance.

### 3.5 v1 scope: in and out

The v1 release addresses the threat model with explicit boundaries on what is and isn't covered.

**In scope for v1.** End-to-end encryption of message content. Metadata minimization through SimpleX's identifier-less architecture and Briar's pure peer-to-peer mode. Forward secrecy via per-conversation session key rotation. Cryptographic attestation of identity through the trust graph. Recovery from device loss via social recovery. Auditability of attestations and revocations through the Sigsum transparency log. Protection of the cryptographic identity through hardware-backed key storage on Pixel. Protection against passive network surveillance through Tor as the transport layer. Significant resistance to forensic examination of the device through encrypted at-rest storage tied to passphrase and the hardware element — contingent on a strong passphrase and an intact hardware element at the moment of seizure.

**Explicitly out of scope for v1, with future-version coverage.** Operation during state-imposed internet shutdowns is not supported in v1; this is the primary motivation for the v3 mesh radio integration, which provides offline local communication via LoRa-based protocols. Sensitive work on borrowed laptops is not supported in v1; this is the primary motivation for the v2 bootable USB form factor, which provides a portable cryptographic identity and amnesic operating environment. iOS users are not supported in v1; this is addressed in v2 if funding permits. Non-Pixel Android devices are not supported in v1 and not planned to be supported — this product remains anchored to the GrapheneOS-on-Pixel security baseline.

**Indefinitely out of scope.** Compromise of GrapheneOS itself, compromise of Pixel hardware, TEMPEST-class electromagnetic emanation attacks, and supply-chain attacks against devices delivered to specific users are not within the scope of any planned version of this product. Some of these are out of scope because they require physical mitigations beyond software's reach; others are out of scope because they constitute the trust roots the product is built on, and addressing them would require building a different product from the ground up.

---

### Section 3 references

[^spyware-vendors]: Documented commercial mercenary spyware deployments against journalists and civil society include NSO Group's Pegasus, Paragon's Graphite, and Intellexa's Predator. Forensic attribution and incident documentation: Citizen Lab (Munk School, University of Toronto), Amnesty International Security Lab, Access Now Digital Security Helpline, and the Center for Democracy & Technology.

[^paragon-2025]: Attribution of the June 2025 European-journalist targeting campaign to Paragon's Graphite product, exploiting CVE-2025-43200, per Citizen Lab analysis corroborated by Apple threat-notification recipients in the same cohort.

[^forensic-extraction]: Commercial forensic extraction vendors documented in use against civil society include Cellebrite (UFED, Premium) and Grayshift (GrayKey). Case documentation: Boniface Mwangi (Kenya, July 2025) and the Jordan civil-society cluster (late 2023 through mid-2025), via Citizen Lab, Amnesty International Security Lab, and Access Now Digital Security Helpline reporting.

---

## 4. Solution Overview

_Purpose: high-level architecture sketch that orients the reader before the detailed architecture section. Aim for 1-2 pages._

Contents to write:

### 4.1 Architecture in three layers

- Endpoint: GrapheneOS Pixel device, hardened, with the v1 app
- Transport: Tor as the network anonymization layer, with protocol-layer obfuscation as needed for jurisdiction-specific DPI
- Comms: SimpleX as primary spine for everyday messaging, Briar for highest-sensitivity peer-to-peer fallback

### 4.2 Key design principles

- No project-operated infrastructure that users depend on (the project can disappear and existing deployments keep working)
- Self-sovereign cryptographic identity, no central registry of users
- Trust managed via a graph of signed attestations, not via a PKI or trusted authority
- Forward secrecy and ephemeral message retention at every layer
- Graceful degradation under adversarial network conditions
- UX targeted at users who are not technical specialists; security discipline lives in defaults rather than in user configuration

### 4.3 Differentiation

- Where the product sits relative to Signal, Matrix, Wickr, SimpleX, Briar
- What it adds: integration, identity, trust graph, operational discipline, per-jurisdiction profiles, eventual hardware tier
- Why this combination doesn't exist today

---

## 5. Architecture Detail

_Purpose: enough detail that a technical reviewer can engage with the design choices. Not full specification — that comes in the system design spec later._

### 5.1 Identity Model

Contents to write:

- Three-tier identity: master / operational / device
- Master identity: Ed25519 keypair generated at provisioning, Shamir-split among recovery peers immediately, never stored in active memory after split
- Operational identity: Ed25519 keypair signed by master at provisioning, held in phone's hardware-backed keystore (Titan M2), used for signing capability tokens to devices and for trust graph operations
- Device capability tokens: short-lived signed delegations granting specific permissions to specific device keys, COSE-formatted
- Why three tiers rather than HD keys: independent revocation, scope-bounded delegations, master can stay cold

### 5.2 Trust Graph

Contents to write:

- Each operation (attestation, revocation, introduction, key rotation) is a signed message with: issuer, subject, context, strength, timestamp, expiry, prior-hash, signature
- Operations propagate via the messaging layer as metadata accompanying user-to-user traffic
- Each client maintains a local CRDT view; trust paths computed locally
- Sigsum transparency log for public auditability of attestations and revocations
- Witnesses: trusted NGO partners and academic auditors countersign the log state
- Cascade quarantine on revocation: soft-flag rather than hard-suspend, supports re-attestation

### 5.3 Recovery Model

Contents to write:

- Shamir Secret Sharing of the master identity key, 3-of-5 default, peers designated at onboarding
- Recovery peers selected by the user from their contact list
- Recovery flow: user contacts 3 peers from a fresh device, peers provide shares, master is reconstructed, new operational key signed, master immediately re-split and forgotten
- Graceful failure: fewer than 3 peers available means recovery fails closed; no leakage from partial shares
- Alternative path: fresh identity with in-person re-introduction by an existing contact, accepting loss of historical state

### 5.4 Communications Protocols

Contents to write:

- SimpleX as primary: no persistent identifiers, queue-based, servers can be self-hosted or use defaults
- Briar as highest-sensitivity tier: pure peer-to-peer over Tor, accepted both-parties-must-be-online cost for metadata resistance
- Tor as transport layer for both
- Why not Matrix (server burden), not Session (Session Network as external dependency), not Signal (phone number, centralization)
- Voice/video deferred to v1.x or v2 depending on time

### 5.5 Updates and Release Security

Contents to write:

- Sigstore identity-based signing (no long-lived signing keys)
- Reproducible builds (community can independently verify binaries match source)
- Small pool of external reviewers (2-3) publishing signed attestations per release
- Public transparency log of all releases
- Rollback resistance via signed monotonic version numbers
- Multi-channel distribution: F-Droid/Accrescent, GitHub releases, Tor onion service, optional offline distribution via signed images

### 5.6 UX Principles

Contents to write:

- Signal-familiar surface: message threads, contact list, voice notes, file sharing, group chats
- Trust badges and verification indicators surfaced subtly
- Profile compartmentation for users who want it, invisible for those who don't
- Optional "extra-private mode" toggle per conversation (Briar channel)
- Duress profile support: designated passphrase opens innocuous-looking profile
- Recovery accessible without requiring expertise; multiple recovery paths
- Honest communication of limitations rather than absolute security claims

---

## 6. v1 Scope

_Purpose: explicit definition of what ships in v1, what's deferred, and why. This is the section funders and partners care most about._

Contents to write:

### 6.1 What ships in v1

- Android app for GrapheneOS Pixel only
- SimpleX integration as primary messaging
- Briar integration for highest-sensitivity channel
- Trust graph with attestation, revocation, social recovery
- Provisioning ceremony via in-person QR pairing
- Profile management (multi-profile support within the app)
- Per-jurisdiction profile feed (initial 2-3 profiles based on pilot context)
- Sigstore-based update distribution
- Documentation for users and for the pilot administrators

### 6.2 What's explicitly deferred

- USB-bootable variant (v2)
- iOS support (v2)
- Non-Pixel Android support (likely never; product remains GrapheneOS-Pixel-anchored)
- Mesh radio integration (v3, Meshtastic/MeshCore)
- Established-org enterprise tier with formal admin/governance (v4+)
- Voice/video calling (v1.x if time permits, v2 if not)
- Broader localization beyond English (v1.x post-pilot)

### 6.3 Pilot deployment plan

- 10-15 users in 1-2 local groups, identified through developer's existing network
- Devices provided by the project: GrapheneOS pre-installed on Pixel hardware, app pre-installed, identity not yet provisioned
- In-person provisioning ceremony conducted by developer for initial users
- 6-month pilot period before broader release
- Feedback mechanism: dedicated support channel within the product itself
- Budget estimate: $5-12K hardware plus developer time

### 6.4 Forward-compatibility design choices in v1

- Protocol versioning fields in all signed messages from day one
- Capability tokens with arbitrary scope strings (not hardcoded permissions)
- Multi-device awareness in the protocol layer even though v1 ships only phones
- Device-to-device pairing flow specified generically (same flow used for v2 USB, v3 mesh)
- Trust graph operation types designed for extension
- Storage schemas with version fields and migration framework
- Build system designed to produce multiple artifacts even though v1 ships only one

---

## 7. Roadmap

_Purpose: credible picture of trajectory beyond v1. Funders and partners need to see this._

Contents to write:

### 7.1 Release sequence

- v1 (target: 9-12 months from start of full-time work): scope per Section 6
- v1.5 (6 months post-v1): iteration on pilot feedback, UX refinements, possible voice/video, possible expanded localization
- v2 (12-18 months post-v1): USB-bootable variant, iOS app
- v3 (18-24 months post-v1): mesh radio integration (Meshtastic/MeshCore), addresses internet-shutdown threat
- v4+ (longer term): established-org features, optional Matrix federation for enterprise users, hardware partnerships for pre-keyed devices

### 7.2 Dependencies between releases

- How v1 design choices enable v2 (capability tokens, multi-device protocol, generic pairing flow)
- How v2 enables v3 (USB establishes the additional-device pattern that mesh radios follow)
- What requires architectural revisitation (probably nothing through v3, possibly some changes for established-org tier in v4)

### 7.3 Out-of-scope indefinitely

- Things the project does not intend to do (compete with Signal for mass-market, build custom crypto primitives, run user-facing infrastructure)
- Things that depend on conditions outside the project's control (broader hardware availability, regulatory changes)

---

## 8. Operational and Governance Plan

_Purpose: describe how the project is run, signed, audited, and sustained._

Contents to write:

### 8.1 Development team

- Solo developer initially
- Recruitment plan for collaborators (contributors via OSS contribution, hired contractors via grant funding)
- When and how the team scales

### 8.2 Release security

- Sigstore identity-based signing as primary mechanism
- Reproducible builds as required practice
- External reviewer pool: 2-3 people who do not write code but rebuild and attest each release
- Transparency log of all releases
- Plan for handling signing identity compromise

### 8.3 Code and contribution governance

- Open source license: Apache 2.0 (permissive, maximizes downstream reuse by allied projects)
- Code review: external reviewers for security-critical changes, less formal for UX/UI
- Contribution process: standard GitHub-style with security-aware review

### 8.4 Path to foundation

- Project initially operated by developer
- Foundation incorporation when justified by funding scale and operational maturity (estimated 18-24 months out)
- Examples to draw from: Signal Foundation, Tor Project, Briar Project

### 8.5 Audit and assurance

- Self-audit and automated tooling for v1 development
- External cryptographic review before public beta (post-pilot)
- Continuous review during ongoing development
- Bug bounty program once project has resources

### 8.6 Partnership approach

- Initial outreach: Tactical Tech, Front Line Defenders, Access Now, Citizen Lab, Open Technology Fund
- Roles partners might play: technical review, pilot facilitation, threat intel, localization, end-user training
- Relationship structure: collaborative rather than vendor/customer

---

## 9. Risks and Limitations

_Purpose: honest acknowledgment of what could go wrong and what the product doesn't protect against. Reviewers respect honesty here._

Contents to write:

### 9.1 Project risks

- Solo developer is a single point of failure for the project itself
- Funding may not materialize at the scale needed
- Pilot users may not validate the architecture
- An architectural mistake in v1 could constrain future versions

### 9.2 Product limitations

- v1 does not survive internet shutdowns (mesh comes in v3)
- v1 does not support the borrowed-laptop workflow (USB comes in v2)
- Addressable user base in v1 is meaningfully smaller than the full target audience due to GrapheneOS/Pixel requirement
- Social recovery depends on the user's peer network being available and uncompromised
- Forward compatibility decisions might prove incorrect; some v2+ features may require breaking changes

### 9.3 Security limitations

- No protection against compromise of GrapheneOS itself
- No protection against compromise of the user's Pixel hardware
- No protection against the developer's signing identity being compromised (multi-sig later)
- No protection against deliberate compromise of recovery peers above the Shamir threshold
- No protection against pattern-of-life metadata leakage outside the product (other apps, device location, etc.)

### 9.4 Mitigations and monitoring

- For each significant risk: what reduces likelihood, what reduces impact if it occurs
- Process for receiving and acting on vulnerability reports
- Plan for sunset/migration if the project becomes unsustainable

---

## 10. Funding and Resourcing

_Purpose: realistic picture of what's needed and where it could come from._

Contents to write:

### 10.1 Development cost estimate

- Solo developer time to v1: 9-12 months full-time or equivalent
- Pilot hardware: $5-12K
- External audit before beta: $20-50K
- External reviewer compensation: nominal (in-kind for many, small honoraria for some)
- Total v1 budget estimate: $30-75K plus 9-12 months of developer time

### 10.2 Potential funding sources

- Open Technology Fund (US, but operationally independent, has funded Signal and Tor)
- European democracy and digital rights funds (SIDA, GIZ, EIDHR, Dutch Foreign Ministry)
- Private foundations: Ford, Open Society, Mozilla, Omidyar, Knight
- Self-funding from developer for early stages

### 10.3 Post-v1 sustainability

- Continued grant funding for core development
- Established-org tier as paid offering subsidizing grassroots use
- Possible hardware partnerships in v3+ (pre-keyed USBs, mesh radio kits)
- Donations channel for individual supporters

### 10.4 Timeline to first funded development

- Design brief completion and review: 2-3 months
- Initial funding conversations: 3-6 months
- Funded development start: roughly 6 months from design brief completion

---

## Appendix A: Technical Decisions and Rationale

_Purpose: capture the key architectural decisions with their reasoning, alternatives considered, and references. Lets reviewers engage with the choices rather than just the conclusions._

Decisions to document:

### A.1 Identity model: capability tokens vs HD keys vs threshold signatures

- Decision: hybrid three-tier with capability tokens
- Alternatives considered and why not selected
- References to relevant prior work

### A.2 Trust graph: CRDT vs blockchain vs centralized

- Decision: signed-operation CRDT with sigsum transparency log
- Alternatives considered
- References

### A.3 Recovery: social/Shamir vs trustee/escrow vs paper backup

- Decision: 3-of-5 Shamir among peer-designated recovery contacts
- Alternatives considered
- Why not pure paper backup or trustee model

### A.4 Hardware token role: phone secure element vs external token

- Decision: phone's built-in secure element for v1 (no external token in phones-only scope)
- How v2+ extends to external tokens for USB form factor

### A.5 Comms protocol: SimpleX + Briar vs Matrix vs Session vs custom

- Decision: SimpleX primary, Briar for highest-sensitivity
- Alternatives evaluated
- Rationale for each rejection

### A.6 Updates: Sigstore vs TUF vs custom multi-sig

- Decision: Sigstore identity-based signing with reproducible builds
- Why not full TUF (overkill for project scale)
- Why not custom (reinventing solved problems)

### A.7 Platform: GrapheneOS Pixel only vs broader Android

- Decision: GrapheneOS Pixel only for v1
- Rationale: hardware attestation, reduced testing surface, security baseline
- Tradeoff: addressable user base is meaningfully smaller

### A.8 Mesh protocol selection: Meshtastic vs MeshCore

- Decision (for v3 scope): protocol-agnostic integration supporting both
- Rationale: let users follow local mesh community conventions
- Architectural differences noted

---

## Appendix B: Glossary

_Purpose: define terms used in the document for readers who may not share full technical background._

Terms to define:

- Attestation, revocation, capability token
- CRDT, transparency log, Sigstore, sigsum
- Shamir Secret Sharing, threshold cryptography
- Forward secrecy, ephemeral messaging
- DPI, IMSI catcher, mercenary spyware
- GrapheneOS, Titan M2, hardware attestation
- SimpleX, Briar, Tor, Meshtastic, MeshCore
- HRD, OSS, OTF, NGO

---

## Appendix C: References

_Purpose: cite the prior work this design draws on, threat intelligence sources, and related projects._

Sources to include:

- Cryptographic protocol references (Signal protocol, Olm/Megolm, SimpleX double-ratchet, FROST)
- Threat research (Citizen Lab on Pegasus, Graphite, Predator, Cellebrite usage)
- Community resources (Tactical Tech Security in-a-Box, EFF SSD, Access Now Helpline, Front Line Defenders)
- Related projects (Signal, Element, Wickr, Session, Wire, Cwtch, Veilid)
- Standards and protocols (Sigstore, TUF, COSE, Ed25519)
- Reproducible builds and supply chain security (Debian RB, NixOS, Sigsum, Rekor)

---

## Document changelog

- 0.1 (initial outline): scaffold structure based on architecture decisions to date
