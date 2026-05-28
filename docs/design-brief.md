# Cairn — Design Brief

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

**Bounded exposure under compelled unlock.** The product does not include a duress-profile concealment feature. The architectural answer to compelled unlock is the tier-separated identity model: the master cryptographic identity is Shamir-split among recovery peers and is not present on the device, so even full unlock under coercion does not yield the master identity, the ability to issue master-level attestations, or the recovery shares themselves. What unlock yields is the operational identity, the on-device message history, and the contact list. The operational response to any coercion event is revocation of the exposed operational identity, recovery via the social-recovery process, and reissuance of a new operational identity — bounding the compromise to material at the time of seizure rather than to the user's project-level cryptographic position. This is in-scope for v1 as an architectural property, not as a separate feature.

**Explicitly out of scope for v1, with future-version coverage.** Operation during state-imposed internet shutdowns is not supported in v1; this is the primary motivation for the v3 mesh radio integration, which provides offline local communication via LoRa-based protocols. Sensitive work on borrowed laptops is not supported in v1; this is the primary motivation for the v2 bootable USB form factor, which provides a portable cryptographic identity and amnesic operating environment. iOS users are not supported in v1; this is addressed in v2 if funding permits. Non-Pixel Android devices are not supported in v1 and not planned to be supported — this product remains anchored to the GrapheneOS-on-Pixel security baseline. A duress-wipe feature — a designated passphrase that destroys on-device key material rather than concealing alternate content — is deferred to v1.5; this pattern is observably destructive and matches the existing GrapheneOS duress-PIN model.

**Indefinitely out of scope.** Compromise of GrapheneOS itself, compromise of Pixel hardware, TEMPEST-class electromagnetic emanation attacks, and supply-chain attacks against devices delivered to specific users are not within the scope of any planned version of this product. Some of these are out of scope because they require physical mitigations beyond software's reach; others are out of scope because they constitute the trust roots the product is built on, and addressing them would require building a different product from the ground up. Duress-profile concealment — opening a fake or curated identity under a duress passphrase — is also indefinitely out of scope, because the implementation cannot be made undetectable against the threat tier this product addresses, and detected concealment carries its own legal and physical risks in jurisdictions with compelled-decryption regimes. The v1.5 duress-wipe alternative addresses the same user need through observable destruction rather than concealment; see [Decision D0002](decisions/D0002-duress-profile.md).

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

The product organizes a user's cryptographic identity into three tiers that differ in operational role, storage location, and the conditions under which each is used. The tiers exist because no single keypair can both stay cold enough to survive device compromise and remain reachable enough for routine daily operation. Splitting these requirements across separate keypairs lets the design place each tier where its purpose demands.

**Master identity.** An Ed25519 keypair generated locally at the provisioning ceremony. Immediately after generation, the private key is split using Shamir Secret Sharing into shares distributed to the recovery peers the user designates (see 5.3); the assembled private key is then erased from active memory and is not written to persistent storage. The master public key is the user's stable cryptographic identity over the lifetime of the project — the anchor that appears in the trust graph, the verifier for the operational identity below, and the long-lived reference that survives device loss and reissuance of subordinate keys.

The master is not present on the device in routine operation. Reconstruction requires reassembling the Shamir shares from the recovery peers, which happens only at two moments: provisioning (immediately before the split), and recovery from a fresh device. The architectural implication is that compelled unlock of the active device does not yield the master, regardless of what credentials are extracted — the secret material simply is not there to extract. See [Decision D0002](decisions/D0002-duress-profile.md) for the consequences of this property under the compelled-unlock threat model.

**Operational identity.** An Ed25519 keypair signed by the master at provisioning, held in the phone's hardware-backed keystore — on Pixel devices, the Titan M2 secure element. The operational keypair is generated inside the hardware element, the private key never leaves, and signature operations are gated by both the user's passphrase and the hardware element's policy. The operational identity is the working signing key for daily activity: signing capability tokens to devices, signing trust graph operations (attestations, revocations, introductions), authenticating sessions with the SimpleX and Briar protocol layers.

The operational identity is rotatable. Rotation requires the master and is performed at three predictable moments: at provisioning (the first operational key is signed alongside the master's creation), after a coercion event (the user reconvenes recovery peers, reconstructs the master, rotates, and re-splits), and proactively whenever the user has reason to suspect the operational key has been used outside their control. A rotation issues a new operational keypair signed by the master and revokes the prior operational identity through the trust graph (see 5.2 for revocation cascade semantics). Rotation does not invalidate the user's stable identity — the master public key remains — only the specific operational key that signed recent activity.

**Device capability tokens.** Short-lived signed delegations granting scoped permissions from the operational identity to specific device keys. Tokens are formatted as COSE structures (CBOR Object Signing and Encryption, RFC 9052) — a compact, binary, well-specified envelope that is implementable across the language platforms the project may need (Kotlin and Rust at v1, possibly others later). Each token names an issuer (the operational identity public key), a subject (the device key being delegated to), a set of scope strings (`messaging-send`, `trust-graph-attest`, `recovery-receive`, and so on), a validity period typically measured in hours to days rather than weeks, and the operational identity's signature over all the above.

The scope vocabulary is intentionally not fixed at v1 — capability tokens carry arbitrary scope strings rather than a closed enumeration, so later versions can introduce new scopes (`mesh-relay` in v3, `usb-attached-device` in v2, and so on) without breaking compatibility with older clients, which simply do not recognize the new scope and decline operations requiring it. This is one of the forward-compatibility design choices captured in Section 6.4.

Capability tokens are renewable. The device requests a fresh token from the operational identity, which on the same device means re-prompting for the passphrase that unlocks the hardware element; if the user is unwilling or unable to renew, the device's authority lapses at the token's expiration. Scope-bounded tokens mean that a compromised device cannot, by holding its current token, exceed the permissions that token explicitly granted: a device with a `messaging-send` token cannot issue trust graph attestations even if its key material is fully extracted by forensic tooling.

**Why three tiers rather than alternatives.** The design was evaluated against several simpler models.

A single keypair held on-device was rejected because it conflates the user's stable identity with the working signing key. In that model, device compromise — which is well within the threat model (Section 3.3, Endpoint surface and Returned-after-seizure surface) — compromises the identity that the trust graph anchors on, with no clean path to recover without losing all attestations the user has accumulated.

Hierarchical Deterministic (HD) key derivation, in which all derived keys are computed from a single seed, was rejected because the seed becomes a single master credential whose exposure derives all subordinate keys retroactively. There is no way to revoke one derived key independently of the others, and the seed must be reachable whenever subordinates need to be derived — which means either the seed is on the device (defeating the cold-master property), or every key rotation requires reassembling the seed.

Threshold signature schemes, in which signatures require collaboration among multiple parties, were considered for the master identity directly but rejected for daily operation as operationally too heavy: every signing event would require coordination across the threshold, which is workable for occasional ceremonial master operations but not for the per-message and per-attestation signatures that the working keys produce constantly. Threshold approaches for the master alone remain a candidate for later exploration but are not in v1.

The three-tier model accepts a small additional implementation complexity (three keypairs and a delegation format rather than one keypair) in exchange for properties the simpler models cannot offer: the master can stay cold across device compromise, the operational identity can be rotated without disturbing the stable identity, and device-level tokens can be revoked individually and bounded in scope.

**Storage and access control summary.**

- _Master._ Not stored in any single location. Shamir shares are held by recovery peers, never assembled outside the user's own provisioning or recovery events. The master public key, needed for verifying operational signatures, is published in the trust graph and freely available.
- _Operational._ Hardware element (Titan M2). Signing requires user passphrase plus hardware element policy gate. The private key never leaves the element.
- _Device tokens._ Standard application storage, encrypted at rest by the device's full-disk-encryption key. Token material is recoverable from device storage if the device is unlocked, which is appropriate given that the token itself is short-lived and scope-bounded.

The product treats the operational identity as the central daily credential. Master operations are infrequent and ceremonial (initial provisioning, recovery, identity rotation after coercion). Device-token operations are routine and frequent (every action that requires signing). This separation lets the storage and access decisions for each tier reflect its actual usage rather than forcing a single policy across operations with very different security properties.

### 5.2 Trust Graph

The trust graph is the structure through which Cairn users express, observe, and revise their confidence in each other's identities without depending on a central authority. It is not a database of users and it is not a registry maintained by the project; it is a partially-ordered set of signed claims that each user keeps a local view of, and that propagates between users through the messaging layer the product already operates. The graph's purpose is to let a user evaluate, at the moment of any interaction, whether the public key they are about to trust has been vouched for by parties they themselves trust — and to let that evaluation be revisited when one of those parties is later found to be compromised.

**Four operation types.** The graph is built from four kinds of signed messages, each issued by an operational identity (Section 5.1) and each carrying the same envelope. An _attestation_ asserts that the issuer has verified, in some specified context and to some specified strength, that a given public key belongs to a given party. A _revocation_ withdraws a prior attestation — issued by the same party that issued the original, or in the case of compromise by the affected party themselves against attestations made by their compromised key. An _introduction_ records that the issuer has connected two other parties to each other, naming both; it is the operation by which trust paths extend through the social network. A _key rotation_ announces that an operational identity has been replaced (per Section 5.1's rotation events) and binds the new operational key to the master that previously signed the old one, so peers can follow the transition without losing continuity. Four operations are sufficient for the v1 graph; protocol versioning (Section 6.4) leaves room for additional types as later work identifies them.

**Signed-operation schema.** Every operation carries the same eight named fields. The _issuer_ is the operational public key making the claim. The _subject_ is the public key the claim is about — for an attestation or revocation, the party being attested to or revoked; for an introduction, the two parties being introduced; for a key rotation, the new operational key being announced. The _context_ field names the scope of the claim — for example, "verified in person at provisioning," "verified via video call with shared secret," or organizational tags such as "project: documentation work." Context is freeform rather than enumerated for the same forward-compatibility reason that capability scopes are open-ended in Section 5.1. The _strength_ field carries the issuer's confidence — a small ordinal, not a probability, because users will not produce calibrated probabilities under operational pressure. The _timestamp_ records when the issuer signed the operation, used in conflict resolution. The _expiry_ optionally bounds how long the operation remains active without reissuance; an unset expiry indicates the operation is intended to persist until explicitly revoked. The _prior-hash_ is a hash of the issuer's most recent prior operation against the same subject, forming a per-(issuer, subject) chain that lets receivers detect equivocation. The _signature_ is the operational identity's signature over the preceding seven fields, verifiable against the master-signed operational key recorded elsewhere in the graph.

**CRDT semantics.** The operation set is a conflict-free replicated data type: every well-formed operation is independently mergeable, the order of arrival does not affect the final state, and two clients that have seen the same set of operations compute the same view regardless of the path by which they received them. Where operations conflict — two attestations from the same issuer about the same subject with different content, for example — the conflict is resolved by signed timestamp, with the prior-hash chain providing the tiebreaker that detects equivocation attempts in which an issuer signs inconsistent operations at the same logical time. Operation types unknown to a client are retained verbatim and ignored for computation rather than rejected, preserving them for forwarding to peers that may understand them; this is one of the forward-compatibility design choices captured in Section 6.4 and is what permits later versions to extend the graph without invalidating older deployments.

**Propagation via the messaging layer.** Operations travel as metadata accompanying ordinary user-to-user traffic on the SimpleX and Briar channels users already have open. There is no separate trust-graph service, no graph-replication transport, and no project-operated infrastructure that propagation depends on — the same SimpleX queues that carry message content carry graph deltas, and Briar's peer-to-peer sessions exchange any operations the two endpoints have that the other does not. This satisfies the no-project-operated-infrastructure principle in Section 4.2: a Cairn deployment continues to function for its existing users if the project disappears, because nothing in the trust graph depends on the project being present.

**Local-only trust path computation.** Each client maintains its own CRDT view of the operations it has received, and trust paths are computed locally against that view at the moment they are needed. There is no canonical global graph and no authoritative answer to "is this party trusted." The answer is always relative to a specific user's view and a specific user's confidence threshold; different users will reach different conclusions about the same subject depending on which attestations they have seen and which issuers they themselves trust. This is the design's analog of the trust-graph property the project name evokes: a user follows the markers other travelers have left along their path, and a user with a different path sees a different sequence of markers.

**Sigsum transparency log integration.** Attestations and revocations are anchored in Sigsum (Section 3.4 trust root), which provides public, append-only auditability of the operations that have been issued. NGO partners and academic auditors — the same partner pool identified for release attestation in Section 5.5 — act as Sigsum witnesses, cosigning log state so that no single party can rewrite history undetectably. The log's role is detection, not prevention: a compromised operational key can issue malicious attestations, and the log will record them; the witnessed log state makes the malicious attestations publicly visible to auditors and to the user whose key was compromised, supporting subsequent revocation and rotation. Introductions and key rotations are also logged for the same audit purpose; the per-(issuer, subject) prior-hash chains in the log let external auditors detect equivocation patterns without participating in any specific user's trust computation.

**Cascade quarantine on revocation.** When a user revokes an attestation issued by a peer they have come to suspect, the downstream attestations that depended on that peer are soft-flagged rather than hard-suspended. A flagged attestation continues to exist in the graph and continues to be visible; what changes is that path computations involving it surface a warning, and the user can choose to re-attest the affected subject directly, accept the flagged path with explicit acknowledgment, or quarantine it entirely. The cascade is soft because hard suspension would convert one compromise into recursive blast-radius collapse — a single revocation against a well-connected peer would silently disable a large fraction of the graph, and users have no operational way to re-bootstrap that volume of trust. The soft-flag approach lets the user repair selectively, retaining the introductions that remain credible after independent verification while excising the ones that no longer are.

**Forced peer designation, partially mitigated.** Section 3.3 identifies forced peer designation at provisioning as an attack surface: a user under coercion at the moment of identity establishment may be made to designate peers chosen by an adversary. The trust graph's visible-attestation property is one of the limited mitigations available against this surface. Attestations are signed and logged, and downstream peers see them; an adversary-influenced peer who later begins issuing attestations or introductions inconsistent with the user's actual social graph produces signals that the user's other contacts can observe and act on. This does not prevent the initial compromise — the operational mitigations for that live in Section 5.3 — but it bounds how long an adversary-influenced peer can operate before their pattern of attestations exposes them. The same observability supports the Section 3.3 Recovery network surface concern: a recovery peer who issues unexpected attestations is producing public evidence of compromise that the user and their network can act on.

**Why this design rather than alternatives.** Several simpler or more conventional models were evaluated and rejected.

A _centralized PKI_ — a project-operated certificate authority issuing identity certificates against a project-controlled root — was rejected on two grounds. The CA is a single point of failure whose compromise or coercion breaks every identity it has signed, and operating it violates the no-project-operated-infrastructure principle (Section 4.2). The threat model in Section 3.2 explicitly assumes adversaries with the legal and extralegal capability to compel a project-operated CA; a design that places such an asset within the project is a design that has not honestly engaged with its own threat model.

_Blockchain-anchored attestations_ — recording each operation as a transaction on a public chain — were rejected on cost, metadata, and energy grounds. Each attestation, revocation, introduction, and rotation would produce a public transaction with timing and value metadata visible to chain analysts whose capabilities overlap meaningfully with the adversaries in Section 3.2. The economic cost of writing per-user operations to a public chain scales poorly to organizational use, the performance characteristics are wrong for the volume of operations the graph produces, and the energy footprint of proof-of-work chains is gratuitous given that the audit-trail need is fully met by Sigsum at a small fraction of the cost.

A _PGP-style web of trust without a transparency log_ was rejected on auditability grounds. The conceptual model of issued and revoked signatures over public keys is close to what Cairn does, but the lack of a transparency log means that revocations propagate unreliably, attestation reissuance is observationally indistinguishable from forgery, and external auditors have no anchor to compare any specific user's view against. The Sigsum integration is what converts the web-of-trust pattern from a folk practice into a design that supports public audit.

A _single-issuer hierarchical attestation_ model — every Cairn user attested to by one organization, that organization's signature serving as the trust anchor — was rejected because it couples the entire user base's trust to a single organization's continued operation and integrity. The project explicitly does not place itself in that role, and is not willing to ask a partner organization to assume it; the design intent is that trust originates in users' direct verification of each other, with partner organizations acting as witnesses and auditors rather than as gatekeepers.

**Storage and operational summary.** The local CRDT view is held in standard application storage, encrypted at rest by the device's full-disk-encryption key and gated by the user's passphrase along with the operational identity it depends on. The view is recoverable from device storage if the device is unlocked, which is appropriate — its content is the user's own observed history of public claims, not secret material. Signing of new operations uses the operational identity (Section 5.1), so a device whose operational key has been revoked cannot continue to issue graph operations. Verification of incoming operations is purely local, depends on no network reachability, and degrades gracefully: a client offline for an extended period continues to compute trust paths against the view it last had, and merges any newly-arrived operations whenever connectivity returns. Specific choices about which CRDT library and which Sigsum integration approach to use are deferred to the technical specification that follows this brief.

### 5.3 Recovery Model

The product splits the user's master Ed25519 identity using Shamir Secret Sharing at the provisioning ceremony (Section 5.1), distributes the shares among recovery peers, and reassembles the secret only at the two moments when its authority is needed: provisioning itself, and recovery from a fresh device. The recovery model specifies how that second moment works — how peers are designated, how the request reaches them, how the master is reconstructed under conditions that resist coercion, and what happens when the process fails.

**Threshold and parameters.** The default is 3-of-5 Shamir shares, configurable at provisioning. The default is chosen against two concrete failure modes that sit on opposite sides of the same parameter. A threshold lower than 3 makes coordinated coercion cheap: an adversary willing to compromise two peers can reconstruct the master, and small thresholds also let a single compromised peer plus a forged participation from one other reach the secret with thin verification. A threshold higher than 3 makes routine availability fragile: recovery already requires that the user reach a quorum from a fresh device under conditions where the user has just lost their primary identity, and every additional required peer multiplies the probability that someone is unreachable, traveling, deceased, or estranged. Three-of-five sits at the point where the adversary must compromise a majority of the user's chosen network rather than a minority, while the user can still recover after losing two peers to ordinary attrition. Users with unusual operational profiles — small trusted circles, or unusually high coercion risk against any single contact — can adjust at provisioning; the product surfaces the tradeoff explicitly rather than hiding it behind a default.

**Peer designation.** Recovery peers are chosen by the user from their existing contact list. The selection is not algorithmic. The product does not score contacts, does not recommend specific peers, and does not require any property of the chosen set — selection is the user's call because the relevant properties (who can be trusted to refuse pressure, who maintains operational discipline, who is geographically and socially distant from the user's other peers) are not legible to software. What the product does provide is decision support: at provisioning, it surfaces selection guidance covering geographic distribution (peers in different jurisdictions resist single-jurisdiction legal process), social distance (peers who do not all know each other resist single-introduction HUMINT compromise), and demonstrated ability to refuse coercion (peers with operational history, not new contacts). The v1 pilot's in-person provisioning ceremony is where this guidance is delivered effectively — a facilitator walks through the selection with the user, names the tradeoffs, and pushes back on poor choices. Broader deployments without trusted facilitators will deliver the guidance through documentation and in-app prompts, with weaker effect.

**Recovery flow.** Recovery begins on a fresh device, typically because the prior device was seized, lost, suspected compromised, or wiped after a coercion event (per [D0002](decisions/D0002-duress-profile.md) and Section 5.6). The user installs the application on the new device and initiates the recovery action, which reaches out to the designated peers through the messaging layer using the contact channels the peers and user established at provisioning. Each contacted peer receives a recovery request bound to the user's master public key, and verifies the request out of band before releasing their share. Out-of-band verification is essential and is not solely automated — the HUMINT surface (Section 3.3) means that an in-app prompt alone could be initiated by an adversary holding the user's seized device or by a social engineer who has reached the user's contacts. Peers are expected to contact the user through a separate channel — a voice call, a face-to-face meeting, a known-good account they recognize — to confirm that the user is the one requesting recovery and is doing so under conditions they control. Only after this confirmation does the peer release the share. When three shares have arrived, the master is reconstructed in local memory on the fresh device. A new operational keypair is generated in that device's hardware element and signed by the reconstructed master (per the rotation flow in Section 5.1); the prior operational identity is revoked through the trust graph, which propagates the revocation through the user's network and triggers the cascade quarantine described in Section 5.2. The reconstructed master is then immediately re-split using Shamir among the peer set — the same peers by default, or a revised set if the user chooses to rotate — and erased from active memory. The fresh device holds the new operational identity in its hardware element and never holds the master at rest.

**Fail-closed behavior.** If fewer than three peers respond, recovery fails. The partial shares that did arrive are discarded; nothing about the master is computable from any number of shares below the threshold, which is the foundational property of Shamir Secret Sharing and not a property the product layers on. The fresh device retains no recovery state across attempts — a subsequent attempt restarts the request flow rather than resuming with previously-received shares — so an adversary observing one failed attempt cannot accumulate shares across attempts toward the threshold. The failure is graceful, in the sense that no recovery state leaks, but it is a real failure: the user without a quorum of available peers has lost the identity.

**Fresh-identity path.** The alternative when recovery is not viable is to provision a fresh identity on the new device and re-enter the user's network through in-person re-introduction by an existing contact. The fresh identity carries no historical attestations, no message history, and no continuity with the prior identity from the perspective of the trust graph — the user is, cryptographically, a new participant whose first attestation is the re-introducing contact's signature. This path is preferable in two cases. The first is when the user has reason to suspect that recovery peers may themselves be compromised — for example, after a coercion event whose scope is unclear, where reconstructing the master could deliver it to an adversary watching the recovery request flow rather than to the user alone. The second is when too much time has passed and the shares are no longer trustworthy: peers may have lost their shares, replaced devices without preserving them, or themselves been compromised in the interim. Re-introduction accepts the loss of historical state in exchange for not depending on a peer network whose integrity cannot be assured at the moment recovery is needed.

**Recovery network surface.** The peer network designated for social recovery is itself a high-value target (Section 3.3, Recovery network surface). An adversary who identifies three of the user's peers and compromises them — through HUMINT, coercion, or device compromise — reconstructs the master without ever attacking the user directly. This is the architectural cost of refusing centralized trustees. The design does not pretend Shamir-among-peers is strictly superior to alternatives; it argues that Shamir-among-peers is the only model that does not require the user to trust an institution they cannot reach, audit, or hold accountable. The lever the user controls is peer selection, and the selection guidance above is the design's contribution. Two operational properties layer additional resistance: recovery peers are visible in the trust graph as a structural relationship (so the user's broader network can notice anomalies — a peer who begins behaving suspiciously, an attestation pattern that suggests pressure), and peers can be rotated post-provisioning by reconstructing the master and re-splitting to a revised peer set, so a peer designation made under poor conditions is not permanent.

**Forced peer designation surface.** The related but distinct risk that the user is coerced at the moment of provisioning to designate adversary-selected peers (Section 3.3, Forced peer designation surface) is mitigated through three layered operational properties. First, the v1 in-person provisioning ceremony, conducted with a known facilitator outside the adversary's presence, is the primary defense — coercion at the moment of provisioning becomes substantially harder when the ceremony itself is private. Second, the visibility of recovery peers in the trust graph means that anomalous peer designations — peers who do not appear in the user's normal communication patterns, peers chosen against stated selection guidance — are observable to the user's broader network. Third, the rotation property above allows the user to revise peer designations after provisioning, so a user who was coerced at the ceremony but later regains control can replace the imposed peer set. None of these closes the surface; the pilot's in-person ceremony reduces it meaningfully, and broader deployments will need to address it through ceremony design choices yet to be specified.

**Post-coercion response.** The recovery flow is the operational response to compelled unlock. Per [D0002](decisions/D0002-duress-profile.md), the product does not include a duress-profile concealment feature; the architectural answer to coercion is the tier separation already established in Section 5.1 (the master is not on the device to extract) combined with this recovery flow (the exposed operational identity is revoked and replaced). Section 5.6 surfaces the post-coercion recovery flow as a first-class in-app action rather than a setting buried in administration — the user who has just been through a seizure, a coerced unlock, or a suspected compromise reaches the recovery flow through a direct path, not by navigating settings under stress.

**Alternatives considered.**

A _trustee model with infrastructure in friendly jurisdictions_ — escrow of the master with M-of-N trustees operating from legally protected locations — was the initial design before the threat model was generalized. It was rejected because many of the users this product targets have no friendly jurisdiction they can reach: organizers in Myanmar, journalists in Iran, activists in Gaza cannot rely on infrastructure in Switzerland or Iceland to be operationally reachable, legally accountable to them, or culturally aligned with their work. The design refuses to assume access to a friendly jurisdiction because that assumption excludes the users with the highest stakes.

_Pure paper backup of the master key_ was rejected because it lacks graceful failure modes. A paper backup is lost, seized, photographed, or disposed of incorrectly, and the user has no signal that any of these has happened. It depends on indefinite user discipline — secure storage, awareness of when it has been compromised, the ability to retrieve it under the conditions in which recovery becomes necessary — that the threat tier this product addresses cannot rely on. Shamir among peers degrades predictably: the user knows whether they can reach three peers, and the trust graph surfaces the structural relationship of those peers to the rest of the network.

_Threshold cryptography for active operations_ — using a threshold scheme so that every master signature requires collaboration among peers in real time, rather than reconstructing the master only at recovery — was rejected for the reasons summarized in the Section 5.1 alternatives discussion. The master signs at provisioning, at operational-identity rotation, and at recovery; these are infrequent and ceremonial moments. Imposing threshold coordination on every such moment is workable but adds significant operational weight for the marginal property that the master is never reconstructed even briefly. Reconstruction-on-recovery accepts a brief window during which the master exists in active memory on the fresh device, in exchange for keeping the routine path simple and the protocol implementable at v1 scope. Threshold approaches remain a candidate for later exploration.

_Cloud-escrow with provider key custody_ — the master held by a commercial provider under contractual terms — is rejected, and rules out the entire class of provider-as-trustee architectures. Users in adversarial jurisdictions cannot rely on a provider to refuse cooperation with the legal process those jurisdictions can compel, cannot rely on a provider's continued operation across the time horizons their work requires, and cannot independently verify that the provider is holding the material under the terms claimed. This includes hardware-security-module-backed provider escrow, transparency-logged escrow, and multi-party-computation escrow with provider participation: the architectural rejection is of the provider trust relationship itself, not of the specific cryptographic construction. Social recovery is the alternative to this entire class of design, and the recovery network surface (Section 3.3) is the architectural cost of accepting that alternative.

### 5.4 Communications Protocols

The product carries two messaging protocols, not one, because the threat model spans a range of operational contexts that no single protocol covers well. Routine daily messaging needs an architecture that scales to the rhythm of normal communication — asynchronous delivery, queued messages, contact discovery without out-of-band coordination for every exchange. The highest-sensitivity exchanges need an architecture that gives up some of that convenience to eliminate the metadata-leak surface that any server-mediated system inherently presents. SimpleX and Briar are paired in v1 because each is the right tool for one of these regimes, and the operational choice between them is exposed to the user at the conversation level rather than dictated by the system.

**SimpleX as the primary spine.** SimpleX is the everyday messaging substrate. Its central architectural property is that there are no persistent user identifiers: queues are addressed cryptographically, the address of a queue is shared out-of-band when two users connect, and any given server sees only the messages routed through it rather than a user's broader contact graph. There is no account, no username, no phone number, no email address that ties activity together across servers — the identifier that links a user to a queue is a key, and the key is paired only with the specific recipient who needs to write to that queue. SimpleX's double-ratchet derivative provides forward secrecy for message content; queues are short-lived and rotatable; servers are self-hostable if a user or group prefers to operate their own, or can default to the SimpleX network's published relays.

For the threat model this addresses the Network and Metadata surfaces from Section 3.3 in specific ways. No persistent identifier means no obvious join key for traffic correlation across services or across time. Per-recipient queue addressing means no single server holds a roster of the user's contacts. Self-hostability means the project does not need to operate user-depended-on infrastructure and a user with elevated requirements can choose their own substrate without abandoning the protocol — consistent with the principle in Section 4.2 that no project-operated infrastructure is in the user's trust path.

SimpleX is not a complete answer. A user who connects multiple devices to the same set of queues creates correlatable activity at those queues regardless of how the identifiers are constructed. A server, whether operated by the SimpleX project, by a third party, or by the user themselves, can be coerced, compromised, or compelled to retain logs it would not retain in normal operation; the protocol limits what such a compromise yields, but does not reduce it to zero. The trust placed in the SimpleX protocol's cryptographic correctness is one of the trust roots named in Section 3.4, and the same residual risks named there — implementation flaws, protocol-level vulnerabilities not yet discovered — apply here.

**Briar as the highest-sensitivity tier.** Briar is the second protocol, scoped to conversations that warrant the heavier operational cost. Briar is pure peer-to-peer over Tor: there are no servers in the path, no queues, no infrastructure that a third party can compromise to gain visibility into the exchange. Two parties communicate directly, each running a Tor hidden service, the other party connecting to that hidden service over the Tor network. The cost is that direct messaging is synchronous in the strict sense — both parties must be online for messages to flow in real time. Briar provides an asynchronous mailbox capability over Tor that bounds the delay for offline recipients, but the design does not pretend this matches the always-on convenience of a queue-based service.

That cost is accepted explicitly. For conversations where eliminating server-mediated metadata is the dominant requirement — a journalist coordinating with a source, an activist communicating with someone whose name should not appear in any third party's logs even in aggregate form — the synchronous-rendezvous burden is the price paid for the stronger property. Briar's design has been refined over years of use by journalists and activists in hostile network environments and its operational track record is part of why it is selected as the second protocol rather than a custom implementation of similar properties.

Briar's limitations are also real. Both parties must run Tor; both parties must be running the Briar transport long enough for the exchange to occur; the Tor network itself is a trust root with the limits named in Section 3.4. The asynchronous mailbox does not eliminate the synchronous nature of the protocol, only smooths it; users who need fully asynchronous messaging at this sensitivity tier are better served by SimpleX with operational discipline around what is communicated.

**When each tier applies.** SimpleX is the default for every conversation. Briar is opt-in per-conversation, surfaced in the UI as the "extra-private mode" toggle described in Section 5.6. The choice is per-conversation rather than per-user-globally because the appropriate tier depends on the topic and the recipient, not on a property of the user as a whole — the same person may have a Briar conversation with a source and a SimpleX conversation with their editor, and the architecture treats these as orthogonal decisions. The toggle is a user choice rather than an algorithmic one because the product does not have visibility into which exchanges warrant the heavier protocol; that judgment belongs to the user and the people who support them.

**Tor as transport for both.** Both protocols run over Tor. Tor's role is named explicitly as a trust root in Section 3.4 with its known limitations against global passive adversaries, and that framing carries over here. Tor complicates traffic analysis and network-level surveillance for the threat tier without claiming to eliminate them. For jurisdictions where Tor itself is subject to DPI fingerprinting and active blocking, the architecture accommodates pluggable transports — obfs4, meek, or whichever transport is operationally appropriate at the time of deployment. Specific transport selection is operational rather than architectural and is deferred to the system design spec; the commitment at this level is that the transport layer is replaceable without disturbing the protocols above it.

**Push notifications.** GrapheneOS does not ship with Google Play Services and the product does not depend on them. Push delivery requires a mechanism that operates without that dependency, and the architectural commitment is to a protocol with no required external service the project does not control. UnifiedPush is the current leading candidate as a self-hostable open protocol that meets this constraint; specific distributor selection is deferred to the system design spec. The metadata implications of push are acknowledged: a push server, whichever protocol it implements, sees the timing of notifications delivered to a user even when it cannot see the content, and this is itself metadata of the kind named in Section 3.3. The architecture must accommodate users who prefer to disable push entirely and rely on polling at intervals they control, accepting the battery and latency cost in exchange for one fewer party seeing arrival timing.

**Voice and video.** SimpleX supports voice and video calling natively. Inclusion in v1 is contingent on time during the implementation period; the architecture preserves the slot but the feature is treated as a v1.x or v2 candidate per Section 6.2 rather than a v1 commitment. The protocol-versioning framework described in Section 6.4 accommodates this kind of incremental capability addition without forcing a client-wide migration.

**Alternatives considered.** The two-protocol selection was made against a survey of the available landscape, and several alternatives were rejected with specific reasoning.

_Matrix and the Element client_ were rejected as the primary protocol. The Matrix federation model requires every user to trust their homeserver or to operate one; homeservers see all of their users' traffic; cross-server federation makes the metadata surface larger rather than smaller. Cross-ref Section 4.2: no project-operated infrastructure should be user-depended-on, and the Matrix federation model effectively pushes that infrastructure responsibility onto every user or onto a per-user choice of trusted operator. The complexity of the federation protocol is also a real cost for a security-focused project — more surface to audit, more surface to defend.

_Signal_ was rejected despite the strength of the Signal Protocol itself. Phone number registration is a non-starter for the target audience: the phone number is a tracking vector, a registration leak surface, and a forcing function for ties to telco infrastructure that the threat model treats as compromised. Signal's centralized architecture introduces operational dependence on the Signal Foundation, which is a single party that can be pressured, subpoenaed, or fail. The protocol itself remains a reference for forward-secrecy construction; the deployment model is the disqualifying factor.

_Session_ was rejected on multiple grounds. The Session Network — the protocol's transport substrate — is an external dependency the project does not control and whose long-term operational trajectory is uncertain. The cryptographic stack is a fork of the Signal Protocol with changes that have drawn scrutiny, and the protocol's evolution is determined by the Session project on a timeline that may not align with the security posture this product needs to maintain.

_Wickr_ was rejected. Concentration risk is the primary concern: Wickr is AWS-owned, and the threat tier this product addresses includes adversaries with both legal and extralegal means to apply pressure to a large cloud provider operating under a specific jurisdiction's legal framework. Wickr's enterprise focus is also a poor match for the grassroots audience, and the auditability available for Wickr does not match what open-source projects like SimpleX and Briar provide.

_Cwtch_ was considered as an alternative to Briar in the highest-sensitivity tier. Its properties — peer-to-peer over Tor, no servers, designed for the same threat tier as Briar — are similar enough that the choice is closer than the others. Briar is selected for v1 on the basis of its longer operational track record, its existing relationships with NGO partners likely to be involved in pilot facilitation, and the larger body of deployed experience among the target user population. Cwtch remains a candidate for future evaluation and the integration shape is similar enough that a switch is not architecturally costly if later experience favors it.

_A custom protocol_ was considered and rejected for the obvious reasons. The protocols this product needs are solved problems with implementations under active audit; building a new one would multiply the audit burden, place the project in the path of protocol-level cryptanalytic scrutiny it is not staffed to absorb, and lose the cumulative review effort that SimpleX and Briar have already received. The project's contribution is integration, identity, trust graph, and operational discipline — the layer above the protocols — and the protocols themselves are correctly delegated to projects whose mission is to build and maintain them.

### 5.5 Updates and Release Security

Software updates are among the most consequential attack surfaces this product exposes (Section 3.3, Update channel surface). A single malicious release reaches every user who installs it, and an adversary who can produce one indistinguishable from a legitimate release has accomplished, in one step, what they would otherwise have to accomplish per-device. The defense is structural: no single credential, no single party, and no single distribution channel is trusted to assert that a release is genuine. A release is genuine when its provenance is independently visible — to the developer, to a pool of external reviewers, and to anyone who chooses to check the public record after the fact.

**Sigstore identity-based signing.** Releases are signed with Sigstore. The developer does not hold a long-lived signing key. Instead, each release is signed with a fresh keypair generated for that release and bound to a verified identity — the developer's OIDC-authenticated email or equivalent — through Sigstore's Fulcio certificate authority. The certificate is short-lived; the keypair is discarded after signing. The signing event itself, including the certificate and the artifact digest, is recorded in Sigstore's Rekor transparency log at the moment of issuance. The security property this produces is that there is no master signing key for an adversary to steal, no signing credential that persists between releases, and no signing event that occurs invisibly. Compromise of a signing event affects exactly the release it signed, and the compromise is visible in Rekor regardless of whether anyone is watching at that moment.

**Reproducible builds.** The build is deterministic: the same source tree, processed by the same toolchain configuration, produces a byte-identical output artifact. Build reproducibility is a property the project commits to maintain across versions, not a one-time achievement — it is verified continuously during development, not measured retroactively at release. The implication for security is that the binary the developer signs and the binary produced by an independent build from the same source can be compared directly. Divergence is a finding. A build pipeline that has been compromised to inject malicious code cannot ship that code without producing a binary that disagrees with every clean independent build, and disagreement is what reviewers are looking for.

**External reviewer pool.** Two to three reviewers, independent of the developer and of each other, rebuild every release from source and publish signed attestations that their binary matches the developer's signed artifact. Reviewers are not contributors and do not write code; their function is to be a second and third pair of eyes on the build product, with no incentive aligned with shipping. Their attestations are recorded in the Sigsum transparency log — the same minimum-trust witness-cosignature log that anchors the trust graph (Section 3.4, Sigsum trust root), reused here so that the audit surface is unified rather than fragmented across multiple logs. A user verifying a release checks the developer's Sigstore signature against Rekor and the reviewer attestations against Sigsum; either alone is insufficient. The reviewer pool is the operational answer to the question "what if the developer's identity is compromised but the developer does not know it." Reviewers rebuilding from the public source will not reproduce a binary that incorporates a hidden modification injected through the developer's signing path, and the discrepancy becomes a public artifact in Sigsum.

**Public transparency log of releases.** Every signed release artifact and every reviewer attestation is logged. A release that does not appear in the log is not a release; the client refuses to install it. This is what closes the targeted-attack surface as much as it can be closed at this layer: an adversary cannot deliver a signed update to a single user out-of-band, because that user's client will not find the corresponding Sigsum entry and will reject the artifact. Witnesses — the same NGO and academic partners that cosign the trust-graph log state — cosign the release log state, so log tampering by the log operator is itself detectable. The detection mechanism is not prevention; an adversary willing to burn a signing identity to attack one user can produce a logged-but-malicious release, and that compromise affects however many users install it before reviewers and witnesses catch the anomaly. The transparency log makes the timeline of any such event auditable after the fact, which is the property the design optimizes for.

**Rollback resistance.** Version numbers in signed release metadata are monotonic, and the client refuses to install a release whose version is lower than the highest version it has previously installed. An adversary in possession of an older signed release — for example, one that was legitimate at the time but contains a since-patched vulnerability — cannot use that artifact's still-valid signature to downgrade a user back into the vulnerable state. This is a small property with a large operational effect: it means the security guarantees of an update are not undone by the mere existence of older legitimate artifacts.

**Multi-channel distribution.** The same signed artifacts are distributed through F-Droid (and Accrescent, as that platform matures), GitHub releases, a Tor onion service operated by the project, and offline signed images suitable for hand-delivery in environments where any single channel is blocked or surveilled. Multi-channel distribution does not change what is being delivered — every channel carries the same Sigstore-signed, Sigsum-logged artifact — but it lets users cross-check what they received against what other users received, and protects against channel-specific blocking by adversaries with the ability to interdict particular routes. Pilot users in jurisdictions where F-Droid is blocked obtain releases through Tor or offline images without any change in the verification path.

**Mitigation summary for Section 3.3 surfaces.** The stack described above is the product's primary defense against the Update channel attack surface named in Section 3.3, and a significant component of the defense against the Distribution and supply-chain surface. For the update channel: a malicious update cannot ship without producing artifacts in Rekor and Sigsum that diverge from independent reviewer attestations, and a targeted update cannot ship at all because the client requires the log entry. For the supply-chain surface: the pilot's developer-as-supply-chain risk reduces as reproducible builds and reviewer attestations make the developer's local build no longer the sole assertion of what the binary contains. What this defense does not address: a coordinated compromise of the developer's signing identity and enough reviewer identities to issue concurring false attestations; a targeted attack delivered through a distribution channel the project has not detected as compromised; and users who do not verify reviewer attestations at install time. The pilot's device-preparation workflow — the developer installing GrapheneOS and the application before handing over the device — remains a trust placement separate from the release-security stack, narrowed but not eliminated by these mechanisms.

**Signing identity compromise plan.** If the developer's Sigstore identity is compromised, the response sequence is pre-staged: the developer publishes a revocation through an out-of-band channel established at project start (a signed announcement through partner organization channels, with the verification key separately held); the reviewer pool refuses to issue further attestations against releases signed by the compromised identity; the project transitions to a new identity, with the transition itself attested by reviewers and recorded in Sigsum. Because every signing event was already logged in Rekor, the timeline of the compromise — when the identity began signing, when it stopped being controlled by the developer, when the revocation was published — is reconstructable after the fact rather than being a matter of internal claim. This compromise-recovery property is one of the structural reasons identity-based signing was chosen over a long-lived developer key, where compromise would yield no comparable forensic record.

**Alternatives considered.**

_The Update Framework (TUF)._ TUF is the gold-standard general-purpose secure-update framework, with a sophisticated role-and-threshold model — root, targets, snapshot, timestamp roles, each with their own key sets and rotation policies, and threshold-signature support across roles. At Cairn's solo-developer scale, the operational complexity of TUF (key ceremonies, role hierarchies, threshold signature management, periodic role rotation) exceeds what one developer can maintain rigorously over time, and an inconsistently-maintained TUF deployment is worse than a consistently-maintained simpler stack. The Sigstore-plus-reproducible-builds-plus-reviewer-attestations combination captures most of TUF's relevant security properties — no long-lived signing key, transparency log of all signing events, multiple-party verification of release contents — at substantially lower operational cost. TUF remains a candidate for re-evaluation post-v1 if project scale grows enough to justify the operational overhead, or if specific TUF properties (key threshold management, formal role separation) become operationally relevant.

_Custom multi-signature scheme._ A bespoke release-signing system was considered and rejected. The scrutiny budget applied to Sigstore — public audit, broad adoption across the open-source ecosystem, ongoing maintenance by a multi-party foundation — exceeds anything a solo developer could replicate. No specific gap was identified that a custom scheme would close better than the chosen stack. The general engineering principle (Section 3.4 trust-roots framing: trust widely-deployed analyzed primitives, do not invent) applies straightforwardly here.

_Single developer key with long lifetime._ The status quo for many small projects: a single PGP or similar long-lived signing key, used across all releases over a span of years. This is rejected because a long-lived signing key is exactly the kind of credential nation-state adversaries target most heavily, and a single compromise yields the ability to sign every future release indistinguishably from the developer. The structural answer to "what if my key is stolen" is to not have a key to steal — short-lived signing identities, with the signing event itself anchored in a transparency log, leave no persistent credential as a target.

_No update mechanism — manual rebuild only._ Considered and rejected. Sustainable security requires updates: vulnerabilities are discovered, dependencies change, the threat landscape moves. The question is not whether to ship updates but how to ship them with the integrity properties this threat model demands. A no-updates posture is itself a security failure mode over the project's operating timeline.

The release-security stack is one component of the broader assurance program described in Section 8.2 (Release security operational practice) and Section 8.5 (Audit and assurance), which together specify how the project's security posture is maintained over the project's lifetime rather than asserted once at v1 release.

### 5.6 UX Principles

The product's interaction language is deliberately conventional. The threat model already costs the user something by being visible: a Pixel running GrapheneOS, a Tor-shaped network footprint, an installed application whose presence is itself observable (Section 3.3, Tool-use surface). Forcing the user to learn a novel messaging idiom on top of that visibility compounds friction with no defensive payoff — and friction in security software translates directly to operational mistakes. The design's working assumption is that the interesting cryptographic and trust-graph work belongs behind a surface the user already knows how to operate, not in front of it.

**Signal-familiar surface.** Threads, contact list, voice notes, attachments, group chats. A user coming from Signal, WhatsApp, or any mainstream messenger should recognize the layout, the gestures, and the mental model on first launch without orientation. This is not a UX taste preference; it is a security property. Every minute spent learning where a button lives is a minute not spent on operational discipline, and every novel interaction is a place where a user, under stress, will guess wrong. The interesting design work in this product happens in the layers behind the chat surface — the identity tiers (5.1), the trust graph (5.2), the recovery model (5.3), the protocol selection between SimpleX and Briar (5.4) — and surfaces only where the user must make an informed choice. The conventional foreground is what makes the unconventional background tolerable.

**Subtle trust signals.** Trust-graph state — verification status on a contact, freshness of an attestation chain, the soft-quarantine flag from a cascading revocation (5.2) — is conveyed through small, consistent visual cues attached to the entities they describe. A contact row carries its verification badge; an attestation chain is drillable from the contact detail; a revocation flag appears against the contact and the conversations that depend on it. The badges are visible enough to be findable when the user wants them and quiet enough not to dominate the chat surface during normal use. This is a deliberate middle ground. Hiding trust signals entirely would remove the user's ability to verify state and to notice anomalies — the trust graph would still function, but the user could not see when it had something to say. Surfacing trust signals as continual notifications would train the user to dismiss them, which the literature on security warning fatigue consistently demonstrates degrades engagement with security UI rather than improving it. Information on demand, attached to the entity it describes, is the target.

**Invisible profile compartmentation.** Multi-profile support exists in the architecture (per-jurisdiction, per-role, per-organization), but the UI does not advertise it to users who do not engage with it. A user with one identity sees a single-identity application: no profile switcher, no chrome implying that switching exists. A user with multiple profiles sees the switcher, and it appears in a familiar idiom (an account-style affordance, not a novel construct). The profile model is opt-in at the level of UI surface as well as at the level of operational use. This matters because telegraphing the existence of multiple profiles to users who have only one — and, by extension, to anyone examining their device — would create an inferred question (where are the other profiles?) that the architecture does not need to answer.

**Extra-private mode as a labeled toggle.** Per-conversation, the user can elevate from the SimpleX channel to the Briar channel (5.4). The control is labeled in plain language — "extra-private" rather than "Briar over Tor" — and a tooltip surfaces the cost honestly: both parties must be online simultaneously, message delivery is slower, attachments are constrained. The user is not asked to know what Briar is; the user is asked to weigh a stated tradeoff. The protocol choice is the user's, but the framing is the design's, and the framing is the part that determines whether the choice gets made well.

**Compelled-unlock guidance as a first-class action.** Per Decision [D0002](decisions/D0002-duress-profile.md), the product does not include duress-profile concealment in v1 or any planned version. The architectural answer to compelled unlock is tier separation (5.1): the master identity is Shamir-split among recovery peers and is not present on the device, so even full coerced unlock does not yield the master, the ability to issue master-level attestations, or the recovery shares themselves. What unlock yields is the operational identity, the on-device message history, and the contact list — bounded, not unbounded, exposure. The UX corollary is that the post-coercion recovery flow is surfaced as a top-level option in the security/recovery menu, not buried under advanced settings. The flow walks the user through revoking the exposed operational identity through the trust graph, contacting recovery peers, reconstructing the master, and reissuing a new operational identity signed by the restored master. Documentation accompanying the flow explains why no duress concealment is offered — that detected concealment is itself prosecutable in compelled-decryption jurisdictions, and that the tier model already does the protective work concealment aspires to — so that the user understands the design's commitment rather than experiencing it as a missing feature.

**Recovery accessible without cryptographic literacy.** Two recovery paths are exposed in plain language. The primary path is Shamir-based social recovery: "contact three of the people you designated when you set this up, and they each give you a code that puts your identity back together." The secondary path is fresh identity with in-person reintroduction by an existing contact, accepting the loss of historical state: "start over with a new identity and let someone who already knows you vouch for it." The user is told what each path does and what each path costs — the second loses message history and prior attestations — without being asked to understand threshold cryptography. The user's job is to choose; the product's job is to make the consequences of each choice legible.

**Honest communication of limitations.** Where a security claim has limits, the UI says so. Verification status is rendered as "verified through chain of attestations" rather than "secure"; encryption status is "encrypted end-to-end via SimpleX" rather than "unbreakable"; Tor transport is "routed through Tor (resists most network observers)" rather than "anonymous." The intent is calibration. A user who understands the actual shape of the protection — what it covers, what it doesn't — makes better operational decisions than a user who has been told the product is secure full stop. Section 3 specifies what the threat model does and does not cover; the UI's job is to keep that calibration present in daily use rather than letting it decay into the misplaced confidence that absolute-sounding labels produce.

**Defaults over configuration.** The threat model does not assume the user is a security expert (3.1, audience note: the model assumes the user's support network understands the tradeoffs on the user's behalf). Security-relevant decisions are accordingly made by the design as defaults rather than presented as user choices. Where a user must choose — recovery peers, profile compartmentation, extra-private mode — the choice is staged with explicit consequences and a recommended default that fits the v1 audience. A misconfigured user is more vulnerable than a default-configured one, and a configuration surface broad enough to accommodate every expert preference is also broad enough to accommodate every novice mistake. The product errs toward the latter risk.

**Onboarding via facilitator.** First-run is structured around the v1 pilot model: in-person provisioning conducted by a trained facilitator who is present with the user during the ceremony. The provisioning ceremony, recovery peer designation, initial profile creation, and trust-graph seeding are walked through together. This is consistent with the threat-model audience note (3.1): the people who understand the tradeoffs are the facilitators, not necessarily the users, and the onboarding flow is designed so the facilitator's presence is the unit of operational discipline. The flow is architected to extend to remote onboarding in later versions, but v1 does not pretend to a self-serve onboarding it cannot yet support safely.

**Alternatives considered.** The UX philosophy was weighed against several alternative orientations.

A power-user surface exposing the full configuration space — protocol selection per message, signing-key visibility, capability-token scope editing, transparency-log inspection — was rejected. The orientation conflicts directly with the v1 audience: users who lack the context to make these decisions well would be asked to make them anyway, and the configuration surface itself widens the attack surface. A misconfigured user is more exposed than a default-configured one, and a UI that invites misconfiguration is a UI that produces it.

Aggressive security nudges and warnings — modal verification prompts before sensitive sends, repeated reminders to verify contacts, persistent banners on unverified conversations — were rejected on evidence. The published literature on security warning fatigue is consistent across browser-certificate warnings, OS permission prompts, and enterprise-software security dialogs: continual prompting trains users to dismiss security UI rather than engage with it, and the dismissal generalizes to the prompts that actually matter. The product's approach is information-on-demand rather than continual notification: trust state is always findable, never insistent.

Hiding the security surface entirely — no badges, no verification indicators, no visible trust-graph state — was rejected on the opposite ground. It would remove the user's ability to verify trust state and to notice when something has changed. A revoked contact, a stale attestation, a quarantine flag from a cascading revocation: each is information the user needs to act on, and a UI that hides it has decided on the user's behalf that they do not need to know. The subtle-but-consistent badge model is the deliberate middle ground between nag and silence.

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
- Duress-wipe pattern (v1.5; no duress-profile concealment in any planned version — see [D0002](../decisions/D0002-duress-profile.md))

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
- v1.5 (6 months post-v1): iteration on pilot feedback, UX refinements, duress-wipe pattern (per [D0002](../decisions/D0002-duress-profile.md)), possible voice/video, possible expanded localization
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
