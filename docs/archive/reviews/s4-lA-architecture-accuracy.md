# §4 — Architecture Summary Accuracy Lens

## Summary

§4 overstates several architectural commitments relative to what §5 actually
specifies, and elides a v1/v1.5 distinction that §5 repeatedly stages. The
most consequential mismatches are: (a) §4 names Briar as part of the
"communications layer" (§4.1 line 250) when §5.4 line 436 is explicit that
v1 ships SimpleX-only and Briar is v1.5; (b) §4.1's bullet on the trust graph
(line 253) says the graph "propagates attestations, revocations,
introductions, and key rotations" — only four operation types, where §5.2
specifies five (line 345: attestation, attestation withdrawal, key compromise
revocation, introduction, key rotation), collapsing the very distinction
[D0006] introduces; and (c) §4.1 line 255 mentions "two-layer signing" but
omits the source-review-vs-reproducible-builds v1→v1.5 transition that
§5.5 line 482 treats as central to release security. The pattern: §4 elides
v1.5 deferrals and conflates operations §5 carefully splits, leaving the
first-time reader with a v1.5-or-later mental model rather than a v1 one.

## Critical findings

### F1: §4.1 lists Briar in the v1 "communications layer" mental model

- **Evidence:** §4.1 line 250 (`design-brief.md:250`):
  "**Communications layer.** SimpleX is the v1 messaging substrate ... Briar
  joins as the highest-sensitivity tier in v1.5." But the bullet at line 248
  prior says "v1 ships SimpleX messaging over Tor; v1.5 adds Briar," and the
  layer-header subtitle treats the communications layer as inclusive of both
  ("**Communications layer.** SimpleX is the v1 messaging substrate...
  Briar joins as the highest-sensitivity tier in v1.5. Above the messaging
  protocols..."). The reader who scans the three-layer block (242–256)
  forms a mental model in which the communications layer has two protocols.
  §5.4 line 436 is unambiguous: "v1 ships SimpleX-only; Briar integration is
  deferred to v1.5 per D0004 ... **For v1, users have one messaging tier**;
  the highest-sensitivity-tier discipline is exercised operationally (what
  is and is not said over SimpleX) rather than mechanically (toggling into
  Briar). The two-tier architecture returns in v1.5."
- **Impact:** A reader using §4 as their architecture summary will believe
  Cairn ships a two-tier messaging stack with operational tier selection at
  v1. §5.4's explicit "users have one messaging tier" is a meaningful scope
  reduction that §4 buries inside a clause. Funders and reviewers may
  evaluate Cairn against a multi-protocol commitment Cairn does not yet make.
- **Recommendation:** Revise §4.1 line 250 to lead with "v1 ships SimpleX
  over Tor only; Briar is a v1.5 commitment with the architectural slot
  preserved" before describing what Briar will add. Mirror §5.4 line 448's
  "In v1, sensitivity tiering is operational rather than mechanical" so the
  v1 reader doesn't infer a per-protocol tier selector.

### F2: §4.1 lists four trust-graph operation types; §5.2 specifies five

- **Evidence:** §4.1 line 253 (`design-brief.md:253`):
  "The cryptographic trust graph (Section 5.2) that propagates
  **attestations, revocations, introductions, and key rotations** across the
  user's social network..." (four named types). §5.2 line 345
  (`design-brief.md:345`): "**Five operation types.** ... An _attestation_
  asserts ... **Attestation withdrawal** retracts the issuer's endorsement
  ... **Key compromise revocation** declares that an operational key was
  used outside the user's control ... An **introduction** records ... A
  **key rotation** announces..." §5.2 line 352 calls out that "The split
  between withdrawal and compromise revocation is specified in D0006 and
  addresses the cascade-laundering attack identified in the Section 5
  adversarial review."
- **Impact:** §4 collapses two operations §5 explicitly keeps separate. The
  split is not editorial — it is the architectural fix for the cascade
  laundering attack and the basis of the soft-vs-hard quarantine semantics
  in §5.2 lines 374–380. A reader who internalizes §4's four-operation
  model will not understand why §5.2 has two distinct cascade behaviors.
  This is the exact "claim invention vs. understatement" failure mode in the
  lens brief: §4 understates what §5 actually does.
- **Recommendation:** Rewrite §4.1 line 253's enumeration to "attestations,
  attestation withdrawals, key-compromise revocations, introductions, and
  key rotations" — five operations, matching §5.2 line 345 — and add a
  half-sentence noting the withdrawal/compromise split closes a specific
  cascade-laundering attack (per D0006).

### F3: §4.1 omits the v1 source-review vs. v1.5 reproducible-builds transition

- **Evidence:** §4.1 line 255 (`design-brief.md:255`):
  "The release-security stack (Section 5.5): two-layer signing (long-lived
  APK key plus per-release Sigstore attestation), external reviewer pool of
  5+ with 3-of-5 attestation threshold, multi-channel distribution." §5.5
  line 482 (`design-brief.md:482`): "**External source-code review in v1;
  reproducible builds in v1.5.** v1 ships with external source-code review
  — reviewers read the source tree corresponding to each release and
  publish signed attestations that they have done so. ... Reproducible
  builds ... are deferred to v1.5 per D0004." §5.5 line 496 further states
  "For the supply-chain surface in v1: reviewer attestations are over source
  code, which means a compromised build pipeline that produced a malicious
  binary from the same source would not be detected by source-review alone.
  v1.5 closes this gap..."
- **Impact:** §4.1's release-security summary names the reviewer pool and
  threshold but not the reviewer activity. A first-time reader will assume
  reviewers verify binary/build artifacts (the modern default for projects
  that brand "reproducible builds"). §5.5 explicitly carves out a v1
  supply-chain gap that v1.5 closes — a material limitation that affects
  how partners and pilot users evaluate v1 release security.
- **Recommendation:** Add "v1 reviewers attest to source review; v1.5
  transitions to reproducible-build binary equivalence" to the §4.1 line 255
  release-security bullet. Without this, §4 overstates v1 supply-chain
  defense.

### F4: §4.1 implies hardware-anchored operational identity uniformly; §5.1 says StrongBox-or-TEE depending on Pixel generation

- **Evidence:** §4.1 line 246 (`design-brief.md:246`) does qualify
  ("StrongBox-backed hardware element where Ed25519 is supported on the
  target Pixel generation, TEE-backed otherwise"), which matches §5.1 line
  307 ("on Pixel devices, the StrongBox security level backed by the Titan
  M2 secure element where Ed25519 is supported on the target Pixel
  generation, TEE-backed otherwise"). However, §4.2 line 269 collapses this
  to "the operational identity is hardware-gated and rotatable," and §4.1
  line 257 to "the operational identity is hardware-gated and rotatable." §5
  is consistent that the hardware-element property has a meaningful split
  between StrongBox (a discrete secure element, Titan M2) and TEE (in the
  application processor) — these have materially different threat
  properties.
- **Impact:** Less critical than F1–F3 because §4.1 line 246 does qualify
  correctly, but the principles section (§4.2) and the integration summary
  (§4.1 line 257) flatten the qualification. A reader who only reads the
  principles/summary will assume uniform StrongBox guarantees.
- **Recommendation:** Either (a) add "where supported, otherwise TEE-backed"
  to §4.2 line 269's hardware-gated mention, or (b) at minimum make §4.1
  line 257 read "the operational identity is hardware-element-gated
  (StrongBox where Ed25519-supported, TEE-backed otherwise)" so the
  qualification doesn't disappear between line 246 and the layer summary.

## Significant findings

### F5: §4.1 line 246 says "device-scoped capability tokens that authorize specific operations"; §5.1 specifies a richer claim set than §4 suggests

- **Evidence:** §4.1 line 246 (`design-brief.md:246`): "the device-scoped
  capability tokens that authorize specific operations." §5.1 line 317
  (`design-brief.md:317`) specifies tokens as `COSE_Sign1`/CBOR structures
  with issuer, subject, "a set of scope strings (`messaging-send`,
  `trust-graph-attest`, `recovery-receive`, and so on), a validity period
  typically measured in hours to days rather than weeks, and the operational
  identity's signature." §5.1 line 319 also notes "The scope vocabulary is
  intentionally not fixed at v1 — capability tokens carry arbitrary scope
  strings rather than a closed enumeration" — a forward-compatibility
  property §4 does not name.
- **Impact:** Modest. §4 omits the scope-string extensibility and the
  short-lived/renewable property. The short-lived property is what makes
  device-token theft bounded (§5.1 line 321: "a compromised device cannot,
  by holding its current token, exceed the permissions that token explicitly
  granted"). Readers who only see §4 don't know capability tokens are
  short-lived and renewable.
- **Recommendation:** Add to §4.1 line 246's description: "tokens are
  short-lived (hours to days), scope-bounded, and renewable from the
  operational identity, so a compromised device's authority lapses at
  expiration without master involvement."

### F6: §4.1 line 254 calls recovery "Shamir-based social recovery" but does not surface the 3-of-5 threshold §5.3 specifies as the v1 default

- **Evidence:** §4.1 line 254 (`design-brief.md:254`): "The Shamir-based
  social recovery model (Section 5.3) that lets the user recover identity
  without centralized trustees, with peer-verification mechanisms —
  pre-shared challenges and a 48-hour cooling-off window per D0005 — that
  defeat impersonation attacks." §5.3 line 400 (`design-brief.md:400`):
  "**Threshold and parameters.** The default is 3-of-5 Shamir shares,
  configurable at provisioning." The 3-of-5 parameter is identical to the
  reviewer 3-of-5 in §5.5 — and §5.5 line 484 explicitly says "the 3-of-5
  threshold **mirrors the Shamir parameter in 5.3**." §4 names the 5+/3-of-5
  reviewer threshold (line 255) but not the matching 3-of-5/5 recovery
  threshold.
- **Impact:** Numerical asymmetry. The brief deliberately mirrors thresholds
  across two different domains; §4 surfaces one and hides the other. A
  reader does not see the parallelism the design intends.
- **Recommendation:** Add "(3-of-5 default, configurable at provisioning)"
  to §4.1 line 254 after "Shamir-based social recovery" so the threshold is
  visible at the architectural-summary level. Doing so also makes the
  parallelism with §4.1 line 255's reviewer threshold legible.

### F7: §4.1 line 257 claims "messaging metadata is minimized at the protocol layer"; §5.4 is much more qualified

- **Evidence:** §4.1 line 257 (`design-brief.md:257`): "messaging metadata
  is minimized at the protocol layer." §5.4 line 442 (`design-brief.md:442`):
  "SimpleX is not a complete answer. A user who connects multiple devices to
  the same set of queues creates correlatable activity at those queues
  regardless of how the identifiers are constructed. A server, whether
  operated by the SimpleX project, by a third party, or by the user
  themselves, can be coerced, compromised, or compelled to retain logs..."
  §5.4 line 456 on push: "a push distributor, whichever protocol it
  implements, sees the timing of notifications delivered to a user even when
  it cannot see the content, and this is itself metadata of the kind named
  in Section 3.3."
- **Impact:** §4's "minimized at the protocol layer" is a clean,
  audience-accessible summary, but §5.4 explicitly names server-coercion,
  self-hosted-server log retention, and push timing as metadata leaks the
  protocol does not minimize. The §4 phrasing approaches the "calibrated
  language" failure §4.2 line 273 itself warns against ("'verified through
  chain of attestations' rather than 'secure'").
- **Recommendation:** Soften to "messaging metadata is minimized **at the
  protocol layer subject to specific residual leaks named in §5.4** (server
  coercion, multi-device queue correlation, push timing)." This matches
  §4.2's stated calibration principle.

### F8: §4.1 line 257 claims master is "never on the device in routine operation"; §5.1 also says this but specifies a bounded-window exposure that §4 omits

- **Evidence:** §4.1 line 257 (`design-brief.md:257`): "the user's master
  identity is never on the device in routine operation." §5.1 line 305
  (`design-brief.md:305`): "**Bounded-window exposure, not zero exposure.**
  The reconstruction window itself is the master's exposure surface: the
  seed exists in active memory during provisioning and recovery, and any
  forensic implant resident on the device at those moments can capture it
  (see Section 3.3 Returned-after-seizure surface)." §4.2 line 269 does say
  "bounded-window exposure, not zero exposure" — but only for tier
  separation generally, and the line-257 layer summary phrasing is the
  cleaner, more memorable one.
- **Impact:** "Never on the device in routine operation" is technically
  accurate (provisioning and recovery aren't "routine operation"), but the
  framing optimizes the reader's takeaway toward a stronger claim than §5.1
  supports. §5.1 specifically frames provisioning and recovery as
  exposure-window moments that need GrapheneOS-verified-boot defense and
  fresh-device guidance — a meaningful operational property §4 elides.
- **Recommendation:** Append "(provisioning and recovery are
  bounded-window exposure moments; see §5.1)" to §4.1 line 257's
  master-not-on-device claim, so the layer summary doesn't read as
  zero-exposure.

### F9: §4.1 line 248 claims pluggable transports as "an ongoing engineering commitment"; §5.4 specifies a starker operational consequence

- **Evidence:** §4.1 line 248 (`design-brief.md:248`): "Pluggable-transport
  selection is an ongoing engineering commitment rather than a one-time
  decision — DPI evasion is a continuously-being-solved problem (Section
  5.4)." §5.4 line 454 (`design-brief.md:454`): "the practical implication
  is that **users in DPI jurisdictions are offline when an active transport
  is blocked**, until an updated transport propagates through reviewer
  attestation and installation."
- **Impact:** §4 frames the transport story as a commitment to ongoing
  work; §5.4 names the user-visible consequence — pilot users will go dark
  during transport-block events for as long as a new transport takes to ship
  through the 3-of-5 reviewer pipeline. This is a material operational
  property: the reviewer pipeline (§5.5) is the gating mechanism for
  transport updates.
- **Recommendation:** Add to §4.1 line 248: "with the operational
  consequence that users in DPI jurisdictions are offline during active
  blocks until a transport update propagates through the reviewer pipeline."
  This also links the transport story to the release-security story §4 keeps
  separate.

## Minor findings

### F10: §4.1 line 246 names "the device's StrongBox-backed hardware element where Ed25519 is supported"; §5.1 line 307 says "Titan M2 secure element"

- **Evidence:** §4.1 line 246 uses "StrongBox-backed hardware element"; §5.1
  line 307 names "the StrongBox security level backed by the Titan M2 secure
  element." Both are correct, but §4 uses the generic name and §5 names the
  specific chip. Not a mismatch, but the §5 specificity is what makes the
  GrapheneOS-on-Pixel-only constraint legible.
- **Impact:** Minor. The specificity helps readers connect §4's
  Pixel-only constraint to a specific hardware property.
- **Recommendation:** Optional. §4.1 line 246 could say "StrongBox-backed
  hardware element (Titan M2 on supported Pixel generations)..." Not
  required.

### F11: §4.1 line 252 names "three-tier identity model (master → operational → device)"; §5.1 distinguishes operational identity (a keypair) from device capability tokens (signed delegations, not a keypair tier)

- **Evidence:** §4.1 line 252 (`design-brief.md:252`): "The three-tier
  identity model (master → operational → device, per Section 5.1)..."
  §5.1's organization (lines 303, 307, 317) treats this carefully: master
  is an Ed25519 keypair, operational is an Ed25519 keypair, but "device" in
  §5.1 line 317 is "Device capability tokens" — short-lived signed
  delegations to specific device keys. The "device" tier is not symmetrical
  with the other two; it's the delegation layer, not a third user-keypair.
- **Impact:** Minor terminology. The "three-tier" framing is the common
  shorthand and §5.1's structure (three subsection headers) supports it,
  but a careful reader of §5.1 line 317 will notice the third tier is
  structurally different (capability token + device key) from the other
  two (which are user identity keypairs). Not load-bearing in §4 but worth
  noting for readers who treat §4 as the canonical mental model.
- **Recommendation:** Optional. If revising §4.1 line 252, consider
  "master identity → operational identity → device-scoped capability
  tokens" to mirror §5.1's structure without overhauling the "three tiers"
  framing.

### F12: §4.1 line 253 says trust graph is "anchored in Sigsum commitments"; §5.2 line 372 specifies "commitment-only" with content-vs-commitment distinction §4 omits

- **Evidence:** §4.1 line 253 (`design-brief.md:253`): "anchored in Sigsum
  commitments." §5.2 line 372 (`design-brief.md:372`): "**Sigsum
  transparency log integration (commitment-only).** Operations are anchored
  in Sigsum (Section 3.4 trust root) through commitments — hashes of the
  operations — rather than by submitting the operation content itself."
- **Impact:** §4 actually has the right word ("commitments"), but a reader
  unfamiliar with transparency log architecture may not understand that
  "commitment" specifically means hash-not-content. §5.2's privacy property
  — operation content stays out of public view — is what addresses the
  "Public transparency-log metadata" surface, which §4 does not mention.
- **Recommendation:** Optional. Add half a sentence to §4.1 line 253:
  "anchored in Sigsum commitments (hashes of operations, not operation
  content, keeping issuer/subject/context out of public view)." This makes
  the privacy property visible at the §4 level.

## Patterns

The dominant pattern is **v1-vs-v1.5 elision**. §5 stages many architectural
properties as "v1 ships X, v1.5 adds Y": SimpleX-only vs.
SimpleX+Briar (§5.4 line 436), source review vs. reproducible builds
(§5.5 line 482), no local CRDT vs. cached operations (§5.2 line 366), no
extra-private toggle vs. toggle with tooltip (§5.4 lines 448–450),
documentation-based vs. in-app post-coercion recovery (§5.6 line 522). §4
treats most of these as if the v1.5 state is the architecture. A reader who
takes §4 as the architectural summary forms a v1.5-or-later mental model
and then encounters §5's v1 scope cuts as surprise restrictions rather than
as the design's honest staging.

The secondary pattern is **operation/property compression**. §4 names
collective categories ("revocations," "two-layer signing," "metadata
minimized") where §5 specifies a split that does load-bearing work — the
withdrawal-vs-compromise-revocation split (§5.2 lines 345, 352, 374), the
APK-key-vs-Sigstore split that §4 captures correctly but separates from the
v1 source-review property (§5.5 lines 480, 482), and the multi-source
metadata accounting in §5.4 line 442. The compression is editorially
defensible at the §4 abstraction level, but readers who treat §4 as the
architecture summary lose the distinctions §5 makes specifically because
the design depends on them.
