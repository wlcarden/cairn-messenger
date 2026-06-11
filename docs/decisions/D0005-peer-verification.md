# D0005 — Recovery peer verification mechanism: pre-shared challenges plus delay-and-confirm

**Status:** Accepted
**Date:** 2026-05-27

## Context

The Section 5 adversarial review surfaced finding F1: the recovery flow's out-of-band verification is the load-bearing element of the compelled-unlock answer in D0002, the master-not-on-device property in 5.1, and the recovery-network-surface mitigation in 5.3. The mechanism was specified only as "peers are expected to" verify out-of-band before releasing shares, with no enforcement protocol. Under stress, peers will release shares to whoever can place a phone call with credible voice and context — and voice cloning is off-the-shelf in 2026 while contextual material exfiltrates with compelled unlock.

Three mechanism options were considered (see [section-5-review.md F1](../archive/section-5-review.md)): pre-shared peer challenges, delay-and-confirm protocol, two-peer cross-validation, or combinations.

## Decision

**Combine pre-shared peer challenges with a delay-and-confirm protocol.** Both mechanisms specified in Section 5.3 of the design brief.

### Pre-shared peer challenges (single-use phrases per consolidated external-reads triage C8 / M2)

At provisioning, the user and each designated recovery peer establish a unique secret phrase (or shared random token) known only to that pair. **Phrases are single-use:** each successful peer challenge results in a NEW phrase agreed out-of-band for the next recovery attempt, surfaced to both parties through a structured renewal flow at the recovery's completion. This closes the cryptographer review's M2 finding (long-term static phrase reusable across recovery attempts becomes closer to a password than to a cryptographic nonce; a compromised peer who saw one recovery has the phrase indefinitely under the prior reusable model). Phrases are stored:

- By the user: distributed across recovery-aware notes (paper, hardware-backed password manager, or another Cairn user's encrypted message archive), not on the device itself. The off-device storage problem is named as a known weak point at this threat tier; the provisioning ceremony walks the user through specific storage options matched to their context (Section 5.3 expanded operational guidance).
- By each peer: held in the peer's Cairn application, encrypted at rest by the peer's full-disk-encryption key.

To release a share, the peer requires the user to repeat the phrase through a channel of the peer's choosing (not the recovery-request channel). The peer never transmits the phrase first — only verifies that the user can produce it independently. An adversary holding the user's seized device does not have the phrase even after full unlock (it is not stored on-device); voice cloning does not yield the phrase (the user must speak it from independent memory or recovery notes); social engineering through the recovery request itself does not yield the phrase (the peer asks for the phrase, does not provide it).

### Delay-and-confirm protocol (peer-side enforcement per consolidated external-reads triage C5 / H5)

After all required shares have arrived and verification challenges have passed, share release is held for a mandatory **48-hour cooling-off period** before the master is reconstructed. **The 48-hour timer runs on the peer device, not the fresh device** — closing the cryptographer review's H5 finding (the prior architectural framing had the fresh device counting down 48 hours after shares arrived, against a clock that the fresh device's owner — including a Cellebrite-class adversary holding the device — could advance to compress the window to seconds). Peer-side enforcement means:

- Each peer, upon completing challenge verification, schedules share release at its own device's current-time + 48h. The peer's device clock controls the timing, not the recovering device's clock.
- Shares are NOT delivered to the recovering device until 48h after the peer completes challenge verification. The recovering device receives shares only at the end of the cooling-off window, not before.
- The legitimate user can cancel the recovery during the window through any channel they control — sending a cancellation request from any device the user has authenticated identity for, or contacting any of the peers through any out-of-band channel. Cancellation reaches the peer through any channel; the peer discards its scheduled share-release.
- The recovering device displays the time remaining and the channels through which the user can cancel; this display is informational (telling the user when shares will arrive) rather than security-enforcing (which is what the prior architecture incorrectly assumed).
- An adversary holding the user under continuous control can prevent the user from issuing a cancellation, but the delay creates a non-zero window in which a coercion event must be either continuous (24-48h of physical control over both the user and any device the user might use to cancel) or detectable by the user's network (the user disappears for two days, peers notice).

After the cooling-off period without cancellation, peers release shares to the recovering device; the master is reconstructed and the new operational identity is issued.

### Master re-split atomicity under interruption (per consolidated external-reads triage C10 / M4)

The master re-split flow that follows reconstruction is **atomic with respect to the master's lifetime**. Specifically:

- The reconstructed master seed is held in `secrecy`-wrapped pinned memory across the full re-split-and-distribute operation, not zeroized between sub-steps.
- All N peers receive their new shares before any zeroize step fires. If new shares cannot all be delivered (network failure, peer offline, partial distribution failure), the master is zeroized, the new-share fragments are discarded by recipient peers via a re-split-failed signal, and the recovery is treated as failed-but-non-leaking. The flow does not enter a partial-completion state where the master is leaked because re-split partially completed and then crashed.
- The new operational identity is signed by the master **only after** the re-split has succeeded across all N peers, not before. This prevents the failure mode where the master signs the new operational identity, then crashes before re-split completes, leaving the user with a new operational identity signed by a master whose re-split-distribution status is indeterminate.
- The flow either completes in full (all peers have new shares; new operational identity is signed and propagated; master is zeroized) or no observable state change occurs (no peer has a new share; no new operational identity exists; master is zeroized).

## Alternatives considered

**Pre-shared challenges only.** Lighter; lower recovery latency. Rejected because it provides no time-cancel window: an adversary who has obtained the phrase (through coercion of the user, or through compromised peer-side storage that an adversary has exfiltrated) can complete recovery immediately. The phrase is the strongest single defense but a single defense is the wrong architectural shape for this threat tier.

**Delay-and-confirm only.** Lighter; no per-peer phrase to manage. Rejected because the 48-hour window is too short to defeat a determined adversary who controls the user for that long, and it does nothing against same-day voice-cloning impersonation that the user cannot detect.

**Two-peer cross-validation.** Considered. The protocol would have peers see who else has been contacted for the same recovery and compare notes through a separate channel. Rejected because (a) it depends on peers actively coordinating, which under stress most peers will not do reliably; (b) it complicates the recovery UX significantly for marginal protection beyond the chosen mechanisms; (c) the comparison channel itself becomes a target. The chosen pair handles the threats this would have addressed.

**All three combined.** Considered. Rejected as over-engineering: the pre-shared challenge defeats impersonation; the delay defeats real-time pressure that defeated the challenge; cross-validation adds complexity without addressing a remaining failure mode. The marginal protection does not justify the UX and implementation cost.

## Consequences

### Section 5.3 (Recovery Model) updates

The "Recovery flow" paragraph is rewritten to specify both mechanisms. The "Recovery network surface" paragraph references the mechanisms as the principal mitigations against post-coercion peer-HUMINT. Section 5.3's "Recovery flow timing" gets specified (per F30 in the review): expected timing envelope is 48h plus peer-response time (typically 24-72h total); the user's UI state during the wait is documented.

### Section 5.6 (UX Principles) updates

The compelled-unlock-guidance paragraph references the peer-verification mechanism so the chain "unlock yields peer identity; peer verification refuses the adversary's recovery" is honest about what protects what.

### D0002 (duress profile) framing

The compelled-unlock answer in D0002 still holds, but its load-bearing element shifts from "the tier model" to "the tier model + recovery peer verification (D0005)". The architectural protection of the master is conditional on this mechanism functioning.

### Pilot operational requirements

The pilot's in-person provisioning ceremony must now include peer-challenge establishment. The facilitator walks user and peer through phrase agreement and the user's notes location for storing phrases. The pilot user-facing documentation describes the recovery flow including how to cancel within the 48h window.

### User-experience cost

Recovery takes a minimum of 48 hours from the time the user has gathered shares. This is a real availability cost but acceptable for the threat tier — the realistic recovery scenario already involves multi-day waiting for peer responses and out-of-band verification, and the 48h cancel-window adds a bounded delay to a process that is rarely time-critical at finer granularity. Users in time-critical states have the fresh-identity path (Section 5.3) as the lower-latency alternative.

### Reversibility

The mechanism can be revised in v1.x if pilot evidence shows specific failure modes. The decision point most likely to be revisited is the 48-hour delay — pilot users may indicate it is too long (recovery takes too much elapsed time) or too short (adversaries successfully maintain control through it). The mechanism shape (challenges + delay) is structural and unlikely to change; the parameters (specifically the delay duration) are tunable.

## References

- [docs/section-5-review.md](../archive/section-5-review.md) F1
- [docs/decisions/D0002-duress-profile.md](D0002-duress-profile.md) — the compelled-unlock answer this mechanism makes load-bearing
- Prior art: similar delay-and-confirm patterns in cryptocurrency cold-wallet recovery (Trezor, Ledger); pre-shared challenge phrases in operational tradecraft (signal/countersign protocols).
