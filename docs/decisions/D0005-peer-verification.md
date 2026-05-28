# D0005 — Recovery peer verification mechanism: pre-shared challenges plus delay-and-confirm

**Status:** Accepted
**Date:** 2026-05-27

## Context

The Section 5 adversarial review surfaced finding F1: the recovery flow's out-of-band verification is the load-bearing element of the compelled-unlock answer in D0002, the master-not-on-device property in 5.1, and the recovery-network-surface mitigation in 5.3. The mechanism was specified only as "peers are expected to" verify out-of-band before releasing shares, with no enforcement protocol. Under stress, peers will release shares to whoever can place a phone call with credible voice and context — and voice cloning is off-the-shelf in 2026 while contextual material exfiltrates with compelled unlock.

Three mechanism options were considered (see [section-5-review.md F1](../section-5-review.md)): pre-shared peer challenges, delay-and-confirm protocol, two-peer cross-validation, or combinations.

## Decision

**Combine pre-shared peer challenges with a delay-and-confirm protocol.** Both mechanisms specified in Section 5.3 of the design brief.

### Pre-shared peer challenges

At provisioning, the user and each designated recovery peer establish a unique secret phrase (or shared random token) known only to that pair. Phrases are stored:

- By the user: distributed across recovery-aware notes (paper, hardware-backed password manager, or another Cairn user's encrypted message archive), not on the device itself.
- By each peer: held in the peer's Cairn application, encrypted at rest by the peer's full-disk-encryption key.

To release a share, the peer requires the user to repeat the phrase through a channel of the peer's choosing (not the recovery-request channel). The peer never transmits the phrase first — only verifies that the user can produce it independently. An adversary holding the user's seized device does not have the phrase even after full unlock (it is not stored on-device); voice cloning does not yield the phrase (the user must speak it from independent memory or recovery notes); social engineering through the recovery request itself does not yield the phrase (the peer asks for the phrase, does not provide it).

### Delay-and-confirm protocol

After all required shares have arrived and verification challenges have passed, share release is held for a mandatory **48-hour cooling-off period** before the master is reconstructed. During the window:

- The legitimate user can cancel the recovery through any channel they control — sending a cancellation request from any device the user has authenticated identity for, or contacting any of the peers through any out-of-band channel.
- The fresh device displays the time remaining and the channels through which the user can cancel.
- An adversary holding the user under continuous control can prevent the user from issuing a cancellation, but the delay creates a non-zero window in which a coercion event must be either continuous (24-48h of physical control over both the user and any device the user might use to cancel) or detectable by the user's network (the user disappears for two days, peers notice).

After the cooling-off period without cancellation, the master is reconstructed and the new operational identity is issued.

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

- [docs/section-5-review.md](../section-5-review.md) F1
- [docs/decisions/D0002-duress-profile.md](D0002-duress-profile.md) — the compelled-unlock answer this mechanism makes load-bearing
- Prior art: similar delay-and-confirm patterns in cryptocurrency cold-wallet recovery (Trezor, Ledger); pre-shared challenge phrases in operational tradecraft (signal/countersign protocols).
