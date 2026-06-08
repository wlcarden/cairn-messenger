# D0040 — Recovery coercion-resistance: the in-app build of D0005 (recovery Stage 3)

**Status:** Accepted
**Date:** 2026-06-08

## Context

[D0005](D0005-peer-verification.md) decided the recovery-peer verification
mechanism — **single-use challenge phrases** + a **peer-clock 48h cooling-off** +
an **atomic-or-non-leaking master re-split**. That decision is the load-bearing
element of the compelled-unlock answer (D0002) and the master-not-on-device
property (design brief §5.1): without it, a peer under stress releases a share to
whoever can place a credible phone call.

[D0038](D0038-recovery-app-integration.md) staged the app build. Stages 1 and 2
have **landed and are on-device-proven**:

- **Stage 1 (paper-share recovery)** — the recovery-card codec, the
  `recovery_decode_card` FFI, and the Kotlin flow that reconstructs the master
  from a threshold of pasted/scanned cards and re-roots this device's persistent
  TEE operational identity under it. One-device-proven; adversarially reviewed.
- **Stage 2 (peer-share distribution)** — envelope key-11 `recovery_share` +
  key-12 `recovery_request`, adapter + FFI + Kotlin, so a verified peer **holds**
  a recovery card (encrypted `recovery_shares` category) and **returns** it on the
  owner's request + the peer's **manual approval**. Two-Pixel-proven over Tor.

This document resolves how to build **Stage 3 — D0005 coercion-resistance** in the
app, and — critically — how the **fresh-device peer-recovery gather** (the real
blank-device scenario) couples to it. The gather was previously framed as a "thin
wrapper" on Stage 2; that was wrong (§2), and the correction is the spine of this
doc.

This is downstream of D0005 (it implements that decision, does not re-decide it).
Where D0005's mechanism leaves an implementation choice, this doc makes it.

## Decision summary

1. **The fresh-device identity-matching problem is solved by the challenge phrase
   itself** — the phrase doubles as the **identity proof** AND the **share
   selector**, so a blank recovering device needs neither its old operational key
   nor its own master pubkey to gather. This collapses the gather and Stage 3 into
   one coherent design (§2, §3).
2. **Stage 3 builds in three sub-stages**, lowest-risk first: **3a** challenge
   phrases + the fresh-device gather; **3b** the peer-clock cooling-off; **3c** the
   atomic re-split. The fresh-device gather rides on 3a (§7).
3. Challenge phrases are **established at distribution**, stored **peer-side
   encrypted-at-rest associated with the held share**, **off-device** for the
   owner, verified **out-of-band on a channel of the peer's choosing**, and
   **renewed at recovery completion** (§3) — faithfully per D0005.
4. The cooling-off timer runs on the **peer's clock** (the fresh device's clock is
   untrusted); the recovering device's countdown is display-only; cancellation is
   **primarily out-of-band (peer-side manual cancel)** plus an optional envelope
   **key-13 `recovery_cancel`** (§4).
5. The atomic re-split is **greenfield and the highest-risk surface**; it is staged
   **last** and gated behind an explicit two-phase protocol over the async transport
   (§5). It does NOT block 3a/3b shipping.

## 1. What Stage 3 must add (over the landed Stages 1–2)

Stage 2 today: a peer holds a card and returns it on **manual approval** to a
contact **whose operational key matches the giver's** — i.e. the same-device,
same-identity case (validated: Alice asks Bob for the share Bob holds for Alice,
over their existing connection). Stage 3 must make recovery work in the **real
coercion-resistant scenario**:

- The owner is on a **fresh/blank device** (new operational key — §2).
- The peer must **authenticate** the requester as the owner before releasing
  (challenge phrase — §3), not merely tap "approve".
- Release is **delayed 48h on the peer's clock** with a **cancel window** (§4).
- On reconstruction, the master **re-splits atomically** to all peers before the
  new identity is signed (§5).

## 2. The fresh-device identity-matching problem (the coupling the gather hides)

On a fresh device, `KeystoreEd25519Signer.generateOrLoad` mints a **new** TEE
operational key. So when the owner re-pairs with peer Bob to gather, **Bob sees a
brand-new contact**, not "Alice." Stage 2 keys held shares by the giver's
operational key and matches a `recovery_request` by the requester's current key
(`recoveryPeers.holds(contact.peerKeyHex)`); a fresh-device request from a new key
matches **nothing** and is ignored. So the gather cannot be a thin wrapper — the
peer needs a key-independent way to know "this new contact is the owner, and
_which_ held share is theirs."

**Resolution — the challenge phrase is the matcher.** At distribution, the peer
stores the held card **together with** the single-use phrase agreed for that pair
(§3). On recovery, the requester proves the phrase out-of-band; the peer finds the
held share whose phrase the requester produced, and releases _that_ one. The phrase
therefore does double duty:

- **Identity proof** — only the real owner knows the phrase (it is off the seized
  device and not yielded by voice cloning — D0005).
- **Share selector** — the phrase is bound 1:1 to a held share, so the peer needs
  no key match and the **blank device needs neither its old key nor its own master
  pubkey** to gather. This is why 3a (challenge phrases) and the gather are the same
  work, and why building the gather first with a stop-gap matcher (a peer-side
  picker) would be throwaway: the phrase replaces it.

Consequence: the gather flow is **3a**, not a separate "Stage 2.5."

## 3. Challenge phrases (Stage 3a)

Faithful to D0005's "pre-shared peer challenges (single-use)":

- **Establishment — at distribution.** When the owner entrusts a recovery card to a
  peer (the landed Stage-2 `entrustRecoveryShare`), the flow now also has the pair
  agree a phrase out-of-band; the owner stores it **off-device** (paper / hardware
  password manager / another Cairn user's encrypted archive — never on this
  device), the peer stores it **with the held card** (§6 storage), encrypted at
  rest. New surface: extend the entrust flow + a peer-side "phrase for this held
  share" record.
- **Verification — at recovery.** The peer asks the requester to repeat the phrase
  **through a channel of the peer's choosing** (not the recovery-request channel);
  the peer never transmits the phrase first, only checks the requester can produce
  it. In-app, this is a **peer-side confirmation step**: the approval dialog
  (landed Stage 2) gains "confirm <name> produced the phrase for the share you hold
  for <master>" before release is scheduled. The phrase check is **operator-driven**
  (the peer verifies out-of-band, then confirms in-app) — Cairn provides the
  binding (phrase ⇄ held share) + the prompt, not an in-band phrase exchange.
- **Single-use + renewal.** On a successful recovery, a **new** phrase is agreed
  out-of-band for the next attempt and re-stored (D0005 M2). New surface: a renewal
  step at recovery completion.

Open fork (resolve in 3a build): whether Cairn stores a **hash/commitment** of the
phrase peer-side (so the peer's app can assist the check) or stores **nothing**
about the phrase and relies on the peer remembering it out-of-band. D0005's
"the peer never transmits the phrase first; verifies the user can produce it" is
satisfied by either, but a peer-side **salted hash** lets the app confirm a typed
phrase without trusting the network — preferred, pending a constant-time-compare +
no-phrase-on-the-wire check.

## 4. Peer-clock cooling-off (Stage 3b)

Faithful to D0005's "delay-and-confirm (peer-side enforcement)":

- After the peer confirms the challenge (§3), the peer **schedules** share release
  at **its own device's** current time + 48h — persisted as a record
  `{held_share_id, release_at_peer_unix}` in the (encrypted) `recovery_shares`
  category. The share is **not delivered** until the window elapses; the fresh
  device's clock is never consulted (D0005 H5).
- **Cancellation.** Primary: **peer-side manual cancel** — the peer's UI lists
  pending scheduled releases and lets the peer discard one (driven by the owner
  reaching them out-of-band: "cancel my recovery"). Secondary/optional: an envelope
  **key-13 `recovery_cancel`** the owner sends from any device/connection they
  still control (authenticated by whatever key that device holds), which discards
  the matching scheduled release. The recovering device shows a **display-only**
  countdown + the cancel channels (informational, not security-enforcing).
- **Firing the timer.** Android has no always-on scheduler we trust for a 48h
  horizon across reboots; the release is evaluated **lazily** — on each app launch /
  recv-loop tick the peer checks `now_peer >= release_at_peer_unix` for each pending
  record and, if due and not cancelled, sends the held card (key-11). A
  `WorkManager` periodic check is an optional nicety, not the source of truth (the
  lazy check is). This keeps timing on the peer's clock without a foreground-service
  dependency for two days.

Open fork: whether to add **key-13 `recovery_cancel`** in 3b or defer it (manual
peer-side cancel covers the threat; the in-band cancel is a convenience). Leaning
**defer key-13** to keep 3b small — manual cancel is the D0005-required path.

## 5. Atomic-or-non-leaking re-split (Stage 3c) — the hard part

D0005 requires the post-reconstruction re-split to be atomic w.r.t. the master's
lifetime: **all N peers get new shares before any zeroize, the new operational
identity is signed only after re-split succeeds, and the flow either completes in
full or leaves no observable state.** This is **greenfield** — it lives nowhere
today (D0018's claim that it is in `cairn-recovery` is incorrect; D0038 §7 flagged
this). It is the **highest-risk surface** and is staged **last**, behind 3a/3b.

The difficulty is the **async transport**: peers may be offline for hours. A
synchronous two-phase commit does not exist over store-and-forward Tor/SMP. The
design must therefore be:

- **Phase 1 (prepare):** the recovered device re-splits the master (held in
  `Zeroizing`/pinned memory throughout) and sends each peer its **new** share
  (key-11) tagged as a _pending re-split_; awaits an **ack** from every peer.
- **Phase 2 (commit):** ONLY after **all** peers ack, the master signs the new
  operational identity (reusing Stage 1's `recovery_reconstruct_and_attest` /
  `adoptMasterAttestation`), the device commits, and the master is zeroized. Peers
  promote their pending re-split share to active on a **commit** signal.
- **Abort (non-leaking):** if any peer does not ack within a bound, the device
  sends a **discard** to peers who received a pending share, zeroizes the master,
  signs **no** new identity, and reports recovery **failed-but-non-leaking**.

Open forks (resolve in 3c, NOT here):

- The ack / commit / discard control messages — likely **key-13/14/15** envelope
  fields, or a small CBOR sub-protocol over key-11. Define in 3c.
- The **bound** for "all peers ack" over async transport, and what a partial-ack
  timeout does (retry vs abort). This is the crux risk.
- Whether v1 ships re-split at all, or whether the **landed Stage-1 re-rooting**
  (the master attests the new operational key, no re-split) is the v1 recovery
  endpoint and re-split is **v1.x**. Re-splitting changes every peer's share, so it
  is only needed to keep the _old_ shares from recovering the master again after a
  recovery — a real but second-order property. **Recommendation: ship 3a + 3b for
  v1; treat 3c (re-split) as v1.x**, since reconstruct-and-re-root is already
  whole, and atomic re-split over async transport is a research-grade problem whose
  failure modes (a leaked master mid-protocol) are exactly what we must not get
  wrong under deadline.

## 6. Storage

All Stage-3 state lives in the existing encrypted `recovery_shares` category (the
`StorageHandle` accepts it; a single held share is transportable-by-design, so the
category's per-DEK encryption is sufficient). Records, keyed per held share:

- the **held card** (landed Stage 2),
- the **phrase commitment** (salted hash; §3 open fork), if peer-assisted,
- the **scheduled-release** record `{release_at_peer_unix}` (§4) when a recovery is
  in cooling-off,
- the **pending re-split** new-share (§5) when 3c lands.

No new FFI storage surface is required (the generic `StorageHandle` put/get/delete
covers it), consistent with how Stage 2 chose the generic store over the
`cairn-recovery::peer_store` crate type.

## 7. Staging

- **Stage 3a — challenge phrases + the fresh-device gather (≥2 devices).** The
  phrase establish-at-distribution + the peer-side verify-and-select + the
  blank-device gather (re-pair peers → request → peer confirms phrase → … note: 3a
  releases immediately on confirm; the 48h delay is 3b) → auto-feed returned cards
  into the landed `addRecoveryCard` → reconstruct + re-root. This is the
  highest-value completion: peer recovery becomes usable for the real scenario, and
  it resolves the §2 matching once. 2-Pixel-validatable. Split in build:
  - **3a-i — challenge-phrase mechanism. LANDED + 2-Pixel-proven over Tor.**
    Holder-side `RecoveryPeerStore` record format `[salt(16)][phraseHash(32)][card]`
    (salted SHA-256, domain-separated; all-zero until set), `setPhrase` /
    `findByPhrase` (the §2 key-independent matcher), and the verify-gated
    `MessagingViewModel.returnShareByPhrase` replacing the old unconditional
    `approveReturnShare`. The holder's request gate is now `hasAnyHeld()` not
    `holds(peerKey)` — a fresh-device requester's NEW key cannot select a share, so
    the phrase selects it (§2). `ShareReturnDialog` requires the phrase; driver hooks
    `setphrase` / `approveshare "<phrase>"`. **Proof:** A entrusts → B holds (154 B)
    → B `setphrase` → A requests → B prompted → **wrong** phrase refused (A receives
    nothing) → A re-requests → **correct** phrase returns the exact 154 B card to A,
    all over bundled Tor on oriole + raven. Wire/codec/FFI unchanged (rides the
    landed key-11/12). Known UX gap deferred to 3a-ii: a mismatched guess consumes
    the prompt (fails closed, but the dialog should keep open + show an error +
    allow retry instead of forcing the requester to re-request).
  - **3a-ii — fresh-device gather UX. LANDED + 2-Pixel-proven over Tor.** From the
    recovery card-collector, `gatherFromPeer()` creates an invite (a `gatheringFromRecovery`
    flag re-routes `goLive`: a pair started here auto-sends a `recovery_request` and
    returns to the collector instead of opening a chat); the returned card auto-feeds
    the existing `addRecoveryCard` path (gated on `ui is Recovery`). `recoveryCards`
    is VM-scoped so the count survives the pairing navigation; `cancelPairing` returns
    to the collector. The retry-on-mismatch gap from 3a-i is also fixed:
    `returnShareByPhrase` returns a Boolean and clears the prompt only on a match, so
    a wrong guess keeps the prompt and the `ShareReturnDialog` shows an inline error +
    allows retry. Driver hook `gatherpeer`. **Proof (oriole + raven):** A is wiped →
    recovery-enrolled with a NEW operational key (`73734c4e…`, ≠ the old `a73c0e67…`)
    → `gatherpeer` → B accepts → on connect A auto-requests → B (holding A-**old**'s
    share) is prompted by A's NEW key and matches it **by phrase, not key** (the §2
    resolution) → returns the 154 B card → A auto-feeds it → A adds 2 paper cards →
    reconstructs + **re-roots under the master** (`adopted master attestation (151 B)
— now master-rooted`). Retry proven separately: a wrong guess kept the prompt;
    the correct phrase on the **same** prompt then returned the share. The
    all-from-peers threshold (≥3 peers for 3-of-5) needs ≥3 devices (same blocker as
    D0037 S3); the mixed 1-peer + 2-paper run proves the gather feeds the same
    accumulator as paper.
- **Stage 3b — peer-clock cooling-off (≥2 devices).** The scheduled-release record +
  the lazy peer-clock firing + the peer-side manual cancel + the display-only
  countdown. Inserts the 48h delay between 3a's challenge-confirm and the release.
  (key-13 `recovery_cancel` deferred per §4.)
  - **3b-i — cooling-off mechanism. LANDED + 2-Pixel-proven over Tor.** A new
    encrypted `recovery_schedules` category + `RecoveryScheduleStore`
    (`[releaseAt(8)][requesterKey(32)][giverKey(32)][connId]`). On phrase-verify,
    `returnShareByPhrase` no longer sends — it **schedules** the release at the
    holder's own clock + the window (D0005 H5: the fresh device's clock is never
    trusted). `fireDueReleases()` (lazy: on unlock + a debug driver hook; re-loads
    the card from the held store and sends key-11 when due) + `cancelFirstScheduledRelease`
    (peer-side manual cancel). Driver hooks `coolingoff "<sec>"` (window override),
    `fireduereleases`, `cancelschedule`. **Proof (oriole + raven, 20 s test window):**
    verify → "release SCHEDULED in 20 s", A receives **nothing**; window elapses →
    fire → A receives the 154 B card; re-run + **cancel before the window** → fire →
    nothing released. Pending (3b-ii): the holder's pending-releases list + cancel
    button in the UI (currently driver-only), a recovering-device cooling-off notice,
    and a production lazy trigger beyond unlock (periodic / recv-tick).
- **Stage 3c — atomic re-split (≥2 devices, highest risk).** Per §5; **recommended
  v1.x**, behind an explicit two-phase protocol. Does not block 3a/3b.

Each sub-stage is a wire/codec/FFI/Kotlin slice in the landed key-8/9/10/11/12
pattern + a 2-device on-device proof, mirroring how Stages 1–2 shipped.

## 8. Threat model honesty

- 3a (phrases) defeats **impersonation** (voice clone / social engineering of the
  request): the adversary cannot produce the off-device phrase.
- 3b (cooling-off) defeats **real-time pressure** that survived 3a: a coercion event
  must be continuous for 48h or become detectable (the owner disappears for two
  days, peers notice).
- 3c (atomic re-split) keeps a **failed/interrupted** recovery from leaking the
  master and keeps **old shares** from re-recovering after a legitimate recovery.

> **What SHIPPED 3a does NOT do (adversarial-review correction, 2026-06-08).** The
> shipped slice is 3a **only** (3b cooling-off is deferred). Shipped-3a-alone is
> exactly the **pre-shared-challenges-only** configuration D0005 considered and
> **rejected as a _standalone_ defense** — because the phrase releases the share
> _immediately_ on confirm, so it adds **nothing against a _coerced owner_** who can
> produce the phrase under live duress. 3a's resistance is scoped to **remote
> impersonation** of the request; **coercion-resistance proper begins at 3b.** Any
> reading of "coercion-resistance LANDED" against the shipped state is an overclaim —
> the status doc and LANDED notes were corrected to say "impersonation".

- **Residual (named):**
  - **Off-device phrase storage** is the weak point at this tier (D0005) — the owner
    keeps the phrase in memory/paper; shoulder-surf or coercion yields it.
  - **Peer-side at-rest. HARDENED (2026-06-08).** The phrase hash is now **Argon2id**
    (m = 19 MiB, t = 2, p = 1; computed in the Rust core, `recovery_phrase_hash`,
    NFC-normalized) — not a bare SHA-256 — so brute-forcing a memorable phrase from an
    exfiltrated peer store costs ~5–6 orders of magnitude more (seconds → years). The
    **cross-peer reuse** amplification is closed by enforcing **per-share phrase
    uniqueness** (`setPhrase` rejects a phrase already used by another held share;
    `findByPhrase` fails closed on >1 match), so phrases are independent by
    construction. _Migration: fresh-install / re-set-phrase — an existing held share's
    old SHA-256 hash won't verify under Argon2id and must be re-set._
  - **Online guessing is bounded** (review remediation): a wrong phrase is retryable
    for typos but only up to `MAX_PHRASE_ATTEMPTS` per prompt, after which the prompt
    is dropped and the requester must re-request — restoring D0005's single-use _cost_
    per guess. A persisted cross-request lockout + single-use renewal-on-success
    (D0005 M2) are the stronger, deferred forms.
  - **First-card gather poisoning. MITIGATED (2026-06-08).** `gatherFromPeer` now
    refuses to start until the owner has added one of their OWN cards (the legitimate
    commitment anchors recovery), and `handleIncomingRecoveryShare` rejects a returned
    card that would be the anchor — so a hostile peer's card can no longer set the
    reconstruction anchor (and `addRecoveryCard` rejects any mismatched card against
    the user-set anchor). Forgery was already impossible (the Rust BLAKE3 commitment
    check at reconstruct).
  - A peer who is _both_ compromised _and_ coerced past the phrase + the 48h is
    outside the model; 3-of-5 peer compromise reaching the master is the acknowledged
    architectural tradeoff (status doc OUT-OF-SCOPE row).
- The cooling-off trades **availability** (recovery takes ≥48h) for
  coercion-resistance — acceptable per D0005; the fresh-identity path is the
  low-latency alternative.

## Reversibility

3a/3b are additive optional-envelope fields + Kotlin, reversible like every prior
stage. 3c is the irreversible-design-risk piece and is explicitly gated to v1.x
behind its own protocol decision, so shipping 3a/3b does not commit the project to
a half-built re-split. The 48h parameter is tunable (D0005).

## References

- [D0005](D0005-peer-verification.md) — the mechanism this implements
- [D0038](D0038-recovery-app-integration.md) — the app-integration staging (Stages 1–2 landed)
- [D0002](D0002-duress-profile.md) — the compelled-unlock answer this makes load-bearing
- [D0006](D0006-cryptographic-envelope.md) §9 — the identity chain recovery re-roots
- design brief §5.3 (Recovery Model), §5.1 (master-not-on-device)
