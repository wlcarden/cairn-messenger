# D0038 — Recovery model: app integration (paper-share-first staging)

**Status:** Accepted (staging + the two foundational forks decided 2026-06-05).
**Depends on:** D0005 (peer verification + 48h cooling-off), D0014 (non-peer / paper
recovery), D0006 §9 (three-hop identity chain), D0018 §3 (Shamir parameters), D0004
(facilitated provisioning ceremony), D0035 (trust-graph activation, for revocation).
**Anchors:** design brief §5.3 (recovery model), §3.3 (recovery-network surface),
§3.5 (in-app post-coercion recovery is a v1 commitment).

## Context

The recovery model is the architectural answer to device loss and compelled unlock:
the user's stable identity is a **master** Ed25519 keypair whose 32-byte seed is
Shamir-split (3-of-5 over GF(256), BLAKE3 commit per D0018 §3) and never kept on a
device; an operational identity is a subordinate key the master attests (hop #3 of
the D0006 §9 chain). On a fresh device the user reconstructs the master from a
threshold of shares and the master signs a **new** operational identity — recovering
their identity without centralized trustees.

The **cryptographic core is built and host-exercisable today** via `cairn-cli`:
`cairn-shamir` (split / reconstruct / commit), `cairn-recovery::reconstruct_and_attest`
(reconstruct seed in `Zeroizing` → sign the new operational identity → wipe), and the
`RECOVERY_PEERS` / `RECOVERY_SHARES` storage categories. The FFI already exposes
`recovery_reconstruct_and_attest` + `recovery_verify_master_attestation` with the
`ShareRecord` / `MasterAttestationRecord` types.

**What does not exist is any app-layer recovery experience.** There is no Kotlin UI to
recover, no paper-share encoding, no share distribution over the wire, and none of the
D0005 coercion-resistance protocol (challenge phrases, 48h cooling-off, atomic
re-split). The brief makes the in-app post-coercion recovery flow + paper-share
recovery **v1 commitments** (§3.5, §5.3), yet today a user can only recover via the CLI.
This decision stages closing that gap, starting with the part that converts the most
already-built core into a shipping feature with the least unbuilt surface and **one**
device to validate.

## Decision summary

| Question                            | Decision                                                                                                                                                                                                                                                                                                                                          |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Provisioning posture**            | **The app does RECOVERY, not provisioning.** Master generation + Shamir split + share rendering stay the **CLI-facilitated ceremony** (D0004; the "facilitator reachable" v1 audience precondition). `split` is **never exposed at the FFI** — which also keeps the D0018 §1.7 RNG-injection surface closed (no RNG plumbed across the boundary). |
| **First stage**                     | **Paper-share recovery** (D0014): enter/scan a threshold of paper shares → reconstruct → install a new master-attested operational identity. Host + 1-device validatable; no peer protocol, no cooling-off.                                                                                                                                       |
| **Carrier for peer shares (later)** | Envelope **key-11** control message, following the key-8/9/10 (read-receipt / vouch / introduction) precedent exactly.                                                                                                                                                                                                                            |
| **Coercion protocol (later)**       | D0005 challenge phrases + **peer-device-clock** 48h cooling-off + atomic-or-non-leaking re-split — the largest, ≥2–3-device surface, staged last.                                                                                                                                                                                                 |

## 1. What recovery is (and what the app must do)

Recovery is: on a fresh device that has generated a new operational (device) key in
StrongBox, take a threshold of the master's shares, reconstruct the seed **in Rust**,
have the master sign a `MasterAttestation` binding `master → new operational pubkey`,
wipe the seed, and **adopt** that attestation as the device's hop-#3 credential. The
master public key is unchanged across the ceremony — it is the user's durable identity;
only the operational key beneath it is reissued.

The app's recovery responsibility is therefore four steps:

1. **Collect** a threshold of shares (Stage 1: from paper; later: from peers).
2. **Reconstruct + attest** — `recovery_reconstruct_and_attest(shares, commitment,
new_op_pubkey = the fresh StrongBox device key, now)` → the signed master
   attestation. (Already FFI-exposed; the seed never crosses to Kotlin.)
3. **Adopt** the recovered identity — persist the master attestation as the hop-#3
   credential, record the master pubkey as the durable identity, mint the operational
   self-token, and bring the session up under the recovered identity.
4. **Revoke** the prior operational identity (Stage 1.5; see §6).

## 2. Provisioning stays CLI-facilitated (resolved fork)

Per D0004, provisioning is a facilitated ceremony: a trusted facilitator runs the CLI to
generate the master, split it, and produce the share kit (paper + any peer shares). The
app does **not** generate or split a master. This is consistent with the v1 audience
model (an in-person facilitator is one of the four preconditions) and is the simplest
secure posture: the app never holds `split`, so the master seed exists on a device only
transiently during reconstruction, and the D0018 §1.7 concern — a hostile UniFFI binding
injecting a deterministic RNG into `split` — is structurally impossible because `split`
is not on the FFI. In-app self-service provisioning is a **v1.x** consideration, not v1.

## 3. Stage 1 — paper-share recovery (resolved fork)

Paper-share recovery (D0014) uses the same 3-of-5 Shamir scheme but with shares the
facilitator's CLI **prints / QR-encodes** for the user to store physically. There is **no
peer protocol and no 48h cooling-off** (the cooling-off defends against peer
impersonation, which user-held shares do not have); coercion-resistance rests on
physical-storage security, which the brief states honestly (§5.3, §3.3).

The flow, on a fresh install:

1. The app reaches a "Recover an existing identity" entry (from first-run onboarding and
   from the §3.5 in-app post-coercion path).
2. The user scans (QR) or types a threshold of share cards plus the **recovery header**
   (commitment + master pubkey — see §4).
3. The app calls `recovery_reconstruct_and_attest` with the fresh device key as the new
   operational identity, adopts the result (§1 step 3), and lands the user in a working,
   recovered session.

This exercises the entire split→reconstruct→re-attest core through real UI on **one**
device: provision via CLI, write down the shares, fresh-install, recover.

## 4. The paper-share kit format (new codec)

A share kit must let **any threshold of cards** reconstruct, so each card is
self-describing. Proposed encoding (a new canonical codec in `cairn-shamir` / a thin
`cairn-recovery` wrapper, with a CLI emitter and an FFI decoder — split itself stays
CLI-only):

- **Per share card:** `id` (1 byte, non-zero) + `value` (`SECRET_LEN` bytes) — a QR
  payload, plus a short human-typeable text fallback (base32 of the same bytes; the
  BIP-39 wordlist infra from `FriendlyName` is an alternative if words beat base32 in
  user testing).
- **Recovery header (printed once on the kit):** the BLAKE3 `commitment` (32 bytes) + the
  **master public key** (32 bytes — `reconstruct_and_attest`'s verifier needs the
  expected master). A header QR + text fallback.

New surface for Stage 1:

- **CLI:** extend `split-seed` to also emit the print/QR kit (today it writes raw 33-byte
  `.bin` files).
- **FFI:** `recovery_decode_share(text) -> ShareRecord` and
  `recovery_decode_header(text) -> { commitment, master_pubkey }` (pure codec; no secret
  generation, no RNG). `recovery_reconstruct_and_attest` is reused unchanged.
- **Kotlin:** the recovery UI (ZXing QR scanning is already wired for pairing) + identity
  adoption.

## 5. Identity adoption after recovery

`reconstruct_and_attest` returns a `SignedMasterAttestation` for the new operational
pubkey, but the app must then **install** the recovered identity: store the master
attestation as the hop-#3 credential, set the master pubkey as the durable identity
anchor, mint the operational self-token (the D0035 collapsed-v1 token, now rooted under a
real master rather than self-issued), and unlock/bring up the session. This is the one
genuinely new identity-model wiring in Stage 1 and is where the recovered master first
becomes the chain root the trust graph anchors to. (Open sub-question for the Stage-1
implementation: whether a recovered identity coexists with or replaces a
locally-generated demo identity in `CairnSession` — to be resolved in the Stage-1 build,
not here.)

> **LANDED (2026-06-08) — Stage 1 paper-share recovery, on-device-proven.** S1a (codec +
> CLI emit, `5f2c94e`), S1b (`recovery_decode_card` FFI, `185be83`), and S1c (the Kotlin
> recovery flow) complete Stage 1. The **open coexistence sub-question is resolved by a
> corrected premise**: the "locally-generated demo identity" was a stale-docstring
> misread — the live operational key is the **persistent TEE Ed25519 key**
> (`KeystoreEd25519Signer`, already shipped). So recovery does not replace or coexist with
> a demo key; it **re-roots the existing persistent operational key** under the recovered
> master. Adoption (`CairnSession.adoptMasterAttestation`) persists the signed attestation
> (hop #3) + the master pubkey (the durable anchor) to the IDENTITY store; both reload at
> bootstrap (`master-rooted=true`), and My-Identity surfaces the master's friendly name.
> **Scoped out of Stage 1 (deferred):** re-minting the collapsed-v1 self-token under the
> recovered master so the trust graph anchors to it — the self-token stays self-issued for
> now (that is the optional D0035 two-key un-collapse, not a recovery dependency).
>
> Flow: Welcome → "Recover an existing identity" → new local passphrase (the new device's
> at-rest data is device-bound, **not** Shamir-recovered) → bootstrap → collect cards
> (paste one-per-line, or scan) → the BLAKE3 commitment is the have-enough-shares oracle
> (`reconstruct_and_attest` returns `RecoveryFailed` with no mutation on a short/wrong set,
> so the UI is "try, then add the rest") → adopt + re-root.
>
> **On-device proof (Pixel 6 / GrapheneOS, single device — recovery is 1-device
> validatable).** A real CLI 3-of-5 split (master `2f3e3838…`, friendly name "Collect Life
> Island") drove, via the debug driver hooks: 3 paper cards decoded across the FFI →
> `attemptRecovery` → `adopted master attestation (151B) — now master-rooted` →
> `re-rooted under master Collect Life Island`; relaunch → `master-rooted=true` (persisted
> attestation reloads); negative path → 2 cards `reconstruct failed (insufficient/wrong
cards)` (recoverable, no crash), +3rd card → success. (Screens use `FLAG_SECURE`, so the
> logcat events are the oracle.)
>
> **Adversarial review (2026-06-08).** A 6-lens agent-swarm review (crypto-chain,
> secret-hygiene, malicious-input, state-machine, identity-threat, error-handling),
> each finding independently skeptic-verified, refuted 12 of 16 raw findings and
> confirmed 4 (all low/nit — no critical/high/medium survived). Remediated: (1) a
> real CI guard now backs the NeverExport FFI-boundary discipline
> (`scripts/check-ffi-no-secrets.py` fails the build on a secret-carrier type as a
> `uniffi::Record` field — the prior `assert_exportable` is a blanket-impl no-op
> allow-list, and the docstrings that overstated the guard are corrected); (2)
> `leaveRecovery` now cancels an in-flight `attemptRecovery` (tracked job +
> `CancellationException` re-throw + post-await UI re-check) so a late completion
> can't clobber the contact list; (3) bootstrap reloads the attestation + master
> pubkey BOTH-or-NEITHER (a torn write → not-recovered, not a half-state); (4)
> success clears the collection state + a docstring fix. Re-validated host gates +
> APK + on-device happy path.

## 6. Stage 1.5 — revoke the prior operational identity

§5.3 specifies that recovery revokes the seized operational identity (`revoked_as_of` =
the compromise time) so the exposed key is repudiated. The trust-graph op already exists
(D0035 compromise-revocation minting); it is simply not sequenced into recovery. Stage
1.5 wires a revocation of the old operational key into recovery completion. Host /
1-device testable.

## 7. Later stages (named, deferred)

- **Stage 2 — peer share distribution (≥2 devices).** An envelope **key-11**
  `recovery_share` control message (and likely a key-12 `recovery_request`), added by the
  exact key-8/9/10 pattern (optional, omitted-when-absent, empty-payload control
  envelope, byte-identical to the prior schema). Adapter send/recv routing + uniffi
  wiring + `peer_store` write-on-receipt (the `peer_store` persistence is not yet
  FFI-exposed). Lets a peer **hold** and **return** a share over the existing SimpleX/Tor
  transport; shares released on manual peer approval (no challenge/cooling-off yet).

  > **LANDED (2026-06-08) — Stage 2 peer-share distribution, two-device-proven.** S2a
  > (`d3a2780`): envelope key-11 `recovery_share` + key-12 `recovery_request` (the
  > key-8/9/10 optional-omitted-byte-identical pattern) + adapter
  > `send_recovery_share`/`send_recovery_request` + recv surfacing; the five optional
  > control fields collapsed into a `ControlFields` struct. S2b (`2075f4e`): the FFI on
  > `SimplexAdapterHandle` + `ReceivedMessageRecord.recovery_share/recovery_request`. S2c
  > (`724a338`): the Kotlin flow — `RecoveryPeerStore` (held shares in the encrypted
  > `recovery_shares` category keyed by giver), recv routing (HOLD vs RETURN disambiguated
  > by a pending-request set), `entrustRecoveryShare`/`requestHeldShare`/approve-or-decline,
  > a manual-approval `ShareReturnDialog`, conversation-overflow affordances gated on a
  > VERIFIED contact (D0005 peer selection), and driver hooks. A **held share IS a card**
  > (`CAIRN-RECOVERY-…` text), so a returned share feeds the same `addRecoveryCard` →
  > reconstruct path as paper recovery.
  >
  > Resolved: the `peer_store` is the generic encrypted `recovery_shares` category via the
  > existing `StorageHandle` (not the `cairn-recovery::peer_store` crate type) — simpler +
  > sufficient for the manual-approval flow. \*\*On-device proof (two physical Pixels — oriole
  >
  > - raven — over bundled Tor):** after pairing, A entrusts a real CLI card → B logs
  >   `now HOLDING a recovery share … (154B)` → A requests → B `asked for their held share
back — awaiting approval` → B approves → A `RETURNED our held share (154B)`. Host-proven
  >   too (the S2a distribute→hold→request→return round-trip over the mock transport).
  >   **Deferred:\*\* the fresh-device re-pair-then-gather-and-reconstruct wrapper (a thin layer
  >   on this mechanism — gather returned cards from a threshold of peers, then the existing
  >   reconstruct).

- **Stage 3 — D0005 coercion-resistance (≥2–3 devices).** Single-use pre-shared challenge
  phrases (schema + user-off-device / peer-encrypted-at-rest storage + rotation), the
  **peer-device-clock** 48h cooling-off (scheduled release + cancellation message; the
  fresh device's clock is explicitly NOT trusted, per D0005), and the
  **atomic-or-non-leaking re-split** two-phase commit across N peers (D0005 §, D0018 §3.5)
  — which is greenfield (it lives nowhere today, despite D0018's claim it is in
  `cairn-recovery`). This is the largest, riskiest surface and is staged last.

## 8. Doc-vs-code reconciliations (fold in with Stage 1)

- **BLAKE3 commit construction is specified three ways.** D0018 §3.4 says
  `commit = BLAKE3(seed)`; the `cairn-shamir` docstring says `BLAKE3(domain || seed)`; the
  code uses `blake3::derive_key("Cairn Shamir commit-of-secret v1", seed)` (keyed mode),
  with a pinned test vector. The **code is authoritative** (domain separation is correct);
  reconcile D0018 §3.4 + the docstring to the `derive_key` construction.
- **Shamir RNG injection (D0018 §1.7).** The forbidden "RNG parameter across the FFI"
  vector stays closed by this decision — `split` is never exposed. Record that exposing
  `split` later (in-app provisioning) would require the FFI wrapper to call `OsRng`
  internally and never accept an RNG argument.
- **Atomic re-split is greenfield**, not existing code to extend (Stage 3).

## 9. Threat model (honest)

- **Recovery-network surface (§3.3):** three compromised peers reconstruct the master.
  Paper-share recovery (Stage 1) avoids this entirely (no peers); peer recovery (Stages
  2–3) re-incurs it, as the acknowledged price of refusing centralized trustees.
- **Paper-share physical security:** the kit is the recovery secret in physical form;
  compromise of a threshold of cards is master compromise. The mitigation is geographic
  distribution + storage discipline, not a cryptographic control — stated, not hidden.
- **Bounded master exposure:** the master seed is on a device only transiently during a
  reconstruction the user initiated; it is reconstructed in `Zeroizing` and wiped in Rust,
  never crossing to Kotlin.

## 10. Staging + validation

- **Stage 1 — paper-share recovery.** The kit codec (CLI emit + FFI decode), the Kotlin
  recovery UI, and identity adoption (§5). Host gates + a **single-device** validation:
  CLI-provision → record the shares → fresh-install → recover → confirm a working session
  under the recovered master. The §8 reconciliations land here.
- **Stage 1.5 — old-identity revocation** sequenced into recovery completion (§6).
  Host / 1-device.
- **Stage 2 — peer share distribution** (key-11; ≥2 devices).
- **Stage 3 — D0005 coercion-resistance + atomic re-split** (≥2–3 devices).

Each stage is its own host-gate-clean, propose-commit unit.

## Reversibility

- **Recovery-only-in-app** is additive: in-app self-service provisioning can be layered in
  v1.x by exposing an `OsRng`-internal `split` without disturbing the recovery path.
- **Paper-share-first** does not preclude peer recovery; both are first-class v1
  commitments and share the reconstruct + adopt core. Stage 1 is the common substrate.
- **Key-11** is a permanent, optional, omitted-when-absent wire commitment (the
  read_up_to / vouch / introduction precedent) — no migration before the first peer share
  exists.
- The **fresh-identity path** (new master + re-pair, dropping history — §5.3's "realistic
  primary path" for time-critical users) is intentionally **not** part of this decision; it
  is adjacent (identity abandonment, not master recovery) and tracked separately.

## Cross-references

- D0005 (peer verification, challenges, 48h cooling-off), D0014 (paper / non-peer
  recovery), D0006 §9 (three-hop chain), D0018 §3 (Shamir), D0004 (facilitated
  provisioning), D0035 (revocation).
- Design brief §5.3, §3.3, §3.5.
- Open question Q23 (non-peer path selection for v1.x/v2) — paper shares are the v1
  commitment this decision implements; the other paths (time-locked, single-trustee,
  explicit-no-recovery) remain Q23.
