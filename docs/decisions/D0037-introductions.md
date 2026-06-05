# D0037 — introductions: consent-gated, connection-making, symmetric (introducer-initiated)

**Status:** Accepted (scope + design; implementation staged)
**Date:** 2026-06-04

> **Confirmed (2026-06-04):** the connection-making layer D0036 §7 deferred lands
> as **full, consent-gated introductions** — the lighter "invite-relay without
> per-introduction consent" fork was **rejected** (losing per-connection consent
> recreates the auto-network-building D0034 §7 warns against). An **introducer**
> (Bob) who has verified **both** parties brokers a new connection between them;
> **both** the subject (Carol) and the recipient (Alice) **explicitly consent**
> before anything connects. The new Alice↔Carol channel is the **existing
> one-time-invitation pairing** (`create_invitation` / `accept_invitation`),
> **relayed** through Bob; the trust half is the **existing vouch** (D0036) sent
> in **both directions** (symmetric), so both new contacts carry Bob's provenance
> from genesis. **No `introduction` op-type** is added (reuses `Attest`); a new
> `MessageEnvelope` key-10 field carries the introduction control messages.
> Introductions are **off by default and never automatic** — the
> compartmentalize-vs-connect choice (D0034 §7) stays first-class.

## Context

D0036 made transitive trust _visible_ (provenance annotation) but deliberately
stopped short of _connecting_ people: a vouch shares Bob's attestation of Carol,
but Alice still has no way to reach Carol. This decision closes that gap — the
"meet someone through a trusted contact" capability the trust graph has pointed at
since the verification-loop discussion (design brief §5.2, "opt-in
introductions").

Two findings make it tractable and bound its risk:

- **The connection primitive already exists.** Pairing is a one-time invitation
  relay (`create_invitation` → `/_connect <userId>`; `accept_invitation` →
  `/_connect <userId> <link>`, `cairn-simplex-adapter/src/adapter.rs`). There is
  no native SimpleX 1:1 "introduce" command, so an introduction is **Cairn-layer
  orchestration over the pairing Cairn already has** — not new transport.
- **The trust half is already built.** An introduction _is_ a vouch (D0036
  `build_vouch` / `ingest_vouch`) plus a relayed invite. The provenance verify +
  store + display path is unchanged.

So the genuinely new work is the **3-party coordination + the two consent gates**,
not crypto or transport. The maintainer chose the **full** model over the lighter
invite-relay-only fork: every connection an introduction creates must be
consented to by the person being connected, per D0034 §7.

## Decision summary

| Fork                       | Decision                                                                                                                                                                                                                                       |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Scope**                  | **Connection-making introductions** — Bob brokers a new Alice↔Carol channel with his vouch attached. The D0036 §7 deferral, now in scope (§1)                                                                                                  |
| **Consent model**          | **Full, dual, per-introduction.** Carol consents to being introduced to Alice; Alice consents to connect to Carol. Neither is ever auto-connected. The lighter no-per-introduction-consent fork is **rejected** (§2)                           |
| **Initiation**             | **Introducer-initiated** (Bob decides to introduce, extending the vouch UX). Requester-initiated ("Alice asks Bob to introduce her to Carol") is an additive follow-on — same machinery + an opening request message (§3, §8)                  |
| **Direction**              | **Symmetric.** Bob vouches for Alice _to_ Carol and for Carol _to_ Alice, so **both** new contacts carry Bob's provenance — Bob is introducing two people he has verified (§3)                                                                 |
| **The connection**         | **Relayed one-time invitation** — Carol mints a fresh invite on consent; Bob relays it to Alice; Alice `accept_invitation`s it (the existing TOFU pairing). No new transport, no reusable addresses (§4)                                       |
| **Coordination transport** | The introduction control messages ride the **existing Bob↔Carol and Bob↔Alice connections** (Bob already has both). Only the final Alice↔Carol pairing is a new connection (§4)                                                                |
| **Wire carrier**           | A new optional **`MessageEnvelope` key-10** field carrying a CBOR type-discriminated introduction message (`request` / `response` / `deliver`), empty text payload — the D0032/D0036 control-message pattern (§5)                              |
| **Op model**               | **Reuse `Attest` — no `introduction` op-type.** The attestation halves are ordinary vouches; the introduction is a wire protocol (D0006 §4's `introduction` op stays deferred) (§6)                                                            |
| **Contact provenance**     | A contact created via an introduction carries the ingested vouch from genesis; the introducer is recorded. Symmetric — Carol's new Alice-contact is contextualized too (§7)                                                                    |
| **Liveness**               | Asynchronous + store-and-forward: Carol mints the invite when she _approves_ (she is online to approve), so there is no hard liveness requirement; an offline Carol's request queues (§4, §9)                                                  |
| **Default**                | **Off by default; never automatic.** Introductions are an explicit act on both sides; the compartmentalize-vs-connect choice (D0034 §7) is first-class (§2, §8)                                                                                |
| **What defers**            | Requester-initiated flow; multi-hop (introducing a contact-of-a-contact); reusable contact addresses; the master hierarchy; revocation propagation (inherited from D0036 §7) (§8)                                                              |
| **Staging**                | **Stage 1** Rust+FFI (the three introduction messages + orchestration, reusing vouch + invitation); **Stage 2** Kotlin (initiator + the two consent surfaces + contact-from-introduction); **Stage 3** three-device on-device validation (§10) |

## 1. What an introduction is

Bob has verified **both** Alice and Carol. He brokers a connection between them:
Alice and Carol end up paired (a real SimpleX channel), each holding Bob's
attestation of the other, so each new contact shows _"Bob, whom you verified in
person, introduced you — Bob verified them in person"_ from the first message. It
is the composition of two things Cairn already has — **pairing** (§4) and **vouch**
(§6) — plus the **3-party consent orchestration** that is this decision's real
content (§3).

## 2. Consent is the whole point (the rejected fork)

The lighter fork — Bob relays a Carol-provided invite + his vouch **without
Carol's per-introduction consent** — was rejected. It collapses to "anyone Bob
chooses can open a connection to Carol," which is precisely the
auto-network-building D0034 §7 identifies as dangerous for source-protection
users: Carol loses control of who reaches her. The **full** model gives **both**
connected parties an explicit veto:

- **Carol consents** to being introduced to Alice _before_ any invite is minted.
- **Alice consents** to connect to Carol _before_ any pairing happens.

Introductions are **off by default and never automatic** — there is no
"auto-introduce my contacts" mode. The product keeps "stay compartmentalized" as
easy and as blessed as "connect" (D0034 §7): declining an introduction is a
first-class, unremarkable action.

## 3. The flow (introducer-initiated, symmetric)

1. **Initiate.** Bob, viewing his verified contact Carol, picks **"Introduce
   Carol to…"** → selects Alice (another verified contact).
2. **Request Carol's consent.** Bob → Carol (over the existing Bob↔Carol
   connection): `IntroduceRequest{ peer_key: Alice, vouch: Bob's Attest(Alice) }`.
   Carol's client surfaces _"Bob wants to introduce you to **Alice** — Bob
   verified Alice in person. [Approve] [Decline]."_ (The friendly name is derived
   from Alice's key per D0036 — no chosen name travels.)
3. **Carol approves → mints + responds.** On Approve, Carol `create_invitation`s a
   fresh one-time invite for Alice, ingests Bob's vouch for Alice (provenance),
   records a **pending introduction** (Alice's key → "via Bob"), and replies
   Carol → Bob: `IntroduceResponse{ accept: true, invite: <uri> }`. On Decline:
   `{ accept: false }` — Bob is notified, **Alice is never contacted**.
4. **Deliver to Alice.** Bob → Alice (over Bob↔Alice): `IntroduceDeliver{
peer_key: Carol, vouch: Bob's Attest(Carol), invite: <Carol's uri> }`.
   Alice's client surfaces _"Bob introduces you to **Carol** — Bob verified Carol
   in person. [Connect] [Decline]."_
5. **Alice consents → connects.** On Connect, Alice ingests Bob's vouch for Carol
   and `accept_invitation`s Carol's uri → pairs with Carol (TOFU). The new
   Carol-contact carries Bob's provenance from genesis. On Decline: Carol's invite
   goes unused (expires) — no connection.
6. **Carol contextualizes the incoming connection.** When Alice's first envelope
   arrives, Carol's TOFU-learned sender key matches her **pending introduction**
   (step 3) → the new Alice-contact is created "via Bob" with Bob's vouch for
   Alice attached. **Symmetric:** both ends hold Bob's provenance.

Both Carol (step 3) and Alice (step 5) explicitly consented; both learn the other
only after Bob brokered it.

## 4. The connection: relayed one-time invitation (reused)

The new Alice↔Carol channel is the **existing pairing primitive** — Carol's
`create_invitation` + Alice's `accept_invitation` — with the invite **relayed**
through Bob instead of shared directly. Nothing in the transport changes.

The **coordination** messages (§3 steps 2/3/4) ride the **existing** Bob↔Carol and
Bob↔Alice connections — Bob is already connected to both, so no new connection is
needed to orchestrate; only the final Alice↔Carol pairing is new.

**Liveness is soft.** Carol mints the invite at the moment she _approves_ — she is
by definition online then. If Carol is offline when Bob requests, the request
**queues** (SimpleX store-and-forward) until she returns. No party must be
simultaneously online. (Cairn uses one-time invitations, not reusable contact
addresses; on-demand minting at approval-time is why that suffices — §9.)

## 5. Wire carrier: `MessageEnvelope` key-10

A new optional **key-10** field (`introduction`, a `bstr` of a canonical-CBOR
type-discriminated message) carries the three message types, with an empty text
payload — the same control-message shape as `read_up_to` (key 8, D0032) and
`vouch` (key 9, D0036). Omitted when absent, so non-introduction envelopes stay
byte-identical. The CBOR carries `{ type: request|response|deliver, peer_key,
vouch_bytes, invite_uri? }`; the codec lives in `cairn-trust-graph` alongside the
vouch codec (no CBOR dependency in `cairn-uniffi`). Each message inherits the
envelope's `COSE_Sign1` device-signature, so the orchestrating sender (Bob, then
Carol) is authenticated for free (the D0036 §3 two-layer model).

## 6. Op model: reuse `Attest`

The trust halves of an introduction are ordinary **vouches** — Bob's existing
`Attest(Alice)` and `Attest(Carol)` ops, packaged by `build_vouch` and verified by
`ingest_vouch` (D0036). The introduction adds **no** trust-graph op-type; it is a
**wire protocol** that _carries_ vouches plus an invite. D0006 §4's `introduction`
op-type stays deferred — keeping the op schema closed and the change confined to
the wire + UI layers, exactly as the vouch did.

## 7. Contact provenance from genesis

A contact created via an introduction is, at creation, already a vouched contact:
the ingested `Attest` (Bob → the new peer) means `provenance_for` returns Bob's
named, depth-1 provenance from the first render (D0036 §6 — fenced to the user's
own verified contacts; Bob qualifies). The introducer is recorded so the UI can
say _"introduced by Bob."_ This is symmetric — Carol's new Alice-contact (§3 step 6) is contextualized identically.

## 8. What this does NOT do (deferred, named)

- **Requester-initiated introductions** ("Alice asks Bob to introduce her to
  Carol") — same machinery plus an opening `IntroduceAsk` (Alice→Bob); additive.
- **Multi-hop** — Bob can only introduce contacts **he** has verified, not a
  contact-of-a-contact. Depth-1, matching D0036 §6.
- **Reusable contact addresses** — Cairn stays on one-time invitations (§4).
- **Revocation / freshness propagation** and the **master/operational hierarchy**
  — inherited deferrals (D0036 §7, D0035 §7); introductions are self-rooted.
- **Auto-introduction** — there is no automatic mode; every introduction is an
  explicit, consented act (§2).

## 9. Threat model + metadata (honest)

An introduction is intrinsically de-compartmentalizing — that is _why_ the dual
consent (§2) exists. The exposures, stated plainly:

- **Bob** learns Alice and Carol are now connected (he brokered it).
- **Carol** learns Alice exists (key + derived name) + that Bob vouches for Alice
  — _before_ she consents, so her consent is informed (§3 step 2).
- **Alice** learns Carol exists (key + name + a connection address) + Bob's vouch
  — _before_ she connects (§3 step 4).

The controls: both connected parties veto (§2); introductions are off by default
and never automatic; the friendly name (not a chosen handle) is all that travels
(D0036); and the trust is bounded — the UI says _"Bob **introduced** you / Bob
**vouches**,"_ never _"verified"_ (D0036 §3). A high-risk user who should stay
compartmentalized simply declines — the safe path is the easy path (D0034 §7).

**Failure modes** the state machine must handle: Carol declines (Bob notified,
Alice untouched); Alice declines (Carol's invite expires unused); the invite
expires before Alice accepts (re-request); a party offline mid-flow (messages
queue). No partial state leaves a dangling connection.

## 10. Staging + validation

- **Stage 1 — Rust + FFI.** The key-10 introduction field + the three-message
  codec (`cairn-trust-graph`); the orchestration on the handle
  (`send_introduce_request`, the response→relay step, `accept_introduction`
  wrapping `accept_invitation`), reusing `build_vouch` / `ingest_vouch` /
  `create_invitation` / `accept_invitation`. Host gates + the aarch64 APK build.
- **Stage 2 — Kotlin.** The **"Introduce … to …"** initiator (extends the vouch
  picker); **Carol's** approve/decline surface; **Alice's** connect/decline
  surface; contact-from-introduction (provenance + "introduced by" from genesis);
  driver hooks.
- **Stage 3 — three-device on-device validation.** Bob introduces Carol↔Alice on
  three physical/emulated identities over Tor: Carol approves + mints, Bob relays,
  Alice connects, and **both** new contacts show Bob's named provenance. (This
  also closes the 3-party display gap D0036 left open.) Reconcile D0036 §7 /
  D0034 §7 / design brief §5.2 / status.

Each stage is its own host-gate-clean, propose-commit unit.

## Reversibility

- **Introducer-initiated** is extensible to requester-initiated additively (one
  extra opening message); the consent + relay machinery is shared.
- **Reuse-`Attest`** keeps the op schema closed; an `introduction` op-type remains
  an additive option if a future need (e.g. non-repudiable introduction records)
  appears.
- **The key-10 field** is a permanent, optional, omitted-when-absent wire
  commitment (the `read_up_to` / `vouch` precedent) — no migration before the
  first introduction exists.
- **Dual consent** is the load-bearing security property; relaxing it would
  reintroduce the rejected fork (§2) and is a high bar.

## Cross-references

- [D0036 — provenance annotation](D0036-provenance-annotation.md) — §7 deferred
  this connection-making layer; the vouch primitive (`build_vouch` /
  `ingest_vouch` / `provenance_for`) reused as the trust half; §3 the two-layer
  authentication; §6 the named depth-1 display reused for the new contacts.
- [D0034 — group chat scope](D0034-group-chat-scope.md) — §7 the
  compartmentalization-vs-connection risk that mandates the dual consent + the
  off-by-default default; §4 provenance-not-reputation.
- [D0035 — trust-graph activation](D0035-trust-graph-activation.md) — §1 the
  collapsed single-key identity the vouches are rooted at; §7 the master hierarchy
  deferral inherited here.
- [D0032 — read receipts](D0032-read-receipts.md) — the `MessageEnvelope`
  control-message pattern the key-10 field mirrors.
- [D0026 — cairn-simplex-adapter](D0026-cairn-simplex-adapter.md) — the
  `create_invitation` / `accept_invitation` pairing primitives the relay reuses;
  the `MessageEnvelope` recv dispatch the key-10 field extends.
- [design brief §5.2](../design-brief.md) — the trust-graph "opt-in introductions"
  this realizes.
