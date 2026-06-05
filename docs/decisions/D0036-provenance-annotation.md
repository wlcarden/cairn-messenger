# D0036 — provenance annotation: deliberate attestation-sharing + transitive-trust display (depth-1)

**Status:** Accepted (scope + design; implementation staged)
**Date:** 2026-06-04

> **Confirmed (2026-06-04):** the trust graph's transitive layer lands first as
> **provenance annotation**, not connection-making introductions. A contact
> **deliberately vouches** for a peer by sharing their signed `Attest` op (+ their
> capability token) over a new `MessageEnvelope` control field (the read-receipt
> control-message pattern, D0032). The receiver authenticates the **voucher** via
> the envelope signature (a key they already hold from pairing) and the
> **attestation content** via `verify_chain_links`, stores the foreign op (the
> trust-graph store is already issuer-keyed), and surfaces **named, depth-1**
> provenance when it later encounters that peer's key ("Bob — whom you verified in
> person — also verified this key in person"). **No new connections are
> auto-created**, **no new op-type** is added (the vouch reuses `Attest`), and the
> display is **provenance, not reputation** (named contacts, depth-1, never an
> aggregate score). Connection-making introductions, multi-hop transitivity, and
> revocation-freshness propagation are deferred.

## Context

Trust-graph **activation** (D0035) made verification mint a durable, signed,
revocable attestation — but every operation so far is **local**: minted, stored,
and read on one device. D0035 §7 named the next layer — _"transitive trust /
introductions … needs cross-device attestation exchange over the wire + a
trust-path UI"_ — and deferred it. This decision is that layer, scoped to its
smallest threat-model-aligned form.

The product motivation is the demo-user confusion that opened the D0034
discussion: a user expected "verify" to answer _"do people I trust vouch for this
person?"_ Activation answered _"have **I** verified them?"_; provenance annotation
answers the transitive question — but as **accountable provenance**, the framing
D0034 §4 fixed (named, bounded, never a Sybil-gameable count).

**The novelty is cross-device.** For Alice to benefit from "Bob verified Carol,"
Bob's signed attestation must travel to Alice's device and verify there. Two
findings make this tractable without new crypto:

- **The wire already carries control messages.** Read receipts (D0032) ride the
  same `MessageEnvelope` as text, distinguished by an optional field
  (`read_up_to`, key 8) + an empty text payload (`cairn-simplex-adapter`
  `adapter.rs`). A vouch is the same shape with a new field.
- **The store already holds foreign chains.** `cairn-trust-graph`'s store is keyed
  by `(issuer, subject)` (`record_id_for`), so a contact's attestations
  (issuer ≠ me) are naturally distinguishable from my own — no schema change.

The **annotate-vs-connect** fork (confirmed with the maintainer) resolved to
**annotate**: it is the smaller build, reuses `Attest`, and — critically — never
auto-builds the contact graph that endangers source-protection users (D0034 §7).
Connection-making introductions are a separate, larger, opt-in-heavy later unit.

## Decision summary

| Fork               | Decision                                                                                                                                                                                                                                                                    |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Scope**          | **Provenance annotation (display), not connection-making.** A vouch lets the receiver _see_ who vouches for a key; it never opens a connection. Introduce-and-connect is deferred (§7)                                                                                      |
| **The vouch act**  | **Deliberate, sender-initiated, opt-in per vouch.** Bob explicitly vouches for a _verified_ contact to one other contact — never an automatic broadcast of Bob's attestations (which would leak Bob's whole graph). The opt-in is the privacy control (§1)                  |
| **Wire carrier**   | A new optional **`MessageEnvelope` field (key 9)** carrying the vouch (the `Attest` op chain bytes + the voucher's capability token), empty text payload — the D0032 read-receipt control-message pattern (§2)                                                              |
| **Authentication** | **Two layers:** the envelope's `COSE_Sign1` signature authenticates the _voucher_ (a key the receiver holds from pairing); `verify_chain_links` (voucher op-key + carried token) verifies the _attestation content_. Honest claim: "Bob **vouches**," never "verified" (§3) |
| **Op model**       | **Reuse `Attest` — no new op-type.** The "vouch/introduction" semantics live at the wire/exchange layer, not the trust-graph op schema. (`introduction` op-type stays deferred, D0006 §4) (§4)                                                                              |
| **Storage**        | Foreign ops stored under `issuer = voucher` in the existing trust-graph store; the receiver holds no plaintext beyond the signed op + the voucher's op-key (§5)                                                                                                             |
| **Display**        | **Named, depth-1 provenance:** "your verified contacts Bob (in person), Dave (over a channel) vouch for this key." Count-adjacent but **fenced from reputation** (D0034 §4): only the user's _own_ verified contacts, always named, never an aggregate score (§6)           |
| **Privacy**        | A vouch reveals the voucher's edge ("Bob knows Carol") to the receiver — accepted because it is deliberate and per-vouch; the UI tells the voucher what they disclose (§1, §7)                                                                                              |
| **What defers**    | Connection-making introductions; multi-hop (depth > 1) transitivity; revocation/freshness propagation (a stale vouch is not auto-withdrawn); master-rooted trust (§7)                                                                                                       |
| **Staging**        | **Stage 1** Rust + uniffi + wire carrier (vouch send/ingest + provenance query); **Stage 2** Kotlin vouch UI + provenance display + two-Pixel validation (§8)                                                                                                               |

## 1. The vouch is a deliberate, opt-in act

Bob, viewing a contact he has **verified** (Carol), chooses **"Vouch for Carol
to…"** and picks one other contact (Alice). His client sends Alice a single vouch
control message. This is the **opt-in privacy control**: Bob chooses, per vouch,
to reveal to Alice that he knows + has verified Carol. There is **no** automatic
sharing of Bob's attestations — that would leak Bob's entire contact graph to
every contact, the exact de-compartmentalization D0034 §7 warns against. Only a
_verified_ contact is vouchable (vouching for a key Bob himself only TOFU-knows
carries no provenance worth sharing).

## 2. The wire carrier: a `MessageEnvelope` control field

The vouch rides the existing device-signed, chained `MessageEnvelope` as a new
optional **key 9** (`vouch`, a `bstr` of the canonical-CBOR `{op_chain, token}`
structure), with an **empty text payload** — structurally identical to how a read
receipt sets key 8 (`read_up_to`) with an empty payload (D0032). The recv path
dispatches on key 9: a present `vouch` field marks the envelope a vouch control
message (surfaced as provenance, never rendered as a chat bubble). Carrying the
vouch _inside_ the envelope means it inherits the envelope's `COSE_Sign1`
device-signature + `prior_envelope_hash` chaining for free (§3).

## 3. Two-layer authentication; "vouches", never "verified"

A vouch makes **two** distinct claims, verified independently:

1. **"This vouch is really from Bob."** The `MessageEnvelope` is `COSE_Sign1`-signed
   by Bob's device key — the key Alice pinned when she paired with Bob (in the v1
   collapsed identity, operational == device key, D0035 §1). The transport already
   verifies this on every recv.
2. **"Bob attested Carol at strength X."** The carried `Attest` op chain is verified
   by `verify_chain_links(op_chain, bob_token, bob_op_key)` — the same three-hop
   verifier the local classifier uses. The carried capability token satisfies the
   device→token→operational hops; `bob_op_key` is Bob's known contact key.

What a vouch does **not** prove is that Bob's claim is **true** — Bob could vouch
in-person for a key he never met. Alice's confidence is therefore **bounded by her
trust in Bob**. The UI states this honestly: it says **"Bob vouches (in person)"**
— attributed to Bob — **never "verified."** This is D0034 §5(b)'s "the stream is
intact for the key you hold" honesty, applied transitively.

## 4. Op model: reuse `Attest`, add no op-type

The vouch shares Bob's **existing** `Attest(Carol)` op; the
"vouch/introduction" act is a **wire-layer** event, not a trust-graph operation.
This keeps the op schema closed (the `introduction` op-type in D0006 §4 stays
deferred with connection-making introductions, §7) and means the entire
trust-graph crate is unchanged except for the foreign-ingest + provenance-query
surface (§5). Reusing `Attest` is also semantically right: Bob is sharing the
attestation he _already made_, not making a new kind of claim.

## 5. Storing foreign attestations

On a verified vouch, Alice stores Bob's `Attest(Carol)` chain under
`issuer = Bob` in the existing trust-graph store (`store_signed_op`). Because the
store keys on `(issuer, subject)`, foreign attestations never collide with Alice's
own (issuer = Alice). Alice also caches Bob's capability token (keyed by Bob's
op-key) so re-verification on read needs no re-fetch. The receiver persists only
**public, signed** data (the op + the voucher's public key) — no new secret-bearing
surface (the `never_export_gate` discipline, D0027, is preserved).

The new uniffi surface is two methods on the trust-graph handle:

- `ingest_vouch(voucher_op_key, op_chain_bytes, voucher_token_bytes)` — verify
  (against `voucher_op_key` + token) then store; rejects an unverifiable vouch.
- `provenance_for(subject_op_key) -> [{voucher_op_key, strength}]` — every stored
  foreign attestation for a subject, for the display (§6).

## 6. Display: named, depth-1, fenced from reputation

When Alice encounters Carol's key — pairing with her, or viewing a contact whose
key matches — the UI calls `provenance_for(carol_key)` and surfaces, e.g.:

> _Vouched for by your verified contacts: **Bob** (in person), **Dave** (over a
> channel)._

Three guardrails keep this **provenance, not reputation** (D0034 §4):

- **Only the user's own verified contacts** are counted — never a global tally. A
  vouch from an unverified contact is shown weakly or not at all (you have no
  basis to trust their claim).
- **Always named + attributed.** The screen lists _who_ vouched, at _what
  strength_ — the accountable edge — not an anonymous "N people."
- **No aggregate score.** "2 of your contacts vouch" is count-adjacent and stays
  group-local + non-portable; it never becomes a number attached to Carol that
  travels (the D0034 honeypot prohibition). This is the same fence the D0034
  removal-convergence tally sits behind.

This is **depth-1 only**: Alice sees her _direct_ contacts' attestations, not
contacts-of-contacts. Multi-hop paths amplify the honeypot risk and need real
graph traversal — deferred (§7).

## 7. What this does NOT do (deferred, named)

- **Connection-making introductions.** A vouch never carries Carol's connection
  info and never opens a SimpleX connection; Alice still pairs with Carol through
  the normal flow (where the provenance then annotates her). Introduce-and-connect
  is the larger, opt-in-heavy follow-on (the maintainer's deferred fork).
- **Multi-hop (depth > 1) transitivity** — only direct contacts' vouches count.
- **Revocation / freshness propagation.** A vouch is a **point-in-time** snapshot:
  if Bob later revokes Carol, Alice's stored provenance is **not** auto-withdrawn
  (it would need Bob to re-share or a pull mechanism). The display is honest about
  this ("as of when Bob vouched"); live propagation is deferred.
- **Master-rooted trust** (D0035 §7) — vouches are self-rooted, same as the
  attestations they carry.

## 8. Staging + validation

- **Stage 1 — Rust + uniffi + wire carrier.** Add the `MessageEnvelope` key-9
  `vouch` field + send/recv dispatch (`cairn-simplex-adapter` + the messaging
  uniffi surface); add `ingest_vouch` + `provenance_for` to the trust-graph handle
  (verify-then-store foreign chains + the query). Host gates (`cargo fmt` + clippy
  `-D warnings` + `cargo test`) + the aarch64 APK build.
- **Stage 2 — Kotlin + on-device.** The **"Vouch for … to …"** action on a verified
  contact (pick a recipient) + the provenance surface when encountering a vouched
  key; driver hooks; **two-Pixel validation** (Bob vouches Carol to Alice on real
  hardware; Alice's device shows the named provenance); reconcile D0035 §7 /
  D0034 §4 / design brief §5.2 / status.

Each stage is its own host-gate-clean, propose-commit unit.

## Reversibility

- **Annotate-not-connect** is freely extensible upward: connection-making
  introductions add a separate wire flow + the `introduction` op-type without
  changing the vouch primitive (the vouch becomes one component of an
  introduction).
- **Reuse-`Attest`** avoids a schema commitment; adding an `introduction` op-type
  later is additive.
- **The `MessageEnvelope` key-9 field** is a permanent wire commitment (optional,
  omitted-when-absent, so 1:1 text envelopes stay byte-identical — the
  `read_up_to` precedent), but adding it before any vouch exists incurs no
  migration.
- **Depth-1** is reversible to multi-hop on evidence the bounded form is
  insufficient.

## Cross-references

- [D0035 — trust-graph activation](D0035-trust-graph-activation.md) — §7 named this
  layer as the deferred next step; the self-rooted attestations + the
  `TrustGraphHandle` this extends; §1 the collapsed operational == device identity
  the two-layer authentication relies on.
- [D0034 — group chat scope](D0034-group-chat-scope.md) — §4 accountable
  provenance-not-reputation (the display fence); §5(b) the "intact for the key you
  hold" honesty applied transitively; §7 the compartmentalization risk that
  rules out auto-sharing + connection-making here.
- [D0032 — read receipts](D0032-read-receipts.md) — the `MessageEnvelope`
  control-message pattern (optional field + empty payload) the vouch carrier
  mirrors.
- [D0006 — cryptographic envelope](D0006-cryptographic-envelope.md) — §2 the
  `Attest` op reused here; §4 the `introduction` op-type left deferred.
- [D0026 — cairn-simplex-adapter](D0026-cairn-simplex-adapter.md) — the
  `MessageEnvelope` schema + recv dispatch the key-9 field extends.
- [design brief §5.2](../design-brief.md) — the trust-graph capability this
  advances toward "opt-in introductions."
