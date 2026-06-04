# D0032 — read receipts: off-by-default, reciprocal, read-only

**Status:** Accepted
**Date:** 2026-06-04

> **Confirmed (2026-06-04):** read receipts ship **OFF by default**, **reciprocal**
> (off = you send none AND display none), and **read-only** (a single peer
> acknowledgement — "read"; "sent" stays the existing XFTP-upload-complete
> indicator). The wire signal is an optional envelope key, so content envelopes
> are byte-unchanged.

## Context

The messaging-legibility unit (D0026 §12) gave each outgoing message a
`SendStatus` (SENDING → SENT/FAILED), with **SENT** meaning the Cairn envelope
reached the XFTP relay (the `send` path awaits `sndFileCompleteXFTP`). What it
could not show is whether the **peer** received or read it — there was no
peer-originated signal. Read receipts add that signal.

For Cairn's audience (activists, journalists, high-risk users), a read receipt
is a **metadata leak**: it tells the sender _that_ you read a message and
_when_ — an online-activity / attention signal an adversary correlating timing
can exploit. So the posture is not the mainstream "on by default": it is
**off by default, opt-in, reciprocal**.

This is downstream of D0026 §2 (the envelope schema it extends) and §3.2 (the
`MESSAGES` chain a receipt rides on). No new crypto; a receipt is a normal
signed + chained Cairn envelope.

## Decision summary

| Concern                 | Decision                                                                                                                                                                     |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Default**             | **OFF.** When off, no read acks are ever sent — byte-for-byte the pre-feature behaviour on the wire (§3)                                                                     |
| **Reciprocity**         | Off = send none **and** display none. You only see others' read-status if you also expose yours — no free-riding on the metadata you're unwilling to emit (§3)               |
| **Scope**               | **Read only.** One peer ack ("read"). No separate "delivered" ack (it would double the peer-originated control traffic over the XFTP/Tor carrier for marginal value) (§1)    |
| **Wire representation** | **Optional envelope key 8 `read_up_to: uint`**, OMITTED when absent — a read receipt is an **empty-payload** chained envelope carrying `read_up_to` (§2)                     |
| **Granularity**         | **Cumulative high-water mark** — `read_up_to = N` acks "I've received everything up to message N from you"; the peer marks its outgoing ≤ N as read (§2)                     |
| **Policy vs mechanism** | The Rust adapter **always** provides the mechanism (`send_read_receipt` + `read_up_to` on recv); the **enabled?** policy lives Kotlin-side (a `SharedPreferences` flag) (§4) |
| **Anti-ping-pong**      | A read-receipt envelope NEVER triggers a read receipt in response (control envelopes are not "messages to read") (§2)                                                        |

## 1. Read-only, cumulative

The peer sends **one** ack kind. "Sent" already exists (the local
`sndFileCompleteXFTP` await = the envelope reached the XFTP relay). A separate
"delivered" ack (the peer's device downloaded + decrypted it) would be a second
peer-originated control envelope — and every Cairn envelope is a full
`CryptoFile`/XFTP upload over Tor, so doubling control traffic for a middle tick
is not worth it in v1. "Read" is the meaningful human signal.

The ack is a **cumulative high-water mark**: `read_up_to = N` means "I have
received everything up to message number N from you." The recipient marks all of
its outgoing messages with number ≤ N as read. Cumulative (vs per-message) means
**one** receipt acks a whole catch-up read, minimising envelopes on the carrier.

## 2. Wire: optional key 8, empty-payload control envelope

The envelope is an integer-keyed canonical-CBOR map (D0026 §2.1, keys 1–7) with
**forward-compatible unknown-key tolerance**. Read receipts add:

```
| 8 | read_up_to | uint | Present ONLY on a read-receipt envelope |
```

**Encoded only when present.** A normal content envelope omits key 8 and so
encodes **byte-identically** to the pre-feature schema — critical because every
envelope is hash-chained (`prior_envelope_hash` = SHA-256 of the prior
signature); adding an always-present key would change every envelope's bytes and
break the chain + persisted history. Canonical order appends key 8 after key 7,
so a receipt envelope is well-formed; old decoders ignore it (the existing
"unknown key 99 tolerated" property).

A **read receipt is a real, signed, chained envelope** with an **empty payload**

- `read_up_to = Some(N)`, sent on the sender→recipient direction. It advances
  that pair's chain like any envelope. It is **not** displayed as a message:
  `load_message_history` already skips empty-payload envelopes (the pairing hello),
  which also covers receipts; the recv path routes a `read_up_to`-bearing envelope
  to read-status handling, not to the message list — and crucially does **not**
  emit a receipt in response, so two clients reading each other cannot ping-pong.

`N` is derived from the **recv-chain high-water** for the peer (the highest
message number received from them), so `send_read_receipt(conn, peer)` needs no
caller bookkeeping — the adapter already tracks it. Acking an envelope number
that happens to be a control envelope is harmless: the mark is monotonic and the
recipient only flips its **content** messages ≤ N.

## 3. Off by default, reciprocal — the privacy contract

- **Off (default):** the client sends **no** `read_up_to` envelopes, and ignores
  any `read_up_to` it receives for display. On the wire this is identical to the
  pre-feature build — zero read-status metadata emitted.
- **On (opt-in):** the client sends a receipt when the user **views** unread
  messages, and displays the read-status the peer reports.

**Reciprocity** (off ⇒ neither send nor display) means a user cannot harvest
others' read-status while withholding their own — you expose exactly as much as
you consume. It also keeps the mental model simple: one switch, symmetric effect.

## 4. Policy vs mechanism split

The Rust adapter (`cairn-simplex-adapter` + the uniffi handle) **always** exposes
the mechanism: `send_read_receipt`, `read_up_to` on received messages, and the
`peer_read_up_to` high-water from `load_message_history` (for reconstructing
read-status when a conversation is re-opened — message numbers are plumbed into
the history records for the ≤ N match). Whether to _use_ the mechanism is a
**Kotlin policy**: a `SharedPreferences` boolean (default false), gating both the
outgoing `send_read_receipt` calls and the display of incoming `read_up_to`. The
setting is a non-sensitive UI preference (it reveals nothing about content), so
it does not need the encrypted store.

## 5. Validation plan + boundary

**Host:** envelope round-trip with/without `read_up_to` + a **byte-identity**
test (a `None` envelope encodes exactly as before — chain safety); adapter tests
(receipt carries `read_up_to`; `load_message_history` reconstructs
`peer_read_up_to` + numbers; a receipt is not surfaced as content) + the aarch64
APK build.

**On-device (two Pixels over Tor):** with receipts **ON**, A→B message, B views →
A's bubble flips to **Read** (and survives an A reopen via reconstruction); with
receipts **OFF** (default), A viewing B's message sends **no** receipt (logcat
shows none) and A shows no read-status (reciprocal).

**Boundary (honest):** the cumulative high-water is a per-pair monotonic mark,
not a per-message timestamped read log; "read" means "the peer's client reported
having received up to here while receipts were on," which is the honest UX. The
SMP wire behaviour of the extra envelope is the same integration-test-gated
carrier as all messaging.

## Cross-references

- [D0026 — cairn-simplex-adapter](D0026-cairn-simplex-adapter.md) — §2.1 the
  envelope schema key 8 extends; §3.2 the `MESSAGES` chain receipts ride; §12 the
  running log entry.
- [D0006 — cryptographic envelope](D0006-cryptographic-envelope.md) — §6.4 the
  forward-compat unknown-key discipline this relies on.
