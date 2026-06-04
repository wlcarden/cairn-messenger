# D0031 — deeper delete-purge: message history + libsimplex connection

**Status:** Accepted
**Date:** 2026-06-04

> **Confirmed (2026-06-04):** when a contact is deleted, also purge its
> Cairn-owned `MESSAGES` history AND tear down the SimpleX-side connection /
> queue — closing the privacy gap that contact-delete (D0026 §12, rename+delete)
> left as a follow-on. Single-commit, on-device-validated on two Pixels.

## Context

Contact delete (the rename/delete unit, D0026 §12) removed only the encrypted
`CONTACTS` row. Two things survived:

1. **The conversation's `MESSAGES` history** — the decrypted Cairn envelopes the
   user saw, persisted per D0026 §3.2 and **decryptable at rest under unlock**
   (D0006 §3.5). Deleting the contact but leaving its plaintext history is the
   real privacy gap: a "deleted" conversation is still fully readable on a seized
   - unlocked device.
2. **The SimpleX-side connection** — the SMP queue + libsimplex's own chat record
   (queue secrets + message metadata in the SQLCipher chat DB). It keeps
   receiving, and holds metadata about a contact the user believes is gone.

This is downstream of D0026 §3.2 (the `MESSAGES` record-id scheme it deletes
from) and D0026 §1.3 (the simplex-chat command layer it extends with `/_delete`).
No new crypto; it adds a delete path across the existing layers.

## Decision summary

| Concern                           | Decision                                                                                                                                                                                                 |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **What the history purge covers** | **Both directed `MESSAGES` chains** — outgoing `me→peer` AND incoming `peer→me` — each a contiguous `0..` walk (mirroring `collect_direction`) calling `storage.delete`; `Ok(false)` ends the chain (§1) |
| **Chain cursors**                 | **Dropped** for the pair (`forget_chain_state`) so a re-pair with the same key restarts at the **genesis** chain, not the purged history's stale `prior_envelope_hash` (§1)                              |
| **SimpleX-side teardown**         | **`/_delete @<contactId> full notify=off`** — `ApiDeleteChat` `full` mode (queue + conversation), **silent** to the peer (§2)                                                                            |
| **Notify the peer?**              | **No (`notify=off`)** — removing a contact must not emit a network signal to them; the privacy default (§2)                                                                                              |
| **Ordering / durability**         | **`MESSAGES` purge FIRST + authoritative** (irreversible local privacy action); **connection teardown best-effort** after — a failure leaves a lingering queue, never un-deletes history (§3)            |
| **Where it lives**                | Rust adapter (`purge_conversation`) + transport (`delete_connection`) + uniffi export + Kotlin `deleteCurrentContact` (cancels the recv loop, purges off-Main, then drops the `CONTACTS` row) (§4)       |

## 1. The local `MESSAGES` purge

`MESSAGES` records are keyed by
`message_record_id_for(sender, recipient, message_number)` (D0026 §3.2) — a
SHA-256 hash, so a peer's records **cannot** be found by scanning the category
(the hash hides the peer). The only enumeration is to **recompute** the ids by
walking `message_number = 0,1,2,…` for both directed pairs until a gap. So
`purge_direction` is the exact `collect_direction` read-walk, but calls
`storage.delete(MESSAGES, id)` and treats its `Ok(false)` (no such row) as the
end of the contiguous chain. Messages are persisted strictly in order (send
numbers are contiguous; the recv chain-gap check rejects out-of-order delivery),
so the contiguous prefix IS the whole chain — the same invariant `rehydrate_chain`
relies on.

`purge_conversation` then calls `forget_chain_state(peer)` to drop the in-memory
send + recv `ChainState` cursors. Without this, a later re-pair with the same
operational key would find a cached cursor still expecting the purged history's
last `prior_envelope_hash` and raise `EnvelopeChainGap`; dropping it restarts the
pair at genesis (empty prior hash, message 0).

## 2. The libsimplex teardown — `full`, silent

`SidecarTransport` gains `delete_connection(conn)`; `flow::delete_connection`
issues `protocol::cmd_delete_contact(id)` = **`/_delete @<id> full notify=off`**,
reference-derived from `simploxide-api-types` 0.9.0 (`ApiDeleteChat` /
`ChatDeleteMode::Full` renderings):

- **`full`** (not `entity`/`messages`) — delete the connection AND the
  SimpleX-side conversation entirely. Cairn keeps its own history separately
  (§1), so the SimpleX layer's copy is pure metadata to shed.
- **`notify=off`** — the deletion is **silent**. The default (`notify=on`) tells
  the peer "you were deleted"; for a privacy-focused messenger, removing a
  contact must emit **no** network signal to them. Silent is the security-aligned
  default.

Wire fidelity for `/_delete` is the same integration-test-gated provenance as
every other command in `protocol.rs` — proven on-device here (§5), not claimed by
a unit test.

## 3. Ordering is the privacy contract

The two halves have asymmetric durability:

- The **`MESSAGES` purge** is local, irreversible, and the privacy action the
  user asked for. It happens **first** and is **authoritative**.
- The **connection teardown** is a network command that can fail (Tor blip,
  relay timeout). It is **best-effort**, attempted after the history is already
  gone. A failure surfaces to the caller but **never un-deletes** the history —
  it leaves a lingering SMP queue, a retriable resource leak (the pre-D0031
  status quo for the queue), not readable content.

So `purge_conversation` = purge both directions → forget chain state → (best
effort) `transport.delete_connection`. A storage failure aborts before any
teardown; a teardown failure is non-fatal to the privacy outcome.

## 4. Surface

- **cairn-simplex-adapter** — `protocol::cmd_delete_contact`;
  `SidecarTransport::delete_connection` + `flow::delete_connection`, implemented
  on `SimploxideTransport`, `FfiSidecarTransport`, and `MockSidecarTransport`
  (the mock records teardowns for assertions); `SimplexAdapter::purge_conversation`
  - `purge_direction` + `forget_chain_state`.
- **cairn-uniffi** — `SimplexAdapterHandle.purge_conversation(connection_id,
peer_operational_pubkey)` (async; validates the 32-byte key; facade-maps
  errors).
- **Android** — `MessagingViewModel.deleteCurrentContact` cancels the contact's
  background recv loop (it is on the connection being torn down), launches
  `purge_conversation` off the Main thread (best-effort), then
  `ContactStore.delete` drops the `CONTACTS` row and navigates home.

## 5. Validation + boundary

**Host gates:** `cargo fmt` + clippy `-D warnings` + 3 new Rust tests
(`purge_conversation_deletes_both_directions_and_tears_down`,
`purge_conversation_resets_send_chain_to_genesis`,
`delete_connection_issues_delete_command` asserting `/_delete @42 full
notify=off`) + the aarch64 APK build (the `#[cfg(target_os="android")]`
`delete_connection` impl + the regenerated `purgeConversation` binding).

**On-device (two Pixels over bundled Tor):** A paired with B
(`CONNECTED connId=4`), sent a real message (`sndFileCompleteXFTP`), then deleted
the contact. Logcat showed the full purge path in order — `deleteCurrentContact`
→ `contact … deleted (history+connection purge requested)` →
`cairn-smp: delete_connection tearing down conn=4` → `cmd '/_delete' →` →
`contacts: 0` → **`cmd '/_delete' → ok`** (real on-device libsimplex 6.5.x
**accepted** the command) — and the home returned to "No conversations yet", app
stable.

**Boundary (honest):** the peer-side effect of `notify=off` (B is genuinely not
told) is not asserted between two cooperating phones; the validated parts are the
local purge + the daemon-accepted teardown, consistent with the project's
integration-test verification boundary for SMP wire behaviour.

## 6. Follow-up (2026-06-04): re-pair-after-one-sided-delete chain re-anchor

§1's `forget_chain_state` reset only the **deleter's** chain to genesis. The
read-receipts validation surfaced the other half: after a **one-sided** delete (A
purges B; B does NOT purge A), the two sides' `prior_envelope_hash` chains are
asymmetric — A is genesis, B stays advanced (its cursor rehydrates from B's
retained `MESSAGES`, D0026 §3.2). On a re-pair this desyncs **both** directions:

1. B's pairing hello chains from B's stale (advanced) send cursor, so A's
   `recv_learning_sender` raised `EnvelopeChainGap` → **A never completed the
   re-pair** (the reported "re-adding a deleted contact silently fails to
   connect").
2. After connecting, A's genesis-restarted SENDs (A purged → empty
   `prior_envelope_hash`) did not link to B's stale steady-state recv chain → the
   A→B direction would have **silently dropped**.

**Fix — re-anchor the chain, only on the pairing handshake.** The first envelope
of a (re-)pairing has no prior to link against, so `recv_learning_sender` now
runs a re-anchoring tail (`finish_recv_reanchor`) that accepts the envelope
regardless of its `prior_envelope_hash` and anchors the recv chain to it
(persisting at the receiver's CURRENT position, so the non-deleter **appends** to
its retained history, never overwrites). Steady-state `recv` keeps the strict
chain-gap check — so the D0026 §2.3 stolen-key-detection property is **fully
preserved for the ongoing conversation** (a forger cannot trigger a mid-stream
re-anchor; re-anchoring only happens on an explicit pairing handshake, after which
manual key re-verification, D0006 §70, is the human check). The Android shell
routes **both** sides' first recv of a fresh pairing through the learning path:
the inviter already does (to learn the acceptor); the acceptor now adds its new
connId to a `reanchorFirstRecv` set so its first `receiveLoop` recv re-anchors
(binding the re-learned sender to the expected peer), then resumes strict `recv`.
A **resume** (saved contact, not a fresh pairing) is never added, so it keeps the
strict steady-state recv.

**Why not the one-line shared-tail relaxation.** Relaxing the shared `finish_recv`
to accept a genesis-prior "restart" mid-stream would fix both directions in ~5
lines, but it would hand a stolen-key forger the exact escape hatch §2.3 closes
(send a `prior=empty` envelope → masked as a re-pair). Confining the re-anchor to
the handshake path avoids that.

**Host gates:** `cargo fmt` + clippy `-D warnings` + a new
`repair_after_one_sided_delete_round_trips_both_directions` test (full two-way
round-trip after a one-sided purge) alongside the unchanged
`out_of_chain_envelope_surfaces_chain_gap` (still asserts steady-state `recv`
rejects an empty-prior orphan — the §2.3 property, now proven preserved) + the
aarch64 APK build.

**On-device (two Pixel 6 / GrapheneOS over bundled Tor):** the full reported
repro. A↔B paired and exchanged a message each way (the acceptor's re-anchoring
first recv is the live-path regression — B received A's message with no gap),
then A deleted B one-sided (`contacts: 0`). On the **re-pair** (A re-invites, B
re-accepts while still holding A with advanced chains), A's logcat showed
`LEARNED` + `CONNECTED` with **no `EnvelopeChainGap`** — the exact failure before
the fix — and **both directions then flowed**: B received A's genesis-restarted
send (`RECV len=10`, Direction 2 / the symmetric fix) and A received B's reply
(`RECV len=10`). Before the fix, A never completed the re-pair (the reported "fails
to connect"), and even had it connected, A→B would have silently dropped.

## Cross-references

- [D0026 — cairn-simplex-adapter](D0026-cairn-simplex-adapter.md) — §3.2 the
  `MESSAGES` record-id scheme purged here; §1.3 the simplex-chat command layer
  `/_delete` extends; §12 the running log entry for this landing.
- [D0006 — cryptographic envelope](D0006-cryptographic-envelope.md) — §3.5 the
  at-rest-decryptable history this purges.
- [D0030 — change-passphrase](D0030-change-passphrase.md) — the prior at-rest
  lifecycle unit; both use `cairn-storage` mutation primitives.
