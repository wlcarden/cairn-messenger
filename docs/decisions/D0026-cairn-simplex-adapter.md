# D0026 — cairn-simplex-adapter: SimplOxide-sidecar transport + Cairn message envelope per D0020 §1

**Status:** Accepted
**Date:** 2026-05-29
**Revised:** 2026-05-30 — re-anchored under D0020 §1 (see Revision note)
**Revised:** 2026-06-01 — SimplOxide carrier (`CryptoFile`/XFTP, uniform) + message-number ownership + published-crate coordinates (see Revision note 2026-06-01). The `=0.11.0` pin + the `SimploxideTransport` body remain deferred per §12.

## Revision note (2026-05-30)

The original 2026-05-29 version of this document specified a **project-owned Rust SMP client + a project-owned reimplementation of the SimpleX double-ratchet derivative.** That contradicted [D0020](D0020-integration-architecture.md) §1, which had already chosen the SimplOxide-client-against-a-SimpleX-Chat-CLI-sidecar model — and worse, the original D0026 re-selected the exact option **D0020 §1.8 had already considered and rejected** ("Clean-room SMP-only Rust implementation"). The original D0026 was written without engaging D0020 — a process error.

The contradiction was resolved in favor of D0020 after a security analysis (recorded in the project log). The pure-Rust SMP path **fails the security-benefit test** decisively:

- **The alternative is Haskell, which is memory-safe.** So there is no memory-safety argument for a Rust reimplementation; both are memory-safe. The usual pure-Rust security edge does not apply on this axis.
- **Reimplementing the double-ratchet is a net security LOSS.** SimpleX's PQ-augmented double-ratchet (sntrup761) is non-standard, has no off-the-shelf Rust crate, and a solo from-spec reimplementation with zero deployment history is the canonical "don't roll your own crypto" failure mode. A ratchet state-machine bug silently breaks forward secrecy or post-compromise security — the exact properties the user trusts the tool for. The SimpleX reference ratchet has Trail of Bits audit + years of field deployment. Design brief §3.4 already commits the principle: "trust widely-deployed analyzed primitives, do not invent."
- **D0020 §1.8 had already priced this:** "~3-6 person-months for text-only 1:1 ... reimplementing the PQ ratchet alone is multi-month work." The brief's §6.3 + §10.4 sustainability arithmetic does not have that slack at v1.

This document is therefore **downstream of D0020**: D0020 §1 owns the integration-model decision (SimplOxide sidecar); this document specifies the `cairn-simplex-adapter` crate surface that consumes it. **The surviving Cairn value-add from the original — the application-layer message envelope (canonical-CBOR + COSE_Sign1 + AAD `cairn-v1-message-envelope` + `prior_envelope_hash` chain), the size-bin padding, and the per-conversation record-ids — is preserved**, because those are Cairn's own application-layer concerns that ride INSIDE whatever transport SimpleX provides. What is removed is the project-owned SMP wire implementation and the project-owned ratchet; those delegate to SimplOxide / SimpleX Chat.

## Revision note (2026-06-01) — SimplOxide carrier, message-number ownership, published-crate coordinates

A **pre-pin design resolution.** Pinning `simploxide-client` (a D0018 §1/§9.1 coordination event) and implementing the concrete `SimploxideTransport` body remain deferred to a CLI-present, audit-capable cycle per §12. But three design questions are answerable NOW — from reading the published `simploxide-client` v0.11.0 source — and resolving them before the pin de-risks that later cycle. The carrier choice is the headline (decided: **`CryptoFile`/XFTP, uniform**); the message-number and crate-coordinate findings ride along because the same investigation surfaced them.

### (a) Carrier: every Cairn envelope rides SimpleX as a binary `CryptoFile` (XFTP), uniformly

SimplOxide's send surface is `ClientApiExt::send_message<CID: Into<ChatId>, M: MessageLike>`. `MessageLike` resolves to either a text message (`String` / `Text` → `make_text`) or a file (`File` / `CryptoFile` → `make_file`). Cairn's envelope is opaque signed bytes carried in SimpleX's `payload` (§2.2), so the only real choice is **text vs. file**:

- **Text is disqualified by size.** A text message must fit one SMP block (~16 KB). Cairn's size-bin padding (§3) tops out at the **65536-byte bucket**, and even the 16384 bucket — base64-armored to sit in a UTF-8 text field (~33% inflation → ~21.8 KB) — exceeds a single block. Text would force **per-bucket carrier branching** (small buckets as text, large buckets as file), which leaks the bucket class in the carrier type and doubles the recv path.
- **`CryptoFile` (XFTP) is size-robust and uniform.** XFTP encrypts + chunks the file content and transfers it via XFTP relays independent of the SMP block size, so **all** buckets (including 65536) ride one code path. It is **binary** — no base64 inflation — so the transferred object size equals the padded bucket size exactly (see (b)). And it gives a **single uniform recv path** (always a received file), removing the text/file branch.

**Decision:** all Cairn messages ride as a `CryptoFile` whose content is the COSE_Sign1-signed, size-bin-padded envelope bytes (§2.1), regardless of bucket. Uniformity is itself a metadata property: Cairn's own traffic never varies carrier type by message size.

**Cost (recorded, not hidden):** uniform `CryptoFile` pays a per-message XFTP overhead — a relay upload on send + a relay download on recv, plus latency — even for a one-word message that would otherwise fit a text block. This is accepted at v1 in exchange for size-robustness + carrier uniformity, and is **revisitable against pilot-device latency** (a hybrid small-as-text path would buy latency back at the cost of reintroducing the carrier-type-leaks-bucket-class concern above — so any such revisit must re-pad small messages up to a single uniform text size, not branch on the natural size).

### (b) §3 padding maps directly onto XFTP object size; the observation surface shifts to XFTP relays

Because the carrier is binary, the XFTP-relay-observable encrypted-object size **is** the padded bucket size — §3's bucketing property holds end-to-end with no base64 distortion. The shift to note: envelope content now traverses **XFTP relays**, a different observation point than SMP message queues. Both are SimpleX-network infrastructure and both route through the shared C-Tor proxy (§8), so the _network-level_ adversary model is unchanged; the relay sees padded-bucket-sized encrypted objects, not message bodies. This is a documented property, not a regression — §3 already scopes the size-bin defense to metadata-fingerprinting and explicitly NOT to traffic-flow analysis (the Tor threat model).

### (c) The per-`(sender, recipient)` message number is CAIRN's (chain-derived), NOT SimpleX's chat-item id

§3.2 / §4 key the `MESSAGES` record-id on a per-pair `message_number`. The §1.3 seam note ("the transport assigns the per-`(sender, recipient)` message number … carried back through the seam") is **corrected here.** SimplOxide's `send_message` returns a `NewChatItemsResponse` carrying a **chat-item id that is local-database-global-monotonic — not per-pair-contiguous and not zero-based.** Using it as the record-id number would break the committed `rehydrate_chain` (`adapter.rs`), which walks per-pair numbers `0, 1, 2, …` until the first gap and depends on that contiguity to reconstruct the `prior_envelope_hash` cursor after a restart. The correct source is **Cairn's own chain position**: the next number is the rehydrated `last_message_number + 1` (0 at genesis), which the adapter already reconstructs from `MESSAGES`. SimpleX's chat-item id remains usable as a SimpleX-layer ACK / ordering token, but it is **not** Cairn's `message_number`.

**Deferred implementation consequence:** the internal `SidecarTransport` seam currently returns the number (`send -> u64`, `recv -> (u64, bytes)`) on the now-corrected "assigned by the ratchet" premise. When `SimploxideTransport` lands, number assignment moves into the adapter (derived from chain state) and the seam's number return becomes vestigial — drop it to `send -> ()` / `recv -> bytes`. Tracked with the §12 implementation step. The mock-backed tests are unaffected: `MockSidecarTransport`'s per-connection counter coincidentally satisfies both readings because the mock's send and recv share one in-memory wire (a luxury the real two-device transport does not have, which is exactly why the number must be Cairn-derived in production).

### (d) Published-crate coordinates (supersede the §1.1 placeholder)

The crate is published as **`simploxide-client` v0.11.0** (Apache-2.0 / MIT). The WebSocket feature is **`websocket`**, NOT `ws` as §1.1 / §1.3 and the crate-level docs currently say; the `cli` feature is default-on. The exact `=0.11.0` pin is the deferred coordination event (run with `cargo-audit` + `cargo-deny` in a tool-equipped environment per §12); this note records the coordinates so that pin is mechanical when the cycle runs. The upstream integration-model owner, **D0020 §1/§1.1, was corrected 2026-06-01** (its own revision note: `websocket`, not `ws`). The one remaining `ws` → `websocket` correction site is the crate doc at `src/sidecar.rs:17`, to fix at the pin cycle alongside the `SimploxideTransport` body. Within this document, §1.3 is corrected in place by its appended note and §1.1 records the original (now superseded by this note); `src/lib.rs` does not name the feature.

## Context

D0018 §8.6 enumerates `cairn-simplex-adapter`. D0020 §1 decides the SimpleX integration model: **`simploxide-client` (with `ws` feature) talking over loopback WebSocket (`127.0.0.1:5225`) to an unmodified SimpleX Chat CLI binary bundled as a per-ABI native asset and run as an Android `ForegroundService` child process.** D0020 §1.10 defines the `cairn-transport` trait that abstracts the four SimpleX properties Cairn depends on.

This document specifies the `cairn-simplex-adapter` crate surface that realizes D0020 §1:

1. The `Transport` trait implementation wrapping SimplOxide (per D0020 §1.10).
2. The Cairn application-layer message envelope that rides as the opaque `payload` SimpleX transports.
3. The size-bin padding policy per design brief §3.3.
4. The per-conversation record-id derivation for `RATCHET_STATE` + `MESSAGES` storage.
5. The group-membership-minimization architectural property.
6. The async surface + `RetryBudget` reuse + failure modes.

This document does NOT re-decide:

- **The SimpleX integration model.** D0020 §1 owns it (SimplOxide sidecar; clean-room SMP rejected per §1.8).
- **The double-ratchet.** SimpleX / SimplOxide owns it. Cairn does not reimplement it. This is the central correction of the revision.
- **The SMP wire protocol.** SimplOxide's typed API + the CLI sidecar own it; the upstream-sync mechanism (D0020 §1.3) keeps it current.
- **The `ForegroundService` lifecycle for the CLI child process.** D0020 §1.6 + Android-shell concern.
- **Briar (the v1.5 second transport).** Separate D-doc; the `Transport` trait (D0020 §1.10) is the seam that admits it without disturbing `cairn-crypto` / `cairn-envelope` / `cairn-trust-graph` / `cairn-recovery`.

## Decision summary

| Concern                           | Decision                                                                                                                                                                       | Rationale link |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------- |
| **Integration model**             | SimplOxide client over loopback WebSocket to the SimpleX Chat CLI sidecar per D0020 §1. NOT a project-owned SMP client                                                         | §1             |
| **Double-ratchet**                | SimpleX / SimplOxide owns it (PQ-augmented, sntrup761). Cairn does NOT reimplement it                                                                                          | §1             |
| **Crate seam**                    | `cairn-simplex-adapter` implements the D0020 §1.10 `Transport` trait (`create_invitation` / `accept_invitation` / `send` / `recv`) over SimplOxide                             | §1             |
| **Cairn message envelope**        | Canonical-CBOR per D0018 §2.3, `COSE_Sign1` per D0018 §2.1, signed under D0006 §9's three-hop chain, AAD `cairn-v1-message-envelope` per D0006 §8. Rides as the `send` payload | §2             |
| **Envelope ↔ transport boundary** | Cairn's signed envelope is the opaque `payload` SimpleX's E2EE transport carries. Two orthogonal layers: SimpleX ratchet (FS + PCS on-wire) wraps Cairn's signed envelope      | §2             |
| **Size-bin padding**              | Power-of-2 buckets {256, 1024, 4096, 16384, 65536} applied to the Cairn envelope BEFORE handing to SimplOxide's `send`                                                         | §3             |
| **Storage record-ids**            | `RATCHET_STATE` is SimplOxide's concern (the CLI persists ratchet state); Cairn's `MESSAGES` history keyed by `(sender, recipient, message_number)` per §4                     | §4             |
| **Group-membership minimization** | Per-message single-recipient envelope field — architectural at v1 even though v1 ships 1:1 per D0004                                                                           | §5             |
| **Server selection**              | SimplOxide config; default to the SimpleX network's published relays; self-hosting supported. v1 bundled default per release config                                            | §6             |
| **Async surface**                 | All I/O `async fn`; `RetryBudget` re-exported from `cairn-sigsum-client` per D0023 §5.3                                                                                        | §7             |
| **Tor composition**               | The CLI sidecar's outbound traffic routes through the C-Tor SOCKS proxy (D0020 §2.2 + D0025); Cairn-Rust talks to the CLI over loopback WebSocket, not raw Tor                 | §8             |
| **Failure surface**               | `SimplexAdapterError` per D0018 §4.2; typed by layer (transport / sidecar / envelope / storage / padding); no ciphertext or peer strings in error bodies                       | §9             |

---

## 1. Integration model + the Transport trait seam

### 1.1 Decision

`cairn-simplex-adapter` consumes **`simploxide-client` (with `ws` feature)** to talk to the SimpleX Chat CLI sidecar over loopback WebSocket at `127.0.0.1:5225` per D0020 §1.1. It implements the D0020 §1.10 `cairn-transport::Transport` trait so that the rest of the Cairn core (and the v1.5 Briar adapter) couple to a transport-agnostic seam rather than to SimpleX directly.

```rust
// Implements the D0020 §1.10 trait:
impl Transport for SimplexAdapter {
    fn create_invitation(&self) -> Result<Invitation, SimplexAdapterError>;
    fn accept_invitation(&self, inv: Invitation) -> Result<ConnectionId, SimplexAdapterError>;
    async fn send(&self, conn: ConnectionId, payload: &[u8]) -> Result<(), SimplexAdapterError>;
    async fn recv(&self, conn: ConnectionId) -> Result<Vec<u8>, SimplexAdapterError>;
}
```

The `payload` in `send` / `recv` is Cairn's signed, padded message envelope (§2 + §3). SimplOxide handles the SMP wire protocol, the double-ratchet (FS + PCS), queue lifecycle, and out-of-band invitation flow.

### 1.2 Rationale

Per D0020 §1.3 + §1.8 the integration-model rationale is settled (license isolation; upstream-sync; Haskell-toolchain avoidance; clean-room SMP rejected). At the crate-surface level:

1. **The ratchet is delegated to audited upstream — the security win of the revert.** Cairn does not own the forward-secrecy / post-compromise-security machinery; SimpleX's audited PQ-ratchet does. Cairn's TCB shrinks by exactly the surface that is hardest to get right.
2. **Cairn keeps its genuine value-add.** The application-layer signed envelope (device key under capability token per D0006 §9, AAD domain separation per D0006 §8, the `prior_envelope_hash` chain) is Cairn's contribution and rides as the opaque payload. This is the layer auditors should scrutinize as Cairn's — and it is small, declarative, and canonical-CBOR-encoded.
3. **The `Transport` trait keeps the coupling boundary clean** per D0020 §1.10 — admits Briar at v1.5 without changing the crypto/envelope/trust-graph/recovery crates, and admits a mock transport for `cairn-cli` integration tests without the CLI sidecar.

### 1.3 What "the adapter" actually is

`cairn-simplex-adapter` is a **WebSocket client of the CLI sidecar + an envelope-construction/parse layer**. It is NOT a protocol implementation. Its security-critical surface is exactly: (a) constructing + signing the Cairn envelope correctly, (b) padding it correctly, (c) verifying inbound envelopes correctly, (d) the typed error surface. The SMP wire + ratchet correctness belongs to SimpleX.

> **Revision 2026-05-31 — the envelope flow is implemented over an internal `SidecarTransport` seam; the SimplOxide WebSocket transport is deferred.** §1.1 specifies the production transport as `simploxide-client` (with `ws`). That crate is not yet available to this build, so the dependency was **inverted** (the move D0026 §1.2's "admits a mock transport … without the CLI sidecar" already anticipated): an internal `SidecarTransport` trait (`src/sidecar.rs`) abstracts the raw byte transport BELOW the Cairn envelope, and `SimplexAdapter<T>` is generic over it. This lets the adapter's security-critical surface — (a)–(d) above — be implemented + tested ONCE, generically: `send` (build → sign → pad → persist → advance `prior_envelope_hash` chain) and `recv` (verify signature/AAD → bind envelope to the expected sender → chain-check → unpad → persist) are exercised end-to-end over an in-memory `MockSidecarTransport` (two-party round-trip, chain-linking, sig/AAD + sender-binding + chain-gap rejection). The transport assigns the per-`(sender, recipient)` message number (§3.2), carried back through the seam (`send -> u64`, `recv -> (u64, bytes)`). The concrete `SimploxideTransport` (the loopback WebSocket to the CLI) is the ONE deferred piece — it returns `NetworkUnreached` pending `simploxide-client`, and slots in behind the same seam with no change to the envelope flow when the crate lands. Per-pair chain state is cached in memory and rehydrated lazily from the `MESSAGES` history on the first chain access after a restart (added 2026-06-01: `rehydrate_chain` walks the contiguous per-pair message numbers and derives the cursor from the last envelope's `next_prior_envelope_hash`, so the `prior_envelope_hash` chain survives process restarts; validated by send- + recv-chain cross-restart tests over the mock transport). **Corrections from the 2026-06-01 revision notes (this blockquote's "deferred / `simploxide-client` / `NetworkUnreached` / `send -> u64`" framing is superseded):** (i) the published feature is `websocket`, not `ws`; (ii) the message number is Cairn-derived (the per-pair chain position), not transport-assigned — so the seam's number return was **dropped** to `send -> ()` / `recv -> Vec<u8>` (the mock's shared-wire counter still satisfied it in tests); (iii) **the transport LANDED on `simploxide-ws-core`, NOT `simploxide-client`** (2026-06-01): the high-level Bot SDK does not compile on the pinned rust 1.85 and has an upstream websocket-config bug, so the adapter uses the low-level raw-WS `simploxide-ws-core` (no MSRV bump, no subprocess). `SimploxideTransport` is now a **real ws-core client** (lazy dial + `/user` handshake + command RPC + event drain + uniform `CryptoFile` carrier, hermetically mock-WS-tested); Cairn owns the simplex-chat command/JSON layer (`src/protocol.rs`). Live two-party wire fidelity is the `integration-tests` gate. See the §12 revision note for the full toolchain×feature probe matrix.

---

## 2. Cairn message envelope

### 2.1 Schema (integer-keyed canonical-CBOR map per D0018 §2.3)

Unchanged from the original D0026 — this is Cairn's application-layer envelope and survives the integration-model correction intact:

| Key | Field                          | CBOR type | Notes                                                                                 |
| --- | ------------------------------ | --------- | ------------------------------------------------------------------------------------- |
| 1   | `version`                      | uint      | v1 = 1                                                                                |
| 2   | `sender_operational_pubkey`    | bstr (32) | D0006 §9                                                                              |
| 3   | `recipient_operational_pubkey` | bstr (32) | D0006 §9                                                                              |
| 4   | `timestamp`                    | uint      | Unix-seconds                                                                          |
| 5   | `prior_envelope_hash`          | bstr      | Empty for first envelope; else SHA-256 of prior envelope's COSE_Sign1 signature bytes |
| 6   | `payload`                      | bstr      | Application-level payload                                                             |
| 7   | `padding`                      | bstr      | Per §3 size-bin padding                                                               |

Signed via `COSE_Sign1` per D0018 §2.1 with the device key (D0006 §9 hop #1), capability-token bytes in the unprotected headers (hop #2), AAD domain tag `cairn-v1-message-envelope` per D0006 §8.

### 2.2 Composition with SimpleX

```
SimpleX SMP queue message (SimplOxide / CLI sidecar owns this + below)
└── SimpleX PQ-augmented double-ratchet ciphertext (FS + PCS; SimpleX owns)
    └── Cairn COSE_Sign1 envelope (canonical CBOR; CAIRN owns — this crate)
        └── Cairn message-envelope payload (key 6)
```

Cairn hands the signed+padded envelope bytes to SimplOxide's `send`; SimplOxide does the ratchet + SMP wire. Inbound, SimplOxide hands Cairn the decrypted envelope bytes via `recv`; Cairn verifies the signature + AAD + chain.

The two layers are orthogonal: a ratchet compromise (SimpleX layer) reveals message content but cannot forge a Cairn envelope (the device-key signature defeats forgery); a device-key compromise (Cairn layer) enables forgery but does not reveal historical ratchet-state content (SimpleX's FS holds on-wire).

> **Revision 2026-06-01 — the carrier is a `CryptoFile` (XFTP), not an in-queue text message.** The "SimplOxide's `send`" above is concretely `send_message` with a binary `CryptoFile`: the padded envelope bytes ARE the file content, transferred via XFTP relays. This is uniform across all size buckets and avoids the ~16 KB SMP-block ceiling that text + base64 would breach at the 16384/65536 buckets. See the 2026-06-01 revision note (a) for the full rationale + cost.

### 2.3 Rationale + chain integrity

`prior_envelope_hash` mirrors D0006 §5's trust-graph chain: a recipient online continuously can detect an attacker using a stolen device key by observing the chain. `next_prior_envelope_hash = SHA-256(COSE_Sign1.signature_bytes)` — same composition as D0023 §1 (Sigsum leaf) + D0024 §5 (release leaf). One audited primitive across the workspace.

Operational-identity addressing (not device-key) means device-key rotation under suspected compromise does not break message chains — the operational identity is stable.

> **Revision 2026-06-01 (FFI/Android signing path) — the external-signer path is now BUILT; the device signature is produced in StrongBox.** On Android the device key (D0006 §9 hop #1) is StrongBox-resident and `NeverExport` (D0020 §3.4), so the cairn-uniffi messaging handle cannot hold a `SigningKey`. Resolved by an `EnvelopeSigner` abstraction (`envelope.rs`): `LocalIdentity` holds `Arc<dyn EnvelopeSigner>` rather than a concrete `SigningKey`, and `MessageEnvelope::sign_with(signer)` builds the `COSE_Sign1` `Sig_structure` Rust-side (binding the AAD domain tag per D0006 §8), hands those bytes to the signer, and assembles the envelope from the returned 64-byte signature — so a hardware signer signs in StrongBox while the key never enters the process. It sits on a new additive `cairn-envelope` `Sign1Builder` external-signer path (`signing_input` + `finalize_with_signature`, D0018 §2.2); `finalize(&SigningKey)` is reimplemented as that path plus an in-process sign, so all three are byte-identical by construction (regression-tested). `impl EnvelopeSigner for SigningKey` keeps the in-process path for the `cairn-cli` demo + the mock-transport tests — the same shape D0023's `TreeLeafSigner` took for the Sigsum leaf. **Built + tested 2026-06-01**; the FFI handle now needs only (1) the cairn-uniffi `HardwareKeySigner → EnvelopeSigner` bridge and (2) the deferred `SimploxideTransport` body (§12). FFI surface design: D0027 §2.4.

---

## 3. Size-bin padding

Unchanged from the original D0026. Power-of-2 buckets {256, 1024, 4096, 16384, 65536}; payloads > 65536 transmit at natural size (documented outlier). Padding bytes from workspace `getrandom` per D0018 §1.7.

**Where the padding sits in the corrected model:** Cairn pads its envelope BEFORE calling SimplOxide's `send`. SimpleX's ratchet then wraps the padded envelope; the SMP-server-observable wire size carries the bucket size + ratchet overhead, not the true message size. This is the same "pad before the transport's E2EE wrapping" property the original D0026 §4.2 specified — the only change is that the wrapping layer is SimplOxide's ratchet rather than a Cairn-owned ratchet.

> **Revision 2026-06-01 — the bucket maps 1:1 onto XFTP object size.** Because the carrier is a binary `CryptoFile` (per the 2026-06-01 note), there is no base64 inflation: the padded bucket size IS the XFTP-relay-observable encrypted-object size. The observation surface for the size-bin defense is the XFTP relay (file objects), not the SMP queue (in-queue messages); both route through the shared C-Tor proxy (§8), so the network adversary model is unchanged.

Per design brief §3.3, this is the metadata-fingerprint defense. It does NOT defend traffic-flow analysis (Tor threat model). Cover traffic is v1.x+.

---

## 4. Storage record-ids

### 4.1 Decision

- **Ratchet state is SimplOxide's / the CLI sidecar's concern.** The CLI persists its own ratchet + queue state in its data directory (`-d /data/data/.../simplex/` per D0020 §1.6). Cairn's `cairn-storage` `RATCHET_STATE` category is therefore NOT used to store SimpleX ratchet state in the corrected model — that was an artifact of the project-owned-ratchet design. (The category constant remains reserved in `cairn-storage` for any future Cairn-owned ratchet, e.g., a v1.5 Briar tier that needs Cairn-side ratchet persistence.)
- **Cairn `MESSAGES` history** is keyed by `SHA-256(sender_operational_pubkey ‖ recipient_operational_pubkey ‖ message_number_be)` per the original §3.2. Cairn persists its own application-level message history (the decrypted envelopes the user sees) in the `MESSAGES` category, decryptable under unlock per D0006 §3.5.

> **Revision 2026-06-01 — `message_number` is CAIRN's per-pair chain position, not SimpleX's chat-item id.** This `message_number` is the per-`(sender, recipient)` contiguous sequence (`0` at genesis, then `last_message_number + 1`) that `rehydrate_chain` reconstructs from `MESSAGES` after a restart — NOT SimplOxide's `NewChatItemsResponse` chat-item id (which is local-DB-global-monotonic and sparse per-pair, and would break the contiguous-walk rehydration). The earlier "assigned by the SMP ratchet, carried through the seam" framing in §1.3 is superseded; see the 2026-06-01 revision note (c).

### 4.2 What changed vs. the original

The original D0026 §3.2 had two record-id schemes (ratchet + messages) because Cairn owned the ratchet. In the corrected model only the `MESSAGES` scheme is Cairn's; the ratchet scheme moves to SimplOxide. The `message_record_id_for` helper survives; the `ratchet_record_id_for` helper is retained in the crate only if a Cairn-owned ratchet lands later (flagged for removal-or-retention at the implementation cycle).

---

## 5. Group-membership minimization

Unchanged from the original D0026 §5. The envelope's `recipient_operational_pubkey` is ALWAYS a single pubkey; a v1.5 multi-recipient broadcast is N independent `send` calls (fan-out), group membership in the SENDER's local state, never on the SimpleX queue. v1 ships 1:1 per D0004. Holding the property at v1 means the v1.5 group lift is fan-out orchestration, not schema change.

---

## 6. Server selection

SimplOxide is configured with the SMP server set; default to the SimpleX network's published relays, self-hosting supported per design brief §5.4. The v1 release bundles a default server list (release config); the Android-shell UI MAY accept user-pasted servers at v1.x+. The SimpleX Network Consortium (April 2026, "perpetual, irrevocable" protocol access per D0020 §1.7) is the governance signal that makes the default-relay dependency a tracked-but-acceptable trust placement.

---

## 7. Async surface

All I/O `async fn`; `tokio = "=1.40.0"`. `RetryBudget` re-exported from `cairn-sigsum-client` per D0023 §5.3.

Cancel-safety:

- `send` (one envelope to SimplOxide over WebSocket): cancel-safe — dropping before the CLI ACKs leaves no Cairn-side persistent change; the CLI's own idempotence governs the SMP side.
- `recv` (poll for next message): cancel-safe.
- `create_invitation` / `accept_invitation`: the invitation round-trip with the CLI is cancel-safe at the Cairn level; the CLI owns the queue-creation atomicity.

No `spawn_blocking`: the WebSocket client + envelope construction are pure-async + sub-millisecond crypto (one COSE_Sign1 sign/verify per message); no CPU-bound boundary.

---

## 8. Tor composition

Per D0020 §1.2 + §2.2, the SimpleX Chat CLI sidecar is configured to route its outbound traffic through the C-Tor SOCKS proxy at `127.0.0.1:9050` (the proxy `cairn-tor-transport` / D0025 manages). Cairn-Rust talks to the CLI over loopback WebSocket; it does NOT open raw Tor streams for SimpleX traffic. The `TorStream` surface in `cairn-tor-transport` remains available for non-SimpleX direct-Tor needs (e.g., the D0020 §2.4 bridge-manifest fetch).

This is a cleaner composition than the original D0026 §8 (which had the Cairn-owned SMP client calling `TorTransport::connect` directly): in the corrected model the CLI sidecar owns its Tor routing through the shared C-Tor proxy, and Cairn-Rust does not sit on the SMP wire path at all.

---

## 9. Failure modes + typed error surface

`SimplexAdapterError` per D0018 §4.2 — typed by layer; no `Vec<u8>` ciphertext, no key bytes, no peer strings:

```rust
#[non_exhaustive]
pub enum SimplexAdapterError {
    /// Loopback WebSocket to the CLI sidecar failed after the retry
    /// budget was exhausted.
    Network { retry_budget_used: u8 },

    /// v1 skeleton stub; the SimplOxide-client body lands per §11.
    NetworkUnreached,

    /// The CLI sidecar is not reachable on 127.0.0.1:5225 (service not
    /// started, child process died). Distinct from Network so the
    /// caller can prompt the shell to restart the ForegroundService.
    SidecarUnavailable,

    /// SimplOxide returned an error or unexpected reply shape.
    SidecarProtocol,

    /// The named connection/queue was not found by the sidecar.
    ConnectionNotFound,

    /// The Cairn envelope's signature did not verify against the
    /// peer's operational identity (tamper, or unobserved device-key
    /// rotation).
    EnvelopeSignatureVerifyFailed,

    /// The Cairn envelope's canonical-CBOR decode failed.
    EnvelopeDecodeFailed,

    /// The Cairn envelope's AAD domain tag was not
    /// cairn-v1-message-envelope (cross-protocol substitution).
    EnvelopeDomainTagMismatch,

    /// The peer's prior_envelope_hash chain has a gap.
    EnvelopeChainGap { last_observed_message_number: u64, observed_message_number: u64 },

    /// Padding was malformed.
    PaddingMalformed,

    /// Storage failure for Cairn message history.
    Storage(#[from] cairn_storage::StorageError),

    /// Trust-graph envelope encode/decode failure (device-key +
    /// capability-token verification path).
    Envelope(#[from] cairn_trust_graph::TrustGraphError),
}
```

### 9.1 What changed vs. the original

- Removed `RatchetOutOfSync` + `SmpProtocolViolation` + `QueueNotFound` + `TransportError(TorTransportError)` — these were artifacts of Cairn owning the SMP wire + ratchet + direct Tor connection.
- Added `SidecarUnavailable` + `SidecarProtocol` + `ConnectionNotFound` — the corrected failure modes of talking to SimplOxide / the CLI sidecar.
- The envelope-layer + padding-layer + storage-layer variants survive unchanged (those are Cairn's application layer).

### 9.2 No-error-oracle discipline

All variants carry small scalars or type tags. `EnvelopeChainGap` counters are bounded diagnostic numerics. No ciphertext, key bytes, or peer strings.

---

## 10. Out of scope

1. **The SimpleX integration model** — D0020 §1 (SimplOxide sidecar; clean-room SMP rejected per §1.8).
2. **The double-ratchet** — SimpleX / SimplOxide owns it.
3. **The CLI sidecar `ForegroundService` lifecycle** — D0020 §1.6 + Android shell.
4. **The backup FFI-in-process path** — D0020 §1.9 (activated only if the sidecar proves unworkable on representative pilot devices).
5. **Briar (v1.5 second transport)** — separate D-doc; the `Transport` trait is the seam.
6. **Voice/video, attachments, group chat, read receipts** — v1.x/v2 or UI-policy per design brief §5.4 + §5.6.

## 11. Reversibility

- **SimplOxide → backup FFI-in-process (D0020 §1.9):** tractable; the `Transport` trait insulates the rest of Cairn. The activation criterion is documented sidecar-unreliability evidence on representative devices.
- **SimpleX → Briar (v1.5 second transport):** the `Transport` trait admits it without touching crypto/envelope/trust-graph/recovery.
- **Cairn message envelope schema change:** the HARDEST — once envelopes are emitted at §2.1, the `prior_envelope_hash` chain locks the schema. Additions forward-compat per D0006 §6.4; breaks require coordinated release + conversation-state migration.
- **AAD domain tag change:** effectively a v2 break (invalidates every existing envelope signature).
- **Reverting to project-owned SMP:** the path D0020 §1.8 rejected; would require accepting the ratchet-reimplementation security cost the revision-note analysis rules out. Not a reversal the project would make absent a fundamental change in the SimpleX dependency's viability.

## 12. Implementation status

This document is accepted (revised). The matching `cairn-simplex-adapter` crate skeleton lands as a separate commit. Implementation order:

1. `cairn-simplex-adapter/src/{lib,error}.rs` — pure data + error surface.
2. `cairn-simplex-adapter/src/envelope.rs` — Cairn message envelope per §2 (survives unchanged from the original skeleton). Real + tested.
3. `cairn-simplex-adapter/src/padding.rs` — size-bin padding per §3 (survives unchanged). Real + tested.
4. `cairn-simplex-adapter/src/storage.rs` — `message_record_id_for` per §4 (survives; `ratchet_record_id_for` flagged for removal-or-retention). Real + tested.
5. `cairn-simplex-adapter/src/{sidecar,protocol}.rs` — the `SidecarTransport` impl over `simploxide-ws-core` (the raw WS client) + the simplex-chat command/JSON layer. **Landed 2026-06-01** (see the revision note below): the connection + command-RPC + event-drain machinery is hermetically mock-WS tested; the live two-party flow is step 7.
6. CLI integration in `cairn-cli`: `simplex-send` + `simplex-recv` subcommands against a mock `Transport` for the demo (no CLI sidecar needed for the mock path per D0020 §1.10).
7. SimplOxide integration testing: against a local SimpleX Chat CLI under the `integration-tests` cargo feature per D0023 §10's pattern.

**Removed from the original skeleton:** `ratchet.rs` (the project-owned double-ratchet) is deleted — SimpleX owns the ratchet.

> **Revision 2026-06-01 — SimpleX transport landed on `simploxide-ws-core` (NOT the `simploxide-client` Bot SDK); no MSRV event.** Ahead of the step-5 pin, the published `simploxide-client =0.11.0` subtree was audited in a network-capable environment. A toolchain × feature **probe matrix** (build-verified, not just `cargo tree`) found **two independent blockers** that ruled out the high-level Bot SDK:
>
> 1. **MSRV.** `simploxide-client 0.11.0` does NOT compile on the pinned rust **1.85** — `pub const TTL_MAX = Duration::from_hours(8784)` (`lib.rs:454`, not feature-gated) uses a `const fn` stabilized only on newer rust (~1.87+; simploxide declares no `rust-version`). The earlier resolution-only `cargo tree` audit missed this: **resolution ≠ compilation.**
> 2. **Upstream feature bug.** Even on rust 1.94, the architecturally-correct `websocket`-only configuration fails to compile: `BotBuilder::new` (`ws.rs:325-326`) sets `db_prefix`/`db_key` unconditionally, but those fields are `#[cfg(feature="cli")]`-gated → `E0560`. Only the `cli` (default) config compiles — and `cli` pulls simplex-chat **subprocess management** (`tokio/process`, `extra_args`), which D0020 §1 assigns to the CLI sidecar, NOT to Cairn-Rust.
>
> **Decision: depend on the LOW-LEVEL `simploxide-ws-core =0.2.0` instead.** Its `connect("ws://127.0.0.1:{port}")` → `(RawClient, EventQueue)` is exactly the D0020 §1.1 sidecar-connect model with **no subprocess** (its `cli`/`tokio::process` feature is off by default), and **it (+ its `simploxide-core =0.5.0` dep) compiles on the pinned rust 1.85** — so there is **NO MSRV coordination event**. (The `time` RUSTSEC-2026-0009 advisory is therefore NOT coupled to this transport after all — and it was subsequently **RESOLVED outright** on 2026-06-01 by the separate 1.88 MSRV rotation (D0018 §7.4) plus its paired `serde =1.0.220` / `time 0.3.47` pin bump (§9.1); it is **no longer accept-listed** in `deny.toml` / `.cargo/audit.toml`.) ws-core also **sheds** `simploxide-client` + `simploxide-api-types` + `serde-aux` + `serde-value` + `ordered-float` + `signal-hook-registry` from the message-path trust surface; the cost is that **Cairn owns the simplex-chat command/JSON layer** (`src/protocol.rs`) — squarely this document's "project-owned SMP client" thesis (and the §24-§31 carrier note). New subtree is MIT/Apache (allowlisted), no duplicate versions, `cargo audit` clean; `tokio` stays at the workspace `=1.40.0` pin (cargo selects `tokio-util 0.7.17` + `socket2 0.5.10`) and gains the `sync` feature.
>
> **Landed this session (steps 5 + 6):**
>
> - Workspace + adapter **pins** (`simploxide-ws-core =0.2.0`; `serde` / `serde_json` at the JSON boundary; `tokio` `sync`).
> - `src/protocol.rs` — reference-derived simplex-chat command builders (`/user`, `/_connect <userId>[ <link>]`, `/_send … json <composedMessages>`, `/freceive`) + defensive response/event parsers, unit-tested over reference-shaped fixtures.
> - `src/sidecar.rs` `SimploxideTransport` rewritten over ws-core: lazy dial, `/user` handshake, command RPC, event drain, typed error mapping, + the uniform `CryptoFile` carrier (envelope bytes staged on disk for the daemon's XFTP upload, completed downloads read back). **Hermetic mock-WS-server tests** (`sidecar::mock_ws_tests`) validate the connection + RPC + parse machinery against a localhost WebSocket server.
> - The **message-number-ownership** correction of note (c) below, now IMPLEMENTED: the `SidecarTransport` seam dropped its vestigial number return (`send -> ()`, `recv -> Vec<u8>`); the adapter derives the per-pair number from its chain position (`next_message_number`). Validated by the existing 48-test adapter suite (incl. both cross-restart rehydration tests) over the mock + the `cairn-cli` file-wire demo (step 6, commit `ce1a756`, its `FileSidecarTransport` updated to the numberless seam).
>
> **Still gated on the live SimpleX Chat CLI binary (step 7, `integration-tests`):** the simplex-chat **wire fidelity** — the exact response/event `type` tags, the `CryptoFile` `fileSource` shape, and the offer → accept → `rcvFileComplete` recv lifecycle — is reference-derived and validated ONLY against a live daemon, NOT in the hermetic tests. Per-connection demultiplexing of incoming files is likewise deferred to that cycle (the v1 1:1 group-minimization property, §5, means a single active conversation).
>
> **Revision 2026-06-01 (step 7 — LIVE-VALIDATION GATE CLOSED).** The transport was validated end-to-end against two real `simplex-chat` v6.5.2 CLI daemons over the public SMP + XFTP relays. `tests/live_simplex.rs` (gated behind `integration-tests` + `#[ignore]`) drives the full `SimplexAdapter<SimploxideTransport>`: alice creates an invitation, bob accepts, both await establishment, alice sends a signed + size-bin-padded Cairn envelope as a `CryptoFile`, and bob XFTP-downloads it, verifies it (`COSE_Sign1` + AAD `cairn-v1-message-envelope` + `prior_envelope_hash` chain), and recovers the exact payload — **PASS**. A standalone probe also confirmed a 16384-byte binary `CryptoFile` round-trips XFTP byte-for-byte.
>
> **Wire-format findings (simplex-chat v6.5.2), now ground-truth in `protocol.rs`:** `/user` → `activeUser.user.userId`; `/_connect <userId>` → `invitation.connLinkInvitation.connFullLink`; `/_connect <userId> <link>` → `sentConfirmation`; **establishment is async** — `contactConnecting` then `contactConnected` carrying the usable `contact.contactId`; `/_send @<contactId> json [{msgContent:{type:file},fileSource:{filePath}}]` → `newChatItems` + `sndFileProgressXFTP`/`sndFileCompleteXFTP`; recv = `newChatItems`(file offer with `chatItem.file.fileId`) → **explicit** `/freceive <fileId>` (NOT auto-accepted despite `files:allow:always`) → `rcvFileDescrReady` → `rcvFileComplete`(local path) → read.
>
> **The one real bug the live run forced (a seam correction):** the first-cut transport keyed `ConnectionId` on the _pending_ `pccConnId` from the create/accept response, but `/_send` needs the _established_ `contactId` (a different id, available only at `contactConnected`). Fixed: the `SidecarTransport` seam gained an `await_connection` method (D0020 §1.10 surface change), `accept_invitation` now awaits `contactConnected`, and the `ConnectionId` is the established `contactId`. The `send`/`recv` protocol logic was already correct — the hermetic mock tests had pinned it, so the live failure isolated cleanly to the connection lifecycle. **The gate is closed.** Remaining follow-ups (multi-conversation incoming-file demux; a send-side XFTP-upload-complete await for delivery assurance) are tracked, not blocking.
>
> **Android-transport finding (2026-06-01) — the desktop ws-core path does NOT carry to Android unchanged.** Investigating on-device wiring surfaced that D0020 §1.1's "CLI subprocess" model is blocked on Android: there is **no standalone Android `simplex-chat` CLI binary** (the release artifacts are the full `.apk` + Linux-glibc/macOS/Windows CLIs; `simplex-chat-libs` has no Android assets). The official Android integration is JNI `libsimplex.so` in-process — D0020 §1.9's backup. The ws-core seam (D0020 §1.10) accommodates this as a **second `SidecarTransport` impl** backed by `simploxide-ffi-core` (whose async API mirrors ws-core); `libsimplex` / `simploxide-ffi-core` / `simploxide-sxcrt-sys` are AGPL-3.0 (compatible with Cairn's AGPL).
>
> **Android FFI transport LANDED (2026-06-01) — `FfiSidecarTransport`, `#[cfg(target_os = "android")]`.** `sidecar.rs` now factors the seam into (i) a `RawChannel` trait (send-one-command / next-event over raw `String` frames), (ii) a transport-agnostic `flow` (the whole invitation / `contactConnected`-await / `CryptoFile` send-recv lifecycle), and (iii) two channels: `WsChannel` (ws-core, desktop/dev/CI) and `FfiChannel` (`simploxide-ffi-core`, in-process `libsimplex`, Android). `FfiChannel::conn()` calls `init(DefaultUser, DbOpts)` instead of `connect(ws://…)`; everything below is shared. **The dependency is declared ONLY under `[target.'cfg(target_os = "android")'.dependencies]`** so the x86_64-linux CI host (clippy/test `--all-features`) never builds `simploxide-sxcrt-sys` (`links = "simplex"`), whose build script hard-fails without a `libsimplex` bundle (`SXCRT`/static/autobuild). The cfg is both the architecture (in-process path only exists on Android) and the CI guardrail.
>
> **Two findings the actual build + a host RUNTIME PROOF forced (the prior "compile-validate" had run on the default 1.94.1, masking both):**
>
> 1. **Response-envelope divergence.** The same simplex-chat core wraps replies differently per transport: ws-core/CLI uses `{"corrId","resp":{…}}`, but the in-process FFI uses `{"result":{…}}` (no `corrId`), for **both** responses and events. The inner `{"type":…}` object is identical. So "reuse `protocol.rs` verbatim" was wrong at the _frame_ layer; fixed by teaching `Resp::from_frame` to accept `resp` OR `result` (one line; both are real envelopes of the same core), keeping the shared `flow` transport-agnostic. Regression-locked by `protocol::tests::parses_ffi_result_envelope`.
> 2. **MSRV correction: the FFI build needs rust 1.91, NOT 1.88 — and the bump is DONE.** `simploxide-sxcrt-sys 0.2.0`'s LIB uses `Duration::from_mins` (stable since 1.91, `duration_constructors`); its `build.rs` `let`-chains (the earlier "≥1.88" claim) were a _necessary-but-insufficient_ part. The workspace MSRV was therefore bumped **1.88 → 1.91** (the second deliberate rotation, D0018 §7.4) — `sxcrt-sys` + the `cfg(target_os = "android")` `FfiSidecarTransport` now compile for `aarch64-linux-android` ON THE PINNED toolchain (they did not on 1.88). All four host gates re-pass on 1.91 (churn: a few mechanical `collapsible_if`/`is_multiple_of`/`write!().expect()` lint fixes). Host builds were never blocked (target-gated off).
>
> **Validation done here (this x86_64 box):** (a) host `--all-features` on the pinned 1.88 confirms `sxcrt-sys` is never built (CI-safe) + the ws-core path + the shared `flow` still pass all tests; (b) a **host runtime proof** booted in-process `libsimplex` **v6.5.3.0** against the official x86_64-glibc bundle and exercised the exact ffi-core API + commands the transport uses — `init` → `/user` (userId, profile) → `/_connect` (a real `simplex:/invitation#…@smp8.simplex.im/…` link); (c) an `aarch64-linux-android` type-check (rust 1.94.1 + NDK r25 clang + `SXCRT`) compiles `cairn-simplex-adapter` incl. the `ffi` module.
>
> **APK native bundling + link LANDED (2026-06-01) — the Android build links + bundles `libsimplex`; only the on-device RUN is environment-blocked here.** Findings from doing it:
>
> - **No official checksummed android-`libsimplex` artifact exists.** `simplex-chat-libs` ships linux/macOS/Windows only; the sole source is extracting from the official **SimpleX APK** (`simplex.apk` / `simplex-aarch64.apk`, v6.5.2). **arm64-v8a ONLY** — SimpleX publishes no x86_64 build (arm64 + armv7), and Cairn does not cross-build GHC (D0020 §1.8).
> - **The Android `libsimplex.so` is STATIC-GHC** — one ~191 MB `.so` with the GHC runtime baked in (`readelf` NEEDED = only `libc`/`libm`/`libdl`), NOT the ~161 separate dynamic `libHS*.so` the desktop bundle ships. So bundling is **one lib**, not 162. It exports the full `sxcrt-sys` C API (`chat_*` + `hs_init*`, verified).
> - **The `cairn-uniffi` cdylib links it.** `cargo ndk` (NDK r28) cross-compiles `libcairn_uniffi.so` for `aarch64-linux-android` with `SXCRT=<libs>/arm64-v8a` → the cdylib gains `DT_NEEDED: libsimplex.so` (verified in + out of the APK). `android/app/build.gradle.kts` wires it: arm64-v8a only, `cargoNdk` arm64 target, and an operator-provided `-PcairnSimplexLibsDir` added to `jniLibs` (so the 191 MB binary ships in the APK without being committed). Result: a **210 MB arm64 debug APK** with `lib/arm64-v8a/{libcairn_uniffi.so, libsimplex.so}`.
> - **On-device RUN is blocked on an x86_64 host** (a hard environment constraint, not a code issue): the modern emulator (QEMU2) refuses arm64 images on x86_64 ("system image must match host architecture"), and there is no x86_64 `libsimplex` to run instead. So **on-device validation requires a real arm64 Android device** — unavailable in this build environment.
> - **Version skew (tracked):** the APK ships `libsimplex` **v6.5.2**; `sxcrt-sys 0.2.0` + the host runtime proof used **v6.5.3** — minor, link-compatible (all symbols present), but a real-device run should confirm.
>
> **Still deferred (needs real arm64 hardware OR is a v1.x lever):** the on-device run (FFI init + a two-party message on a physical arm64 device); routing the in-process daemon through the C-Tor SOCKS proxy (a post-init `/network socks=…` command, D0020 §2.2); an encrypted DB (`DbOpts::encrypted`); multi-conversation demux. The `cairn-uniffi` handle's per-target transport selection is **DONE** (D0027 §2.4); the MSRV prerequisite is **DONE** (finding #2). So ws-core remains the **desktop/dev/CI** transport (live-validated above); the Android FFI transport is now **code-complete + host-runtime-proven + arm64-link-validated + APK-bundled**, pending only a real-device run.

---

## 13. Cross-references

- [D0020 — integration architecture](D0020-integration-architecture.md) — §1 owns the SimpleX integration model (SimplOxide sidecar) this document implements; §1.8 rejected the clean-room SMP path the original D0026 erroneously re-chose; §1.10 the `Transport` trait seam; §1.7 Consortium governance signal; §2.2 the shared C-Tor proxy
- [D0003 — implementation language](D0003-implementation-language.md) — Rust core
- [D0004 — v1 scope cuts](D0004-v1-scope-cuts.md) — 1:1 v1; Briar v1.5
- [D0006 — cryptographic envelope](D0006-cryptographic-envelope.md) — §3.5 on-wire FS (SimpleX's) vs at-rest decryptable-under-unlock; §5 prior_hash schema; §8 AAD domain tags; §9 three-hop verification
- [D0018 — engineering foundation](D0018-engineering-foundation.md) — §1.6 memory hygiene; §2.1 COSE_Sign1; §2.3 canonical CBOR; §4.1 async; §8.1 unsafe_code = forbid; §8.6 workspace layout
- [D0022 — cairn-storage layer](D0022-storage-layer.md) — `MESSAGES` category; `RATCHET_STATE` now reserved-not-used per §4
- [D0023 — cairn-sigsum-client](D0023-sigsum-integration.md) — `RetryBudget` reuse per §7
- [D0025 — cairn-tor-transport](D0025-cairn-tor-transport.md) — the C-Tor proxy the CLI sidecar's traffic routes through
- [design brief §5.4 Communications Protocols](../design-brief.md) — SimpleX-as-protocol; double-ratchet derivative properties
- [design brief §3.3](../design-brief.md) — size-bin padding; group-membership minimization
- [docs/network-transport-research.md](../network-transport-research.md) — superseded by D0020 §1 for the integration model (see that doc's corrective header)
