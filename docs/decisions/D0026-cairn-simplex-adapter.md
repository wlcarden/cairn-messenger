# D0026 — cairn-simplex-adapter: SimplOxide-sidecar transport + Cairn message envelope per D0020 §1

**Status:** Accepted
**Date:** 2026-05-29
**Revised:** 2026-05-30 — re-anchored under D0020 §1 (see Revision note)

## Revision note (2026-05-30)

The original 2026-05-29 version of this document specified a **project-owned Rust SMP client + a project-owned reimplementation of the SimpleX double-ratchet derivative.** That contradicted [D0020](D0020-integration-architecture.md) §1, which had already chosen the SimplOxide-client-against-a-SimpleX-Chat-CLI-sidecar model — and worse, the original D0026 re-selected the exact option **D0020 §1.8 had already considered and rejected** ("Clean-room SMP-only Rust implementation"). The original D0026 was written without engaging D0020 — a process error.

The contradiction was resolved in favor of D0020 after a security analysis (recorded in the project log). The pure-Rust SMP path **fails the security-benefit test** decisively:

- **The alternative is Haskell, which is memory-safe.** So there is no memory-safety argument for a Rust reimplementation; both are memory-safe. The usual pure-Rust security edge does not apply on this axis.
- **Reimplementing the double-ratchet is a net security LOSS.** SimpleX's PQ-augmented double-ratchet (sntrup761) is non-standard, has no off-the-shelf Rust crate, and a solo from-spec reimplementation with zero deployment history is the canonical "don't roll your own crypto" failure mode. A ratchet state-machine bug silently breaks forward secrecy or post-compromise security — the exact properties the user trusts the tool for. The SimpleX reference ratchet has Trail of Bits audit + years of field deployment. Design brief §3.4 already commits the principle: "trust widely-deployed analyzed primitives, do not invent."
- **D0020 §1.8 had already priced this:** "~3-6 person-months for text-only 1:1 ... reimplementing the PQ ratchet alone is multi-month work." The brief's §6.3 + §10.4 sustainability arithmetic does not have that slack at v1.

This document is therefore **downstream of D0020**: D0020 §1 owns the integration-model decision (SimplOxide sidecar); this document specifies the `cairn-simplex-adapter` crate surface that consumes it. **The surviving Cairn value-add from the original — the application-layer message envelope (canonical-CBOR + COSE_Sign1 + AAD `cairn-v1-message-envelope` + `prior_envelope_hash` chain), the size-bin padding, and the per-conversation record-ids — is preserved**, because those are Cairn's own application-layer concerns that ride INSIDE whatever transport SimpleX provides. What is removed is the project-owned SMP wire implementation and the project-owned ratchet; those delegate to SimplOxide / SimpleX Chat.

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

### 2.3 Rationale + chain integrity

`prior_envelope_hash` mirrors D0006 §5's trust-graph chain: a recipient online continuously can detect an attacker using a stolen device key by observing the chain. `next_prior_envelope_hash = SHA-256(COSE_Sign1.signature_bytes)` — same composition as D0023 §1 (Sigsum leaf) + D0024 §5 (release leaf). One audited primitive across the workspace.

Operational-identity addressing (not device-key) means device-key rotation under suspected compromise does not break message chains — the operational identity is stable.

---

## 3. Size-bin padding

Unchanged from the original D0026. Power-of-2 buckets {256, 1024, 4096, 16384, 65536}; payloads > 65536 transmit at natural size (documented outlier). Padding bytes from workspace `getrandom` per D0018 §1.7.

**Where the padding sits in the corrected model:** Cairn pads its envelope BEFORE calling SimplOxide's `send`. SimpleX's ratchet then wraps the padded envelope; the SMP-server-observable wire size carries the bucket size + ratchet overhead, not the true message size. This is the same "pad before the transport's E2EE wrapping" property the original D0026 §4.2 specified — the only change is that the wrapping layer is SimplOxide's ratchet rather than a Cairn-owned ratchet.

Per design brief §3.3, this is the metadata-fingerprint defense. It does NOT defend traffic-flow analysis (Tor threat model). Cover traffic is v1.x+.

---

## 4. Storage record-ids

### 4.1 Decision

- **Ratchet state is SimplOxide's / the CLI sidecar's concern.** The CLI persists its own ratchet + queue state in its data directory (`-d /data/data/.../simplex/` per D0020 §1.6). Cairn's `cairn-storage` `RATCHET_STATE` category is therefore NOT used to store SimpleX ratchet state in the corrected model — that was an artifact of the project-owned-ratchet design. (The category constant remains reserved in `cairn-storage` for any future Cairn-owned ratchet, e.g., a v1.5 Briar tier that needs Cairn-side ratchet persistence.)
- **Cairn `MESSAGES` history** is keyed by `SHA-256(sender_operational_pubkey ‖ recipient_operational_pubkey ‖ message_number_be)` per the original §3.2. Cairn persists its own application-level message history (the decrypted envelopes the user sees) in the `MESSAGES` category, decryptable under unlock per D0006 §3.5.

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
5. `cairn-simplex-adapter/src/adapter.rs` — the `Transport` trait impl over SimplOxide. Network-bound; stubs to `NetworkUnreached` in the skeleton, lands with the SimplOxide integration step.
6. CLI integration in `cairn-cli`: `simplex-send` + `simplex-recv` subcommands against a mock `Transport` for the demo (no CLI sidecar needed for the mock path per D0020 §1.10).
7. SimplOxide integration testing: against a local SimpleX Chat CLI under the `integration-tests` cargo feature per D0023 §10's pattern.

**Removed from the original skeleton:** `ratchet.rs` (the project-owned double-ratchet) is deleted — SimpleX owns the ratchet.

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
