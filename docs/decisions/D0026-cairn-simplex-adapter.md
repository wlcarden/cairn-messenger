# D0026 — cairn-simplex-adapter: project-owned Rust SMP client + Cairn message envelope per design brief §5.4

**Status:** Accepted
**Date:** 2026-05-29

## Context

D0018 §8.6 enumerates `cairn-simplex-adapter` in the workspace layout but does not specify which SimpleX integration approach to take, what protocol version to track, how the Cairn message envelope composes with the SMP wire format, what the size-bin padding policy is, or how the ratchet-state + message-history storage layouts map onto the `cairn-storage` substrate.

Design brief §5.4 commits SimpleX as the primary messaging spine for v1 (Briar joins at v1.5). The same section names SimpleX's properties Cairn relies on:

- Identifier-less queue model — no persistent user identifier; queues addressed cryptographically; per-recipient queue addressing means no single server holds a roster of the user's contacts.
- Double-ratchet derivative providing **forward secrecy AND post-compromise security** for on-wire message content. The at-rest store is decryptable under unlock regardless of ratchet state per D0006 §3.5.
- Queues are short-lived and rotatable; servers self-hostable or default to the SimpleX network's published relays.

The research that backs this decision is in [docs/network-transport-research.md](../network-transport-research.md). That document surveys four SimpleX-integration candidates: project-owned Rust SMP client (Option S-A); FFI to Haskell simplexmq (Option S-B); subprocess simplex-chat + IPC (Option S-C); defer SimpleX (Option S-D). The decision is **S-A: project-owned Rust SMP client**, paired with **T-A: Arti-embedded Tor** per D0025. The pure-Rust pairing extends D0023's project-owned witness-cosignature verification and D0024's project-owned Rust Rekor verifier discipline to the messaging layer.

This decision specifies:

1. The SMP protocol version this crate targets and the upstream-spec tracking discipline.
2. The Cairn ↔ SimpleX boundary — what this crate owns vs. what the SimpleX spec defines.
3. The Cairn message envelope schema layered on SMP payloads (signed under D0006 §9's three-hop chain; AAD domain-tagged per D0006 §8).
4. The double-ratchet derivative state management and storage layout.
5. The size-bin padding policy per design brief §3.3.
6. The group-membership-minimization architectural property (held at protocol-layer even though v1 ships 1:1 only per D0004).
7. The server-selection model and self-hosting support.
8. The async surface, RetryBudget reuse, and cancel-safety pattern.
9. The composition with `cairn-tor-transport` (D0025).
10. The failure modes + typed error surface per D0018 §4.2.

This decision does NOT specify:

- The specific SMP spec section-by-section implementation. The crate tracks the SimpleX upstream RFC; this decision pins the targeted version + the discipline, not the wire-format details.
- Group chat semantics. v1 ships 1:1 only per D0004; the architectural property is preserved but group-specific protocol layout is deferred to a future D-doc.
- Voice/video. SimpleX supports these natively per design brief §5.4; treated as v1.x / v2 candidate per design brief §6.2.
- UI policy on message rendering, read receipts, delivery receipts. UX-layer per design brief §5.6 minimization principles.
- The Briar adapter (v1.5 D-doc).

## Decision summary

| Concern                           | Decision                                                                                                                                                                                     | Rationale link |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| **SMP protocol version**          | SimpleX Messaging Protocol v7 (latest stable spec at decision time); spec-tracking discipline per §1.3                                                                                       | §1             |
| **Implementation model**          | Project-owned Rust client implementing SMP per spec. No FFI to Haskell simplexmq; no subprocess simplex-chat                                                                                 | §1             |
| **Cairn message envelope**        | Canonical-CBOR per D0018 §2.3, wrapped in `COSE_Sign1` per D0018 §2.1, signed under D0006 §9's three-hop chain. AAD domain tag `cairn-v1-message-envelope` per D0006 §8                      | §2             |
| **SMP payload composition**       | Cairn envelope bytes are the payload SMP transports. SMP's double-ratchet derivative wraps the Cairn envelope; the wire body the SimpleX server sees is opaque ratchet-encrypted ciphertext  | §2             |
| **Double-ratchet implementation** | Project-owned Rust per the SimpleX upstream double-ratchet derivative spec; X3DH for initial key agreement; per-message asymmetric ratchet step for post-compromise security                 | §3             |
| **Ratchet state storage**         | `cairn_storage::categories::RATCHET_STATE`; per-conversation record id derived from the peer's long-term identity pubkey. AAD-bound per D0022 §2.4                                           | §3             |
| **Message history storage**       | `cairn_storage::categories::MESSAGES`; per-message record id; chronological retrieval supported. Decryptable under unlock per D0006 §3.5 (NOT ratchet-FS-bound)                              | §3             |
| **Size-bin padding policy**       | Deterministic padding to power-of-2 byte buckets: {256, 1024, 4096, 16384, 65536}. Larger payloads transmit at their natural size with no padding (defeats the buckets for outliers)         | §4             |
| **Padding-on-noise discipline**   | Padding occurs at the Cairn envelope level BEFORE SMP wrapping; the wire size leak observable to SMP servers carries only the bucket size, not the message size                              | §4             |
| **Group-membership minimization** | Per-message recipient resolution (no persistent group roster on-wire) — architectural at the protocol layer even though v1 ships 1:1. Multi-recipient propagation deferred to a future D-doc | §5             |
| **Server selection**              | Default: the SimpleX network's published relays per release-bundled `simplex_servers.toml`. User-configurable self-hosted server URL at Android-shell UI; the crate accepts either           | §6             |
| **Async surface**                 | All I/O `async fn`. `RetryBudget` re-exported from `cairn-sigsum-client` per D0023 §5.3. Cancel-safety: per-message send is cancel-safe; mid-ratchet-rotation is NOT                         | §7             |
| **Tor composition**               | Every outbound SMP connection routes through `cairn_tor_transport::TorTransport::connect(...)`. No raw socket exposure                                                                       | §8             |
| **Failure surface**               | `SimplexAdapterError` per D0018 §4.2; typed by failure mode (queue-not-found, ratchet-out-of-sync, decode-failed, etc.); no `Vec<u8>` ciphertext or peer-supplied strings in error bodies    | §9             |

---

## 1. Implementation model and SMP version

### 1.1 Decision

Cairn implements the SimpleX Messaging Protocol per the [upstream RFC](https://github.com/simplex-chat/simplexmq/blob/master/rfcs/2022-04-25-simplex-messaging.md) and the protocol-version revisions the SimpleX project publishes. v1 targets SMP v7 (latest stable at decision time).

The crate `cairn-simplex-adapter` owns:

- The SMP wire-protocol implementation (queue create/write/read/delete; server protocol commands; agent-side state machine).
- The double-ratchet derivative implementation (§3) tracking the SimpleX upstream spec.
- The Cairn message envelope construction + signing (§2).
- The per-conversation ratchet-state persistence via `cairn-storage` (§3).
- The size-bin padding (§4) before SMP wrapping.
- The composition with `cairn-tor-transport` (§8).

### 1.2 Rationale

Three properties matter:

1. **Pure-Rust discipline holds at the protocol layer.** Same logic as D0023 §3.1 + D0024 §3 + D0025 §1: keeping the protocol implementation in safe Rust means the audit boundary is wholly inside the workspace's existing audit posture. No GHC runtime to ship; no FFI cancel-safety semantics to design; no subprocess to manage; `cairn-simplex-adapter` stays `unsafe_code = "forbid"` per D0018 §8.1.
2. **Cairn's typed-error + memory-hygiene disciplines apply uniformly.** A project-owned implementation can match D0018 §4.2 error variants + D0018 §1.6 `SecretBox`/`Zeroizing` patterns from day one. The Haskell-FFI option (S-B) would have required negotiating these properties across the FFI boundary — possible but expensive.
3. **The implementation cost is bounded by the spec.** SMP v7 is a documented protocol with a reference Haskell implementation as the spec's existence proof. Cost estimate per the research doc: 6–12 weeks of engineering effort for the v1 surface (1:1 messaging, queue lifecycle, double-ratchet, size-bin padding). The estimate is comparable to the existing protocol-layer crates (cairn-trust-graph, cairn-recovery) combined.

### 1.3 Spec-tracking discipline

SMP is a versioned protocol; the SimpleX project ships protocol revisions on its own cadence. Cairn's tracking discipline:

- Each Cairn release pins to a specific SMP version (e.g., v7). The version is named in the release notes.
- A new SMP version is adopted as a coordinated release event: implementation work, test-vector cross-validation against the reference Haskell impl (`simplexmq`), audit review of the upgrade, then ship.
- Adopting a new SMP version is NOT a runtime decision the client makes; users do not see "auto-upgrade to SMP v8". They get the version their Cairn release pins.
- Backward-compatibility with SMP v6 (the version preceding v7) is supported through one Cairn release after the v7 adoption, then dropped. This matches the SimpleX project's own deprecation cadence.

### 1.4 What this decision does NOT pin

Specific SMP wire-format details (command opcodes, encoding fields, server response framing) are NOT pinned in this D-doc. The crate tracks the upstream RFC at the implementation level; the audit posture verifies wire compatibility via cross-validation tests against the reference Haskell impl (analogous to D0018 §5.2's existing `cairn-envelope` cross-validation pattern against go-cose).

---

## 2. Cairn message envelope

### 2.1 Schema (integer-keyed canonical-CBOR map per D0018 §2.3)

| Key | Field                          | CBOR type | Notes                                                                                                                                                              |
| --- | ------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | `version`                      | uint      | Cairn message-envelope schema version; v1 = 1                                                                                                                      |
| 2   | `sender_operational_pubkey`    | bstr (32) | The sender's operational identity per D0006 §9                                                                                                                     |
| 3   | `recipient_operational_pubkey` | bstr (32) | The intended recipient's operational identity                                                                                                                      |
| 4   | `timestamp`                    | uint      | Unix-seconds when the envelope was constructed                                                                                                                     |
| 5   | `prior_envelope_hash`          | bstr      | SHA-256 of the prior envelope this sender sent to this recipient; zero-length for the first envelope. Same posture as D0006 §5 `prior_hash` for trust-graph chains |
| 6   | `payload`                      | bstr      | The application-level payload (e.g., text message bytes, attachment-ref bytes)                                                                                     |
| 7   | `padding`                      | bstr      | Random bytes to reach the configured size bucket per §4                                                                                                            |

The envelope is signed via `COSE_Sign1` per D0018 §2.1, with the device key (per D0006 §9 hop #1) and the capability token bytes carried in the unprotected headers (per D0006 §9 hop #2 verification).

AAD domain tag per D0006 §8: `cairn-v1-message-envelope`.

### 2.2 Composition with SMP

The SMP wire body is opaque from Cairn's perspective: SMP's double-ratchet derivative wraps the Cairn envelope bytes and the SimpleX server sees only ratchet-encrypted ciphertext. The structure on-wire:

```
SMP queue message body
└── Double-ratchet ciphertext (SimpleX-provided E2EE)
    └── Cairn COSE_Sign1 envelope (canonical CBOR encoded)
        └── Cairn message-envelope payload (key 6 of the schema above)
```

The Cairn envelope's signature commits to the payload + the prior_envelope_hash chain + the recipient binding. The double-ratchet provides forward secrecy + post-compromise security on-wire. The two layers are orthogonal: ratchet compromise reveals message content but does not let an attacker forge envelopes (the signature defeats forgery); envelope compromise (an attacker holds the device key) lets the attacker forge but does not reveal historical ratchet-state content (forward secrecy holds at the on-wire layer).

### 2.3 Rationale

Three properties matter:

1. **`prior_envelope_hash` per-sender-per-recipient chain.** Mirrors D0006 §5's trust-graph `prior_hash`: a recipient who has been online continuously can detect an attacker who issues a message under a stolen device key by observing the prior_envelope_hash chain. The chain doesn't appear in the public Sigsum log (that's commitment-only for trust-graph ops, not messaging); the chain is observable by the recipient only.
2. **AAD domain tag prevents cross-protocol substitution.** A signed envelope with the `cairn-v1-message-envelope` tag cannot be replayed against any other envelope verification path (trust-graph, master-attestation, capability-token, release-manifest). Same defense D0006 §8 applies at every other envelope surface.
3. **Operational identity addressing, not device key.** The envelope names sender + recipient operational identities. Device-key rotation under suspected compromise (per design brief §5.1) does NOT break message chains — the operational identity is stable; the device key signs but the chain identifier is operational.

### 2.4 Sender-recipient pair uniqueness

Each `(sender_operational_pubkey, recipient_operational_pubkey)` pair has its own envelope chain. A user sending to multiple recipients has multiple chains; each is independent. This matches the per-(issuer, subject) chain model from D0006 §5 for trust-graph ops.

---

## 3. Double-ratchet derivative + state storage

### 3.1 Decision

Cairn implements the SimpleX double-ratchet derivative per the upstream spec. The crate exposes:

- `RatchetState` — per-conversation ratchet state struct (root key, sending chain key, receiving chain key, header keys, message-number counters).
- `RatchetState::initialize(x3dh_output)` — establish a new ratchet via X3DH key agreement.
- `RatchetState::encrypt(plaintext, &mut self)` — advance the sending chain; return the wire ciphertext + the new state.
- `RatchetState::decrypt(ciphertext, &mut self)` — advance the receiving chain; return the plaintext + the new state.

### 3.2 Storage layout

`cairn_storage::categories::RATCHET_STATE` holds one record per conversation. The record id is `SHA-256(local_operational_pubkey ‖ peer_operational_pubkey)` — deterministic per pair. AAD-bound per D0022 §2.4.

`cairn_storage::categories::MESSAGES` holds one record per message. The record id is `SHA-256(sender_operational_pubkey ‖ recipient_operational_pubkey ‖ envelope_message_number)`. Chronological retrieval is supported via the per-category list operation.

### 3.3 Memory hygiene

Per D0018 §1.6:

- Root keys, chain keys, and message keys are held in `SecretBox<[u8; KEY_LEN]>` for their function scope.
- Plaintext message bytes are held in `Zeroizing<Vec<u8>>` until handed off to the UI layer (where the UI layer's memory hygiene takes over).
- AEAD nonces are generated fresh per message via the workspace `getrandom` per D0018 §1.7.

### 3.4 Cancel safety

`RatchetState::encrypt` and `decrypt` mutate state. Cancellation mid-operation (drop of the future) leaves the ratchet state in the PRE-call state — the state is taken by `&mut self` and the mutation commits at the end of the function. If the function returns mid-way (e.g., a storage write fails after the in-memory state advanced), the caller MUST NOT persist the partial state; the function signals this via the typed error variant.

### 3.5 At-rest decryptability per D0006 §3.5

The double-ratchet provides on-wire forward secrecy; the at-rest store does NOT delete old ratchet state to preserve at-rest decryptability per D0006 §3.5. A user with the unlock passphrase + StrongBox access can decrypt their entire message history regardless of ratchet state evolution. The on-wire FS property defends against attackers who observe wire traffic; at-rest decryption is a separate, unlock-bound property.

---

## 4. Size-bin padding

### 4.1 Decision

Cairn message envelopes are padded BEFORE SMP wrapping to one of the following byte buckets:

```text
256, 1024, 4096, 16384, 65536
```

A payload of N bytes pads to the smallest bucket ≥ (N + envelope overhead). Payloads exceeding 65536 bytes transmit at their natural size with no padding (the outlier-defeats-bucket case is documented; user awareness lives in the UX layer).

The padding bytes are generated via the workspace `getrandom` per D0018 §1.7; the receiver discards the padding by reading the `payload` field's actual length and ignoring the trailing `padding` bytes.

### 4.2 Rationale

Three properties matter:

1. **Metadata-fingerprint defense per design brief §3.3.** "Size-bin padding of graph deltas (metadata-fingerprint defense)" is named as the architectural commitment. The buckets are coarse enough that small text messages (256B), medium attachments (4KB-16KB), and large attachments (64KB) each fit a distinct bucket; the SimpleX server observing wire sizes learns the bucket, not the message size.
2. **Power-of-2 buckets minimize differential leakage.** A power-of-2 bucket gives an attacker a 2× range guess on the message size; a finer bucket would be more efficient bandwidth-wise but leak more. The 5-bucket choice is a deliberate operational compromise.
3. **Padding before SMP wrapping.** The double-ratchet sees a padded plaintext; the wire ciphertext is therefore the bucket size + ratchet overhead. If padding happened AFTER SMP wrapping (i.e., at the wire layer), the unpadded ciphertext size would leak through the ratchet — defeating the purpose.

### 4.3 What this does not defend against

A traffic-analysis-capable adversary at the global passive level can correlate timing of messages across queues; per-message size is just one input. The buckets defend against per-message fingerprinting; they do NOT defend against traffic-flow analysis. Per design brief §3.3, traffic-flow analysis falls under the Tor threat model.

### 4.4 Out of scope at v1

- Cover traffic (sending dummy messages on a clock to defeat timing analysis) is NOT in v1 scope. v1.5+ may add cover traffic for users opting into the highest-sensitivity tier (paired with the v1.5 Briar tier).
- Per-conversation bucket selection (different buckets for different conversations) is NOT in v1 scope. All conversations use the same 5-bucket policy.

---

## 5. Group-membership minimization (architectural property)

### 5.1 Decision

The protocol-layer architecture supports per-message recipient resolution (no persistent group roster on-wire). Even though v1 ships 1:1 only per D0004, the design property is held:

- The Cairn message envelope's `recipient_operational_pubkey` is ALWAYS a single pubkey. A future multi-recipient broadcast sends N independent envelopes, one per recipient, NOT one envelope with a recipient list.
- The per-conversation ratchet state is ALWAYS per-(sender, recipient) pair; never per-group.

### 5.2 Rationale

Per design brief §3.3:

> "The design minimizes group-level metadata where the protocols permit (per-message recipient resolution rather than persistent member rosters where possible)."

Holding this property at v1 (when no groups ship) means the v1.5 group lift does not require restructuring the message-envelope schema. A v1.5 group send is N envelope sends in a fan-out; the group membership lives in the SENDER's local state, not on the SimpleX queue or in the envelope.

### 5.3 Cost the project accepts

N-recipient fan-out has 1/N efficiency compared to a single broadcast envelope. At v1 pilot scale (10–15 contacts, modest group sizes), the bandwidth cost is acceptable. At broader scale (large public groups), this approach becomes operationally expensive — which is the design brief's intent: large public groups are outside the threat model Cairn serves. If a user has 200 group contacts, they should be on a different tool.

---

## 6. Server selection

### 6.1 Decision

The crate accepts a `SimplexServerConfig` at construction time:

```rust
pub struct SimplexServerConfig {
    pub servers: Vec<SimplexServer>,
}

pub struct SimplexServer {
    pub server_address: String, // .onion v3 address or hostname
    pub server_pubkey: [u8; 32],
}
```

The release ships a baked-in `simplex_servers.toml` listing the SimpleX network's published relays (same release-bundling posture as the witness pool per D0023 §3.3 + the pluggable transports list per D0025 §3). The Android-shell UI MAY accept user-pasted server entries that override the bundled defaults at runtime (v1.x+ enhancement; v1 ships the bundled list only).

### 6.2 Rationale

Three properties matter:

1. **Self-hostability per design brief §5.4.** A user (or group, or NGO partner) can run their own SMP server; the protocol does not require a Cairn-operated relay. The config surface accepts arbitrary servers.
2. **Default to a vetted relay set.** Pilot users should not have to choose a server; the baked-in list provides operational continuity at v1 pilot scale.
3. **Server-address pinning.** Each entry binds an address to a pubkey; an attacker who intercepts the SMP connection cannot substitute a different server without producing a signature failure.

### 6.3 Out of scope

- Server-reputation tracking (which servers are reliably online; which have been observed dropping queues). v1.5+ operational concern.
- Server discovery via DHT or other dynamic mechanisms. v1 uses the bundled list; v1.x may add discovery if operational evidence warrants.

---

## 7. Async surface

### 7.1 Decision

All I/O methods are `async fn`. The crate depends on `tokio = "=1.40.0"` per the workspace pin.

`RetryBudget` is re-exported from `cairn-sigsum-client` per D0023 §5.3:

```rust
pub use cairn_sigsum_client::RetryBudget;
```

Public surface (sketch):

```rust
pub struct SimplexClient { /* ... */ }

impl SimplexClient {
    pub async fn send_message(
        &self,
        recipient: &VerifyingKey,
        payload: &[u8],
        retry_budget: RetryBudget,
    ) -> Result<MessageSent, SimplexAdapterError>;

    pub async fn poll_inbox(
        &self,
        retry_budget: RetryBudget,
    ) -> Result<Vec<ReceivedMessage>, SimplexAdapterError>;

    pub async fn rotate_queue(
        &self,
        peer: &VerifyingKey,
        retry_budget: RetryBudget,
    ) -> Result<(), SimplexAdapterError>;
}
```

### 7.2 Cancel safety

- `send_message`: cancel-safe. Dropping the future before the SMP server ACKs leaves no persistent state change; the caller may retry safely.
- `poll_inbox`: cancel-safe. Polling is idempotent.
- `rotate_queue`: NOT cancel-safe. A queue rotation is a multi-step operation (advertise new queue → write final message on old queue → delete old queue); cancellation mid-rotation can leave dangling state. The function signature documents this.
- `RatchetState` mutations: cancel-safe at the in-memory level (the `&mut self` mutation commits at function return); the storage write is the boundary that requires atomicity per §3.4.

### 7.3 No `spawn_blocking` on the I/O path

Same reasoning as D0025 §5.3: no CPU-bound crypto crosses the boundary at I/O time. The ratchet step is in-memory and sub-millisecond; the AEAD per-message encrypt is fast enough to not need `spawn_blocking`.

---

## 8. Tor composition

### 8.1 Decision

Every outbound SMP connection routes through `cairn_tor_transport::TorTransport::connect(...)`. The `SimplexClient` constructor accepts a `TorTransport` reference; the crate does NOT open raw sockets.

### 8.2 Rationale

Three properties matter:

1. **Single transport surface.** Per D0025, `TorTransport` is the workspace's only outbound-network surface. No ad-hoc TCP; no SOCKS5 client duplication.
2. **Pluggable-transport inheritance.** When `TorTransport` is configured with pluggable transports per D0025 §3, every SMP connection automatically rides them; the SMP adapter does not have to know about transports.
3. **Network-state observation cascade.** When the Android shell signals `TorTransport::observe_network_state(Offline)`, in-flight `SimplexClient` operations surface `SimplexAdapterError::TransportError { source: ... }` via the TorStream's close-with-reason. The SMP retry logic at the caller decides whether to wait for reconnection or surface to the user.

### 8.3 Out of scope

- Direct SMP over TLS without Tor. The design brief commits Tor as the transport per §5.4; the crate does not support bypassing it.
- I2P or other alternative anonymity networks. The architecture is Tor-pinned at v1.

---

## 9. Failure modes + typed error surface

`SimplexAdapterError` per D0018 §4.2 — indices, lengths, type tags only:

```rust
#[non_exhaustive]
pub enum SimplexAdapterError {
    /// Underlying network failure after the retry budget was exhausted.
    Network { retry_budget_used: u8 },

    /// Placeholder for the network-bound surfaces that aren't
    /// implemented yet. v1 skeleton stubs to this; the SMP body
    /// lands when CI grows a wiremock or local-SMP-server harness.
    NetworkUnreached,

    /// The named SMP queue was not found on the server.
    QueueNotFound,

    /// The ratchet state could not advance — the wire ciphertext
    /// was not the next-expected message number, OR the chain key
    /// did not produce a valid decryption. Recovery: out-of-band
    /// re-key with the peer.
    RatchetOutOfSync { expected_message_number: u64, observed_message_number: u64 },

    /// The peer's prior_envelope_hash chain has a gap — an envelope
    /// is missing between the last-received and the current one.
    /// Indicates either a delivery failure (the missing envelope
    /// will arrive later) or a chain-tampering attack.
    EnvelopeChainGap { last_observed_message_number: u64, observed_message_number: u64 },

    /// The Cairn envelope's signature did not verify against the
    /// peer's operational identity. Indicates either tamper or
    /// the peer's device-key rotation Cairn has not yet observed.
    EnvelopeSignatureVerifyFailed,

    /// The Cairn envelope's canonical-CBOR decode failed.
    EnvelopeDecodeFailed,

    /// The Cairn envelope's AAD domain tag was not
    /// `cairn-v1-message-envelope` — cross-protocol substitution
    /// attempt rejected per D0006 §8.
    EnvelopeDomainTagMismatch,

    /// Padding was malformed — the wire payload was smaller than
    /// the bucket-size or the bucket-size was unknown.
    PaddingMalformed,

    /// The SMP server returned an unexpected response shape.
    SmpProtocolViolation,

    /// Storage failure for ratchet state or message history.
    Storage(#[from] cairn_storage::StorageError),

    /// Trust-graph encode/decode failure (for the device key + capability token verification path).
    Encode(#[from] cairn_trust_graph::TrustGraphError),

    /// Underlying Tor transport failure; carries the wrapped error.
    TransportError(#[from] cairn_tor_transport::TorTransportError),
}
```

### 9.1 No-error-oracle discipline

All variants carry small scalars or type tags. Message numbers are bounded counters per the SMP spec; expected/observed in `RatchetOutOfSync` and `EnvelopeChainGap` are diagnostic numerics that do not leak ciphertext, plaintext, or peer-supplied strings. No ciphertext bytes, no key bytes, no plaintext bytes appear in error bodies.

### 9.2 Cross-error orthogonality

The variants split by failure layer so the caller distinguishes:

- Transport-layer issues (`TransportError`, `Network`)
- Protocol-layer issues (`SmpProtocolViolation`, `QueueNotFound`)
- Ratchet-layer issues (`RatchetOutOfSync`)
- Envelope-layer issues (`EnvelopeSignatureVerifyFailed`, `EnvelopeDecodeFailed`, `EnvelopeDomainTagMismatch`, `EnvelopeChainGap`)
- Storage-layer issues (`Storage`)

This mirrors D0024 §7's split-by-layer discipline.

---

## 10. Out of scope

This decision does NOT address:

1. **Group chat protocol details.** v1 ships 1:1 per D0004; the architectural property (per-message recipient resolution) is preserved per §5 but group-specific protocol layout is deferred.
2. **Voice / video.** SimpleX-native voice/video is v1.x / v2 per design brief §5.4 + §6.2.
3. **Attachment file-transfer protocol.** SimpleX has a separate file-transfer surface; v1 may bundle small attachments inline (≤ 64KB bucket) but larger file transfers via the SimpleX file-transfer protocol are deferred to a follow-up D-doc.
4. **Push-notification integration.** UnifiedPush wake-up is the Android-shell concern per design brief §5.4; this crate exposes `poll_inbox` that the shell calls on wake-up.
5. **The Briar adapter (v1.5).** Briar is a separate D-doc consuming `cairn-tor-transport`'s onion-service hosting (§7 of D0025).
6. **Read receipts / delivery receipts.** UI policy per design brief §5.6 minimization; if implemented, they are payloads inside the Cairn message envelope (key 6), not separate envelope types.
7. **End-to-end encrypted backups of message history.** D0006 §3.5 specifies at-rest decryptable-under-unlock; backup is the same surface, exported through the Android-shell backup flow (which lives outside the Rust core).
8. **Per-conversation extra-private mode (v1.5 toggle).** Per design brief §5.4, this is the v1.5 Briar-mode toggle; v1 has uniform SimpleX behavior across all conversations.
9. **Cover traffic.** v1.x+ enhancement per §4.4.

## 11. Reversibility

The decisions in this document are mostly reversible:

- **SMP version rotation:** tractable; same coordinated release event as Arti per D0025 §1.4. The protocol-version pin lives in the Cairn release, not in user state.
- **Message envelope schema change:** the HARDEST. Once envelopes are emitted at the §2.1 schema, every subsequent envelope must follow it OR the prior_envelope_hash chain breaks. Schema additions (new keys) are forward-compatible per D0006 §6.4; schema BREAKS require coordinated release + a migration plan for existing conversation state.
- **Size-bin policy change:** tractable for SEND side (new releases pick new buckets); tractable for RECEIVE side (the receiver reads payload-length from the envelope, ignores padding). Bucket-size changes do not break interoperability; they affect future metadata-fingerprint posture.
- **AAD domain tag change:** would invalidate every existing envelope signature. Not reversible without coordinated re-attestation across the user base; effectively a v2 break.
- **Tor → other transport substitution:** D0025-scoped; if `cairn-tor-transport`'s `TorTransport` surface changes, this crate's composition with it changes. The two-axis coupling per the research doc applies.
- **SimpleX → other messaging protocol substitution (e.g., signal-protocol fork):** requires a wholly new D-doc; the crate's name + every wire-format detail change. Not reversible at this layer; this is the architectural commitment.

## 12. Implementation status

This D-doc is accepted. The matching `cairn-simplex-adapter` crate skeleton + SMP implementation land as separate commits consuming D0026. v1 implementation order:

1. `cairn-simplex-adapter/src/{lib,error}.rs` — pure data + error surface, no SMP yet.
2. `cairn-simplex-adapter/src/envelope.rs` — Cairn message envelope schema per §2 with canonical-CBOR round-trip + signing path. Real + tested.
3. `cairn-simplex-adapter/src/padding.rs` — size-bin padding per §4. Real + tested.
4. `cairn-simplex-adapter/src/ratchet.rs` — double-ratchet derivative per §3. Real + tested; reference-vector cross-validation against the SimpleX upstream test vectors per §1.4.
5. `cairn-simplex-adapter/src/storage.rs` — `RATCHET_STATE` + `MESSAGES` category integration per §3.2. Real + tested.
6. `cairn-simplex-adapter/src/smp_client.rs` — SMP wire-protocol implementation per §1. Network-bound; bodies stub to `NetworkUnreached` in the skeleton, land with the SMP-test-harness integration step.
7. `cairn-simplex-adapter/src/client.rs` — `SimplexClient` async handle per §7, composing the layers above + `TorTransport` per §8.
8. CLI integration in `cairn-cli`: `simplex-send-message` + `simplex-poll-inbox` subcommands for end-to-end demo.
9. SMP integration testing: a local SMP server harness for the integration-tests cargo feature per D0023 §10's pattern; opt-in against a public SMP relay for end-to-end smoke tests.

The Android-shell `cairn-uniffi` surface that exposes `SimplexClient::send_message` + `poll_inbox` to Kotlin is the `cairn-uniffi` D-doc's concern; this crate exposes the Rust-side methods.

---

## 13. Cross-references

- [D0003 — implementation language](D0003-implementation-language.md) — Rust core; pure-Rust discipline this decision extends to the protocol layer
- [D0004 — v1 scope cuts](D0004-v1-scope-cuts.md) — 1:1 v1 commitment; Briar deferred to v1.5
- [D0006 — cryptographic envelope](D0006-cryptographic-envelope.md) — §3.5 forward secrecy on-wire vs at-rest decryptable-under-unlock; §5 prior_hash schema (mirrored for envelope chain); §8 AAD domain-tag discipline; §9 three-hop verification
- [D0015 — v1 release-security posture](D0015-v1-release-security-posture.md) — release-bundling posture for simplex_servers.toml
- [D0018 — engineering foundation](D0018-engineering-foundation.md) — §1.6 memory hygiene; §2.1 COSE_Sign1; §2.3 canonical CBOR; §4.1 async discipline; §8.1 unsafe_code = forbid; §8.6 workspace layout
- [D0021 — library-pin audit](D0021-library-pin-audit.md) — pin discipline for SMP-related additions
- [D0022 — cairn-storage layer](D0022-storage-layer.md) — `RATCHET_STATE` + `MESSAGES` categories; AAD-binding for per-conversation records
- [D0023 — cairn-sigsum-client](D0023-sigsum-integration.md) — `RetryBudget` reuse per §7.1; baked-in TOML resource pattern per §6.1
- [D0025 — cairn-tor-transport](D0025-cairn-tor-transport.md) — the transport-layer dependency this crate composes
- [design brief §5.4 Communications Protocols](../design-brief.md) — SimpleX-as-protocol commitment, double-ratchet derivative properties, per-recipient queue addressing
- [design brief §3.3 Public transparency-log metadata + observable metadata](../design-brief.md) — size-bin padding commitment, group-membership minimization architectural property
- [docs/network-transport-research.md](../network-transport-research.md) — the substrate this decision rests on; Option S-A (project-owned Rust SMP client) per §"Candidate SimpleX integration approaches"
- [SimpleX SMP RFC](https://github.com/simplex-chat/simplexmq/blob/master/rfcs/2022-04-25-simplex-messaging.md) — upstream protocol spec
