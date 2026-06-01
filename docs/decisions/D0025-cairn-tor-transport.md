# D0025 — cairn-tor-transport: crate surface over the C-Tor ForegroundService per D0020 §2

**Status:** Accepted
**Date:** 2026-05-29
**Revised:** 2026-05-30 — re-anchored under D0020 §2 (see Revision note)

## Revision note (2026-05-30)

The original 2026-05-29 version of this document specified `arti-client` embedded in-process as the Tor implementation. **That contradicted [D0020](D0020-integration-architecture.md) §2, which had already chosen C-Tor via `guardianproject/tor-android` on the strength of the Sprint 3 consolidated triage research** (`docs/reviews/external-reads-consolidated.md`). The original D0025 was written without engaging D0020's prior decision — a process error.

The contradiction was resolved in favor of D0020 after a security analysis (recorded in the project log) found that the pure-Rust embedding did not deliver a net security benefit over D0020's choice:

- **Arti's one categorical advantage — memory-safe network-byte parsing vs. C-Tor's memory-unsafe C — is neutralized by D0020 §2.2's process isolation:** C-Tor runs in a separate `ForegroundService`, so a memory-corruption bug in C-Tor does not sit in Cairn's key-holding address space.
- **C-Tor's audit maturity and deployment scale are themselves a security argument** (Briar's production path; the substrate audit firms recognize), against Arti's `tor-hsservice` 0.42.0 self-documented warning: "not (yet) recommended for production use, or for any purpose that requires privacy."
- **Arti is not rejected, only deferred** per D0020 §2.7's three gating events. The pure-Rust Tor path returns when its security-maturity case actually closes, rather than on a bet that it will.

This document is therefore **downstream of D0020**: D0020 §2 owns the integration-model decision (C-Tor via tor-android); this document specifies the `cairn-tor-transport` crate surface that consumes it. The surviving crate-design content from the original (pluggable-transport config structure, `NetworkState` observation, `RetryBudget` reuse, the typed-error surface) is preserved; the embedding model is corrected from Arti to the C-Tor SOCKS5 + control-port client.

## Context

D0018 §8.6 enumerates `cairn-tor-transport` in the workspace layout. D0020 §2 decides the Tor integration model: **C-Tor via `guardianproject/tor-android` (`libtor.so` 0.4.9.8+), run as an Android `ForegroundService`, with the Rust core speaking SOCKS5 to `127.0.0.1:9050` for messaging traffic and the control-port at `127.0.0.1:9051` (cookie auth) for circuit management.** Pluggable transports ship via the Lyrebird per-ABI bundle.

This document specifies the `cairn-tor-transport` crate surface that realizes D0020 §2:

1. The Rust-side client surface (SOCKS5 stream construction + control-port client).
2. The pluggable-transport / bridge-manifest configuration model.
3. The network-state-transition contract with the Android shell.
4. The async surface (tokio integration; `RetryBudget` reuse from D0023 §5.3).
5. The failure-mode + typed-error surface per D0018 §4.2.

This document does NOT re-decide:

- **The Tor implementation choice.** D0020 §2 owns it (C-Tor; Arti deferred per §2.7).
- **The `ForegroundService` lifecycle, Lyrebird bundling, or the `libtor.so` JNI wrapper.** Those are Android-shell + D0020 §2.5 concerns. This crate is the Rust-side SOCKS5/control-port client that assumes a C-Tor endpoint is reachable.
- **Onion-service hosting at v1.** Deferred to v1.5 per D0020 §2.8 (C-Tor `ADD_ONION` via control-port). The architectural slot is preserved here (§7); v1 ships client mode only.
- **The bridge-manifest signing + distribution.** D0020 §2.4 owns the remote-updateable signed-manifest mechanism (Sigstore-signed, Sigsum-witnessed). This crate consumes a parsed manifest; it does not fetch or verify it (that composes `cairn-sigstore-verify` + `cairn-sigsum-client`).

## Decision summary

| Concern                            | Decision                                                                                                                                                                               | Rationale link |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| **Tor implementation**             | C-Tor via `guardianproject/tor-android` per D0020 §2. This crate is the Rust-side SOCKS5 + control-port client, NOT an embedded Tor implementation                                     | §1             |
| **Client surface**                 | `TorTransport` handle wrapping a SOCKS5 connector (`127.0.0.1:9050`) + a control-port client (`127.0.0.1:9051`, cookie auth). Async, tokio-runtime-bound                               | §1             |
| **Outbound model at v1**           | `connect(conversation_id, target, port)` opens a SOCKS5 stream with `IsolateSOCKSAuth` username = `hash(conversation_id)` per D0020 §2.6 (per-conversation circuit isolation)          | §2             |
| **Onion service hosting**          | v1.5 slot per D0020 §2.8: C-Tor `ADD_ONION` via control-port. v1 stub returns `OnionServiceHostingDeferred`                                                                            | §7             |
| **Pluggable transports / bridges** | `BridgeManifest` parsed from the D0020 §2.4 remote-updateable signed manifest (obfs4 default + WebTunnel + Snowflake + meek via Lyrebird). Manifest fetch/verify is out of crate scope | §3             |
| **Network state transitions**      | Android shell signals `observe_network_state(NetworkState)`. `Offline → Online` triggers `SIGNAL NEWNYM` via control-port + reconnect per D0020 §2.9                                   | §4             |
| **Async surface**                  | All I/O `async fn`; same `RetryBudget` type as D0023 §5.3 re-exported from `cairn-sigsum-client`                                                                                       | §5             |
| **Retry policy**                   | Exponential backoff capped at 60s for connect; max 5 retries by default. Control-port command failures surface to the caller                                                           | §5             |
| **Failure surface**                | `TorTransportError` per D0018 §4.2 — typed by failure mode; no `Vec<u8>` payloads; no bridge lines / peer hostnames / cookie bytes in error bodies                                     | §6             |
| **Stream semantics**               | `TorStream: AsyncRead + AsyncWrite` over the SOCKS5 connection. No TLS layered here (SimpleX carries its own E2EE; the SMP queue server's TLS is SimplOxide's concern)                 | §5             |

---

## 1. Client surface

### 1.1 Decision

`cairn-tor-transport` is the **Rust-side SOCKS5 + control-port client** for the C-Tor `ForegroundService` D0020 §2 specifies. It does NOT embed a Tor implementation.

The crate exposes a `TorTransport` handle that:

- Opens outbound SOCKS5 streams to `127.0.0.1:9050` (the C-Tor SOCKS proxy).
- Speaks the control-port protocol to `127.0.0.1:9051` (cookie auth) for circuit management (`SIGNAL NEWNYM`), bootstrap-status subscription, and — at v1.5 — onion-service hosting (`ADD_ONION`).
- Adds Cairn-specific lifecycle controls (network-state observation per §4) + the workspace's typed-error discipline.

### 1.2 Rationale

Per D0020 §2.3, the integration-model rationale (C-Tor's production maturity, Briar's precedent, the `tor-hsservice` production-readiness gap, Lyrebird PT bundling) is settled. At the crate-surface level:

1. **The SOCKS5 + control-port split mirrors what Briar, Cwtch, and OnionShare do.** It is the audit-firm-recognized shape for messaging-tool Tor integration. The Rust client is small (a SOCKS5 connector + a line-oriented control-port protocol client); the security-critical Tor logic lives in the well-audited C-Tor the `ForegroundService` runs.
2. **No `unsafe_code` in this crate.** The `libtor.so` JNI wrapper is Android-shell code per D0020 §2.2; this crate only speaks loopback SOCKS5 + control-port, both pure-safe-Rust. `cairn-tor-transport` stays `unsafe_code = "forbid"` per D0018 §8.1.
3. **Single async runtime.** The SOCKS5 + control-port client is tokio-native, matching the workspace pin; cancel-safety semantics are uniform with `cairn-sigsum-client`, `cairn-sigstore-verify`, and `cairn-simplex-adapter`.

### 1.3 The C-Tor endpoint is assumed reachable

This crate assumes the `ForegroundService` has C-Tor running and reachable at the loopback addresses. If C-Tor is not up (service not started, bootstrap not complete), the SOCKS5 / control-port connection fails and surfaces as a typed error (`Network` / `BootstrapIncomplete`). The crate does NOT start, supervise, or restart the C-Tor process — that is the `ForegroundService`'s job per D0020 §2.5.

---

## 2. Outbound stream construction + per-conversation circuit isolation

### 2.1 Decision

```rust
let stream: TorStream = transport
    .connect(conversation_id, target_host, target_port, retry_budget)
    .await?;
```

The SOCKS5 username is set to `hash(conversation_id)` with `IsolateSOCKSAuth` enabled in the C-Tor configuration per D0020 §2.6. Different conversations therefore do not share Tor circuits at the network layer: an exit-node compromise sees individual streams but cannot cluster them by source conversation.

`target_host` is the SMP queue server's hostname / `.onion` address (resolved through Tor). The returned `TorStream` implements `AsyncRead + AsyncWrite`.

### 2.2 Composition with the SimpleX adapter

In practice the caller of `connect` is the C-Tor `ForegroundService`'s SOCKS proxy, which the SimpleX Chat CLI sidecar uses for its outbound traffic per D0020 §1.2 + §2.2 (the CLI is configured to route through `127.0.0.1:9050`). At the Cairn-Rust level, `cairn-simplex-adapter` (D0026) talks to the CLI sidecar over loopback WebSocket; the CLI's own Tor routing goes through the same C-Tor proxy this crate manages. The `TorStream` surface remains available for any Cairn-Rust component that needs a directly-Tor-routed stream (e.g., the D0020 §2.4 bridge-manifest fetch "over Tor itself when possible").

### 2.3 Documented limitation

Per D0020 §2.6: per-conversation circuit isolation increases circuit-establishment latency; each new conversation pays a fresh-circuit cost. Acceptable for Cairn's threat tier; documented in the brief's §5.4.

---

## 3. Pluggable transports / bridge manifest

### 3.1 Decision

The crate accepts a `BridgeManifest` at construction time, parsed from the **remote-updateable signed bridge manifest** D0020 §2.4 specifies:

- Default bundle: obfs4 + WebTunnel via Lyrebird (single binary). Default selection: obfs4.
- User-selectable: Snowflake; meek-azure as last-resort fallback.
- The manifest is **remote-updateable** — D0020 §2.4 makes this an architectural commitment because PT viability shifts on a months-scale cat-and-mouse cadence (WebTunnel "key tool in Russia" → "most bridges blocked" in six months; Snowflake DTLS fingerprinting in Russia March 2026).

### 3.2 What this crate does vs. does not own

- **Owns:** parsing a verified `BridgeManifest` into the configuration C-Tor's control-port needs to launch Lyrebird with the right bridge lines; correlating a per-bridge bootstrap failure back to its manifest index for the typed error surface.
- **Does NOT own:** fetching the manifest, verifying its Sigstore signature, or checking its Sigsum witness cosignatures. That composes `cairn-sigstore-verify` (D0024) + `cairn-sigsum-client` (D0023) + the monotonic-version rollback-resistance check D0020 §2.4 specifies. The crate consumes an already-verified manifest.

### 3.3 Fallback behavior

If a configured bridge fails to bootstrap, `TorTransportError::BridgeBootstrapFailed { bridge_index }` surfaces and the caller decides whether to try the next bridge, fall back to a different PT, or escalate to the user. The crate does NOT implement automatic transport-switching policy — that is a UI-layer decision.

---

## 4. Network-state transitions

### 4.1 Decision

The Android shell signals network-state changes via:

```rust
transport.observe_network_state(NetworkState::Online);
transport.observe_network_state(NetworkState::Offline);
transport.observe_network_state(NetworkState::Constrained);
```

`Offline → Online` issues `SIGNAL NEWNYM` over the control-port + notifies the caller that in-flight messages may need retransmission per D0020 §2.9. `Online → Offline` pauses connect retries. `Constrained` is advisory at v1 (treated as `Online`).

### 4.2 Rationale

The Android `ConnectivityManager` callback is the OS-level signal; per D0020 §2.9, `cairn-tor-transport` subscribes to it (via the shell) and tears down circuits via control-port on handoff/disconnect. Routing the signal through an explicit method call keeps the Rust core off the platform-API surface, consistent with D0020 §3's Kotlin-mediated boundary.

### 4.3 Idempotence

Transitions execute on edge changes; calling with the current state is a no-op.

> **Revision 2026-05-31 — control-port client implemented; `observe_network_state` is async.** The §4.1 examples show `observe_network_state` as a sync call, but issuing `SIGNAL NEWNYM` on the `Offline → Online` edge requires control-port I/O, so the method is now `async fn observe_network_state(...) -> Result<(), TorTransportError>`. It updates the tracked state (releasing the mutex) BEFORE awaiting the NEWNYM, so a NEWNYM failure does not roll back the observed transition; the failure surfaces as the return error. The NEWNYM is skipped (returns `Ok`) when no control cookie path is configured. The control-port client (`crate::control`) authenticates with **SAFECOOKIE** (challenge-response; the 32-byte cookie is never transmitted) — HMAC-SHA256 computed as HKDF-Extract via the already-pinned `hkdf` (audited primitive, no new pin, no hand-rolled crypto) — using a per-command connection lifecycle (§5.2). `signal_newnym()` + `bootstrap_phase()` (`GETINFO status/bootstrap-phase` → progress 0–100) are exposed directly. Validated by `tests/control_port.rs` (8 cases) against a mock control-port server. Onion-service hosting (`ADD_ONION`, §7) remains the v1.5 follow-up.

---

## 5. Async surface

### 5.1 Decision

All I/O methods are `async fn`. The crate depends on `tokio = "=1.40.0"` per the workspace pin.

`RetryBudget` is re-exported from `cairn-sigsum-client` per D0023 §5.3 — same type, same defaults (max 5 retries, 250ms initial, 60s cap), same caller-scoping discipline.

### 5.2 Cancel safety

- Dropping a `connect()` future cancels the in-flight SOCKS5 handshake cleanly.
- Mid-stream cancellation (dropping a `TorStream`) closes the SOCKS5 connection; partial read/write state is the caller's responsibility per the `AsyncRead`/`AsyncWrite` contracts.
- Control-port commands (`SIGNAL NEWNYM`, bootstrap-status queries) are individually cancel-safe — each is a single request/response over the control connection.

### 5.3 No `spawn_blocking` on the I/O path

The SOCKS5 + control-port client is pure-async loopback I/O; no CPU-bound crypto crosses the boundary. The D0018 §4.1 `spawn_blocking` pattern does not apply.

---

## 6. Failure modes + typed error surface

`TorTransportError` per D0018 §4.2 — indices, lengths, type tags only; no `Vec<u8>` payloads; no peer-supplied strings:

```rust
#[non_exhaustive]
pub enum TorTransportError {
    /// Loopback connection to the C-Tor SOCKS proxy or control-port
    /// failed after the retry budget was exhausted.
    Network { retry_budget_used: u8 },

    /// Placeholder for the network-bound surfaces not yet implemented.
    /// v1 skeleton stub; the C-Tor SOCKS5 + control-port client body
    /// lands per §9.
    NetworkUnreached,

    /// The C-Tor ForegroundService is reachable but Tor bootstrap has
    /// not completed; outbound circuits are not yet available.
    BootstrapIncomplete,

    /// All configured bridges in the manifest failed to bootstrap.
    AllBridgesFailed { bridges_attempted: u8 },

    /// A specific bridge in the manifest failed to bootstrap. The
    /// `bridge_index` is the 0-based index into the BridgeManifest so
    /// the caller can correlate without the bridge line in the payload.
    BridgeBootstrapFailed { bridge_index: u8 },

    /// The bridge manifest could not be parsed.
    BridgeManifestParse,

    /// The control-port returned an error or unexpected reply shape.
    ControlPortProtocol,

    /// `target_host` did not resolve over Tor.
    HostResolutionFailed,

    /// SOCKS5 connection refused or reset by the target.
    ConnectionRefused,

    /// Stream closed mid-operation; `reason` names why.
    StreamClosed { reason: StreamCloseReason },

    /// Onion-service hosting is deferred to v1.5 per D0020 §2.8;
    /// host_onion_service() returns this in v1.
    OnionServiceHostingDeferred,
}

#[non_exhaustive]
pub enum StreamCloseReason {
    CallerClose,
    CircuitFailure,
    NetworkTransition,
    PeerReset,
}
```

### 6.1 No-error-oracle discipline

All variants carry small scalars or type tags. `bridge_index` indexes the project-owned manifest, not a peer-controlled value. No bridge lines, control-port cookie bytes, or peer hostnames appear in error bodies.

---

## 7. Onion-service hosting (architectural slot for v1.5)

Per D0020 §2.8, v1.5 release-distribution onion-service hosting uses **C-Tor `ADD_ONION` via the control-port** (not Arti `tor-hsservice`, which carries the production-privacy warning). This document preserves the API slot:

```rust
pub async fn host_onion_service(
    &self,
    config: OnionServiceConfig,
) -> Result<OnionServiceHandle, TorTransportError> {
    Err(TorTransportError::OnionServiceHostingDeferred)
}
```

Shipping the slot at v1 means consuming code (a future `cairn-briar-adapter` or the release-distribution surface) compiles against the same `TorTransport` handle without restructuring; the v1.5 body issues `ADD_ONION` over the control-port client this crate already owns.

---

## 8. Out of scope

This document does NOT address:

1. **The Tor implementation choice** — D0020 §2 (C-Tor; Arti deferred per §2.7).
2. **The `libtor.so` JNI wrapper + `ForegroundService` lifecycle** — Android-shell + D0020 §2.5.
3. **Lyrebird bundling as per-ABI native asset** — D0020 §2.4 + the build pipeline.
4. **Bridge-manifest fetch + signature/witness verification** — composes D0023 + D0024; this crate consumes a verified manifest.
5. **Onion-service hosting body** — v1.5 per D0020 §2.8.
6. **The mailbox-pattern relay** — v1.5 architectural commitment per D0020 §2.5.
7. **arti migration** — gated on D0020 §2.7's three events.

## 9. Reversibility

- **C-Tor → arti migration:** the deliberately-deferred path per D0020 §2.7. This crate's `TorTransport::connect` surface is designed to survive the swap — the SOCKS5 stream contract is implementation-agnostic; an arti backend would replace the SOCKS5 connector with `arti-client` calls behind the same `connect()` signature. The control-port surface would change (arti has no control-port; circuit management would move to arti's API). The migration is tractable but touches the control-port-dependent methods.
- **Bridge-manifest format change:** tractable; coordinated release event per D0020 §2.4's versioned-manifest design.
- **`TorStream` wire surface (AsyncRead+AsyncWrite):** the HARDEST to reverse once `cairn-simplex-adapter` (D0026) and the bridge-manifest fetch consume it.

## 10. Implementation status

This document is accepted (revised). The matching `cairn-tor-transport` crate skeleton lands as a separate commit. Implementation order:

1. `cairn-tor-transport/src/{lib,error}.rs` — pure data + error surface.
2. `cairn-tor-transport/src/config.rs` — `BridgeManifest` parser per §3. Real + tested.
3. `cairn-tor-transport/src/transport.rs` — `TorTransport` handle stub: `connect()` returns `NetworkUnreached`, `host_onion_service()` returns `OnionServiceHostingDeferred`. Config + `observe_network_state` + accessors real + tested.
4. The SOCKS5 + control-port client body lands when CI grows a C-Tor test harness OR an opt-in integration-test flag against a local C-Tor instance per D0023 §10's pattern.
5. CLI integration in `cairn-cli`: `tor-connect` subcommand for end-to-end demo (requires a running C-Tor).

The workspace pin posture: this crate does NOT pin `arti-client` (the original D0025 error). It pins a SOCKS5 client + a minimal control-port protocol client; specific crate selection lands at implementation-cycle commit per D0021's pin-audit.

> **Revision 2026-05-31 — the SOCKS5 client is HAND-ROLLED; no new pin.** The implementation-cycle decision the paragraph above defers ("specific crate selection … per D0021's pin-audit") resolved to **hand-rolling** the SOCKS5 CONNECT client (`src/socks5.rs`) rather than pinning a crate (e.g. `tokio-socks`). Rationale per D0021's "pure-Rust unless the alternative is security-worse" + dependency-minimization discipline: the protocol needed is small (RFC 1928 CONNECT + RFC 1929 username/password auth, pure-safe-Rust over `tokio`), we need explicit username/password control to drive `IsolateSOCKSAuth` (D0020 §2.6), the SOCKS framing is not itself the security boundary (the audited C-Tor is), and a hand-rolled client is hermetically testable via a mock SOCKS5 server with no new dependency-pin/audit event. The only added dependency is `sha2` — already an existing workspace pin (the isolation credential is `hex(SHA-256(conversation_id))`) — plus the `net` + `io-util` tokio features. `connect` is implemented + validated by `tests/socks5_connect.rs`; the **control-port** protocol client (cookie auth + `SIGNAL NEWNYM` + bootstrap-status) is the remaining network follow-up. A new typed error variant `TorTransportError::SocksProtocol` (the SOCKS-port analogue of `ControlPortProtocol`, §6) surfaces proxy handshake/auth/framing failures + unrecognized CONNECT reply codes; the SOCKS layer cannot reliably distinguish "Tor not bootstrapped", so `BootstrapIncomplete` stays the control-port's job.

---

## 11. Cross-references

- [D0020 — integration architecture](D0020-integration-architecture.md) — §2 owns the Tor integration model (C-Tor via tor-android) this document implements; §2.4 bridge manifest; §2.6 circuit isolation; §2.7 arti gating events; §2.8 onion-service hosting; §2.9 network-change handling
- [D0003 — implementation language](D0003-implementation-language.md) — Rust core
- [D0006 — cryptographic envelope](D0006-cryptographic-envelope.md) — §3.5 on-wire FS is SimpleX's (D0026); Tor is anonymity-of-route
- [D0018 — engineering foundation](D0018-engineering-foundation.md) — §4.1 async discipline; §8.1 unsafe_code = forbid; §8.6 workspace layout
- [D0023 — cairn-sigsum-client](D0023-sigsum-integration.md) — `RetryBudget` reuse per §5.1; bridge-manifest witness cosignatures
- [D0024 — cairn-sigstore-verify](D0024-sigstore-release-verification.md) — bridge-manifest signature verification
- [D0026 — cairn-simplex-adapter](D0026-cairn-simplex-adapter.md) — the SimpleX sidecar whose outbound traffic routes through the C-Tor proxy this crate manages
- [design brief §5.4 Communications Protocols](../design-brief.md) — Tor-as-transport commitment
- [docs/network-transport-research.md](../network-transport-research.md) — superseded by D0020 §2 for the integration model (see that doc's corrective header)
