# D0025 — cairn-tor-transport: Arti-embedded Tor client + pluggable-transports architecture per design brief §5.4

**Status:** Accepted
**Date:** 2026-05-29

## Context

D0018 §8.6 enumerates `cairn-tor-transport` in the workspace layout but does not specify which Tor implementation to embed, how circuits are built, how pluggable transports are configured, or how the Android shell signals network-state transitions across the FFI surface.

Design brief §5.4 commits Tor as the transport layer for SimpleX (v1) and Briar (v1.5). The same section names pluggable transports (obfs4, meek, webtunnel, snowflake, "whichever the Tor Project's current guidance indicates") as an ongoing engineering commitment, not a one-time decision. Tor is named explicitly as a trust root in §3.4 with its known limitations against global passive adversaries.

The research that backs this decision is in [docs/network-transport-research.md](../network-transport-research.md). That document surveys four Tor-transport candidates: Arti embedded (Option T-A); system Tor subprocess + SOCKS5/ControlPort (Option T-B); Android Orbot via SOCKS5 (Option T-C); user-provided Tor via raw SOCKS5 (Option T-D). The decision is **T-A: Arti embedded as a pure-Rust in-process library**, paired with **S-A: project-owned Rust SMP client** in D0026. The pure-Rust pairing extends the workspace's established discipline (D0023 §3's project-owned witness-cosignature verification, D0024 §3's project-owned Rekor verifier).

This decision specifies:

1. The Arti embedding model and the Rust-side library surface this crate exposes.
2. The outbound circuit / connection construction model for v1's SMP-queue-server use case.
3. The pluggable transports configuration model and the architectural commitment to replaceability.
4. The network-state-transition contract with the Android shell (foreground service, wifi ↔ cellular ↔ offline).
5. The async surface (tokio integration; RetryBudget reuse from D0023 §5.3).
6. The failure-mode + typed-error surface per D0018 §4.2.

This decision does NOT specify:

- Onion-service HOSTING at v1. Briar v1.5 needs it; the architectural slot is preserved in this decision (§7) but the v1 implementation surface ships client mode only.
- Specific pluggable-transport selection at v1 ship (obfs4 vs webtunnel vs snowflake). Per design brief §5.4, "specific transport selection is operational rather than architectural and is deferred to the system design spec."
- The Android-shell foreground service lifecycle. That lives in `cairn-uniffi` + Android-shell code, not in this crate.
- The user-facing "I cannot reach my queue" UI affordance. UI policy lives at the Android shell.

## Decision summary

| Concern                       | Decision                                                                                                                                                                                | Rationale link |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| **Tor implementation**        | `arti-client` embedded in-process. Pure-Rust per the workspace discipline; same audit boundary as the rest of the I/O surface                                                           | §1             |
| **Client surface**            | `TorTransport` handle wrapping an `arti_client::TorClient`. Async, tokio-runtime-bound. Exposes outbound `connect(target)` + the lifecycle the Android shell drives                     | §1             |
| **Outbound model at v1**      | Client-side circuit construction to SMP queue servers (the SimpleX network). NOT onion-service hosting at v1                                                                            | §2             |
| **Onion service hosting**     | Architectural slot preserved for v1.5 Briar integration. Same `TorTransport` handle gains `host_onion_service(...)` then; v1 stubs surface returns NotYetImplemented                    | §2             |
| **Pluggable transports**      | Configured at `TorTransport::new` via a `PluggableTransportConfig` arg pulled from a baked-in `pluggable_transports.toml` resource per release (same posture as D0023 `witnesses.toml`) | §3             |
| **Network state transitions** | Android shell signals via `TorTransport::observe_network_state(NetworkState)`. Internal circuit recreation policy: drop on `Offline`; reconnect on `Online`                             | §4             |
| **Async surface**             | All I/O methods `async fn`; same `RetryBudget` type as D0023 §5.3 re-exported from `cairn-sigsum-client`. Cancel-safety: dropping a future cancels the in-flight stream cleanly         | §5             |
| **Retry policy**              | Exponential backoff capped at 60s for circuit construction; max 5 retries by default. Stream-level failures surface to the caller (SimpleX adapter) for protocol-aware retry decisions  | §5             |
| **Failure surface**           | `TorTransportError` per D0018 §4.2 — typed by failure mode (bootstrap failed, no circuit, connect refused, etc.); no `Vec<u8>` payloads; no peer-supplied strings                       | §6             |
| **Stream semantics**          | `TorStream: AsyncRead + AsyncWrite`. The crate does NOT layer TLS; that's the caller's responsibility (SMP carries TLS to the queue server itself)                                      | §5             |
| **Arti workspace pin**        | `arti-client = "=1.X.X"` exact pin per D0018 §1; specific patch version selected at implementation-cycle commit; pin-audit per D0021 included                                           | §1             |

---

## 1. Embedding model

### 1.1 Decision

Cairn embeds `arti-client` as a Rust library dependency, running entirely in-process. No subprocess; no FFI to a C Tor binary; no separate runtime to manage.

The crate exposes a single primary type `TorTransport` that wraps an `arti_client::TorClient` and adds Cairn-specific lifecycle controls (network-state observation per §4) + the workspace's typed error discipline.

### 1.2 Rationale

Three properties matter:

1. **Pure-Rust discipline holds end-to-end at the transport layer.** Same logic as D0023 §3.1's project-owned witness verification: keeping the network-critical surface in safe Rust means the audit boundary is the same boundary as the rest of the workspace. No C Tor source to track; no subprocess lifecycle to reason about; no `unsafe_code` exception expansion (`cairn-tor-transport` stays `unsafe_code = "forbid"` per D0018 §8.1).
2. **Single async runtime.** Arti's tokio integration matches the workspace's tokio 1.40.x pin. No runtime bridging; cancel-safety semantics are uniform with `cairn-sigsum-client` + `cairn-sigstore-verify`.
3. **Onion-service hosting in-process is the natural fit for v1.5 Briar.** Briar's peer-to-peer-over-Tor model requires each user to host an onion service. Arti's onion-service hosting (stable since 1.2.x) is the embedded path; system-Tor's ControlPort-based onion-service management is the alternative, with higher operational complexity. The v1 commitment locks Arti so v1.5 Briar can build on the same substrate.

### 1.3 Trade-off the project accepts

Binary-size cost: Arti embedded carries its own dependency graph (substantial). The APK size grows by the Arti dep tree's compiled footprint. This is the trade for pure-Rust discipline.

Update cadence: Arti security patches ride Cairn releases. The same posture applies to every other Rust dep, but Arti is a higher-stakes one. Pin-audit per D0021 includes Arti's release-channel monitoring.

### 1.4 Arti version pin posture

Per D0018 §1, library versions are pinned with `=X.Y.Z` (exact), not `^X.Y.Z` (semver). The specific Arti version pin lands at implementation-cycle commit time; the pin selection criteria are:

- Latest stable in Arti's release channel
- Onion-service hosting stable in that version (1.2.x+)
- Pluggable-transport API stable in that version
- The version's transitive dep tree has been pin-audited per D0021

A future Arti rotation (e.g., Cairn picks up Arti 2.x) is a coordinated release event per the same pattern that governs every other workspace pin.

---

## 2. Outbound circuit construction

### 2.1 v1 decision: client-side outbound only

At v1, `TorTransport` supports outbound stream construction:

```rust
let stream: TorStream = transport
    .connect(target_host, target_port, retry_budget)
    .await?;
```

`target_host` is either a hostname (resolved over Tor via Arti's DNS-over-Tor) or an `.onion` v3 address. For v1's SimpleX use case, the target is an SMP queue server's hostname / onion address per the SimpleX network configuration.

The returned `TorStream` implements `AsyncRead + AsyncWrite` and represents one circuit-isolated stream. Closing the stream closes the circuit (Arti's default isolation policy is per-stream).

### 2.2 Onion-service hosting (v1.5 architectural slot)

The architectural commitment in this decision: `TorTransport` will gain `host_onion_service(...)` at v1.5 when Briar lands. The v1 skeleton method returns `TorTransportError::OnionServiceHostingDeferred` so consuming code compiles against the eventual API without behavioral surprises.

### 2.3 No raw circuit control surface

`TorTransport` does NOT expose Arti's lower-level circuit construction (one-hop, vanguards-lite control, etc.). The crate's surface is "give me a stream to this target"; circuit policy is Arti's decision.

If a v1.5+ use case requires per-circuit control (e.g., bandwidth-limited reuse for batch operations), that's a follow-up D-doc.

---

## 3. Pluggable transports

### 3.1 Decision

Pluggable transports are configured at `TorTransport::new` via a `PluggableTransportConfig` arg. The config is parsed from a baked-in `pluggable_transports.toml` resource shipped per release — same posture as the witness pool `witnesses.toml` per D0023 §3.3.

```toml
[[transport]]
name = "obfs4"
bridge_line = "obfs4 1.2.3.4:443 FINGERPRINT cert=... iat-mode=0"

[[transport]]
name = "webtunnel"
bridge_line = "webtunnel ..."

[[transport]]
name = "snowflake"
bridge_line = "snowflake ..."
```

The transport list is RELEASE-SCOPED: changes ride Cairn releases. The user does not edit the file at runtime. This is the same posture D0023 §3.3 establishes for the witness pool — release-coordinated trust-root rotation.

### 3.2 Rationale

Three properties matter:

1. **Replaceability is architectural; selection is operational.** Per design brief §5.4: "The commitment at this level is that the transport layer is replaceable without disturbing the protocols above it. Specific transport selection is operational rather than architectural and is deferred to the system design spec."
2. **Release-coordinated transport rotation matches the Tor Project's guidance cadence.** Per §5.4: "transport choices appropriate at v1 release may be blocked by v2 because DPI evasion is a continuously-being-solved problem rather than a solved one." A Cairn release with an updated transport list is the unit of response.
3. **Baked-in resource avoids user-config attack surface.** Per the same logic as the Sigsum witness pool: user-editable bridge lines would expose the config to coercion, social-engineering, and supply-chain attacks against the user's local config. Shipping the bridge list as a release-signed resource keeps the trust root project-side.

### 3.3 Bridge-line acquisition (out-of-scope for this crate)

How bridge lines get acquired (Tor Project's BridgeDB, partner-organization out-of-band channels, user-pasted lines) is an operational concern. The v1 release ships with a baked-in set per the system design spec; v1.5+ MAY add an Android-shell UI for the user to paste a bridge line that the shell injects into a runtime-mutated `PluggableTransportConfig`. That's a follow-up decision; the crate surface supports it.

### 3.4 Fallback behavior

If a configured transport fails to bootstrap (bridge unreachable, transport binary missing), `TorTransport::new` surfaces `TorTransportError::PluggableTransportBootstrapFailed { transport_name }` and the caller decides whether to retry, fall back to a different transport, or error to the user.

The crate does NOT implement automatic transport-switching policy. That's a UI-layer decision: which transport is tried first, which is the fallback, when to escalate to the user — all live above the crate boundary.

---

## 4. Network-state transitions

### 4.1 Decision

The Android shell signals network-state changes via:

```rust
transport.observe_network_state(NetworkState::Online);
transport.observe_network_state(NetworkState::Offline);
transport.observe_network_state(NetworkState::Constrained); // e.g., metered cellular
```

`NetworkState::Online` triggers re-bootstrap of the Tor client if previously offline; existing circuits are validated and reused where possible.

`NetworkState::Offline` drops in-flight circuits + pauses bootstrap retries.

`NetworkState::Constrained` is advisory; the v1 implementation treats it as `Online` but a v1.5 enhancement may reduce keepalive frequency under constraint.

### 4.2 Rationale

Three properties matter:

1. **Shell-driven network observation.** The Android shell has the operating-system-level signal for network availability; the Rust core does not. Routing the signal through an explicit method call avoids the Rust core polling the OS layer (which would require a callback surface or platform-specific code that doesn't belong in `cairn-tor-transport`).
2. **Idempotent transitions.** Calling `observe_network_state(Online)` when already online is a no-op. The crate tracks its current state; transitions execute on edge changes.
3. **Foreground service interaction is shell-layer.** Per the research doc's Android-specific concerns: the messaging foreground service is a shell-layer concern; `cairn-tor-transport` is invariant to whether the shell-side service runs in foreground or background.

### 4.3 Reconnection policy

After `Online → Offline → Online`, Arti's bootstrap re-runs. Existing `TorStream`s held by callers fail with `TorTransportError::StreamClosed { reason: NetworkTransition }`; the caller (the SimpleX adapter) reconnects the affected streams per its own protocol-level retry logic.

---

## 5. Async surface

### 5.1 Decision

All I/O methods are `async fn`. The crate depends on `tokio = "=1.40.0"` per the workspace pin.

`RetryBudget` is re-exported from `cairn-sigsum-client` per D0023 §5.3 — the same type, same defaults (max 5 retries, 250ms initial, 60s cap), same caller-scoping discipline.

```rust
pub use cairn_sigsum_client::RetryBudget;
```

The bootstrap path and the `connect()` path both accept an optional `RetryBudget` argument; callers can shrink the budget for snappier failure surfacing on user-blocking operations.

### 5.2 Cancel safety

Dropping a future returned by `connect()` cancels the in-flight stream construction cleanly. Arti's `tokio` futures handle cancellation at every await point.

Mid-stream cancellation (dropping a `TorStream` mid-read or mid-write) closes the underlying circuit; the partial read/write state is the caller's responsibility per the standard `AsyncRead`/`AsyncWrite` contracts.

Bootstrap cancellation is delicate: cancelling a partial-bootstrap leaves the underlying Arti client in an unknown state. The crate's `TorTransport::new` is NOT cancel-safe — callers must let it run to completion or call `shutdown()` to clean up. This is documented on the constructor.

### 5.3 No `spawn_blocking` on the I/O path

Arti is a pure-async library; no CPU-bound crypto operations cross the boundary. The D0018 §4.1 `spawn_blocking` pattern doesn't apply here.

### 5.4 No exposure of `tokio::time` to consumers

The crate uses `tokio::time` internally (for backoff timing); consumers receive `Result<...>` or `Future<...>` types and do not see `tokio::time::sleep` or `tokio::time::timeout` in the public API. This keeps the crate's surface tokio-version-tolerant for future upgrades.

---

## 6. Failure modes + typed error surface

`TorTransportError` per D0018 §4.2 — indices, lengths, type tags only; no `Vec<u8>` payloads; no peer-supplied strings:

```rust
#[non_exhaustive]
pub enum TorTransportError {
    /// Underlying network failure (timeout, no-route-to-host) after
    /// the retry budget was exhausted.
    Network { retry_budget_used: u8 },

    /// Placeholder for the network-bound surfaces that aren't
    /// implemented yet. v1 skeleton ships with the testable load-
    /// bearing primitives + this stub; the actual Arti exercise
    /// lands when CI grows the integration harness per §9.
    NetworkUnreached,

    /// Arti client bootstrap did not complete within the budget.
    /// The retry-budget value names how many bootstrap retries
    /// were consumed.
    BootstrapFailed { retry_budget_used: u8 },

    /// All configured pluggable transports failed to bootstrap.
    /// `transports_attempted` names how many entries in the
    /// release's pluggable_transports.toml were tried.
    AllPluggableTransportsFailed { transports_attempted: u8 },

    /// A specific named pluggable transport failed to bootstrap.
    /// `transport_index` is the 0-based index into the configured
    /// list so the caller can correlate to the entry's name
    /// without the bridge line itself being in the error payload.
    PluggableTransportBootstrapFailed { transport_index: u8 },

    /// The pluggable_transports.toml could not be parsed.
    PluggableTransportConfigParse,

    /// `target_host` did not resolve over Tor.
    HostResolutionFailed,

    /// Tor connection refused or reset by the target.
    ConnectionRefused,

    /// Stream was closed mid-operation; the variant carries why
    /// the stream closed so the caller can decide retry policy.
    StreamClosed { reason: StreamCloseReason },

    /// Onion-service hosting is deferred to v1.5; the host_onion_-
    /// service() method returns this variant in v1 so callers
    /// compile against the eventual API.
    OnionServiceHostingDeferred,
}

#[non_exhaustive]
pub enum StreamCloseReason {
    /// Caller explicitly closed.
    CallerClose,
    /// Underlying circuit failed.
    CircuitFailure,
    /// Network state transitioned offline.
    NetworkTransition,
    /// Remote peer reset the connection.
    PeerReset,
}
```

### 6.1 No-error-oracle discipline

All variants carry small scalars or type tags. `transport_index` is the index into the project-owned `pluggable_transports.toml`, not a peer-controlled value. No bridge lines, no peer hostnames, no certificate bytes appear in error bodies.

### 6.2 Composability with upstream errors

`TorTransportError` does NOT directly wrap `arti_client::Error` (the upstream Arti error type). The wrapping is intentional: the upstream error variants reveal more about Arti's internal state than the no-error-oracle discipline allows, and we don't want Arti's `Display` output (which may include peer-controlled metadata) to leak through Cairn's error surface.

Each Arti error converts to a `TorTransportError` variant via an internal `From` impl that selects the appropriate type tag and discards the original payload.

---

## 7. Onion-service hosting (architectural slot for v1.5)

### 7.1 v1.5 commitment

This decision preserves the architectural slot for onion-service hosting per design brief §5.4's Briar v1.5 commitment. The v1 implementation stubs the API surface; the v1.5 D-doc fills in the body.

```rust
pub async fn host_onion_service(
    &self,
    config: OnionServiceConfig,
) -> Result<OnionServiceHandle, TorTransportError> {
    Err(TorTransportError::OnionServiceHostingDeferred)
}
```

### 7.2 Why now, not v1.5

Specifying the slot now means consuming-code (a future `cairn-briar-adapter` or equivalent) can compile against the same `TorTransport` handle without restructuring. The implementation cycle for v1.5 Briar adds the body; no client-side API churn.

---

## 8. Out of scope

This decision does NOT address:

1. **Specific Arti version pin.** Selected at implementation-cycle commit per §1.4's pin-audit criteria.
2. **Specific pluggable-transport bridge selection.** Per design brief §5.4, deferred to the system design spec. The v1 release's bridge list is set at release-pipeline time.
3. **User-pasted bridge lines.** v1.5+ Android-shell concern; the crate's `PluggableTransportConfig` supports runtime mutation but v1 doesn't expose it.
4. **Onion-service hosting body.** v1.5 D-doc concern; v1 stubs the API surface.
5. **Foreground service lifecycle.** Android-shell concern; the crate is invariant.
6. **Push-notification wake-up integration.** UnifiedPush + the foreground service together drive the wake-up; the crate's `observe_network_state` is what those callers invoke.
7. **Circuit isolation policy beyond the default.** Per-stream isolation is Arti's default; per-conversation isolation (one Tor identity per peer) is a v1.5+ enhancement requiring a separate decision.
8. **Tor-relay-operator coordination.** v1 uses the public Tor network; running project-operated Tor relays is design-brief §3.4 / §4.2 deferred.
9. **DPI-evasion strategies beyond pluggable transports.** Specific techniques (domain fronting beyond meek, traffic shaping) are operational + may evolve per Tor Project guidance; the crate is replaceable per §3.

## 9. Reversibility

The decisions in this document are mostly reversible:

- **Arti version rotation (e.g., 1.x → 2.x):** tractable; same coordinated release event as any other workspace pin. Arti's tokio API is stable across patch releases; major-version rotation may require API call-site updates.
- **Arti → system-Tor-via-SOCKS5:** tractable but expensive. Would require restructuring the crate's surface (Arti's onion-service hosting API has no direct SOCKS5 equivalent — system Tor uses ControlPort). The `TorTransport` handle's outbound `connect(...)` would survive; the onion-service slot would change shape. No existing data structure pins the choice.
- **Arti → Orbot (Option T-C from the research):** tractable for the outbound side (SOCKS5 to Orbot). Loses in-process onion-service hosting for v1.5 Briar; either Briar v1.5 specifies an Orbot-mediated onion-service path or the project rotates back to Arti at v1.5 ship.
- **Pluggable-transport configuration format change:** tractable; same coordinated release event as the witness pool TOML.
- **TorStream wire surface (AsyncRead+AsyncWrite) change:** the HARDEST. Once the SimpleX adapter (D0026) consumes it, the surface contract is locked. Same hardness as D0023's leaf-hash schema.

## 10. Implementation status

This D-doc is accepted. The matching `cairn-tor-transport` crate skeleton + Arti integration land as separate commits consuming D0025. Implementation order:

1. `cairn-tor-transport/src/{lib,error}.rs` — pure data + error surface, no Arti integration yet.
2. `cairn-tor-transport/src/config.rs` — `PluggableTransportConfig` + TOML parser per §3. Real + tested.
3. `cairn-tor-transport/src/transport.rs` — `TorTransport` handle stub returning `NetworkUnreached` for `connect()` + `OnionServiceHostingDeferred` for `host_onion_service()`. Configuration + accessor methods real + tested.
4. Workspace pin addition per §1.4: `arti-client = "=1.X.X"` at implementation-cycle time.
5. Arti integration: `connect()` body lands when CI grows an Arti-testing harness OR an opt-in integration-test flag against the public Tor network per D0023 §10's pattern.
6. `observe_network_state` body lands with the integration step.
7. CLI integration in `cairn-cli`: `tor-bootstrap` + `tor-connect` subcommands for end-to-end demo.
8. The onion-service hosting body lands at v1.5 per the Briar D-doc that follows.

The Android-shell `cairn-uniffi` surface that exposes `observe_network_state` to Kotlin is the `cairn-uniffi` D-doc's concern; this crate exposes the Rust-side method.

---

## 11. Cross-references

- [D0003 — implementation language](D0003-implementation-language.md) — Rust core; pure-Rust discipline this decision extends
- [D0006 — cryptographic envelope](D0006-cryptographic-envelope.md) — §3.5 forward secrecy on-wire (SimpleX provides this; Tor is anonymity-of-route)
- [D0015 — v1 release-security posture](D0015-v1-release-security-posture.md) — multi-channel distribution; the crate's audit posture rides D0015's release model
- [D0018 — engineering foundation](D0018-engineering-foundation.md) — §4.1 async discipline; §8.1 unsafe_code = forbid (no exception for this crate); §8.6 workspace layout
- [D0021 — library-pin audit](D0021-library-pin-audit.md) — pin discipline for Arti additions per §1.4
- [D0022 — cairn-storage layer](D0022-storage-layer.md) — no direct dependency, but pluggable-transports.toml release-bundling rides the same posture
- [D0023 — cairn-sigsum-client](D0023-sigsum-integration.md) — `RetryBudget` reuse per §5.1; baked-in TOML resource pattern per §3.1
- [D0024 — cairn-sigstore-verify](D0024-sigstore-release-verification.md) — release-bundle posture for the pluggable_transports.toml resource
- [D0026 — cairn-simplex-adapter](D0026-cairn-simplex-adapter.md) — the protocol-layer consumer of `TorStream`s this crate produces (forthcoming)
- [design brief §5.4 Communications Protocols](../design-brief.md) — Tor-as-transport commitment, pluggable-transport replaceability
- [docs/network-transport-research.md](../network-transport-research.md) — the substrate this decision rests on; Option T-A (Arti embedded) per §"Candidate Tor transport approaches"
- [Arti documentation](https://gitlab.torproject.org/tpo/core/arti) — upstream Arti project
