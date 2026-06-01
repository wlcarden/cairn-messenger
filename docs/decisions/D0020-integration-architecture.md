# D0020 — Integration architecture: SimpleX + Tor + FFI hybrid

**Status:** Accepted
**Date:** 2026-05-29
**Revised:** 2026-06-01 — corrected the SimplOxide cargo feature name in §1.1 (`websocket`, not `ws`); see the §1.1 revision note.

## Context

Per the consolidated external-reads triage Sprint 3 research (`docs/reviews/external-reads-consolidated.md`), seven research agents investigated current state-of-the-art for the three substantial integration surfaces Cairn must specify before v1 implementation begins:

1. **SimpleX integration** — how the Rust core talks to SimpleX's protocol stack; whether to FFI in-process, run as sidecar, reimplement, or hybrid
2. **Tor integration** — whether to embed arti, use C-Tor via JNI, or use Orbot; which pluggable transports to bundle; mobile lifecycle handling
3. **FFI architecture** — UniFFI vs hand-written JNI for the Rust↔Kotlin boundary; specifically how Android KeyStore and StrongBox operations are mediated when Rust cannot directly access the Android Java APIs

This decision document captures the integration architectures. Library and Rust-ecosystem decisions are documented separately in [D0018](D0018-engineering-foundation.md). License (AGPL-3.0-only) is documented in [D0019](D0019-license.md).

The decision document is partitioned into three integration topics:

1. SimpleX integration: SimplOxide + CLI sidecar
2. Tor integration: C-Tor via guardianproject/tor-android (arti deferred to v1.5+)
3. FFI architecture: hybrid UniFFI + hand-written jni-rs (KeyStore mediation)

Each topic specifies the integration mechanism, the rationale, alternatives considered, residual risks, and operational commitments.

## Decision summary

| Surface                       | v1 mechanism                                                                                           | Deferred to                                              | Rationale                                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| SimpleX                       | SimplOxide client + SimpleX Chat CLI sidecar (ForegroundService)                                       | —                                                        | License-isolation; production-proven pattern; auto-syncs to upstream                          |
| Tor                           | C-Tor via guardianproject/tor-android + Lyrebird PT bundle                                             | arti for v1.5+ migration                                 | C-Tor is Briar's production path; arti `tor-hsservice` self-documents as not production-ready |
| Pluggable transports          | Lyrebird single-binary bundle (obfs4 default + WebTunnel + Snowflake + meek user-selectable)           | Conjure as v1.5 candidate                                | Cat-and-mouse with censors requires remote-updateable bridge manifest                         |
| Onion-service hosting         | C-Tor control-port (v1.5+)                                                                             | arti `tor-hsservice` for v2+                             | tor-hsservice 0.42.0 still carries production-use warning                                     |
| FFI primary surface           | UniFFI 0.31.1 (pinned exact)                                                                           | Custom JNI bridge if profiling shows boundary bottleneck | Production-validated by matrix-rust-sdk + Bitwarden                                           |
| Android KeyStore mediation    | UniFFI `callback_interface` to Kotlin; Kotlin performs KeyStore operations; signatures return as bytes | —                                                        | Rust cannot directly access Android Java KeyStore API                                         |
| Capability-token co-signature | Two independent StrongBox calls per token (device-key + operational-identity)                          | —                                                        | Hardware-backed; neither key's material exits hardware                                        |

---

## 1. SimpleX integration

### 1.1 Decision

**Use SimplOxide (`simploxide-client` with the `websocket` feature) against a SimpleX Chat CLI sidecar process bundled into the Android app as a ForegroundService.** The Rust core's `cairn-simplex-adapter` crate consumes the SimplOxide typed API; the SimpleX Chat CLI binary is bundled as a per-ABI native asset from `simplex-chat-libs` releases and runs as a separate process; the Rust core communicates with it via local WebSocket on `127.0.0.1:5225`.

> **Revision 2026-06-01 — feature-name correction.** The original wrote the `ws` feature; the published `simploxide-client` v0.11.0 exposes the WebSocket transport under the **`websocket`** feature, with `cli` default-on. The decision is unchanged — SimplOxide over a loopback WebSocket to the CLI sidecar — only the cargo feature name is corrected. **Further revised 2026-06-01:** the implementation landed on the LOW-LEVEL **`simploxide-ws-core =0.2.0`** (a raw command/event WS client), NOT the high-level `simploxide-client` Bot SDK — the SDK does not compile on the pinned rust 1.85 (`const Duration::from_hours`) and its websocket-only build is upstream-broken. This D0020 decision is **unchanged** (ws-core is a SimplOxide crate; SimplOxide over a loopback WebSocket to the CLI sidecar) and needs **no MSRV coordination event**; the `=0.11.0` / `websocket` pin is moot. D0026 §12 records the full toolchain×feature probe matrix + the landed ws-core transport.

### 1.2 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Android app process                                          │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Kotlin UI shell (cairn-android-shell, cairn-ui)        │  │
│  └─────────────────────┬──────────────────────────────────┘  │
│                        │ UniFFI                              │
│                        ▼                                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Rust core (cairn-crypto, cairn-envelope, ...)          │  │
│  │   ▲                                                    │  │
│  │   │  cairn-simplex-adapter (uses simploxide-client)    │  │
│  │   ▼                                                    │  │
│  │   WebSocket: ws://127.0.0.1:5225                       │  │
│  └─────────────────────┬──────────────────────────────────┘  │
│                        │                                     │
│                        ▼                                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Android ForegroundService: SimpleXCliService           │  │
│  │   spawns: simplex-chat -p 5225 -d /data/.../simplex/   │  │
│  │   binary: libsimplex.so + libHSsimplex-chat-*.dylib    │  │
│  │   (pre-built from simplex-chat-libs releases)          │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

The CLI sidecar process and the Cairn app process are within the same Android app sandbox (no Binder boundary); communication is loopback WebSocket. The CLI is the unmodified upstream `simplex-chat` binary published in `simplex-chat-libs` releases.

### 1.3 Rationale

**License isolation.** SimpleX Chat is AGPL-3.0-only. Cairn is AGPL-3.0-only per [D0019](D0019-license.md). The CLI sidecar pattern keeps the SimpleX Chat source code in a separate process; Cairn's Rust core does not link AGPL-3.0 SimpleX Chat source statically. While Cairn's chosen license matches SimpleX's, the process-boundary isolation simplifies the license-compatibility audit story and preserves Cairn's flexibility if the project license is ever revisited (per D0019 Reversibility section, the license is partially-reversible only pre-public-release).

**Production-proven pattern.** SimplOxide is actively maintained (commit cadence; automated upstream sync via `autoupdater.sh`); its `simploxide-client` typed API auto-generates from SimpleX API docs so the binding stays current as the upstream protocol evolves. The official SimpleX Chat Android app bundles the same `libsimplex.so` for `arm64-v8a`, `armeabi-v7a`, `x86_64` and calls C functions from Kotlin via JNI; Cairn's sidecar pattern is a minor variation on this proven approach.

**Auto-sync to upstream.** SimplOxide 0.11.0 (May 24, 2026) tracks SimpleX Chat 6.5.3.0. The upstream-sync mechanism means Cairn does not need to track the SimpleX protocol evolution by hand; the binding stays current automatically.

**Avoids Haskell toolchain in Cairn's build.** Embedding `libsimplex` via FFI in-process would require Cairn's build environment to include Nix + GHC + Cabal/Stack (the Haskell cross-compile toolchain SimpleX uses to produce Android targets). The sidecar pattern lets Cairn consume pre-built `libsimplex.zip` artifacts from `simplex-chat-libs` releases without bringing the Haskell toolchain into Cairn's build pipeline. This materially reduces build-complexity surface.

### 1.4 Engineering scope estimate (surface-completion language)

`cairn-simplex-adapter` is complete when:

- SimplOxide client connects to the CLI sidecar at `127.0.0.1:5225` over WebSocket
- Cairn-initiated `/connect` produces a SimpleX invitation URI Cairn UI can render as QR code
- A second device pairs via `/connect <uri>` and the two devices exchange test messages successfully
- Cairn-side message-send/receive operations go through the adapter; the adapter's typed API matches Cairn's `cairn-transport` trait abstraction (per §1.10 below)
- ForegroundService lifecycle correctly manages the CLI process across Android lifecycle events (start, network change, app backgrounding, app kill, system memory pressure)

No calendar projection per D0018's empirical-metrics framing.

### 1.5 APK size implications

The CLI sidecar adds approximately **30-60 MB** to the APK install size, driven by:

- `libsimplex.so` per-ABI (~10-20 MB each)
- GHC runtime libraries (`libHSsimplex-chat-*-inplace-ghc*.dylib` plus `deps/` libraries)
- Both `arm64-v8a` and `x86_64` shipped per D0018 §7.2 target ABIs

For v1 pilot scale (10-15 users), this size is acceptable; pilot users are informed at consent that the APK is large because Cairn bundles SimpleX as a separate-process binary for license-isolation and operational-clarity reasons. D0013 pilot consent disclosure covers this.

For v1.5+ broader release, the APK size is worth reconsidering against:

- App Bundle dynamic delivery (Android App Bundle's dynamic feature module mechanism)
- F-Droid alternative distribution path size constraints
- User-experience implications of large initial download in low-bandwidth jurisdictions

This is a v1.5 architectural review item; no v1 commitment changes.

### 1.6 Android ForegroundService lifecycle

`SimpleXCliService` is an Android `Service` with `foregroundServiceType` set to **`remoteMessaging`** (per the Tor integration discussion in §2.5; same FGS type covers both Tor and SimpleX subsystems). The service:

- Starts when Cairn UI launches; persistent notification with bootstrap status
- Spawns `simplex-chat -p 5225 -d /data/data/...` as child process
- Restarts the child if it dies (with backoff; failure beyond threshold escalates to user-visible notification)
- On Android lifecycle network-change broadcasts: signals child to reconnect to SimpleX servers
- On low-memory conditions: keeps running (FGS protection); persistent notification + the explicit user consent at install time provide the operational justification

The child process's stdout/stderr is captured for diagnostic logging (release builds: INFO level only per D0018 §4.3 logging discipline; child-process output never includes secret material because the WebSocket boundary is the only path Cairn-secret material enters the CLI).

### 1.7 SimpleX governance signal

The SimpleX Network Consortium announced April 2026 provides "perpetual, irrevocable" protocol access surviving company sale or shutdown. This **materially reduces** a sustainability risk the brief's §3.4 trust roots framing previously had to absorb implicitly. The brief's §5.4 SimpleX integration paragraph and §3.4 trust roots can both reference the Consortium as a positive governance signal once D0020 lands.

### 1.8 Alternatives considered

**FFI in-process via `simploxide-ffi-core`.** _(Considered, rejected.)_ Embeds `libsimplex` in the Cairn app process. Avoids the WebSocket round-trip latency and the process-spawn complexity. Rejected because:

- Forces Cairn's Android build to include the Haskell cross-compile toolchain (Nix + GHC); materially increases build-system complexity
- AGPL-3.0 contagion is the same (Cairn already AGPL-3.0; not the discriminator)
- Lifecycle management of in-process FFI is more complex than ForegroundService child process management
- No production-Android documentation exists for non-SimpleX-team apps successfully shipping with this pattern

**Clean-room SMP-only Rust implementation.** _(Considered, rejected for v1; possible v2+ option.)_ Implement SMP wire protocol from spec in Rust. SMP is "closer to SMTP than to Signal" — substantially simpler than MLS or Signal Protocol. Rejected because:

- Engineering scope is large (~3-6 person-months for text-only 1:1 between two devices; ~3-6 additional months for hardening and upstream tracking)
- SimpleX's PQ-augmented double-ratchet with sntrup761 is non-standard; no off-the-shelf Rust crate matches it; reimplementing the PQ ratchet alone is multi-month work
- SimpleX team's policy permits this but they have not offered to audit third-party clean-room implementations
- The audit-credibility framing favors using SimpleX's reference protocol implementation via SimplOxide rather than introducing a parallel Rust implementation auditors must independently verify

**SimpleX-as-system-app with Cairn as separate client.** _(Considered, rejected.)_ User installs SimpleX Chat Android app; Cairn connects to it via local WebSocket the SimpleX CLI exposes. Rejected because:

- The production SimpleX Android app does not expose CLI mode by default; would require either forking SimpleX Android or contributing CLI-exposure upstream
- User-installation friction: pilot users would install two apps; partner-mediated consent protocol per D0013 would need to cover both
- The CLI sidecar pattern achieves the same architectural property (process boundary) without the user-install friction

**iOS framework reuse via Android NDK.** _(Considered, rejected.)_ Not viable. SimpleX iOS uses libsimplex compiled for Apple platforms (Mach-O); no path to reuse iOS binaries on Android.

### 1.9 Backup approach

If the CLI sidecar pattern proves operationally unworkable (e.g., Android background-process restrictions block the CLI from staying alive on representative pilot devices), the backup approach is **FFI in-process via SimplOxide `ffi-core`**. Cost: Cairn build pipeline absorbs the Haskell cross-compile toolchain (Nix + GHC + Cabal); license consequence is the same (Cairn is already AGPL-3.0).

Activation criterion: documented evidence over multi-week pilot-readiness test that the sidecar process cannot reliably persist across Android lifecycle events on at least two representative GrapheneOS-on-Pixel device models.

### 1.10 Cairn transport trait abstraction

Per the SimpleX research's coupling-minimization recommendation, Cairn's `cairn-simplex-adapter` implements a `cairn-transport` trait that abstracts the four SimpleX-specific properties Cairn depends on:

- Identifier-less queue addressing
- Double-ratchet forward secrecy + post-compromise security
- Self-hostable servers
- Out-of-band invitation flow

```rust
pub trait Transport: Send + Sync {
    type SendError: std::error::Error + Send + Sync + 'static;
    type RecvError: std::error::Error + Send + Sync + 'static;

    /// Create a new identifier-less queue and return an out-of-band invitation
    /// the peer can scan or paste to establish the connection.
    fn create_invitation(&self) -> Result<Invitation, Self::SendError>;

    /// Accept a peer's invitation and complete the out-of-band pairing.
    fn accept_invitation(&self, invitation: Invitation) -> Result<ConnectionId, Self::SendError>;

    /// Send a message over an established connection with forward-secrecy guarantees.
    async fn send(&self, conn: ConnectionId, payload: &[u8]) -> Result<(), Self::SendError>;

    /// Receive a message; blocks until next message or returns error on connection failure.
    async fn recv(&self, conn: ConnectionId) -> Result<Vec<u8>, Self::RecvError>;
}
```

This abstraction:

- Lets Cairn add Briar as the v1.5 second transport without changing `cairn-crypto`, `cairn-envelope`, `cairn-trust-graph`, or `cairn-recovery`
- Lets the `cairn-cli` tooling crate use a mock transport for end-to-end integration tests without spinning up the CLI sidecar
- Provides a clean Cairn-vs-SimpleX coupling boundary that the consolidated triage SimpleX research specifically recommended

---

## 2. Tor integration

### 2.1 Decision

**Use C-Tor via `guardianproject/tor-android` (`libtor.so` 0.4.9.8 or later) for v1.** The Rust core's `cairn-tor-transport` crate speaks SOCKS5 to `127.0.0.1:9050` for messaging traffic and uses Tor's control-port (cookie auth) for circuit management and event subscription. Bundle Lyrebird as a per-ABI native asset providing obfs4 + WebTunnel + Snowflake + meek pluggable transports.

**arti is explicitly deferred to v1.5+** as a migration target conditional on documented gating events (per §2.7).

### 2.2 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Android app process                                          │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Rust core (cairn-crypto, cairn-envelope, ...)          │  │
│  │   ▲                                                    │  │
│  │   │  cairn-tor-transport                               │  │
│  │   ▼                                                    │  │
│  │   SOCKS5: 127.0.0.1:9050  (messaging traffic)          │  │
│  │   Control: 127.0.0.1:9051 (cookie auth; circuit mgmt)  │  │
│  └─────────────────────┬──────────────────────────────────┘  │
│                        │                                     │
│                        ▼                                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Android ForegroundService: TorService                  │  │
│  │   wraps: libtor.so (C-Tor) via JNI                     │  │
│  │   spawns: lyrebird (PT subprocess) on demand           │  │
│  │   manages: SOCKS5 + control-port lifecycle             │  │
│  │   handles: ConnectivityManager network-change events   │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 2.3 Rationale

**Production-readiness gap in arti.** Per the Sprint 3 Tor research:

- `tor-hsservice` 0.42.0 self-documents as "not (yet) recommended for production use, or for any purpose that requires privacy" — Cairn's v1.5+ onion-service-hosting for release distribution cannot use arti
- `arti-client` API explicitly warned as pre-1.x unstable: "please expect a certain amount of breakage between now and us declaring arti-client 1.x"
- The Tor Project's own production mobile deployment (Tor VPN for Android) using arti via Onionmasq is still beta with Cure53-audited issues (18 findings; 4 exploitable)
- arti does not support the control-port protocol that onion-service hosting requires

**C-Tor matches Briar's production path.** Briar has used `guardianproject/tor-android` (originally derived from C-Tor) in production for years. This is the path the audit-firm record recognizes for messaging-tool Tor integration. Choosing this path puts Cairn's Tor integration on a substrate auditors have seen in prior comparable-project work.

**Pluggable transport bundling.** Lyrebird is the Tor Project's consolidated PT binary providing obfs4, meek, Snowflake, and WebTunnel in one process. Cairn bundles Lyrebird as a per-ABI native asset (`armeabi-v7a` skipped per D0018 §7.2; `aarch64-linux-android` and `x86_64-linux-android` shipped); the Tor process launches it as a subprocess per Tor PT spec v1.

**arti pluggable-transport support is incomplete.** Even when arti reaches v1.x stability, PTs are still launched as separate subprocesses (`tor-ptmgr` implements pt-spec.txt v1 only); the caller (Cairn) ships Lyrebird as a per-ABI asset regardless. The C-Tor vs arti decision does not change the PT-distribution burden.

### 2.4 Pluggable transport selection

**Default bundle:** obfs4 + WebTunnel via Lyrebird (single binary). Default selection at provisioning: obfs4.

**User-selectable in advanced settings:** Snowflake; meek-azure as last-resort fallback.

**Operational reality:** the bridge list is **remote-updateable** via a signed manifest fetched over Tor. This is a Cairn architectural commitment per the consolidated triage Tor research: WebTunnel went from "key tool in Russia" to "most bridges blocked" inside six months (June 2025); Snowflake DTLS fingerprinting hit in Russia March 2026. A static PT manifest will degrade to unusable under DPI shifts. **Bake remote configurability into v1 wire format.**

**Bridge manifest specification:**

- Fetched over Tor itself when possible (bootstrap-only fallback to direct fetch when no Tor circuit available)
- Signed via project Sigstore identity per [D0015](D0015-v1-release-security-posture.md) release-security stack
- Witness-cosigned via the Sigsum witness pool per [D0018](D0018-engineering-foundation.md) §2.4 witness threshold (minimum 3 witnesses, 2-of-3 acceptance)
- Versioned with rollback resistance (monotonic version numbers; client refuses lower-version manifests)
- Cached locally for offline operation

**Conjure** (Tor's newer PT, in Tor Browser alpha for Desktop and Android) is a v1.5 candidate. Its deployment footprint as of May 2026 is too narrow (small ISP cooperators) to make a v1 default; revisit at v1.5 architecture-completeness planning.

### 2.5 Mobile lifecycle: ForegroundService with `remoteMessaging` type

**Decision.** `TorService` is an Android `Service` with `foregroundServiceType = "remoteMessaging"` (Android 14+). Persistent notification shows Tor bootstrap status and circuit health.

**Rationale.** Per the consolidated triage research:

- `dataSync` foregroundServiceType was capped by Android 15 stricter timers; not appropriate for indefinite Tor connection
- `specialUse` is restricted; declaring it causes `ForegroundServiceTypeNotAllowedException` unless VPN/exact-alarm qualifying criteria are met
- `remoteMessaging` was added in Android 14; allowed to run without a visible activity when started from the background — the right fit for a messaging app's Tor connection

**No FCM.** FCM is Google's recommended Doze-mode workaround but is operationally a non-starter for a Tor-based messenger (centralized push; deanonymizes the receiver).

**Mailbox pattern as v1.5 architectural commitment.** Per the consolidated triage Tor research (and §5.4-5.5 brief implications), Briar Mailbox exists specifically because the battery-vs-always-online tension is fundamental for Tor messengers on mobile. **v1.5 architecture-completeness adds mailbox-style relay as an architectural commitment**: a separate device that holds messages, freeing the phone to be offline/Doze-friendly. This is documented as a v1.5 §7.1 architectural addition in the brief updates per §4 below.

### 2.6 Circuit isolation pattern

Per the consolidated triage Tor research's circuit-isolation guidance:

**Decision.** `IsolateSOCKSAuth` set in torrc. SOCKS5 username = `hash(conversation_id)` for per-conversation circuit isolation. Cairn's `cairn-tor-transport::send_via_circuit(conversation_id, payload)` encodes the username deterministically.

**Operational meaning.** Different SimpleX queues do not share Tor circuits at the network layer. An exit-node compromise still sees individual streams; cannot cluster them by source conversation. This is defense-in-depth, not categorical protection — global passive-adversary attacks against Tor as a whole remain outside Cairn's threat model per §3.4 trust roots.

**Documented limitation.** Per-conversation circuit isolation increases circuit-establishment latency; each new conversation pays a fresh-circuit cost. For Cairn's threat tier, this is acceptable; for high-frequency-conversation usage patterns, the cost would dominate. Documented in §5.4 brief update.

### 2.7 arti migration deferral with documented gating events

**Decision.** arti migration is a v1.5+ candidate gated on **three specific events**:

1. `arti-client` reaches 1.x stable (no longer warned as pre-1.x API-unstable)
2. `tor-hsservice` removes its "not recommended for production use, or for any purpose that requires privacy" warning AND publishes a Tor Project blog post explicitly endorsing arti for production messaging-tool embedding
3. A maintained UniFFI-wrapped mobile distribution exists (e.g., `arti-mobile-ex` graduates from experimental status)

If all three gating events occur, Cairn's v1.5 architecture review evaluates migration. If only some occur, Cairn stays on C-Tor and re-evaluates at the next release-planning cycle.

This is documented in the brief's §7.1 v1.5 entry and §5.4 Tor paragraph (per §4 brief updates below).

### 2.8 Onion-service hosting (v1.5+)

**Decision.** For v1.5+ release-distribution onion-service hosting per [D0015](D0015-v1-release-security-posture.md), use **C-Tor `ADD_ONION` via control-port API**. arti's `tor-hsservice` 0.42.0 still warned as not for production privacy use.

This is consistent with what Cwtch, Briar, and OnionShare use today. The control-port API approach is well-documented and audit-firm-recognized.

### 2.9 Network-change handling

`cairn-tor-transport` subscribes to Android `ConnectivityManager` callbacks. On WiFi/cellular handoff or network-disconnect events:

1. Existing Tor circuits are torn down via control-port (`SIGNAL NEWNYM`)
2. The Cairn application is notified that in-flight messages may need retransmission
3. Circuit re-establishment begins on next network availability

### 2.10 Tor's own operational health (informational)

Per the consolidated triage Tor research:

- ~8,000 active relays (mid-2025); ~5,300 guards; ~2,500 exits
- Funding pressure ("many digital rights projects lost their backing" in 2025) is the operational health signal worth tracking
- Counter Galois Onion (CGO) is a 2026 protocol-level improvement Cairn does not need to take action on; future upgrade path is preserved by not blocking it

Cairn's §3.4 trust roots framing on Tor remains as-is; no operational changes flow from this research beyond awareness of the funding-pressure signal for the project's biennial trust-roots health report per §9.4.

---

## 3. FFI architecture: hybrid UniFFI + jni-rs

### 3.1 Decision

**Use UniFFI 0.31.1 (pinned) for the bulk of the Kotlin↔Rust FFI surface; use hand-written `jni-rs` for hardware-element-mediated operations (Android KeyStore / StrongBox).** This hybrid matches matrix-rust-sdk/Element X and Bitwarden production patterns.

### 3.2 Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│ Android app process                                                  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Kotlin UI shell                                                │  │
│  │                                                                │  │
│  │   ┌──────────────────────┐  ┌─────────────────────────────┐    │  │
│  │   │ UniFFI bindings      │  │ Hand-written JNI wrappers   │    │  │
│  │   │ (bulk surface)       │  │ (KeyStore mediation)        │    │  │
│  │   │ - Envelope ops       │  │ - Sign with device key      │    │  │
│  │   │ - Trust graph ops    │  │ - Sign with op-identity key │    │  │
│  │   │ - Recovery flow      │  │ - Generate hardware key     │    │  │
│  │   │ - Storage I/O        │  │ - Get attestation chain     │    │  │
│  │   └──────────┬───────────┘  └──────────┬──────────────────┘    │  │
│  └──────────────┼─────────────────────────┼───────────────────────┘  │
│                 │                         │ callback_interface       │
│                 ▼                         ▼                          │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Rust core                                                      │  │
│  │   #[uniffi::export] / #[uniffi::Object] / callback_interface   │  │
│  │   HardwareKeySigner trait (implemented by Kotlin)              │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

UniFFI handles the 90%+ of FFI calls that don't touch hardware-element keys. For the small set of operations that require StrongBox/TEE access (capability-token signing; hardware key generation; attestation chain retrieval), Rust calls back into Kotlin via UniFFI's `callback_interface` mechanism; Kotlin performs the Android KeyStore call and returns the result (signature bytes; certificate chain bytes).

### 3.3 Rationale

**UniFFI for bulk:** matches matrix-rust-sdk/Element X (entire SDK surface including matrix-sdk-crypto-ffi); Bitwarden internal SDK; Mozilla Firefox storage/syncing. Production-validated; widely deployed.

**Hand-written JNI / callback-interface for KeyStore:** because **Rust cannot directly access Android KeyStore.** The KeyStore API is Binder-based Java; the `android-keyring` crate exists but explicitly states "should not be deemed mature enough for production level or sensitive applications." All KeyStore/StrongBox operations must be Kotlin-mediated.

**libsignal precedent (NOT followed for v1).** Signal uses a custom `bridge_fn` proc-macro that emits hand-tuned JNI/FFI/Node binding code. This is the gold-standard pattern for FFI control and performance. Cairn does NOT follow this approach for v1 because:

- libsignal's pattern is multiple engineer-years of investment Cairn cannot replicate
- UniFFI overhead is microseconds; Cairn's operations are millisecond-scale (signing a capability token takes 50-500ms on StrongBox per §3.5 below); FFI overhead is irrelevant
- Cairn's audit-credibility framing favors using a tool auditors recognize (UniFFI ships in Firefox; Bitwarden; Element X)

If profiling shows the FFI boundary becomes a bottleneck (e.g., high-frequency operations Cairn doesn't currently anticipate), the migration target is libsignal's pattern — but that's a v2+ consideration.

### 3.4 Hardware-element mediation pattern

**Rust side:**

```rust
#[uniffi::export(callback_interface)]
pub trait HardwareKeySigner: Send + Sync {
    fn sign(&self, key_alias: String, payload: Vec<u8>) -> Result<Vec<u8>, SignError>;
    fn generate_key(&self, key_alias: String, spec: KeyGenSpec) -> Result<PublicKey, KeyGenError>;
    fn attestation_chain(&self, key_alias: String) -> Result<Vec<Certificate>, AttestationError>;
}

#[uniffi::export]
pub fn build_capability_token(
    signer: Box<dyn HardwareKeySigner>,
    device_key_alias: String,
    op_key_alias: String,
    claims: CapabilityClaims,
) -> Result<CapabilityToken, BuildError> {
    let payload = canonical_encode(&claims)?;
    // Two independent StrongBox/TEE calls.
    // The signing keys never leave hardware. The signatures return as bytes.
    let sig_device = signer.sign(device_key_alias, payload.clone())?;
    let sig_op = signer.sign(op_key_alias, payload.clone())?;
    Ok(CapabilityToken {
        payload,
        sig_device,
        sig_op,
    })
}
```

**Kotlin implementation:**

```kotlin
class AndroidKeyStoreSigner(private val keyStore: KeyStore) : HardwareKeySigner {
    override fun sign(keyAlias: String, payload: ByteArray): ByteArray {
        val entry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(entry.privateKey)  // StrongBox/TEE; no material crosses
            update(payload)
            sign()                      // returns signature bytes
        }
    }

    override fun generate_key(keyAlias: String, spec: KeyGenSpec): PublicKey {
        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).run {
            setDigests(KeyProperties.DIGEST_SHA256)
            setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            setIsStrongBoxBacked(true)  // request hardware element
            setUserAuthenticationRequired(spec.requireAuth)
            setAttestationChallenge(spec.attestationChallenge)
            build()
        }
        kpg.initialize(parameterSpec)
        val keyPair = kpg.generateKeyPair()
        return PublicKey(keyPair.public.encoded.toList())
    }

    override fun attestation_chain(keyAlias: String): List<Certificate> {
        return keyStore.getCertificateChain(keyAlias).toList().map {
            Certificate(it.encoded.toList())
        }
    }
}
```

**Properties this pattern delivers:**

- Neither key's material exits hardware: `sign(device_alias, payload)` → device key signs in StrongBox; bytes return. `sign(op_alias, payload)` → operational identity signs in StrongBox; bytes return. The Rust core receives two signature byte arrays; it does NOT receive either signing key.
- Each `KeyStore` call is bound to one alias; there is no atomic two-key signing call but the security property is preserved (both keys' material stays in hardware)
- The pattern preserves D0006 §9 capability-token co-signature semantics

### 3.5 StrongBox latency: architectural justification for hours-to-days capability-token renewal

Per the consolidated triage UniFFI+Android research, StrongBox operations are dramatically slower than TEE:

- AES-GCM 1MiB on StrongBox: ~3 seconds
- Asymmetric key generation: >9 seconds on Pixel 8
- ECDSA P-256 signing: tens-to-hundreds of milliseconds
- Google's official documentation: "slower, more resource-constrained, supports fewer concurrent operations"

For Cairn's capability-token co-signature pattern (device + operational identity), expect **aggregate latency of ~50-500ms per token** depending on hardware. This is:

- **Acceptable for capability-token renewal at hours-to-days cadence** (the user pays ~250ms once every few hours; imperceptible UX cost)
- **Inappropriate for per-message signing** (a user sending 30-80 messages per day per the persona-04 review would pay ~7-40 seconds of cumulative signing latency per day)

**Architectural consequence:** the brief's §5.1 capability-token renewal cycle (hours-to-days; the user passphrase-prompted on renewal) is now justified by hardware latency cost, not arbitrary UX preference. This is a more defensible framing for partner-organization and audit-firm review than "we picked hours-to-days because it felt right." The brief's §5.1 paragraph is updated accordingly per §4 brief updates below.

**Per-message signing pattern:** the device key (in TEE, not StrongBox; faster signing) signs each message. The operational identity key (in StrongBox; slower) signs only the capability token periodically. This split is consistent with D0006 §9 and is now grounded in measured hardware performance.

### 3.6 Memory management at the UniFFI boundary

Per the consolidated triage UniFFI+Android research, UniFFI's `RustBuffer` does not implement `Drop`; it must be explicitly destroyed (`RustBuffer::destroy` or `RustBuffer::destroy_into_vec`). For Cairn's secret-handling discipline this means **secret types MUST NOT cross the UniFFI boundary as byte arrays.**

**Pattern: opaque object handles for secret-bearing types.**

```rust
#[derive(uniffi::Object)]
pub struct OpIdentityKey {
    // SecretBox does NOT implement uniffi::Lower; the type system prevents export
    key: SecretBox<SigningKey>,
}

#[uniffi::export]
impl OpIdentityKey {
    pub fn fingerprint(&self) -> Vec<u8> {
        // PUBLIC value returned: the fingerprint is not the key
        self.key.expose_secret().public_key().fingerprint().to_vec()
    }

    pub fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, SignError> {
        // Operation method: returns the public signature; key never crosses
        self.key.expose_secret().sign(&payload).map_err(Into::into)
    }
}
```

Kotlin holds an opaque pointer (UniFFI's `Arc<u64>` handle); the bytes never enter Kotlin's JVM heap. When Kotlin's `OpIdentityKey.close()` is called explicitly (or the wrapper is GC'd), UniFFI's free-function on the Rust side runs `Drop`, which runs `Zeroize::zeroize` on the inner SecretBox.

**Critical:** Never rely on Kotlin GC for zeroization of Rust-held secrets. Always call explicit `close()`. Per the consolidated triage research: "Destructors may not run when a process is killed, which can easily happen on Android." Kotlin code holding Cairn objects implements `AutoCloseable`; consumption follows `use { … }` blocks.

### 3.7 Sealed marker trait pattern: compile-time enforcement of "no secret types across UniFFI"

```rust
// In crates/cairn-crypto/src/never_export.rs
mod sealed {
    pub trait Sealed {}
}

/// Marker trait: implementing this prevents UniFFI export.
/// Manually implement on all secret-bearing types.
pub trait NeverExport: sealed::Sealed {}

// Apply to all secret types in cairn-crypto:
impl sealed::Sealed for SecretBox<SigningKey> {}
impl NeverExport for SecretBox<SigningKey> {}

impl<T: Zeroize> sealed::Sealed for Zeroizing<T> {}
impl<T: Zeroize> NeverExport for Zeroizing<T> {}
```

Combined with the CI grep gate per [D0018](D0018-engineering-foundation.md) §5.4 (rejects PRs where `#[uniffi::export]` functions take or return types in the disallowed list), this enforces "no secret bytes across UniFFI" structurally rather than by review discipline alone.

**Stable-Rust limitation:** `auto trait` and negative impls require nightly. The CI grep gate is the stable-Rust equivalent enforcement.

### 3.8 Android Attestation Root pinning

Per D0018 §9.3 operational commitments, Cairn pins both the old (RSA 4096) and new (ECDSA P-384) Android Key Attestation root certificates from day one. The 2026 rotation deadline (March 31, 2026) has passed; RKP-enabled devices exclusively use the new root from April 10, 2026. Annual review cadence per D0018 §9.3 keeps the trust anchors current.

### 3.9 GrapheneOS-specific considerations

**`hardened_malloc-rs` NOT used.** Per the consolidated triage research, GrapheneOS uses hardened_malloc as the system allocator by default; on stock Android the system allocator is Scudo. Both provide reasonable protections. Adding `hardened_malloc-rs` as Cairn's Rust global allocator creates a sized-deallocation mismatch surface (per GrapheneOS hardened_malloc issue #113) for marginal gain.

**Verified-boot attestation in Cairn's Rust core.** Cairn verifies the verified-boot fingerprint against both Google's attestation root chain and the GrapheneOS verified-boot key fingerprint published at <https://grapheneos.org/attestation.json> (with OpenSSH signature at `attestation.json.sig`). The attestation chain bytes are obtained via Kotlin (`KeyStore.getCertificateChain(alias)`) and passed to Rust for verification. Cairn must trust both the Google attestation root AND the GrapheneOS verified-boot key fingerprint to permit GrapheneOS users (this is the architectural commitment to support GrapheneOS as primary v1 platform per D0017 GrapheneOS-only v1 baseline).

**`Auditor` app reference.** GrapheneOS's `Auditor` app (MIT/Apache-licensed) is the reference implementation for verified-boot attestation. Cairn's verification logic in `cairn-identity` draws from Auditor's approach for the verified-boot extension parsing.

### 3.10 Cross-compile and Gradle integration

Per [D0018](D0018-engineering-foundation.md) §7:

- `cargo-ndk-android-gradle` (Willir's plugin) for per-buildType Rust profile control
- Android NDK r28+ for 16 KB page-size mandate compliance
- AGP 8.5.1+ for 16 KB alignment preservation in App Bundles
- Targets: `aarch64-linux-android` + `x86_64-linux-android` only (drop `armv7-linux-androideabi`)

### 3.11 UniFFI version pinning and upgrade discipline

UniFFI 0.31.1 pinned exactly per D0018 §9.2. Upgrade is a coordinated event requiring:

1. Kotlin binding regeneration (`uniffi-bindgen` against new UniFFI version)
2. Re-validation of all `#[uniffi::export]` function signatures (UniFFI's lift/lower behavior changes between minor versions)
3. Re-running the discipline-grep CI gate against the regenerated bindings
4. Re-running fuzz harness `fuzz_uniffi_boundary` with the new binding behavior
5. Documented upgrade rationale in a follow-up D-doc

Upgrade is not transparent; it's a non-trivial code-and-test event.

### 3.12 Engineering scope estimate (surface-completion language)

`cairn-uniffi` is complete when:

- UDL bindings generate cleanly for all `#[uniffi::export]` and `#[uniffi::Object]` items
- `HardwareKeySigner` callback interface is implemented in Kotlin against Android KeyStore
- Two-key capability-token signing produces verifiable tokens (device-key signature + operational-identity signature both verify against their respective public keys)
- Memory management discipline test (`fuzz_uniffi_boundary`) does not surface double-free, use-after-free, or Drop-skip scenarios
- Attestation chain verification round-trips: Cairn generates a hardware-backed key with attestation challenge; retrieves the chain via Kotlin callback; verifies the chain in Rust against Google's attestation root + GrapheneOS verified-boot fingerprint

No calendar projection per D0018's empirical-metrics framing.

### 3.13 Alternatives considered

**Pure UniFFI (no hand-written JNI).** _(Considered, rejected.)_ Rust cannot directly access Android KeyStore; without callback-interface, every KeyStore operation would require a Kotlin-mediated UniFFI call anyway. The decision to use UniFFI's `callback_interface` mechanism (which is what this document recommends) achieves the same property as hand-written JNI for the KeyStore path while keeping the rest of the FFI surface uniform under UniFFI.

**Pure hand-written JNI via `jni-rs`.** _(Considered, rejected for v1; libsignal's path.)_ Multiple engineer-years of investment Cairn cannot replicate. Profiling-justified migration path for v2+ if hot-path-call-rate dominates.

**`flapigen`.** _(Considered, rejected.)_ Less active than UniFFI; Mozilla's recommendation is UniFFI. Smaller user base.

**Mozilla `ffi-support`.** _(Considered, rejected.)_ UniFFI's predecessor; subsumed by UniFFI for the use cases Cairn has.

---

## 4. Brief and D-doc updates

The following brief sections receive updates referencing this decision:

- **§3.4 trust roots**: SimpleX Consortium governance signal (April 2026); Tor's funding-pressure signal as ongoing monitoring item
- **§5.1 capability-token renewal**: StrongBox latency (50-500ms per token) as architectural justification for hours-to-days renewal cadence; per-message signing via device key (TEE, faster); operational identity (StrongBox, slower) signs only capability tokens
- **§5.4 Tor**: C-Tor integration mechanism via guardianproject/tor-android; Lyrebird PT bundle (obfs4 default + WebTunnel + Snowflake + meek user-selectable); remote-updateable bridge manifest (signed via project Sigstore identity + witness cosigned); arti deferred to v1.5+ with documented gating events; per-conversation circuit isolation via SOCKS5 username hashing
- **§5.4 SimpleX**: integration mechanism is SimplOxide + CLI sidecar pattern; ForegroundService lifecycle with `remoteMessaging` type; APK size acknowledgment
- **§5.5 release security**: cross-reference to bridge-manifest signing requirements
- **§6.1 v1 engineering surface**: `cairn-transport` trait abstraction; `cairn-uniffi` hybrid pattern; Android NDK r28+; ForegroundService lifecycle for both Tor and SimpleX subsystems
- **§6.3 pilot deployment plan**: APK size acknowledgment as part of partner-mediated consent disclosure
- **§7.1 v1.5 entry**: mailbox-pattern relay as architecture-completeness item; bridge-manifest-rotation cadence
- **§7.1 v1.5 entry**: onion-service hosting via C-Tor control-port; arti migration as v1.5+ conditional candidate
- **§9.4 trust-roots health report**: bridge manifest rotation as biennial-or-as-needed item; SimpleX/Tor governance health as monitored items

### D-doc updates

- **D0013 pilot consent**: add APK size disclosure (~30-60 MB) and architectural-reason explanation (license isolation; sidecar pattern); add bridge-manifest signature trust path
- **D0015 release security**: cross-reference bridge-manifest signing as part of the Sigstore/Sigsum stack
- **D0017 CalyxOS inclusion**: verified-boot attestation parity check now has concrete D0020 §3.9 reference for what Cairn verifies

---

## Consequences

### Engineering scope additions

The integration architecture decisions add concrete engineering surface beyond what was previously vaguely framed as "SimpleX adapter" and "Tor adapter":

- `cairn-simplex-adapter` + ForegroundService for CLI sidecar lifecycle
- `cairn-tor-transport` + ForegroundService for C-Tor lifecycle + Lyrebird subprocess management + bridge-manifest fetcher + circuit-isolation discipline
- `cairn-uniffi` + Kotlin-side `HardwareKeySigner` implementation + attestation chain verification

Per D0018's empirical-metrics framing, no calendar projection. Each surface has surface-completion criteria specified above.

### Operational commitments

- Bridge manifest rotation cadence: as-needed when DPI shifts; the project publishes signed manifest updates per `cairn-tor-bridges` module
- Android Attestation Root rotation review: annual per D0018 §9.3
- SimpleX upstream sync: SimplOxide auto-syncs; Cairn validates compatibility with new versions during pre-release testing
- Tor upstream sync: `guardianproject/tor-android` and Lyrebird versions tracked; updates absorbed in regular release cycle

### Reversibility

- **SimpleX integration mechanism**: reversible at moderate cost. Switch from CLI sidecar to FFI in-process (or vice versa) is a build-pipeline change; lives in `cairn-simplex-adapter` plus the Android Service.
- **Tor integration mechanism**: reversible at high cost. Switch from C-Tor to arti requires the three gating events per §2.7 plus migration work in `cairn-tor-transport`. The `cairn-transport` trait abstraction in `cairn-simplex-adapter` is a Cairn-side property; Tor doesn't have a similar trait but it could be added if migration becomes worthwhile.
- **FFI mechanism**: reversible at very high cost. Switch from UniFFI to libsignal-style custom bridge would touch every `#[uniffi::export]` site plus the Kotlin binding. Treated as a v2+ consideration if profiling justifies it.

## References

### Sources consulted (Sprint 3 research agents, 2026-05-29)

- SimpleX integration: simplex.chat documentation; SimplOxide repository at github.com/a1akris/simploxide; SimpleX Chat repository; SimpleX team's third-party-client policy; SimpleX v6.5 Consortium announcement; Trail of Bits SimpleX review
- Tor + arti: Tor Project blog (arti 2.x release announcements; staying-ahead-of-censors-2025; advancing-digital-rights-in-2026); Briar source repository; Cwtch documentation; arti-client / tor-hsservice / tor-ptmgr docs.rs; Lyrebird repository; guardianproject/tor-android; Cure53 Tor VPN for Android audit; net4people/bbs Snowflake DTLS issue
- UniFFI + Android: mozilla/uniffi-rs; libsignal-rs bridge_fn documentation; matrix-rust-sdk; Bitwarden SDK; Android Key Attestation documentation; GrapheneOS Attestation Compatibility Guide; KeyDroid analysis paper (arXiv 2507.07927)

### Cross-references

- [D0003](D0003-implementation-language.md) — Rust core + Kotlin UI implementation language (foundational)
- [D0006](D0006-cryptographic-envelope.md) — Cryptographic envelope construction (consumes this document's FFI patterns for capability-token co-signature)
- [D0009](D0009-sudden-unavailability.md) — Sudden-unavailability contingency (consumes this document's ForegroundService lifecycle assumptions)
- [D0013](D0013-pilot-consent-exit.md) — Pilot consent (consumes this document's APK size disclosure requirement)
- [D0015](D0015-v1-release-security-posture.md) — Release security (consumes this document's bridge-manifest signing extension)
- [D0017](D0017-calyxos-inclusion.md) — CalyxOS inclusion (consumes this document's verified-boot-attestation specifics)
- [D0018](D0018-engineering-foundation.md) — Cryptographic library and Rust ecosystem foundation (this document consumes D0018 library decisions and discipline framework)
- [D0019](D0019-license.md) — Project license (consumes this document's SimpleX license-isolation rationale)
- [docs/reviews/external-reads-consolidated.md](../reviews/external-reads-consolidated.md) — Sprint 3 origin and triage
- [docs/design-brief.md](../design-brief.md) §3.4, §5.1, §5.4, §5.5, §6.1, §6.3, §7.1, §9.4
