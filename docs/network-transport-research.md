# Network transport + messaging-protocol research

> **⚠️ Superseded for the integration-model decision (2026-05-30).** This document was written without first reviewing [D0020](decisions/D0020-integration-architecture.md), which had **already decided** the SimpleX + Tor integration model on the strength of the Sprint 3 consolidated triage research (`reviews/external-reads-consolidated.md`):
>
> - **SimpleX:** SimplOxide client against a SimpleX Chat CLI sidecar (D0020 §1) — NOT a project-owned Rust SMP client.
> - **Tor:** C-Tor via `guardianproject/tor-android` (D0020 §2) — NOT Arti embedded; Arti deferred per D0020 §2.7's gating events.
>
> This document's "Recommendation framework" reached **T-A (Arti embedded) + S-A (project-owned Rust SMP)**, which contradicts D0020. The contradiction was resolved in favor of D0020 after a security analysis found the pure-Rust bundle did not deliver a net security benefit — neutral-to-worse for Tor (C-Tor's memory-unsafety is process-isolated per D0020 §2.2; its audit maturity is itself a security argument) and **clearly worse for SimpleX** (reimplementing the audited PQ double-ratchet solo is the canonical "don't roll your own crypto" failure the design brief §3.4 forbids; D0020 §1.8 had already rejected the clean-room SMP path).
>
> **D0020 §1-2 is authoritative for the integration model.** D0025 + D0026 are re-anchored as the downstream crate-surface decisions that implement D0020. This document is retained as a record of the (incomplete, since it missed D0020) option analysis; its option taxonomy (T-A/T-B/T-C/T-D, S-A/S-B/S-C/S-D) is still a useful map, but the recommendation is void. The lesson: **survey existing D-docs before surveying external options.**

---

This document surveys the realistic options for the two coupled network-layer crates per D0018 §8.6's enumerated layout: `cairn-tor-transport` (the transport) and `cairn-simplex-adapter` (the messaging protocol on top of it). It is not the decision — D0025 and D0026 capture that (re-anchored under D0020 per the note above). This document is the substrate the decisions were meant to rest on.

The goal is the same as `storage-research.md`: make the option space legible so the trade-offs are explicit. What each path costs. What each path closes off. Where existing D-docs have already narrowed the search.

## What needs to be transported

From [implementation-status.md](implementation-status.md)'s DEFERRED-on-network rows, plus the trust-graph + recovery state already implemented:

### Per-conversation traffic (foreground UX)

| Item                                             | Volume                | Frequency                                    | Latency budget                                | Notes                                                       |
| ------------------------------------------------ | --------------------- | -------------------------------------------- | --------------------------------------------- | ----------------------------------------------------------- |
| Text message (E2EE under SimpleX double-ratchet) | ~200 bytes – a few KB | bursty, user-driven                          | sub-second perceived; multi-second acceptable | Cairn's primary user-visible surface                        |
| Attachment (image, doc)                          | KB – MB               | bursty                                       | seconds                                       | Multi-channel; some go via separate SimpleX file transfer   |
| Delivery receipt / read receipt                  | tens of bytes         | per-message                                  | seconds                                       | Optional per UX policy (per design brief §5.6 minimization) |
| Ratchet state advance ack                        | tens of bytes         | per-message                                  | seconds                                       | Folded into the message envelope                            |
| Group rekey / member-set change                  | low-KB                | rare (D0004 cuts the v1 group model further) | seconds                                       | v1 ships 1:1; group is v1.5+                                |

### Trust-graph + recovery propagation (background)

| Item                                                            | Volume                                      | Frequency                                | Latency budget              | Notes                                                                |
| --------------------------------------------------------------- | ------------------------------------------- | ---------------------------------------- | --------------------------- | -------------------------------------------------------------------- |
| Trust-graph operation propagation (attest / revoke / re-attest) | ~150 bytes                                  | rare per peer; bursty during onboarding  | minutes acceptable          | The op envelopes already exist; the wire transport is what's missing |
| Recovery peer share transfer at provisioning                    | ~64 bytes × 5 peers (one per recovery peer) | once per provisioning; once per re-split | minutes-to-hours acceptable | Per D0005; HIGH sensitivity (post-Shamir share material)             |
| Recovery peer share gathering during recovery                   | ~64 bytes × 3 peers minimum                 | once per recovery event                  | minutes-to-hours acceptable | Two-party coordination per peer                                      |
| Master attestation broadcast (op-identity rotation)             | ~200 bytes                                  | rare                                     | minutes acceptable          | Carried as a trust-graph op                                          |
| Sigsum log emission (commitment-only logging per D0023)         | small per-op                                | per trust-graph op                       | minutes acceptable          | Already substrated via cairn-sigsum-client                           |

### Volume estimates (back-of-envelope)

For a pilot user (10–15 contacts, modest message volume over months):

- Foreground text: dominant by message-count, small by per-message volume
- Attachments: dominant by per-event volume but rare in pilot
- Trust-graph + recovery: tens of envelopes total over months
- Sigsum emissions: one per trust-graph op

**Bottom line:** the network layer is text-message-heavy by frequency, attachment-heavy by per-event size, and trust-graph-light by total bytes. Recovery share transfer is rare but HIGH-sensitivity per-event.

## Constraints already locked in by existing D-docs

These narrow the option space before any new decision is needed.

### Design brief §5.4 — SimpleX as messaging protocol + Tor as transport

> "Messaging rides on SimpleX's identifier-less queue model … reaching contacts via Tor for transport-layer anonymity."

The PROTOCOL choice is locked. The TRANSPORT choice is locked. What remains: HOW to integrate each (which library? which embedding pattern? which interface to the Android shell?).

### D0003 — Rust core + Kotlin UI

The core implementation language is Rust per D0003. Two consequences:

1. Any SimpleX integration must present a Rust-callable surface. The reference SimpleX implementation is Haskell (`simplexmq`); a Haskell runtime would have to be embedded or run out-of-process if the reference impl is consumed directly.
2. Any Tor integration must present a Rust-callable surface. Two paths exist: Arti (pure Rust) or out-of-process Tor + SOCKS5.

### D0018 §4.1 — Synchronous crypto core; tokio at I/O surface only

> "Cryptographic core crates … are synchronous. The async runtime (`tokio` 1.51.x LTS) is reserved for I/O surface only (`cairn-tor-transport`, `cairn-simplex-adapter`, `cairn-sigsum-client`, `cairn-sigstore-verify`)."

Both new crates are explicitly named as async. The async pattern is settled; the open question is cancel-safety patterns (D0023's RetryBudget partially established this; one of the three pending decisions is consolidating across crates).

### D0018 §8.1 — `unsafe_code` posture

`cairn-tor-transport` and `cairn-simplex-adapter` are NOT on the §8.1 exception list (cairn-storage and cairn-uniffi are). Both crates must be `unsafe_code = "forbid"`.

Implications:

- Arti is pure-safe-Rust; compatible.
- System Tor + SOCKS5: client side can be safe Rust; subprocess management can be safe Rust.
- FFI to Haskell (simplexmq): would require `extern "C"` calls, which require `unsafe`. Compatible only if the FFI lives in a separate adapter crate flagged on the exception list (a new D-doc decision).
- Project-owned Rust SMP client: safe Rust; compatible.

### D0006 §3.5 — Forward secrecy ON-WIRE only; at-rest decryptable under unlock

> "Forward secrecy of on-wire message content via the SimpleX double-ratchet derivative; at-rest message history on the device remains decryptable under unlock regardless of ratchet state."

The on-wire FS property is delivered by SimpleX's double-ratchet derivative. The transport layer (Tor) does NOT need to deliver FS — SimpleX already does at the protocol layer. Tor's role is anonymity-of-route, not message-content confidentiality.

### D0006 §1.4 — AAD domain tags per protocol surface

Every signed envelope carries an AAD domain tag (`cairn-v1-trust-graph-op`, `cairn-v1-master-attestation`, `cairn-v1-capability-token`, etc.). The messaging-layer envelope will need its own tag (e.g., `cairn-v1-message-envelope`); D0006 §8's domain-separation discipline applies to message envelopes the same as everything else.

### D0004 — v1 scope cuts

Multiple v1 scope cuts touch the messaging layer:

- v1 ships 1:1 messaging; group messaging is v1.5+. The protocol layer must still support the group-membership-minimization property at v1 even with no v1 groups (so the v1.5 lift doesn't break the model).
- No iOS at v1. Platform fan-out (different OIDC providers, different Tor integration patterns) is not a v1 concern.
- Reproducible builds are v1.5; v1 ships the source-review posture per D0015.

### D0022 — at-rest storage layer

The on-disk side of the messaging layer (queued outbound messages, conversation ratchet state, received-but-unread state) is the cairn-storage substrate's concern. The network crates are the WIRE side; storage of the wire's input/output state is already substrated. The boundary is clean.

### D0023 — Sigsum integration

Sigsum is already substrated. The network crates do NOT have to re-substrate it; they CAN call into `cairn-sigsum-client::sigsum_emit` when emitting trust-graph ops that need logging. Same posture for `cairn-sigstore-verify` per D0024.

### Design brief §3.3 — observable metadata attack surface

> "Tor relay correlation; SimpleX queue identifier correlation; size-bin padding of graph deltas (metadata-fingerprint defense); identifier-less queue model."

The brief commits to size-bin padding for metadata-fingerprint defense. The protocol-layer implementation must support deterministic-size padding regardless of message content; this is a CONSTRAINT on whichever SimpleX integration approach we pick.

---

## Candidate Tor transport approaches

The space sorts into four categories.

### Option T-A: Arti (pure Rust Tor) embedded in-process

`arti` is the Tor Project's official Rust rewrite. Status as of 2026-05:

- Client mode (relay circuits + onion service connection initiation): stable; production-quality.
- Onion service hosting: stable since v1.2.x (2024-2026).
- Pluggable transports: supported via the `arti-client` API; bridges are configured at runtime.
- Embedding pattern: pure-library, no subprocess. Async tokio surface.
- Audit posture: pure Rust; no C interop; no separate binary to manage.

**Pros:**

- Pure-Rust discipline holds end-to-end. No subprocess management. No system Tor install required.
- Same async runtime (`tokio`) as the rest of the I/O layer; integrates cleanly.
- Onion-service hosting in-process is a natural fit for Cairn's onion-service identity model (a user's onion address is their identity at the transport layer).
- API surface is more disciplined than the C Tor ControlPort; less surface area for misuse.
- Updates ride the Rust release cadence rather than the user's system Tor cadence.

**Cons:**

- Younger codebase than C Tor; less battle-tested at the bleeding-edge feature surface (e.g., new pluggable transports, vanguards-lite).
- Larger binary footprint than a SOCKS5 client + system Tor (Arti = full Tor in-process; Cairn ships the Tor implementation with the app).
- Carries Arti's own dependency graph (substantial); pin-audit per D0021 will be a multi-line addition.
- If Arti has a security incident, the Cairn release rotates to ship the patch — same posture as any other Rust dep, but a higher-stakes one.

**Audit boundary:** Arti is in Cairn's audit scope at the pin-audit level (per D0021), not at the source-audit level. The pre-pilot audit per D0011 reviews the Cairn integration, not the entirety of Arti's source.

**Cancel-safety:** Arti's `tokio` client connections handle cancellation cleanly per the upstream API design. Mid-circuit cancellation is supported.

### Option T-B: System Tor binary subprocess + SOCKS5 + ControlPort

Cairn spawns a `tor` C-binary subprocess (or expects one to be running) and talks to it via SOCKS5 for connections + ControlPort for circuit / onion-service control.

**Pros:**

- C Tor is the most-deployed, most-audited Tor implementation; mature pluggable transport set; battle-tested at scale.
- Smaller per-crate code footprint (Cairn ships the IPC client, not the Tor implementation).
- Tor updates can happen independently of Cairn updates (system package upgrade).
- Standard Tor configuration model (torrc); operators familiar with it can debug at the Tor layer.

**Cons:**

- Adds a runtime dependency on a separate binary. On Android, this either means bundling `tor` (cf. Orbot's approach) or requiring Orbot installed — neither is purely-Cairn.
- ControlPort is a stringly-typed protocol; misuse is easy. The Rust client wrapping it has to be careful.
- Subprocess lifecycle adds operational complexity: start/stop, crash detection, restart-on-failure, log capture, fsync of state files.
- Two artifacts to audit / two release cadences to track. The §6.5 release-pipeline already tracks Rust deps; adding C Tor adds a separate dep audit.

**Audit boundary:** larger — both Cairn's IPC client AND the C Tor build / pin / vendoring posture.

**Cancel-safety:** SOCKS5 connections cancel cleanly. ControlPort sessions are more delicate.

### Option T-C: Android Orbot via SOCKS5 (Android-shell concern; Rust-neutral)

The Android shell uses Orbot (separate app) for Tor, exposed as a local SOCKS5 proxy. Cairn's Rust core just speaks SOCKS5 to localhost; the Android shell is responsible for ensuring Orbot is running.

**Pros:**

- Orbot is the established Android-Tor integration pattern; broad user familiarity in privacy-tool ecosystem.
- Decouples Cairn from Tor lifecycle entirely; less code in Cairn's audit scope.
- Trivial Rust surface — just a SOCKS5 client.
- iOS port (v3 per design brief §6) can swap Orbot for whatever the iOS equivalent is without touching the Rust core.

**Cons:**

- Requires an external app the user installs separately. Operational complexity at install time + at-update-time (Orbot version drift).
- No onion-service hosting at the Cairn level (Orbot supports it but requires extra coordination); cuts off the in-process onion-service identity model.
- Users in jurisdictions where Orbot is blocked or unavailable have no path.
- Orbot's own threat model is broader than Cairn's; trust-root inheritance per design brief §3.4 grows.

**Audit boundary:** smallest Rust-side; largest operational-side (Orbot trust placement).

### Option T-D: Raw SOCKS5 to user-provided Tor (any backend)

Cairn speaks SOCKS5 to a Tor endpoint at a configurable address; the user supplies whichever Tor they want (Orbot, system Tor, a remote Tor instance).

**Pros:**

- Maximum flexibility for advanced users.
- Trivial Rust surface.
- No Tor implementation bundled.

**Cons:**

- v1 pilot users are NOT advanced users (per design brief §6.3 + D0013); requiring them to configure their own Tor is a UX failure.
- Fragmenting the v1 user base across whatever-Tor-they-configured complicates support + debugging.
- Default-on path doesn't exist; "easy install" is not achievable.
- Same trust-root inheritance issue as Option T-C, multiplied by whatever the user picks.

**Verdict:** not a v1 candidate. Could land as a v1.5+ advanced option layered on whichever Option T-A/B/C is the v1 default.

---

## Candidate SimpleX integration approaches

### Option S-A: Project-owned Rust SMP client (Cairn implements the SimpleX Messaging Protocol per spec)

Cairn writes a Rust client of the SimpleX Messaging Protocol (SMP) per [the SimpleX protocol spec](https://github.com/simplex-chat/simplexmq/blob/master/rfcs/2022-04-25-simplex-messaging.md) and related RFCs. The same approach D0023 §3 takes for project-owned witness-cosignature verification.

**Pros:**

- Pure Rust; aligns with D0003 + the workspace pure-Rust discipline (modulo SQLite per D0022).
- Audit scope is wholly Cairn's; same audit posture as the rest of the protocol layer.
- Cancel-safety + error surface can match D0018 §4.2's typed-error discipline from day one.
- No FFI surface to manage; no Haskell runtime to bundle.
- Integrates cleanly with the existing canonical CBOR + COSE_Sign1 envelope discipline.

**Cons:**

- Substantial implementation work. SMP is a documented protocol but the spec covers session establishment, queue rotation, double-ratchet state, ack semantics, and per-queue server interactions — each is a meaningful module.
- Cairn becomes responsible for SMP wire-protocol correctness; any incompatibility with the reference Haskell impl is Cairn's bug to fix.
- Protocol updates (SMP v2, v3, v3.x) need to be tracked and re-implemented.
- No upstream feature reuse; if simplex-chat ships a new feature (e.g., file transfers, new ratchet improvements), Cairn re-implements it.

**Audit boundary:** wholly Cairn's; comparable in scope to D0006 + D0023 combined.

### Option S-B: FFI bridge to Haskell `simplexmq`

Cairn embeds the Haskell `simplexmq` library via the GHC C foreign function interface. The Rust core makes `extern "C"` calls into the linked Haskell library.

**Pros:**

- Reuses the SimpleX project's reference implementation; new SMP features come "for free" with library updates.
- Spec-compliance is by-construction (uses the same code the SimpleX project tests against).
- Less protocol-correctness work to audit.

**Cons:**

- Ships a Haskell runtime (GHC RTS) inside the Cairn binary. Substantial binary-size cost (megabytes); substantial audit-scope cost (the GHC runtime + the simplexmq dependency tree is large).
- `unsafe_code` is required at every FFI call site. `cairn-simplex-adapter` would need to move onto D0018 §8.1's exception list (a new D-doc decision).
- GHC RTS lifecycle interacts with tokio's runtime in non-trivial ways; cancel-safety semantics across the FFI boundary need careful design.
- Memory hygiene per D0018 §1.6 is hard to enforce across an FFI boundary (we can't `Zeroize` Haskell-allocated memory).
- The reference `simplexmq` library is GPL-3.0; AGPL-3.0 compatibility is fine in principle but the linking interpretation has nuances worth noting per D0019.
- Android NDK builds with GHC are not a settled toolchain pattern (GHC's cross-compilation story for Android is rough).

**Audit boundary:** Cairn's integration + the full GHC + simplexmq dependency tree at pin-audit level.

### Option S-C: Subprocess `simplex-chat` + Cairn IPC

Cairn spawns a `simplex-chat` (Haskell binary) subprocess and talks to it via the WebSocket / TCP control interface simplex-chat exposes.

**Pros:**

- Reuses the SimpleX project's reference implementation as a black box.
- Subprocess isolation means a simplex-chat crash doesn't take Cairn down.
- No FFI required; pure Rust client of a documented IPC surface.

**Cons:**

- Adds a runtime dependency on `simplex-chat` being installed (or bundled). Same Android-runtime concern as Option T-B's system Tor.
- IPC adds latency overhead per message; for ratchet-state mutations this is sub-millisecond, not a real issue, but adds a moving part.
- Two artifacts to ship + update; coordination cost per release.
- Same Haskell runtime concerns as Option S-B but in subprocess form; binary size + lifecycle.
- simplex-chat's full feature set (groups, file transfers, link previews) is way larger than Cairn's threat model wants; Cairn would be filtering its surface down rather than using a focused library.

**Audit boundary:** Cairn's IPC client + the operational posture around the simplex-chat binary (which version is shipped, how it's updated, what surface it exposes).

### Option S-D: Defer SimpleX; ship v1 on a simpler protocol

Cairn ships v1 with a Cairn-defined messaging protocol layered directly on Tor, deferring SimpleX integration to v1.5.

**Pros:**

- Smallest engineering scope at v1.
- Removes one upstream-integration risk from v1 ship path.
- Total control over wire format + threat-model surface.

**Cons:**

- Re-implements work SimpleX has already solved (queue rotation, identifier-less routing, queue ack semantics).
- Loses the design brief §4.3 differentiation that names "identifier-less queue model" as a v1 architectural commitment.
- Breaks the v1.5 protocol-upgrade path (existing v1 users would migrate to SimpleX at v1.5; protocol-migration is hard for messaging).
- Per design brief §3.4 trust-roots framing ("trust widely-deployed analyzed primitives, do not invent"), inventing a messaging protocol is exactly the failure mode.

**Verdict:** materially weakens the v1 architectural commitments. Listed for option-space completeness; not a serious candidate.

---

## Coupling between Tor + SimpleX choices

The two axes are not fully independent. Some pairings are more natural than others:

| Tor pick      | SMP pick      | Why this pairs                                                                                                                                                                                 |
| ------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T-A (Arti)    | S-A (Rust)    | Pure-Rust end-to-end; matches D0003 + workspace discipline. Single tokio runtime; single error surface; single audit scope.                                                                    |
| T-A (Arti)    | S-B (FFI)     | Awkward: Arti is pure Rust, simplexmq is Haskell. Mixing the runtimes adds no value vs. Option T-B + S-B.                                                                                      |
| T-B (sys Tor) | S-B (FFI)     | Both are "embed an upstream runtime"; consistent posture but doubles the dep-tree audit scope vs. T-A + S-A.                                                                                   |
| T-B (sys Tor) | S-C (subproc) | Two subprocesses; same operational posture for both; Cairn becomes a coordinator of two external runtimes. Maximum operational complexity.                                                     |
| T-C (Orbot)   | S-A (Rust)    | Tor lives in Orbot (Android-managed); Cairn owns the messaging protocol in Rust. Decoupled lifecycles; Cairn keeps protocol-layer ownership while delegating transport-layer hosting to Orbot. |
| T-C (Orbot)   | S-B / S-C     | Adds back a Haskell-runtime dependency despite Orbot already keeping Tor out of Cairn; loses the "lean Cairn" rationale of picking Orbot.                                                      |

The two natural fits are:

- **T-A + S-A** (pure-Rust everywhere; maximum Cairn-side ownership; biggest engineering scope)
- **T-C + S-A** (Orbot for transport, Cairn-owned protocol layer; smallest Cairn binary; depends on Orbot)

A third reasonable pairing per the design brief §6.3 pilot scale + D0015 release-security framing:

- **T-A + S-A with Orbot fallback at the Android shell layer** — Cairn ships Arti as the default in-process Tor + leaves the Android shell free to route through Orbot if it's available. This is a UX-layer decision, not a Rust-core one; the Rust core would just see "SOCKS5 endpoint" either way if the Android shell offered a SOCKS5 endpoint to the core.

---

## Encryption + threat-model layering

The v1 stack composes:

```
┌──────────────────────────────────────────────────────────┐
│ Cairn application message (canonical-CBOR per D0018 §2.3) │
│ + AAD domain tag per D0006 §1.4 + §8                      │
├──────────────────────────────────────────────────────────┤
│ SimpleX double-ratchet derivative (FS per D0006 §3.5)     │
├──────────────────────────────────────────────────────────┤
│ SMP wire format + size-bin padding (D0006 §3.3)           │
├──────────────────────────────────────────────────────────┤
│ Tor circuit (anonymity-of-route)                          │
├──────────────────────────────────────────────────────────┤
│ TLS to the SMP queue server (defense-in-depth)            │
└──────────────────────────────────────────────────────────┘
```

- The OUTBOUND message is canonical-CBOR Cairn data + AAD domain tag + COSE_Sign1 envelope for any signed pieces (trust-graph ops, capability tokens carrying messaging-layer signature).
- SimpleX adds FS via the double-ratchet; this is at the PROTOCOL layer per design brief §5.4.
- SMP carries the message through a queue with identifier-less routing per design brief §4.3.
- Tor anonymizes the ROUTE of the SMP wire bytes.
- TLS to the SMP queue server is defense-in-depth (not the primary confidentiality property; that's the double-ratchet).

The MESSAGE-LAYER threat surface that the new crates own:

- Cairn-message envelope construction + parsing (this is application-layer; layered on whatever SimpleX provides for message bodies)
- AAD domain-tag discipline for messaging envelopes (same as trust-graph; per D0006 §8)
- Size-bin padding policy (per design brief §3.3; metadata-fingerprint defense)
- Group-membership-minimization policy at the protocol layer (per design brief §3.3; even though v1 ships 1:1 only per D0004)
- Cancel-safety + retry budgets per D0018 §4.1 + D0023's RetryBudget precedent

---

## Android-specific concerns

### Foreground service for messaging

Android's background-execution limits (Doze, App Standby, Battery Optimization) mean the messaging layer needs a foreground service to maintain SMP queue connections + Tor circuits across user-inactive periods. This is an Android-shell concern; the Rust core just exposes the long-lived `MessagingClient` handle.

### UnifiedPush for wake-ups

Per design brief §5.4 + §3.4, UnifiedPush is the distribution-channel-availability dependency for push notifications. The Rust core's role: accept a "new message available" wake-up via the UniFFI callback layer per D0020 §3; reconnect SMP queue + flush messages. This is independent of Tor/SimpleX choice.

### Network state changes (wifi ↔ cellular ↔ offline)

Cairn must gracefully handle network-state transitions: pause queue connections when offline; resume on reconnect. Both Arti and system Tor handle the Tor-level transition; the SMP layer needs to reconnect on top.

### Background data restrictions

Some Android distributions (per-carrier restrictions, per-profile work-profile rules) restrict background data. The messaging client must surface "I cannot reach my queue right now" as a typed condition the UI can render; not as a silent failure.

### Battery + power management

Tor circuits + always-on SMP queue connections are bandwidth-light but constantly-on. Battery cost at v1 pilot scale (10–15 contacts) is dominated by Tor circuit keepalives, not SMP traffic. Arti's keepalive policy + C Tor's keepalive policy differ slightly; this is a tunable per-deployment.

---

## Trade-off summary table

| Dimension                                | T-A + S-A                                     | T-A + S-B                                  | T-B + S-A                                       | T-B + S-B                                | T-C + S-A                                           |
| ---------------------------------------- | --------------------------------------------- | ------------------------------------------ | ----------------------------------------------- | ---------------------------------------- | --------------------------------------------------- |
| Pure-Rust discipline                     | end-to-end                                    | Rust transport + Haskell protocol          | safe Rust client + C Tor binary                 | C Tor + Haskell protocol                 | safe Rust client + external Orbot                   |
| Audit surface                            | smallest in-Cairn; Arti is the heavy upstream | medium (Arti + GHC + simplexmq pin-audits) | medium (C Tor pin-audit + Cairn-owned SMP impl) | largest (C Tor + GHC + simplexmq)        | smallest in-Cairn; Orbot is operational             |
| Engineering scope to v1 (relative)       | LARGE (Cairn-owned SMP)                       | medium (Arti integration + FFI scaffold)   | LARGE (subprocess mgmt + SMP impl)              | medium (subprocess mgmt + FFI scaffold)  | LARGE (Cairn-owned SMP) + Orbot integration         |
| Operational complexity at runtime        | low (one runtime)                             | medium (GHC RTS lifecycle)                 | medium (subprocess lifecycle)                   | high (two upstream runtimes)             | medium (depends on Orbot's lifecycle)               |
| Binary size                              | medium-large (Arti embedded)                  | very large (Arti + GHC + simplexmq)        | small (sys Tor unbundled)                       | medium (sys Tor unbundled, GHC embedded) | smallest in-Cairn (Tor not bundled)                 |
| User install footprint                   | one APK                                       | one APK                                    | APK + system Tor                                | APK + system Tor                         | APK + Orbot                                         |
| Onion-service identity model (in-Cairn)  | natural fit                                   | natural fit                                | possible via ControlPort                        | possible via ControlPort                 | indirect (Orbot exposes onion services)             |
| Cancel-safety story                      | uniform tokio across both crates              | FFI boundary needs design                  | uniform tokio; ControlPort lifecycle delicate   | both above                               | uniform tokio for SMP; Orbot opaque                 |
| iOS portability (v3 per design brief §6) | best (pure Rust travels)                      | poor (GHC + iOS is unsettled)              | medium (system Tor iOS story exists)            | poor (GHC + iOS)                         | n/a — iOS uses an equivalent of Orbot               |
| v1 ship-risk                             | implementation-scope risk                     | FFI + binary-size risk                     | subprocess-mgmt + impl-scope risk               | both above                               | implementation-scope risk + Orbot-availability risk |

---

## Decision factors

### Axis 1: How much of the messaging-protocol surface should be in Cairn's audit scope?

If the answer is "as much as practical, so v1 pilot users can rely on the same audit posture as the trust-graph + recovery layers": S-A (project-owned Rust SMP client). This is the same logic D0023 §3 applied to witness-cosignature verification ("project-owned per-witness Ed25519 verify; no sigsum-go shim").

If the answer is "delegate as much as practical to upstream so Cairn's surface is small": S-B or S-C. This trades audit-scope for FFI/IPC complexity.

### Axis 2: How much pure-Rust discipline matters?

If the workspace pure-Rust discipline (modulo SQLite per D0022) is a strong commitment, T-A + S-A is the only pairing that holds it. Every other pairing breaks the discipline at one or both layers.

If pure-Rust is "preferred but not required at this layer": any pairing becomes acceptable; pick on other axes.

### Axis 3: What's the v1 engineering capacity?

Implementing SMP from spec (S-A) is substantial. The reference simplexmq's source is the existence proof that it's tractable — but its size + the protocol's feature surface mean this is a 6–12 week module for a solo developer per design brief §6.1's engineering-capacity framing.

If v1 ship timeline cannot absorb that scope:

- T-A + S-B reuses simplexmq as a Haskell library; cuts the protocol implementation work substantially but pays in FFI / binary-size costs.
- Defer SimpleX to v1.5 (S-D); reframe v1 as having a Cairn-defined messaging protocol — materially weakens v1's architectural commitments per design brief §4.3.

### Axis 4: How does the Android shell prefer to integrate?

If the Android shell wants Cairn to be self-contained (one APK, no external app dependency): T-A (Arti in-process). User installs just Cairn.

If the Android shell wants to delegate Tor to the established Orbot pattern: T-C. User installs Cairn + Orbot.

If the Android shell wants flexibility (user picks which Tor to use): T-D, but only as a v1.5+ option; v1 needs a default.

### Axis 5: Onion-service identity model

Per design brief §5.4, a user's onion address is their identity at the transport layer. This requires Cairn (or its delegate) to host onion services per user.

- T-A: hosts onion services in-process. Cleanest.
- T-B: hosts onion services via ControlPort. Possible; more delicate.
- T-C: hosts onion services indirectly via Orbot. Requires Orbot's onion-service support being available + Cairn coordinating with it.
- T-D: depends on user's Tor.

If onion-service identity is a v1 commitment (the brief implies it but D0004 didn't explicitly defer it), T-A or T-B is required; T-C may work if Orbot's onion-service path is reliable; T-D is not viable.

### Axis 6: Migration discipline

Whichever pair we pick, future versions may swap one component. The cleanest migrations:

- T-A → T-B (or vice-versa) keeping S-A: the SMP wire format does not change; users keep their messaging history; only the Tor implementation swaps.
- S-A → S-B (or vice-versa) keeping T-A: messy. The on-wire format is SMP; the on-disk format is Cairn's. Swapping the SMP client implementation could break compatibility with stored ratchet state if Cairn's state structs differ from simplexmq's.
- T-A + S-A → T-A + S-B: requires migrating ratchet state from Cairn's serialization to Haskell's; substantial migration work.

Locked-in once chosen at non-trivial cost. Same hardness as D0022's storage-engine pick.

---

## What this research doesn't decide

This document does not pre-decide:

- Which specific Tor library version to pin (Arti version, system Tor version) — the pin-audit per D0021 happens at decision time.
- The Cairn message envelope schema (analog of D0006's signed-op schema, but for messaging-layer wire bodies) — that's part of the actual D-doc.
- The size-bin padding policy (specific bin sizes; padding-on-noise policy) — that's a D-doc-level decision rooted in the design brief §3.3 commitment.
- Cancel-safety patterns specific to messaging (mid-conversation cancel; mid-attachment cancel) — those are tied to the picked implementation.
- The UniFFI surface that exposes the messaging client to the Android shell — that's the D0020 layer (and the pending cairn-uniffi D-doc).
- Whether Tor + SimpleX should be ONE D-doc or TWO. The two crates are coupled at the implementation layer but distinct at the architectural-commitment layer; two D-docs is the established pattern (D0022 + D0023 + D0024 are each one crate) but a single coupled D-doc has precedent (D0006 covers multiple envelope concerns).

---

## Recommendation framework (not the recommendation)

If the priority order is:

1. **Pure-Rust discipline + audit-scope ownership of the protocol layer** → **T-A (Arti) + S-A (project-owned Rust SMP)**. Largest engineering scope; smallest external trust surface; cleanest match to the workspace discipline established through D0023.
2. **v1 ship-timeline + reuse-the-reference-implementation pragmatism** → **T-A (Arti) + S-B (FFI to simplexmq)**. Cuts the SMP implementation scope; pays in FFI / Haskell-runtime / unsafe-code-exception costs.
3. **Lean Cairn binary + delegate Tor to the established Android pattern** → **T-C (Orbot) + S-A (project-owned Rust SMP)**. Smallest Cairn-side; depends on Orbot at install time.

Any of the three is defensible. The pick depends on whether the project values audit-scope ownership > engineering scope, audit-scope ownership > binary size, or pure-Rust discipline > everything else.

The recommendation that aligns with the rest of the workspace's established patterns (D0023's project-owned witness verification; D0024's project-owned Rust Rekor verifier per §3.1) is **T-A + S-A**. This continues the pattern of "Cairn owns the security-critical surface in Rust; upstream protocols are integrated, not re-implemented, but the verifier/client code on Cairn's side is Cairn-authored."

The trade-off the project would accept by picking T-A + S-A: ~6–12 weeks of additional v1 engineering scope, in exchange for a protocol layer that is wholly auditable in Rust and that does not require an FFI surface or a second runtime.
