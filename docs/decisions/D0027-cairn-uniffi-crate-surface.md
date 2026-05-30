# D0027 — cairn-uniffi: crate surface implementing the D0020 §3 FFI architecture

**Status:** Accepted
**Date:** 2026-05-30

## Context

D0020 §3 decides the FFI architecture: **UniFFI 0.31.1 (pinned) for the bulk Kotlin↔Rust surface; hand-written `jni-rs` / UniFFI `callback_interface` for Android KeyStore / StrongBox mediation.** D0020 §3 is thorough on the _mechanism_ — the `HardwareKeySigner` callback trait (§3.4), StrongBox latency justification (§3.5), `RustBuffer` memory management + opaque handles for secrets (§3.6), the sealed `NeverExport` marker trait (§3.7), attestation-root pinning (§3.8), GrapheneOS specifics (§3.9), cross-compile/Gradle (§3.10), version-pin discipline (§3.11), and alternatives (§3.13).

This document is **downstream of D0020 §3** — the same relationship D0025/D0026 hold to D0020 §1-2. D0020 §3 owns the FFI-architecture decision; this document specifies the `cairn-uniffi` crate surface that realizes it, filling only the gaps D0020 §3 leaves open. (This sequencing is deliberate per the 2026-05-30 process correction: survey the existing D-doc _first_, then specify the crate surface as its implementation, rather than re-deciding settled architecture.)

The genuine gaps D0020 §3 leaves to the crate-surface level:

1. The crate module layout (§1).
2. The enumerated export surface — which workspace types cross the boundary, and the opaque-handle vs. plain-record split per type (§2).
3. The FFI error facade — how the workspace's typed `*Error` enums cross the boundary as `uniffi::Error` enums while preserving the D0018 §4.2 no-error-oracle discipline (§3).
4. The `NeverExport` enforcement enumeration + the discipline-grep CI gate structure (§4).
5. Async-across-FFI — how the four async I/O crates export as Kotlin `suspend fun`s, and where the tokio runtime is registered (§5).

This document does NOT re-decide anything in D0020 §3: not the UniFFI 0.31.1 + jni-rs hybrid, not the `HardwareKeySigner` callback trait, not the memory-management pattern, not attestation pinning, not the cross-compile toolchain.

## Decision summary

| Concern                        | Decision                                                                                                                                                                                                                      | Rationale link |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| **Crate role**                 | `cairn-uniffi` is the SINGLE FFI boundary crate. No other crate carries `#[uniffi::export]`. It depends on the workspace crates and re-exposes a curated surface                                                              | §1             |
| **Module layout**              | `lib.rs` (UDL scaffold + setup) + per-domain modules (`identity`, `trust_graph`, `recovery`, `messaging`, `transparency`, `hardware`, `error`)                                                                                | §1             |
| **Export-surface rule**        | Secret-bearing types → `uniffi::Object` opaque handles (operation methods only; key bytes never lower). Public/derived data → `uniffi::Record` plain structs                                                                  | §2             |
| **Hardware mediation**         | `HardwareKeySigner` `callback_interface` per D0020 §3.4 (re-stated, not re-decided). Lives in the `hardware` module                                                                                                           | §2             |
| **Error facade**               | One `CairnFfiError` enum (`uniffi::Error`) per domain method group; each variant a flat type-tag mapping of the source crate's typed error. No `Vec<u8>`, no source-error nesting that could leak peer data through `Display` | §3             |
| **No-error-oracle across FFI** | The Kotlin-visible error carries the same indices/lengths/type-tags-only discipline as D0018 §4.2; the FFI mapping flattens (does not `#[from]`-nest) so upstream `Display` strings do not cross                              | §3             |
| **NeverExport enforcement**    | Every secret-bearing type implements `NeverExport` per D0020 §3.7; a CI discipline-grep gate asserts no `NeverExport` type appears in a `uniffi::Record` / `Lower` position                                                   | §4             |
| **Async export**               | The four async I/O surfaces export as Kotlin `suspend fun`s via `#[uniffi::export(async_runtime = "tokio")]`; cairn-uniffi owns the single tokio runtime registration                                                         | §5             |
| **Sync export**                | Crypto-core operations (sign, verify, envelope build, chain-walk) export as plain Kotlin funs; they are sub-millisecond + sync per D0018 §4.1                                                                                 | §5             |
| **UniFFI version**             | 0.31.1 pinned per D0020 §3.11 (re-stated). The pin lands in the workspace deps when the binding-generation body lands                                                                                                         | §6             |

---

## 1. Crate role + module layout

### 1.1 Decision

`cairn-uniffi` is the **single FFI boundary crate**. No `#[uniffi::export]` attribute appears in any other workspace crate. `cairn-uniffi` depends on the domain crates (`cairn-identity`, `cairn-trust-graph`, `cairn-recovery`, `cairn-storage`, `cairn-sigsum-client`, `cairn-sigstore-verify`, `cairn-tor-transport`, `cairn-simplex-adapter`) and re-exposes a curated, Kotlin-facing surface.

```text
cairn-uniffi/
├── src/
│   ├── lib.rs          — uniffi::setup_scaffolding!() + the tokio runtime registration (§5)
│   ├── hardware.rs     — HardwareKeySigner callback_interface per D0020 §3.4
│   ├── identity.rs     — capability-token + master-attestation exports
│   ├── trust_graph.rs  — trust-graph op build/verify + chain-walk + cascade-status exports
│   ├── recovery.rs     — Shamir split/reconstruct + peer-store exports
│   ├── messaging.rs    — SimplexAdapter Transport-seam exports (async)
│   ├── transparency.rs — sigsum emit/verify + sigstore release-verify exports (async)
│   ├── error.rs        — the CairnFfiError facade (§3)
│   └── never_export_gate.rs — compile-time + test assertions for §4
└── Cargo.toml
```

### 1.2 Rationale

1. **Single boundary keeps the export surface auditable in one place.** A reviewer evaluating "what can Kotlin reach + what secret types might leak" reads one crate, not eleven. This is the same audit-scope-concentration logic D0020 §3.1 applies to choosing UniFFI (a tool auditors recognize) over a bespoke per-crate FFI.
2. **The domain crates stay FFI-agnostic.** `cairn-crypto` et al. do not depend on `uniffi`; they expose normal Rust APIs. Only `cairn-uniffi` knows about the boundary. This preserves the `cairn-cli` + test consumers, which use the same domain APIs without the FFI layer.
3. **Per-domain modules mirror the workspace's existing decomposition** so the export surface maps 1:1 to the D-doc that owns each domain (D0006 identity, D0023 sigsum, D0024 sigstore, D0025 tor, D0026 simplex).

---

## 2. Export surface: the opaque-handle vs. plain-record split

### 2.1 Decision

The split rule, applied per type:

- **Secret-bearing or capability-bearing types → `uniffi::Object` (opaque handle).** Kotlin holds an `Arc`-handle pointer; the bytes never lower into the JVM heap. Only operation methods are exposed (e.g., `.sign(payload) -> Vec<u8>`, `.fingerprint() -> Vec<u8>`). This is D0020 §3.6's pattern, applied to the enumerated set below.
- **Public or already-derived data → `uniffi::Record` (plain struct).** Crosses by value as a flat record. These carry no secret material.

### 2.2 Enumerated surface (v1)

**Opaque `uniffi::Object` handles (operation methods only; no byte-lowering of secrets):**

| Type                     | Origin                                                   | Exposed methods (illustrative)                                               |
| ------------------------ | -------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `OpIdentityKeyHandle`    | wraps `cairn-crypto` op-identity `SecretBox<SigningKey>` | `fingerprint()`, `sign(payload)` — never `to_bytes`                          |
| `SimplexAdapterHandle`   | `cairn_simplex_adapter::SimplexAdapter`                  | `create_invitation()`, `accept_invitation()`, `send()`, `recv()` (async; §5) |
| `SigsumClientHandle`     | `cairn_sigsum_client::SigsumClient`                      | `sigsum_emit()`, `verify_chain_links_with_sigsum()` (async)                  |
| `TorTransportHandle`     | `cairn_tor_transport::TorTransport`                      | `connect()`, `observe_network_state()` (async + sync)                        |
| `SigstoreVerifierHandle` | `cairn_sigstore_verify::SigstoreVerifier`                | `verify_release()` (async)                                                   |
| `StorageHandle`          | `cairn_storage::Storage`                                 | category put/get/delete (the handle wraps the SQLite connection)             |

**Plain `uniffi::Record` data (public / derived; cross by value):**

| Type                      | Origin                                   | Notes                                                     |
| ------------------------- | ---------------------------------------- | --------------------------------------------------------- |
| `QuarantineStatusRecord`  | `cairn_trust_graph::QuarantineStatus`    | the cascade-status enum + its fields; public              |
| `VerifiedReleaseRecord`   | `cairn_sigstore_verify::VerifiedRelease` | the verified manifest; public release data                |
| `EmitOutcomeRecord`       | `cairn_sigsum_client::EmitOutcome`       | record_id + leaf_hash + emission_status; public           |
| `ReceivedMessageRecord`   | `cairn_simplex_adapter::ReceivedMessage` | sender pubkey + payload + timestamp                       |
| pubkey / hash byte arrays | various                                  | `Vec<u8>` of PUBLIC keys + hashes — these are not secrets |

### 2.3 The hardware callback (re-stated from D0020 §3.4, not re-decided)

`hardware.rs` declares the `HardwareKeySigner` `callback_interface` exactly per D0020 §3.4 — `sign(key_alias, payload)`, `generate_key(key_alias, spec)`, `attestation_chain(key_alias)`. Kotlin implements it against Android KeyStore; the device + operational-identity signing keys never leave StrongBox. This document does not modify the trait; it only fixes its module home.

### 2.4 What is NOT exported

- No `SigningKey` / `SecretBox` / `Zeroizing` type lowers as bytes (enforced per §4).
- No `RatchetState` — SimpleX owns the ratchet per D0026; there is no Cairn ratchet to export.
- No raw storage DEK / KEK / per-record nonce — those stay inside `cairn-storage`.

---

## 3. The FFI error facade

### 3.1 Decision

UniFFI requires exported fallible functions to return a `Result<_, E>` where `E` derives `uniffi::Error`. The workspace's typed errors (`SigsumError`, `StorageError`, `TrustGraphError`, `SimplexAdapterError`, `TorTransportError`, `SigstoreVerifyError`) are NOT directly exported. Instead `cairn-uniffi` defines a **`CairnFfiError`** enum (`uniffi::Error`) whose variants are a **flat type-tag mapping** of the source errors.

```rust
#[derive(uniffi::Error)]
pub enum CairnFfiError {
    // Identity / trust-graph / recovery (sync-core)
    SignatureVerifyFailed,
    CapabilityScopeMismatch,
    ChainLinkInvalid { op_index: u32 },
    // Storage
    StorageRecordNotFound,
    StorageDecryptFailed,
    // Transparency (sigsum / sigstore)
    SigsumInsufficientWitnesses { valid: u8, required: u8 },
    SigsumInclusionVerifyFailed,
    SigstoreFulcioChainInvalid,
    SigstoreRekorVerifyFailed,
    // Messaging / transport
    SidecarUnavailable,
    EnvelopeSignatureVerifyFailed,
    TorBootstrapIncomplete,
    // Catch-alls (forward-compat for #[non_exhaustive] sources)
    NetworkUnreached,
    UnmappedInternal,
}
```

### 3.2 Rationale: the no-error-oracle discipline must hold across the FFI boundary

This is the most security-relevant gap D0020 §3 leaves open. Three properties:

1. **Flat mapping, NOT `#[from]`-nesting.** If `CairnFfiError` wrapped the source errors (`#[from] SigsumError`), UniFFI would lower the source error's `Display` string to Kotlin. Some source `Display` strings are safe, but the boundary is exactly where an attacker-probed error message could leak. The flat mapping reproduces only the type-tag + the bounded scalars (indices, counts) the source error already exposes per D0018 §4.2 — never a `Vec<u8>`, never a peer-supplied string. The same no-error-oracle discipline the source crates hold (D0006 / D0018 §1.4) is reproduced at the boundary, not bypassed by it.
2. **Each source crate's `#[non_exhaustive]` is absorbed by `UnmappedInternal`.** A future source-error variant that this build's mapping does not cover maps to `UnmappedInternal` rather than failing to compile or leaking a default `Display`. Same posture as D0023's `TrustGraphStoreUnknown` sentinel.
3. **`NetworkUnreached` crosses as a distinct variant** so the Kotlin shell can render "not yet implemented / offline" distinctly from a hard failure during the skeleton phase + the eventual offline cases.

### 3.3 Mapping is total + tested

`error.rs` provides `From<SigsumError> for CairnFfiError` (and the other five) as total matches with explicit wildcard → `UnmappedInternal` arms. A test asserts each source error's documented variants map to a non-`UnmappedInternal` `CairnFfiError` (so a new source variant that should have a real mapping surfaces in CI rather than silently degrading to `UnmappedInternal`).

---

## 4. NeverExport enforcement

### 4.1 Decision

Per D0020 §3.7, `cairn-crypto` already defines the sealed `NeverExport` marker trait (`crates/cairn-crypto/src/never_export.rs`). This document fixes the enforcement enumeration + the CI gate:

1. **Every secret-bearing type implements `NeverExport`:** `SecretBox<SigningKey>`, `Zeroizing<T>`, the storage DEK/KEK wrapper types, and any future secret-bearing type. (`cairn-crypto` owns the impls; cairn-uniffi consumes the marker.)
2. **`cairn-uniffi` exposes NO `NeverExport` type as a `uniffi::Record` field or a `uniffi::Lower` argument/return.** Opaque `uniffi::Object` handles MAY hold a `NeverExport` type as a private field (that's the point — the bytes stay Rust-side), but the type never lowers.
3. **CI discipline-grep gate** per D0020 §3.11 step 3: a CI script greps the generated UDL + the `#[uniffi::export]` signatures and fails if any `NeverExport`-marked type name appears in a lowering position. `never_export_gate.rs` additionally carries a compile-time `static_assertions`-style check + a test that constructs the export surface and asserts (by type) no secret type is reachable as bytes.

### 4.2 Rationale

D0020 §3.6 + §3.7 establish the pattern + the marker; §3.11 + §3.12 reference the discipline-grep gate + the `fuzz_uniffi_boundary` harness but do not specify their structure. This section makes the enforcement concrete: the marker trait is necessary but not sufficient — the CI gate is what catches a future `#[uniffi::export]` that accidentally lowers a secret. The gate is the executable form of the "secret types MUST NOT cross the UniFFI boundary as byte arrays" rule (D0020 §3.6).

---

## 5. Async across the FFI boundary

### 5.1 Decision

The four async I/O crates (`cairn-sigsum-client`, `cairn-sigstore-verify`, `cairn-tor-transport`, `cairn-simplex-adapter`) export their `async fn` methods as **Kotlin `suspend fun`s** via UniFFI's async support: `#[uniffi::export(async_runtime = "tokio")]`. `cairn-uniffi` owns the **single tokio runtime registration** for the whole boundary (in `lib.rs`).

The sync crypto-core operations (capability-token build, envelope sign/verify, chain-walk, cascade-status, Shamir split/reconstruct) export as **plain Kotlin funs** — they are sub-millisecond + synchronous per D0018 §4.1 and need no async surface.

### 5.2 Rationale

1. **This is the largest gap D0020 §3 leaves open.** D0020 §3 sketches sync examples (`build_capability_token`) but does not address that four of the workspace crates are async (D0018 §4.1 reserves tokio for them). Without a decision here, the async surfaces could not cross the boundary at all.
2. **Single runtime registration avoids multiple-runtime hazards.** All four async crates already share the same tokio 1.40 pin + the same `RetryBudget` discipline (D0023 §5.3). Registering one tokio runtime at the cairn-uniffi layer means a single executor drives every async export; the Kotlin side sees uniform `suspend fun` semantics.
3. **The StrongBox-latency split (D0020 §3.5) is consistent with this.** The hardware callback (`HardwareKeySigner`) is invoked from Kotlin's side synchronously within a Rust async export when needed; the ~250ms StrongBox cost lands inside a `suspend fun` the Kotlin UI already awaits off the main thread. No new latency surface.

### 5.3 Cancel-safety across the boundary

The async exports inherit each source crate's documented cancel-safety (D0023 §5.2, D0025 §5.2, D0026 §7). Kotlin coroutine cancellation drops the Rust future; the per-crate cancel-safety contract governs what partial state (if any) survives. The not-cancel-safe operations (e.g., `SimplexAdapter` queue rotation if it lands; `TorTransport::new` bootstrap) are documented on the Kotlin `suspend fun` so the shell does not cancel them mid-flight.

---

## 6. UniFFI version + workspace pin

UniFFI 0.31.1 pinned exactly per D0020 §3.11 (re-stated, not re-decided). The pin + the `uniffi-bindgen` build-dep land in the workspace `[workspace.dependencies]` when the binding-generation body lands per §8. The upgrade discipline (binding regeneration, signature re-validation, discipline-grep re-run, fuzz re-run, follow-up D-doc) is D0020 §3.11's; this document does not modify it.

---

## 7. Out of scope

1. **The FFI mechanism** — D0020 §3 (UniFFI + jni-rs hybrid).
2. **The `HardwareKeySigner` trait definition** — D0020 §3.4 (re-stated in §2.3, not modified).
3. **Memory-management pattern, attestation pinning, GrapheneOS specifics, cross-compile toolchain** — D0020 §3.6–§3.10.
4. **The Kotlin side** — the `AndroidKeyStoreSigner` impl, the coroutine call sites, the `AutoCloseable`/`use {}` discipline for opaque handles (D0020 §3.6) — Android-shell concern.
5. **The `fuzz_uniffi_boundary` harness implementation** — gated on the binding-generation body; D0018 §5.2 fuzz infrastructure owns the harness shape.

## 8. Implementation status

This document is accepted. The matching `cairn-uniffi` crate skeleton lands as a separate commit. Implementation order:

1. `cairn-uniffi/src/{lib,error}.rs` — the `CairnFfiError` facade + the total `From` mappings (§3). Real + tested (no UniFFI binding generation needed for the mapping logic).
2. `cairn-uniffi/src/never_export_gate.rs` — the compile-time + test enforcement (§4). Real + tested.
3. `cairn-uniffi/src/hardware.rs` — the `HardwareKeySigner` trait declaration (§2.3). The `callback_interface` UniFFI attribute is feature-gated so the skeleton compiles without the UniFFI proc-macro until the binding-generation body lands.
4. The per-domain export modules + the actual `#[uniffi::export]` attributes + the UDL generation land when the Android-shell build pipeline (cargo-ndk-android-gradle per D0020 §3.10) is stood up. Until then the skeleton ships the error facade + the NeverExport gate + the trait declarations as the testable load-bearing primitives.
5. Workspace pin addition: `uniffi = "=0.31.1"` per D0020 §3.11, added when step 4 lands.

The skeleton's testable surface is the error facade (the security-critical no-error-oracle mapping) + the NeverExport enforcement — the two things that most need to be right before any byte crosses to Kotlin.

---

## 9. Cross-references

- [D0020 — integration architecture](D0020-integration-architecture.md) — §3 owns the FFI architecture this document implements; §3.4 HardwareKeySigner; §3.6 memory management; §3.7 NeverExport marker; §3.11 version pin + upgrade discipline; §3.12 engineering scope
- [D0018 — engineering foundation](D0018-engineering-foundation.md) — §1.4 / §4.2 no-error-oracle (reproduced across the boundary per §3); §4.1 sync-core / async-I/O split (the §5 export split); §5.2 fuzz infrastructure; §8.1 unsafe_code (cairn-uniffi is on the §8.1 exception list with cairn-storage); §8.6 workspace layout
- [D0006 — cryptographic envelope](D0006-cryptographic-envelope.md) — the identity / trust-graph / capability-token surfaces exported per §2
- [D0022 — cairn-storage](D0022-storage-layer.md) — the `StorageHandle` opaque export + the KeyProvider callback boundary
- [D0023 / D0024 / D0025 / D0026] — the four async I/O crates whose surfaces export as `suspend fun`s per §5
- [implementation-status.md](../implementation-status.md) — the StrongBox / Android-shell rows this crate unblocks
