# D0023 — cairn-sigsum-client: commitment-only logging + witness-cosignature verification

**Status:** Accepted
**Date:** 2026-05-29

## Context

D0018 §8.6 enumerates `cairn-sigsum-client` in the workspace layout but does not specify the leaf-hash schema, the HTTPS client, the caching strategy, or the witness-cosignature verification approach. The design brief §3.3 and D0006 §3.3 both spec **commitment-only logging**: Sigsum stores SHA-256 hashes of trust-graph operations, never operation content, so issuer/subject/context stay out of public view.

This decision specifies:

1. The leaf-hash schema (what byte string each trust-graph op contributes to Sigsum).
2. The HTTPS transport pin (`hyper`-based with no async-runtime exposure across the crate's public API).
3. The witness-cosignature verification approach (project-owned per-witness Ed25519 verification, no `sigsum-go` shim).
4. The caching strategy for log heads + previously-observed leaves (in `cairn_storage::categories::SIGSUM_CACHE`).
5. The cancel-safety + retry patterns for the async I/O surface.
6. The trust-graph integration point (when a leaf is emitted; when verification is triggered).
7. The failure modes and their typed-error surface per D0018 §4.2.

This decision does NOT specify witness pool recruitment, witness count, or witness threshold beyond what D0015 already commits: minimum 3 witnesses with 2-of-3 acceptance over any given log state.

## Decision summary

| Concern                              | Decision                                                                                                                                                                                                  | Rationale link |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| **Leaf hash**                        | `SHA-256( COSE_Sign1.signature_bytes( signed_op ) )` — same byte-input as D0006 §5's `prior_hash`                                                                                                         | §1             |
| **HTTPS transport**                  | `reqwest = "=0.12.x"` with `default-features = false, features = ["rustls-tls", "json"]` — no `native-tls`, no `cookies`, no system DNS leaks                                                             | §2             |
| **HTTP request body**                | Submit-leaf via Sigsum's documented `add-leaf` endpoint with the rfc6962-compatible request format                                                                                                        | §2             |
| **Witness-cosignature verification** | Project-owned per-witness Ed25519 verify against the witness pool config; no `sigsum-go` shim                                                                                                             | §3             |
| **Witness pool config**              | Static `witnesses.toml` shipped with the release; each entry: `name`, `pubkey_hex`, `url`. Pool changes require a release                                                                                 | §3             |
| **Acceptance threshold**             | 2-of-3 cosignatures over the same `tree_size`+`root_hash`+`timestamp` triple, with all three witnesses configured. Smaller pools (1 or 2 active) fail verification per D0015                              | §3             |
| **Log-head cache**                   | Latest signed `tree_head` per log endpoint, cached in `SIGSUM_CACHE` category; consistency proofs gated on monotonic `tree_size`                                                                          | §4             |
| **Leaf cache**                       | Per-op `(leaf_hash, inclusion_proof, observed_at)` cached in `SIGSUM_CACHE`. Re-verification skips network if cached proof matches current log head                                                       | §4             |
| **Async surface**                    | The `SigsumClient` exposes `async fn` methods. The crate is the first to depend on `tokio = "=1.51.x"` LTS per D0018 §6                                                                                   | §5             |
| **Cancel safety**                    | All network operations are wrapped in `spawn_blocking` for the verification phase; the `add-leaf` POST is naturally restart-safe (Sigsum is idempotent on identical leaf hashes)                          | §5             |
| **Retry policy**                     | Exponential backoff capped at 60s; max 5 retries for `add-leaf`; max 3 retries for proof fetches. Each call carries a `RetryBudget` the caller can scope                                                  | §5             |
| **Trust-graph integration**          | A new `cairn-trust-graph::sigsum_emit` module wraps `store_signed_op` so storage + Sigsum emission are colocated. Verification happens at chain-walk time via `verify_chain_links` extension              | §6             |
| **Split-view detection**             | The cache compares each new log head against the previous one; split-view (two log heads with the same `tree_size` but different `root_hash`) surfaces as a typed error and halts subsequent verification | §7             |

---

## 1. Leaf hash schema

### 1.1 Decision

For each signed trust-graph op, the Sigsum leaf hash is:

```text
leaf_hash = SHA-256( COSE_Sign1.signature_bytes( signed_op ) )
```

This is byte-identical to D0006 §5's `prior_hash` byte input.

### 1.2 Rationale

Three properties matter:

1. **Stable across implementations.** The hash commits to the operation's signature bytes — the unambiguous canonical commitment to the op's content per D0006 §5's existing rationale. Two implementations that produce the same signed op produce the same leaf hash.
2. **No content leakage.** Per design brief §3.3, the leaf hash MUST NOT reveal issuer/subject/context. SHA-256 of the signature bytes leaks no content; the signature itself is a cryptographically pseudorandom 64-byte string under EUF-CMA.
3. **Composable with the chain integrity primitive.** A consumer that has the signed op + its `prior_hash` can compute the leaf hash and verify the Sigsum inclusion proof; the same leaf hash that anchors the op's existence in Sigsum is the value the next op's `prior_hash` field commits to. Two distinct integrity properties chain on the same hash.

### 1.3 Discipline note

The leaf hash is NOT the entire signed envelope — just the signature bytes. This is intentional: the verifier must already possess the envelope (via the messaging layer per design brief §3.3) to extract the signature bytes and recompute the leaf. The leaf hash plus the inclusion proof prove only "this signature is in the log"; "this op signed this content under this key" requires the verifier to hold the envelope and run the existing `verify_chain` path.

---

## 2. HTTPS transport: `reqwest` with `rustls-tls`

### 2.1 Decision

```toml
reqwest = { version = "=0.12.5", default-features = false, features = ["rustls-tls", "json"] }
```

Disabled features (security-relevant rationale):

- `native-tls`: would route through the OS TLS stack (different across Pixel generations + GrapheneOS versions); rustls is pure-Rust + audited and gives reproducible TLS behavior across deployment targets.
- `cookies`: Cairn does not need HTTP cookies; disabling shrinks attack surface and removes a stateful behavior we'd otherwise have to reason about.
- `cookies-system`: same.
- `gzip`, `brotli`, `deflate`: not needed for Sigsum's small JSON payloads; enabling decompression adds a parser surface vulnerable to compression-bomb attacks.

Kept feature:

- `json`: required for serializing the `add-leaf` request body + parsing the log response (signed tree head, inclusion proof).

### 2.2 Rationale

`reqwest` is the dominant HTTPS client in production Rust. Alternatives surveyed:

- **`ureq`**: pure-Rust, synchronous, smaller surface. **Rejected** because the rest of the crate is async (D0018 §6 designates I/O crates as async); a sync HTTPS client would force `spawn_blocking` for every call, fragmenting the cancellation story.
- **`hyper` direct**: lowest-level Rust HTTPS client. **Rejected** because writing the request-construction + JSON-serialization layer manually adds engineering cost without security benefit; `reqwest`'s wrapper layer is well-audited.
- **`isahc`**: libcurl-based. **Rejected** because it adds a C dependency where pure-Rust is available; matches the workspace's pure-Rust discipline (modulo SQLite per D0022).

`rustls` is in audit scope as Cairn's TLS stack; it's already widely audited (Mozilla, AWS, Cloudflare, many others) and is a trust root for Cairn's HTTPS surface.

### 2.3 Request shape

Per Sigsum's documented HTTP API (https://www.sigsum.org/docs/api/):

- **Submit leaf**: `POST <log_url>/add-leaf`, body = the rfc6962 leaf format (signed by the submitter's key — Cairn's operational identity).
- **Get latest tree head**: `GET <log_url>/get-tree-head`
- **Get inclusion proof**: `GET <log_url>/get-inclusion-proof?leaf_hash=…&size=…`
- **Get cosignatures**: `GET <log_url>/get-cosignatures?size=…`

Each request carries the `Accept: application/octet-stream` header per the Sigsum spec.

---

## 3. Witness-cosignature verification: project-owned

### 3.1 Decision

Cairn does NOT use `sigsum-go` (Go-based Sigsum reference implementation) as a shim. Witness cosignature verification is implemented project-side in Rust:

1. The witness pool is configured statically in a `witnesses.toml` resource shipped with the release. Each entry: `name` (display), `pubkey_hex` (32-byte Ed25519 pubkey), `url` (witness's cosignature endpoint).
2. For each `tree_head` retrieved from the log, the client fetches cosignatures from each configured witness in parallel.
3. Each cosignature is a witness Ed25519 signature over `tree_size || root_hash || timestamp` (the Sigsum-specified signing input).
4. The client verifies each cosignature via the existing `cairn_crypto::ed25519::VerifyingKey::verify_strict` path — same code path as every other Ed25519 verification in Cairn.
5. A tree head is "accepted" if at least 2 of 3 configured witnesses signed it.

### 3.2 Rationale

Three arguments:

1. **No Go runtime in the trust path.** Adding `sigsum-go` as a shim would either require a Go runtime on Android (impractical) or a FFI to a Go-compiled binary (adds an additional language-runtime + memory model to the trust path). Both reject; project-owned Rust verification keeps the trust path within one runtime + audit surface.
2. **The verification math is small.** Cosignature verification is Ed25519 over a 48-byte signing input. The total verification logic is < 100 LoC. Re-implementing it is dramatically cheaper than maintaining a cross-language interop layer.
3. **Audit budget per D0011.** Each cosignature verify path is in scope. Project-owned Rust means the auditor reviews ~100 LoC; `sigsum-go` shim would mean reviewing the FFI boundary + the upstream Go code + the build pipeline that produces the embedded Go binary.

### 3.3 Witness pool config format

```toml
# witnesses.toml — shipped with the release; bumped by a release
[[witness]]
name = "Witness Alpha"
pubkey_hex = "abcdef…"
url = "https://witness-alpha.example.org"

[[witness]]
name = "Witness Bravo"
pubkey_hex = "012345…"
url = "https://witness-bravo.example.org"

[[witness]]
name = "Witness Charlie"
pubkey_hex = "fedcba…"
url = "https://witness-charlie.example.org"
```

Pool changes — adding witnesses, rotating pubkeys, removing witnesses — require a Cairn release. The witness pool is part of the trust-root configuration per design brief §3.4 + D0015's witness-pool concentration acknowledgment; rotating it via runtime configuration would defeat the integrity property that pinning provides.

### 3.4 Acceptance threshold

A tree head is accepted iff:

- The pool has exactly 3 witnesses configured (the "minimum 3 witnesses" per D0015).
- At least 2 of those 3 witnesses returned cosignatures for the same `tree_size || root_hash || timestamp` triple.
- Each accepted cosignature verifies via `verify_strict` against the configured pubkey.

If the witness pool config has fewer than 3 entries, every `accept_tree_head` call fails with `SigsumError::WitnessPoolTooSmall`. This is the "v1 ships without operational Sigsum witness coverage" failure mode per D0015 §"Sigsum witness threshold"; it surfaces as a typed error rather than silent degradation.

---

## 4. Caching strategy in `SIGSUM_CACHE`

### 4.1 Log-head cache

Per log endpoint, cache:

- The last accepted signed `tree_head` (with `tree_size`, `root_hash`, `timestamp`).
- The set of cosignatures that backed that acceptance.
- The Unix-seconds when the head was observed.

Record id: SHA-256 of the log URL.

On next call to `latest_tree_head`:

1. Fetch a fresh `tree_head` from the log.
2. Verify cosignatures per §3.4.
3. **Monotonic check**: the fresh `tree_size` MUST be `>= cached_tree_size`. A regression indicates either log split-view or log corruption — both fail-loudly per §7.
4. **Inclusion-proof bridge**: if the cached `tree_size > 0`, fetch a consistency proof from `cached_tree_size` to fresh `tree_size`; verify the proof per Sigsum's documented Merkle hash-tree spec.
5. On success, persist the fresh `tree_head` as the new cached value.

### 4.2 Leaf cache

Per emitted trust-graph op, cache:

- The leaf hash (32 bytes per §1).
- The inclusion proof at the `tree_size` when first observed.
- The log URL.
- The Unix-seconds when the proof was last verified.

Record id: SHA-256(log_url ‖ leaf_hash).

On verification: if the cache has an inclusion proof against an older `tree_size` AND the current accepted `tree_head` is consistency-proven from that older size, the cached proof transitively proves inclusion at the current head. No network fetch needed.

The cache is per-operation; cache eviction policy is operational (a v1.5+ surface). v1 caches every leaf indefinitely; pilot scale per implementation-status.md is ~hundreds of ops per user.

---

## 5. Async surface + cancel safety

### 5.1 Async API

```rust
pub struct SigsumClient {
    http: reqwest::Client,
    storage: Arc<cairn_storage::Storage>,
    witness_pool: WitnessPool,
    log_url: Url,
}

impl SigsumClient {
    pub async fn emit_leaf(
        &self,
        signed_op: &SignedTrustGraphOp,
    ) -> Result<LeafHash, SigsumError>;

    pub async fn verify_inclusion(
        &self,
        signed_op: &SignedTrustGraphOp,
    ) -> Result<InclusionProof, SigsumError>;

    pub async fn refresh_tree_head(&self) -> Result<TreeHead, SigsumError>;
}
```

Per D0018 §6 the I/O surface is the only async-exposed layer; cryptographic verifications wrapped in `spawn_blocking` per D0018 §6's discipline pattern.

### 5.2 Cancel safety

Sigsum's `add-leaf` endpoint is idempotent on identical leaf hashes — re-submitting the same leaf returns the same proof. This means `emit_leaf` is safely retriable: if the client cancels mid-request and the server received the leaf, the next retry observes the leaf already present and returns the proof without duplicate work.

For the verification path, every `verify_strict` call happens inside `spawn_blocking` to avoid cancel-safety hazards. The pattern:

```rust
let tree_head_bytes = tree_head.signing_input();
let cosignature = cosig.bytes;
let verifying_key = witness.pubkey;

tokio::task::spawn_blocking(move || {
    verifying_key.verify_strict(&tree_head_bytes, &cosignature)
}).await??;
```

### 5.3 Retry policy

```rust
pub struct RetryBudget {
    pub max_retries: u8,
    pub initial_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RetryBudget {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(60),
        }
    }
}
```

Each `SigsumClient` method accepts a `RetryBudget` parameter (or uses `Default`); the budget is exhausted on transient HTTP errors (5xx, connection-reset, timeout) and surfaces a final `SigsumError::Network` error.

Non-retried errors (auth failures from the log, malformed cosignatures, witness pool too small) fail fast without consuming the budget.

---

## 6. Trust-graph integration point

### 6.1 Emit on store

A new module `cairn-trust-graph::sigsum_emit` wraps `store_signed_op` with co-located Sigsum emission. Consuming code calls the wrapper instead of `store_signed_op` directly when the op should be both persisted and logged. The wrapper:

1. Calls `store::store_signed_op(storage, op)` to persist.
2. If a `SigsumClient` is configured, calls `sigsum_client.emit_leaf(op).await` and persists the returned inclusion proof to the SIGSUM_CACHE category.
3. Returns both the storage record id and the leaf hash.

Errors at step 2 do NOT roll back step 1: persistence succeeds, Sigsum emission is best-effort with retries. A subsequent call to `emit_leaf` (e.g., on app start sweep) catches up missed emissions.

### 6.2 Verify on chain walk

The existing `verify_chain_links` continues to operate on local data only — it does not call into Sigsum directly. A new `verify_chain_links_with_sigsum` wrapper:

1. Calls `verify_chain_links` for the existing chain integrity checks.
2. For each verified op, calls `sigsum_client.verify_inclusion(op).await` against the cached proof.
3. Returns a typed error indicating which op failed Sigsum verification, distinct from chain-link failures.

The wrapper composes; chain-link integrity and Sigsum inclusion are orthogonal failure modes per design brief §3.3.

### 6.3 Separation of concerns

The chain-walk + cascade-quarantine primitives stay Sigsum-unaware. Consuming code chooses when to require Sigsum verification (always for sensitive ops; lazily for messaging-history ops). This is the same separation D0006 §3.3 already specified: "operations themselves propagate via the messaging layer and live in the participants' local stores, not in Sigsum."

---

## 7. Failure modes + typed error surface

`SigsumError` per D0018 §4.2 — indices, lengths, type tags only; no `Vec<u8>` payloads:

```rust
#[non_exhaustive]
pub enum SigsumError {
    /// Underlying network failure (timeout, connection-reset, HTTP 5xx).
    Network { retry_budget_exhausted: bool },
    /// Witness pool config has fewer than 3 entries. Operational
    /// failure per D0015.
    WitnessPoolTooSmall { configured: u8 },
    /// Fewer than 2 of 3 witnesses returned valid cosignatures.
    InsufficientWitnessCosignatures { valid: u8, required: u8 },
    /// A witness cosignature failed Ed25519 verify.
    CosignatureVerifyFailed { witness_index: u8 },
    /// The fetched tree_size is smaller than the cached one. This is
    /// either log split-view OR log corruption. Either way, halt.
    LogTreeSizeRegression { cached: u64, fetched: u64 },
    /// Two log heads with the same tree_size but different root_hash.
    /// Pure split-view indicator. Halt.
    LogSplitView { tree_size: u64 },
    /// The inclusion proof does not verify against the accepted tree head.
    InclusionProofVerifyFailed,
    /// The consistency proof from old_size to new_size does not verify.
    ConsistencyProofVerifyFailed { old_size: u64, new_size: u64 },
    /// Storage failure when caching log state.
    Storage(cairn_storage::StorageError),
    /// Trust-graph op encode failure (unreachable for envelopes built
    /// via the public API).
    Encode(cairn_trust_graph::TrustGraphError),
    /// Sigsum protocol parse failure (malformed JSON, malformed
    /// cosignature shape, etc.).
    MalformedResponse,
}
```

### 7.1 Split-view detection

`LogTreeSizeRegression` and `LogSplitView` both indicate the log is no longer behaving honestly. v1 surfaces these as halting errors — the client refuses to verify further ops against this log endpoint until the user takes explicit action.

Operational response (v1.5+): a UI affordance lets the user switch to a backup log endpoint OR mark all unverified ops as quarantined pending out-of-band verification. v1 ships with the typed error; the UI handling lives in the Android shell.

---

## 8. Out of scope

This decision does NOT address:

1. **Witness pool recruitment.** Q5 (NGO partner outreach) per D0015's Sigsum witness threshold cross-reference. This decision presumes a recruited pool exists; absence surfaces as `WitnessPoolTooSmall`.
2. **Sigstore identity-based signing** for release artifacts. That's D0024 (Sigstore release verification) — different surface, different witnesses, different verification flow.
3. **Cross-log query** (verifying an op against multiple logs simultaneously). v1 ships with a single log endpoint per release; multi-log shard would land in v1.5+ if D0015 deferral target activates.
4. **Offline-tolerant verification.** Per design brief §5.3 + the Sigsum dependency note, v1 recovery + verification require online connectivity to Sigsum. Offline-tolerant caching lands at v1.5 per the same brief reference.
5. **The witness pool config UI.** v1 ships the `witnesses.toml` as a baked-in resource; the user does not edit it. v1.5+ may add a UI for the user to view (not modify) the witness pool.
6. **Push notification of trust-graph events.** When a new op is logged, the relevant downstream verifier's logic (notify-on-revocation, notify-on-cascade-event) is a UI-layer concern.

## 9. Reversibility

The decisions in this document are mostly reversible:

- **HTTPS client switch (reqwest → ureq / hyper-direct)**: tractable. The crate's public API is async; switching to a synchronous client requires wrapping in `spawn_blocking` at the call sites.
- **Witness-cosignature implementation (Rust → sigsum-go FFI)**: tractable but expensive. Would require an FFI boundary + a build-pipeline addition. No existing data structure pins the implementation choice.
- **Leaf hash schema change**: the HARDEST to reverse. Once leaves are emitted with the §1.1 schema, every subsequent leaf must follow it (else split-view detection fires on consistency). Changing the schema requires a coordinated trust-graph + cairn-sigsum-client release with explicit migration. v1 must specify it correctly.
- **Witness pool acceptance threshold (2-of-3 → other)**: requires a release. Cosignatures are pinned to a specific threshold at verification time; relaxing or tightening interacts with witness-pool composition.

## 10. Implementation status

This D-doc is accepted. The matching `cairn-sigsum-client` crate skeleton + the `cairn-trust-graph::sigsum_emit` integration land as separate commits consuming D0023. v1 implementation order:

1. `cairn-sigsum-client/src/{lib,client,witness,cache,error}.rs` per §§1-7
2. Workspace pin additions per §2.1: `reqwest`, `tokio` (workspace's first async dep), `url`, `serde`, `serde_json`
3. Test fixtures: a mock log endpoint via `wiremock` (test-only dep) for unit tests; integration test against a public Sigsum log (e.g., poc.sigsum.org) gated behind a `--features integration-tests` flag so CI doesn't depend on external network availability
4. `cairn-trust-graph::sigsum_emit` wraps `store_signed_op` per §6
5. `verify_chain_links_with_sigsum` wraps `verify_chain_links` per §6.2
6. CLI integration in cairn-cli: `sigsum-emit` + `sigsum-verify` subcommands for end-to-end demo

The `witnesses.toml` baked-in resource is a release-time decision; the v1 ship will include three witness entries the Q5 partner outreach has recruited (per D0015).

---

## 11. Cross-references

- [D0006 — cryptographic-envelope completion](D0006-cryptographic-envelope.md) — §3.3 commitment-only logging spec; §5 prior_hash schema this decision's §1 reuses
- [D0011 — audit budget and timing](D0011-audit-budget-and-timing.md) — audit-scope posture per §3.2
- [D0015 — v1 release-security posture](D0015-v1-release-security-posture.md) — witness threshold (3 witnesses, 2-of-3); witness-pool concentration risk acknowledgment
- [D0018 — engineering foundation](D0018-engineering-foundation.md) — §6 async discipline; §8.6 workspace layout
- [D0022 — cairn-storage layer](D0022-storage-layer.md) — SIGSUM_CACHE category used here
- [design brief §3.3 public transparency-log metadata](../design-brief.md) — commitment-only architectural commitment
- [implementation-status.md](../implementation-status.md) — Sigsum integration rows pending; this decision unblocks them
- Sigsum protocol spec — https://www.sigsum.org/docs/
