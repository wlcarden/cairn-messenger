# D0022 — cairn-storage layer: rusqlite + per-value XChaCha20-Poly1305

**Status:** Accepted
**Date:** 2026-05-29

## Context

D0018 §8.6 enumerates `cairn-storage` in the workspace layout but does not specify the storage engine, the encryption layering, or the schema/migration discipline. Six concrete defenses in the [implementation-status reconciliation](../implementation-status.md) block on D0022:

1. 90-day stale-flag escalation per D0006 §2 (per-attestation timer across sessions)
2. Trust-graph history persistence (chain-walk verifier currently consumes in-memory slices)
3. At-rest message persistence with passphrase + hardware-element binding per D0006 §3.5
4. Recovery-peer share storage per D0005
5. Atomic re-split coordination per D0018 §3.5 (two-phase commit across N peers)
6. Soft-flag UI acknowledgment state (which attestations the user has touched vs. left to auto-quarantine)

The the storage research (in git history) surveyed the realistic option space against three already-locked-in constraints (D0018 §1.4 XChaCha20-Poly1305 at-rest AEAD; D0018 §6 cairn-storage is synchronous; D0020 §3 StrongBox mediation via UniFFI callback). Three survivors after the engineering screen + the quality screen: rusqlite, redb, hand-rolled append-only logs. This decision picks among them and specifies the encryption layering + schema discipline that goes with the choice.

## Decision summary

| Layer                 | Decision                                                                                                                      | Rationale link |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------- |
| **Storage engine**    | `rusqlite = "=0.32.1"` with bundled libsqlite3-sys; WAL mode + `synchronous=FULL`                                             | §1 below       |
| **At-rest AEAD**      | XChaCha20-Poly1305 per D0018 §1.4 (already pinned at workspace level)                                                         | §2 below       |
| **Per-record format** | `version_byte ‖ nonce(24) ‖ XChaCha20-Poly1305(DEK, payload, AAD)`                                                            | §2.3           |
| **AAD construction**  | canonical-CBOR of `(category_tag, record_id, schema_version)`                                                                 | §2.4           |
| **Key derivation**    | passphrase → Argon2id → KEK; KEK + StrongBox-attested material → HKDF → DEK                                                   | §2.2           |
| **DEK granularity**   | one DEK per data category (so per-category rotation is bounded)                                                               | §2.2           |
| **Key provider**      | `cairn-storage::KeyProvider` trait; Android shell implements via UniFFI callback; test harness implements with in-memory keys | §4             |
| **Schema versioning** | per-record version byte (AAD-bound) + per-category schema_version table                                                       | §3             |
| **Migration policy**  | forward-only at v1; transactional wrapping; no automatic migration on decrypt failure                                         | §3.2           |
| **Workspace lints**   | `cairn-storage` opts into `unsafe_code = "deny"` exception per D0018 §8.1                                                     | §6.4           |

---

## 1. Storage engine: rusqlite

### 1.1 Decision

Use **rusqlite 0.32.1** with the `bundled` feature so libsqlite3-sys ships its own SQLite source rather than relying on the Android system library. Pinned as `rusqlite = { version = "=0.32.1", features = ["bundled"] }` in the workspace deps; consumed by `cairn-storage` as `rusqlite = { workspace = true }`.

SQLite configuration applied at connection open:

```rust
conn.pragma_update(None, "journal_mode", "WAL")?;
conn.pragma_update(None, "synchronous", "FULL")?;
conn.pragma_update(None, "foreign_keys", "ON")?;
conn.pragma_update(None, "temp_store", "MEMORY")?;
conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
```

SQLite build-time omissions (passed to libsqlite3-sys via `features`):

- `SQLITE_OMIT_LOAD_EXTENSION` — no runtime extensions; the C-extension API is a real attack surface we don't use.
- `SQLITE_OMIT_DEPRECATED` — drop ~10 KB of legacy interfaces.
- `SQLITE_DQS=0` — disable double-quoted string literals (the SQL-standard violation that has caused real bugs in projects that didn't disable it).
- No FTS5, no R-Tree, no JSON1 — disabled by default in the bundled build configuration we'll commit.

### 1.2 Rationale

Four arguments dominate the security calculus per the analysis in the storage research's decision-factors analysis (in git history) and the follow-on security comparison:

1. **Durability matters more than memory safety for Cairn's failure mode.** Lost ratchet state breaks message decryption forever (no recovery within the storage layer; only via Shamir social recovery + identity rotation). Failed-to-persist revocation means a compromised key keeps appearing valid until the next attempt. SQLite's WAL + `synchronous=FULL` has decades of crash-tested durability semantics with near-zero remaining bug rate. redb's durability is documented but younger.
2. **The memory-safety win for redb is reduced by Cairn's architecture.** The storage engine sees only ciphertext blobs from our own per-value AEAD; attacker bytes go through canonical-CBOR decode + AEAD verify _before_ SQLite touches them. The attack path "exploit SQLite memory-safety bug" requires first compromising our encoding pipeline, at which point a SQLite bug isn't the dominant concern.
3. **SQLite as audit trust root saves real budget per D0011.** A funded audit reviews "how Cairn uses SQLite" not "is SQLite correct." With redb the engine itself is in audit scope. SQLite's trust-root posture is the industry pattern at Cairn's threat tier (Signal, WhatsApp, Bitwarden, Element X all do this).
4. **Migration tooling maturity.** SQL schema migration has mature patterns (`refinery`, `barrel`); KV migrations are designed per-project. At Cairn's pre-pilot scale this matters less than it will at v1.5+.

The non-security axes corroborate (industry-validated production posture; mature backup/export via `.dump`; ~1.5 MB binary impact tractable; D0020 already adds a C++ dep via the SimpleX CLI sidecar so "first C dep" isn't accurate).

### 1.3 Concurrency

SQLite + WAL supports concurrent readers + one writer. `cairn-storage` exposes a `Storage` handle that holds the rusqlite Connection; the type is `!Sync` (a single Connection is `Send` but not `Sync`). Multi-threaded callers either share one writer via a Mutex or open additional read-only connections to the same file.

Cairn's v1 access pattern is dominantly read-mostly with bursty writes (message arrival, trust-graph op insertion, occasional state mutation). A single writer Connection wrapped in a Mutex is sufficient; the readers-pool pattern is a v1.5+ optimization if profiling shows contention.

---

## 2. Encryption layering: per-value XChaCha20-Poly1305 with AAD-binding

### 2.1 Decision

The storage engine sees only ciphertext blobs. Per D0018 §1.4 the at-rest AEAD is XChaCha20-Poly1305 with 192-bit nonces; that decision is unchanged here and applied per-record.

The schema layout is uniform across all categories:

```sql
CREATE TABLE storage (
  category TEXT NOT NULL,           -- e.g. "trust_graph_op"
  record_id BLOB NOT NULL,          -- category-specific key (often a SHA-256 prefix)
  ciphertext BLOB NOT NULL,         -- nonce(24) ‖ XChaCha20-Poly1305(DEK, payload, AAD)
  version INTEGER NOT NULL,         -- per-record schema version (also bound into AAD)
  PRIMARY KEY (category, record_id)
);

CREATE TABLE schema_version (
  category TEXT PRIMARY KEY,        -- one row per data category
  version INTEGER NOT NULL          -- current schema version for this category
);

CREATE TABLE meta (
  key TEXT PRIMARY KEY,             -- "encryption_kek_salt", "storage_schema_version", etc.
  value BLOB NOT NULL               -- cleartext; bootstrap data not encrypted
);
```

The KV-uniform layout pays the cost of "no SQL queries on encrypted columns" upfront. Per the locked-in constraint in D0018 §1.4, application-layer encryption means we can't query on encrypted columns anyway; the uniform shape simplifies access discipline.

### 2.2 Key derivation chain

```text
Passphrase (UTF-8 from user)
    │
    ▼
Argon2id(passphrase, kek_salt, m=64 MiB, t=3, p=1)
    │ (256-bit output)
    ▼
KEK
    │
    ▼
HKDF-SHA256(IKM = KEK ‖ StrongBox-attested key material,
            salt = "cairn-v1-storage-kdf",
            info = category_tag)
    │ (256-bit output per category)
    ▼
DEK_category
```

**Argon2id parameters at v1**: m=64 MiB, t=3 iterations, p=1 parallelism. This matches modern best-practice for mobile devices (the OWASP 2024 recommendation is m=46-64 MiB, t=1-3, p=1 for resource-constrained environments). At v1.5 we calibrate against actual Pixel device timing — target a ~500 ms unlock latency on the slowest supported Pixel generation.

**StrongBox-attested key material** is the per-device wrapped key returned by the `KeyProvider` callback (§4). Combining via HKDF binds the DEK to _both_ the passphrase and the device. Neither alone decrypts; both are required.

> **Realized (2026-06-03) — the device factor is now real.** The Android shell shipped this material as a demo constant (`0x2A…×32`), making the device factor a no-op (any device with the passphrase + ciphertext could derive the DEK). It is now `StrongBoxStorageKeyMaterial` (`CairnSession.kt`): a **non-exportable AndroidKeyStore HMAC-SHA256 key** in StrongBox (the Pixel 6 Titan M2; TEE fallback), no user-auth (the passphrase is the user factor; this is the device factor), used to compute `HMAC(key, "cairn-v1-storage-kek-material")` → the 32 device-bound bytes. The Rust mixing (`derive_category_dek`, key_provider.rs) was already correct, so this was Kotlin-only. **Validated on two Pixels:** the material is StrongBox-level and stable across restarts (the correct passphrase re-unlocks; a non-deterministic material would fail the canary), a wrong passphrase is rejected, and — the device-binding proof — **A's encrypted store copied onto B and opened with A's correct passphrase is rejected** (`unlock failed: wrong passphrase`), because B's StrongBox HMAC differs. **Migration:** a store created under the old constant cannot be opened once this is in force (fresh installs only — same caveat as the at-rest DB encryption, D0026 §12). **Consequence (intended):** local at-rest data is now device-bound — unrecoverable on another device from the passphrase alone; this is the defense against off-device brute force, and is separate from identity recovery (D0005).

**Per-category DEK** means rotating one category (e.g. message history) doesn't require re-encrypting everything else. The HKDF `info` parameter carries the category_tag string; the salt is the constant `cairn-v1-storage-kdf`. Categories landed at v1:

- `identity` (operational identity keys; small; rarely rotated)
- `capability_tokens` (rotated hours-to-days)
- `master_attestation` (rotated only at op-identity rotation)
- `trust_graph` (operations issued + received)
- `quarantine_state` (computed cascade results + soft-flag UI acknowledgments)
- `recovery_peers` (peer pubkeys, names, share commitments)
- `recovery_shares` (shares this user holds of OTHER users' masters)
- `ratchet_state` (SimpleX conversation ratchet state)
- `messages` (per-conversation message history)
- `sigsum_cache` (log heads + witness cosignatures)

A future revision can split or merge categories without changing the format; the `info` parameter carries the category identity.

### 2.3 Per-record format

```text
ciphertext column =
    version_byte (1 byte)
  ‖ nonce         (24 bytes, random per write)
  ‖ XChaCha20-Poly1305(DEK_category, payload, AAD)
```

The 16-byte Poly1305 tag is appended by the AEAD (chacha20poly1305 crate convention); not separately framed.

`version_byte` is also bound into the AAD (§2.4). Storing it outside the ciphertext lets the decoder _select_ the schema-version codec before decrypting; binding it into AAD prevents an adversary from swapping `version_byte` to trigger a different decode path.

### 2.4 AAD construction

```text
AAD = canonical_cbor_encode([
  category_tag    : tstr,
  record_id       : bstr,
  version         : uint,
])
```

The AAD is reconstructed by the reader from the category column + record_id column + version column read at the same row. An adversary with write access to the storage file who swaps a row from `("trust_graph_op", id_A, ...)` to `("trust_graph_op", id_B, ...)` invalidates the AEAD tag — the AAD is now `(category, id_B, version)` but the ciphertext was sealed with `(category, id_A, version)`. The defense composes the AEAD's per-tuple authenticity with the slot-binding the AAD enforces.

Canonical CBOR encoding ensures the AAD is byte-stable across implementations and across runs.

---

## 3. Schema discipline

### 3.1 Per-record + per-category schema versioning

Two layers of versioning, both bound to integrity:

1. **Per-record `version_byte` at the head of the ciphertext column.** Bound into AAD per §2.4. The decoder reads the version, selects the matching deserializer, and verifies the AAD-binding catches downgrade or swap attacks.

2. **Per-category `schema_version` row in the `schema_version` table.** Cleartext (it's bootstrap data the migration code reads before any key material is available). Used by the migration runner to decide whether to apply migrations on app start.

### 3.2 Migration semantics

- **Forward-only at v1.** Migrations advance schema versions; rolling back is not supported. v1.5+ may add reversibility if pilot evidence warrants it.
- **Transactional wrapping.** Each migration runs inside a single SQLite transaction. Failure rolls back to the pre-migration state. The connection's auto-commit is off during migration.
- **No automatic migration on first-decrypt-failure.** If decryption fails (wrong key, AAD mismatch, ciphertext tamper), the failure is surfaced — never silently fall through to a "maybe it's a different schema" migration attempt. That path is an attack surface.
- **Explicit migration trigger at app start.** Each app start reads `schema_version` per category and applies pending migrations in declared order. A migration that touches multiple categories holds a single transaction across all of them; partial migration is impossible.
- **Logging discipline per D0018 §4.3.** Migration logs record the from-version + to-version + duration + row count. No secret material in logs.

### 3.3 Backup / export

`cairn-storage` exposes a `Storage::export(out_path, key_provider)` method that writes a canonical-CBOR document of `(category, record_id, decrypted_payload)` tuples for migration to a fresh device after seizure-induced re-provisioning.

The export is _cleartext canonical CBOR_ — the migration scenario is the user transferring their own data to their own next device under their own unlock. The on-disk export file is the user's responsibility to secure (a temporary file on an unlocked device, transferred immediately via OOB channel, deleted after transfer). This matches the operational guidance in the design brief §3.3 returned-after-seizure surface.

The matching `Storage::import(in_path, key_provider)` method re-encrypts each record under the destination device's freshly-derived DEKs.

Export format is documented in `cairn-storage/EXPORT_FORMAT.md` (to land with the crate skeleton).

---

## 4. Key provider trait (StrongBox mediation)

Per D0020 §3.4 hardware-element operations route through UniFFI's `callback_interface` because Rust cannot directly call Android's KeyStore. `cairn-storage` defines:

```rust
pub trait KeyProvider {
    /// Derive the KEK from the user's passphrase using Argon2id with
    /// the stored salt. Returns the 32-byte KEK in a Zeroizing wrapper.
    fn derive_kek(
        &self,
        passphrase: &Zeroizing<Vec<u8>>,
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, KeyProviderError>;

    /// Return the StrongBox-attested key material to combine with the
    /// KEK via HKDF. On Android this delegates through UniFFI to the
    /// Kotlin shell, which invokes Android KeyStore. In tests this
    /// returns a fixed in-memory byte string.
    fn strongbox_material(&self) -> Result<Zeroizing<[u8; 32]>, KeyProviderError>;

    /// Optional: signal that the device has been recently unlocked.
    /// `cairn-storage` uses this to decide whether to keep DEKs cached
    /// vs. re-derive on each operation.
    fn unlock_state(&self) -> UnlockState;
}
```

Implementations land at:

- **`cairn-storage::testing::InMemoryKeyProvider`** — for unit + integration tests inside the workspace. Argon2id with reduced parameters (m=1 MiB, t=1, p=1) so tests are fast; StrongBox material is a fixed `[0x55; 32]`.
- **`cairn-uniffi::AndroidKeyProvider`** (future crate per D0018 §8.6) — wraps the UniFFI callback that calls into Kotlin for Argon2 (the Kotlin shell holds the salt + invokes the libargon2 binding) and Android KeyStore (returns the wrapped key material).

The `KeyProvider` trait is the only Hardware-Abstraction-Layer surface `cairn-storage` exposes. The crate itself remains hardware-neutral; all hardware interaction goes through this trait.

---

## 5. Alternatives considered

Per the the storage research (in git history):

### 5.1 redb

Pure Rust ACID KV; reviewable codebase (~20k LoC); Rust memory safety eliminates an entire class of bug. **Rejected** primarily because durability matters more than memory safety for Cairn's specific failure modes (lost ratchet state has no in-engine recovery path) and SQLite's durability story is decades more battle-tested. The memory-safety win is reduced by Cairn's architecture (the storage engine sees only ciphertext blobs from our own AEAD; attacker bytes don't reach SQLite's parser directly). The reduced audit-budget posture (engine in scope vs. trust root) cuts against redb at the project's funded-audit posture.

Could be reconsidered at v1.5+ if:

- Production validation evidence accumulates (redb-in-production at multi-year scale)
- Cairn's audit budget shifts toward self-audit (where redb's reviewability matters more than SQLite's pedigree)
- A SQLite supply-chain attack materializes that changes the trust-root calculus

### 5.2 Hand-rolled append-only logs

Zero third-party dep; smallest audit surface; ~50 KB binary impact. **Rejected** because:

- Engineering cost to design correct atomic-write-then-rename + fsync(parent_dir) discipline + concurrent compaction is significant (multi-week, not multi-day) and competes with v1 ship velocity
- Reinventing primitives that battle-tested databases provide; the audit cost is "every fsync ordering you chose"
- Cross-record consistency (e.g. atomic re-split coordination) is hand-rolled
- Index rebuild on startup grows with history; mitigated by snapshotting but that re-introduces durability complexity

The hand-rolled posture is appropriate for a research codebase but mismatched to Cairn's pre-pilot ship cadence. Reconsider only if SQLite + redb both become disqualified.

### 5.3 sled

Documented historical data-loss bugs disqualifying at Cairn's threat tier. The maintainer flagged the project as alpha through 2024; production-time bug rate is unclear. **Rejected without further consideration.**

### 5.4 rocksdb / fjall

`rocksdb`: C++ dep, multi-megabyte binary, configuration surface too complex for Cairn's scale. **Rejected** for v1; revisit if scale ever requires LSM-tree write amplification optimization (unlikely at Cairn's data volume).

`fjall`: pure-Rust LSM-tree aiming to be "rocksdb in Rust." **Rejected** for v1 because too new (2024+) for production validation; revisit at v1.5 if redb's posture has hardened by then and an LSM-tree story is needed.

### 5.5 SQLCipher

The natural counterpart to rusqlite — SQLite + transparent file-level AES-256-CBC + HMAC-SHA256. Used by Signal, WhatsApp, Bitwarden. **Rejected** because:

- SQLCipher's AEAD is AES-CBC + HMAC; D0018 §1.4 picks XChaCha20-Poly1305 with explicit nonce-misuse-resistance argument for the recovery scenario. Adopting SQLCipher would either (a) require a D0018 §1.4 revision (whole-stack audit implication) or (b) run two AEAD primitives in production (cost in audit surface + cargo-vet footprint).
- File-level encryption transparently encrypts indexes too — convenient but precludes ever using SQL queries on cleartext fields. Cairn's per-value application-layer encryption doesn't benefit from this anyway.
- The pattern Cairn adopts (rusqlite + per-value XChaCha20-Poly1305) preserves D0018 §1.4's primitive choice while inheriting SQLite's durability story. Best of both.

If at-rest nonce-derivation later becomes structurally problematic, switching to SQLCipher is a candidate change — same SQL substrate, different AEAD layer. This reversibility is one of the arguments for picking rusqlite over redb.

---

## 6. Consequences

### 6.1 What unblocks

The six rows in [implementation-status.md](../implementation-status.md)'s D0022-blocked list:

1. **90-day stale-flag escalation** — `cairn-trust-graph` gets a `cascade::TimerState` extension that reads/writes per-attestation timer baselines through `cairn-storage`. The escalation rule (90 days since first-flag observation) becomes implementable.
2. **Trust-graph history persistence** — `cairn-trust-graph::verify_chain_links` callers fetch chains from `cairn-storage::trust_graph` instead of from in-memory slices. The chain-walk primitive itself doesn't change.
3. **At-rest message persistence with passphrase + hardware-element binding** — the `cairn-simplex-adapter` crate (D0025-deferred) uses `cairn-storage::messages` + `cairn-storage::ratchet_state` for the per-conversation state.
4. **Recovery-peer share storage** — `cairn-recovery` gets a `recovery_peers` storage path for the user's chosen peers; the shares this user holds of OTHER users' masters live in `cairn-storage::recovery_shares`.
5. **Atomic re-split coordination per D0018 §3.5** — `cairn-recovery-orchestrator` (future crate) uses `cairn-storage` for two-phase commit intermediate state. The peer-protocol coordination layer still needs D0025 (network).
6. **Soft-flag UI acknowledgment state** — `cairn-trust-graph::cascade` gets a sibling primitive `cascade::user_state` that reads/writes per-attestation UI-action history through `cairn-storage`.

### 6.2 Library pins to add to workspace `Cargo.toml`

```toml
# Storage layer per D0022
rusqlite = { version = "=0.32.1", features = ["bundled"] }
argon2 = { version = "=0.5.3", default-features = false, features = ["alloc"] }
```

`argon2` is pinned at the workspace level for the password-stretching step (§2.2). `chacha20poly1305` is already a workspace dep via D0018 §1.4. `cairn-crypto::hkdf` is already implemented.

`rusqlite` 0.32.x is the current stable line as of 2026-05; `bundled` feature pulls libsqlite3-sys with a bundled SQLite source. Build configuration omissions per §1.1 are applied via `libsqlite3-sys` feature flags or via `RUSTFLAGS` at the crate's `build.rs` if features prove insufficient.

### 6.3 Audit-scope posture

- **SQLite is treated as a trust root** per D0011 audit scope. The auditor reviews schema design, query construction, migration discipline, and per-value encryption layering. The auditor does NOT review SQLite itself.
- **`cairn-storage` is fully in audit scope.** This includes the encryption layering, key derivation chain, AAD construction, schema versioning, migration runner, and the `KeyProvider` trait.
- **The Android `KeyProvider` implementation lives in `cairn-uniffi`** per D0020 §3 and is in scope for the FFI-boundary audit, not the storage audit.

This matches D0011's audit scope enumeration: cryptographic surfaces in scope; trust roots (SQLite, ed25519-dalek, chacha20poly1305) out of scope.

### 6.4 `unsafe_code` exception per D0018 §8.1

`cairn-storage` is one of two crates D0018 §8.1 permits `unsafe_code = "deny"` rather than `"forbid"`. The exception is needed because:

1. **`mlock` wrapper for KEK / DEK lifetime.** Linux + Android `mlock`/`mlock2` wrapping for the in-memory cached DEKs requires `unsafe` to call libc directly. Wrapped in a small `MlockedSecret<T>` type with documented invariants.
2. **No other `unsafe` blocks expected.** rusqlite itself wraps libsqlite3-sys; we consume the safe API. The `KeyProvider` trait is safe. Migration code is safe.

Every `unsafe` block carries a documented safety argument at the call site per D0018 §8.1.

### 6.5 Crate lints

`cairn-storage/src/lib.rs` opens with:

```rust
#![cfg_attr(not(test), deny(unsafe_code))]
#![cfg_attr(test, allow(unsafe_code))]
#![warn(missing_docs)]
```

`unsafe_code` is deny rather than forbid at production builds; tests may exercise the `mlock` wrapper in deliberately failing scenarios.

---

## 7. Open items deferred to follow-up decisions

This D-doc establishes the engine + encryption layering + schema discipline. It does NOT decide:

1. **Argon2id parameter calibration against pilot Pixel devices.** v1 ships with m=64 MiB, t=3, p=1 (modern OWASP recommendation). v1.5 calibrates against actual Pixel-generation timing to target ~500 ms unlock latency on the slowest supported generation. A separate sub-decision lands then.
2. **Category-keyed DEK rotation triggers.** v1 supports per-category rotation but doesn't specify _when_ to rotate. The rotation triggers depend on operational policy (rotate-on-compromise vs. rotate-on-schedule); to be decided when the rotation surface lands.
3. **Atomic re-split protocol's exact storage interaction.** D0018 §3.5 specifies two-phase commit across N peers but the on-disk representation of in-flight operations is open. To be decided when `cairn-recovery-orchestrator` is designed.
4. **Per-DEK nonce-counter discipline (if added).** v1 uses random 24-byte nonces; collision probability is negligible by birthday bound (2^96 same-key encryptions before 2^-32 collision probability — vastly beyond Cairn's scale). If a future surface needs to bound this empirically, a deterministic-nonce sub-decision lands.
5. **Read-pool sizing for concurrent reads.** v1 uses one shared writer Connection; if profiling shows contention, the read-pool pattern lands as a v1.5 optimization.

---

## 8. Reversibility

This decision is **partially reversible**:

- **Schema migration**: SQLite's `.dump` + reload pattern allows full data migration to a different engine. The export format documented in §3.3 is the migration substrate.
- **AEAD primitive switch (e.g. to SQLCipher's AES-CBC)**: tractable. The per-record format §2.3 versioning supports adding a new `version_byte` that selects a different AEAD; co-existing records are decryptable under the matching primitive.
- **Storage engine switch (rusqlite → redb)**: tractable but expensive. Requires rewriting the schema-layer code in `cairn-storage`; data migration via export/import.

The decision that is HARDEST to reverse is the per-value AAD-binding shape — once data is encrypted with `AAD = (category, record_id, version)`, changing the AAD construction breaks all existing records. This is intentional: the AAD-binding is the slot-swap defense and shouldn't be weakened.

---

## 9. Implementation status

This D-doc is accepted; the matching `cairn-storage` crate skeleton lands as the first commit consuming it. The skeleton includes:

- `cairn-storage/Cargo.toml` per §6.2 pins
- `cairn-storage/src/lib.rs` with the module structure per §§1-4
- `cairn-storage/src/key_provider.rs` with the `KeyProvider` trait + `InMemoryKeyProvider` test impl
- `cairn-storage/src/error.rs` with the typed error surface per D0018 §4.2
- `cairn-storage/src/schema.rs` with the initial schema_version=1 layout
- Initial unit tests covering the AEAD-with-AAD round trip + AAD-tamper rejection

Subsequent commits expose category-specific storage paths as the consuming crates land their persistence requirements.

---

## 10. Cross-references

- [D0006 — cryptographic-envelope completion](D0006-cryptographic-envelope.md) — at-rest decryptable under unlock (§3.5); 90-day stale-flag escalation (§2)
- [D0011 — audit budget and timing](D0011-audit-budget-and-timing.md) — audit-scope posture per §6.3
- [D0018 — engineering foundation](D0018-engineering-foundation.md) — §1.4 XChaCha20-Poly1305; §6 synchronous discipline; §8.1 `unsafe_code` exception; §8.6 workspace layout
- [D0020 — integration architecture](D0020-integration-architecture.md) — §3 UniFFI callback for hardware-mediated operations
- [D0021 — library pin audit](D0021-library-pin-audit.md) — pin discipline this decision must follow
- the storage research (in git history) — alternatives analysis source
- [implementation-status reconciliation](../implementation-status.md) — the D0022-blocked rows this decision unblocks
