# Storage layer research

This document surveys the realistic options for `cairn-storage` per D0018 §8.6's enumerated crate layout. It's not the decision — D0022 captures that. This document is the substrate the decision rests on.

The goal is to make the option space legible so the trade-offs are explicit: what each path costs, what each path closes off, where existing D-doc constraints have already narrowed the search.

## What needs to be stored

From [implementation-status.md](implementation-status.md)'s D0022-blocked rows, plus inventory of the implemented protocol crates:

### Per-user persistent state

| Item                                                                                                  | Volume                                              | Sensitivity                                       | Mutation pattern                                          |
| ----------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ------------------------------------------------- | --------------------------------------------------------- |
| Master public key (for verifying master attestations)                                                 | 32 bytes                                            | Public                                            | Write-once at provisioning (or rotation)                  |
| Operational identity public + private keypair                                                         | 64 bytes (private wrapped)                          | High (device-key tier)                            | Rotated under suspected compromise; otherwise stable      |
| Device keypair (StrongBox-held; only handle persists)                                                 | Handle bytes                                        | Hardware-bound                                    | Stable per device                                         |
| Capability token currently held (signed by op identity, names device key as subject)                  | ~200 bytes                                          | Medium                                            | Rotated hours-to-days per D0018 §5.1 commit               |
| Master attestation envelope (signed by master, certifies op identity)                                 | ~150 bytes                                          | Public-derivable                                  | Rotated at op-identity rotation                           |
| Trust-graph operations issued by this user                                                            | grows; ~150 bytes each                              | Public-derivable (commitments anchored in Sigsum) | Append-only per (issuer, subject) chain                   |
| Trust-graph operations received about this user's contacts                                            | grows                                               | Same                                              | Append-only per remote (issuer, subject) chain            |
| Computed cascade-quarantine state per attestation                                                     | one byte + (revoker pubkey, timestamp)              | Derived                                           | Recomputed on chain mutation                              |
| Soft-flag UI acknowledgments (which attestations user has touched)                                    | one row per attestation                             | Operational                                       | Append/update; informs 90-day timer                       |
| 90-day stale-flag timer baselines (first-flag-observation timestamp per attestation)                  | one row per flagged attestation                     | Operational                                       | Set once when flag first observed; cleared on user action |
| Recovery peer share commitments (the 32-byte BLAKE3 commit each peer holds for the user's own master) | 32 bytes × ~5                                       | Medium                                            | Stable; rotated only at re-split                          |
| Recovery peer pubkeys + names (the user's chosen peers)                                               | per-peer struct                                     | Medium                                            | Stable; mutates only at peer-set changes                  |
| **For each peer**, the share THIS user holds of THEIR master                                          | 32 bytes + commitment per peer-they-attested-us-for | Hardware-bound peer secret                        | Stable; user must persist until peer triggers recovery    |
| SimpleX queue state (per-conversation rotating ratchet state)                                         | grows; per-conversation                             | Very high — ratchet break = message-decrypt break | Mutates every message; fsync-critical                     |
| Per-conversation message history                                                                      | grows large                                         | High                                              | Append + occasional purge                                 |
| Sigsum log-head cache (most recently observed log root + witness cosignatures)                        | small                                               | Public                                            | Updated per fetch                                         |
| Application configuration + UI state                                                                  | small                                               | Low                                               | Mutates on user action                                    |

### Volume estimates (back-of-envelope)

For a pilot user (10–15 contacts, modest message volume over months):

- Identity + capability + master attestation + recovery peer state: < 10 KB
- Trust-graph operations: ~100 ops × 200 bytes = ~20 KB
- Soft-flag + stale-flag UI state: small (one row per flagged attestation; flags should be rare)
- Ratchet state per conversation: ~few KB × 15 = ~50 KB
- Message history: dominant — depends entirely on user behavior; could be 100 MB+ over years
- Sigsum cache: < 100 KB

**Bottom line**: the data layer is ratchet-state-and-message-history heavy. Everything else is small.

## Constraints already locked in by existing D-docs

These narrow the option space before any new decision is needed.

### D0018 §1.4 — XChaCha20-Poly1305 for at-rest

> Cairn's at-rest storage encryption may re-encrypt the same logical object under the same key during recovery scenarios; the 192-bit nonce makes random-nonce collision negligible without requiring counter discipline.

This is the most consequential constraint. It means **the at-rest AEAD is XChaCha20-Poly1305**, not AES-GCM, not AES-CBC-HMAC, not AEGIS. Two implications:

1. **SQLCipher is incompatible.** SQLCipher uses AES-256-CBC + HMAC-SHA256. Adopting SQLCipher would require either changing D0018 §1.4 (whole-stack audit-implication) or running two AEAD primitives in production (cost in audit surface).
2. **Application-layer encryption is the model.** Per-record encryption with random 192-bit nonces, written into a storage engine that sees only ciphertext. The storage engine's job is durability + integrity-of-blob-store, not confidentiality.

### D0018 §6 — Cryptographic core crates are synchronous

> Cryptographic core crates (`cairn-crypto`, `cairn-envelope`, `cairn-shamir`, `cairn-identity`, `cairn-trust-graph`, `cairn-recovery`, **`cairn-storage`**) are synchronous.

`cairn-storage` is explicitly named synchronous. Async I/O wrapping (via `spawn_blocking`) happens at the integration-adapter layer (`cairn-tor-transport`, `cairn-simplex-adapter`, etc.). This narrows the storage-engine choice — anything that requires an async runtime baked into its API (e.g., some sqlx surfaces) is misaligned.

### D0018 §8.1 — `unsafe_code = "deny"` exception, with documented call sites

`cairn-storage` is explicitly named as one of two crates (the other is `cairn-uniffi`) that MAY use `unsafe_code = "deny"` rather than `"forbid"`. The brief mentions an `mlock` wrapper as the example. Constraint: any `unsafe` blocks must have documented justifications + safety arguments at the call site.

### D0006 §3.5 — Forward secrecy is on-wire only; at-rest decryptable under unlock

> Forward secrecy of on-wire message content via the SimpleX double-ratchet derivative; **at-rest message history on the device remains decryptable under unlock regardless of ratchet state**.

This means the at-rest encryption is unlock-bound (passphrase + StrongBox), not ratchet-state-bound. We don't have to delete old ratchet keys to maintain at-rest confidentiality — only on-wire FS.

### D0020 §3 — StrongBox mediates key operations via Kotlin callbacks

The at-rest encryption key derivation chain must accommodate:

1. User's passphrase → KDF (Argon2id) → key-encryption key (KEK)
2. KEK XOR / HKDF-combine with StrongBox-attested key material → data-encryption key (DEK)
3. DEK encrypts each value with XChaCha20-Poly1305 + fresh 192-bit nonce

The StrongBox step happens via the UniFFI `callback_interface` per D0020 §3.4. The Rust `cairn-storage` crate cannot directly call into Android; it requests a "wrap this short key under StrongBox" or "unwrap" operation via callback.

This means **`cairn-storage` exposes a `KeyProvider` trait** that the Android shell implements via callback; the test harness implements with in-memory keys. The crate itself is hardware-neutral.

### D0006 §1.6 + Zeroizing discipline

`SigningKey` private bytes never sit in unwrapped `Vec<u8>`. The storage layer must:

- Decrypt into `Zeroizing<[u8; N]>` (or a `SecretBox` wrapper) on read
- Accept `&Zeroizing<...>` / `&[u8]` for write (the input is already-zeroized by caller)
- Wipe any intermediate buffers on read failure / write failure

## Candidate storage engines

The space sorts into three categories: SQL-relational, embedded KV stores, and append-only logs. Given the application-layer encryption constraint above, the SQL benefits diminish (we can't query on encrypted columns without decrypting), so the comparison is more even than it would be otherwise.

### Option A: `rusqlite` + per-value XChaCha20-Poly1305

The most-audited storage engine on the planet; SQLite is shipped in every Android device, every browser, every iOS device. Used by Signal, WhatsApp, every messaging app at scale.

**Schema sketch:**

```sql
CREATE TABLE kv_blob (
  key BLOB PRIMARY KEY,    -- e.g. b"trust_graph_op:<sha256-prefix>"
  ciphertext BLOB NOT NULL, -- XChaCha20-Poly1305 of the canonical-CBOR payload
  nonce BLOB NOT NULL,      -- 24 bytes
  version INTEGER NOT NULL  -- per-record schema version
);

CREATE TABLE schema_version (
  layer TEXT PRIMARY KEY,
  version INTEGER NOT NULL
);
```

**Pros:**

- Audit pedigree unmatched. SQLite is the most-tested codebase in commercial use; Cairn's audit budget per D0011 doesn't need to cover SQLite.
- Battle-tested durability semantics. `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=FULL` give well-understood crash-safety; documented behavior on power loss.
- Mature migration tooling (`refinery`, `barrel`, etc.).
- Backup / export is trivial (`.dump`, `.backup`).
- Works on Android out of the box (rusqlite bundles its own SQLite to avoid Android-version skew).

**Cons:**

- C dependency (libsqlite3-sys). Increases supply-chain surface vs. pure-Rust alternatives. Mitigated by SQLite's overwhelming audit pedigree, but it's still a C dep in a Rust-discipline codebase.
- SQL surface adds a layer (parsing, planning, query construction). Cairn's access patterns are mostly KV-style; the SQL is overhead, not feature.
- Binary size: ~1.5 MB of compiled SQLite. Mobile-relevant.
- The `unsafe_code = "deny"` exception in D0018 §8.1 covers `mlock`; SQLite's C FFI also requires unsafe at the boundary. Acceptable per D0018 but worth naming.

**Audit-budget posture:** SQLite is treated as a trust root; Cairn's audit reviews the SQL queries + schema + migration discipline, NOT SQLite itself. This matches Signal's posture.

### Option B: `redb` + per-value XChaCha20-Poly1305

Pure-Rust embedded ACID KV store. Active development. Explicit durability documentation. Used by some Cosmos SDK projects + a growing audit/production base.

**Schema sketch:**

```rust
// Each table is a typed (key_type, value_type) namespace.
const TRUST_GRAPH_OPS: TableDefinition<&[u8], (&[u8], &[u8])> =
    TableDefinition::new("trust_graph_ops");
//                              key=op-hash-prefix
//                                       value=(nonce, ciphertext)
```

**Pros:**

- Pure Rust — no C deps. Aligns with the workspace's `unsafe_code = "forbid"` baseline (only `cairn-storage` itself has the exception, and `redb`'s own `unsafe` is bounded and documented).
- Explicit durability spec in the docs (transactions are ACID; fsync calls documented per-API).
- Smaller binary than SQLite (~300 KB).
- API is BTreeMap-shaped; matches Cairn's access patterns naturally.
- ~Modest dependency tree; cargo-deny / cargo-audit footprint smaller than rusqlite.

**Cons:**

- Younger than SQLite. Real production validation is years, not decades. Bugs are still being found.
- Smaller community; if a bug bites at v1.5 partner audit time, fewer eyes to find it.
- No native backup tooling; we write export ourselves.
- Schema migration patterns are still being established by the community; we'd design ours from first principles.
- Audit-budget posture: `redb` itself is in the audit scope, not a trust root. This is a real cost: the audit budget per D0011 has to cover the storage engine, not just its uses.

### Option C: `sled` + per-value XChaCha20-Poly1305

Rust-native embedded KV store. Was the favored choice for many Rust projects circa 2020–2022.

**Posture:** sled has known historical data-loss issues that the maintainers documented honestly. Tauri migrated away from it; many other projects did the same. The maintainer flagged the project as "not 1.0 yet" for years; the current state is "alpha" by its own README.

**Pros:**

- Pure Rust; lock-free B-tree design is interesting.
- Active enough to still receive commits.

**Cons:**

- **Documented historical data-loss bugs.** For a project at Cairn's threat tier — where losing a contact's session ratchet state breaks future message decryption — this is disqualifying without serious validation work that exceeds the v1 budget.
- Less active than `redb` in 2025-2026.
- Audit-budget cost: high (the storage engine is in scope AND has known historical defects to investigate).

**Recommendation lean:** rejected. Listed for completeness; do not pursue without compelling evidence the durability issues are resolved.

### Option D: Hand-rolled append-only log per category + in-memory index

The "simplest possible" design: each category of data (trust-graph ops, ratchet state, messages) gets its own append-only log file. On startup, scan + build in-memory index. Compaction is a periodic rewrite.

**Pros:**

- Zero third-party storage dep.
- Audit surface is just file I/O + serialization.
- Crash recovery is trivially `last_valid_record` (truncate any partial record).
- Aligns well with Cairn's per-(issuer, subject) chain semantics: each chain is naturally append-only.

**Cons:**

- We design durability semantics from scratch (atomic-write-then-rename + fsync(parent_dir)).
- Compaction is non-trivial to get right; concurrent compaction even harder.
- Index rebuild on startup grows with history; mitigated by snapshotting but that re-introduces durability complexity.
- Reinventing primitives that battle-tested databases provide; the engineering cost compounds.
- Audit cost: every fsync ordering + every atomic-rename pattern is in scope.
- Multi-table cross-record consistency is hand-rolled. For Cairn's pattern (mostly independent records per category; rare cross-record transactions like "atomic re-split") this is bearable; for SimpleX integration where ratchet state must update atomically with delivered message persistence, it's harder.

### Option E: `rocksdb` + per-value XChaCha20-Poly1305

LSM-tree KV store; production-grade; used by Cosmos SDK, TiKV, many crypto projects.

**Pros:**

- Production-validated at extreme scale.
- Tunable durability (sync vs. async writes; write-ahead log discipline).
- Compaction is the engine's job, not ours.

**Cons:**

- C++ dependency. Multi-megabyte binary; long build times; complex cross-compilation for Android.
- Configuration surface is huge — getting durability correct is non-obvious.
- Engineered for write-heavy distributed systems; Cairn's scale is "a couple hundred MB on a phone." Overkill.
- Audit cost: rocksdb itself is large surface; treating as trust root requires accepting a meaningful C++ dependency.

**Recommendation lean:** rejected for v1. May reconsider at v2+ if scale justifies.

### Option F: `fjall` + per-value XChaCha20-Poly1305

Newer pure-Rust LSM-tree explicitly aiming to be "rocksdb in Rust."

**Pros:**

- Pure Rust.
- Modern API design.

**Cons:**

- Very new (2024+). Production validation pending.
- Audit posture is the same as `redb`'s but with a much shorter track record.

**Recommendation lean:** reconsider at v1.5+ once production validation matures. Not a v1 candidate.

## Encryption layering

Given D0018 §1.4 picks XChaCha20-Poly1305 application-layer, the open questions are:

### Key derivation: passphrase → DEK

1. **Argon2id** for passphrase stretching (workspace already pulls `argon2` if we add it; D0018 doesn't specify but Argon2id is the standard).
2. **HKDF-SHA256** for combining the Argon2 output with the StrongBox-attested key material (`cairn-crypto::hkdf` is already implemented).
3. **One DEK per data category** (so a key rotation can re-encrypt a subset without re-encrypting everything) vs. **one DEK total** (simpler; full re-encrypt on rotation).

The category-keyed approach is cleaner for the "ratchet state has a 192-bit nonce window; everything else doesn't need that headroom" boundary D0018 §1.4 names.

### Per-record format

```
record_bytes = version_byte ‖ nonce (24 bytes) ‖ XChaCha20-Poly1305(DEK, payload, AAD)
```

Where `AAD = canonical-CBOR encoding of (category_tag, record_id, schema_version)` — binds the record to its intended slot so an adversary with write access to the storage cannot swap a record from one slot to another without invalidating the AEAD tag.

### What's NOT encrypted

- Sigsum log heads (public anyway)
- Schema-version table (needed to bootstrap migration; encrypted-version doesn't help and complicates recovery from corruption)
- Possibly: trust-graph op hashes (used as keys for lookup; encrypting them defeats lookup)

The integrity property of the storage engine (its own checksum if any + the AEAD tag per record) protects against tampering of public data; confidentiality only needed for the private parts.

## Migration discipline

Whatever engine wins, the migration story needs:

1. **Per-record schema version**: one byte at the head of each ciphertext (post-decrypt, since AAD-binding the version means downgrade attacks are caught).
2. **Per-category schema version**: stored in a `schema_version` table or fixed key. Bootstrap: if missing, assume v1.
3. **Forward-only migrations** at v1; reversibility deferred. A failed migration must leave the database in its pre-migration state (transactional migration wrapping).
4. **No automatic migration on first-decrypt-failure** — that's an attack surface. Migrations only run via an explicit code path triggered at app start under a known version delta.

## Android-specific concerns

### Scoped storage

App data lives under `/data/data/<package>/files/`. Sufficient isolation for Cairn's threat model; FBE encrypts the parent at the device level.

### fsync semantics

Android's ext4 (the standard FS for app data) honors fsync. The atomic-write pattern (write to temp file, fsync, rename, fsync parent dir) works correctly. Both SQLite (with `synchronous=FULL`) and `redb` use this pattern.

### Doze + App Standby

Background work is constrained. Cairn's I/O is foreground (user actively in app) or via the `simplex-chat` ForegroundService child process per D0020 §1.6. Storage doesn't need to fight Doze.

### Backup / export

Android's `BackupManager` is opt-in via manifest. Cairn opts out (`android:allowBackup="false"`) — the recovery model is Shamir social recovery, not platform backup. The storage layer doesn't need to integrate with the platform backup at all.

### Application sandboxing under user 0 vs work profile

GrapheneOS supports user profiles. Storage is per-profile naturally. No special work.

## Trade-off summary table

| Criterion                                   | rusqlite                            | redb                  | hand-rolled    | sled                         | rocksdb            | fjall      |
| ------------------------------------------- | ----------------------------------- | --------------------- | -------------- | ---------------------------- | ------------------ | ---------- |
| Audit pedigree of engine                    | Decades, extensive                  | Years, growing        | N/A            | Mixed, known issues          | Years, extensive   | Months     |
| Cargo-deny / supply-chain footprint         | C dep                               | Pure Rust             | None           | Pure Rust                    | C++ dep            | Pure Rust  |
| Binary size impact                          | ~1.5 MB                             | ~300 KB               | ~50 KB         | ~400 KB                      | ~3-5 MB            | ~400 KB    |
| Fit with application-layer encryption       | Good (KV pattern in SQL)            | Excellent (native KV) | Excellent      | Excellent                    | Excellent          | Excellent  |
| Durability story                            | Well-documented                     | Documented            | Hand-designed  | Concerning                   | Tunable, complex   | Documented |
| Schema migration tooling                    | Mature                              | DIY                   | DIY            | DIY                          | DIY                | DIY        |
| In-scope for audit per D0011                | Trust root (auditor doesn't review) | In scope              | In scope       | In scope (with known issues) | Partial trust root | In scope   |
| Engineering cost to v1 ship                 | Low                                 | Low-medium            | High           | N/A (rejected)               | Medium-high        | Medium     |
| Production validation at v1.5 partner pilot | Highest                             | Medium                | Self-validated | N/A                          | Highest            | Low        |

## Decision factors for D0022

The realistic candidates that survive the screen are **rusqlite**, **redb**, and **hand-rolled append-only logs**. The decision turns on three axes:

### Axis 1: How much of the storage engine should be in the audit scope?

- **rusqlite**: zero (SQLite is a trust root; auditor reviews queries + schema + migrations only).
- **redb**: full (engine is in scope; auditor reviews engine's durability + ACID claims).
- **hand-rolled**: full (everything is ours).

For a self-funded baseline per D0008, the rusqlite posture has the lowest audit burden. Against that: every dependency on a C library widens the threat surface vs. pure-Rust alternatives in a way the project has otherwise minimized.

### Axis 2: How much pure-Rust discipline matters?

The codebase is otherwise pure-Rust top to bottom. The only C/C++ deps come in via `ed25519-dalek`'s transitive deps (none, actually — it's pure Rust). Adding `rusqlite` introduces the FIRST C dep in the Rust core.

The counter: D0020 introduces a C/C++ dep in production via the SimpleX CLI binary as a child process. So "pure-Rust" is already not absolute. Adding SQLite isn't a step-change.

### Axis 3: What's the migration discipline cost?

Cairn ships pre-v1 with no users; migrations are theoretical. But D0006 §6.4 commits to forward-compat unknown-field round-tripping, which is one form of migration discipline. SQL schema migration patterns are mature; KV migrations are designed per-project.

For v1 the migration cost is similar across rusqlite and redb (both DIY enough; rusqlite has more reference patterns to copy). Hand-rolled migration is significantly more work.

## What this research doesn't decide

Open questions that the D0022 decision document needs to answer:

1. **Engine selection**: rusqlite vs. redb vs. hand-rolled. The trade-off table above is the substrate; the decision is yours.
2. **Encryption-key derivation specifics**: Argon2id parameter choice (memory cost, time cost, parallelism); category-keyed vs. single-DEK; HKDF labels for the StrongBox-combine step.
3. **Snapshot / backup / export format**: Cairn's recovery model doesn't use platform backup, but users may want to export their trust-graph or message history for migration to a fresh device after seizure. Format = canonical CBOR of the cleartext records seems natural but should be confirmed.
4. **Atomic re-split protocol's storage interaction**: Two-phase commit across N peers per D0018 §3.5 requires storing intermediate state. The protocol design (which lives in `cairn-recovery` or a future `cairn-recovery-orchestrator`) interacts with how the storage layer represents in-flight operations.
5. **Schema version baseline**: do we start every category at version 1 explicitly, or rely on absence-of-version-key = version 1?

## Recommendation framework (not the recommendation)

If the priority is **audit-budget conservation per D0011 + minimum engineering surface to v1 ship**: rusqlite wins. SQLite is a trust root; the audit reviews our schema and queries, not the engine. The C dep is a real cost but tractable in audit posture.

If the priority is **pure-Rust discipline + smaller dependency surface + alignment with the workspace's "minimize C deps" lean**: redb wins. Active development; reasonable durability story; ~300 KB binary impact. The audit cost is real — the engine is in scope — but the engine is small and reviewable.

If the priority is **minimum third-party dep surface + maximum control over durability semantics**: hand-rolled. Highest engineering cost; we own everything good and bad about it.

**My read of the trade-off**: rusqlite is the production-conservative choice; redb is the workspace-discipline-conservative choice; hand-rolled is the audit-purity choice that costs engineering. The D0022 decision is which of those priorities weighs heaviest against the others. I don't have enough context on your audit-budget posture or partner-audit timing to pick between them on your behalf.

What I can offer as a sanity-check: Signal uses SQLCipher (which is SQLite + AES-CBC layer). Bitwarden uses SQLCipher. Element X uses SQLite + their own crypto layer. WhatsApp uses SQLite. The "SQLite + application-layer-encryption" pattern is the dominant choice across messaging projects at Cairn's threat tier; the audit posture of every one of those projects rests on it. That's a strong industry signal but not dispositive — Cairn's pure-Rust discipline + smaller scale + audit-budget constraints are different.
