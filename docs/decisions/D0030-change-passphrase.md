# D0030 — change-passphrase: decouple the SimpleX DB key, then atomic single-DB rekey

**Status:** Accepted
**Date:** 2026-06-03

> **Confirmed (2026-06-03):** Design B (decouple the SimpleX DB key → atomic
> single-DB rekey of cairn-storage) over Design A (rekey both DBs), and a
> **two-stage** delivery (Stage 1 decouple, Stage 2 rekey + UI), each
> on-device-validated and committed separately.

## Context

The at-rest model (D0022 §2.2, now fully realized — real passphrase KEK + real
StrongBox device material) has no **change-passphrase**. Adding one is the last
piece of the passphrase lifecycle. The difficulty is that, as built, the
passphrase keys **two independent databases**:

1. **cairn-storage** — `KEK = Argon2id(passphrase, salt)`; each category DEK =
   `HKDF(KEK ‖ StrongBox material, info=category)`; records are XChaCha20-sealed
   under the DEK.
2. **the libsimplex chat DB** — SQLCipher-encrypted under
   `dbKey = HMAC(passphrase, "cairn-v1-simplex-db-key")`, set at `init`
   (`CairnSession.deriveDbKey`).

A naive change-passphrase must re-key **both**. That is the wrong design (§1).

This is downstream of D0022 §2.2 (the at-rest model it extends) and D0026 §12
(the SimpleX DB-key derivation it changes). No new crypto; it adds a rekey
operation + decouples one key.

## Decision summary

| Concern                           | Decision                                                                                                                                                                       |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **SimpleX DB key source**         | **Decouple** — a _random_ 32-byte key generated once and stored **inside cairn-storage**, not derived from the passphrase (§2)                                                 |
| **What change-passphrase rekeys** | **cairn-storage only**, in **one atomic SQLite transaction** (re-encrypt every record under new DEKs + rotate the KEK salt) (§3)                                               |
| **The libsimplex DB on change**   | **Untouched** — its key's _plaintext_ is unchanged (only its at-rest copy inside cairn-storage is re-sealed), so it opens normally; no `apiStorageEncryption`, no two-DB dance |
| **Old-passphrase check**          | `change_passphrase(old, new)` decrypts with the old-derived DEKs first; a wrong `old` fails the first record decrypt → rollback, nothing changed                               |
| **Quick unlock (D0029)**          | **Invalidated** on a successful change (the wrapped blob holds the _old_ passphrase) — deleted; the user re-enrolls                                                            |
| **StrongBox material (D0022)**    | **Unchanged** — it is device-bound, not passphrase-derived                                                                                                                     |
| **Staging**                       | Stage 1: decouple the DB key (prerequisite). Stage 2: the rekey primitive + UI                                                                                                 |
| **Migration**                     | Fresh installs only (the established at-rest caveat)                                                                                                                           |

---

## 1. Why not rekey both databases (Design A)

Keeping `dbKey = HMAC(passphrase)` forces change-passphrase to re-encrypt
cairn-storage **and** rekey the libsimplex SQLCipher DB (via SimpleX's
`apiStorageEncryption`, not currently wired). The fatal problem is **atomicity
across two independent databases**: if the cairn-storage rekey commits but the
libsimplex rekey then fails (a crash, an XFTP-busy DB, a SQLCipher error), the
two DBs are keyed to **different** passphrases. Neither the old nor the new
passphrase opens _both_ — the app is permanently wedged, with no clean rollback
(you cannot atomically commit-or-abort across two separate SQLite files). Adding
a journal/recovery protocol to make this safe is a large, error-prone surface
for a feature that Design B makes trivially atomic. **Rejected.**

## 2. Design B — decouple the SimpleX DB key (Stage 1)

The libsimplex DB key does **not** need to be a function of the passphrase; it
only needs to be **available once cairn-storage is unlocked** and **stable**.
So: generate a random 32-byte key on first launch, store it as a record in
cairn-storage (`IDENTITY` category, id `simplex-db-key`), and use the **stored**
value for `dbKey` — instead of `HMAC(passphrase)`.

```text
first launch:  random 32B → store in cairn-storage (sealed under IDENTITY DEK)
every launch:  open cairn-storage (needs passphrase) → read simplex-db-key
               → init libsimplex with it
```

Properties:

- **Still passphrase-gated, transitively** — reading the key requires opening
  cairn-storage, which requires the passphrase (and the device's StrongBox
  material). Security is **equivalent** to the HMAC derivation (both need the
  passphrase); Design B adds one indirection and one stored secret.
- **Stable across a passphrase change** — the key's _plaintext_ never changes;
  only its sealed at-rest copy is re-encrypted under the new DEK during the
  rekey. So the libsimplex DB opens with the same key before and after — **no
  libsimplex rekey at all**.
- **Ordering already holds** — `CairnSession.bootstrap` opens cairn-storage and
  validates the passphrase _before_ it builds the `SidecarEndpointConfig`, so
  the key is readable at exactly the point `dbKey` is needed.

This is the prerequisite refactor; on its own it is a no-op for the user (fresh
installs get a random key; messaging is unaffected).

> **Realized — Stage 1 (2026-06-03).** `CairnSession.simplexDbKey(storage)`
> mints a random 32-byte key into cairn-storage (`IDENTITY` /
> `cairn-simplex-db-key-v1`) on first launch and returns the stored value as the
> SQLCipher `dbKey`. On-device-validated on a Pixel: minted+stored on first
> launch; the real SimpleX DB opens under it (`db at-rest: encrypted` →
> `FFI conn ESTABLISHED`, invitation created); **reused not re-minted across a
> restart** with the DB re-opening; and the two-party loopback selftest
> round-trips over Tor. (Device B was physically disconnected; the single-device
> proofs fully cover the decoupling, which doesn't touch the per-message path.)

## 3. The atomic rekey (Stage 2)

`cairn-storage` gains `Storage::change_passphrase(key_provider, old, new)`:

```text
1. derive old KEK from `old` + the current salt; derive old DEKs.
   (decrypting the first record with them verifies `old` — a wrong old aborts.)
2. generate a FRESH salt; derive new KEK from `new` + fresh salt; derive new DEKs
   (StrongBox material unchanged).
3. BEGIN TRANSACTION
     for each category, for each record_id:
        pt  = open(old_DEK[cat], cat, id, ciphertext)   // decrypt
        ct' = seal(new_DEK[cat], cat, id, pt)            // re-encrypt (fresh nonce)
        UPDATE storage SET ciphertext = ct' WHERE category=cat AND record_id=id
     meta_set(META_KEK_SALT, fresh_salt)
   COMMIT            // atomic: all rows + salt, or nothing
4. swap the in-memory DEK cache to the new DEKs.
```

Atomicity is a single SQLite transaction over one file — either every record is
re-encrypted under the new DEKs and the salt is rotated, or the transaction
rolls back and the **old passphrase still works** (no data loss, no half-state).
The unlock canary is just an `IDENTITY` record, so it is re-encrypted by the
loop with everything else — no special-casing.

`cairn-uniffi` exports `StorageHandle.change_passphrase(old, new)`; the KEK/DEKs
never cross the FFI (the rekey runs entirely in Rust).

## 4. Quick-unlock interaction (D0029)

The quick-unlock blob wraps the **old** passphrase. After a successful change it
would decrypt to a stale phrase, so the Kotlin flow **invalidates quick unlock**
(`QuickUnlock.disable` — deletes the blob + Keystore key) on success and tells
the user to re-enable it. Re-wrapping the new passphrase automatically would
require a biometric prompt mid-flow; invalidating is simpler and safer (the
passphrase always works as the fallback).

## 5. Migration + consequences

- **Stage 1 migration:** a libsimplex DB created under the old
  `HMAC(passphrase)` key won't open under the random-stored-key model — **fresh
  installs only**, the same caveat the at-rest DB encryption + the StrongBox-KEK
  binding already carry (D0026 §12). The test harness `pm clear`s, so this is
  clean in validation.
- **No new device-binding consequence** — the StrongBox material is unchanged,
  so the device-bound property (D0022 §2.2 realized note) is preserved across a
  passphrase change.

## 6. Validation plan

- **Host (Rust unit tests):** `change_passphrase` round-trips (records readable
  under the new passphrase, unreadable under the old); a wrong `old` aborts with
  no mutation; salt rotates; a simulated mid-rekey failure rolls back (old still
  opens).
- **On-device (two Pixels):** set passphrase → write data (pair a contact,
  exchange a message) → change passphrase → relaunch: the **old** passphrase is
  rejected, the **new** passphrase unlocks with the **contact + history intact**
  and **messaging still works** (proving the libsimplex DB opened under the
  stable stored key); quick unlock shows as disabled after the change.

## 7. Cross-references

- [D0022 — storage layer](D0022-storage-layer.md) — §2.2 the KEK/DEK model the
  rekey re-derives; the realized StrongBox-material note (unchanged by a rekey)
- [D0026 — cairn-simplex-adapter](D0026-cairn-simplex-adapter.md) — §12 the
  SimpleX DB-key derivation Stage 1 replaces
- [D0029 — quick unlock](D0029-quick-unlock.md) — the wrapped blob this
  invalidates on change
- D0005 — identity recovery (orthogonal: this is local at-rest re-keying, not
  identity recovery)
