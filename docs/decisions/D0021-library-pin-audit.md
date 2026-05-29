# D0021 — Library pin audit + revision (Cargo.toml drift, coset role, hygiene)

**Status:** Accepted
**Date:** 2026-05-29

## Context

A pin audit of the workspace `Cargo.toml` against D0018's library
specifications revealed:

1. **Cargo.toml drift from D0018 spec** for two cryptographic pins
   (`vsss-rs`, `coset`). The implementation-phase `Cargo.toml` was
   authored from a stale read of D0018 (or D0018 was revised after
   `Cargo.toml` was written), introducing version drift that
   propagated forward through eight Tier 1 MDC implementation surfaces
   before being detected.
2. **One real coset finding** — the encoder side of `coset` delegates
   to `ciborium`'s non-canonical default. D0018 §2.2 itself
   documented this gap and §2.3 specified the project-owned canonical
   encoder as the answer. This D-doc clarifies the decoder/oracle role
   coset retains.
3. **Two hygiene findings** discovered during the audit pass
   (`displaydoc` unused, `dudect-bencher` 0.7.0 available with explicit
   MSRV declaration).

This D-doc records all three sets of findings and the discipline note
that explains how a more rigorous version of the same audit would have
caught the drift before any implementation work depended on it.

Important: this D-doc is the **revised** version. An earlier draft of
D0021 (committed 5b2161b, since revised) concluded "vsss-rs is
unsuitable for byte-level GF(2⁸)" and justified a from-scratch
implementation (commit 2ad574f, now reverted in commit 56a825d). That
conclusion was wrong: it was based on testing `vsss-rs` 4.3.8 (the
drifted `Cargo.toml` pin) instead of `vsss-rs` 5.4.0 (the D0018
spec), and the 4.x → 5.x major version added the byte-level GF(2⁸)
module my audit said didn't exist. The current D0021 records this
self-critique as part of the discipline note in §4.

## Decision summary

| Finding                     | D0018 spec                  | Cargo.toml (pre-audit)      | Status                                                                                                          |
| --------------------------- | --------------------------- | --------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `vsss-rs` pin drift         | `=5.4.0` (§3.1 line 610)    | `=4.3.8`                    | Aligned per §1 below; cairn-shamir refactored to wrap `vsss-rs::Gf256`                                          |
| `coset` pin drift           | `=0.4.2` (§2.2 line 607)    | `=0.3.8`                    | Aligned per §1 below; coset's role clarified per §2 below                                                       |
| coset non-canonical encoder | n/a (already known to §2.2) | n/a                         | Role clarified — decoder + interop oracle; canonical encoder remains `cairn-envelope::canonical` per D0018 §2.3 |
| `displaydoc` unused         | n/a                         | `=0.2.5` present, zero uses | Removed from workspace deps per §3.1 below                                                                      |
| `dudect-bencher` minor bump | n/a                         | `=0.6.0`                    | Bumped to `=0.7.0` per §3.2 (separate hygiene commit)                                                           |

---

## 1. Finding: Cargo.toml drift from D0018 specifications

### 1.1 Evidence

- **D0018 line 610**: `vsss-rs = { version = "=5.4.0", default-features = false, features = ["std", "zeroize"] }`
- **Cargo.toml (pre-audit) line 77**: `vsss-rs = { version = "=4.3.8", default-features = false, features = ["std", "zeroize"] }`
- **D0018 line 607**: `coset = "=0.4.2"`
- **Cargo.toml (pre-audit) line 74**: `coset = "=0.3.8"`

Both are exact-version pins (`=X.Y.Z`) per D0018's reproducible-build
discipline, so the drift is two specific version mismatches, not a
semver-range ambiguity.

### 1.2 Why this matters

The `vsss-rs` 4.3.8 → 5.4.0 jump is a major version bump that introduced
the byte-level GF(2⁸) Shamir module (`vsss-rs-5.4.0/src/gf256.rs`).
`vsss-rs` 4.3.8 exposed only the prime-field scalar API
(`shamir::split_secret<F: PrimeField, ...>`) — which is what an earlier
draft of D0021 tested. That earlier draft therefore concluded "vsss-rs
cannot do byte-level GF(2⁸)" and justified a from-scratch implementation
in `cairn-shamir` (commit 2ad574f). The conclusion was wrong: the
library _can_ do byte-level GF(2⁸); the wrong version was in the
workspace.

The `coset` 0.3.8 → 0.4.2 jump did not change the canonical-encoder
gap (the same `cbor::ser::into_writer` delegation pattern remains in
`src/common/mod.rs`'s `to_vec` / `to_tagged_vec`), so the substantive
coset finding survives — see §2 below — but the audit should have been
done against 0.4.2 from the start.

### 1.3 How it was found

The drift surfaced when applying D0021 §6's pending D0018 inline
touch-ups: grepping for "vsss-rs" and "coset" mentions in
`docs/decisions/D0018-engineering-foundation.md` exposed the
version-pin specifications. Cross-checking against `Cargo.toml`
produced the discrepancies in §1.1.

The drift had been latent through eight Tier 1 MDC implementation
commits (workspace foundation → cairn-shamir GF(2⁸) implementation) plus
D0021's original draft. None of those tasks had reason to look at the
D0018 line numbers for the pin specifications. The first time anyone
had to cross-reference both was when applying the D0018 inline
touch-ups in this audit pass.

### 1.4 Decision

**Align `Cargo.toml` with D0018** for both drifted pins. Bumping is
non-breaking for `coset` (only used as a transitive dep — workspace
already builds clean at 0.4.2). For `vsss-rs`, the major version bump
enables wrapping `vsss-rs::Gf256` as D0018 §3.1 originally specified.

This commit (b543241) bumped both pins. The follow-on commit
(56a825d) refactored `cairn-shamir`:

- Deleted `crates/cairn-shamir/src/gf256.rs` (256 LoC of from-scratch
  field arithmetic — the work that should not have happened)
- Rewrote `crates/cairn-shamir/src/share.rs` (~150 LoC saved) as a
  thin wrapper around `vsss-rs::Gf256::split_array` / `combine_array`
- Kept `crates/cairn-shamir/src/commit.rs` (BLAKE3 commit-of-secret is
  Cairn's value-add — `vsss-rs` does not provide one)
- 22 share / commit / lib tests pass (13 gf256-arithmetic tests
  vanished with the module they tested — those checks now live in
  `vsss-rs`'s own test suite, which is what we should be relying on
  per D0018 §3.1's audit-target framing)

The `vsss-rs::Gf256` module is the Cure53 PVY-01-003 reference
cache-side-channel-resistant GF(256) construction per D0018 §3.1 line 316. This is stronger auditable provenance than 250 LoC of our own
arithmetic could provide without external audit.

### 1.5 D0018 §3.1 stands as written

The earlier D0021 draft proposed superseding D0018 §3.1. The revised
D0021 makes no such proposal: D0018 §3.1 specified `vsss-rs` 5.4.0
because it does what Cairn needs. The error was in `Cargo.toml`'s
drift, not in D0018. A small inline touch-up to D0018 §3.1 will record
this D-doc as the audit reference, but the substantive `vsss-rs`-as-
primary decision is unchanged.

---

## 2. Finding: `coset`'s encoder is non-canonical (already known to D0018; decoder role preserved)

### 2.1 Evidence (verified against 0.4.2)

- `CborSerializable::to_vec` and `TaggedCborSerializable::to_tagged_vec`
  in `coset-0.4.2/src/common/mod.rs` delegate to
  `cbor::ser::into_writer(&value, &mut data)` — that's `ciborium`'s
  default encoder.
- `ciborium` does not enforce canonical CBOR by default. This is
  precisely the gap that motivated D0018 §2.3's project-owned canonical
  encoder.
- D0018 §2.2 itself documented this: _"Critical gap:
  `Header::to_cbor_value` does NOT sort `rest` (custom) header
  parameters. ... Cairn closes this gap by building the protected
  header bytes manually via the `cairn-cbor-canonical` helper per
  section 2.3."_ (D0018 line 192-198)

The D0018 spec already anticipated and answered this gap. The finding
in this D-doc is not a new architectural discovery; it is a clarification
of `coset`'s **role** given that D0018's spec was correct.

### 2.2 Decision

**`coset` retained in workspace dependencies for two roles**:

1. **Decoder for incoming peer envelopes.** `coset`'s
   `ProtectedHeader::original_data` preservation (in
   `header/mod.rs::cbor_bstr`) is structurally correct for the decode
   → re-verify path: the original bytes the signer saw are carried
   through unchanged, so signature verification works against the
   original (potentially non-canonical) signing input.
2. **Reference implementation for `veraison/go-cose` interop
   validation.** When the cross-implementation interop surface lands
   (pending per `metrics.md`), `coset` becomes the Rust-side reference
   that the Go-side `veraison/go-cose` is compared against. Both must
   agree on the bytes Cairn emits.

The canonical encoder remains `cairn-envelope::canonical` per D0018
§2.3. `cairn-envelope::cose_sign1` builds the `Sig_structure` and the
outer 4-tuple via that canonical encoder, never via `coset`'s
`to_vec` chain.

### 2.3 D0018 §2.2 inline touch-up

A small inline touch-up to D0018 §2.2 will explicitly enumerate the
decoder/oracle roles `coset` plays (the spec already documents the
encoder gap; what's missing is the explicit role positive-statement).
The substantive `coset`-for-decoder-and-interop decision is unchanged.

---

## 3. Hygiene actions

### 3.1 `displaydoc` removal

- D0018 §4.3 originally pinned `displaydoc = "0.2"` alongside `thiserror`
- Investigation: zero usage in `cairn-crypto`, `cairn-envelope`, or
  `cairn-shamir` (`grep -rn displaydoc --include="*.rs"` returns
  nothing)
- `thiserror` covers the error-with-Display surface ergonomically; no
  current or planned Cairn module needs `displaydoc`'s markdown-style
  doc-comment derive
- **Action**: Remove `displaydoc` from workspace dependencies. Re-add
  via D-doc if a future surface needs the markdown derive
- This change is committed alongside this D-doc (5b2161b)

### 3.2 `dudect-bencher` pin bump

- D0018 §5.3 pinned `dudect-bencher = "=0.6.0"`
- `cargo info dudect-bencher@0.7.0`: declares `rust-version = "1.85"`
  matching our toolchain pin; same author / repo / license / features
  (`core-hint-black-box`)
- `cargo info dudect-bencher@0.6.0`: `rust-version: unknown`
- **Action**: Bump pin to `=0.7.0` per the spec-hygiene discipline
  (explicit MSRV declarations preferred over implicit ones)
- Committed separately as a hygiene commit (c364d10)

---

## 4. Discipline note for future library-pin audits

The Cargo.toml drift in §1 + the original D0021 draft's wrong
"vsss-rs unsuitable" conclusion share a root cause: the audit treated
`Cargo.toml` as ground truth without cross-checking against D0018.

For future D-doc pin audits in cryptographic-discipline use, the
workflow must verify **spec** AND **code** are aligned **before**
drawing conclusions about a library's API. Specifically:

1. For each pinned library mentioned in the audit, quote both the
   D0018 specification line (file + line number) **and** the
   `Cargo.toml` pin line (file + line number).
2. If they differ, the substantive finding is the drift, not the
   library's API. Investigate (and reconcile) the drift before
   concluding anything about the library.
3. When inspecting library APIs, extract the **D0018-specified
   version** from `~/.cargo/registry/cache/`, not whatever happens
   to be in the workspace lockfile. The lockfile may reflect drifted
   pins.
4. If the spec is correct and the code drifted, the fix is to align
   code with spec. If the code is correct and the spec drifted (rarer),
   the fix is to revise the spec via a new D-doc.

This is a process change, not a tooling change. It generalises the
discipline note from the earlier D0021 draft: an "API conformance
check" before pinning is necessary but not sufficient — once pinned, a
**spec/code reconciliation check** is required before drawing library
conclusions from later audits.

A small periodic-audit task (~quarterly) reconciling `Cargo.toml`
against D0018 would have caught the drift before it propagated through
implementation. A CI-level lint that compares D0018 pin specifications
against the workspace `Cargo.toml` would catch this automatically; this
is a candidate future surface but not a v1 commitment.

---

## 5. Cross-references

- **D0006** §3 (envelope structure), §6 (trust-graph attestations), §9
  (capability tokens) — informs the byte-level Shamir + canonical CBOR
  requirements that the audit verified
- **D0018** §1 (crypto primitives), §2.2 (CBOR / COSE libraries), §2.3
  (canonical encoder), §3.1 (Shamir library), §3.4 (commit-of-secret),
  §4.3 (logging discipline), §5.3 (constant-time benchmarking) —
  surfaces inspected by this audit
- **D0020** §3.7 (`NeverExport` discipline) — the `cairn-shamir::Share`
  type's `Zeroizing<[u8; SECRET_LEN]>` payload field is in the secret-
  bearing types catalog
- **`metrics.md`** 2026-05-29 entries for `cairn-envelope` (canonical
  CBOR + COSE_Sign1) and `cairn-shamir` (now wrapping `vsss-rs::Gf256`
  rather than from-scratch arithmetic) — implementation evidence

---

## 6. Implementation status

| Action                                                             | Status                             | Location                                         |
| ------------------------------------------------------------------ | ---------------------------------- | ------------------------------------------------ |
| `vsss-rs` 4.3.8 → 5.4.0 pin alignment                              | Complete (b543241)                 | `Cargo.toml` `[workspace.dependencies]`          |
| `coset` 0.3.8 → 0.4.2 pin alignment                                | Complete (b543241)                 | `Cargo.toml` `[workspace.dependencies]`          |
| `cairn-shamir` refactor to wrap `vsss-rs::Gf256`                   | Complete (56a825d)                 | `crates/cairn-shamir/src/{share,lib,Cargo.toml}` |
| Delete from-scratch `gf256.rs` (256 LoC)                           | Complete (56a825d)                 | `crates/cairn-shamir/src/gf256.rs` (removed)     |
| Keep `cairn-shamir::commit` (BLAKE3 commit-of-secret)              | Complete                           | `crates/cairn-shamir/src/commit.rs`              |
| `displaydoc` removed from workspace deps                           | Complete (5b2161b)                 | `Cargo.toml` `[workspace.dependencies]`          |
| `dudect-bencher` 0.6.0 → 0.7.0 bump                                | Complete (c364d10)                 | `Cargo.toml` `[workspace.dependencies]`          |
| D0018 §2.2 inline touch-up (coset decoder/oracle role enumeration) | Pending                            | `docs/decisions/D0018-engineering-foundation.md` |
| D0018 §3.1 inline touch-up (reference this D-doc)                  | Pending                            | `docs/decisions/D0018-engineering-foundation.md` |
| D0018 §4.3 inline touch-up (`displaydoc` removed)                  | Pending                            | `docs/decisions/D0018-engineering-foundation.md` |
| D0018 §5.3 inline touch-up (`dudect-bencher` 0.7.0)                | Pending                            | `docs/decisions/D0018-engineering-foundation.md` |
| `cairn-shamir` `dudect-bencher` constant-time gate                 | Pending separate surface           | `metrics.md` Tier 1 MDC milestone                |
| `veraison/go-cose` interop validation surface                      | Pending separate surface           | `metrics.md` Tier 1 MDC milestone                |
| Future: periodic `Cargo.toml` vs D0018 reconciliation lint         | Candidate future surface (post-v1) | CI / repo tooling                                |
