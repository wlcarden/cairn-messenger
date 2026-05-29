# D0021 — Library pin audit + revision (vsss-rs, coset, hygiene)

**Status:** Accepted
**Date:** 2026-05-29

## Context

During the implementation phase (per `metrics.md` surface-completion
record 2026-05-29 — eight Tier 1 MDC surfaces landed in one working
session), two D0018-pinned cryptographic libraries surfaced API
conformance gaps that the spec-writing phase had not caught. This D-doc
records both findings, the remediations, two smaller hygiene actions
discovered during the audit pass, and a discipline note for future
library-pinning decisions.

Both findings emerged organically — vsss-rs while implementing
`cairn-shamir`, coset while implementing `cairn-envelope::cose_sign1` —
not during D0018 drafting. This is the MDC pathway (working code before
partner conversations, per the consolidated triage M1 reorientation)
working as intended: actual implementation surfaces architectural
questions that pure specification work misses. The discipline note in §4
generalises the lesson for future D-docs that pin libraries for
cryptographic-discipline use.

This D-doc supersedes D0018 §3.1 for byte-level Shamir, clarifies D0018
§2.2's role for coset, and applies two hygiene updates to D0018 §4.3
(displaydoc) and §5.3 (dudect-bencher). A follow-up touch-up to D0018
itself should fold these revisions back into the source D-doc's text
inline.

## Decision summary

| Library                        | D0018 pin | Finding                                                       | v1 mechanism                                                                             | Status                                |
| ------------------------------ | --------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------- |
| `vsss-rs` 4.3.8                | §3.1      | Requires `F: PrimeField`; no GF(2⁸) support                   | Project-owned byte-level GF(2⁸) Shamir in `cairn-shamir`                                 | D0018 §3.1 superseded by §1 below     |
| `coset` 0.3.8                  | §2.2      | Encoder delegates to non-canonical `ciborium`                 | Keep as decoder + interop oracle; canonical encoder lives in `cairn-envelope::canonical` | D0018 §2.2 role clarified by §2 below |
| `displaydoc` 0.2.5             | §4.3      | Unused in any crate; `thiserror` covers the surface           | Remove from workspace deps                                                               | Hygiene per §3.1 below                |
| `dudect-bencher` 0.6.0 → 0.7.0 | §5.3      | 0.7.0 declares `rust-version = "1.85"`; 0.6.0 leaves implicit | Bump pin (separate hygiene commit)                                                       | Hygiene per §3.2 below                |

---

## 1. Finding: `vsss-rs` is unsuitable for byte-level Shamir

### 1.1 Evidence

- `vsss_rs::shamir::split_secret` (`vsss-rs-4.3.8/src/shamir.rs:166`)
  declares the bound `F: PrimeField`.
- Every `PrimeField` implementation surveyed in the Rust ecosystem at
  2026-05 is a cryptographic-curve scalar field: curve25519's
  order-2²⁵² prime field, BLS12-381's scalar field, secp256k1's scalar
  field, etc. None are GF(2⁸).
- `PrimeField` and GF(2⁸) (a non-prime extension field of order 2⁸) are
  not interchangeable. The trait bound is structural, not nominal —
  adding a wrapper impl would require fabricating a fictional "prime"
  for an algebraically composite field.

### 1.2 Why this matters for Cairn

- D0006 §9 + RFC 8032 §5.1.5: Cairn splits the **32-byte Ed25519 seed**,
  not the derived scalar. The Shamir layer operates at the byte level
  because the seed is bytes, not a scalar.
- The seed-not-scalar requirement is load-bearing: per RFC 8032 §5.1.6,
  Ed25519 nonce derivation uses `h[32..64]` (the seed-derived prefix).
  Splitting at the scalar level would lose `h[32..64]`, forcing
  XEdDSA-style randomized nonce generation at reconstruction. That
  trade-off:
  - Breaks bit-identical recovery (different `(R, S)` per re-signing of
    the same payload)
  - Removes the deterministic-nonce safety property RFC 8032 explicitly
    calls out
  - Requires a CSPRNG path at every sign call after recovery
  - Changes the cryptographic design (vanilla Ed25519 → XEdDSA-variant)
    in a way that would propagate to D0006's audit story
- Splitting the seed therefore requires byte-level Shamir (independent
  GF(2⁸) polynomials per byte position) which `vsss-rs` does not
  implement at v4.3.8.

### 1.3 Alternatives considered

- **`sharks` crate**: clean byte-level Shamir API, but unmaintained
  since 2021 with no audit pedigree. Vendoring it would add the same
  audit surface as writing our own implementation with worse
  ergonomics and no upstream maintenance.
- **`shamirsecretsharing` crate**: a thin C wrapper. Excluded by D0018's
  pure-Rust stance and last touched in 2018.
- **Custom GF(2²⁵⁶) Shamir**: single polynomial over an extension field
  of order 2²⁵⁶. Algebraically viable but no library support exists, the
  field arithmetic is heavier, and the audit story is no better than
  byte-level given there are no published test vectors for this field
  shape.
- **A different existing crate**: surveyed `crates.io` for byte-level
  Shamir alternatives. None are actively maintained, audit-grade, and
  pure Rust at 2026-05. This is an ecosystem gap, not a Cairn-specific
  oversight.
- **Comparable-project precedent**: Signal SVR, Trezor SLIP-0039, Briar
  backup, and Glacier Protocol all implement their own byte-level
  Shamir for similar use cases. The "roll your own crypto" maxim does
  not apply here — these are well-known algorithms in well-understood
  fields, not novel protocol designs.

### 1.4 Decision

**Implement byte-level Shamir directly in `cairn-shamir`.** Landed
2026-05-29 per `metrics.md`.

- ~250 LoC core split across `gf256.rs` (field arithmetic), `share.rs`
  (split / reconstruct / Lagrange interpolation), and `commit.rs` (BLAKE3
  commit-of-secret per D0018 §3.4)
- Field arithmetic validated against FIPS 197 §4.2 GF(2⁸) multiplication
  vectors (`0x53*0xCA=0x01`, `0x57*0x83=0xC1`, `0x57*0x13=0xFE`) — these
  are the same vectors AES implementations use; the field is shared
- 35 tests: 13 GF(2⁸) (incl. FIPS 197 vectors), 6 commitment (incl.
  direct cross-check against `blake3::derive_key`), 14 share-layer
  (incl. exhaustive C(4,3) subset reconstruction, tamper resistance,
  parameter validation, duplicate-id rejection), 2 property tests
  (round-trip + single-bit tamper rejection)
- Structural constant-time discipline: no data-dependent branches, no
  secret-indexed table lookups; multiplication uses
  shift-and-conditional-XOR with bitmask arithmetic
  (`(b & 1).wrapping_neg()` for the all-ones-or-all-zeros mask);
  inversion uses Fermat's little theorem with a fixed schedule of 7
  squarings + 6 multiplications regardless of input
- Empirical constant-time gate via `dudect-bencher` is pending as a
  separate surface per `metrics.md`. The structural argument is sound;
  the empirical gate makes the audit story concrete
- `cairn-shamir` is in the audit scope per D0018 §6 from day one — Cairn
  does not rely on third-party Shamir library audit pedigree

### 1.5 `vsss-rs`'s future role

`vsss-rs` may still be appropriate for **verifiable secret sharing**
(Feldman / Pedersen VSS) per D0006 §6 trust-graph attestations. Those
use cases operate on cryptographic-curve scalars (where attestations
need to be publicly verifiable without revealing the secret) and fit
`vsss-rs`'s `PrimeField` shape.

Action: keep `vsss-rs` in workspace dependencies with a comment noting
the deferred role; do not include in any crate's direct `[dependencies]`
list until that surface lands.

### 1.6 D0018 §3.1 revision

- D0018 §3.1 originally mandated `vsss-rs` for all Shamir use
- This D-doc supersedes D0018 §3.1 for byte-level seed Shamir (the v1
  recovery story)
- A follow-up commit should touch up D0018 §3.1's text inline to point
  at this D-doc and at `cairn-shamir`'s implementation, while preserving
  the future-VSS rationale for keeping the workspace dep

---

## 2. Finding: `coset`'s encoder is non-canonical; decoder role preserved

### 2.1 Evidence

- `CborSerializable::to_vec` and `TaggedCborSerializable::to_tagged_vec`
  in `coset-0.3.8/src/common/mod.rs` delegate to
  `cbor::ser::into_writer(&value, &mut data)` — that's `ciborium`'s
  default encoder.
- `ciborium` does not enforce canonical CBOR by default. This is
  precisely the gap that motivated D0018 §2.3's project-owned canonical
  encoder.
- `ProtectedHeader::cbor_bstr` in `coset-0.3.8/src/header/mod.rs` has a
  three-branch fallback:
  ```rust
  if let Some(original_data) = self.original_data {
      original_data            // ← Preserves bytes on decode→re-emit
  } else if self.is_empty() {
      vec![]                   // ← Canonical for empty
  } else {
      self.to_vec()?           // ← Non-canonical for fresh construction
  }
  ```
- For Cairn's fresh-construction use case (no `original_data`,
  non-empty), this falls through to the non-canonical path.
- The outer 4-tuple emission for `CoseSign1` (`sign/mod.rs`
  `to_cbor_value`) builds a `Value::Array` and passes it to the same
  non-canonical `to_vec` chain.

### 2.2 Why this matters for Cairn

- D0018 §2 + D0006 §3: Cairn requires **deterministic byte production**
  for `COSE_Sign1` because the signature commits to specific bytes. Two
  implementations producing different bytes from the same logical
  inputs cannot interop signatures across the trust graph — a signed
  envelope from device A would fail verification on device B.
- `ciborium`-default encoding is non-deterministic across several axes:
  map key ordering, head-encoding choices (smallest-form not enforced),
  definite-vs-indefinite length container encoding. Any of these can
  produce different bytes for the same logical Value.

### 2.3 Decision

**Canonical encoder = `cairn-envelope::canonical`** (already implemented;
landed 2026-05-29 per `metrics.md`).

- `cairn-envelope::cose_sign1` builds the `Sig_structure` and the outer
  4-tuple via the canonical encoder, never via `coset`'s encoder
- `coset` is retained in workspace dependencies for two distinct roles:
  1. **Decoder for incoming peer envelopes.** Coset's
     `ProtectedHeader::original_data` preservation is structurally
     correct for the decode → re-verify path: the original bytes the
     signer saw are carried through unchanged, so signature verification
     works against the original (potentially non-canonical) signing
     input.
  2. **Reference implementation for `veraison/go-cose` interop
     validation.** When the cross-implementation interop surface lands
     (pending per `metrics.md`), coset becomes the Rust-side reference
     implementation that the Go-side `veraison/go-cose` is compared
     against. Both must agree on the bytes Cairn emits.

### 2.4 D0018 §2.2 role clarification

- D0018 §2.2 originally described `coset` as "CBOR Object Signing and
  Encryption (COSE) library" without distinguishing encode-time vs
  decode-time roles
- This D-doc clarifies: **decoder + interop oracle, not canonical
  encoder**
- The canonical encoder lives in `cairn-envelope::canonical` per D0018
  §2.3 (which remains correct; the gap was in §2.2, not §2.3)
- A follow-up commit should touch up D0018 §2.2's text inline to
  describe the decoder/oracle role explicitly

---

## 3. Hygiene actions

### 3.1 `displaydoc` removal

- D0018 §4.3 originally pinned `displaydoc = "=0.2.5"` alongside
  `thiserror`
- Investigation: zero usage in `cairn-crypto`, `cairn-envelope`, or
  `cairn-shamir` (`grep -rn displaydoc --include="*.rs"` returns
  nothing)
- `thiserror` covers the error-with-Display surface ergonomically; no
  current or planned Cairn module needs `displaydoc`'s markdown-style
  doc-comment derive
- **Action**: Remove `displaydoc` from workspace dependencies. Re-add
  via D-doc if a future surface needs the markdown derive
- This change lands in the same commit as D0021 (since this D-doc
  documents the removal)

### 3.2 `dudect-bencher` pin bump

- D0018 §5.3 pins `dudect-bencher = "=0.6.0"`
- `cargo info dudect-bencher@0.7.0`: declares `rust-version = "1.85"`
  matching our toolchain pin; same author / repo / license / features
  (`core-hint-black-box`)
- `cargo info dudect-bencher@0.6.0`: `rust-version: unknown`
- **Action**: Bump pin to `=0.7.0`
- Per user direction, this is a **separate hygiene commit** from D0021,
  preserving the surgical scope of each commit

---

## 4. Discipline note for future library pins

The `vsss-rs` and `coset` findings share a root cause: D0018 library
pins were chosen by **category** ("Shamir SSS library", "COSE
library") rather than by **verified API surface** ("supports byte-level
GF(2⁸)", "produces canonical CBOR"). The MDC pathway surfaced both
gaps; pure spec work would not have.

For future D-doc library pins in cryptographic-discipline use, the
workflow should include an **API conformance check**:

1. Identify the **one** load-bearing property the library must expose
   for Cairn's use case. Example properties: "deterministic encoding",
   "byte-level GF(2⁸)", "constant-time inverse", "preserves original
   bytes through decode → re-emit cycle".
2. Quote the specific method signature from the library that exposes
   that property, by file path + line number.
3. If no such method exists, **do not pin the library**. Either pick a
   different one, or write a focused implementation and document the
   choice.

This is a process change, not a tooling change. The MDC pathway
(working code before partner conversations) is the natural mechanism
for surfacing these gaps. D-docs that pin libraries without working
implementations are **aspirational architecture**, not **validated
architecture** — both have a place, but they should be labeled
distinctly in the D-doc workflow.

A small further check: when a D-doc revision like this one supersedes a
prior pin, the workspace `Cargo.toml` should retain a comment block at
each affected dependency pointing to the revising D-doc, so future
contributors see the trail without having to grep through the
decisions/ directory.

---

## 5. Cross-references

- **D0006** §3 (envelope structure), §6 (trust-graph attestations), §9
  (capability tokens) — informs the byte-level Shamir + canonical CBOR
  requirements that exposed these gaps
- **D0018** §1 (crypto primitives), §2.2 (CBOR/COSE libraries), §2.3
  (canonical encoder), §3.1 (Shamir library), §3.4 (commit-of-secret),
  §4.3 (logging discipline), §5.3 (constant-time benchmarking), §6
  (audit-target scope) — surfaces revised by this D-doc
- **D0020** §3.7 (`NeverExport` discipline) — the `cairn-shamir::Share`
  type's `Zeroizing<[u8; SECRET_LEN]>` payload field is in the secret-
  bearing types catalog
- **`metrics.md`** 2026-05-29 entries for `cairn-envelope` (canonical
  CBOR + COSE_Sign1) and `cairn-shamir` (skeleton + GF(2⁸) Shamir +
  BLAKE3 commit) — implementation evidence for both findings

---

## 6. Implementation status

| Action                                                   | Status                          | Location                                                |
| -------------------------------------------------------- | ------------------------------- | ------------------------------------------------------- |
| Byte-level GF(2⁸) Shamir implementation                  | Complete                        | `crates/cairn-shamir/src/{gf256,share,commit}.rs`       |
| Canonical CBOR encoder                                   | Complete                        | `crates/cairn-envelope/src/canonical.rs`                |
| `COSE_Sign1` construction via canonical encoder          | Complete                        | `crates/cairn-envelope/src/cose_sign1.rs`               |
| `displaydoc` removed from workspace deps                 | Edit applied; commit with D0021 | `Cargo.toml` `[workspace.dependencies]`                 |
| `dudect-bencher` 0.6.0 → 0.7.0                           | Edit applied; commit separately | `Cargo.toml` `[workspace.dependencies]`                 |
| `vsss-rs` retained with deferred-role comment            | Pending                         | `Cargo.toml` (update during D0018 §3.1 inline touch-up) |
| D0018 §2.2 text inline touch-up (coset role)             | Pending                         | `docs/decisions/D0018-engineering-foundation.md`        |
| D0018 §3.1 text inline touch-up (vsss-rs supersession)   | Pending                         | `docs/decisions/D0018-engineering-foundation.md`        |
| D0018 §4.3 text inline touch-up (`displaydoc` removed)   | Pending                         | `docs/decisions/D0018-engineering-foundation.md`        |
| D0018 §5.3 text inline touch-up (`dudect-bencher` 0.7.0) | Pending                         | `docs/decisions/D0018-engineering-foundation.md`        |
| `cairn-shamir` `dudect-bencher` constant-time gate       | Pending separate surface        | `metrics.md` Tier 1 MDC milestone                       |
| `veraison/go-cose` interop validation surface            | Pending separate surface        | `metrics.md` Tier 1 MDC milestone                       |
