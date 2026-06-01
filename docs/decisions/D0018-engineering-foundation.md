# D0018 — Engineering foundation: cryptographic library selections, Rust ecosystem discipline, and Cargo workspace baseline for v1 implementation

**Status:** Accepted
**Date:** 2026-05-29

## Context

Q8 in [open-questions.md](../open-questions.md) named library selection for cryptographic primitives as a question requiring resolution before v1 implementation begins. Sprint 3 of the consolidated external-reads triage (per `docs/reviews/external-reads-consolidated.md`) committed to resolving this as the first engineering decision under the MDC (Minimum Demoable Capability) pathway: working code first, then partner conversations against code-as-evidence.

Seven research agents with web-search access were dispatched on 2026-05-29 to investigate current state-of-the-art across:

1. Rust cryptographic primitives (Ed25519, X25519, HKDF, AEAD, SHA, memory hygiene, CSPRNG)
2. CBOR + COSE in Rust (ciborium, coset; deterministic encoding correctness)
3. Shamir Secret Sharing libraries (vsss-rs vs alternatives; constant-time properties)
4. Tor + arti on Android (production-readiness for embedded use)
5. SimpleX integration approaches
6. Rust ecosystem cross-cutting (async, error handling, logging, testing, fuzzing, supply chain)
7. UniFFI + Android crypto bindings (StrongBox integration; FFI patterns)

This decision document captures the library and ecosystem decisions. Integration architectures (SimpleX, Tor, FFI hybrid) are documented separately in [D0020](D0020-integration-architecture.md). License decision (AGPL-3.0-only) is documented separately in [D0019](D0019-license.md).

### Empirical-metrics framing per consolidated triage

Per the consolidated external-reads triage's empirical-metrics commitment, this decision document specifies **library and version pinning**, **discipline commitments**, and **workspace baseline structure** — but does **NOT** specify calendar-time estimates for implementation. Calendar-time projections are explicitly empirical from this point forward: actual elapsed development time against these specifications produces baseline cadence data, and that data calibrates subsequent projections rather than borrowed-from-comparable-project estimates.

## Decision

**Adopt the RustCrypto-stack library selections matching libsignal and vodozemac production versions, the operational discipline framework documented below, and the Cargo workspace baseline specified in this decision.** Pin specific crate versions; treat upgrades as non-trivial events requiring lockstep migration across the dependency graph.

The decision is partitioned into nine sections:

1. Cryptographic primitives (Ed25519, X25519, HKDF, AEAD, SHA, memory hygiene, CSPRNG)
2. Encoding primitives (CBOR, COSE) plus the canonical encoding helper specification
3. Shamir Secret Sharing
4. Cross-cutting Rust ecosystem decisions (async, error handling, logging)
5. Testing and verification (property-based testing, fuzzing, constant-time verification)
6. Supply chain security (cargo audit, deny, geiger, machete, auditable)
7. Build and cross-compile for Android
8. Cargo workspace baseline (workspace.toml, clippy.toml, rustfmt.toml, deny.toml, CI workflow)
9. Operational commitments

Each section names specific decisions with rationale. Alternatives considered and "what would change this recommendation" caveats are documented per major decision.

---

## 1. Cryptographic primitives

### 1.1 Ed25519 signing: `ed25519-dalek` 2.2.0

- **Crate**: `ed25519-dalek`
- **Version**: 2.2.0 (released 2025-07-09)
- **Maintainer**: dalek-cryptography
- **License**: BSD-3-Clause
- **Audit**: Quarkslab 2019; libsignal + vodozemac production validation

**Rationale.** Pure-Rust pairs natively with `x25519-dalek` sharing the audited `curve25519-dalek` field arithmetic; this is the only stack where one library and one timing-variability fix covers both signing and ECDH. `SigningKey::from_bytes` accepts the 32-byte seed per RFC 8032 §5.1.5 — exactly what Shamir reconstruction produces (per [D0006](D0006-cryptographic-envelope.md) §9 capability-token construction). Splits the seed (not the derived scalar) preserves Ed25519's deterministic nonce contract.

**Constant-time properties.** `SigningKey` automatically zeroizes on drop with default `zeroize` feature. `verify_strict` defends against signature malleability and small-subgroup attacks. RUSTSEC-2024-0344 (curve25519-dalek `Scalar29::sub`/`Scalar52::sub` timing variability) fixed in `curve25519-dalek` 4.1.3; `ed25519-dalek` 2.2.0 pulls 4.1.3+.

**Critical: do not adopt 3.0.0-rc.0** (2026-05-28) until a stable 3.0.0 release ships and downstream Rust security-critical projects (libsignal, vodozemac) migrate. The 3.0 series bumps MSRV to 1.85 and edition to 2024 but is otherwise a continuation of the 2.x API. There is no security urgency to upgrade.

**Alternatives considered.** `ring` (BoringSSL bindings; in low-key maintenance per Brian Smith's own discussion); `ed25519-zebra` (Zcash Foundation; consensus-critical for Zcash; no public audit); `aws-lc-rs` (AWS-LC; FIPS 140-3 path; Android cross-compile issues per aws-lc-rs#918). Each is defensible; `ed25519-dalek` is selected on ecosystem-coherence grounds (libsignal/vodozemac/Wire all use it).

**What would change this recommendation.** (a) FIPS compliance becomes a hard product requirement → switch to `aws-lc-rs`. (b) A CVE in `curve25519-dalek` 4.x affecting non-Scalar-sub paths → re-evaluate against `ed25519-zebra`. (c) `ed25519-dalek` 3.0.0 stable ships and libsignal migrates → schedule a coordinated upgrade.

### 1.2 X25519 ECDH: `x25519-dalek` 2.0.1

- **Crate**: `x25519-dalek`
- **Version**: 2.0.1 (released 2024-02-07; stable since)
- **License**: BSD-3-Clause

**Rationale.** Shares `curve25519-dalek` with `ed25519-dalek` — single audit surface, single timing-fix cadence. The `EphemeralSecret`/`StaticSecret`/`ReusableSecret` distinction encodes nonce-reuse and key-reuse boundaries in the type system, helping prevent misuse.

**Critical usage discipline.** `SharedSecret::was_contributory()` MUST be called after every ECDH and the agreement rejected if false. The vodozemac 2026 audit (Soatok blog Feb 2026) showed even Matrix's mature E2EE code failed to call this check. **This is a project-wide discipline commitment**: every X25519 call site must invoke `was_contributory()` and reject zero-result agreements. The CI grep gate per section 5.3 enforces this.

**Alternatives considered.** `ring` X25519 (consistent only if Ed25519 also `ring`-based; rejected per 1.1); `aws-lc-rs` X25519 (FIPS path; rejected per 1.1 reasoning).

**What would change this recommendation.** Stable `x25519-dalek` 3.0.0 ships and Cairn's MSRV catches up to 1.85; likely worth upgrading once both true.

### 1.3 HKDF: `hkdf` 0.12.4

- **Crate**: `hkdf` (RustCrypto/KDFs)
- **Version**: 0.12.4 (matches libsignal/vodozemac pin)
- **License**: MIT OR Apache-2.0

**Rationale.** Generic over `Digest`; pairs with `sha2` 0.10.x stack. libsignal still uses `hkdf = "0.12"` and `sha2 = "0.10"` as of May 2026 — there is no urgency to lead the migration to 0.13. The HKDF construction itself is structurally trivial (extract + expand around HMAC); library quality reduces to the HMAC and SHA-2 implementations underneath, which are well-audited.

**Coordinated migration to 0.13.0.** When libsignal and vodozemac migrate to `hkdf 0.13` + `sha2 0.11` + `hmac 0.13` + MSRV 1.85, Cairn migrates in lockstep as a single coordinated step. Until then, stay pinned.

**Alternatives considered.** `ring` HKDF (consistent only if rest of stack `ring`-based; rejected per 1.1 reasoning).

### 1.4 AEAD: `chacha20poly1305` 0.10.1 (XChaCha20-Poly1305 variant)

- **Crate**: `chacha20poly1305` (RustCrypto/AEADs)
- **Version**: 0.10.1 (released 2022-08-09; production-stable)
- **Variant used**: `XChaCha20Poly1305` (192-bit nonce)
- **Audit**: NCC Group 2020 (MobileCoin-funded)

**Rationale.** XChaCha20-Poly1305's 192-bit nonce eliminates practical collision risk at any message volume Cairn will encounter (~2^96 messages before a single expected collision under random-nonce sampling). The constant-time properties are inherent to the ChaCha20/Poly1305 design rather than dependent on hardware AES-NI availability — important on Android where AES-NI presence is heterogeneous and constant-time AES software fallbacks are rare. The "stale" 2022 release date is a feature, not a bug: the audited primitive has had nearly four years of production use without incident.

**Why XChaCha20 over standard ChaCha20.** Standard ChaCha20-Poly1305 uses 96-bit nonces; nonce uniqueness must be tracked per-key. Cairn's at-rest storage encryption may re-encrypt the same logical object under the same key during recovery scenarios; the 192-bit nonce makes random-nonce collision negligible without requiring counter discipline.

**Why not AES-GCM-SIV.** True nonce-misuse resistance is the formally correct choice for at-rest storage where nonce-derivation may genuinely repeat. The `aes-gcm-siv` crate (0.11.1, 2022-07-31) is functionally appropriate, but has no direct cryptographic audit — only audits of its `aes-gcm` dependency. The 192-bit nonce of XChaCha20 covers the operational case Cairn faces; AES-GCM-SIV's formal misuse-resistance is over-specified for the threat. If at-rest nonce-derivation later becomes structurally problematic, switching to `aes-gcm-siv` is a candidate change.

**Why not AEGIS or Deoxys-II.** `aegis` is misleading marketing per libsodium's own warnings (nonce reuse under a given key allows state recovery — NOT misuse-resistant despite 256-bit nonce). `deoxys` is cryptographically clean (CAESAR portfolio) but the Rust crate has no constant-time guarantees per its own documentation. Neither has the audit pedigree the threat model requires.

**Alternatives considered.** `ring` ChaCha20-Poly1305 (consistent only if rest of stack `ring`-based); `aes-gcm` (no nonce-misuse resistance; nonce uniqueness discipline burden); `aes-gcm-siv` (no direct audit); `aegis` (rejected on nonce-reuse-state-recovery grounds); `deoxys` (no constant-time guarantee in Rust).

### 1.5 SHA-2: `sha2` 0.10.9

- **Crate**: `sha2` (RustCrypto/hashes)
- **Version**: 0.10.9 (matches libsignal/vodozemac pin)
- **License**: MIT OR Apache-2.0

**Rationale.** SHA-256 and SHA-512 are required: trust-graph Ed25519 signing uses SHA-512 internally per RFC 8032; HKDF derivation per 1.3; `prior_hash` and `issuer_cert_hash` per D0006 §§5,7 use SHA-256. The `sha2` crate's aarch64 SHA-NI intrinsic backend matters specifically on Android: Pixel/Snapdragon/Tensor SoCs from 2018+ all support ARMv8.2 SHA instructions, giving hardware-accelerated hashing without sacrificing the pure-Rust audit story. Coordinated migration to 0.11.0 happens alongside the `hkdf` 0.13 migration.

**Why not BLAKE3 as primary.** Faster but lacks the decades of SHA-2 cryptanalysis pedigree, has no FIPS path until 2028 per NIST's January 2026 announcement, and would add a separate audit dependency. Reserve BLAKE3 for non-security-critical content-addressing if needed at all — and even there, the audit-cost of justifying its use is rarely worth the performance gain at messaging cadence.

**Specific BLAKE3 use case Cairn DOES adopt.** Per the Shamir research and the Cure53 Privy audit recommendation, a 32-byte BLAKE3 commit-of-secret stored alongside (not inside) each Shamir share lets reconstruction detect tampering without changing the Shamir scheme. This is a single specific use of BLAKE3 in `cairn-shamir`; not a general project-wide hash choice. The `blake3` crate version: 1.8.5 (April 2026) or newer.

### 1.6 Memory hygiene: `zeroize` 1.8.2 + `secrecy` 0.10.3 + `subtle` 2.6.1

- **Crates**: `zeroize` 1.8.2, `secrecy` 0.10.3, `subtle` 2.6.1
- **License**: each is MIT OR Apache-2.0 or equivalent permissive

**Rationale.** These three are the de-facto-standard Rust memory-hygiene primitives, present in libsignal, vodozemac, every dalek crate, and effectively every audited Rust crypto library. No better-maintained alternative has emerged.

**Honest acknowledgment of limitations per consolidated triage C12.** Per `docs/design-brief.md` §5.1 (post-Sprint 1 update), `zeroize` does NOT defeat all forensic-extraction scenarios. Specifically:

- LLVM may spill secret bytes to caller-save registers or stack slots that `zeroize` cannot reach (stack-spill copies and intermediate registers)
- Rust executes `Drop` only on the location where a value resides at scope exit; values that moved leave the source slot stale (Move-aware Drop limitation)
- `mlock`/`mlockall` can fail silently on Android with `RLIMIT_MEMLOCK` (typically restrictive; check return value)
- Hardware-level cache lines containing the secret (`zeroize` does not reach these)
- Compiler-introduced copies elsewhere in memory (the `volatile_write` `zeroize` performs covers one address only)
- No coverage for memory page swap or core dumps before scope exit

The discipline accepts these limitations and bounds them through:

- Time-boundary (sub-second wall-clock duration for reconstruction window)
- Space-boundary (recovery happens on fresh device acquired specifically for the purpose, not on a device that may already host a forensic implant)
- Process-boundary (per D0009 panic = "abort" in release; no unwind-on-panic copies of stack frames)
- Documentation (every secret-handling module top-of-file comment names these limitations)

This is a defense-in-depth measure, not a guarantee. The brief's §5.1 language now correctly characterizes this.

**Specific commitments:**

- `#[derive(ZeroizeOnDrop)]` on every type holding key/seed bytes
- `secrecy::SecretBox<T>` for all API-boundary secret material
- `subtle::ConstantTimeEq` and `ConditionallySelectable` for all comparison and conditional-select operations on key material
- Never write `==` on a secret type; the type system + custom clippy lint per section 8 makes this a compile error or CI-failure pattern

### 1.7 CSPRNG: `getrandom` 0.4.2

- **Crate**: `getrandom`
- **Version**: 0.4.2 (released 2026-03-03)
- **License**: MIT OR Apache-2.0

**Rationale.** Stateless OS-syscall wrapper. On Android, `linux_getrandom` backend bumps minimum API level to 23 (Marshmallow); Cairn's `aarch64` and `x86_64` targets support this trivially. All CSPRNG output should come directly from the OS source; routing all randomness through this single point makes the audit story tractable.

**Critical usage discipline.** Never use `thread_rng()` or `SmallRng` for key generation. The `CryptoRng` marker trait (`rand_core::CryptoRng`) is the type-system gate; require it on all key-generation function signatures.

**For Shamir splitting specifically.** Call `OsRng`/`SysRng` directly inside the splitting function. Do NOT accept an RNG parameter from the caller — that creates a deterministic-RNG injection vector that a hostile UniFFI binding could exploit.

**What would change this recommendation.** (a) Android API-level bump that drops support for current `getrandom` backends; (b) A finding that the Linux `getrandom(2)` syscall has a flaw at the kernel level (affects all stacks equally).

---

## 2. Encoding primitives + canonical encoding helper

### 2.1 CBOR: `ciborium` 0.2.2 (pinned `=0.2.2`)

- **Crate**: `ciborium`
- **Version**: `=0.2.2` (exact pin)
- **License**: MIT OR Apache-2.0

**Rationale.** Production-grade CBOR encoder/decoder; 438 reverse dependencies on crates.io including `blake3`, `criterion`, `aws-smithy-types`. RFC 8949 §4.2.1 conformance per integer-width minimization, float minimization, definite-length encoding — verified against source review.

**Critical gap: ciborium does NOT sort map keys.** Open issue [enarx/ciborium#154](https://github.com/enarx/ciborium/issues/154) confirms this is documented design intent. `Value::Map` is `Vec<(Value, Value)>` to preserve wire order; `serialize_map` emits in iteration order. This is the principal correctness gap relative to a strict deterministic encoder, and Cairn closes it in the `cairn-cbor-canonical` helper per section 2.3.

**Why pin to `=0.2.2`** (exact version, not semver range). Unpublished main-branch work has had refactors that could subtly change byte-on-wire output; locking the version locks the byte-level encoder behavior. Upgrade to a later version is a coordinated change requiring re-validation of test-vector cross-implementation byte-identity per section 2.4.

### 2.2 COSE: `coset` 0.4.2 (pinned `=0.4.2`)

- **Crate**: `coset`
- **Version**: `=0.4.2` (exact pin; released 2026-03-02)
- **Maintainer**: Google
- **License**: Apache-2.0

**Rationale.** Best-maintained Rust COSE library; healthy maintenance cadence; large test suite at `sign/tests.rs` (61KB). Correctly constructs `Sig_structure` per RFC 9052 §4.4. Verifies the empty-protected-header case correctly (emits `h''` zero-length bstr per RFC 9052 §3 SHOULD; accepts both `h''` and `h'a0'` on parse).

**Critical gap: `Header::to_cbor_value` does NOT sort `rest` (custom) header parameters.** Well-known headers (alg, crit, content_type, kid, iv, partial_iv, counter_signature; labels 1-7) happen to emit in numerical-label order which coincides with bytewise lex sort for those values. But anything in `rest: Vec<(Label, Value)>` is in insertion order. Cairn closes this gap by building the protected header bytes manually via the `cairn-cbor-canonical` helper per section 2.3, then passing through `ProtectedHeader { original_data: Some(bytes), header }` to use coset's verbatim-preservation path.

**Coset's role in Cairn (per D0021 §2):** coset is retained for two roles distinct from canonical encoding:

1. **Decoder for incoming peer envelopes.** `ProtectedHeader::original_data` preservation in `coset-0.4.2/src/header/mod.rs::cbor_bstr` carries the bytes the signer originally saw through the decode → re-verify path; signature verification works against the original (potentially non-canonical) signing input.
2. **Reference implementation for `veraison/go-cose` interop validation.** The cross-implementation interop surface (pending per `metrics.md`) compares coset's parse of Cairn's emitted bytes against `veraison/go-cose`'s parse; both must agree.

The canonical encoder for emit-side bytes remains `cairn-envelope::canonical` per section 2.3. `cairn-envelope::cose_sign1` builds the `Sig_structure` and the outer 4-tuple via that canonical encoder, never via `coset::CborSerializable::to_vec` (which delegates to `ciborium`'s non-canonical default — re-confirmed against 0.4.2 in D0021 §2.1).

**Tag confirmation per D0006 §6.** `CoseSign1::TAG = 18` per IANA CBOR Tags registry (verified via docs.rs). Cairn uses **untagged** form: `CoseSign1::to_vec()` and `from_slice()`. Tag 98 (COSE_Sign multi-signer) is NOT used.

**External-signer path (added 2026-06-01, for hardware-resident device keys).** `cairn-envelope::cose_sign1::Sign1Builder` exposes `signing_input()` (the canonical `Sig_structure` bytes per RFC 9052 §4.4) + `finalize_with_signature(sig)` (assemble the `COSE_Sign1` from an externally-produced 64-byte Ed25519 signature) alongside the in-process `finalize(&SigningKey)`. This lets a device key that never enters the process — an Android StrongBox key per D0020 §3.4 / D0006 §9 — sign the `Sig_structure` in hardware while the envelope is built + assembled in Rust; only the signature crosses back. `finalize` is reimplemented as `signing_input` + an in-process Ed25519 sign + `finalize_with_signature`, so all three paths are byte-identical by construction (regression-tested in `external_signer_path_matches_finalize`). `cairn-simplex-adapter`'s `EnvelopeSigner` (D0026 §2.3) is the first consumer; the trust-graph / capability-token / release-manifest signers continue to use `finalize` unchanged.

### 2.3 Canonical encoding helper: `cairn-cbor-canonical`

Both `ciborium` and `coset` have gaps relative to strict cross-implementation determinism. Cairn writes a project-owned `cairn-cbor-canonical` helper module per the consolidated triage CBOR/COSE research. The helper is part of the `cairn-envelope` crate and is the audit-target surface per D0011 pre-pilot audit scope.

**`cairn-cbor-canonical` specification:**

- **Map keys sorted by bytewise lex of encoded key bytes at every nesting level.** Recursive sort: encode each key with deterministic-CBOR; sort entries by encoded-key byte sequence; emit definite-length map header for `len(pairs)`; for each (sorted) entry emit `cbor_encode(key)` + `canonical_encode(value)`.
- **Floats forbidden in the schema.** Cairn's signed-operation envelope does not include floats. The encoder refuses to encode `f32` or `f64` values; the decoder rejects float-type CBOR items in signature-input path.
- **Bignums forbidden in the schema.** Integers limited to `±2^63 - 1` (signed) or `2^64 - 1` (unsigned); no CBOR tag 2 / tag 3 bignum encoding.
- **Indefinite-length items refused on decode** in signature-input path. Encoder never emits indefinite-length items (would be invalid per RFC 8949 §4.2.1 anyway).
- **Protected header built manually** rather than via `coset::HeaderBuilder` + `protected()`. Pattern:

```rust
fn encode_protected_header(header: &Header) -> Vec<u8> {
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = header.iter()
        .map(|(label, value)| (
            canonical_encode_key(label),
            canonical_encode_value(value),
        ))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    // Emit definite-length map header
    let mut out = Vec::new();
    write_map_header(&mut out, pairs.len());
    for (k, v) in pairs {
        out.extend_from_slice(&k);
        out.extend_from_slice(&v);
    }
    out
}
```

Then pass to coset via:

```rust
let protected_bytes = encode_protected_header(&header);
let protected = ProtectedHeader {
    original_data: Some(protected_bytes),
    header: parsed_header,
};
```

This bypasses coset's internal ordering and gives Cairn full control over the bytes that go into `Sig_structure`.

- **Empty protected header**: emit as `h''` (zero-length bstr) per RFC 9052 §3 SHOULD; never `h'a0'` (empty CBOR map encoded as bstr). Verifiers per spec accept either; senders per Cairn spec emit `h''`.

- **`Sig_structure` form per D0006 §6**: `[ "Signature1", body_protected: bstr, external_aad: bstr, payload: bstr ]` encoded with deterministic-CBOR; signed bytes are the deterministic-CBOR encoding of this synthetic structure.

- **`external_aad` domain separation per D0006 §8**: UTF-8 byte strings `"cairn-v1-capability-token"` or `"cairn-v1-trust-graph-operation"`.

- **`prior_hash` per D0006 §5**: `SHA-256(COSE_Sign1.signature_bytes(prior_operation))` — hashes the 64-byte Ed25519 signature bytes of the prior operation, not the prior operation's payload or full envelope.

- **`issuer_cert_hash` per D0006 §7**: `SHA-256(canonical_encode(master_attestation.Sig_structure))`.

**Engineering scope estimate (per surface-completion language):** `cairn-cbor-canonical` is complete when it produces byte-identical output to `veraison/go-cose` (Go reference per section 2.4) for the test-vector corpus per section 2.4, including the protected-header canonicalization, Sig_structure construction, and prior_hash / issuer_cert_hash byte input. No calendar projection per the empirical-metrics framing.

### 2.4 Test-vector strategy and cross-implementation oracle

**Reference implementation: `veraison/go-cose` v1.3.0+** (Go; only COSE implementation with rigorous deterministic CI; uses `fxamacker/cbor` with `Sort: cbor.SortCoreDeterministic + IndefLength: cbor.IndefLengthForbidden + DupMapKey: cbor.DupMapKeyEnforcedAPF`). Cairn's `cairn-cbor-canonical` output is validated byte-identical against go-cose for the same logical inputs.

**Secondary references:** `pycose` (Python; widely used in academic/IETF audit contexts); `laurencelundblade/t_cose` (C; embedded-focused; Sign1 specifically).

**Test-vector format:** Cairn-internal JSON files at `crates/cairn-envelope/tests/vectors/` with per-field hex of every intermediate:

```json
{
  "name": "trust-graph-operation-001",
  "domain_separation_tag": "cairn-v1-trust-graph-operation",
  "signing_key_seed_hex": "...",
  "protected_header_cbor_hex": "...",
  "unprotected_header_cbor_hex": "a0",
  "payload_cbor_hex": "...",
  "external_aad_hex": "636169726e2d76312d74727573742d67726170682d6f7065726174696f6e",
  "sig_structure_cbor_hex": "...",
  "signature_hex": "...",
  "envelope_cbor_hex": "...",
  "prior_operation_signature_hex": "...",
  "expected_prior_hash_hex": "..."
}
```

A failing test points exactly at which step diverges; this is what makes cross-implementer interoperability tractable to debug.

**Anchor sources:** RFC 9052 Appendix C.2 (Sign1 worked examples); `cose-wg/Examples` repository (`sign1-tests/`, `eddsa-examples/`); `gluecose/test-vectors` JSON CDDL-schema'd suite.

### 2.5 RFC 9338 countersignatures: explicit non-use

Cairn's device-key cosignature per D0006 §9 is an **explicit chain** structure (device-key-signature → capability-token (signed by operational identity) → operational-identity-signature → master-attestation), NOT RFC 9338 header-embedded countersignatures. This decision avoids the single-vs-multiple counter-signature encoding interop hazard between major COSE implementations. The architecture document and D0006 §9 both name this explicitly.

---

## 3. Shamir Secret Sharing

### 3.1 Primary: `vsss-rs` 5.4.0

- **Crate**: `vsss-rs`
- **Version**: 5.4.0 (commit `e5756a4` "address audit findings", 2026-04-24)
- **Maintainer**: Michael Lodder (`mikelodder7`)
- **License**: Apache-2.0 OR MIT

**Rationale.** `Gf256::mul` is constant-time Russian-peasant carryless multiply (no lookup tables; source `src/gf256.rs:681-693`). `Gf256` implements `subtle::ConstantTimeEq` + `ConditionallySelectable` + `zeroize::DefaultIsZeroes`. `Gf256::invert` uses Fermat's-little-theorem (self^254) without branches. README states "All operations are constant time unless explicitly noted." Direct support for GF(256) byte-wise threshold scheme via `Gf256` field + `shamir::split_secret` API.

**Audit-findings-addressed commit (April 24, 2026).** Three specific bugs fixed:

- Audit finding #1: biased polynomial coefficients — `Field::random` now uniformly samples [0, 255] including zero (post-Fordefi 2024 consensus per Privy's January 2025 blog reversing Cure53's earlier position)
- Audit finding #2: biased random Gf256 sampler
- Audit finding #3: saturating-add identifier overflow producing duplicate x-coordinates (now `field_bounded_add`)

**Residual risk: audit firm name and full report not yet public.** The April 24 commit references audit findings but the upstream publication has not landed. **This makes D0011's Sprint 1 addition (Shamir-library timing-safety verification in pre-pilot audit scope) the public record for this code path** if upstream firm publication is still missing at Cairn's audit kickoff.

**Implementation-phase confirmation (per D0021).** The D0021 library-pin audit confirms this primary `vsss-rs` 5.4.0 decision. During the implementation phase the workspace `Cargo.toml` briefly drifted to `vsss-rs` 4.3.8, which lacks the `Gf256` byte-level module; an earlier D0021 draft (commit `5b2161b`) misattributed the gap to library inadequacy and justified a from-scratch implementation (commit `2ad574f`). The drift was caught during the inline touch-ups for this D-doc, `Cargo.toml` was bumped to 5.4.0 (commit `b543241`), and `cairn-shamir` was refactored to wrap `vsss-rs::Gf256` (commit `56a825d`) as originally specified here. The audit-discipline lesson is recorded in D0021 §4.

### 3.2 Backup: vendor `oxidecomputer/omicron/trust-quorum/gfss`

If `vsss-rs` does not publish the audit firm name + report by Cairn's pre-pilot audit kickoff (per D0011 Phase B funding event), the backup approach is to vendor `oxidecomputer/omicron/trust-quorum/gfss` (MPL-2.0; file-level copyleft is consumable from AGPL-3.0 Cairn).

**Why backup-only (not primary).** `trust-quorum/gfss::SecretShares` already wraps the share vec in `secrecy::SecretBox`, which is not what Cairn wants — Cairn's protocol distributes shares in plaintext over already-established secure channels (peer recovery via SimpleX; paper shares printed for physical storage). The reconstructed SECRET should be in `SecretBox`; the shares themselves are about to leave the device.

**Adaptation required.** If activated as backup, vendor the `gfss/src/` directory under `crates/cairn-shamir/vendor/gfss/` with provenance documentation; expose Cairn's own `Share` type wrapping `Gf256` without `SecretBox`-wrapping at the share level; preserve all constant-time properties and zeroization.

### 3.3 Reference standard: `dsprenkels/sss-rs`

`dsprenkels/sss-rs` (v0.1.7, October 2025) is **explicitly cited by Cure53 PVY-01-003 as the reference cache-side-channel-resistant GF(256) implementation.** Cairn does not use this library directly (the C-backed wrapper has less clean `zeroize` integration than `vsss-rs`), but the project's cross-implementation test vectors validate Cairn's reconstruction against this reference for canonical-GF(256) correctness.

### 3.4 BLAKE3 commit-of-secret alongside shares

Per the Cure53 Privy audit recommendation (page 13): "detection of potentially dishonest parties... using a collision-resistant hash function for the purpose of generating a validation check for the reconstructed secret." A 32-byte BLAKE3 of the master seed stored alongside each share (NOT inside the share, so it cannot be tampered to validate a wrong reconstruction).

**Specification:** at provisioning, compute `commit = BLAKE3(seed_32_bytes)` (32-byte output). Distribute `(share_i, commit)` to each peer. At reconstruction, after combining 3-of-5 shares to reconstruct `seed'`, verify `BLAKE3(seed') == commit`. If mismatch: at least one share was tampered; reconstruction is rejected without exposing which share or which byte position.

**Implementation:** in `cairn-shamir`. Uses the `blake3` crate (1.8.5+) for this specific operation only; this is the single justified use of BLAKE3 in Cairn (per section 1.5).

### 3.5 Atomic-or-non-leaking semantics per D0005

Per D0005 (post-Sprint 1 update), the master re-split is atomic with respect to the master's lifetime:

- Reconstructed seed held in `secrecy::SecretBox<[u8; 32]>` across the full re-split-and-distribute operation
- All N peers receive new shares before any zeroize step fires
- On partial failure: master is zeroized, new-share fragments are discarded by peers via re-split-failed signal, recovery is treated as failed-but-non-leaking
- New operational identity signed by master only after re-split succeeds across all N peers

**No library provides this orchestration.** `cairn-shamir` exposes the primitive operations (`split_secret`, `combine_shares`); the atomic-re-split orchestration is in `cairn-recovery`. Both `vsss-rs` and `trust-quorum/gfss` APIs are compatible with this pattern.

### 3.6 Constant-time verification: `dudect-bencher` CI gate

Per section 5.3, Cairn's CI runs `dudect-bencher` against release-profile builds for the Shamir reconstruction and Ed25519 signing surfaces. The CI gate asserts t-statistic stays below 4.5 over 10⁶ iterations. This is the operational answer to the Sprint 1 C15 finding (Shamir-library timing-safety verification).

---

## 4. Cross-cutting Rust ecosystem decisions

### 4.1 Async pattern: synchronous core; tokio at I/O surface only

**Decision.** Cryptographic core crates (`cairn-crypto`, `cairn-envelope`, `cairn-shamir`, `cairn-identity`, `cairn-trust-graph`, `cairn-recovery`, `cairn-storage`) are **synchronous**. The async runtime (`tokio` 1.51.x LTS) is reserved for I/O surface only (`cairn-tor-transport`, `cairn-simplex-adapter`, `cairn-sigsum-client`, `cairn-sigstore-verify`).

**Rationale.** Crypto operations are CPU-bound and sub-second; they do not benefit from async. Async introduces cancel-safety hazards: standard async Rust has no async drop; dropping a future stops it instantly mid-state, leaving partial cryptographic state in heap allocations until the wrapper's Drop runs. The recommended pattern is to perform crypto under `spawn_blocking` (or `rayon::spawn`) into a task that cannot be cancelled mid-operation and signal the result back. Tokio's own documentation states `spawn_blocking` is "poorly suited for expensive CPU-bound computations"; for those use `rayon` or a dedicated thread.

**Implementation pattern at the boundary.**

```rust
// In an async I/O context that needs to call sync crypto:
let result = tokio::task::spawn_blocking(move || {
    // Sync crypto operations here; cannot be cancelled mid-operation
    cairn_envelope::sign(&payload, &operational_identity)
}).await?;
```

**`async-std` is discontinued** (March 2025). Do not adopt. Smol is acceptable for `no_std` contexts (relevant only if v2 USB form factor work materializes); not relevant for v1 Android.

### 4.2 Error handling: `thiserror` 2.0 for library; `anyhow` 1.x for application

**Decision.** Library crates (Rust core; everything called via UniFFI) use `thiserror` 2.0.x with structured `enum`s per subsystem. Application code (CLI tooling; internal main binary; tests) uses `anyhow` 1.x with `.context(...)` for audit trail.

**Critical discipline: NO raw byte payloads in error variants.** Errors carry indices, lengths, and type tags only:

```rust
#[derive(thiserror::Error, Debug)]
pub enum EnvelopeError {
    #[error("ciphertext too short: got {got} bytes, need at least {min}")]
    Truncated { got: usize, min: usize },
    #[error("AEAD authentication failed (tag mismatch)")]
    AuthFail,           // NO inner bytes
    #[error("malformed COSE header at field {0}")]
    BadHeader(&'static str),
    #[error("invalid Shamir share count: got {got}, threshold {threshold}")]
    InsufficientShares { got: usize, threshold: usize },
}
```

**Why this matters.** Default `Debug`/`Display` derivations expose anything `?`-formatted. A `Vec<u8>` or `&[u8]` in an error variant becomes a secret-leak vector through error-propagation logs. The discipline prevents this structurally rather than relying on log-level discipline alone.

**Enforcement.** Per section 5.4, CI grep gate rejects PRs that add `Vec<u8>` or `&[u8]` to error variants. The libsignal issue #659 recommendation ("change occurrences from `&[u8]` to `&[u8; KNOWN_SIZE]` ... or preferably a higher-level wrapper type, such as by exposing the types from dalek-crypto, as they also provide a good zeroization strategy") is the project-wide principle.

**`From`-conversions** only from types whose `Display` is known-safe. Wrap third-party errors that may stringify input bytes — convert them at the boundary to an opaque variant.

### 4.3 Logging: `log` 0.4 facade in libraries; `tracing` 0.1 in application

**Decision.** Library crates depend on `log` 0.4 (facade only — no subscriber). Application binary uses `tracing` 0.1.x + `tracing-subscriber` 0.3.x.

**Critical structural defense: `release_max_level_info` feature.**

```toml
[workspace.dependencies]
log = { version = "0.4", features = ["release_max_level_info"] }
```

This feature **statically removes** debug/trace call sites at compile time in release builds. The macros become no-ops; the call sites do not exist in the release binary. This is the single most effective defense against accidental secret-byte leaks in production logs.

**Discipline rules:**

1. No type carrying secret material implements `Debug` to expose its contents. `secrecy::SecretBox<T>` `Debug` impl prints `SecretBox<...>` only; preserve this behavior in custom wrapper types.
2. CI grep gate (per section 5.4) rejects `debug!`/`trace!` macros that format-arg on types matching `Secret*`, `KeyShare`, `PrivateKey`, `Plaintext`, or `&[u8]` argument types.
3. Release-build log level cap (in addition to `release_max_level_info`):
   ```rust
   #[cfg(debug_assertions)]
   const MAX_LEVEL: Level = Level::DEBUG;
   #[cfg(not(debug_assertions))]
   const MAX_LEVEL: Level = Level::INFO;
   ```
4. Span fields are by-name reference only: `info_span!("envelope_encrypt", recipient_id = %id, key_version = key.version())` — never `key = ?secret`.
5. `log-panics` 2.1.x installed at process start to route panics through the structured logger.

**Why split lib (`log`) vs app (`tracing`).** The Rust core is consumable by both Android process (logging through UniFFI/logcat) and CLI/tests (logging through `tracing-subscriber`) without a dependency on a specific subscriber. This matches libsignal's pattern (libsignal uses `log` 0.4 + `env_logger` + `log-panics` at the library level, not `tracing`).

---

## 5. Testing and verification

### 5.1 Property-based testing: `proptest` 1.x

**Decision.** Adopt `proptest` 1.x as primary. Skip `quickcheck` (works but proptest's per-value `Strategy` model wins for structured generation Cairn needs). Use `proptest-derive` for `Arbitrary` strategies on domain types.

**Properties to commit to writing for v1:**

1. **Envelope round-trip**: `decrypt(encrypt(m, k)) == m` for arbitrary `m: Vec<u8>` and arbitrary valid `k`.
2. **Envelope tamper-resistance**: for arbitrary `m, k`, flipping any single bit in `encrypt(m, k)` produces a decryption error, never a successful decryption.
3. **Shamir threshold completeness**: for arbitrary `(t, n)` with `1 ≤ t ≤ n ≤ 16` and arbitrary secret `s`, any `t`-subset of shares reconstructs `s`; any `(t-1)`-subset does NOT reconstruct `s`.
4. **Shamir share independence**: any subset of `t-1` shares is statistically indistinguishable from random (test via collision frequency over many runs — informational, not a security proof).
5. **Signing determinism / non-malleability**: for arbitrary `msg`, `sign(msg, k)` verifies under `pubkey(k)`; modified signatures fail.
6. **CBOR canonicalization idempotence**: `canonical_encode(canonical_decode(canonical_encode(v))) == canonical_encode(v)` for arbitrary `v`.
7. **Sig_structure construction stability**: for arbitrary headers + payloads, the `Sig_structure` bytes are deterministic across multiple runs and match the cross-implementation reference (`veraison/go-cose`) within property-test scope.

### 5.2 Fuzzing: `cargo-fuzz` for in-tree; OSS-Fuzz once open source

**Decision.** Adopt `cargo-fuzz` (libFuzzer-based) for in-tree fuzz targets. Use `arbitrary` 1.x with `derive` feature for structure-aware harnesses. Integrate with OSS-Fuzz once the project repository is public (per D0019 license decision and Sprint 4 partner-conversation outcome).

**Fuzz targets to commit to writing for v1:**

1. `fuzz_envelope_parse`: bytes → `try_parse(envelope_bytes)` — assert no panic.
2. `fuzz_envelope_decrypt`: `(key, envelope_bytes)` via `arbitrary` — assert authenticated outcome (Ok | Err), no panic, no oracle.
3. `fuzz_shamir_reconstruct`: `Vec<Share>` via `arbitrary` derive — assert reconstruction either succeeds with valid output length or returns typed error.
4. `fuzz_cose_header`: COSE header parser only — separate target reduces noise.
5. `fuzz_canonical_cbor`: bytes → canonical_decode → re-encode → expect byte-identity.
6. `fuzz_uniffi_boundary`: harness that mimics Kotlin's call patterns (handle lifecycle); detect double-free, use-after-free, and Drop-skip scenarios.

**Corpus management.** Seed from project test vectors (per section 2.4); RFC 8152 / RFC 9052 / RFC 9053 test vectors; Cairn-generated Ed25519 corpus; OASIS SAM TSS v1.0 Shamir vectors. Commit `fuzz/corpus/<target>/` to git. Minimize before commit with `cargo fuzz cmin`.

**CIFuzz** for short PR-time runs (60-second budget per target). OSS-Fuzz for continuous deep runs.

### 5.3 Constant-time verification: `dudect-bencher` CI gate

**Decision.** Adopt `dudect-bencher` (Rust port of `oreparaz/dudect`; rozbb/dudect-bencher) for empirical constant-time verification of secret-byte-handling code. Statistical Welch's t-test on timing distributions across two input classes.

**CI gate specification:**

- Target functions: Shamir reconstruction (`combine_shares`); Ed25519 signing (`sign`); AEAD tag comparison; share equality; constant-time CBOR-encoded-key comparison in the canonical helper sort
- Test pattern: feed (secret=0x00…00, random) vs (secret=0xFF…FF, random) over 10⁶ iterations
- Assertion: Welch's t-statistic stays below 4.5
- Run in CI against **release-profile builds** (per the dalek `subtle` historical bug where `opt-level` reintroduced variable time)
- Failure mode: regression in constant-time properties fails CI; the PR cannot merge

**`ctgrind` is abandonware.** Version 0.0.0 from 2017; not viable for production CI. Trail of Bits' December 2025 LLVM constant-time intrinsics work proposes a stable infrastructure but Rust integration is not stabilized as of May 2026.

**`subtle` 2.6.1** is the de-facto-standard primitive library for constant-time comparison and conditional-select; required at every secret-byte equality and conditional-select call site. Custom clippy lint per section 8 disallows `==` on disallowed-types (secret-bearing types).

**`dudect-bencher` pin: 0.7.0 (bumped from 0.6.0 per D0021 §3.2).** 0.7.0 declares `rust-version = "1.85"` matching the toolchain pin; 0.6.0 left MSRV implicit. Same author, repo, license, and `core-hint-black-box` feature. The CI-gate semantics above are unchanged.

### 5.4 CI grep gates for discipline enforcement

Three grep-based CI gates enforce project-wide disciplines:

1. **Secret-leak in logs**: reject PRs where `debug!`/`trace!`/`info!`/`warn!`/`error!` macros format-arg on types matching pattern `Secret*`, `*KeyShare`, `*PrivateKey`, `Plaintext`, `*Seed`, or take `&[u8]` argument types
2. **Raw bytes in errors**: reject PRs where `thiserror::Error` derive contains variants with field types `Vec<u8>` or `&[u8]` (per section 4.2 discipline)
3. **Non-constant-time comparison on secrets**: reject PRs where `==` operator is applied to disallowed-types in the secret module hierarchy; enforce `subtle::ConstantTimeEq::ct_eq` instead

These are pre-commit hook + GitHub Action workflow; PRs blocking on these gates require maintainer override with documented justification (which is captured in the PR record).

---

## 6. Supply chain security

### 6.1 Required CI gates

- **`cargo audit`** — RustSec advisory DB (curated ~600 advisories). Fail CI on any unmitigated advisory. Maintained at `rustsec.org`; advisory feed at `github.com/rustsec/advisory-db`.
- **`cargo deny`** with all four checks (advisories, licenses, sources, bans). License allowlist per D0019; `multiple-versions = "warn"` initially, `"deny"` after initial cleanup.
- **`cargo geiger`** — unsafe-code percentage across deps as informational metric; alarm only on regressions.
- **`cargo machete`** — detect unused dependencies; reduce attack surface.
- **`cargo auditable`** — embed dependency tree into release binaries. Microsoft and multiple Linux distros do this; lets downstream scanners audit the shipped binary directly.

### 6.2 Recommended (adopt incrementally)

- **`cargo vet`** — track audited dependency versions against trusted-org audit feeds (Google, Mozilla, Fermyon publish public feeds). Higher discipline cost but provides positive evidence of audit, not just negative evidence of known CVE.
- **`cargo crev`** — distributed web-of-trust reviews; complementary to cargo-vet.

### 6.3 SBOM and binary auditability

`cargo auditable build --release` embeds the dependency tree into the release binary so downstream scanners can audit the shipped binary independently. This is consumed by partner-organization reviewers per the v1.5 reviewer-pool work and by audit firms during the pre-pilot audit per D0011.

---

## 7. Build and cross-compile for Android

### 7.1 Android NDK r28+ (hard requirement)

**Decision.** Use **Android NDK r28** or newer.

**Rationale.** Google Play's 16 KB page-size mandate has a deadline of **May 31, 2026** (mandatory for new apps; auto-extendable but constrained). NDK r28 produces 16 KB-aligned `.so` files by default; older NDK versions do not. Apps that fail 16 KB alignment cannot be uploaded as new submissions. **AGP 8.5.1+** preserves alignment in App Bundles.

### 7.2 Target ABIs

**Decision.** v1 ships `aarch64-linux-android` (arm64-v8a) + `x86_64-linux-android` only.

- **`aarch64-linux-android`**: mandatory since Aug 2019; primary target for Pixel-on-GrapheneOS pilot devices
- **`x86_64-linux-android`**: mandatory since Aug 2019; also serves Chromebook/x86 tablets and emulators (audit-firm laptop testing path)
- **`armv7-linux-androideabi`**: DROPPED. Android 14+ blocks 32-bit installs on devices with ARMv9 cores; new flagships physically lack 32-bit support. v1's audience (privacy-conscious users on recent hardware) is not constrained by 64-bit-only.
- **`i686-linux-android`**: skipped; legacy 32-bit emulators only.

This is documented in `docs/design-brief.md` §6.3 as the v1 pilot device baseline.

### 7.3 Build-system integration: `cargo-ndk-android-gradle` (Willir's plugin)

**Decision.** Use `cargo-ndk-android-gradle` (Willir's fork) rather than Mozilla's `rust-android-gradle`.

**Rationale.** Per-buildType Rust profile control: `dev` builds debug Rust (faster compile, slower runtime); `release` builds release Rust with `panic = "abort"` and stripped symbols. Mozilla's plugin does not expose this control as cleanly.

**Underlying tool.** `bbqsrc/cargo-ndk` is the cross-compile tool both Gradle plugins wrap. Auto-detects NDK install from Android Studio; emits correct `jniLibs/` layout for AGP.

### 7.4 Reproducible builds

**Decision.** Pin Rust toolchain via `rust-toolchain.toml`; build under Nix with `crane` for bit-for-bit reproducibility; set `SOURCE_DATE_EPOCH` in Nix derivations; use `cargo auditable` in the release profile.

**`rust-toolchain.toml`:**

```toml
[toolchain]
channel = "1.88.0"  # pinned; rotated deliberately (bumped 1.85 -> 1.88, see below)
targets = ["aarch64-linux-android", "x86_64-linux-android"]
profile = "minimal"
components = ["rustfmt", "clippy"]
```

> **Toolchain bump 1.85.0 → 1.88.0 (2026-06-01 — the first deliberate rotation).** Triply-justified, all converging on rust ≥1.88: (1) the SimpleX **Android FFI transport** — `simploxide-sxcrt-sys`'s `build.rs` uses `let`-chains (stabilized 1.88) per D0026 §12; (2) the high-level `simploxide-client` (`const Duration::from_hours`, ~1.87+); (3) the **`time` RUSTSEC-2026-0009** fix (`time >= 0.3.47` needs 1.88). Workspace `rust-version` bumped to `1.88` in lockstep. Re-validation: all four CI gates (clippy `--all-targets --all-features -D warnings` / test / doc / fmt) pass on 1.88 across all 14 crates. Churn was minimal + mechanical: a removed `clippy::match_on_vec_items` allow (now covered by `indexing_slicing`), a `doc_link_code` doc-comment reword, and a `format_push_string` (nursery) workspace-allow (a tracked `write!`-conversion follow-up). Byte-stability discipline (§9.1) is unaffected — exact crate pins unchanged; this is a compiler-toolchain rotation, re-validated.

**`RUSTFLAGS`** for release builds: `--remap-path-prefix=$PWD=. -C strip=symbols`. Sets Gradle's `BuildConfig.BUILD_TIME` to a fixed value (commit timestamp).

**F-Droid reproducibility** (relevant at v1.5+ broader release): requires exact reproducibility of Rust toolchain version, NDK version, and full build environment. Achievable but adds CI complexity. The v1 pilot does not target F-Droid; v1.5+ does.

---

## 8. Cargo workspace baseline

This section specifies the exact workspace structure for the project's first commits. The configurations below are production-grade and absorbed from the consolidated triage research output.

### 8.1 Workspace `Cargo.toml`

```toml
[workspace]
resolver = "2"
members = [
    # Cryptographic primitives + envelope construction
    "crates/cairn-crypto",
    "crates/cairn-envelope",
    "crates/cairn-shamir",
    "crates/cairn-identity",
    "crates/cairn-trust-graph",
    "crates/cairn-recovery",
    "crates/cairn-storage",
    # Integration adapters
    "crates/cairn-simplex-adapter",
    "crates/cairn-tor-transport",
    "crates/cairn-sigsum-client",
    "crates/cairn-sigstore-verify",
    # FFI surface (UniFFI)
    "crates/cairn-uniffi",
    # Internal tooling
    "crates/cairn-cli",
    # Fuzzing harness
    "fuzz",
]

[workspace.package]
edition = "2024"
rust-version = "1.88"  # bumped 1.85 -> 1.88 (2026-06-01 coordination event; see §7.4)
license = "AGPL-3.0-only"
authors = ["Cairn maintainers and contributors"]
repository = "https://github.com/cairn-project/cairn"  # placeholder; updated when repo created

[workspace.dependencies]
# Cryptographic primitives
ed25519-dalek      = { version = "=2.2.0", default-features = false, features = ["std", "rand_core", "zeroize"] }
x25519-dalek       = { version = "=2.0.1", default-features = false, features = ["static_secrets", "zeroize"] }
hkdf               = "=0.12.4"
chacha20poly1305   = "=0.10.1"
sha2               = "=0.10.9"
blake3             = "=1.8.5"  # for Shamir commit-of-secret only

# Memory hygiene
zeroize     = { version = "=1.8.2", features = ["derive"] }
secrecy     = "=0.10.3"
subtle      = "=2.6.1"

# CSPRNG
getrandom   = "=0.4.2"
rand_core   = "=0.9.0"

# CBOR + COSE
ciborium    = "=0.2.2"
coset       = "=0.4.2"

# Shamir Secret Sharing
vsss-rs     = { version = "=5.4.0", default-features = false, features = ["std", "zeroize"] }

# Logging facade (library-level only)
log         = { version = "0.4", features = ["release_max_level_info"] }

# Application-level (cairn-cli only)
tracing             = "0.1"
tracing-subscriber  = { version = "0.3", features = ["env-filter", "json"] }
log-panics          = { version = "2.1", features = ["with-backtrace"] }
anyhow              = "1.0"

# Error handling
thiserror   = "2.0"
# `displaydoc` removed per D0021 §3.1 — zero usage across cairn-crypto /
# cairn-envelope / cairn-shamir; thiserror covers the error-with-Display
# surface ergonomically. Re-add via D-doc if a future surface needs the
# markdown-style doc-comment derive.

# FFI
uniffi      = { version = "=0.31.1" }

# Async (cairn-cli + I/O adapters only; NOT crypto core)
tokio       = { version = "1.51", features = ["rt-multi-thread", "macros"] }

# Testing
proptest    = { version = "1", default-features = false, features = ["std"] }
arbitrary   = { version = "1", features = ["derive"] }

[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"
unused_must_use = "deny"
trivial_casts = "warn"
trivial_numeric_casts = "warn"

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "warn", priority = -1 }
nursery = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
indexing_slicing = "warn"
arithmetic_side_effects = "warn"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
mem_forget = "deny"
exit = "deny"

[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
panic = "abort"
strip = "symbols"
debug = false
overflow-checks = true

[profile.release-with-debug]
inherits = "release"
debug = "line-tables-only"  # for crash-symbol resolution without exposing secrets
```

Per-member crate `Cargo.toml` writes:

```toml
[lints]
workspace = true

[package]
edition.workspace = true
rust-version.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true
```

**Specific crate exception for `unsafe_code`.** The `cairn-storage` crate (which holds `mlock` wrapper if used) and the `cairn-uniffi` crate (which holds JNI-callback boundary code) MAY require `unsafe_code = "deny"` instead of `"forbid"` with documented `#[allow(unsafe_code)]` at the specific call sites. This is the only exception path; all other crates remain at `"forbid"`.

### 8.2 `clippy.toml`

```toml
allow-unwrap-in-tests = true
allow-expect-in-tests = true
cognitive-complexity-threshold = 25

disallowed-types = [
  { path = "ed25519_dalek::SecretKey", reason = "use SecretBox<SecretKey> and compare via subtle" },
  # Add others as the codebase grows
]

disallowed-methods = [
  { path = "std::env::var", reason = "use a config-loading layer; never read secrets via env in code paths reachable from FFI" },
]
```

### 8.3 `rustfmt.toml`

```toml
edition = "2024"
style_edition = "2024"
max_width = 100
hard_tabs = false
tab_spaces = 4
newline_style = "Unix"
use_field_init_shorthand = true
use_try_shorthand = true

# Nightly-only options; document and adopt when on nightly fmt
# imports_granularity = "Module"
# group_imports = "StdExternalCrate"
reorder_imports = true
reorder_modules = true
```

### 8.4 `deny.toml`

```toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

[licenses]
unlicensed = "deny"
allow = [
    "Apache-2.0",
    "MIT",
    "BSD-3-Clause",
    "BSD-2-Clause",
    "ISC",
    "Unicode-DFS-2016",
    "Zlib",
    "CC0-1.0",
    "MPL-2.0",
    "AGPL-3.0-only",  # Cairn's own license; permitted for deps that match
]
copyleft = "deny"  # blocks GPL-2.0, GPL-3.0, LGPL variants; AGPL-3.0 explicitly allowed above
default = "deny"
confidence-threshold = 0.93

[bans]
multiple-versions = "warn"  # tighten to "deny" after initial cleanup
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

### 8.5 CI workflow baseline (GitHub Actions sketch)

```yaml
name: ci

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  fmt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo fmt --all -- --check

  clippy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo clippy --workspace --all-targets --all-features -- -D warnings

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --workspace --all-features

  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rustsec/audit-check@v1

  deny:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v1
        with:
          command: check all

  geiger:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-geiger
      - run: cargo geiger --workspace --forbid-only
        continue-on-error: true # informational; no fail gate yet

  machete:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bnjbvr/cargo-machete@main

  discipline-grep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Secret-leak grep gate
        run: |
          ! grep -rnE 'debug!.*\?(secret|key_share|private_key|plaintext)' --include='*.rs' crates/
      - name: Raw bytes in errors grep gate
        run: |
          ! grep -rnE 'thiserror.*\n.*Vec<u8>|&\[u8\]' --include='*.rs' crates/
      - name: Non-CT comparison on secrets grep gate
        run: |
          ! grep -rnE 'SecretBox.*==' --include='*.rs' crates/

  dudect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo bench --bench dudect_shamir --release -- --continuous false --runs 1000000
      - run: cargo bench --bench dudect_ed25519_sign --release -- --continuous false --runs 1000000
      # Script asserts t-statistic < 4.5

  fuzz-pr:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz
      - run: |
          for target in fuzz_envelope_parse fuzz_envelope_decrypt fuzz_shamir_reconstruct fuzz_canonical_cbor; do
            cargo fuzz run "$target" -- -max_total_time=60
          done

  auditable-release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-auditable
      - run: cargo auditable build --release --target aarch64-linux-android
      - run: cargo auditable build --release --target x86_64-linux-android
```

### 8.6 Repository structure

```
cairn/
├── Cargo.toml                  # workspace definition
├── Cargo.lock                  # committed
├── rust-toolchain.toml         # pinned Rust 1.85
├── clippy.toml
├── rustfmt.toml
├── deny.toml
├── LICENSE                     # AGPL-3.0 full text
├── COPYING -> LICENSE          # symlink
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md                 # disclosure policy per D0012
├── flake.nix                   # reproducible build env
├── flake.lock                  # committed
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── crates/
│   ├── cairn-crypto/
│   ├── cairn-envelope/         # includes cairn-cbor-canonical helper
│   ├── cairn-shamir/
│   ├── cairn-identity/
│   ├── cairn-trust-graph/
│   ├── cairn-recovery/
│   ├── cairn-storage/
│   ├── cairn-simplex-adapter/
│   ├── cairn-tor-transport/
│   ├── cairn-sigsum-client/
│   ├── cairn-sigstore-verify/
│   ├── cairn-uniffi/           # UDL bindings
│   └── cairn-cli/              # internal tooling
├── android/                    # Kotlin UI shell; Gradle project
│   ├── settings.gradle.kts
│   ├── build.gradle.kts
│   └── app/
├── fuzz/                       # cargo-fuzz harness
│   ├── Cargo.toml
│   ├── fuzz_targets/
│   └── corpus/
├── docs/                       # design brief, decisions, runbooks, reviews
└── tests/
    └── vectors/                # cross-implementation test vectors
```

---

## 9. Operational commitments

### 9.1 Library version pinning policy

All cryptographic primitive crates pinned with **exact version** (`=X.Y.Z` not `^X.Y.Z`). Upgrade is a deliberate event with cross-implementation byte-identity re-validation; not a transparent dependency-update flow.

### 9.2 UniFFI version pinning

UniFFI 0.31.1 pinned exactly. Mozilla's own documentation acknowledges "long way from a 1.0 release"; 0.30→0.31 broke method checksums; 0.29 removed `UniffiCustomTypeConverter`. Treat upgrades as non-trivial code-and-test events requiring Kotlin binding regeneration and re-validation.

### 9.3 Android Attestation Root rotation

Per the consolidated triage UniFFI+Android research: new ECDSA P-384 root key for Android Key Attestation; deadline March 31, 2026 (already past); RKP-enabled devices exclusively use new root from April 10, 2026.

**Cairn commitment.** Pin both old and new attestation roots from day one. Document annual review cadence for trust-anchor rotation: maintainer reviews Android Key Attestation root state once per calendar year, updates trust anchors if rotation has occurred since last review, documents in §9.4 trust-roots health report per `docs/design-brief.md` §9.4.

Estimated operational time: ~2-4 hours per annual review.

### 9.4 vsss-rs audit firm publication watch

Cairn's pre-pilot audit kickoff (Phase B funding event per D0011) checks whether `vsss-rs`'s audit firm name + report has been publicly published. If still missing:

- Cairn's pre-pilot audit scope per D0011 (Shamir-library timing-safety verification per Sprint 1 C15 addition) becomes the public record for this code path
- The auditor is informed of `vsss-rs`'s commit `e5756a4` references to specific findings; the auditor independently verifies the constant-time properties claimed
- Cairn does not block pilot launch on upstream publication; Cairn's own audit is the substitute substrate

### 9.5 `release_max_level_info` discipline

The workspace `Cargo.toml` `log` feature `release_max_level_info` is structurally load-bearing for the no-secret-leak-in-logs commitment. Any future PR that removes this feature (or changes it to `release_max_level_debug` etc.) MUST be reviewed against the secret-handling discipline and explicitly justified. The discipline-grep gate per section 5.4 catches one class of regression; this is the second class.

### 9.6 dudect-bencher CI gate maintenance

The constant-time CI gate per section 5.3 requires the t-statistic threshold (currently 4.5) to be maintained per surface. If a future PR's dudect run produces t-statistic > 4.5 against a previously-passing function, the PR fails CI. The threshold is not silently relaxable; relaxing requires documented justification (e.g., baseline statistical noise on a specific CI runner).

---

## Alternatives considered (workspace-wide)

### `ring`/`aws-lc-rs` for the cryptographic stack

_Considered, rejected._ `ring` is in low-key maintenance per Brian Smith's own discussion; `aws-lc-rs` is FIPS-validated and AWS-maintained but has Android cross-compile issues (aws-lc-rs#918, #635). Neither matches the libsignal/vodozemac production deployments that Cairn aligns with for audit-credibility reasons.

### Pure async core (tokio everywhere)

_Considered, rejected._ Async introduces cancel-safety hazards for cryptographic operations (no async drop; mid-state futures); the Tokio docs themselves recommend `spawn_blocking` or `rayon` for CPU-bound work. Crypto operations are CPU-bound and sub-second. Sync-core + tokio-at-I/O-boundary is cleaner.

### `eyre` for application errors

_Considered, rejected._ `anyhow` is the de-facto standard; `eyre`'s reporter feature is not needed for Cairn's CLI tooling. Simpler dependency footprint.

### `quickcheck` over `proptest`

_Considered, rejected._ `quickcheck` works but `proptest`'s per-value `Strategy` model wins for structured generation Cairn needs (COSE headers, Shamir share triples, etc.).

### Custom JNI bridge instead of UniFFI

_Considered, deferred to D0020._ libsignal's pattern is the gold standard but is several engineer-years of investment Cairn cannot replicate for v1. The hybrid UniFFI + jni-rs approach per D0020 is operationally appropriate; revisit if profiling shows the boundary is a bottleneck.

### `mozilla/rust-android-gradle` instead of Willir's

_Considered, rejected._ Mozilla's plugin lacks per-buildType Rust profile control. Willir's fork is the production-grade choice for Cairn's debug-vs-release-Rust requirement.

## Consequences

### Brief section updates

The following design-brief sections receive updates referencing this decision:

- **§5.1**: capability-token renewal cadence justification (StrongBox latency rationale per D0020 — informs the hours-to-days cycle Cairn commits to)
- **§5.5**: Cargo workspace lints baseline (`unsafe_code = "forbid"` with documented exceptions; `panic = "abort"` in release; `release_max_level_info` for log crate); release-engineering pipeline references D0018 build system pinning
- **§5.7 (or §6.1) Implementation language and build architecture**: detailed library selections per this document; reference D0018 as the source of truth for crate versions
- **§6.1 v1 engineering surface**: Android NDK r28+ requirement (16KB page-size mandate); target ABIs (aarch64 + x86_64; drop armv7); cargo-ndk-android-gradle (Willir) plugin; reference D0018
- **§6.3 pilot deployment plan**: Pixel device-baseline (64-bit ARM only; ARMv8.2+ for SHA-NI hardware acceleration; reference D0018 §7.2)
- **§9.4 trust-roots health report**: add Android Attestation Root rotation as biennial-or-as-needed item per §9.3
- **§10.4 Phase D operational time**: add UniFFI version pinning (~4-8 hours per upgrade) and attestation root rotation (~2-4 hours annually) as recurring items

### D0011 audit scope cross-reference

D0011 pre-pilot audit scope per Sprint 1 C15 update (Shamir-library timing-safety verification) explicitly references D0018 §3.1 vsss-rs version and §9.4 audit-firm-publication-watch.

### Open questions affected

- **Q8 (cryptographic library selection)**: resolved by this decision document
- **Q3 (pre-pilot audit firm)**: this decision document provides the auditor with concrete library targets (vsss-rs 5.4.0 with commit e5756a4; cairn-cbor-canonical helper specification; constant-time CI gate baseline)

### What this document does not commit to

- **Specific function signatures** in the cryptographic primitives. Detailed API design is system-design specification work that follows from this foundation.
- **Test-vector contents.** This document specifies the format and oracle (veraison/go-cose); the actual test-vector files are produced during implementation.
- **Android Service lifecycle details.** Deferred to D0020 integration architecture document.
- **Specific Pixel device model recommendations.** v1 supports any Pixel model that runs GrapheneOS at the time of v1 ship; the pilot device-baseline is named in §6.3 against the then-current GrapheneOS-supported devices.

### Reversibility

The decision is **layered reversibility**:

- **Library version pinning**: reversible at moderate cost. Upgrade is a coordinated step; downgrade is similar. Document version changes in subsequent D-docs as schema changes warrant.
- **Library selection** (e.g., `ed25519-dalek` vs `ring`): reversible at high cost (requires re-validation of test vectors, re-evaluation of audit-credibility framing, possibly D0006 cryptographic envelope updates). Switch is feasible but treated as a major architectural change.
- **Cross-cutting discipline** (async pattern; error handling; logging discipline): partially reversible at high cost. Changing the discipline mid-development would require touching every existing module.
- **Cargo workspace baseline** (lints; CI gates; profile settings): fully reversible at low cost. Tightening discipline is always permitted; loosening requires documented justification.

## References

### Sources consulted (Sprint 3 research agents, 2026-05-29)

- Rust cryptographic primitives state-of-the-art: `ed25519-dalek` crates.io / docs.rs; `x25519-dalek`; RustCrypto/KDFs `hkdf`; RustCrypto/AEADs `chacha20poly1305`; RustCrypto/hashes `sha2`; `zeroize`; `secrecy`; `subtle`; `getrandom`; comparison against libsignal and vodozemac production usage
- CBOR + COSE: `enarx/ciborium` GitHub + crates.io; `google/coset` GitHub + crates.io; RFC 8949 (CBOR); RFC 9052 (COSE); IANA CBOR Tags registry; `veraison/go-cose` as cross-implementation reference
- Shamir Secret Sharing: `mikelodder7/vsss-rs` v5.4.0; `oxidecomputer/omicron/trust-quorum/gfss`; `dsprenkels/sss-rs`; Cure53 PVY-01-003 (Privy SSS audit); OASIS SAM TSS v1.0
- Rust ecosystem cross-cutting: corrode.dev "State of Async Rust 2026"; `signalapp/libsignal` Cargo.toml; rustsec.org; cargo-audit, cargo-deny, cargo-geiger, cargo-machete, cargo-auditable repositories
- UniFFI + Android crypto bindings: `mozilla/uniffi-rs`; `signalapp/libsignal`; Android KeyStore / StrongBox documentation; KeyDroid analysis paper (arXiv 2507.07927); GrapheneOS attestation documentation

### Cross-references

- [D0003](D0003-implementation-language.md) — Rust core + Kotlin UI implementation language (foundational decision)
- [D0006](D0006-cryptographic-envelope.md) — Cryptographic envelope completion (consumes this document's library selections + canonical encoding helper specification)
- [D0011](D0011-audit-budget-and-timing.md) — Audit budget and timing (consumes this document's audit-target surface enumeration)
- [D0019](D0019-license.md) — Project license (AGPL-3.0-only; informs `cargo deny` license allowlist)
- [D0020](D0020-integration-architecture.md) — Integration architectures (consumes this document's library decisions; specifies SimpleX + Tor + FFI patterns)
- [open-questions.md](../open-questions.md) — Q8 resolution
- [docs/reviews/external-reads-consolidated.md](../reviews/external-reads-consolidated.md) — Sprint 3 origin and triage
- [docs/design-brief.md](../design-brief.md) §4.1, §5.1, §5.5, §5.7, §6.1, §6.3, §9.4, §10.4
