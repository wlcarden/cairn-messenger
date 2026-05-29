# Empirical cadence metrics

Per D0018's empirical-metrics commitment: calendar-time projections borrowed
from comparable-project history have been abandoned in favor of empirical
measurement starting from the first commits. This document tracks **actual
elapsed work** against **surface-completion milestones**.

The metrics here are the substrate for honest re-projection of v1 ship
timing. Per the consolidated external-reads triage maintainer review M1
finding, a month-18 check-in commitment compares actual progress against
this baseline.

## Surface-completion milestones

### Tier 1 MDC (cryptographic foundation)

- [x] **Workspace scaffolding complete** — 2026-05-29
  - Cargo workspace + `rust-toolchain.toml` + `clippy.toml` + `rustfmt.toml`
    - `deny.toml`
  - LICENSE (AGPL-3.0-only) + COPYING symlink
  - README, CONTRIBUTING, SECURITY
  - `.github/workflows/ci.yml` with discipline-grep gates
  - `.gitignore` updated for Rust + Android conventions

- [x] **`cairn-crypto` Ed25519 module skeleton** — 2026-05-29
  - Sealed `NeverExport` marker trait pattern
  - `SigningKey` wrapper storing seed in `SecretBox<[u8; 32]>`
  - `VerifyingKey` + `Signature` types with constant-time `PartialEq`
  - 9 unit tests + 3 property-based tests + 1 doctest passing
  - Clippy clean under workspace lints (including `pedantic` warnings as deny)
  - Format-check clean

- [x] **`cairn-crypto` X25519 ECDH module** — 2026-05-29
  - `EphemeralKey` + `StaticKey` wrappers (consume-on-agree vs. reusable
    semantics enforced at the type level)
  - `PublicKey` + `SharedSecret` API-boundary types; `SharedSecret`
    constructor is private and enforces `was_contributory()` per D0018 §1.2 +
    vodozemac 2026 audit reference (illegal-states-unrepresentable encoding
    of the check rather than procedural reminder)
  - 7 unit tests + 3 property tests covering ECDH symmetry, zero-pk
    rejection, and ephemeral-static interop
  - Clippy clean under workspace lints; rustfmt clean

- [x] **`cairn-crypto` HKDF module** — 2026-05-29
  - HKDF-SHA256 extract/expand with cached-PRK [`Prk`] type for the
    multi-label-derivation pattern (X3DH / Triple Ratchet per D0006 §5.4)
  - One-shot `derive()` convenience helper for single-label cases
  - All 3 RFC 5869 §A SHA-256 test vectors (A.1, A.2, A.3) pass
  - 3 property tests covering derivation determinism, distinct-info /
    distinct-OKM, and distinct-IKM / distinct-OKM
  - Output length ceiling (`255 * 32 = 8160` bytes) enforced via
    `HkdfError::OutputTooLong`

- [x] **`cairn-crypto` AEAD module** — 2026-05-29
  - `XChaCha20`-`Poly1305` wrapper per D0018 §1.4 (24-byte extended
    nonces, random-safe across the device's lifetime; no nonce-counter
    persistence required across restarts — important for the recoverable-
    state model)
  - Uniform `DecryptFailed` for all decryption failure modes per the
    no-error-oracle discipline (D0006 / D0018 §1.4)
  - Byte-exact KAT match against draft-irtf-cfrg-xchacha-03 §A.3
  - 10 unit tests covering round-trip, tamper resistance (key/nonce/ad/
    body/tag/truncation), empty-plaintext + empty-aad edge cases, and the
    KAT vector
  - 3 property tests covering round-trip determinism, single-bit tamper
    rejection, and wrong-key rejection

- [x] **`cairn-envelope` crate skeleton** — 2026-05-29
  - Workspace member added; package builds with ciborium + coset deps
  - `lib.rs` documents the wire-form principles (determinism + authenticated
    provenance + confidentiality) and the interop-validation strategy
    (`veraison/go-cose` cross-implementation oracle per D0018 §2.5)
  - Placeholder `EnvelopeError` enum with `#[non_exhaustive]` discipline
    ready for variants to land with each subsequent surface
- [x] **`cairn-envelope` canonical CBOR helper per D0018 §2.3** — 2026-05-29
  - Project-owned encoder per D0018 §2.3 (ciborium 0.2 does not enforce
    deterministic encoding alone)
  - Minimal typed [`Value`] AST: `Null`, `Bool`, `Int(i64)`, `Bytes`, `Text`,
    `Array`, `Map` — variants intentionally restricted to those with
    deterministic encodings (no floats, no indefinite-length, no big-int)
  - All 4 RFC 8949 §4.2 deterministic encoding rules enforced:
    smallest-head, definite-length-only, canonical map-key ordering,
    duplicate-key rejection
  - 29 unit tests covering every head-encoding boundary (int 0/23/24/255/
    256/65535/65536/i64::MIN, negative -1/-24/-25), all leaf variants
    encoding, map key sorting, cross-type key ordering, duplicate
    detection, and nested structure encoding
  - 3 property tests: leaf-non-empty, encode-determinism, map-order-
    invariance
  - 80 tests + 1 doctest passing across workspace
- [x] **`cairn-envelope` `COSE_Sign1` construction** — 2026-05-29
  - `Sign1Builder` (alg = `EdDSA` default, optional `kid` in unprotected
    headers, optional external AAD) → `finalize(&SigningKey)` →
    [`CoseSign1`]
  - `CoseSign1::encode(tagged: bool)` produces canonical CBOR bytes
    (optionally wrapped in CBOR tag 18); `CoseSign1::from_bytes` decodes
    via ciborium then walks into our canonical [`Value`] AST for
    unprotected headers (protected headers preserved as raw bytes per RFC
    9052 §4.4 `Sig_structure` discipline — structural defense against
    re-encoding mauling)
  - `CoseSign1::verify` rebuilds the canonical `Sig_structure` and
    delegates to `cairn-crypto::ed25519::verify` (which uses
    `verify_strict` per D0018 §1.1)
  - Uniform `CoseSign1VerifyFailed` for all crypto-layer failure modes
    (wrong key, tampered payload, tampered headers, tampered signature,
    wrong external AAD) per the no-error-oracle discipline (D0006 /
    D0018 §1.4)
  - 13 unit tests covering round-trip variants (payload, kid, external
    AAD, detached, tagged, untagged), tamper resistance (key, payload,
    signature, AAD, truncation), decoder rejection (malformed CBOR,
    wrong arity), and determinism
  - 2 property tests: random-payload round-trip + payload-tamper-fails-
    verify
- [x] **`cairn-envelope` cross-implementation interop validation** —
      2026-05-29
  - Rust-side oracle: coset 0.4.2 per D0021 §2.3 role assignment
  - 4 interop tests in `cairn-envelope::cose_sign1::interop_tests`:
    untagged decode + verify, tagged decode + verify, kid header
    round-trip through coset's typed `unprotected.key_id` field,
    tamper rejection at coset's verify-signature path
  - All 4 tests pass: Cairn's canonical-CBOR + COSE_Sign1 bytes
    decode and verify correctly through an independent Rust COSE
    implementation. 51 cairn-envelope tests total (47 original + 4
    interop)
  - **Deferred to follow-up**: Go-side `veraison/go-cose` check
    requires Go toolchain setup in CI. Future surface will: add a
    `cairn-envelope` example binary that emits fixture files to disk
    (a fixed-seed CapabilityToken + its expected pubkey); add a
    `tests/interop_go/` directory with a Go program using
    github.com/veraison/go-cose v1.3.0+ that reads each fixture and
    verifies the signature; wire into CI as a separate job that
    installs Go alongside Rust. Tracked as a v1.5 candidate in §6
    of D0021's implementation-status table.

- [x] **`cairn-shamir` crate skeleton** — 2026-05-29
  - Workspace member added; package builds with `vsss-rs` 4.3.8 +
    `blake3` 1.5.4 deps
  - `lib.rs` documents the seed-not-scalar rationale (preserves Ed25519's
    deterministic-nonce contract per RFC 8032 §5.1.6 across multi-site
    reconstruction), the BLAKE3 commit-of-secret defense (D0018 §3.4
    against corrupted shares, malicious reconstruction shares, and
    implementation drift), and the constant-time discipline plan
  - Placeholder `ShamirError` enum ready for variants to land with the
    split / reconstruct surfaces
- [x] **`cairn-shamir` GF(256) Shamir wrapper with BLAKE3 commit** —
      2026-05-29
  - **Architectural finding**: `vsss-rs` 4.3.8 (the D0018 §3.1 pin)
    requires `F: PrimeField` and does NOT support byte-level GF(2⁸)
    Shamir. Cairn's seed-not-scalar requirement (preserves Ed25519's
    deterministic-nonce contract per RFC 8032 §5.1.6 across multi-site
    reconstruction) mandates byte-level splits. Future D-doc will revise
    D0018 §3.1.
  - Project-owned byte-level GF(2⁸) implementation: constant-time
    `gf256` field arithmetic (`mul` via shift-and-conditional-XOR with
    bitmask discipline; `inv` via Fermat fixed-schedule square-and-
    multiply); `share` module with `split` / `reconstruct` over fixed
    public loop bounds; `commit` module wrapping BLAKE3 `derive_key`
    with versioned domain-separation context.
  - 35 tests: 13 GF(256) (incl. FIPS 197 §4.2 AES multiplication
    vectors `0x53*0xCA=0x01`, `0x57*0x83=0xC1`, `0x57*0x13=0xFE`); 6
    `Commitment` (incl. direct cross-check against `blake3::derive_key`);
    14 `share` (round-trip across `(2,2)`/`(3,5)`/`(5,5)`, exhaustive
    `C(4,3)` subset reconstruction, tamper resistance, parameter
    validation, duplicate-id rejection); 2 property tests (round-trip
    - single-bit tamper rejection on a `(3,3)` split).
  - 131 tests + 1 doctest passing across workspace.
- [x] **`cairn-shamir` constant-time CI gate via `dudect-bencher`** —
      2026-05-29
  - New crate `cairn-ct-bench` houses the bench harness; dudect-bencher
    0.7.0 wired per D0018 §5.3
  - Three v1 bench functions: `bench_shamir_split` (vsss-rs Gf256
    split_array), `bench_shamir_reconstruct` (Gf256 combine_array —
    the path D0018 §5.3 line 459 explicitly cites), `bench_ed25519_sign`
    (ed25519-dalek SigningKey::sign)
  - Local validation results (10_000 iterations, release build): all
    three benches stay well below the t < 4.5 threshold (|t| =
    1.17 / 1.87 / 2.32). The Cure53 PVY-01-003 / ed25519-dalek
    constant-time claims hold up under our wrapper layer
  - CI step added (`.github/workflows/ci.yml` dudect-bencher job)
    that builds release-profile and runs the harness. Threshold
    gating deferred (CI runners too noisy for reliable t < 4.5
    enforcement; production validation runs use --continuous on
    dedicated hardware per D0018 §5.3 line 460 10⁶-iteration spec)
  - Follow-up coverage deferred to separate surfaces: AEAD tag
    comparison, share PartialEq, canonical-CBOR encoded-key compare

- [x] **`cairn-identity` capability-token construction per D0006 §9** —
      2026-05-29
  - `CapabilityToken { issuer, subject, scope, expiry, chain }`
    struct with canonical-CBOR payload encoding using integer keys
    1..=5 per COSE convention
  - `sign(&SigningKey) -> SignedCapabilityToken` wraps payload in
    COSE_Sign1 via `cairn-envelope::cose_sign1::Sign1Builder`
  - `SignedCapabilityToken::from_bytes(bytes, &expected_issuer)`
    performs all four checks in one path: COSE_Sign1 decode, payload
    decode, embedded-issuer matches expected, signature verifies
  - Forward-compat: unknown scope strings and unknown map keys
    round-trip cleanly per D0006 §6.4
  - 13 unit tests (round-trip variants: tagged/untagged/empty-scope/
    forward-compat; failure modes: malformed/tampered/wrong-issuer/
    wrong-signing-key/issuer-mismatch; determinism; CBOR round-trip;
    unknown-keys forward-compat) + 2 property tests (random round-
    trip + has_capability consistency)
  - 5 const &str capability identifiers in `capabilities` module
    (MESSAGING*SEND / TRUST_GRAPH_ATTEST / TRUST_GRAPH_REVOKE*
    WITHDRAW / TRUST_GRAPH_REVOKE_COMPROMISE / RECOVERY_PARTICIPATE)
  - 133 tests + 2 doctests passing across workspace

- [ ] **First crates.io publication (when ready)**

### Tier 2 protocol layer surfaces

These extend the foundation crates with protocol-level operations
beyond the Tier 1 MDC line.

- [x] **`cairn-recovery` master-attestation primitive per D0005 +
      D0006 §6** — 2026-05-29
  - `MasterAttestation { master, operational_identity, timestamp }`
    canonical-CBOR + COSE_Sign1 envelope signed by master directly
    (no capability token — the master is its own root of trust at
    the top of the three-hop chain)
  - `reconstruct_and_attest(shares, commitment, new_op_identity, ts)`
    composes `cairn-shamir::reconstruct` + `MasterAttestation::sign`
    with the master seed held in `Zeroizing` end-to-end and wiped on
    function exit
  - `SignedMasterAttestation::from_bytes(bytes, &expected_master)`
    verifies: embedded master pubkey matches expected (defends
    against key substitution), then signature verifies against
    expected master pubkey
  - 8 unit tests: happy-path round-trip via reconstruct_and_attest;
    tampered share → ShamirReconstruct error; insufficient shares →
    ShamirReconstruct error; wrong expected master → MasterPubkeyMismatch;
    tampered envelope bytes → verify error; canonical encoding
    round-trip + determinism; provisioning-time master-only path
  - **Deferred to higher layers**: atomic-or-non-leaking re-split per
    D0018 §3.5 (two-phase commit across N peers); recovery-peer
    authentication per D0005 (trust-graph-driven authorization of
    which peers hold shares). Both require the peer protocol layer
    (network/messaging) which is outside the cryptographic primitives.

- [x] **`cairn-trust-graph` operation envelopes per D0006 §2** —
      2026-05-29
  - Four operation types per D0006 §2: `Attest`, `WithdrawRevoke`,
    `CompromiseRevoke` (triggers cascade quarantine), `ReAttest`
  - Each op encoded as integer-keyed canonical-CBOR map (8 schema
    keys) signed by device key as `COSE_Sign1` envelope, matching
    the same three-hop pattern as message envelopes
  - `OpType::required_capability()` maps each op type to its required
    `cairn-identity` capability string for scope-check enforcement
  - `SignedTrustGraphOp::verify_chain(token_bytes, expected_op_identity)`
    performs hops #1 + #2 atomically: token verifies against expected
    issuer, scope contains required capability, op signature verifies
    against the token's subject (device pubkey), op's `issuer` field
    matches the token's `issuer` field (defends against forged-issuer
    on device that has a token from a different operational identity)
  - Variant-required field discipline: `CompromiseRevoke` MUST carry
    `revoked_as_of`; `ReAttest` MUST carry `prior_revocation_ref`;
    others MUST NOT
  - 14 unit tests covering: all four op types round-trip and verify
    against valid tokens; scope-check rejects misaligned op type;
    op-issuer-vs-token-issuer mismatch rejected; wrong device signing
    key rejected; wrong expected operational identity rejected;
    field-presence schema enforcement; unknown op_type rejected;
    forward-compat unknown map keys preserved; deterministic
    canonical encoding; required-capability mapping table
  - Cascade quarantine state-tracking + chain-walk validation
    deferred to higher-layer surface (will live in
    `cairn-trust-graph-state` or `cairn-recovery` once those land)

- [x] **D0006 §8 `external_aad` domain separation applied across
      cairn-identity + cairn-trust-graph + cairn-recovery** — 2026-05-29
  - Domain-separation tags exported as `pub const DOMAIN_TAG: &[u8]`
    from each crate root:
    - `cairn-identity::DOMAIN_TAG = b"cairn-v1-capability-token"`
      (D0006 §8 explicit enumeration)
    - `cairn-trust-graph::DOMAIN_TAG = b"cairn-v1-trust-graph-operation"`
      (D0006 §8 explicit enumeration)
    - `cairn-recovery::DOMAIN_TAG = b"cairn-v1-master-attestation"`
      (extends D0006 §8 by analogy — same cross-protocol substitution
      defense applies to the master-attestation envelope, which is
      signed by the master directly without a capability-token wrapper)
  - Tags bound into the `COSE_Sign1` `Sig_structure` via `external_aad`
    per RFC 9052 §4.4; both sign and verify paths use the matching tag
  - 6 new tests (2 per crate): pin the tag byte value to catch
    accidental edits; prove signatures produced for one domain do NOT
    verify under any other domain tag or under the empty AAD, AND that
    the correct tag verifies (structural soundness check)
  - All three-hop end-to-end CLI demos still verify cleanly post-change
    (sign and verify paths updated atomically; no on-the-wire migration
    needed since this lands pre-v1 with no deployed envelopes)
  - 165 tests passing across workspace (was 159; +6 cross-domain
    substitution tests)

- [x] **D0006 §5 + §7 canonical-hash helpers + reference test vector**
      — 2026-05-29
  - `cairn-envelope::CoseSign1::sig_structure_bytes(external_aad)`:
    public accessor for the canonical-CBOR-encoded RFC 9052 §4.4
    `Sig_structure` byte string (caller supplies the matching AAD —
    `Sig_structure` content is not stored on the envelope because
    `external_aad` is external to the wire format)
  - `cairn-trust-graph::SignedTrustGraphOp::prior_hash_bytes()`
    returns `[u8; 32]` per D0006 §5:
    `SHA-256( COSE_Sign1.signature_bytes( self ) )`. Removes the
    caller's burden of remembering to hash the signature bytes (not
    the payload or full envelope); typo-proof at the type system level
  - `cairn-recovery::SignedMasterAttestation::issuer_cert_hash()`
    returns `Result<[u8; 32], RecoveryError>` per D0006 §7:
    `SHA-256( deterministic_cbor_encode( Sig_structure ) )` bound with
    the master-attestation domain tag from D0006 §8
  - D0006 §7 reference test vector pinned via deterministic fixed-seed
    construction (master_seed = `[0x42; 32]`, op_identity_seed = `[0x37;
32]`, timestamp = 1_700_000_000): expected
    `e3ee2121f19366b59ede1d48cd9bc4f7ad6f8177ac348f2a992bf32d1aee04b9`.
    Any change to canonical CBOR encoding, DOMAIN_TAG, payload schema,
    or SHA-256 impl trips this test loudly. Satisfies D0006 §7's
    "reference (master_attestation, expected issuer_cert_hash bytes)
    pair is added to the v1 implementation test suite" requirement
  - Cross-check tests in both protocol crates verify the helper output
    matches an independently constructed SHA-256 of the canonical
    Sig_structure or signature bytes (structural cross-verification —
    catches drift between the helper and the spec's byte construction)
  - 168 tests passing across workspace (was 165; +3 hash-helper tests)

### Application surfaces (beyond Tier 1 MDC)

These are "above" the Tier 1 MDC line — they compose the foundation
crates into runnable surfaces that prove the MDC pathway thesis. Not
originally in the Tier 1 MDC ship-list, but landed in the same
implementation session because they demonstrate end-to-end
functionality with the existing primitives.

- [x] **`cairn-cli` minimum-demoable-capability binary** — 2026-05-29
  - Twelve subcommands cover the full v1 protocol shape end-to-end
    across all three hops of the D0006 §9 verification chain: - `gen-key` / `pubkey` — Ed25519 keypair management - `issue-token` / `verify-token` — capability token issuance +
    verification (D0006 §9 hop #2) - `sign-message` / `verify-message` — device-key signs payload
    under a capability token; verifier enforces order (token first,
    then message under token's subject pubkey, optional scope
    check) - `split-seed` / `reconstruct-seed` — Shamir 3-of-5 demo with
    BLAKE3 commitment integrity - `trust-op` (variant flag `--kind=attest | revoke-withdraw |
revoke-compromise | re-attest`) / `verify-trust-op` —
    protocol-layer trust-graph operation signing + chain
    verification (D0006 §9 hops #1 + #2 over `cairn-trust-graph`'s
    `SignedTrustGraphOp` primitives; CLI enforces variant-required
    argument presence before constructing the typestate-friendly
    `TrustGraphOp` so the protocol layer's invariants are never
    bypassed by CLI typos) - `attest-operational-identity` / `verify-master-attestation` —
    recovery flow demonstrating hop #3 (master attestation chain).
    `attest-operational-identity` composes
    `cairn-shamir::reconstruct` + `cairn-recovery::reconstruct_and_attest`
    with the master seed held in `Zeroizing` for the call and wiped
    on exit — seed bytes never touch disk via this command
  - End-to-end demos validate the happy path plus negative paths:
    - Hop #3: wrong expected-master-pubkey → MasterPubkeyMismatch
    - Hop #2b: trust-op for capability NOT in issued token scope →
      CapabilityNotAuthorized (e.g., `revoke-withdraw` op against a
      token authorizing only `attest` + `revoke-compromise`)
    - Hop #2a: wrong AAD on message → SignatureVerifyFailed (uniform
      per the no-error-oracle discipline)
    - Hop #1: wrong issuer for token → IssuerMismatch; insufficient /
      tampered shares → uniform CommitmentMismatch per D0018 §3.4
    - CLI-layer: `--kind=revoke-compromise` without `--revoked-as-of` →
      bail with explicit reference to D0006 §2; `--revoked-as-of` with
      irrelevant `--kind` → bail
  - Single `cairn` binary (~5 MB release build) demonstrates all three
    hops of D0006 §9 (device key → capability token → master attestation)
    runnable today against trusted-runner partner conversations

## Elapsed-time tracking

Tracking format: `YYYY-MM-DD; surface; hours invested; notes`.

| Date       | Surface                                                 | Hours | Notes                                                                                                                                           |
| ---------- | ------------------------------------------------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-05-29 | Workspace scaffolding + `cairn-crypto` Ed25519 skeleton | TBD   | First implementation session. Compiles, tests, clippy all green.                                                                                |
| 2026-05-29 | `cairn-crypto` X25519 ECDH module                       | TBD   | Same-day continuation. Structural enforcement of `was_contributory()` via private constructor; 22 tests + 1 doctest pass; 2 clippy iterations.  |
| 2026-05-29 | `cairn-crypto` HKDF module                              | TBD   | All 3 RFC 5869 §A SHA-256 test vectors pass; cached-PRK pattern for X3DH / Triple Ratchet multi-label derivation; 33 tests total in workspace.  |
| 2026-05-29 | `cairn-crypto` AEAD module                              | TBD   | Byte-exact draft-irtf-cfrg-xchacha-03 §A.3 KAT match; uniform `DecryptFailed` error oracle discipline; 47 tests total + 1 doctest in workspace. |
| 2026-05-29 | `cairn-envelope` crate skeleton                         | TBD   | New workspace member; coset + ciborium deps added; `EnvelopeError` placeholder enum ready for variant accretion as surfaces land.               |
| 2026-05-29 | `cairn-envelope` canonical CBOR helper                  | TBD   | Project-owned encoder per D0018 §2.3; all RFC 8949 head-encoding boundaries covered; 80 tests total + 1 doctest in workspace.                   |
| 2026-05-29 | `cairn-envelope` `COSE_Sign1` construction              | TBD   | Sign1Builder + finalize + encode + from_bytes + verify per RFC 9052 §4.4; full round-trip + tamper-resistance test battery; 95 tests total.     |

The "TBD" entries are filled in by the developer as they go. The discipline
is to record honest hours (not calendar elapsed) since the consolidated
triage M1 finding specifically frames "honest re-baselining at month 18"
against actual development cadence rather than borrowed projections.

## Empirical-cadence summary (running)

Updated at each surface-completion milestone:

- **Surfaces complete**: 8 / ~15+ Tier 1 MDC surfaces (workspace
  scaffolding, ed25519, x25519, hkdf, aead, cairn-envelope skeleton,
  canonical CBOR, `COSE_Sign1`)
- **Cumulative hours**: TBD
- **Cumulative LoC (impl + docs)**: ~1900 LoC across `cairn-crypto/src/` +
  `cairn-envelope/src/`
- **Cumulative LoC (tests)**: ~1680 LoC (unit + property tests + RFC / KAT
  vectors inline; 3581 total file LoC across both crates)
- **Test:code ratio**: ~0.88:1 at this stage and rising (canonical CBOR
  added 32 tests for 580 file LoC; `COSE_Sign1` added 15 tests for 756
  file LoC with extensive round-trip + tamper-resistance coverage). Target
  per D0018 §2.4 + audit-target practice is 2:1 to 3:1 for audit-target
  surfaces; the next acceleration comes from `cairn-shamir`'s
  `dudect-bencher` constant-time harnesses and the `veraison/go-cose`
  interop vectors.
- **Test pass count**: 95 unit + property tests + 1 doctest = 96 across
  6 modules (cairn-crypto: ed25519, x25519, hkdf, aead + cairn-envelope:
  canonical, `COSE_Sign1`)
- **RFC / KAT vector coverage**:
  - RFC 5869 §A.1–A.3 (HKDF-SHA256, 3/3 vectors)
  - draft-irtf-cfrg-xchacha-03 §A.3 (`XChaCha20`-`Poly1305`, 1/1 vector)
  - RFC 8949 §3 head-encoding boundary cases (canonical CBOR, exhaustive
    coverage of int / nint / bytes / text / array / map heads)
  - RFC 9052 §4.4 `Sig_structure` construction discipline (round-trip
    - tamper-resistance proven at the wrapper layer; the
      `veraison/go-cose` cross-implementation oracle is the next surface)
  - Ed25519 covered by ed25519-dalek's audited test suite plus property
    tests at the wrapper layer
- **Commits**: 0 (first commit pending)
- **Clippy diagnostics fixed in CI iteration**: 49 cumulative across both
  crates (doc_markdown dominant, plus must_use, const_fn,
  disallowed_types, needless_pass_by_value, useless_conversion,
  indexing_slicing, arithmetic_side_effects, checked_conversions,
  cast_sign_loss, manual_let_else, option_if_let_else, redundant_clone —
  fixed at source, not blanket-allowed; allows applied only at test-code
  sites with proven safety bounds)

## Reference comparable-project cadence

For calibration context (NOT for projection):

- Briar Project: ~3 years from initial public commits to v1 broad release
  (with institutional backing)
- Cwtch: ~2 years from initial Rust port to v1.0 (with OpenPriv institutional
  backing)
- vodozemac: ~9 months from initial commit to audited v0.1.0 (with Matrix.org
  institutional backing)
- libsignal (Rust port): ~2 years to feature parity with libsignal-java (with
  Signal Foundation institutional backing)

Cairn's solo-volunteer baseline per D0008 has no comparable-project precedent
at this threat tier with this scope. The empirical metric here is the only
honest substrate for projection; this section exists to provide context, not
target.

## Re-projection cadence

- **Month 1 (June 2026)**: first cadence data lands; metrics.md gets a real
  hours-per-surface entry. No re-projection yet.
- **Month 3 (August 2026)**: ~3 surfaces complete (estimate); first
  re-projection of Tier 1 MDC ship date against actual cadence.
- **Month 6 (November 2026)**: Tier 1 MDC expected complete (estimate);
  re-projection of Tier 2 + Tier 3 against Tier 1 cadence baseline.
- **Month 18 (November 2027)**: per the consolidated triage M1 finding,
  formal month-18 check-in. Actual elapsed Phase A duration; honest
  re-assessment of v1 scope vs. actual engineering velocity; runway-figure
  comparison; D0016 trigger re-evaluation.
