# D0041 — Release-producer pipeline: `cairn-release` + on-device verify (the D0024 §6 producer side)

**Status:** Accepted (phase 1 — self-minted roots — pipeline _mechanics_ proven on-device; **NOT** an external-trust-anchor / real-Sigstore proof — see §3 + §6)
**Date:** 2026-06-08

> **Read this before citing "on-device-proven."** Phase 1 pins roots the
> producer minted in the same `build`. The on-device run proves
> producer↔verifier byte-agreement and the FFI/wire mechanics — it does
> **not** prove anything against a real adversary, and a green
> `verify_release` here means only "this bundle is internally consistent
> with its own bundled roots," which anyone who can run `cairn-release
build` can forge. Real adversarial value begins at phase 2 (§6), gated
> on the real Sigstore keyless client.

## Context

D0024 built the release **verifier** (`cairn-sigstore-verify`): given a
`ReleaseBundle`, `verify_release` checks the full v1 release-security
stack — Fulcio cert chain + OIDC pins, the manifest `COSE_Sign1`
signature, Rekor inclusion, `prior_release_hash` rollback resistance, and
the witness-cosigned Sigsum-anchored release-log inclusion (D0024 §6).
D0023 built the Sigsum substrate (verify + the `emit_leaf` producer
primitive). D0015 set the v1 release-security **posture** (developer-held
APK signing key + per-release Sigstore identity signing + Rekor + a
Sigsum-anchored release log + multi-channel distribution). The
`apk-signing-custody.md` runbook set the key-custody policy (2-of-3
trustees).

What did **not** exist: anything that _emits_ a `ReleaseBundle`. The
verifier proved the consume-side contract; no producer satisfied it, and
no client code invoked the verifier. This document records the
**realized** producer + the client-side verify surface — like D0028, a
pipeline **actually built and validated in-environment**, not specified
for later.

This is downstream of D0024 (the verifier contract it emits for) + D0015
(the posture it realizes the producer side of) + D0023 (the Sigsum
primitives it reuses). It does not re-decide those; it pins the realized
producer + its phasing.

## Decision summary

| Concern                   | Realized decision                                                                                                                                                                            | Validated?                                  |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| **Bundle wire format**    | `ReleaseBundle` / `RekorBundle` canonical-CBOR (D0018 §2.3 integer-keyed maps), reusing the Sigsum `EmittedLeaf` CBOR — the single-file offline-install artifact (D0024 §6.4)                | ✓ round-trip + malformed-decode tests       |
| **Producer**              | New `crates/cairn-release` binary: `build` emits a `ReleaseBundle` over real artifact digests; `verify` replays the REAL `verify_release` on the host                                        | ✓ host tests + CLI over the real 438 MB APK |
| **Trust-root posture**    | **Phase 1: self-minted roots** per `build` (synthetic Fulcio/Rekor/Sigsum), emitted in a roots sidecar so the verifier pins them — proves the pipeline MECHANICS with zero external services | ✓ phase 1 landed                            |
| **Client verify surface** | `cairn-uniffi::ReleaseVerifierHandle.verify(bundle, expected_prior)` — async FFI replaying `verify_release` on-device; surfaces only the decoded manifest                                    | ✓ host tests + on-device                    |
| **On-device proof**       | The Kotlin driver decodes a base64 bundle + roots, composes the verifier over the unlocked session storage, runs the FFI verify                                                              | ✓ Pixel 6 / GrapheneOS (4 outcomes)         |
| **Rollback chain**        | `prior_release_hash = SHA-256(predecessor manifest canonical-CBOR)`; genesis = zero-length; `--expected-prior` enforces it                                                                   | ✓ host + on-device accept/reject            |

---

## 1. The output contract (what the producer emits)

The verifier's input types froze the contract before this work began, so
the producer is "emit exactly the bytes `verify_release` consumes," not a
design-from-scratch problem. A `ReleaseBundle` is the APK(s) **plus**:

- `manifest_envelope_bytes` — `COSE_Sign1` over canonical-CBOR
  `ReleaseManifest` `{version, artifact_sha256[], build_provenance_sha256,
release_timestamp, prior_release_hash}`, signed under the
  `RELEASE_MANIFEST_AAD` domain (D0006 §8 discipline);
- `fulcio_cert_der` — the signing cert from a Sigstore keyless flow;
- `rekor_bundle` + `rekor_signing_time_unix` — RFC 6962 inclusion proof +
  C2SP/ECDSA-P256 signed checkpoint;
- `sigsum_emitted_leaf` + `sigsum_tree_head_body` +
  `sigsum_inclusion_proof_body` — the witness-cosigned release-log proof,
  bound to `release_leaf_hash = SHA-256(COSE_Sign1.signature_bytes)`.

**R1 added the wire format.** `ReleaseBundle` and `RekorBundle` had no
serialization — they could not be written to disk or shipped. `R1` added
`to_canonical_cbor`/`from_canonical_cbor` (integer-keyed maps, the
`EmittedLeaf` CBOR reused for the nested Sigsum leaf) + a
`ReleaseBundleDecodeFailed` error variant. This is the single-file
offline-install artifact the producer writes and the client reads.

## 2. The `cairn-release` producer

A host CLI (`crates/cairn-release`) with two subcommands:

- **`build --apk <file> --version <semver> [--prior-manifest <file>]
--out <dir>`** — hashes the artifact(s) → assembles + COSE-signs the
  manifest → anchors the Rekor + Sigsum proofs → writes
  `release-bundle.cbor` + `release-roots.json` (the roots that pin it) +
  `manifest.cbor` (the next release's chain link) + `build-provenance.json`
  (a minimal SLSA-style in-toto statement; the manifest commits to its
  SHA-256).
- **`verify --bundle <file> --roots <file> [--expected-prior <hex>]`** —
  loads the bundle + roots and replays the REAL
  `cairn_sigstore_verify::verify_release` on the host. This is the
  producer/verifier-agreement oracle: it runs the identical orchestration
  the on-device client runs, before any device is involved.

The six producer obligations map 1:1 onto the six verify steps; the
synthetic-minting helpers mirror the reviewed fixtures in
`cairn-sigstore-verify/tests/verify_release.rs`, lifted out of `#[cfg(test)]`
into a real binary.

## 3. Trust-root posture: the self-minted → staging → production phasing

The bundle's trust anchors (Fulcio root, Rekor key, Sigsum log +
witnesses) are a `SigstoreVerifierConfig` swap, NOT part of the schema.
That lets the realization phase:

- **Phase 1 (landed) — self-minted roots.** `build` generates the Fulcio
  root (rcgen), Rekor key (p256), and Sigsum log + 3 witnesses per
  invocation, and emits them in `release-roots.json`; the verifier pins
  _those_. This proves the pipeline MECHANICS end-to-end — manifest schema,
  canonical CBOR, COSE-with-AAD, the release-leaf-hash binding, the bundle
  serialization, the FFI surface, the on-device verdict — with **zero
  external services**. It is explicitly NOT a real Sigstore signing event;
  pinning roots that ship alongside the artifact proves the verify
  mechanics, not the external trust anchor. `release-roots.json` is the
  honesty boundary: in production those fields are the _pinned public_ trust
  roots compiled into the shipping client, not a transmitted sidecar.
- **Phase 2 (deferred) — Sigstore staging.** Replace the synthetic Fulcio
  cert with a real keyless OIDC flow against `fulcio.sigstage.dev` +
  `rekor.sigstage.dev`, and the synthetic Sigsum log with a real/test log.
  This needs a real OIDC identity + a Rust Fulcio/Rekor keyless **client**
  (the crate is verify-only today) + a live Sigsum log — genuine new
  network engineering, not a config swap.
- **Phase 3 (deferred) — production.** The project's pinned real OIDC
  identity (D0024 §1.1), the recruited Sigsum witness pool (D0015,
  Q5-gated), and the long-lived APK signing key (custody runbook).

## 4. The client verify surface + on-device proof

**R3** added `cairn-uniffi::ReleaseVerifierHandle` (a `uniffi::Object`) +
`ReleaseRootsRecord` / `VerifiedReleaseRecord` / `ReleaseArtifactRecord`
(`uniffi::Record`s) — the Kotlin-facing client side of the pipeline. The
async `verify(bundle_cbor, expected_prior)` replays the full offline
`verify_release` on-device and surfaces only the decoded manifest; no
proof bytes cross (D0027 §3.2 no-error-oracle discipline). It composes a
`SigsumClient` over the app's shared `StorageHandle` `Arc<Storage>`
(mirrors `SigsumClientHandle`). The roots record carries only public trust
roots, so the NeverExport FFI gate is satisfied. `SigstoreVerifyError`
already mapped to `CairnFfiError`; the new `ReleaseBundleDecodeFailed`
joined the `MalformedData` bucket.

**R4** wired a DEBUG-only driver (`--es vrbundle/--es vrroots/--es vrprior`,
base64 extras — matching the rest of the driver surface and sidestepping
GrapheneOS's app-sandbox file-injection restrictions) into a
`MessagingViewModel.verifyReleaseBundle` that builds the verifier over the
unlocked session and runs the FFI verify.

**On-device proof (Pixel 6 / GrapheneOS, arm64, the regenerated uniffi
bindings):**

- genesis → `verifyrelease: OK version=1.0.0-pilot`, artifact
  `sha256=1bf29ce2…` (byte-identical to the host CLI's hash of the real
  438 MB debug APK);
- tampered bundle → `FAILED MalformedData`;
- successor + correct `--vrprior` → `OK version=1.0.1-pilot rollback=checked`;
- successor + wrong `--vrprior` → `FAILED SigstoreVerifyFailed` (rollback
  attack rejected).

The same Rust `verify_release` the host CLI runs, now invoked through the
FFI on real hardware, with all four outcomes matching the host proof.

## 5. Genesis + rollback chain

`prior_release_hash` is the rollback-resistance anchor (D0024 §4.2):
zero-length for the genesis release, else `SHA-256` of the predecessor's
`manifest.cbor` (`ReleaseManifest::canonical_self_hash`, the value
`manifest.cbor` is written to expose). `build --prior-manifest` reads the
predecessor and computes the link; `verify --expected-prior` enforces it.
The genesis release anchors the chain permanently — getting v1.0.0 right
matters more than any later release, because every subsequent
`prior_release_hash` transitively commits to it.

## 6. What this does NOT cover (deferred)

Phase 1 proves the pipeline mechanics. These deferrals are **not
equivalent** — one class gates whether the stack has any adversarial value
at all; the rest are additive. The review (2026-06-08) sharpened this
ranking.

### 6.1 Hard blockers — the stack verifies nothing forgery-resistant until these land

- **A real Sigstore keyless client** (Fulcio cert-request + Rekor upload +
  an OIDC token source) — phase 2; the crate is verify-only today. **This
  is load-bearing for the _whole_ stack:** until it lands, the pinned
  "trust roots" are self-minted, so every downstream check (Fulcio chain,
  OIDC pin, Rekor inclusion, Sigsum) is verifying attacker-forgeable
  material. A green `verify_release` means "internally consistent with its
  bundled roots," forgeable by anyone who can run `cairn-release build`.
- **A real, recruited Sigsum log + witness pool** to `emit_leaf` against
  (D0015 min-3/2-of-3, Q5/funding-gated). Same property: a synthetic log +
  self-minted witnesses prove nothing an adversary couldn't reproduce.

**Phase-2 prerequisites that MUST land _with_ the real roots (not after),
flagged by the review:**

- **Fulcio path-validation constraints — ✓ LANDED (2026-06-08).**
  `validate_cert_chain` (`fulcio.rs`) now enforces RFC 5280 §6.1.4 on top
  of the chain signatures + validity + OIDC pins: every cert used as an
  **issuer** must assert `BasicConstraints` `cA = TRUE` (the "any leaf is
  a CA" confusion check), its `pathLenConstraint` is checked against the
  intermediates below it, and its `KeyUsage` (if present) must permit
  `keyCertSign`; the **leaf** must NOT assert `cA`, its `KeyUsage` (if
  present) must permit `digitalSignature`, and it must carry an
  `ExtendedKeyUsage` including code-signing (the Fulcio profile). The
  synthetic producer (`cairn-release`) was updated to mint
  profile-correct certs (CA `keyCertSign`+`cRLSign`; leaf
  `digitalSignature` + `codeSigning` EKU) so the round-trip exercises
  every new check, and five negative tests cover each constraint
  (`fulcio.rs`). NameConstraints / policy processing remain out of scope
  (Fulcio uses neither).
- **Compiled-in production roots, not caller-supplied.** The FFI
  `ReleaseVerifierHandle::new` accepts a `ReleaseRootsRecord` from the
  caller (correct for per-build synthetic roots; unreachable in release
  builds today via the `BuildConfig.DEBUG` driver gate). Production roots
  must be a baked-in constant the FFI does **not** accept from the caller
  (or verified against a baked-in digest), so the phase-1 "roots from
  outside" shape cannot survive into production by inertia.
- **Type-gate the unused online verify path — ✓ LANDED (2026-06-08).**
  `SigstoreVerifier`'s online `fetch_rekor_bundle` / `fetch_and_verify_rekor`
  (+ the private `http_get_text` + the `reqwest` client field) are now behind
  a non-default `online-rekor` cargo feature; `reqwest` is an optional dep
  pulled only by that feature. The default offline verifier — which is what
  `cairn-uniffi` / `cairn-release` depend on — compiles **no** network
  surface, so the §6.4 air-gap holds by construction, not by calling
  convention. The `rekor_wiremock` harness is gated to the feature; CI's
  `--all-features` run still exercises it.

### 6.2 Additive (the pipeline is meaningful without these; they widen/operationalize it)

- **APK Signature Scheme v3 signing wiring** in Gradle (no `signingConfig`
  today) + the long-lived-key provisioning ceremony (the
  `apk-signing-custody.md` runbook is written; the ceremony has not run).
- **A SLSA build-provenance emitter** worth the name (phase 1 ships a
  minimal placeholder statement; reproducible builds are v1.5 per D0004).
- **A CI release job** (the `auditable-release` cargo-ndk job in `ci.yml`
  is still commented out) + a tag-triggered build→produce→publish workflow.
- **Distribution channels** — F-Droid (primary; source-built, reproducibility
  tension), Accrescent (own signing model), project direct download
  (domain + hosting).
- **Client-side update discovery + downgrade resistance** (the in-app fetch
  of the latest bundle, over the Tor-only posture). `verify(expected_prior)`
  provides the rollback _check_, but the hash chain alone does **not**
  establish "newest" (it links N→N-1). Sound downgrade resistance requires
  the deferred client to (a) durably store the predecessor hash and pass it
  as `expected_prior`, AND (b) refuse a lower `version`/`versionCode`.
  `release_timestamp`/`version` are NOT verifier-checked anti-rollback
  inputs (clarified in `manifest.rs`). Two API improvements should land
  **with** that loop: a three-state expectation
  (`ExpectGenesis`/`ExpectPredecessor`/`NoCheck`) so a client can assert
  "must be genesis" (today's bare `Option` cannot, enabling forked-genesis
  TOFU), and verifier-enforced `versionCode` monotonicity (passed into
  `verify_release`, not a Kotlin-side check a future driver could forget).

### 6.3 Canonical-CBOR decode strictness — release decoders LANDED; cross-cutting extension tracked separately

**Landed (post-decision follow-up).** A forward-compat-safe strictness gate
now closes two malleability vectors in the release-pipeline decoders:
`ReleaseBundle`, `RekorBundle`, `ReleaseManifest`, and the Sigsum
`EmittedLeaf` (plus the local-cache `TreeHead` / `InclusionProof` that share
the file). The gate rejects **trailing bytes** after the single canonical
CBOR item and **duplicate integer keys** — both forbidden by the canonical
encoder (D0018 §2.3). It does this via a shared `decode_canonical_map`
helper (`cairn-sigstore-verify::decode`, mirrored locally in
`cairn-sigsum-client::cache`) that all four release decoders route through.
Unknown integer keys are still **preserved** (the caller's `_` arm skips
them), so forward-compatibility per D0006 §6.4 is intact — this is why the
gate is _not_ re-encode-and-compare (that would reject a newer producer's
added keys). Each decoder gained round-trip + trailing-byte + duplicate-key
unit tests, and a `fuzz_release_bundle` libFuzzer target asserts two
invariants on arbitrary bytes: **never panic** (the `ReleaseBundle` map
nests `RekorBundle` + `EmittedLeaf` as CBOR byte strings, so one target
transitively fuzzes three decoders; `ReleaseManifest` is fuzzed on the same
input as the fourth) and **idempotent re-encode**
(`encode(decode(b)) == encode(decode(encode(decode(b))))`).

**Explicitly NOT closed (contained residual).** The gate does **not** reject
non-minimal integer heads or indefinite-length items — that needs a raw
canonical-form validator that conflicts with `ciborium`'s decode model. The
residual is contained: the manifest payload is byte-pinned by its
`COSE_Sign1` signature (a non-minimal manifest fails the signature check),
the rollback chain hashes the canonical _re-encoding_
(`canonical_self_hash`), the `release_leaf_hash` binds to the COSE signature
bytes (not the manifest CBOR), and every nested proof (Rekor checkpoint
signature, Sigsum cosignature) is verified independently of its CBOR
encoding. Trailing-bytes + duplicate-keys are the malleability vectors
closeable without breaking forward-compat; the rest are cryptographically
re-verified downstream.

**Still tracked separately — the cross-cutting extension.** Applying the
same gate to the envelope / trust-graph / identity / recovery decoders
(`cose_sign1.rs`, `op.rs`, `token.rs`, `introduction.rs`, `vouch.rs`,
`cascade/timer.rs`, `peer_store.rs`) is deferred to its own unit, for three
evidenced reasons: (1) **right home is `cairn-envelope`, not copy-paste** —
those eight-plus sites use the inline `from_reader` + match pattern, and
`canonical.rs` already reserves the decode-strictness surface as "deferred
to next surface" (encode-only today); the clean landing promotes
`decode_canonical_map` into `cairn_envelope::canonical` and routes all
decoders through it, a cross-crate refactor; (2) **wider, deployed,
cross-party blast radius** — those decoders consume peer-exchanged and
on-device-persisted data already round-tripped between the two Pixels (trust
ops, capability tokens, recovery shares, cascade timers), so a
decode-behaviour change warrants its own two-device regression + D0018 §2.4
test-vector-corpus re-run; (3) **lower marginal value** —
`TrustGraphOp`/`CapabilityToken` payloads are extracted from _inside_ a
`COSE_Sign1` signature (`signed.rs`, `token.rs`), so the signature already
byte-pins them, whereas the release `ReleaseBundle`/`RekorBundle`/
`EmittedLeaf` are parsed straight off a downloaded artifact with no outer
signature — which is exactly why they were the priority surface.

## 7. Reversibility

The bundle wire format (R1) and the `ReleaseManifest` schema are the only
hard-to-reverse commitments — they are the cross-checkable contract
between producer and verifier, and the genesis chain anchors on them.
Everything else is additive: `cairn-release` is a standalone host binary
(removable without touching the shipping app); the FFI verify surface is a
new module; the driver hook is DEBUG-only. Swapping phase 1 → phase 2 → 3
trust roots is a verifier-config change plus the producer's network legs,
not a schema change.

## 8. Cross-references

- `docs/decisions/D0024-sigstore-release-verification.md` — the verifier
  contract this emits for.
- `docs/decisions/D0015-v1-release-security-posture.md` — the posture this
  realizes the producer side of.
- `docs/decisions/D0023-sigsum-integration.md` — the Sigsum verify + emit
  primitives reused.
- `docs/decisions/D0028-android-shell-build-pipeline.md` — the
  `cargo-ndk → UniFFI → APK` chain this extends with the new FFI surface.
- `docs/decisions/D0027-cairn-uniffi-crate-surface.md` — the FFI boundary +
  §3.2 no-error-oracle discipline the verify surface honors.
- `docs/runbooks/apk-signing-custody.md` — the APK-key custody policy the
  deferred §6 signing leg executes.
- `docs/decisions/D0004-v1-scope-cuts.md` — reproducible builds deferred to
  v1.5 (why phase 1 ships SLSA-style, not reproducible, provenance).
