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

- **Fulcio path-validation constraints** — `validate_cert_chain`
  (`fulcio.rs`) currently checks chain signatures + validity + OIDC pins
  but **not** RFC 5280 BasicConstraints (CA flag/pathlen), KeyUsage
  `keyCertSign`, or EKU. Benign under a single coordinated self-minted
  root; against the real public Fulcio root this is the "any leaf is a CA"
  confusion class and must be enforced **with** the real root, not later.
- **Compiled-in production roots, not caller-supplied.** The FFI
  `ReleaseVerifierHandle::new` accepts a `ReleaseRootsRecord` from the
  caller (correct for per-build synthetic roots; unreachable in release
  builds today via the `BuildConfig.DEBUG` driver gate). Production roots
  must be a baked-in constant the FFI does **not** accept from the caller
  (or verified against a baked-in digest), so the phase-1 "roots from
  outside" shape cannot survive into production by inertia.
- **Type-gate the unused online verify path.** `SigstoreVerifier` exposes
  `fetch_*` online methods on the same type as the "offline" `verify_release`;
  the air-gap (D0024 §6.4) is preserved only by calling convention. Gate
  the online path behind a feature or document it as out-of-scope for v1.

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

### 6.3 Tracked separately

- **Canonical-CBOR decode strictness** — the bundle decode (like every
  canonical-CBOR decoder in the workspace) accepts trailing bytes,
  non-minimal encodings, and duplicate keys; the encoder is strict but the
  decoders do not re-check canonicality. Contained here (the bundle's
  contents are cryptographically re-verified), but a cross-cutting strictness
  gate + a `fuzz_release_bundle` target are spun off as a separate workspace
  follow-up (it touches the envelope/trust-graph/identity/recovery/sigsum
  decoders + the test-vector corpus, beyond this pipeline).

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
