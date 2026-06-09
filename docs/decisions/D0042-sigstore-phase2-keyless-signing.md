# D0042 — Sigstore phase 2: real keyless signing + pinned staging trust roots (the D0041 §6.1 hard blocker)

**Status:** Proposed (design; resolves the phase-2 forks — one pivotal call flagged for confirmation in §3)
**Date:** 2026-06-09

> **Why this exists.** D0041 phase 1 proved the release pipeline's
> _mechanics_ against **self-minted** trust roots: a green `verify_release`
> there means only "internally consistent with its own bundled roots,"
> forgeable by anyone who can run `cairn-release build`. D0041 §6.1 names
> the **real Sigstore keyless client** as load-bearing for the _whole_
> stack — until it lands, every downstream check (Fulcio chain, OIDC pin,
> Rekor inclusion) is verifying attacker-forgeable material. This decision
> scopes that work against Sigstore **staging** (phase 2); production
> (phase 3) is a config + ceremony change on top.

## Context

The verifier (`cairn-sigstore-verify`) is **done and real** (D0024): it
walks a Fulcio chain to a pinned root with RFC 5280 path constraints
(D0041 §6.1), pins the OIDC issuer/identity, verifies a manifest
signature, checks a Rekor inclusion proof + signed checkpoint against a
pinned Rekor key, and enforces `prior_release_hash` rollback. What does
**not** exist is a producer that obtains those proofs from **real
Sigstore** rather than synthesizing them, and a verifier configured with
**real** pinned roots.

Three constraints from prior decisions bound the design:

- **D0024 §2.2 / §3.2** pin the Fulcio root + Rekor key as **release
  config**, explicitly excluding runtime trust-root resolution ("a
  coordinated release picks up rotation explicitly").
- **D0024 §8** scoped the signing flow as build-infrastructure and
  assumed `cosign sign-blob` in CI. That assumption predates the landed
  manifest envelope (see §3) and is **revised** here.
- **D0041 §6.1** added the `PRODUCTION_ROOTS` tripwire: a shipped FFI
  build refuses caller-supplied roots and uses compiled-in roots that are
  `None` until provisioned. This decision provisions them (staging).

Two environmental facts (probed 2026-06-09): Sigstore staging is
network-reachable from the build host (`rekor.sigstage.dev` → 200), and
keyless signing **requires an OIDC identity** that cannot be driven
autonomously (interactive OAuth needs a human; ambient OIDC needs a CI
runner). This splits phase 2 into a verify-side slice that is provable
now and a sign-side slice gated on a CI identity (§7).

## Decision summary

| Question                     | Resolution                                                                                                                                                                                                             | §      |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| **Phasing**                  | Phase 2 = Sigstore **staging** (real keyless, real staging roots). Phase 3 = production (config + ceremony).                                                                                                           | §1     |
| **Where signing runs**       | **CI (GitHub Actions) ambient OIDC `id-token`** — no human OAuth, no long-lived secret. Developer-interactive (device-code) is the manual fallback.                                                                    | §2     |
| **Manifest signature model** | **PIVOTAL — recommend (A) preserve Ed25519 `COSE_Sign1`**, with Fulcio issuing an Ed25519 ephemeral cert; alternative (B) adopt Sigstore-native ECDSA-P256. Flagged for confirmation.                                  | §3     |
| **Signing client**           | Thin hand-rolled Fulcio + Rekor HTTP client in a **non-shipping** producer/CI tool (exact control over the Ed25519 `COSE_Sign1` + the Rekor entry; off the verify trust boundary). `sigstore-rs` considered, deferred. | §4     |
| **Trust-root provisioning**  | **Pin** the staging Fulcio root + Rekor key + CT-log key as baked-in constants (obtained once via the staging TUF repo). No runtime TUF (D0024 §2.2). Fills the `PRODUCTION_ROOTS` tripwire.                           | §5     |
| **Identity model**           | **CI workflow identity** (issuer = GHA OIDC, SAN = workflow URI) as the v1 release signer; developer-email identity is the manual alternative. Implies a verifier adaptation (§6).                                     | §2, §6 |
| **Verifier adaptations**     | SAN-**URI** identity (CI), **SCT** verification against the pinned CT-log key, and confirming the **Rekor entry-type binding** to the manifest.                                                                        | §6     |
| **v1 proof targets**         | **2a** (autonomous, no OIDC): verify a **real** Rekor staging proof against pinned staging roots. **2b** (OIDC-gated): a real CI keyless signing run that `verify_release` accepts.                                    | §7     |
| **Sigsum side**              | Real recruited log + witness pool is funding/people-gated (D0015 Q5); phase 2 keeps Sigsum synthetic or single-test-log, full recruitment deferred.                                                                    | §8     |

## 1. Phasing: staging first

Sigstore **staging** (`fulcio.sigstage.dev`, `rekor.sigstage.dev`,
`oauth2.sigstage.dev`, TUF `tuf-repo-cdn.sigstage.dev`) is a full,
independent Sigstore instance with its own trust roots. It gives a real
adversarial model — real CA, real transparency log, real OIDC — with zero
production-identity risk and a forgiving operational posture (staging keys
rotate, entries are disposable). Phase 3 (production:
`fulcio.sigstore.dev` / `rekor.sigstore.dev` / the production TUF root) is
the **same code** with different pinned roots + the real release identity;
it is a config + signing-ceremony change, not a schema change.

## 2. Where signing runs: CI ambient OIDC

The keyless signing event runs in **GitHub Actions** with
`permissions: id-token: write`. The runner requests an OIDC JWT from
`https://token.actions.githubusercontent.com` (audience `sigstore`),
presents it to Fulcio, and Fulcio issues a short-lived cert binding the
**ephemeral key** to the **workflow identity**. No human is in the signing
loop, no long-lived signing key exists, and the identity is reproducible
and auditable (it _is_ the workflow path). This is the standard "keyless
CI" model and is what D0024 §8 meant by "build-infrastructure owned."

A **developer-interactive** flow (Sigstore device-code against
`oauth2.sigstage.dev`, identity = a developer email) is the manual
fallback for local/emergency signing and for the very first staging
bring-up before the CI workflow exists. The verifier must accept whichever
identity model a given release pins (§6).

## 3. PIVOTAL — the manifest signature model

The landed producer signs the manifest as an **Ed25519 `COSE_Sign1`**
(`sign_manifest_envelope`, `produce.rs`), and the verifier extracts an
**Ed25519** key from the Fulcio leaf SPKI (`extract_ed25519_key`,
`fulcio.rs`) and verifies that COSE signature. Stock Sigstore (cosign) is
**ECDSA-P256** and signs **blobs** (not `COSE_Sign1`). So "use cosign"
(D0024 §8) and "the manifest is an Ed25519 COSE envelope" (what we built)
are in direct tension. Two coherent end-states:

**(A) Preserve Ed25519 `COSE_Sign1` — RECOMMENDED.** Fulcio issues a cert
for an **Ed25519** ephemeral key (Fulcio accepts Ed25519 CSRs). The
manifest stays a `COSE_Sign1`; the verifier's manifest-verify +
key-extract path is **unchanged** (the audited, tested security boundary).
The Rekor entry commits to the COSE bytes + the cert.

- _Pro:_ zero churn on the security-critical verify path; Cairn's uniform
  envelope (D0006/D0018) holds for the manifest like every other signed
  artifact; the change is confined to the producer/CI signer.
- _Con:_ stock `cosign` cannot produce it (Ed25519 + COSE), so the signer
  is hand-rolled (§4); the Rekor payload is non-standard (Cairn's verifier
  understands it, but `cosign verify` would not).

**(B) Adopt Sigstore-native ECDSA-P256.** The release manifest signature
becomes a detached P-256 signature over the canonical-CBOR manifest bytes
(cosign's `sign-blob` model); the Fulcio leaf carries a P-256 key; the
verifier extracts P-256 + verifies a detached sig (the `COSE_Sign1`
wrapper is dropped **for the release manifest only**; messaging /
trust-graph keep COSE).

- _Pro:_ the CI job is literally `cosign sign-blob`; standard Rekor
  `hashedrekord`; third parties can independently verify with stock
  Sigstore tooling.
- _Con:_ churn on the **security-critical** verify path — re-do Fulcio key
  extraction (P-256 SPKI) + manifest verification (detached P-256) + their
  tests; the release manifest diverges from Cairn's COSE envelope.

**Recommendation: (A).** Cairn's own logic (D0024 §3.1) keeps the
security-critical verifier project-owned + minimal and accepts hand-rolled
tooling **off** the trust boundary (SOCKS5, SMP, the Rekor _verifier_
itself). The signer is off that boundary; the verifier is on it. (A) keeps
churn off the boundary and preserves the uniform envelope. **This is the
one call worth confirming before code** — (B)'s ecosystem-interop +
cosign-simplicity is a legitimate counter-weight, and it is materially
cheaper to choose now than to migrate later.

## 4. Signing client: thin hand-rolled Fulcio + Rekor HTTP

Under (A), the signer (a host/CI tool — `cairn-release` real mode or a
sibling `cairn-sign` bin, **never shipped in the APK**) does, per release:

1. Read the CI ambient OIDC token (an env-provided JWT — no OAuth library).
2. Generate an **ephemeral Ed25519** keypair.
3. POST a Fulcio signing request (the Ed25519 public key + an
   OIDC-token-bound proof of possession) → receive the short-lived cert
   chain (leaf + intermediate) **with an embedded SCT**.
4. `COSE_Sign1`-sign the canonical-CBOR manifest with the ephemeral key
   (the existing `Sign1Builder` external-signer path), zeroize the key.
5. POST a Rekor entry committing to the COSE bytes + the cert → receive
   the inclusion proof + signed checkpoint.
6. Assemble the `ReleaseBundle` (the existing wire format) from the real
   cert DER + COSE bytes + Rekor proof; emit the staging `ReleaseRoots`
   (§5) — replacing the synthetic `mint_*` helpers.

`sigstore-rs` was considered: it provides Fulcio/Rekor/OAuth/TUF clients,
but its Ed25519 + custom-COSE-payload path is awkward (it is oriented to
its own bundle/blob format + ECDSA), and it is a heavy transitive tree
(D0021 pin-audit concern). Since the signer is non-shipping host tooling,
the hand-rolled HTTP (a handful of POSTs, mirroring the existing
hand-rolled Rekor _verifier_ + `cairn-sigsum-client` HTTP) gives exact
control over the COSE + Rekor entry shapes the verifier already expects.
Revisit if the hand-rolled Fulcio/Rekor surface grows.

## 5. Trust-root provisioning: pin, don't resolve at runtime

D0024 §2.2 excludes runtime trust-root resolution. Sigstore distributes
its trust roots as a TUF-signed `trusted_root.json` (Fulcio chains, Rekor
keys, CT-log keys, each with validity windows). Phase 2 uses TUF **once,
at provisioning time** (a host step, fetching the staging
`trusted_root.json` from `tuf-repo-cdn.sigstage.dev`), extracts the
current staging Fulcio root + Rekor public key + CT-log public key, and
**bakes them in** as the staging `ReleaseRoots` (the producer side) and
the verifier's `PRODUCTION_ROOTS` constant (the D0041 §6.1 tripwire
fill-point). Rotation is a coordinated release event (re-pin + ship), per
D0024 §2.2 — never a runtime fetch on the verify path.

## 6. Verifier adaptations phase 2 forces

The verifier is real but was built + tested against the **synthetic**
profile; real Sigstore differs in three concrete ways that are **new
verifier work**, not config:

1. **SAN-URI identity (if the CI-identity model, §2).** Today
   `san_has_email` matches an `rfc822Name`. A CI workflow identity is a
   SAN **URI** (`https://github.com/ORG/REPO/.github/workflows/...@REF`)
   plus GHA-specific Fulcio extension claims. The verifier must pin + match
   the URI identity. (A developer-email release needs no change.)
2. **SCT verification.** Real Fulcio certs embed a **Signed Certificate
   Timestamp** proving CT-log inclusion. The synthetic path has none, so
   the verifier does not check it. Full Sigstore verification verifies the
   SCT against the pinned CT-log key — this should be **added** (or its
   omission explicitly accepted as a documented residual).
3. **Rekor entry-type binding.** Confirm the exact Rekor entry shape the
   producer uploads (a `hashedrekord` / DSSE committing to the COSE bytes +
   cert) and that the verifier's inclusion check binds that entry to the
   manifest — not merely "an entry is included," but "the entry for **this**
   manifest is included."

These are tracked as the verify-side work items of phase 2, alongside the
producer signer (§4).

## 7. Proof targets

- **2a — autonomous, no OIDC (provable now).** Pin the real staging roots
  (§5); fetch a **real** existing Rekor staging inclusion proof
  (`rekor.sigstage.dev`, the `online-rekor` feature path) and verify it
  against the real pinned Rekor staging key. Milestone: the verifier
  checks **attacker-unforgeable** Rekor data (real Merkle tree, real log
  signature) — the first non-synthetic verification, and the half that
  delivers consumer-side forgery-resistance. De-risks 2b (real roots + a
  known-good real entry to test against).
- **2b — OIDC-gated (CI milestone).** A real GitHub Actions staging keyless
  signing run produces a real `ReleaseBundle` that `verify_release` accepts
  against the pinned staging roots — end-to-end real-Sigstore. Gated on the
  GHA workflow + the staging OIDC identity setup (the user's call on
  identity, §2). This is the `auditable-release` CI job D0041 §6.2 names.

## 8. The other §6.1 hard blocker: Sigsum recruitment

D0041 §6.1's _second_ hard blocker — a real recruited Sigsum log + 2-of-3
witness pool (D0015, Q5) — is **funding/people-gated**, not code. Phase 2
(this decision) makes the **Rekor/Fulcio** anchor real; the Sigsum release
anchor stays synthetic (or a single self-run test log) until witnesses are
recruited. A release is forgery-resistant against the Sigstore half well
before the Sigsum half; the cross-log audit property (D0024 §200) fully
activates only when both are real. Tracked separately.

## 9. Reversibility

The pinned roots (§5) and the producer real-mode are additive + per-release
config — re-pinnable, and the synthetic mode stays for tests + offline
development. The **§3 manifest-signature-model** call is the one
hard-to-reverse commitment: choosing (A) vs (B) sets the Fulcio key
algorithm, the Rekor entry type, and whether the verify path changes.
Migrating A→B (or back) after a real release is a coordinated
schema-and-verifier change. Hence the explicit confirmation request.

## 10. Cross-references

- `docs/decisions/D0024-sigstore-release-verification.md` — the verifier
  contract; §8 (signing flow, **revised** here) + §2.2 (root pinning).
- `docs/decisions/D0041-release-producer-pipeline.md` — phase 1 + §6.1
  (this decision is the named phase-2 hard blocker) + the `PRODUCTION_ROOTS`
  tripwire this fills.
- `docs/decisions/D0023-sigsum-integration.md` — the Sigsum half (§8) +
  the hand-rolled HTTP-client pattern §4 mirrors.
- `docs/decisions/D0015-v1-release-security-posture.md` — the posture +
  the Q5 witness-recruitment funding gate (§8).
- `docs/decisions/D0021-library-pin-audit.md` — the dep-weight discipline
  behind the `sigstore-rs` deferral (§4).
