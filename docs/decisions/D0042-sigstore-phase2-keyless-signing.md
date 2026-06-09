# D0042 — Sigstore phase 2: real keyless signing + pinned staging trust roots (the D0041 §6.1 hard blocker)

**Status:** Accepted (design; phase-2 staging). The pivotal manifest-signature fork (§3) was resolved to **(B) Sigstore-native ECDSA-P256** on 2026-06-09.
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
- **D0024 §8** scoped the signing flow as build-infrastructure and assumed
  `cosign sign-blob` in CI. §3 below **confirms** that, and revises the
  manifest representation to match (the manifest stops being a
  `COSE_Sign1`).
- **D0041 §6.1** added the `PRODUCTION_ROOTS` tripwire: a shipped FFI build
  refuses caller-supplied roots and uses compiled-in roots that are `None`
  until provisioned. This decision provisions them (staging).

Two environmental facts (probed 2026-06-09): Sigstore staging is
network-reachable from the build host (`rekor.sigstage.dev` → 200), and
keyless signing **requires an OIDC identity** that cannot be driven
autonomously (interactive OAuth needs a human; ambient OIDC needs a CI
runner). This splits phase 2 into a verify-side slice that is provable now
and a sign-side slice gated on a CI identity (§7).

## Decision summary

| Question                     | Resolution                                                                                                                                                                                                                                                                                                                                                                                               | §      |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| **Phasing**                  | Phase 2 = Sigstore **staging** (real keyless, real staging roots). Phase 3 = production (config + ceremony).                                                                                                                                                                                                                                                                                             | §1     |
| **Where signing runs**       | **CI (GitHub Actions) ambient OIDC `id-token`** — no human OAuth, no long-lived secret. Developer-interactive (device-code) is the manual fallback.                                                                                                                                                                                                                                                      | §2     |
| **Manifest signature model** | **(B) Sigstore-native: a detached ECDSA-P256 signature over the canonical-CBOR manifest** (cosign `sign-blob` model). The release manifest **leaves** the `COSE_Sign1` envelope; messaging/trust-graph keep COSE. Chosen for **independent verifiability** (§3).                                                                                                                                         | §3     |
| **Signing client**           | **Stock `cosign sign-blob`** in CI; `cairn-release` **ingests** cosign's outputs (cert + detached sig + Rekor bundle) into the `ReleaseBundle`. No bespoke keyless signer.                                                                                                                                                                                                                               | §4     |
| **Trust-root provisioning**  | **Pin** real Fulcio/Rekor/CT-log anchors as baked-in constants, no runtime TUF (D0024 §2.2). **As of 2026-06-09:** **both staging and production are coherent Fulcio + CT + Rekor triples** (every public-log transparency anchor pinned + proven). `PRODUCTION_ROOTS` stays `None` pending non-log pieces only (OIDC identity = per-release config / governance; Sigsum = funding — see §5 status, 2b). | §5     |
| **Identity model**           | **CI workflow identity** (issuer = GHA OIDC, SAN = workflow URI) as the v1 release signer; developer-email identity is the manual alternative.                                                                                                                                                                                                                                                           | §2, §6 |
| **Verifier adaptations**     | Fulcio **P-256** key extraction; **detached-P-256** manifest verify (manifest leaves COSE); `ReleaseBundle` wire change; SAN-**URI** identity; **SCT** verification; Rekor entry-type binding.                                                                                                                                                                                                           | §6     |
| **v1 proof targets**         | **2a** (autonomous, no OIDC, manifest-model-independent): verify a **real** Rekor staging proof against pinned staging roots. **2b** (OIDC-gated): a real CI cosign signing run that `verify_release` accepts.                                                                                                                                                                                           | §7     |
| **Sigsum side**              | Real recruited log + witness pool is funding/people-gated (D0015 Q5); phase 2 keeps Sigsum synthetic or single-test-log, full recruitment deferred.                                                                                                                                                                                                                                                      | §8     |

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

A **developer-interactive** flow (cosign device-code against
`oauth2.sigstage.dev`, identity = a developer email) is the manual
fallback for local/emergency signing and for the very first staging
bring-up before the CI workflow exists. The verifier must accept whichever
identity model a given release pins (§6).

## 3. Manifest signature model — (B) Sigstore-native ECDSA-P256

**Decision: the release manifest signature is a detached ECDSA-P256
signature over the canonical-CBOR `ReleaseManifest` bytes (cosign
`sign-blob` model).** The Fulcio leaf carries the P-256 ephemeral key; the
verifier extracts P-256 and verifies the detached signature. The
`COSE_Sign1` wrapper is dropped **for the release manifest only** (D0006
messaging + trust-graph artifacts keep COSE).

**The fork.** The landed producer signed the manifest as an Ed25519
`COSE_Sign1` (`sign_manifest_envelope`), and the verifier extracted Ed25519
(`extract_ed25519_key`). Stock Sigstore (cosign) is ECDSA-P256 + blob
format. So "use cosign" (D0024 §8) and "the manifest is an Ed25519 COSE
envelope" cannot both hold. The alternative considered:

> **(A) Preserve Ed25519 `COSE_Sign1`** — Fulcio issues an Ed25519
> ephemeral cert (it supports Ed25519 CSRs); the manifest stays COSE; the
> verify path is unchanged; the keyless signer is hand-rolled (cosign
> cannot produce Ed25519 + COSE). _Rejected_ — see below.

**Why (B), on the security merits.** The deciding axis is **independent
verifiability**, and it is close to this project's thesis:

- **Transparency is only as strong as the set of independent watchers.** A
  transparency log detects a compromised or coerced maintainer's rogue
  signing _because other parties watch it_. Under (A) the Rekor entry is
  Cairn-specific — only Cairn's own verifier can interpret it, so no third
  party, `cosign verify-blob`, or automated `rekor-monitor` can audit it.
  That collapses detection to "trust Cairn to police itself," exactly the
  trust the log exists to remove. Under (B), anyone can run
  `cosign verify-blob --certificate-identity … --certificate-oidc-issuer …`
  and standard Rekor monitors can watch the release identity. Cairn's
  threat model (at-risk users, plausible maintainer coercion) is the one
  where this matters **most**.
- **Less bespoke code in the release path.** (B) leans on cosign — widely
  audited, Sigstore-maintained — instead of a hand-rolled Fulcio/Rekor
  keyless signer.
- **The crypto-primitive edge for (A) is minor and neutralized here.**
  Ed25519 is the more misuse-resistant primitive in general, but ECDSA's
  catastrophic failure mode (nonce reuse) **cannot occur** with a
  single-use ephemeral key, and ECDSA malleability is neutralized by the
  Rekor hash pin + the verifier's exact-bytes check. Near-zero
  differentiator in the keyless context.
- **The cost of (B) is work, not steady-state security — and the work is
  reduced.** (B) changes the security-critical verify path (Fulcio P-256
  extraction + detached-sig verify), which is real churn + transient
  bug-risk. But `cairn-sigstore-verify` **already** verifies ECDSA-P256 (the
  Rekor checkpoint is a C2SP signed note verified with P-256; `p256` is
  already a workspace pin, D0024 §3.2) — so (B) **reuses** an audited
  in-tree primitive rather than introducing one. A well-tested P-256 verify
  path is not less secure than an Ed25519 one.

**The one caveat (the condition under which (A) would have won):** (B)'s
transparency advantage is _latent_ until independent verification is
actually cultivated — publish the `cosign verify-blob` recipe, register the
release identity with a Rekor monitor. If releases were only ever to be
checked by Cairn's own on-device verifier, (B) would pay churn for an
unused property. The pipeline's whole purpose (trust-minimized, auditable
releases) implies that intent, so (B) is correct.

## 4. Signing client: stock cosign in CI; `cairn-release` ingests

(B) makes the CI signing step the standard keyless flow, with **no bespoke
signer**:

1. CI (GitHub Actions, `id-token: write`) builds the artifacts +
   `cairn-release build-manifest` emits the canonical-CBOR manifest bytes
   (the blob to sign).
2. `cosign sign-blob --yes manifest.cbor` runs with the staging Fulcio /
   Rekor endpoints + the ambient OIDC token → produces the **detached
   P-256 signature**, the **Fulcio cert** (leaf + chain, with embedded
   SCT), and a **Rekor entry** (`hashedrekord`) with its inclusion proof +
   signed checkpoint.
3. `cairn-release ingest-cosign` **ingests** those outputs (cert PEM,
   base64 signature, raw Rekor entry JSON) + the pinned roots into the
   existing `ReleaseBundle` wire format (§6) + emits a `release-roots.json`
   pinning the CI **URI** identity (§6.4) + the real Sigstore roots.

`cairn-release` stays a **packager**: it never holds a signing key, never
talks to the OIDC provider, and never sees a long-lived secret — cosign +
the CI runner own those. `sigstore-rs` was considered as an in-process
alternative but is unnecessary given cosign already does the flow and the
producer is non-shipping host tooling; revisit only if shelling to cosign
proves operationally awkward.

**Landed — ✓ (2026-06-09).** The two subcommands above are implemented
(`cairn-release build-manifest` + `cairn-release ingest-cosign`,
`produce::ingest_cosign`): `ingest-cosign` parses the real cosign outputs
(minimal PEM reader → cert DER; base64 → detached sig DER; the verifier's
`parse_rekor_log_entry` → Rekor bundle + `integratedTime`) and assembles a
`ReleaseBundle`. **The Sigstore proofs are real; the Sigsum proof is minted
synthetically over the real `release_leaf_hash`** (the recruited log is
funding-gated, §8) and pinned in `release-roots.json` alongside the real
Sigstore roots — so a `verify_release` over the ingested bundle proves the
whole **Sigstore** half end-to-end against real keyless signing, with only
the Sigsum step on synthetic roots until §8. Unit-tested in `produce.rs`
against the real Fulcio-GHA cert + production Rekor vectors (structural
assembly + round-trip); the full verify-accept is what proof target 2b's
real CI run exercises.

## 5. Trust-root provisioning: pin, don't resolve at runtime

D0024 §2.2 excludes runtime trust-root resolution. Sigstore distributes
its trust roots as a TUF-signed `trusted_root.json` (Fulcio chains, Rekor
keys, CT-log keys, each with validity windows). Phase 2 uses TUF **once,
at provisioning time** (a host step, fetching the staging
`trusted_root.json` from `tuf-repo-cdn.sigstage.dev`), extracts the current
staging Fulcio root + Rekor public key + CT-log public key, and **bakes
them in** as the staging `ReleaseRoots` (producer side) and the verifier's
`PRODUCTION_ROOTS` constant (the D0041 §6.1 tripwire fill-point). Rotation
is a coordinated release event (re-pin + ship), per D0024 §2.2 — never a
runtime fetch on the verify path.

**Status (2026-06-09) — the staging trust set is now coherent;
`PRODUCTION_ROOTS` stays `None` pending production-only pieces.** The real
anchors are pinned as feature-gated `&str` constants in
`cairn_sigstore_verify::anchors` (the `pinned-anchors` cargo feature),
**separate** from `cairn-uniffi`'s `PRODUCTION_ROOTS` (which stays `None` —
the tripwire is unfilled). Each constant `include_str!`s an already-proven
`tests/vectors/` file and is re-bound by a self-validating anchors test (the
CT-key constants re-verify a real embedded SCT; the wrong key fails closed).

What is real and **coherent within an environment**:

- **Staging — a full Fulcio + CT-log + Rekor triple**, all from sigstage,
  each proven against real log signatures: the chain validates a real
  staging leaf (`fulcio_staging_vector.rs`); the CT key verifies a real
  staging leaf's embedded SCT (`staging_sct_vector.rs`, the same-environment
  proof that **closed the former staging-CT-key gap** — a fresh 2026 staging
  leaf, since the 2022 one predates SCT embedding); the Rekor key verifies a
  real staging inclusion proof (`rekor_staging_vector.rs`).
- **Production — a full Fulcio + CT-log + Rekor triple** (from the public
  production logs, the same GHA signing event): the CT key verifies the GHA
  leaf's SCT, and the Rekor key verifies that event's real inclusion proof
  (`tests/rekor_production_vector.rs`, a 25-node audit path — the verifier's
  RFC 6962 math proven at production tree scale).

**Every transparency anchor capturable from public logs is now pinned +
proven in both environments.** What is still **missing** for a shippable
_production_ root set — why `PRODUCTION_ROOTS` stays `None` — is no longer a
log capture but: (a) **no production OIDC identity** (the project's real
CI/maintainer `iss`+SAN, a phase-3 governance decision — and a per-release
config value, not a pinned root); (b) **no Sigsum log key / witness pool**
(§8, funding-gated). A staging- or production-targeted verifier now needs
only its OIDC-identity config + the Sigsum anchor on top of these pinned
triples. The SCT-enforcement **wiring** is complete and reachable (see §6
item 5): a pinned CT-log key is a config input
(`SigstoreVerifierConfig.ctlog_pubkey_pem`) threaded from the FFI
(`ReleaseRootsRecord.ctlog_pubkey_pem`, defaulted `None`), so the moment a
matching CT key reaches the config, SCT verification is mandatory by
construction — no code change.

**Provisioning requirement (from the 2026-06-09 adversarial review).** A
two-lens adversarial review of the phase-2 verifier (SCT DER byte-surgery +
the orchestration) found **no bugs** — no panics on attacker-controlled
certs, no forgery/spurious-accept, no bypass — and one provisioning hazard:
because `ctlog_pubkey_pem` is `Option`, a future provisioner could pair a
**real** Fulcio root with `None` and silently disable the SCT defense (the
guard against a Fulcio leaf that was never CT-logged). The mitigation is a
hard rule, enforced at provisioning time rather than by a brittle
root-fingerprint check: **filling `PRODUCTION_ROOTS` (or any real-Fulcio
config) MUST set the matching CT-log key.** This is now stated at both the
config field and the `PRODUCTION_ROOTS` const. The review's minor
robustness notes (explicit length-prefix guards in the precert blob builder;
a `der_len`/`read_tlv` length-domain assert) were applied the same day.

## 6. Verifier adaptations phase 2 forces

The verifier is real but was built + tested against the **synthetic Ed25519
COSE** profile; (B) + real Sigstore differ in concrete ways that are **new
verify-side work**, not config. **All six items landed 2026-06-09** — the
B-model verifier core (1–3), CI SAN-URI identity (4), embedded-SCT
verification + its mandatory-path wiring (5), and Rekor entry-type binding
(6). What remains is provisioning (§5), not verifier code.

1. **Fulcio P-256 key extraction — ✓ LANDED.** `extract_ed25519_key` →
   `extract_p256_key` (`VerifyingKey::from_public_key_der` over the leaf
   SPKI, reusing the in-tree `p256` pin; validates `id-ecPublicKey` +
   `prime256v1` + on-curve point in one call). `rejects_non_ed25519_leaf_key`
   inverted to `rejects_non_p256_leaf_key`. **Proven against a real cert:**
   `tests/fulcio_staging_vector.rs` extracts the P-256 key from a genuine
   Sigstore **staging** Fulcio leaf (`tests/vectors/fulcio-staging/`) and
   asserts it equals the leaf's own SPKI key, with negatives confirming the
   OIDC issuer/email pins + validity-window gate reject the real cert when
   mis-pinned. This is the real-cert Fulcio proof §7 deferred here.
2. **Detached-P-256 manifest verify — ✓ LANDED.** The release manifest is
   no longer a `COSE_Sign1`; `verify_release` parses the manifest from
   `manifest_bytes` and verifies a **detached** P-256 signature
   (`Signature::from_der` + `VerifyingKey::verify`) over those bytes against
   the Fulcio-bound key — no `cairn-envelope` COSE verify, no external AAD
   (cosign `sign-blob` has none).
3. **`ReleaseBundle` wire change — ✓ LANDED.** `manifest_envelope_bytes`
   (COSE) → `manifest_bytes` + `manifest_signature` (detached, wire key 8).
   The `release_leaf_hash` primitive rebinds to `SHA-256(detached signature)`
   via a shared `cairn_sigsum_client::leaf_hash_for_signature_bytes` (the
   COSE path now also funnels through it — "one audited primitive, three use
   cases"). The canonical-CBOR decode-strictness gate (D0041 §6.3) applies
   unchanged to the new fields. The change is transparent to `cairn-uniffi` +
   the fuzz harness (opaque bytes through `from_canonical_cbor`). The
   `cairn-release` producer detached-signs with a P-256 dev key (lifted from
   its rcgen leaf via PKCS#8), and `produced_bundle_verifies_against_its_own_roots`
   proves the full producer→verifier round-trip end-to-end.
4. **SAN-URI identity (CI model, §2) — ✓ LANDED (2026-06-09).** Added
   `ExpectedIdentity{Email,Uri}` + `validate_cert_chain_with_identity`, so
   the verifier pins + matches a SAN **URI** CI workflow identity
   (`https://github.com/ORG/REPO/.github/workflows/…@REF`) alongside the
   existing `rfc822Name` email path (`san_has_uri`; new error
   `OidcIdentityMismatch`). `validate_cert_chain` stays a thin `Email`
   wrapper — zero churn to the developer-email path. **Proven against a
   real production GitHub Actions keyless cert** (`tests/fulcio_gha_vector.rs`,
   `tests/vectors/fulcio-gha/`, captured from production Rekor logIndex
   1767842880): accepts the pinned URI identity over the real 3-level
   chain, rejects a wrong URI / the email matcher / a wrong issuer / a
   post-expiry signing time. **Wired into `verify_release` — ✓ (2026-06-09):**
   the config gained `expected_oidc_san_uri: Option<String>` (threaded from
   the FFI `ReleaseRootsRecord` + `cairn-release` `oidc_san_uri`); `Some`
   pins the CI URI, `None` keeps the email path. Without this the keyless CI
   model could not actually drive an end-to-end release verify — the URI
   matcher was a standalone primitive. `tests/verify_release.rs` proves a
   URI-identity release verifies, a wrong URI rejects (`OidcIdentityMismatch`),
   and an email-pinning verifier rejects a URI-only cert.
5. **SCT verification — ✓ LANDED (2026-06-09).** Embedded-SCT verification
   per RFC 6962 §3.2 (`sct::verify_embedded_sct`): parse the SCT from the
   `1.3.6.1.4.1.11129.2.4.2` extension, reconstruct the **precert** TBS
   (the leaf TBS with the SCT extension excised + DER re-encoded), build the
   `digitally-signed` precert blob (issuer-key-hash + 24-bit-length TBS),
   and ECDSA-P256-verify it against the **pinned** CT-log key (matched by
   log ID = `SHA-256(SPKI)`). **No new dependency** — pure byte-work on the
   in-tree `p256` + `sha2`; the precert rebuild is validated **byte-exact**
   by the real CT-log signature itself (a wrong-by-one-byte splice fails
   the ECDSA check). **Proven against the real GHA cert's SCT + the real
   pinned CT-log key** (`tests/sct_vector.rs`): the production SCT verifies;
   wrong CT key, wrong issuer (issuer is bound into the signed blob), and an
   SCT-less cert all reject. **Wiring into the mandatory verify path — ✓
   LANDED (2026-06-09).** `verify_release` step 3b enforces the SCT whenever
   a CT-log key is pinned: it decodes the pinned key, locates the leaf's
   issuer in the pinned Fulcio chain (`fulcio::issuer_cert_der_for`), and
   calls `verify_embedded_sct` — any failure (incl. a leaf with **no** SCT →
   `SctMissing`) aborts the release. The key is a config input
   (`SigstoreVerifierConfig.ctlog_pubkey_pem: Option<…>`), threaded from the
   FFI (`ReleaseRootsRecord.ctlog_pubkey_pem`, defaulted `None`); `None`
   skips SCT (synthetic rcgen leaves carry none — D0041 §6.1 dev path).
   `tests/verify_release.rs::enforces_sct_when_a_ctlog_key_is_pinned` proves
   a pinned key forces SCT and rejects the no-SCT synthetic leaf. The
   primitive is now proven in **both** environments: production
   (`tests/sct_vector.rs`) and **staging** (`tests/staging_sct_vector.rs`, a
   real 2026 staging leaf + the staging CT-log key — see §5 status).
   Enforcement becomes active in a shipped build the moment §5 provisions a
   matching pinned CT key into the verifier config.
6. **Rekor entry-type binding — ✓ LANDED (2026-06-09).** Confirmed the
   gap: the verifier proved Rekor _inclusion_ of a producer-supplied leaf
   hash but never bound it to the signing event, so a valid inclusion proof
   for an unrelated logged entry would pass. Closed it: `verify_release`
   step 4 now reconstructs the `hashedrekord` leaf hash from the manifest's
   artifact hash + the detached signature + the Fulcio cert
   (`rekor::hashedrekord_leaf_hash` / `build_hashedrekord_body`) and
   requires it to equal the proven-included leaf (new error
   `RekorEntryBindingFailed`). The canonical-body reconstruction (sorted-key
   JSON + cosign-exact PEM re-encode + base64) is validated **byte-exact**
   against a real captured production entry (`tests/rekor_gha_binding.rs`,
   no new dependency — `serde_json` was already pinned), and
   `tests/verify_release.rs` proves a valid proof for a _different_ signing
   event is rejected. The `cairn-release` producer emits the bound leaf.

## 7. Proof targets

- **2a — ✓ PROVEN (2026-06-09).** A real Sigstore **staging** Rekor entry
  (a frozen inactive-shard `hashedrekord` + its inclusion proof + signed
  checkpoint) and the staging Rekor **P-256** public key were captured as
  checked-in vectors (`tests/vectors/rekor-staging/`), and
  `parse_rekor_log_entry` + `verify_rekor_inclusion` verify them **offline**
  against the pinned real key (`tests/rekor_staging_vector.rs`): the
  checkpoint signature validates under the real staging key AND the RFC 6962
  audit path reconstructs to the signed root. Negatives confirm rejection
  under a non-pinned key + a tampered audit node. **Milestone:** the first
  attacker-**unforgeable** verification in the release stack — the
  hand-rolled offline Rekor verifier (D0024 §3) is validated against the
  real production-shaped Rekor wire format, not just its own synthetic
  fixtures. Independent of §3; pure-offline (no network at test time, no
  `online-rekor` feature). De-risks 2b (real key + a known-good real entry
  to test against).
- **2a — Fulcio half + B-model verifier core — ✓ PROVEN (2026-06-09).**
  The §6 items 1–3 landed: the verifier now extracts a **real** Sigstore
  staging Fulcio leaf's **P-256** key end-to-end (chain signature, validity
  window, OIDC issuer/email pins, RFC 5280 leaf constraints) and verifies a
  detached P-256 manifest signature against it — `tests/fulcio_staging_vector.rs`
  (5 tests over `tests/vectors/fulcio-staging/`, the first non-synthetic
  Fulcio extraction) plus the synthetic producer→verifier round-trip
  (`cairn-release`) and the B-model `verify_release` harness.
- **2a — CI identity + CT transparency (§6 items 4–5) — ✓ PROVEN
  (2026-06-09).** Against a **real production GitHub Actions keyless
  certificate** (captured from production Rekor logIndex 1767842880,
  `tests/vectors/fulcio-gha/`): the verifier matches the SAN **URI**
  workflow identity over the real 3-level Fulcio chain
  (`tests/fulcio_gha_vector.rs`), and verifies the cert's **embedded SCT**
  against the real **pinned CT-log key** via a hand-rolled RFC 6962 §3.2
  precert reconstruction — validated byte-exact by the real CT-log
  signature, with no new dependency (`tests/sct_vector.rs`). This is the
  identity model Cairn's own CI releases will use (§2) plus the
  CT-inclusion transparency check. **Anchors pinned + SCT wired — ✓
  (2026-06-09).** The real anchors are baked as feature-gated constants
  (`cairn_sigstore_verify::anchors`, `pinned-anchors`), each `include_str!`
  of the proven vector and bound by `anchors::tests` (each CT-key constant
  re-verifies a real embedded SCT); SCT verification is now wired into the
  mandatory `verify_release` path (§6 item 5), enforced whenever a CT-log key
  is pinned. **Both transparency triples now complete — ✓ (2026-06-09):** the
  staging-CT gap closed with a fresh real staging leaf + staging CT-log key
  (`tests/staging_sct_vector.rs`), and the production Rekor key was captured +
  proven against a real 25-node production inclusion proof
  (`tests/rekor_production_vector.rs`) — so **staging and production are each
  a coherent Fulcio + CT + Rekor triple**, every public-log anchor pinned.
  **Remaining (deferred to 2b):** `PRODUCTION_ROOTS` stays `None` for
  **non-log** reasons only — the production OIDC identity (per-release config
  / governance) and the Sigsum anchor (funding-gated) — not for any missing
  capture. SCT enforcement is dark in a shipped build only for lack of a
  matching pinned key reaching the config, not for lack of wiring.
- **2b — OIDC-gated (CI milestone).** A real GitHub Actions staging
  `cosign sign-blob` run produces a real `ReleaseBundle` that
  `verify_release` accepts against the pinned staging roots —
  end-to-end real-Sigstore. Gated on the GHA workflow + the staging OIDC
  identity setup. This is the `auditable-release` CI job D0041 §6.2 names.

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
development. The §3 manifest-signature-model decision (B) is the one
hard-to-reverse commitment — it sets the Fulcio key algorithm, the Rekor
entry type, the `ReleaseBundle` wire shape, and the verify path. Migrating
B→A after a real release is a coordinated schema-and-verifier change. (A)
was considered and rejected (§3); the choice is recorded so a future
revisit starts from the reasoning, not a blank slate.

## 10. Cross-references

- `docs/decisions/D0024-sigstore-release-verification.md` — the verifier
  contract; §8 (signing flow, **revised** here) + §2.2 (root pinning) +
  §3.2 (the in-tree P-256 the §3 decision reuses).
- `docs/decisions/D0041-release-producer-pipeline.md` — phase 1 + §6.1
  (this decision is the named phase-2 hard blocker) + the `PRODUCTION_ROOTS`
  tripwire this fills + §6.3 (decode strictness, applies to the new fields).
- `docs/decisions/D0023-sigsum-integration.md` — the Sigsum half (§8).
- `docs/decisions/D0015-v1-release-security-posture.md` — the posture +
  the Q5 witness-recruitment funding gate (§8).
- `docs/decisions/D0021-library-pin-audit.md` — the dep-weight discipline
  behind the `sigstore-rs` deferral (§4).
