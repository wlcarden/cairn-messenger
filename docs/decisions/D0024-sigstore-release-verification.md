# D0024 — cairn-sigstore-verify: release-artifact identity verification + Rekor inclusion + Sigsum-anchored release log composition

**Status:** Accepted (Rekor checkpoint algorithm revised 2026-05-30)
**Date:** 2026-05-29

> **Revision 2026-05-30 — Rekor checkpoint is ECDSA P-256, not Ed25519.**
> The original §3.2 stated the Rekor checkpoint verify was "Merkle path
>
> - Ed25519 verify," and the skeleton implied reuse of `cairn-crypto`
>   (Ed25519-only). The public `rekor.sigstore.dev` log signs its
>   [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint)
>   [signed note](https://c2sp.org/signed-note) with an **ECDSA P-256**
>   key (signature type `0x02`). An Ed25519 verifier would compile and
>   pass its own tests but never verify a real Rekor checkpoint.
>
> **Correction (now implemented + tested):**
>
> - The Rekor checkpoint signature is verified with **ECDSA P-256**
>   (new verify-only `p256` workspace pin per the revised §6.5), not
>   Ed25519. `cairn-crypto` has no P-256, so this is a deliberate new
>   audited curve in the verify-only trust path.
> - The checkpoint is a C2SP signed note: the signed body is
>   `origin\n` + `<tree_size>\n` + `<base64(root_hash)>\n`; the tree
>   size + root hash used for the inclusion proof are parsed out of the
>   **signature-verified** note bytes (not a separate unsigned field).
> - `RekorBundle` is corrected to carry the exact signed `checkpoint_note`
>   bytes + the DER ECDSA signature (the original skeleton carried a bare
>   signature with no signed body, which cannot verify).
> - The RFC 6962 inclusion proof (Merkle path, `0x00`/`0x01` domain
>   prefixes) is unchanged and dependency-free.
>
> §1 (OIDC pins), §2 (Fulcio root), §4 (manifest schema), §5 (Sigsum
> composition), §7 (error surface) are **unchanged**. Corrected claims
> are marked inline with `[Revised 2026-05-30]`.

## Context

D0018 §8.6 enumerates `cairn-sigstore-verify` in the workspace layout but does not specify which Sigstore Rust crate to consume vs. which surfaces to own in-project, how Fulcio's trust root pins, how Rekor inclusion proofs verify, what release-manifest schema the project signs, or how the verification composes with the D0023 Sigsum substrate.

D0015 commits the v1 release-security stack:

1. Long-lived APK signing key (Android signature continuity; rotation via APK Signature Scheme v3 if compromised).
2. **Per-release Sigstore identity-based signing** on top of the APK key. OIDC provider is U.S.-based in v1 per design brief §5.5 + §3.4; the jurisdictional placement is retained, not removed.
3. **Rekor transparency log entries** for all release signatures (Sigstore's standard).
4. **Sigsum-anchored release log.** Witness cosignatures via the witness pool D0023 already substrated.
5. Multi-channel distribution (F-Droid primary, Accrescent, project-controlled direct download).

This decision specifies the verification half of items 2–4: what code in `cairn-sigstore-verify` reads a candidate release artifact and validates it against Fulcio, Rekor, and the Sigsum-anchored release log before the rest of the application trusts the artifact.

This decision does NOT specify:

- The long-lived APK signing key custody / rotation (item 1) — Android-shell concern, not Rust-core.
- The release signing flow (CI-side OIDC token request, Sigstore signing event production) — release-pipeline concern, not verifier-side.
- F-Droid / Accrescent / direct-download channel selection logic (item 5) — Android-shell concern.
- The witness pool composition or witness count for the release log — D0023 §3 already pins (minimum 3 witnesses, 2-of-3 acceptance), and D0015 commits the same pool serves both trust-graph and release-log surfaces.

## Decision summary

| Concern                           | Decision                                                                                                                                                                                       | Rationale link |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| **OIDC identity to verify**       | Pinned per-project identity claim (`iss` + `email` for v1's U.S.-based provider); claim values shipped in the verifier config baked into each release                                          | §1             |
| **Fulcio root trust**             | Pinned root certificate bundled with the release; rotation is a coordinated release event (same posture as the witness pool — pool changes ride releases per D0023 §3.3)                       | §2             |
| **Rekor verification**            | Project-owned Rust verifier: inclusion proof check (Merkle path) + signed checkpoint verify against a pinned Rekor public key. No `sigstore-rs` shim in the verify path                        | §3             |
| **Release manifest**              | Canonical-CBOR `ReleaseManifest` per D0018 §2.3 — version, sha256 of each release artifact, build provenance hashes. Signed via Sigstore; logged in Rekor + Sigsum                             | §4             |
| **Sigstore + Sigsum composition** | The Sigstore-signed manifest's signature bytes feed the D0023 leaf-hash schema: `release_leaf_hash = SHA-256( signature_bytes( signed_manifest ) )`. Same composition as trust-graph leaves    | §5             |
| **Verifier crate layout**         | `cairn-sigstore-verify` owns: Fulcio cert chain validation, Rekor inclusion + checkpoint verify, manifest decode + signature verify. Depends on `cairn-sigsum-client` for the release-log half | §6             |
| **HTTPS transport**               | Same workspace-pinned `reqwest` as D0023 §2.1 — `default-features = false`, `features = ["rustls-tls", "json"]`                                                                                | §6             |
| **Async surface**                 | `async fn` methods, same pattern as `SigsumClient` per D0018 §4.1                                                                                                                              | §6             |
| **Retry policy**                  | Same `RetryBudget` type as D0023 §5.3 (re-exported from `cairn-sigsum-client`); max-retries default 5 for Rekor + Fulcio fetches                                                               | §6             |
| **Air-gapped verification**       | Manifest + Rekor entry + Sigsum proof + witness cosignatures all ship as bundled release artifacts alongside the APK. A verifier with the pinned trust roots can verify offline                | §6             |
| **Failure surface**               | `SigstoreVerifyError` per D0018 §4.2 — indices, lengths, type tags only; no `Vec<u8>` payloads; no peer-supplied strings; no cert / signature material in error bodies                         | §7             |
| **OIDC issuance log audit**       | Out-of-scope for the Rust core (operational; project-side log of when the developer actually signed, compared against Rekor entries). Named in D0015 + design brief §5.5                       | §8             |
| **Bring-Your-Own-OIDC-provider**  | Out-of-scope for v1. The pinned provider is per-release config; switching providers is a coordinated release event                                                                             | §8             |

---

## 1. OIDC identity model

### 1.1 Decision

The verifier checks the Fulcio-issued signing certificate's embedded OIDC claims against values pinned in the release's bundled config:

- **`iss`** (OIDC issuer URL) — must equal the pinned provider URL for the release.
- **`email`** (the developer's verified email) — must equal the pinned developer-identity string for the release.

Both pins ship with the release (in the bundled `release_config.toml` analog to `witnesses.toml` per D0023 §3.3). The verifier rejects any artifact whose certificate's claims do not match the pinned values.

### 1.2 Rationale

Three properties matter:

1. **Defense against OIDC provider compromise within scope.** If the OIDC provider issues a token for the developer's identity to an attacker, the attacker can produce a Sigstore-signed artifact whose Fulcio cert names the developer's email + the configured issuer. The verifier alone cannot distinguish a legitimate developer-signed artifact from a coerced-provider artifact; defense at this layer is incomplete by design (the OIDC provider is in the trust surface per design brief §3.4). The pin defends against a different attack: an attacker who tries to ship an artifact signed by a different OIDC identity (a fresh attacker-controlled email at the same issuer, or a developer's email at a different issuer) is rejected.
2. **No runtime identity resolution.** The verifier does not query the OIDC provider directly. It reads the cert's claims, compares them against the pinned strings, and returns a typed error if they do not match. No network call to the OIDC provider at verify time — the only network calls are to Rekor and (optionally; see §6.4) Fulcio's checkpoint endpoint.
3. **OIDC provider switching is a release event.** Per D0015, v1 ships with a U.S.-based OIDC provider with the explicit acknowledgment that this places U.S. legal process in the effective trust surface. A future release may pin a different provider; that's a coordinated event (new release with new `release_config.toml` value), not a runtime decision the verifier handles.

### 1.3 Cross-protocol attack surface

If the same developer identity is used to sign other Sigstore-attested artifacts (e.g., other open-source projects the developer maintains), an attacker who obtains a legitimate signing token through the OIDC provider could produce signatures over arbitrary other content. The defense at this layer is narrow: the verifier's `iss` + `email` pin defends only against substitution attacks; the broader defense (the developer's operational discipline on the OIDC identity — hardware security key, alerts on token issuance, out-of-band audit per design brief §5.5) is operational, not cryptographic, and lives outside this decision.

---

## 2. Fulcio CA trust root

### 2.1 Decision

The Fulcio root certificate is bundled with each release (same posture as the witness pool config per D0023 §3.3). The verifier:

1. Loads the pinned Fulcio root from the release's bundled trust bundle.
2. Validates the Fulcio-issued signing certificate's chain to the pinned root.
3. Validates the signing certificate's `NotBefore` / `NotAfter` window — the cert's validity window is by design short (typically 10 minutes per Fulcio's default policy); a signature is valid if the cert was valid at signing time, which the Rekor timestamp attests to (§3).

### 2.2 Rationale

Three properties matter:

1. **Pinned trust root excludes Sigstore-runtime CA rotation.** Fulcio's "publicly trusted" root rotation cadence is a Sigstore-project operational decision; if a future Fulcio root rotation issues new certs the bundled root does not chain to, those certs do not verify. This is intentional: a coordinated Cairn release picks up the new root explicitly rather than implicitly trusting whatever Fulcio's "current" root is at verify time.
2. **No runtime CA download.** The verifier does not fetch `https://fulcio.sigstore.dev/api/v2/trustBundle` at verify time. The bundled root means an air-gapped verifier (per §6.4) can validate certs offline.
3. **Coordinated rotation.** When Fulcio rotates its root, the Cairn release that picks up the new root bundles the new root + the cross-sign from the old root to the new root (if Fulcio publishes one), so existing releases continue to verify against the same chain.

### 2.3 What this does not defend against

A Fulcio infrastructure compromise that issues a malicious certificate signed by the pinned Fulcio root is not detected at this layer. The Rekor transparency log (§3) is the detection mechanism: malicious certs that issue tokens for the developer's identity surface as Rekor entries the developer did not produce, detectable by the out-of-band audit log per D0015 + design brief §5.5.

---

## 3. Rekor transparency log verification

### 3.1 Decision

The verifier performs two Rekor checks per release:

1. **Inclusion proof.** The Rekor entry's Merkle inclusion proof must verify against the signed Rekor checkpoint that was current at the time the bundled proof was captured.
2. **Signed checkpoint verify.** The Rekor checkpoint must verify against a pinned Rekor public key (bundled with the release, same posture as the Fulcio root). _[Revised 2026-05-30]_ The checkpoint is a C2SP [tlog-checkpoint](https://c2sp.org/tlog-checkpoint) signed note whose body is `origin\n<tree_size>\n<base64(root_hash)>\n`; the public Rekor log signs it with **ECDSA P-256** (signed-note signature type `0x02`), so the verify uses the `p256` crate, NOT Ed25519. The tree size + root hash for the inclusion check (item 1) are parsed out of the signature-verified note body, never from a separate unsigned field.

The inclusion proof and the signed checkpoint both ship as bundled release artifacts alongside the APK (per §6.4).

### 3.2 Rationale

Three properties matter:

1. **Project-owned verifier on the verify path.** Per the same logic as D0023 §3.1's project-owned witness verification: the verify path stays Rust-only, no `sigstore-rs` shim in the security-critical surface. The Rust verify code is small (RFC 6962 Merkle path + ECDSA P-256 signed-note verify — _[Revised 2026-05-30]_, originally mis-stated as Ed25519) and audit-friendly. `sigstore-rs` may be consumed at the signing-side / build-pipeline tooling, but not on the verifier.
2. **Pinned Rekor public key excludes runtime trust-root resolution.** Same rationale as §2.2: a coordinated release picks up Rekor key rotation explicitly.
3. **Inclusion + checkpoint together prove log placement.** Either alone is insufficient. The inclusion proof alone proves the entry is in the log at some position; the signed checkpoint proves the log itself is the one Rekor signed; the combination proves "this entry is at position N in the log Rekor attests has at least N+1 entries at this root hash."

### 3.3 Split-view detection

A malicious Rekor operator could serve two different log views: one to the verifier with the bundled inclusion proof, one to the out-of-band auditor with a different log state. The defense is the same as D0023 §7.1's Sigsum split-view detection: the Rekor checkpoint's signed root hash must be consistent across the bundled proof and any out-of-band audit. v1 does NOT implement cross-checkpoint consistency-proof verification in the verifier — it surfaces the checkpoint's root hash so an out-of-band tool can compare. v1.5 may add consistency-proof verification if operational experience indicates the split-view risk warrants it.

---

## 4. Release manifest schema

### 4.1 Decision

The release manifest is a canonical-CBOR encoded `ReleaseManifest` per D0018 §2.3 with integer-keyed map fields:

| Key | Field                     | CBOR type    | Notes                                                                                                                                        |
| --- | ------------------------- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `version`                 | text         | Semantic version string, e.g., `"1.0.0-pilot"`                                                                                               |
| 2   | `artifact_sha256`         | array of map | Each entry: `{1: artifact_name (text), 2: sha256 (bstr 32)}`                                                                                 |
| 3   | `build_provenance_sha256` | bstr 32      | SHA-256 of the build-provenance attestation (SLSA-style)                                                                                     |
| 4   | `release_timestamp`       | uint         | Unix-seconds when the manifest was signed                                                                                                    |
| 5   | `prior_release_hash`      | bstr         | SHA-256 of the previous release's signed manifest (zero-length for the first release); analog of D0006 §5 `prior_hash` for the release chain |

The manifest is signed via `COSE_Sign1` per D0018 §2.1 — the same envelope construction every other Cairn signed artifact uses. The Sigstore signing event signs the canonical-CBOR encoded manifest bytes (the COSE_Sign1 payload).

### 4.2 Rationale

Three properties matter:

1. **Reuse the existing envelope discipline.** The COSE_Sign1 envelope is the workspace's canonical signed-bytes format. The release manifest signs through the same code path; there is no new envelope discipline to audit.
2. **Rollback resistance via `prior_release_hash`.** Design brief §5.5 names rollback resistance ("client refuses lower-version installs"). The `prior_release_hash` field chains the release log so a client that observes release N's manifest can verify it commits to release N-1's manifest. A downgrade attack would require producing a manifest whose `prior_release_hash` references a release whose hash predates N — detectable by the client's stored release-log state.
3. **Build-provenance hash without revealing build environment.** The build-provenance attestation (SLSA-style) names which build pipeline produced the artifact, with witness signatures from the build environment. The manifest commits to its hash, not its content; the attestation itself ships as a bundled artifact alongside the APK for independent verification.

### 4.3 Privacy property

The release manifest fields are not user-private per se — releases are public events. The manifest does not contain user data. The fields chosen are the minimum to support verification + rollback + cross-reference to build provenance.

---

## 5. Sigstore + Sigsum composition

### 5.1 Decision

The release leaf hash committed to the Sigsum-anchored release log is:

```text
release_leaf_hash = SHA-256( COSE_Sign1.signature_bytes( signed_manifest ) )
```

This is the same composition as D0023 §1 for trust-graph leaves: SHA-256 of the signature bytes from the `COSE_Sign1` envelope. The leaf hash is computed via `cairn_sigsum_client::leaf::leaf_hash_for` against the signed-manifest envelope.

### 5.2 Rationale

Three properties matter:

1. **Single leaf-hash schema across the workspace.** Both trust-graph ops (D0023 §1) and release manifests (this decision §5.1) compose the same SHA-256-of-signature-bytes leaf hash. One audited primitive, two use cases.
2. **Cross-log cross-checkability.** A release that signs through Sigstore is logged in BOTH Rekor (Sigstore's log) AND Sigsum (Cairn's witness-cosigned log via D0023). An attacker who compromises one log can be detected by audit against the other; the witness-cosigned Sigsum entry is the secondary attestation that closes the gap design brief §3.3 acknowledges for Rekor's single-operator model.
3. **No new envelope surface.** The release-log leaf is constructed identically to trust-graph leaves; the same canonical CBOR + COSE_Sign1 + signature-extraction code path serves both.

### 5.3 Witness pool

Per D0015, the same witness pool that anchors trust-graph leaves anchors release leaves. The pool is configured per release via `witnesses.toml` (D0023 §3.3). Adding a release leaf to the Sigsum log + collecting witness cosignatures uses the same `cairn_sigsum_client::SigsumClient::emit_leaf` + verification path as trust-graph leaves.

### 5.4 What this does not defend against

A coordinated compromise of the OIDC provider + the Fulcio CA + the Rekor log + the Sigsum witness pool would defeat the verification stack. Each layer's compromise is independently improbable; the combination is what makes the stack the appropriate threat-model fit for the pilot scale per D0015. The verifier's role is to surface anomalies at each layer (typed errors per §7); the operational response to anomalies (refuse install, alert operators, switch channels) is the Android-shell concern.

---

## 6. Verifier crate layout

### 6.1 Crate composition

```text
cairn-sigstore-verify/
├── src/
│   ├── lib.rs              — public surface re-exports
│   ├── client.rs           — async SigstoreVerifier handle
│   ├── manifest.rs         — ReleaseManifest schema + canonical CBOR
│   ├── fulcio.rs           — Fulcio cert-chain validation
│   ├── rekor.rs            — Rekor inclusion proof + checkpoint verify
│   ├── error.rs            — typed SigstoreVerifyError surface
│   └── compose.rs          — composition with cairn-sigsum-client for the witness-cosigned release log
└── Cargo.toml
```

### 6.2 Dependencies

```text
[dependencies]
# === Foundational primitives ===
cairn-crypto = { path = "../cairn-crypto" }
cairn-envelope = { path = "../cairn-envelope" }
cairn-sigsum-client = { path = "../cairn-sigsum-client" }

# === SHA-256 + Ed25519 (Sigstore signing key path) ===
sha2 = { workspace = true }

# === X.509 cert parsing for Fulcio ===
x509-parser = { workspace = true }  # new workspace pin per §6.5

# === Async runtime + HTTPS ===
reqwest = { workspace = true }
tokio = { workspace = true }
url = { workspace = true }

# === JSON for Rekor API responses ===
serde = { workspace = true }
serde_json = { workspace = true }

# === Error handling ===
thiserror = { workspace = true }
```

### 6.3 Public API sketch

```rust
pub struct SigstoreVerifier { /* ... */ }

pub struct SigstoreVerifierConfig {
    pub fulcio_root_pem: Vec<u8>,
    pub rekor_pubkey_pem: Vec<u8>,
    pub expected_oidc_issuer: String,
    pub expected_oidc_email: String,
    pub sigsum_client: cairn_sigsum_client::SigsumClient,
}

impl SigstoreVerifier {
    pub fn new(config: SigstoreVerifierConfig) -> Result<Self, SigstoreVerifyError>;

    /// Verify a release-artifact bundle (manifest + cert chain +
    /// Rekor proof + Sigsum proof) end-to-end.
    pub async fn verify_release(
        &self,
        bundle: &ReleaseBundle,
    ) -> Result<VerifiedRelease, SigstoreVerifyError>;
}
```

### 6.4 Air-gapped verification

The verifier supports two modes:

- **Online mode.** The verifier may fetch fresh Rekor inclusion proofs from `https://rekor.sigstore.dev/api/v1/log/entries/{uuid}` and witness cosignatures from the witness pool. This is the default v1 mode (pilot devices have network connectivity). _[Revised 2026-05-30]_ The original draft wrote `/api/v2/`; the stable endpoint that returns an inclusion-proof-with-checkpoint in a single JSON response is **`/api/v1/log/entries/{uuid}`** (per the Rekor OpenAPI: the `verification.inclusionProof` object carries `logIndex`, `rootHash`, `treeSize`, `hashes`, and the signed `checkpoint`). The Rekor v2 tile-backed API uses a different retrieval model and is deferrable; `SigstoreVerifier::fetch_rekor_bundle` targets v1.
- **Offline mode.** The release bundle includes a pre-captured Rekor inclusion proof + signed checkpoint + witness cosignatures. The verifier checks the bundle without making network calls. This is the air-gapped install path that D0015's "offline signed images" v1.5+ deferral activates against.

The verify path is the same in both modes; the difference is whether the bundle was pre-populated or freshly fetched. v1 ships both modes; the offline mode is the architecturally important one because it is the path that does not require trusting whichever network the verifier sits on.

### 6.5 Workspace pin additions

This decision adds two workspace dependency pins. _[Revised 2026-05-30:
the `p256` pin below was added; the original draft listed only
`x509-parser`.]_

```toml
# === ECDSA P-256 verify for the Rekor signed-checkpoint (D0024 §3) ===
# Verify-only ECDSA P-256 for the C2SP signed-note Rekor checkpoint.
# default-features = false keeps it to curve arithmetic + ECDSA verify
# + PEM/SPKI public-key parsing; no signing, no ECDH, no JWK. Pure-Rust
# (RustCrypto). LANDED 2026-05-30 with the offline Rekor verifier.
p256 = { version = "=0.13.2", default-features = false, features = ["ecdsa", "pem"] }

# === X.509 parse + Fulcio cert-chain verification (D0024 §2) ===
# Cert-chain validation; default-features = false, features = ["verify"].
# LANDED 2026-05-31. ⚠ NOT pure-Rust: the `verify` feature enables the
# optional `ring` dependency (C + assembly, BoringSSL-derived). This is a
# DELIBERATE departure from the workspace pure-Rust discipline for the
# verify-only Fulcio trust path (see the revision note below).
x509-parser = { version = "=0.16.0", default-features = false, features = ["verify"] }
```

> **Revision 2026-05-31 — x509-parser `verify` is NOT pure-Rust; the
> Fulcio chain-signature verification uses `ring`.** The text above
> originally called the `x509-parser` pin "pure-Rust per the workspace
> pure-Rust discipline." That is wrong: x509-parser's `verify` feature
> enables the optional `ring` dependency (BoringSSL-derived C +
> assembly), and `verify_signature` is "limited to what `ring`
> supports." Fulcio chain validation requires verifying an **ECDSA
> P-384** signature (Sigstore's root is P-384), which neither
> `cairn-crypto` (Ed25519/X25519) nor the Rekor `p256` pin covers.
>
> The decision (made deliberately, weighing the project's "pure-Rust
> only if the alternatives are not security-worse" principle): use
> `ring`-backed verification rather than hand-rolling X.509
> chain-signature verification in pure Rust. Hand-rolled X.509
> verification (DER canonicalization, algorithm-confusion guards, chain
> constraints) is error-prone and security-sensitive; `ring`/`webpki`-
> style verification is battle-tested and audit-friendly. `ring` enters
> the **verify-only** trust path (no signing, no key material). A
> test-only `rcgen` dev-dependency (also `ring`-backed) generates the
> Fulcio-validation test certificates.

The `p256` pin also pulls a `base64` dependency (already a workspace
pin from D0023) for the checkpoint note's base64 root-hash line. The
version pins are exact per D0018 §1; rationale and audit posture per
D0021's pin-audit cycle. Note `p256` introduces a NIST curve into the
verify-only trust path — an audited addition, justified by the public
Rekor log's ECDSA P-256 checkpoint key (the revision note at the top).

---

## 7. Failure modes + typed error surface

`SigstoreVerifyError` per D0018 §4.2 — indices, lengths, type tags only; no `Vec<u8>` payloads:

```rust
#[non_exhaustive]
pub enum SigstoreVerifyError {
    /// Underlying network failure after the retry budget was exhausted.
    Network { retry_budget_used: u8 },

    /// Stub for v1 skeleton; mirrors cairn_sigsum_client::SigsumError::NetworkUnreached.
    NetworkUnreached,

    /// Fulcio-issued signing certificate did not chain to the pinned Fulcio root.
    FulcioChainInvalid,

    /// Fulcio signing certificate's validity window did not include the Rekor-attested signing time.
    FulcioCertExpiredAtSigningTime,

    /// OIDC `iss` claim in the Fulcio cert did not match the pinned issuer.
    OidcIssuerMismatch,

    /// OIDC `email` claim in the Fulcio cert did not match the pinned developer identity.
    OidcEmailMismatch,

    /// Rekor inclusion proof's Merkle path did not verify.
    RekorInclusionProofVerifyFailed,

    /// Rekor signed checkpoint did not verify against the pinned Rekor public key.
    RekorCheckpointVerifyFailed,

    /// Release manifest's `prior_release_hash` does not reference the expected predecessor.
    ManifestPriorHashMismatch,

    /// Release manifest's COSE_Sign1 signature did not verify against the Fulcio-issued public key.
    ManifestSignatureVerifyFailed,

    /// Release manifest's canonical-CBOR decode failed (schema drift or tamper past the Sigstore check).
    ManifestDecodeFailed,

    /// Underlying Sigsum-anchored release log verification failed; carries the wrapped Sigsum error.
    SigsumReleaseLog(#[from] cairn_sigsum_client::SigsumError),

    /// Underlying storage failure (for caching previously-verified releases per §6.4).
    Storage(#[from] cairn_storage::StorageError),
}
```

### 7.1 Cross-error orthogonality

The variants intentionally split by layer so callers can distinguish "Sigstore-side failure" from "Sigsum-side failure" from "manifest-schema failure". This mirrors D0023 §6.2's chain-link / sigsum-inclusion separation: each verification layer is an independent failure mode the caller must surface distinctly.

### 7.2 No-error-oracle discipline

All variants carry indices, type tags, or bounded scalars — no `Vec<u8>` cert bytes, no peer-supplied strings beyond the pinned OIDC `iss` / `email` values that the verifier compares against (those are project-owned, not peer-controlled). The `Display` strings reveal which layer rejected, not what content the rejected item contained.

---

## 8. Out of scope

This decision does NOT address:

1. **Release signing flow.** The CI-side OIDC token request, Sigstore signing event production, and Rekor entry posting are release-pipeline concerns, owned by the build infrastructure. v1 expects to use `cosign sign-blob` via the project's GitHub Actions / equivalent pipeline.
2. **OIDC issuance log audit.** The out-of-band log of when the developer actually signed (compared against Rekor entries to detect coerced provider tokens) is operational per D0015 + design brief §5.5. It is not a Rust-core defense.
3. **APK signing key custody and rotation.** The long-lived APK signing key is an Android-shell concern; rotation via APK Signature Scheme v3 happens outside the Rust core.
4. **Bring-Your-Own-OIDC-provider.** v1 pins the project's chosen OIDC provider per release. Users cannot configure their own verifier-side OIDC trust at runtime.
5. **Cross-checkpoint Rekor consistency proofs.** v1 surfaces the Rekor checkpoint root hash to the caller; the out-of-band consistency audit is operational, not Rust-core. v1.5 may add consistency-proof verification if operational experience indicates the split-view risk warrants it.
6. **Build-provenance attestation production.** SLSA-style build-provenance produced by the release pipeline is consumed at verify time (its SHA-256 lives in the manifest per §4.1 key 3), but the production side is the release-pipeline concern.
7. **F-Droid / Accrescent / direct-download channel selection logic.** Multi-channel distribution per D0015 + design brief §5.5 is an Android-shell concern; the verifier validates the artifact, not the channel.
8. **Recruited reviewer attestations.** Per D0015, the recruited 5+/3-of-5 reviewer pool defers to v1.5. When that pool lands, reviewer attestations will be additional Sigsum entries (composed via the same D0023 substrate) gated by a separate v1.5 D-doc; v1's verifier does not require them.

## 9. Reversibility

The decisions in this document are mostly reversible:

- **OIDC provider switch:** tractable. Per-release pinned config; switching providers is a coordinated release event with a new `release_config.toml` value. No existing data structure pins the choice.
- **Fulcio root rotation:** tractable; same coordinated release event posture as the witness pool per D0023 §3.3.
- **Rekor verifier (project-owned Rust → sigstore-rs shim):** tractable but expensive. Would require adding a Go-FFI-equivalent dependency stance for sigstore-rs's transitive Rust deps; no existing data structure pins the implementation.
- **Release-manifest schema change:** the HARDEST to reverse, by the same logic as D0023 §9: once releases are signed under the §4.1 schema, every subsequent release must follow it (else rollback-resistance fires on `prior_release_hash` mismatch). Schema changes require coordinated release + verifier update.

## 10. Implementation status

This D-doc is accepted. The matching `cairn-sigstore-verify` crate skeleton + Rekor-verify implementation land as separate commits consuming D0024. Implementation order:

1. ✅ `cairn-sigstore-verify/src/{lib,manifest,error}.rs` — pure data + schema with no I/O. **Landed** (skeleton).
2. `cairn-sigstore-verify/src/fulcio.rs` — cert-chain validation against the pinned root. _Stubbed (`NetworkUnreached`); pending the `x509-parser` body._
3. ✅ `cairn-sigstore-verify/src/rekor.rs` — inclusion proof + signed checkpoint verify. **Landed 2026-05-30**: RFC 6962 inclusion + C2SP signed-note ECDSA P-256 checkpoint verify, offline + exhaustively unit-tested.
4. ✅ `cairn-sigstore-verify/src/compose.rs` — composition with `cairn-sigsum-client` per §5. **Landed** (skeleton).
5. ✅ `cairn-sigstore-verify/src/client.rs` — async `SigstoreVerifier` handle. **Landed**: constructor + config; the online Rekor fetch (`fetch_rekor_bundle` / `fetch_and_verify_rekor`, 2026-05-30); and the end-to-end `verify_release` orchestration (2026-05-31): manifest decode → Fulcio + OIDC → manifest COSE verify → Rekor inclusion + checkpoint → `prior_release_hash` rollback check, validated in `tests/verify_release.rs`. The §5 Sigsum-anchored-release-log step is the one documented gap (gated on `cairn_sigsum_client::verify_inclusion`, still stubbed).
6. Workspace pin additions per §6.5: ✅ `p256` **landed 2026-05-30** (Rekor checkpoint); `x509-parser` deferred (Fulcio body).
7. CLI integration in `cairn-cli`: `verify-release` subcommand for end-to-end demo. _Pending._
8. Integration testing: a wiremock-based mock Rekor for the online-fetch path; opt-in real-Rekor test gated behind `--features integration-tests` so CI does not depend on external network availability (same pattern as D0023 §10). ✅ **Landed 2026-05-30**: the offline verifier (step 3) is tested directly without wiremock (pure crypto); `tests/rekor_wiremock.rs` covers the online fetch + JSON/signed-note parsing end-to-end (accept / inclusion-tamper / checkpoint-key-mismatch / malformed / retry-budget). The opt-in real-Rekor test remains future work.

The release-pipeline side (CI signing, Rekor posting, Sigsum emission) is operational and lives outside this crate; it lands separately as a release-pipeline runbook.

---

## 11. Cross-references

- [D0015 — v1 release-security posture](D0015-v1-release-security-posture.md) — Sigstore + Rekor + Sigsum + multi-channel commitment this decision implements the verify half of
- [D0018 — engineering foundation](D0018-engineering-foundation.md) — §4.1 async discipline; §8.6 workspace layout
- [D0022 — cairn-storage layer](D0022-storage-layer.md) — `SIGSUM_CACHE` category re-used for release-leaf cache state
- [D0023 — cairn-sigsum-client](D0023-sigsum-integration.md) — leaf-hash schema, witness-cosignature verification, and async client surface this decision composes against
- [D0021 — library-pin audit](D0021-library-pin-audit.md) — pin discipline for `x509-parser` addition per §6.5
- [design brief §5.5 Updates and Release Security](../design-brief.md) — two-signing-layers framing, OIDC trust placement, incident response
- [implementation-status.md](../implementation-status.md) — release-security rows currently ASPIRATIONAL; this decision unblocks them
- Sigstore / Fulcio / Rekor docs — https://docs.sigstore.dev/
