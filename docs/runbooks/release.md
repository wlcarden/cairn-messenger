# Release runbook — building, signing, and publishing a Cairn APK

**Status:** Draft v1 (Phase 1: GitHub Releases, out-of-band signing)
**Last reviewed:** 2026-06-10
**Owner:** Maintainer (developer)
**Scope:** How a downloadable, installable, signed Cairn APK is produced and
published on GitHub Releases — the end-to-end producer procedure.

---

## What this runbook is (and what it defers)

This is the **operator procedure** for cutting a Cairn release: turning the
source tree at a tagged commit into a signed `.apk` that a pilot user can
download from `github.com/wlcarden/cairn-messenger/releases` and install on a
GrapheneOS Pixel.

It covers the **Phase 1** posture: a real signed APK on GitHub Releases, signed
**out-of-band** (the signing key never touches CI). It deliberately defers the
deeper transparency layer (cosign/Sigsum attestation of the real APK, the
on-device update verifier, reproducible builds, F-Droid/Accrescent) to later
phases — those are tracked at the end under [Not yet in scope](#not-yet-in-scope).

### The signing model, and why it is what it is

The APK signing key is the most consequential credential in the project: the
key you ship the first release with becomes the app's permanent cryptographic
identity, and Android will only accept an update if it is signed by the same key
(or a key reachable from it via APK Signature Scheme v3 rotation, which itself
requires the old key). Lose it and you cannot ship a patched update to existing
installs; leak it and an attacker can.

For that reason Cairn signs **out-of-band**, not in CI:

- **Now — custody model (c):** a software keystore held outside the repository,
  used locally via `apksigner`.
- **Later — custody model (b):** the same `apksigner` step, repointed at a
  hardware token (YubiKey) under the 2-of-3 trustee arrangement in
  [`apk-signing-custody.md`](apk-signing-custody.md). The command barely
  changes; only the `--ks` source does.

This is why there is **no `signingConfig` in `android/app/build.gradle.kts`**: a
Gradle signing config assumes the key is reachable at build time, which is the
CI-signing pattern we are explicitly avoiding. `assembleRelease` produces an
_unsigned_ APK; the human signs it afterward with a key CI never sees.

---

## One-time setup

### 1. Tooling

- The pinned Rust toolchain ([`rust-toolchain.toml`](../../rust-toolchain.toml), Rust 1.91).
- Android SDK + **NDK r28+** (D0018 §7.1 — 16 KB page alignment) and Android
  **build-tools** (provides `zipalign` and `apksigner`).
- `cargo-ndk` (the Willir Gradle plugin pulls its own, but the host build needs
  the Rust Android targets: `rustup target add aarch64-linux-android`).
- [`gh`](https://cli.github.com/) authenticated against the repo
  (`gh auth status` should show `repo` + `workflow` scopes).
- The operator-provided Android `libsimplex.so` (D0026 §12) — see step 3.

### 2. The signing keystore (custody model c)

Generate a software keystore **once** and store it outside the working tree
(an encrypted volume or password manager — never in the repo; `*.jks` and
`*.keystore` are gitignored as a backstop only):

```sh
keytool -genkeypair -v \
  -keystore cairn-release.jks \
  -alias cairn \
  -keyalg RSA -keysize 4096 \
  -validity 10000 \
  -dname "CN=Cairn, O=Cairn maintainers and contributors"
```

> [!IMPORTANT]
> **Back the keystore up before it signs anything.** Its loss is unrecoverable
> for update continuity. At minimum: one offline encrypted copy in a second
> physical location. The migration to the hardware-token / 2-of-3 arrangement
> (model b) is specified in [`apk-signing-custody.md`](apk-signing-custody.md)
> and is a prerequisite for any non-pilot ("full") release.

Record the **signer certificate fingerprint** now — users pin it to detect a
substituted key:

```sh
keytool -list -v -keystore cairn-release.jks -alias cairn | grep -A1 'SHA256:'
```

### 3. libsimplex (the 191 MB native dependency)

Per D0026 §12 the build links and bundles the official Android `libsimplex.so`,
extracted from the SimpleX APK's `lib/arm64-v8a/` and provided at build time
(never committed). Place it so that `<dir>/arm64-v8a/libsimplex.so` exists, and
pass `<dir>` as `cairnSimplexLibsDir` and `<dir>/arm64-v8a` as `SXCRT` (below).

---

## Versioning discipline

Cairn uses **semantic versioning**, tags `vMAJOR.MINOR.PATCH`, starting at
**`v0.1.0`**.

Two fields in [`android/app/build.gradle.kts`](../../android/app/build.gradle.kts)
move every release:

| Field         | Rule                                                                |
| ------------- | ------------------------------------------------------------------- |
| `versionName` | The human version; **matches the tag** without the `v` (`"0.1.0"`). |
| `versionCode` | A monotonically **increasing integer**. `1` for v0.1.0, then `2`, … |

`versionCode` must strictly increase or Android refuses the update; the
monotonicity also feeds the rollback-resistance posture in D0015. The tag, the
`versionName`, and the `CHANGELOG.md` heading must agree.

**Cadence:** the release commit sets `versionName` to the release value (e.g.
`0.1.0`); after the release is published, bump the working tree to the next
development version (e.g. `0.1.1-dev` or `0.2.0-dev`) so `main` is never
mistaken for a shipped build.

---

## Release-build gates (read before the first real release)

Two properties of the **debug** build pipeline must change for a build that is
actually relied upon. Both are currently latent — inert only because the
on-device verifier is not yet wired into an install path — and both are tracked
here as release gates rather than silently shipped.

1. **Drop `synthetic-release-roots`.** The shipped cdylib is currently
   cross-compiled with `--features uniffi-bindings,synthetic-release-roots`
   (`android/app/build.gradle.kts`, the `cargoNdk` block). The
   `synthetic-release-roots` feature lets the release verifier accept
   _caller-supplied_ roots (a test affordance, D0041 §6.1). A real release must
   build the cdylib **without** it, so only the baked-in pinned-roots path
   (`new_pinned`) remains. The build file's own comment flags this: _"A
   production build must OMIT it … scope this to the debug variant only."_
2. **Build the native core in release profile.** cargo-ndk currently
   cross-compiles the Rust core in debug profile. A real release should compile
   it optimized (release profile) — smaller, faster, and the profile under
   which the constant-time discipline (dudect, D0018) is validated.

> [!NOTE]
> Both gates are cargo-ndk plugin wiring that must be validated on a machine
> with the Android SDK/NDK + libsimplex (they cannot be build-tested in a
> headless CI-less environment). Until they are wired and validated, a release
> cut from this tree is a **pilot pre-release** of debug-profile native code
> with the synthetic-roots affordance present — acceptable only while the
> verifier is unwired and the release is labeled accordingly (the README status
> banner: _"do not rely on it for safety yet"_).

---

## Per-release procedure

### Step 1 — Prepare the release commit

1. Set `versionName` / `versionCode` in `android/app/build.gradle.kts`.
2. Move the `CHANGELOG.md` `[Unreleased]` content under a new dated
   `## [0.1.0] - YYYY-MM-DD` heading.
3. Commit on a branch, open a PR, let CI go green, merge to `main`.

### Step 2 — Build the unsigned release APK

From a clean checkout of the merged commit:

```sh
cd android
SXCRT=<libsimplex-dir>/arm64-v8a \
  ./gradlew :app:assembleRelease -PcairnSimplexLibsDir=<libsimplex-dir>
# -> app/build/outputs/apk/release/app-release-unsigned.apk
```

The output is **arm64-v8a only** (D0026 §12 — there is no x86_64 libsimplex);
it will not run on an x86_64 emulator. Validate it on a physical Pixel.

### Step 3 — Align, then sign (out-of-band)

`apksigner` requires alignment **before** signing:

```sh
# Align (4-byte / 16 KB-page safe).
zipalign -p -f 4 app-release-unsigned.apk cairn-0.1.0-aligned.apk

# Sign with the software keystore (custody model c). v2+v3 schemes by default.
apksigner sign \
  --ks /path/outside/repo/cairn-release.jks \
  --ks-key-alias cairn \
  --out cairn-0.1.0.apk \
  cairn-0.1.0-aligned.apk
```

When you graduate to the hardware token (model b), only the key source changes —
`apksigner sign --ks NONE --ks-type PKCS11 --provider-class … --provider-arg <pkcs11.cfg> …`
— the rest of the flow is identical. The exact PKCS#11 config is token-specific;
capture it in [`apk-signing-custody.md`](apk-signing-custody.md) when provisioned.

### Step 4 — Verify the signature before publishing

```sh
apksigner verify --verbose --print-certs cairn-0.1.0.apk
```

Confirm `Verified using v2 scheme: true` / `v3 scheme: true`, and that the
printed certificate SHA-256 matches the fingerprint you recorded at keystore
creation. **Publishing a mis-signed APK is worse than not publishing** — a
wrong fingerprint trains users to ignore the check.

### Step 5 — Checksums

```sh
sha256sum cairn-0.1.0.apk > cairn-0.1.0.apk.sha256
```

### Step 6 — Tag and publish

```sh
git tag -s v0.1.0 -m "Cairn v0.1.0 (pilot pre-release)"
git push origin v0.1.0

gh release create v0.1.0 \
  --prerelease \
  --title "Cairn v0.1.0 — pilot pre-release" \
  --notes-file release-notes-v0.1.0.md \
  cairn-0.1.0.apk cairn-0.1.0.apk.sha256
```

Use `--prerelease` for every release while the project is pre-audit. A signed
git tag (`-s`) ties the tag itself to your identity, independent of the APK key.

### Step 7 — Post-release

- Download the published asset and re-run Step 4's verify + `sha256sum -c`
  against it (confirm what users get is what you signed).
- Bump the working tree to the next `-dev` version (versioning cadence above).

---

## Release-notes template

Every release's notes must tell a user how to verify what they downloaded:

```markdown
**⚠️ Pilot pre-release — pre-audit. Do not rely on it for safety yet.**
arm64-v8a only; GrapheneOS-on-Pixel target.

### Verify before installing

1. Checksum:
   `sha256sum -c cairn-0.1.0.apk.sha256`
2. Signing certificate — confirm the SHA-256 matches the published fingerprint:
   `apksigner verify --print-certs cairn-0.1.0.apk`
   Expected signer SHA-256: `AA:BB:…` ← published once, in the README

### Changes

(from CHANGELOG.md)
```

Publish the signer fingerprint **once, durably** (README), not only in a release
body — that is the anchor a user compares every future release against.

---

## Not yet in scope

Honest deferrals, so a release is never labeled as more than it is:

- **cosign/Sigsum attestation of the real APK (Phase 2).** The keyless signing
  _mechanism_ is proven in [`2b-keyless-release-sign.md`](2b-keyless-release-sign.md)
  but currently signs a synthetic artifact and uploads to ephemeral CI
  artifacts. Phase 2 repoints it at the real APK and attaches the
  `ReleaseBundle` to the release. Production Sigstore roots are phase 3 (D0042),
  and the Sigsum log + witness pool is funding-gated.
- **On-device update verification.** `cairn-sigstore-verify` is not wired into
  the install/update flow (README "Releases & verification"). Until it is, the
  APK signature + published fingerprint are the user's verification path.
- **Reproducible builds** (binary-equivalence verification) — v1.5.
- **F-Droid / Accrescent channels** — v1.5; GitHub Releases is the Phase 1
  channel.

---

## References

- [`apk-signing-custody.md`](apk-signing-custody.md) — multi-party (2-of-3)
  custody of the signing key; the model-(b) target.
- [`2b-keyless-release-sign.md`](2b-keyless-release-sign.md) — the keyless
  Sigstore signing mechanism (Phase 2 transparency layer).
- [`cve-response.md`](cve-response.md) — emergency-release path for a CVE.
- [`../decisions/D0028-android-shell-build-pipeline.md`](../decisions/D0028-android-shell-build-pipeline.md)
  — the cargo-ndk → UniFFI → APK build pipeline.
- [`../decisions/D0015-v1-release-security-posture.md`](../decisions/D0015-v1-release-security-posture.md)
  — release-security posture and rollback resistance.
- [`../implementation-status.md`](../implementation-status.md) — current
  release-stack maturity.
