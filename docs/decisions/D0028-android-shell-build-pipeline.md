# D0028 — android/ shell build pipeline: the realized cargo-ndk → UniFFI → APK chain

**Status:** Accepted
**Date:** 2026-05-30

## Context

D0018 §7 + D0020 §3.10 decided the Android build-pipeline architecture (NDK r28+, `cargo-ndk-android-gradle` per D0018 §7.3, AGP 8.5.1+, `aarch64`+`x86_64` ABIs per D0018 §7.2). D0027 specified the `cairn-uniffi` FFI surface. This document records the **realized** `android/` Gradle project that implements those decisions, and — distinct from every prior D-doc — it documents a pipeline that was **actually built and validated against an installed toolchain in-environment**, not specified for later.

This is downstream of D0018 §7 + D0020 §3.10 (the same implements-not-re-decides relationship D0025/D0026 hold to D0020 §1-2 and D0027 holds to D0020 §3). It does not re-decide the toolchain choices; it pins the exact realized versions + the validation evidence.

## Decision summary

| Concern                        | Realized decision                                                                                                    | Validated? |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------- | ---------- |
| **Project location**           | `android/` at the repo root, a Gradle project sibling to the cargo workspace                                         | ✓          |
| **Toolchain matrix**           | JDK 17, Gradle 8.9, AGP 8.5.1, Kotlin 1.9.24, NDK 28.2.13676358 (r28c), build-tools 34.0.0, compileSdk 34, minSdk 31 | ✓          |
| **Rust cross-compile**         | `cargo-ndk-android-gradle` 0.3.4 (Willir's, D0018 §7.3) cross-compiles `cairn-uniffi`'s cdylib into `jniLibs`        | ✓          |
| **Target ABIs**                | `arm64-v8a` + `x86_64` only, enforced via `abiFilters` per D0018 §7.2                                                | ✓          |
| **UniFFI bindgen integration** | A `generateUniffiBindings` Gradle task runs the `uniffi-bindgen` bin → Kotlin into a generated source dir            | ✓          |
| **Pipeline-proof shell**       | `MainActivity` + a host-JVM `FfiBoundaryTest` that calls a representative export across the boundary                 | ✓          |
| **Validation: host FFI test**  | `./gradlew :app:testDebugUnitTest` — JVM loads the `.so` via JNA, `cairnFfiAbiVersion()` returns "0.1.0-dev"         | ✓          |
| **Validation: APK**            | `./gradlew :app:assembleDebug` — 8.6 MB APK with `lib/{arm64-v8a,x86_64}/libcairn_uniffi.so`                         | ✓          |

---

## 1. Realized project layout

```text
android/
├── settings.gradle.kts        — google() + mavenCentral() + gradlePluginPortal()
├── build.gradle.kts           — plugin versions (AGP 8.5.1, Kotlin 1.9.24, cargo-ndk 0.3.4) apply false
├── gradle.properties          — AndroidX on, official Kotlin style
├── gradlew + gradle/wrapper/   — pinned Gradle 8.9 (committed, reproducible)
├── local.properties           — sdk.dir (gitignored; machine-specific)
└── app/
    ├── build.gradle.kts        — the app module + cargoNdk + generateUniffiBindings task
    └── src/
        ├── main/AndroidManifest.xml
        ├── main/kotlin/org/cairnproject/cairn/MainActivity.kt
        └── test/kotlin/org/cairnproject/cairn/FfiBoundaryTest.kt
```

The exact toolchain matrix was chosen for compatibility, not novelty: AGP 8.5.1 (the version D0018 §7 names) pairs cleanly with Gradle 8.7+ (8.9 used), JDK 17, and compileSdk 34. NDK 28.2.13676358 is the latest stable r28 (r28c), satisfying D0018 §7.1's 16 KB-alignment requirement.

## 2. The UniFFI bindgen Gradle integration

The chain D0020 §3.10 + D0027 §8 specified, realized as Gradle tasks:

1. **`cargoBuildHostUniffi`** (`Exec`): `cargo build -p cairn-uniffi --features uniffi-bindings` — produces the host `target/debug/libcairn_uniffi.so`. The generated Kotlin is target-independent, so reading the host `.so` is correct + faster than a cross-compiled one.
2. **`generateUniffiBindings`** (`Exec`, depends on 1): runs the `uniffi-bindgen` bin (`cargo run … --bin uniffi-bindgen -- generate --library <host .so> --language kotlin --no-format --out-dir <generated>`). The output dir is wired into `android.sourceSets["main"].java.srcDir`.
3. **`preBuild`** depends on `generateUniffiBindings`, so the Kotlin compile always sees fresh bindings.
4. **`cargoNdk`** (the plugin) cross-compiles the cdylib for `arm64-v8a` + `x86_64` into the APK's `jniLibs`, independently of the host build in step 1.

The `--no-format` flag is used because `ktlint` is not required in the build environment; the generated Kotlin compiles without reformatting.

## 3. Pipeline-proof scope vs. full UI

This `android/` module is a **pipeline proof**, not the product UI. It establishes that the build chain works end-to-end:

- `MainActivity` calls `cairnFfiAbiVersion()` at startup — a representative `#[uniffi::export]` (D0027 §8's vertical slice). If the `.so` failed to load or the UniFFI ABI checksum mismatched, this throws immediately (fail-fast).
- `FfiBoundaryTest` is a host-JVM test (runs without a device/emulator) that loads the host `.so` via JNA and asserts the Rust core answers across the boundary.

The full Android UI — the Signal-like surface, trust-badge rendering, recovery-flow walkthroughs (design brief §5.6), the `AndroidKeyStoreSigner` implementation of `HardwareKeySigner` (D0020 §3.4), the `ForegroundService`s hosting C-Tor (D0025 / D0020 §2.5) and the SimpleX CLI sidecar (D0026 / D0020 §1.6), and the UnifiedPush wake-up wiring — is the Android-shell team's surface. This module proves the boundary they build against is wired + buildable.

## 4. Validation performed (in-environment, this date)

Unlike prior D-docs that specify pipelines for a later environment, this one was validated against an installed toolchain:

- **Toolchain install:** Android SDK cmdline-tools 20.0, NDK 28.2.13676358 (r28c), build-tools 34.0.0, platform android-34, platform-tools, `cargo-ndk` 3.5.4, Gradle 8.9 — all installed + verified.
- **`./gradlew :app:testDebugUnitTest` → BUILD SUCCESSFUL.** The chain ran: `cargoBuildHostUniffi` → `generateUniffiBindings` → `compileDebugKotlin` (the generated bindings + MainActivity compiled) → `compileDebugUnitTestKotlin` → `FfiBoundaryTest` passed (the Rust↔Kotlin call returned the expected value over JNA).
- **`./gradlew :app:assembleDebug` → BUILD SUCCESSFUL.** cargo-ndk cross-compiled `libcairn_uniffi.so` for both target ABIs; the 8.6 MB `app-debug.apk` contains exactly `lib/arm64-v8a/libcairn_uniffi.so` (1.55 MB) + `lib/x86_64/libcairn_uniffi.so` (1.49 MB), matching D0018 §7.2.

The generated Kotlin surface confirms the D0027 design crossed correctly: `sealed class CairnFfiException` (the flat no-error-oracle facade), `interface HardwareKeySigner`, the three `data class` records, and `fun cairnFfiAbiVersion()`.

## 5. The JNA dual-dependency detail

A bring-up finding worth recording for the Android-shell team: UniFFI's Kotlin runtime uses JNA, which has TWO distribution variants with different native `libjnidispatch.so` payloads:

- **`net.java.dev.jna:jna:5.14.0@aar`** — bundles `libjnidispatch.so` for Android ABIs. Correct for the APK (`implementation`).
- **`net.java.dev.jna:jna:5.14.0`** (plain jar) — bundles desktop dispatch (incl. `linux-x86-64`). Required for the host-JVM `FfiBoundaryTest` (`testImplementation`).

Using only the `@aar` caused the host test to fail with `UnsatisfiedLinkError` on JNA's own dispatch lib. The fix is the dual dependency (both are declared in `app/build.gradle.kts`). This is a known uniffi-on-Android testing gotcha; documenting it here saves the shell team the rediscovery.

## 6. Out of scope

1. **The full Android UI** — the shell team's surface; this is a pipeline proof.
2. **The `AndroidKeyStoreSigner` Kotlin impl of `HardwareKeySigner`** — D0020 §3.4; the Rust-side trait crossed, the StrongBox-backed Kotlin impl is the shell team's.
3. **The C-Tor + SimpleX-CLI `ForegroundService`s** — D0025 / D0026 / D0020 §1.6 + §2.5; the shell hosts them.
4. **The full per-domain UniFFI export surface** — D0027 §2 enumerates it; the pipeline is proven with one representative export, the rest fills in behind it (no further pipeline work needed, just more `#[uniffi::export]` attributes + a rebuild).
5. **Reproducible builds** — D0018 §7.4 (Nix + crane + `rust-toolchain.toml` already present); the v1 pilot does not target F-Droid reproducibility, v1.5+ does.
6. **Instrumented (on-device) tests + signing config** — beyond the pipeline proof; a release signing config + `connectedAndroidTest` land with the shell.

## 7. Reversibility

- **Toolchain version bumps** (AGP/Gradle/NDK/compileSdk): tractable; the matrix is pinned in `build.gradle.kts` + `gradle/wrapper`. AGP↔Gradle↔compileSdk compatibility is the constraint.
- **cargo-ndk-android-gradle → a different Rust-Android Gradle bridge**: tractable; the `cargoNdk` block is the only plugin-specific surface. Mozilla's `rust-android-gradle` is the alternative D0018 §7.3 considered.
- **The `generateUniffiBindings` task shape** (host-`.so`-read vs. library-mode against a cross-compiled `.so`): tractable; both are uniffi-supported.
- **The pipeline-proof `MainActivity`/`FfiBoundaryTest`**: throwaway-by-design; the shell team replaces `MainActivity` with the real UI. `FfiBoundaryTest` is worth keeping as a CI smoke test of the boundary.

## 8. Cross-references

- [D0018 — engineering foundation](D0018-engineering-foundation.md) — §7 the build/cross-compile decisions this implements (§7.1 NDK r28, §7.2 ABIs, §7.3 cargo-ndk-android-gradle, §7.4 reproducible builds)
- [D0020 — integration architecture](D0020-integration-architecture.md) — §3 the FFI architecture; §3.10 cross-compile + Gradle integration; §1.6 + §2.5 the ForegroundServices the shell hosts
- [D0027 — cairn-uniffi crate surface](D0027-cairn-uniffi-crate-surface.md) — the FFI surface this pipeline compiles + binds; §8 the vertical-slice validation this realizes
- [D0003 — implementation language](D0003-implementation-language.md) — Rust core + Kotlin UI; this is the seam between them
- [D0025](D0025-cairn-tor-transport.md) / [D0026](D0026-cairn-simplex-adapter.md) — the transport + messaging surfaces the shell's ForegroundServices host
- [implementation-status.md](../implementation-status.md) — the Android-shell + StrongBox rows this unblocks
