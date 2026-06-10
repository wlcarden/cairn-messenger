# Cairn Android app

The Kotlin + Jetpack Compose shell for Cairn, targeting GrapheneOS-on-Pixel. It
cross-compiles the Rust core (in [`../crates`](../crates)) to
`aarch64-/x86_64-linux-android` via cargo-ndk + UniFFI and bundles `tor` plus
the SimpleX runtime.

## Build

Prerequisites: the pinned Rust toolchain ([`../rust-toolchain.toml`](../rust-toolchain.toml)),
the Android SDK, and NDK **r28+** (16 KB page-size requirement). Exact versions
and the full toolchain matrix are in the build-pipeline decision record below.

```sh
# from this directory
./gradlew :app:assembleDebug   # -> app/build/outputs/apk/debug/*.apk
```

The authoritative device-build pipeline — the cargo-ndk → UniFFI binding
generation → APK chain, the NDK/ABI matrix, and on-device validation notes — is
documented in
[`../docs/decisions/D0028-android-shell-build-pipeline.md`](../docs/decisions/D0028-android-shell-build-pipeline.md).

## Status

Alpha; the end-to-end message path has been demonstrated on two physical
GrapheneOS Pixels over bundled Tor. Read the repository
[`README.md`](../README.md) status banner and
[`../docs/implementation-status.md`](../docs/implementation-status.md) before
relying on any capability. **Do not rely on it for safety yet.**
