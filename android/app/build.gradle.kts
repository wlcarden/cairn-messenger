// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// The Cairn Android shell app module per D0027 / D0020 §3 / D0018 §7.
// This is the v1 PIPELINE-PROOF shell: it cross-compiles cairn-uniffi's
// cdylib via cargo-ndk (D0018 §7.3), generates the UniFFI Kotlin
// bindings, and calls a representative export to prove the Rust core
// loads + answers across the FFI boundary. The full UI is the
// Android-shell team's surface; this module proves the build pipeline.

import java.io.ByteArrayOutputStream

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.github.willir.rust.cargo-ndk-android")
}

// Absolute path to the cargo workspace root (repo root = android/..).
val cargoWorkspaceRoot: String = rootProject.projectDir.parentFile.absolutePath

// Where the generated UniFFI Kotlin bindings land.
val uniffiGeneratedDir = layout.buildDirectory.dir("generated/uniffi/kotlin")

// === Android libsimplex bundling (D0026 §12) — operator-provided, NOT in git ===
// The in-process JNI transport (FfiSidecarTransport) needs the official Android
// `libsimplex.so` (~191 MB, AGPL, GHC-runtime statically baked in). SimpleX
// publishes NO standalone android-libsimplex artifact + NO x86_64 build, so it
// is extracted from the official SimpleX APK's `lib/arm64-v8a/` (arm64-v8a
// ONLY) and provided at build time — never committed (191 MB binary; AGPL
// upstream). The operator runs:
//   SXCRT=<dir>/arm64-v8a \
//     ./gradlew :app:assembleDebug -PcairnSimplexLibsDir=<dir>
// where <dir> contains `arm64-v8a/libsimplex.so`. SXCRT lets `sxcrt-sys`'s
// build script link the cdylib against libsimplex; `cairnSimplexLibsDir` adds
// the .so to the APK's jniLibs so it resolves at load. Absent these, the FFI
// transport cannot build (sxcrt-sys build script hard-fails) — see D0026 §12.
val cairnSimplexLibsDir: String? = project.findProperty("cairnSimplexLibsDir") as String?

android {
    namespace = "org.cairnproject.cairn"
    compileSdk = 34
    ndkVersion = "28.2.13676358" // D0018 §7.1: NDK r28+ for 16 KB alignment

    defaultConfig {
        applicationId = "org.cairnproject.cairn"
        minSdk = 31
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0-dev"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Restrict packaged native libs to **arm64-v8a only** (D0026 §12):
        // the in-process FFI transport needs the official Android libsimplex,
        // which SimpleX publishes for arm64-v8a + armv7 only — there is NO
        // x86_64 libsimplex, and Cairn does not cross-build GHC (D0020 §1.8).
        // (The pre-FFI shell targeted aarch64 + x86_64 per D0018 §7.2; x86_64
        // is dropped now that the build links libsimplex. An x86_64 emulator
        // therefore cannot run this build — on-device testing needs arm64.)
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        // Generates BuildConfig.DEBUG so key-bearing logs (MY_PUBKEY /
        // INVITE_BLOB / LEARNED peer) can be gated out of release builds.
        buildConfig = true
    }
    composeOptions {
        // Kotlin 1.9.24 pairs with Compose Compiler 1.5.14.
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    sourceSets {
        getByName("main") {
            java.srcDir(uniffiGeneratedDir)
            // Bundle the operator-provided Android libsimplex.so (D0026 §12)
            // into the APK's jniLibs WITHOUT committing the 191 MB binary.
            // `cairnSimplexLibsDir` is the parent of `arm64-v8a/libsimplex.so`;
            // AGPL merges it with the cargo-ndk-produced libcairn_uniffi.so so
            // both ship in the APK and libcairn_uniffi.so's `DT_NEEDED:
            // libsimplex.so` resolves at load.
            cairnSimplexLibsDir?.let { jniLibs.srcDir(it) }
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
        }
    }
}

// cargo-ndk-android-gradle (Willir's, D0018 §7.3): cross-compiles the
// cairn-uniffi cdylib for the v1 target ABIs (D0018 §7.2) into the
// APK's jniLibs.
cargoNdk {
    module = ".." // repo root, relative to android/
    librariesNames = arrayListOf("libcairn_uniffi.so")
    // arm64-v8a ONLY (D0026 §12): no x86_64 libsimplex exists to link against.
    targets = arrayListOf("arm64") // aarch64-linux-android
    extraCargoBuildArguments = arrayListOf("-p", "cairn-uniffi", "--features", "uniffi-bindings")
    apiLevel = 31
    // The cross-compile links `sxcrt-sys` → libsimplex; its build script reads
    // `SXCRT` from the environment (set it to `<cairnSimplexLibsDir>/arm64-v8a`
    // when invoking gradlew). cargo-ndk inherits the gradle process env, so a
    // fresh daemon (`--no-daemon` or a clean env) carries SXCRT through.
}

// Build the host cdylib once so uniffi-bindgen can read it. The
// generated Kotlin bindings are target-independent, so reading the
// host .so is correct + faster than reading a cross-compiled one.
val cargoBuildHostUniffi = tasks.register<Exec>("cargoBuildHostUniffi") {
    workingDir = file(cargoWorkspaceRoot)
    commandLine(
        "cargo", "build",
        "-p", "cairn-uniffi",
        "--features", "uniffi-bindings",
    )
}

// Generate the UniFFI Kotlin bindings from the host cdylib per
// D0020 §3.10 / D0027 §5.
val generateUniffiBindings = tasks.register<Exec>("generateUniffiBindings") {
    dependsOn(cargoBuildHostUniffi)
    workingDir = file(cargoWorkspaceRoot)
    val outDir = uniffiGeneratedDir.get().asFile
    doFirst { outDir.mkdirs() }
    commandLine(
        "cargo", "run",
        "-p", "cairn-uniffi",
        "--features", "uniffi-bindings",
        "--bin", "uniffi-bindgen",
        "--",
        "generate",
        "--library", "$cargoWorkspaceRoot/target/debug/libcairn_uniffi.so",
        "--language", "kotlin",
        "--no-format",
        "--out-dir", outDir.absolutePath,
    )
}

// The Kotlin compile + the preBuild step require the generated
// bindings to exist first.
tasks.named("preBuild").configure {
    dependsOn(generateUniffiBindings)
}

// Host-JVM unit tests (D0027 §8 FfiBoundaryTest) load the host-built
// libcairn_uniffi.so via JNA. Point jna.library.path at the cargo
// host target dir + ensure the .so + the generated bindings exist
// before the test runs.
tasks.withType<Test>().configureEach {
    dependsOn(cargoBuildHostUniffi, generateUniffiBindings)
    systemProperty("jna.library.path", "$cargoWorkspaceRoot/target/debug")
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    // Opt-in biometric / device-credential quick unlock (D0029). BiometricPrompt
    // needs a FragmentActivity (MainActivity extends it); fragment is pulled
    // transitively but pinned explicitly so the superclass can't silently regress.
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.6.2")
    // === Bundled C-Tor engine (D0020 §2.2) ===
    // tor-android ships libtor.so per-ABI (abiFilters keeps arm64-v8a) +
    // org.torproject.jni.TorService; jtorctl is the Java tor control-port
    // client. Cairn runs its OWN tor in a ForegroundService so the user needs
    // NO separate Orbot install (the whole point of bundling).
    //
    // Pinned to 0.4.8.19 (the latest 0.4.8.x LTS), NOT the D0020 §2.2 "0.4.9.8+"
    // floor: the 0.4.9.8 AAR sets minCompileSdk=37, which would force AGP
    // ~8.13+/9.x and break the load-bearing Willir cargo-ndk plugin 0.3.4
    // (compileSdk 34 / AGP 8.5.1 today). 0.4.8.19's AAR is minCompileSdk=1 and
    // wraps a current, maintained tor (the 0.4.8.x stable line; Orbot ships
    // 0.4.8.21) with no client-relevant security delta. Revisit 0.4.9.x when
    // the cargo-ndk toolchain is modernized. Floor deviation documented in
    // D0020 §2.2 (revision note).
    implementation("info.guardianproject:tor-android:0.4.8.19")
    implementation("info.guardianproject:jtorctl:0.4.5.7")
    // UniFFI Kotlin runtime uses JNA (the @aar variant for Android).
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    // The async exports (D0027 §5) generate suspend funs backed by
    // kotlinx-coroutines.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    // === Jetpack Compose UI (the chat surface) ===
    // The BOM pins a mutually-consistent Compose set; Kotlin 1.9.24 pairs with
    // Compose Compiler 1.5.14 (composeOptions above). All from google()/central.
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.4")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    // collectAsStateWithLifecycle (StateFlow -> Compose, lifecycle-aware).
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.4")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // === QR pairing (D0026 §12 in-app pairing) — ZXing, GOOGLE-PLAY-FREE ===
    // GrapheneOS ships no Google Play Services, so ML Kit is out. `zxing:core`
    // is pure-JVM QR ENCODE (invitation -> QR bitmap); `zxing-android-embedded`
    // is a GMS-free CameraX scanner exposing the `ScanContract` ActivityResult
    // API (its CaptureActivity manifest entry is merged automatically).
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    testImplementation("junit:junit:4.13.2")
    // The host-JVM FfiBoundaryTest (D0027 §8) loads the Rust .so via
    // JNA on the desktop JVM. The `@aar` JNA above packages
    // libjnidispatch.so for Android ABIs only; the plain jar bundles
    // the desktop (linux-x86-64) dispatch the host test needs.
    testImplementation("net.java.dev.jna:jna:5.14.0")
}
