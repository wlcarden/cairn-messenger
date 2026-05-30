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

        // Restrict packaged native libs to the v1 target ABIs per
        // D0018 §7.2 (aarch64 + x86_64; legacy 32-bit dropped). Without
        // this, JNA's @aar drags libjnidispatch.so for mips/armeabi/x86
        // into the APK.
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            java.srcDir(uniffiGeneratedDir)
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
    targets = arrayListOf("arm64", "x86_64") // aarch64-linux-android + x86_64
    extraCargoBuildArguments = arrayListOf("-p", "cairn-uniffi", "--features", "uniffi-bindings")
    apiLevel = 31
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
    // UniFFI Kotlin runtime uses JNA (the @aar variant for Android).
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    // The async exports (D0027 §5) generate suspend funs backed by
    // kotlinx-coroutines.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    testImplementation("junit:junit:4.13.2")
    // The host-JVM FfiBoundaryTest (D0027 §8) loads the Rust .so via
    // JNA on the desktop JVM. The `@aar` JNA above packages
    // libjnidispatch.so for Android ABIs only; the plain jar bundles
    // the desktop (linux-x86-64) dispatch the host test needs.
    testImplementation("net.java.dev.jna:jna:5.14.0")
}
