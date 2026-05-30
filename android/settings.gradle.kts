// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// Android shell settings per D0027 §1 / D0020 §3 / D0018 §7.
// The Gradle project lives in android/ alongside the Rust cargo
// workspace at the repo root; the cargo-ndk-android-gradle plugin
// (Willir's, per D0018 §7.3) cross-compiles cairn-uniffi's cdylib
// into the APK's jniLibs.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "cairn"
include(":app")
