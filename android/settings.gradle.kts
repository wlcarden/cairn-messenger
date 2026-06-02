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
        // Guardian Project Maven (gpmaven) — the bundled C-Tor engine
        // (D0020 §2.2): info.guardianproject:tor-android (libtor.so +
        // org.torproject.jni.TorService) + jtorctl (Java control-port client).
        // `content { includeGroup }` pins this repo to ONLY serve the
        // info.guardianproject group, so it cannot shadow/spoof any other
        // dependency resolved from google()/mavenCentral() (supply-chain
        // hygiene, D0024 ethos).
        maven {
            url = uri("https://raw.githubusercontent.com/guardianproject/gpmaven/master")
            content { includeGroup("info.guardianproject") }
        }
    }
}

rootProject.name = "cairn"
include(":app")
