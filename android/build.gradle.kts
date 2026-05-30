// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// Root build script. Plugin versions are declared here (apply false)
// and applied in :app per D0018 §7.3 (AGP 8.5.1) + D0020 §3.10.

plugins {
    id("com.android.application") version "8.5.1" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
    id("com.github.willir.rust.cargo-ndk-android") version "0.3.4" apply false
}
