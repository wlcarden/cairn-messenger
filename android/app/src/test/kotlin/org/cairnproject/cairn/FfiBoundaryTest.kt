// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.cairn_uniffi.cairnFfiAbiVersion

/**
 * Host-JVM proof that the UniFFI boundary works end-to-end per
 * D0027 §8: this test loads the host-built `libcairn_uniffi.so` via
 * JNA (jna.library.path is set to target/debug by the Gradle test
 * task) and calls a representative Rust export across the boundary.
 *
 * A green run proves: the Rust core compiled to a cdylib, the UniFFI
 * bindgen produced correct Kotlin, the Kotlin compiled, and the
 * Rust↔Kotlin call returns the expected value. This is the build
 * pipeline validated without needing an Android device/emulator.
 */
class FfiBoundaryTest {
    @Test
    fun rustCoreAnswersAcrossTheFfiBoundary() {
        // cairn-uniffi's Cargo.toml version is "0.1.0-dev".
        assertEquals("0.1.0-dev", cairnFfiAbiVersion())
    }
}
