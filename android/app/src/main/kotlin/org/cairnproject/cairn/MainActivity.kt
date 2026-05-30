// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.app.Activity
import android.os.Bundle
import android.widget.TextView
import uniffi.cairn_uniffi.cairnFfiAbiVersion

/**
 * The Cairn Android shell's pipeline-proof entry point per D0027 / D0020 §3.
 *
 * This minimal Activity calls a representative UniFFI export
 * ([cairnFfiAbiVersion]) to prove the Rust core loaded across the FFI
 * boundary + answers. It establishes that the build pipeline
 * (cargo-ndk cross-compile → UniFFI bindgen → Kotlin → APK) works
 * end-to-end. The full UI is the Android-shell team's surface; this
 * Activity is the load-bearing proof that the boundary is wired.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Call into the Rust core over the UniFFI boundary. If the
        // .so did not load or the ABI checksum mismatched, this throws
        // at startup — which is exactly the fail-fast behavior we want
        // for a pipeline-proof shell.
        val coreVersion = cairnFfiAbiVersion()

        val view = TextView(this)
        view.text = "Cairn core loaded: v$coreVersion"
        setContentView(view)
    }
}
