// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import uniffi.cairn_uniffi.cairnFfiAbiVersion
import uniffi.cairn_uniffi.messagingFfiSelftest

/**
 * The Cairn Android shell's pipeline-proof entry point per D0027 / D0020 §3.
 *
 * Two on-device proofs (D0026 §12):
 *  1. [cairnFfiAbiVersion] — loads the Rust core across the FFI boundary
 *     (which requires libcairn_uniffi.so + its DT_NEEDED libsimplex.so to map
 *     on the device). A throw here means the .so failed to load.
 *  2. [messagingFfiSelftest] — boots the in-process JNI `libsimplex`
 *     transport + creates an invitation, proving the GHC runtime initialises
 *     and answers on the real hardened (GrapheneOS) arm64 runtime — the
 *     on-device equivalent of the host runtime proof. Logged to `CairnFfi`.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Proof 1: the Rust core loaded (+ its libsimplex dependency mapped).
        val coreVersion = cairnFfiAbiVersion()
        Log.i(TAG, "Cairn core loaded: v$coreVersion")

        val view = TextView(this)
        view.text = "Cairn core loaded: v$coreVersion\nFFI selftest: running…"
        setContentView(view)

        // Proof 2: boot in-process libsimplex + create an invitation. App-
        // private paths under filesDir; runs on the tokio runtime (off the
        // main thread) via the async export.
        val dbPath = "${filesDir.absolutePath}/simplex-db"
        val xftpDir = "${filesDir.absolutePath}/xftp"
        // Tor routing (D0020 §2.2): set to the device SOCKS proxy address
        // (e.g. Orbot / the C-Tor ForegroundService at "127.0.0.1:9050") to
        // route /_connect over Tor so the SMP relay's .onion resolves. null =
        // direct connection — the pre-Tor baseline, where /_connect fails to
        // reach the .onion relay. Wired but null until a device proxy runs.
        val socksProxy: String? = null
        CoroutineScope(Dispatchers.Main).launch {
            val status = try {
                val link = messagingFfiSelftest(dbPath, xftpDir, socksProxy)
                Log.i(TAG, "FFI selftest OK — invitation: $link")
                "FFI selftest OK:\n${link.take(72)}…"
            } catch (e: Exception) {
                Log.e(TAG, "FFI selftest FAILED", e)
                "FFI selftest FAILED: ${e.message}"
            }
            view.text = "Cairn core loaded: v$coreVersion\n$status"
        }
    }

    private companion object {
        const val TAG = "CairnFfi"
    }
}
