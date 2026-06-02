// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import android.widget.TextView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.torproject.jni.TorService
import uniffi.cairn_uniffi.cairnFfiAbiVersion
import uniffi.cairn_uniffi.messagingFfiSelftest

/**
 * The Cairn Android shell's pipeline-proof entry point per D0027 / D0020 §3.
 *
 * Three on-device proofs (D0026 §12 / D0020 §2.2):
 *  1. [cairnFfiAbiVersion] — loads the Rust core across the FFI boundary
 *     (requires libcairn_uniffi.so + its DT_NEEDED libsimplex.so to map).
 *  2. **Bundled C-Tor** — Cairn starts its OWN Tor via tor-android's
 *     [TorService] (libtor.so bundled in the APK), so the user needs NO
 *     separate Orbot install (D0020 §2.2). We bind to read the dynamically
 *     chosen SOCKS port + poll the jtorctl control connection until a circuit
 *     is built (Tor bootstrapped).
 *  3. [messagingFfiSelftest] — boots the in-process JNI `libsimplex` and
 *     routes it through the bundled Tor (`/network socks=127.0.0.1:<port>`),
 *     so `/_connect` resolves the SMP relay's `.onion` over Tor. Logged to
 *     `CairnFfi`.
 *
 * This Activity is a diagnostic pipeline-proof, not the product UI. The
 * production lifecycle wraps Tor in a `remoteMessaging` ForegroundService
 * (D0020 §2.5) — deferred; here the visible Activity hosts the bound service.
 */
class MainActivity : Activity() {

    @Volatile
    private var torService: TorService? = null

    private val torConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            torService = (binder as? TorService.LocalBinder)?.service
            Log.i(TAG, "TorService bound")
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            torService = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Proof 1: the Rust core loaded (+ its libsimplex dependency mapped).
        val coreVersion = cairnFfiAbiVersion()
        Log.i(TAG, "Cairn core loaded: v$coreVersion")

        val view = TextView(this)
        view.text = "Cairn core loaded: v$coreVersion\nStarting bundled Tor…"
        setContentView(view)

        val dbPath = "${filesDir.absolutePath}/simplex-db"
        val xftpDir = "${filesDir.absolutePath}/xftp"

        // Proof 2: start the BUNDLED C-Tor engine (tor-android libtor.so) in
        // its own TorService — no separate Orbot install (D0020 §2.2).
        // startService triggers tor bring-up; bindService gives us the instance
        // for getSocksPort() + the jtorctl control connection.
        val torIntent = Intent(this, TorService::class.java)
        startService(torIntent)
        bindService(torIntent, torConnection, Context.BIND_AUTO_CREATE)

        CoroutineScope(Dispatchers.Main).launch {
            // Bootstrap wait runs on IO (the control-port getInfo is blocking).
            val socksPort = withContext(Dispatchers.IO) { awaitTorBootstrap(BOOTSTRAP_TIMEOUT_MS) }
            if (socksPort == null) {
                Log.e(TAG, "Tor bootstrap timed out")
                view.text = "Cairn core loaded: v$coreVersion\nBundled Tor: bootstrap TIMED OUT"
                return@launch
            }
            Log.i(TAG, "Bundled Tor bootstrapped — SOCKS 127.0.0.1:$socksPort")
            view.text =
                "Cairn core loaded: v$coreVersion\nBundled Tor up (SOCKS $socksPort)\nFFI selftest: running…"

            // Proof 3: route the in-process libsimplex through the bundled Tor
            // via /network socks=127.0.0.1:<port> (the wiring committed in
            // 36f2e39); /_connect must resolve the SMP relay's .onion over Tor.
            val socks = "127.0.0.1:$socksPort"
            val status = try {
                val link = messagingFfiSelftest(dbPath, xftpDir, socks)
                Log.i(TAG, "FFI selftest (over Tor) — $link")
                "FFI selftest:\n${link.take(96)}…"
            } catch (e: Exception) {
                Log.e(TAG, "FFI selftest FAILED", e)
                "FFI selftest FAILED: ${e.message}"
            }
            view.text = "Cairn core loaded: v$coreVersion\nBundled Tor up (SOCKS $socksPort)\n$status"
        }
    }

    /**
     * Poll the bound [TorService]'s jtorctl control connection until Tor reports
     * a built circuit (`status/circuit-established == "1"`), then return its
     * actual SOCKS port (tor-android tries 9050, else an auto port). Returns null
     * on [timeoutMs] timeout. The blocking control I/O runs on the caller's
     * dispatcher (expected to be IO).
     */
    private suspend fun awaitTorBootstrap(timeoutMs: Long): Int? =
        withTimeoutOrNull(timeoutMs) {
            var socks: Int? = null
            while (socks == null) {
                socks = socksPortIfCircuitEstablished()
                if (socks == null) {
                    delay(POLL_INTERVAL_MS)
                }
            }
            socks
        }

    /** The bound service's SOCKS port iff a Tor circuit is established, else null. */
    private fun socksPortIfCircuitEstablished(): Int? {
        val svc = torService ?: return null
        val control = svc.torControlConnection ?: return null
        val established = try {
            control.getInfo("status/circuit-established")
        } catch (e: Exception) {
            return null
        }
        val port = svc.socksPort
        return if (established == "1" && port > 0) port else null
    }

    override fun onDestroy() {
        try {
            unbindService(torConnection)
        } catch (e: IllegalArgumentException) {
            // Not bound (e.g. bind failed) — nothing to release.
        }
        super.onDestroy()
    }

    private companion object {
        const val TAG = "CairnFfi"
        const val BOOTSTRAP_TIMEOUT_MS = 180_000L
        const val POLL_INTERVAL_MS = 1_000L
    }
}
