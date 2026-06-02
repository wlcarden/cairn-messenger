// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.torproject.jni.TorService
import uniffi.cairn_uniffi.cairnFfiAbiVersion

/**
 * The Cairn Android shell entry point (D0027 / D0020 §3). Hosts the Compose
 * chat UI ([ChatScreen]) over the [MessagingViewModel], and bootstraps the
 * BUNDLED C-Tor engine (tor-android `libtor.so` in [TorService] — no Orbot,
 * D0020 §2.2): on a built circuit it signals the ViewModel so messaging ops can
 * route through Tor's loopback SOCKS proxy.
 *
 * The production lifecycle wraps Tor in a `remoteMessaging` ForegroundService
 * (D0020 §2.5) — deferred; here the visible Activity hosts the bound service.
 */
class MainActivity : ComponentActivity() {

    private val viewModel: MessagingViewModel by viewModels()

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
        Log.i(TAG, "Cairn core loaded: v${cairnFfiAbiVersion()}")

        setContent { ChatScreen(viewModel) }

        // Bootstrap the bundled C-Tor engine; signal the ViewModel when a
        // circuit is built so messaging ops route through SOCKS 127.0.0.1:9050.
        val torIntent = Intent(this, TorService::class.java)
        startService(torIntent)
        bindService(torIntent, torConnection, Context.BIND_AUTO_CREATE)

        lifecycleScope.launch {
            val socksPort = withContext(Dispatchers.IO) { awaitTorBootstrap(BOOTSTRAP_TIMEOUT_MS) }
            if (socksPort == null) {
                Log.e(TAG, "Tor bootstrap timed out")
                viewModel.onTorFailed("bootstrap timed out")
            } else {
                Log.i(TAG, "Bundled Tor bootstrapped — SOCKS 127.0.0.1:$socksPort")
                viewModel.onTorReady()
            }
        }
    }

    /**
     * Poll the bound [TorService]'s jtorctl control connection until Tor reports
     * a built circuit (`status/circuit-established == "1"`), then return its
     * SOCKS port; null on [timeoutMs] timeout. Blocking control I/O runs on the
     * caller's dispatcher (IO).
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
            // Not bound — nothing to release.
        }
        super.onDestroy()
    }

    private companion object {
        const val TAG = "CairnFfi"
        const val BOOTSTRAP_TIMEOUT_MS = 180_000L
        const val POLL_INTERVAL_MS = 1_000L
    }
}
