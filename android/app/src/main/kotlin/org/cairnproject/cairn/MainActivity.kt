// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.torproject.jni.TorService
import uniffi.cairn_uniffi.cairnFfiAbiVersion
import uniffi.cairn_uniffi.messagingFfiTwoPartySelftest

/**
 * The Cairn Android shell entry point (D0027 / D0020 §3). Hosts the Compose
 * chat UI ([ChatScreen]) over the [MessagingViewModel], and bootstraps the
 * BUNDLED C-Tor engine (tor-android `libtor.so` in [TorService] — no Orbot,
 * D0020 §2.2): on a built circuit it signals the ViewModel so messaging ops can
 * route through Tor's loopback SOCKS proxy.
 *
 * A [CairnForegroundService] (started in [onCreate]) pins the process at
 * foreground-service priority (D0026 §12) so the bundled Tor + the recv loop
 * survive backgrounding — without it the process is reaped within minutes.
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

        // Pin the whole process (Tor + libsimplex + the recv loop) at
        // foreground-service priority so messaging survives backgrounding
        // (D0026 §12). The service runs regardless of POST_NOTIFICATIONS; the
        // runtime grant only makes its ongoing notification visible (API 33+).
        ContextCompat.startForegroundService(
            this,
            Intent(this, CairnForegroundService::class.java),
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFICATIONS)
        }

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

        handleDriverExtras(intent)
    }

    /** Warm re-foreground (launchMode=singleTop): pick up new driver extras. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDriverExtras(intent)
    }

    /**
     * Demo-automation hook for adb-driven two-device tests. Reads optional
     * string extras and dispatches them to the [MessagingViewModel] — the
     * SimpleX invitation URI is percent-encoded and resists `adb input text`,
     * so a harness injects it as an `am start --es invite "<blob>"` extra
     * instead. Not part of the user flow: the Compose TextFields drive the same
     * ViewModel entry points. The ViewModel ignores ops issued before the
     * session/Tor are ready (it gates internally), so drive these only once the
     * app has reached Ready.
     *
     *   --es peer   "<peerKeyHex>"    → createInvitation (logs INVITE_BLOB)
     *   --es invite "<uri>|<peerHex>" → acceptInvitation
     *   --es send   "<text>"          → send to the connected peer
     */
    private fun handleDriverExtras(intent: Intent) {
        intent.getStringExtra("peer")?.let {
            Log.i(TAG, "driver: createInvitation peer=$it")
            viewModel.createInvitation(it)
        }
        intent.getStringExtra("invite")?.let {
            Log.i(TAG, "driver: acceptInvitation")
            viewModel.acceptInvitation(it)
        }
        intent.getStringExtra("send")?.let {
            Log.i(TAG, "driver: send len=${it.length}")
            viewModel.send(it)
        }
        // Two-party loopback selftest (D0026 §12): runs BOTH peers in this one
        // process over the bundled Tor, proving the full envelope round-trip
        // without a second device. Trigger AFTER Tor is up (the proxy is fixed
        // at 127.0.0.1:9050). Result lands in logcat as "SELFTEST2: …".
        intent.getStringExtra("selftest2")?.let {
            val base = filesDir.absolutePath
            Log.i(TAG, "driver: two-party selftest starting")
            lifecycleScope.launch {
                try {
                    val result = withContext(Dispatchers.IO) {
                        messagingFfiTwoPartySelftest(
                            "$base/st2a/simplex-db",
                            "$base/st2a/xftp",
                            "$base/st2b/simplex-db",
                            "$base/st2b/xftp",
                            "127.0.0.1:9050",
                        )
                    }
                    Log.i(TAG, "SELFTEST2: $result")
                } catch (e: Exception) {
                    Log.e(TAG, "SELFTEST2 exception", e)
                }
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
        // A COLD bundled-Tor bootstrap (fresh data dir, e.g. after a clear, or
        // on a VPN-constrained path) fetches the full consensus + builds its
        // first circuit, which can exceed the warm ~10s by minutes. Generous so
        // the app doesn't give up before Tor is ready (D0026 §12 on-device).
        const val BOOTSTRAP_TIMEOUT_MS = 600_000L
        const val POLL_INTERVAL_MS = 1_000L

        /** Request code for the POST_NOTIFICATIONS runtime grant (API 33+). */
        const val REQ_NOTIFICATIONS = 1
    }
}
