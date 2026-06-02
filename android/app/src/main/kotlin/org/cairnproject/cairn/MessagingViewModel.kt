// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A single chat line. */
data class ChatMessage(val mine: Boolean, val text: String)

/** Top-level UI phase (demo 1:1 conversation). */
sealed interface UiState {
    /** Bringing up the encrypted session + bundled Tor. */
    data object Starting : UiState

    /** Session up; show my key + the create/accept choices. */
    data class Ready(val myKeyHex: String) : UiState

    /** I created an invitation; share [inviteToShare] + paste the peer's key. */
    data class Inviting(val myKeyHex: String, val inviteToShare: String) : UiState

    /** Conversation established; chat is live. */
    data class Connected(val myKeyHex: String, val peerKeyHex: String) : UiState

    /** A fatal bootstrap/transport error. */
    data class Failed(val message: String) : UiState
}

/**
 * Drives the demo 1:1 chat over [CairnSession]'s [SimplexAdapterHandle], routed
 * through the bundled Tor (the Activity bootstraps `TorService` and calls
 * [onTorReady]; messaging ops gate on it). The shareable invitation is
 * `"<simplex-uri>|<myKeyHex>"`; the peer's key is exchanged with it (demo —
 * the real path binds operational keys via the trust graph, D0006).
 */
class MessagingViewModel(app: Application) : AndroidViewModel(app) {

    private val _ui = MutableStateFlow<UiState>(UiState.Starting)
    val ui = _ui.asStateFlow()

    private val _messages = MutableStateFlow<List<ChatMessage>>(emptyList())
    val messages = _messages.asStateFlow()

    private val _torStatus = MutableStateFlow("starting bundled Tor…")
    val torStatus = _torStatus.asStateFlow()

    private var session: CairnSession? = null

    @Volatile private var torReady = false
    private var connectionId: String? = null
    private var peerKeyRaw: ByteArray? = null

    init {
        viewModelScope.launch {
            try {
                val s = withContext(Dispatchers.IO) {
                    CairnSession.bootstrap(getApplication<Application>().filesDir)
                }
                session = s
                _ui.value = UiState.Ready(s.identity.publicKeyRaw.toHex())
            } catch (e: Exception) {
                Log.e(TAG, "session bootstrap failed", e)
                _ui.value = UiState.Failed("session: ${e.message}")
            }
        }
    }

    /** The Activity signals the bundled Tor is bootstrapped (SOCKS up). */
    fun onTorReady() {
        torReady = true
        _torStatus.value = "Bundled Tor ready (SOCKS 127.0.0.1:9050)"
    }

    fun onTorFailed(message: String) {
        _torStatus.value = "Bundled Tor: $message"
    }

    /** Create an invitation to share; then await the peer connecting. */
    fun createInvitation(peerKeyHex: String) {
        val s = session ?: return
        val myHex = (ui.value as? UiState.Ready)?.myKeyHex ?: s.identity.publicKeyRaw.toHex()
        peerKeyRaw = runCatching { peerKeyHex.trim().fromHex() }.getOrNull()
        viewModelScope.launch {
            if (!awaitTor()) return@launch
            try {
                val uri = s.handle.createInvitation()
                _ui.value = UiState.Inviting(myHex, "$uri|$myHex")
                val connId = s.handle.awaitConnection()
                onConnected(connId, myHex)
            } catch (e: Exception) {
                Log.e(TAG, "createInvitation failed", e)
                _ui.value = UiState.Failed("invite: ${e.message}")
            }
        }
    }

    /** Accept a peer's `"<uri>|<peerKeyHex>"` invitation. */
    fun acceptInvitation(blob: String) {
        val s = session ?: return
        val myHex = (ui.value as? UiState.Ready)?.myKeyHex ?: s.identity.publicKeyRaw.toHex()
        val parts = blob.trim().split("|", limit = 2)
        if (parts.size != 2) {
            _ui.value = UiState.Failed("invite must be <uri>|<peerKeyHex>")
            return
        }
        peerKeyRaw = runCatching { parts[1].fromHex() }.getOrNull()
        viewModelScope.launch {
            if (!awaitTor()) return@launch
            try {
                val connId = s.handle.acceptInvitation(parts[0])
                onConnected(connId, myHex)
            } catch (e: Exception) {
                Log.e(TAG, "acceptInvitation failed", e)
                _ui.value = UiState.Failed("accept: ${e.message}")
            }
        }
    }

    /** Send [text] to the connected peer. */
    fun send(text: String) {
        val s = session ?: return
        val connId = connectionId ?: return
        val peer = peerKeyRaw ?: return
        if (text.isBlank()) return
        viewModelScope.launch {
            try {
                s.handle.send(connId, peer, text.toByteArray())
                _messages.update { it + ChatMessage(mine = true, text = text) }
            } catch (e: Exception) {
                Log.e(TAG, "send failed", e)
                _messages.update { it + ChatMessage(mine = true, text = "[send failed: ${e.message}]") }
            }
        }
    }

    private fun onConnected(connId: String, myHex: String) {
        connectionId = connId
        val peer = peerKeyRaw
        _ui.value = UiState.Connected(myHex, peer?.toHex() ?: "(peer key unset)")
        if (peer != null) startRecvLoop(connId, peer)
    }

    /** Continuously receive + append messages from the peer. */
    private fun startRecvLoop(connId: String, peer: ByteArray) {
        val s = session ?: return
        viewModelScope.launch {
            while (true) {
                try {
                    // op == device key in the demo, so peer is both.
                    val r = s.handle.recv(connId, peer, peer)
                    _messages.update { it + ChatMessage(mine = false, text = String(r.payload)) }
                } catch (e: Exception) {
                    Log.e(TAG, "recv loop ended", e)
                    break
                }
            }
        }
    }

    private suspend fun awaitTor(): Boolean {
        var waited = 0
        while (!torReady && waited < TOR_WAIT_MS) {
            kotlinx.coroutines.delay(500)
            waited += 500
        }
        if (!torReady) {
            _ui.value = UiState.Failed("bundled Tor not ready")
            return false
        }
        return true
    }

    private companion object {
        const val TAG = "CairnFfi"
        const val TOR_WAIT_MS = 200_000
    }
}

/** Lowercase hex of these bytes. */
fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

/** Parse an even-length hex string to bytes. */
fun String.fromHex(): ByteArray {
    val clean = trim()
    require(clean.length % 2 == 0) { "odd-length hex" }
    return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
