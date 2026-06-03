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

    /** Accepting a peer's invitation; the SMP handshake is in flight over Tor. */
    data class Connecting(val myKeyHex: String) : UiState

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
                val myHex = s.publicKeyRaw.toHex()
                Log.i(TAG, "MY_PUBKEY=$myHex")
                _ui.value = UiState.Ready(myHex)
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

    /**
     * Create an invitation to share (inviter side). The peer's operational key
     * is **learned from its first envelope** (TOFU, D0026 §12) — no need to
     * exchange it beforehand, so the user shares one QR/link and is done.
     */
    fun createInvitation() {
        val s = session ?: return
        val myHex = (ui.value as? UiState.Ready)?.myKeyHex ?: s.publicKeyRaw.toHex()
        peerKeyRaw = null
        viewModelScope.launch {
            if (!awaitTor()) return@launch
            try {
                val uri = s.handle.createInvitation()
                val blob = "$uri|$myHex"
                Log.i(TAG, "INVITE_BLOB=$blob")
                _ui.value = UiState.Inviting(myHex, blob)
                val connId = s.handle.awaitConnection()
                connectionId = connId
                // The inviter does not yet know the peer. Learn it from the
                // peer's first (0-length hello) envelope via TOFU, then go live.
                _ui.value = UiState.Connecting(myHex)
                val first = s.handle.recvLearningSender(connId)
                val learned = first.senderOperationalPubkey
                Log.i(TAG, "LEARNED peer=${learned.toHex()}")
                goLive(connId, myHex, learned, firstInbound = first.payload)
            } catch (e: Exception) {
                Log.e(TAG, "createInvitation failed", e)
                _ui.value = UiState.Failed("invite: ${e.message}")
            }
        }
    }

    /** Accept a peer's `"<uri>|<peerKeyHex>"` invitation (acceptor side). */
    fun acceptInvitation(blob: String) {
        val s = session ?: return
        val myHex = (ui.value as? UiState.Ready)?.myKeyHex ?: s.publicKeyRaw.toHex()
        val parts = blob.trim().split("|", limit = 2)
        if (parts.size != 2) {
            _ui.value = UiState.Failed("invite must be <uri>|<peerKeyHex>")
            return
        }
        val peer = runCatching { parts[1].fromHex() }.getOrNull()
        if (peer == null) {
            _ui.value = UiState.Failed("invite has a malformed peer key")
            return
        }
        viewModelScope.launch {
            if (!awaitTor()) return@launch
            // Show a visible in-flight state: the SMP duplex handshake is
            // several Tor round-trips, so without this the UI looks idle.
            _ui.value = UiState.Connecting(myHex)
            try {
                val connId = s.handle.acceptInvitation(parts[0])
                connectionId = connId
                // Tell the inviter who we are: a 0-length hello so its
                // recvLearningSender learns our operational key (the inviter
                // could not know it before this). Then go live.
                s.handle.send(connId, peer, ByteArray(0))
                Log.i(TAG, "sent hello so the inviter learns our key")
                goLive(connId, myHex, peer, firstInbound = null)
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
                Log.i(TAG, "SENT len=${text.length}: $text")
                _messages.update { it + ChatMessage(mine = true, text = text) }
            } catch (e: Exception) {
                Log.e(TAG, "send failed", e)
                _messages.update { it + ChatMessage(mine = true, text = "[send failed: ${e.message}]") }
            }
        }
    }

    /**
     * Both sides converge here once the peer key is known: pin it, go
     * Connected, surface any **real** first message, and start the steady-state
     * recv loop. `firstInbound` is the inviter's already-consumed TOFU envelope
     * (a 0-length hello is the key-exchange marker, not a chat line — skip it).
     */
    private fun goLive(connId: String, myHex: String, peer: ByteArray, firstInbound: ByteArray?) {
        connectionId = connId
        peerKeyRaw = peer
        Log.i(TAG, "CONNECTED connId=$connId peer=${peer.toHex()}")
        _ui.value = UiState.Connected(myHex, peer.toHex())
        if (firstInbound != null && firstInbound.isNotEmpty()) {
            _messages.update { it + ChatMessage(mine = false, text = String(firstInbound)) }
        }
        startRecvLoop(connId, peer)
    }

    /** Continuously receive + append messages from the peer. */
    private fun startRecvLoop(connId: String, peer: ByteArray) {
        val s = session ?: return
        viewModelScope.launch {
            while (true) {
                try {
                    // op == device key in the demo, so peer is both.
                    val r = s.handle.recv(connId, peer, peer)
                    // 0-length payloads are hello/key-exchange markers, not chat.
                    if (r.payload.isEmpty()) continue
                    val text = String(r.payload)
                    Log.i(TAG, "RECV len=${text.length}: $text")
                    _messages.update { it + ChatMessage(mine = false, text = text) }
                } catch (e: Exception) {
                    // Expected when the conversation closes / transport drops —
                    // a recv that throws ends the loop. WARN (not ERROR): it is
                    // a normal terminal condition, and the Rust cause is logged
                    // de-opaqued under "CairnRust" (debug builds).
                    Log.w(TAG, "recv loop ended (recv threw): ${e.message}", e)
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
