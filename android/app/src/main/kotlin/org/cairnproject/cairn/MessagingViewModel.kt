// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A single chat line. */
data class ChatMessage(val mine: Boolean, val text: String)

/** Top-level UI phase. */
sealed interface UiState {
    /** Bringing up the encrypted session + bundled Tor. */
    data object Starting : UiState

    /** Home: the list of saved contacts + add (invite / scan) actions. */
    data class ContactList(val myKeyHex: String, val contacts: List<Contact>) : UiState

    /** I created an invitation; show [inviteToShare] as a QR for a contact. */
    data class Inviting(val myKeyHex: String, val inviteToShare: String) : UiState

    /** Accepting / establishing; the SMP handshake is in flight over Tor. */
    data class Connecting(val myKeyHex: String) : UiState

    /** A live conversation with [peerKeyHex] ([displayName]). */
    data class Conversation(
        val myKeyHex: String,
        val peerKeyHex: String,
        val displayName: String,
    ) : UiState

    /** A fatal bootstrap/transport error. */
    data class Failed(val message: String) : UiState
}

/**
 * Drives the chat over [CairnSession]'s [SimplexAdapterHandle] + persists
 * contacts (D0026 §12): the home screen lists saved [Contact]s, and a
 * conversation loads its history from the encrypted `MESSAGES` store and
 * resumes the live recv loop on the contact's saved connection id. Pairing is
 * one-link (the inviter learns the peer from its first envelope via TOFU).
 */
class MessagingViewModel(app: Application) : AndroidViewModel(app) {

    private val _ui = MutableStateFlow<UiState>(UiState.Starting)
    val ui = _ui.asStateFlow()

    private val _messages = MutableStateFlow<List<ChatMessage>>(emptyList())
    val messages = _messages.asStateFlow()

    private val _torStatus = MutableStateFlow("starting bundled Tor…")
    val torStatus = _torStatus.asStateFlow()

    private var session: CairnSession? = null
    private var contacts: ContactStore? = null

    @Volatile private var torReady = false
    private var connectionId: String? = null
    private var peerKeyRaw: ByteArray? = null
    private var recvJob: Job? = null
    private var myHex: String = ""

    init {
        viewModelScope.launch {
            try {
                val s = withContext(Dispatchers.IO) {
                    CairnSession.bootstrap(getApplication<Application>().filesDir)
                }
                session = s
                contacts = ContactStore(s.storage)
                myHex = s.publicKeyRaw.toHex()
                Log.i(TAG, "MY_PUBKEY=$myHex")
                showContacts()
            } catch (e: Exception) {
                Log.e(TAG, "session bootstrap failed", e)
                _ui.value = UiState.Failed("session: ${e.message}")
            }
        }
    }

    /** Refresh the contact list from the encrypted store + show the home screen. */
    private fun showContacts() {
        val list = runCatching { contacts?.list() ?: emptyList() }.getOrDefault(emptyList())
        Log.i(TAG, "contacts: ${list.size}")
        _ui.value = UiState.ContactList(myHex, list)
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
     * is learned from its first envelope (TOFU, D0026 §12) — one QR/link, no
     * out-of-band swap.
     */
    fun createInvitation() {
        val s = session ?: return
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
                _ui.value = UiState.Connecting(myHex)
                // Learn the peer from its first (0-length hello) envelope (TOFU).
                val first = s.handle.recvLearningSender(connId)
                val learned = first.senderOperationalPubkey
                Log.i(TAG, "LEARNED peer=${learned.toHex()}")
                goLive(connId, learned, firstInbound = first.payload)
            } catch (e: Exception) {
                Log.e(TAG, "createInvitation failed", e)
                _ui.value = UiState.Failed("invite: ${e.message}")
            }
        }
    }

    /** Accept a peer's `"<uri>|<peerKeyHex>"` invitation (acceptor side). */
    fun acceptInvitation(blob: String) {
        val s = session ?: return
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
            _ui.value = UiState.Connecting(myHex)
            try {
                val connId = s.handle.acceptInvitation(parts[0])
                connectionId = connId
                // Tell the inviter who we are (0-length hello) so its
                // recvLearningSender learns our key; then go live.
                s.handle.send(connId, peer, ByteArray(0))
                Log.i(TAG, "sent hello so the inviter learns our key")
                goLive(connId, peer, firstInbound = null)
            } catch (e: Exception) {
                Log.e(TAG, "acceptInvitation failed", e)
                _ui.value = UiState.Failed("accept: ${e.message}")
            }
        }
    }

    /**
     * Open a SAVED contact: load its persisted history (works offline) into the
     * chat, then resume the live recv loop on its saved connection id so new
     * messages arrive (D0026 §12 — libsimplex re-subscribes its queues on init).
     */
    fun openContact(contact: Contact) {
        val s = session ?: return
        val peer = runCatching { contact.peerKeyHex.fromHex() }.getOrNull() ?: return
        peerKeyRaw = peer
        connectionId = contact.connId
        recvJob?.cancel()
        _messages.value = emptyList()
        viewModelScope.launch {
            val hist = withContext(Dispatchers.IO) {
                runCatching { s.handle.loadMessageHistory(peer) }.getOrDefault(emptyList())
            }
            _messages.value = hist.map { ChatMessage(it.mine, String(it.payload)) }
            Log.i(TAG, "opened ${contact.displayName}: ${hist.size} history msgs")
            _ui.value = UiState.Conversation(myHex, contact.peerKeyHex, contact.displayName)
            if (awaitTor()) startRecvLoop(contact.connId, peer)
        }
    }

    /**
     * Driver/testing hook: open the most-recently-paired saved contact (resume
     * its conversation). Mirrors tapping the top contact in the list — used by
     * the two-device reconnect harness, which can't tap a Compose card.
     */
    fun openFirstContact() {
        val list = runCatching { contacts?.list() ?: emptyList() }.getOrDefault(emptyList())
        val top = list.firstOrNull()
        if (top == null) {
            Log.w(TAG, "openFirstContact: no saved contacts")
        } else {
            openContact(top)
        }
    }

    /** Leave the conversation; cancel the recv loop + return to the contact list. */
    fun backToContacts() {
        recvJob?.cancel()
        recvJob = null
        connectionId = null
        peerKeyRaw = null
        _messages.value = emptyList()
        showContacts()
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
     * Pairing converged: pin the peer, persist the contact (so it lists +
     * resumes later), go to the conversation, surface any real first message,
     * and start the steady-state recv loop. A 0-length hello is the
     * key-exchange marker, not a chat line.
     */
    private fun goLive(connId: String, peer: ByteArray, firstInbound: ByteArray?) {
        connectionId = connId
        peerKeyRaw = peer
        val peerHex = peer.toHex()
        Log.i(TAG, "CONNECTED connId=$connId peer=$peerHex")
        runCatching {
            contacts?.save(
                Contact(
                    peerKeyHex = peerHex,
                    connId = connId,
                    displayName = peerHex.take(8),
                    pairedAtUnix = System.currentTimeMillis() / 1000,
                ),
            )
        }
        _messages.value = emptyList()
        if (firstInbound != null && firstInbound.isNotEmpty()) {
            _messages.value = listOf(ChatMessage(mine = false, text = String(firstInbound)))
        }
        _ui.value = UiState.Conversation(myHex, peerHex, peerHex.take(8))
        startRecvLoop(connId, peer)
    }

    /** Continuously receive + append messages from the peer (cancellable). */
    private fun startRecvLoop(connId: String, peer: ByteArray) {
        val s = session ?: return
        recvJob?.cancel()
        recvJob = viewModelScope.launch {
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
