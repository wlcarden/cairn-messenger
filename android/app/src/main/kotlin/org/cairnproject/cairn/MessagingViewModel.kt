// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.cairn_uniffi.CairnFfiException

/** Delivery state of an outgoing message (received messages are [SendStatus.NONE]). */
enum class SendStatus { NONE, SENDING, SENT, FAILED }

/**
 * A single chat line. [tsUnix] is the message wall-clock time; [id] is a local
 * identity so an optimistic send can be updated in place to its [status].
 */
data class ChatMessage(
    val id: Long,
    val mine: Boolean,
    val text: String,
    val tsUnix: Long,
    val status: SendStatus = SendStatus.NONE,
)

/**
 * A contact's verification state for the conversation header (D0006 §70).
 * [KEY_CHANGED] = a previously-verified contact whose channel presented a key
 * that no longer matches the one verified — surfaced from a recv signature
 * verify-failure ([CairnFfiException.EnvelopeVerifyFailed]).
 */
enum class Trust { UNVERIFIED, VERIFIED, KEY_CHANGED }

/**
 * The persisted trust of a contact for its badge. KEY_CHANGED only arises when a
 * `verified` record's [Contact.verifiedKeyHex] no longer equals its key; a
 * downgrade after a recv verify-failure leaves the record UNVERIFIED (a record
 * is keyed by its peer key and can't store a conflicting one), so on the contact
 * list this resolves to VERIFIED or UNVERIFIED.
 */
fun Contact.trust(): Trust = when {
    verified && (verifiedKeyHex == null || verifiedKeyHex == peerKeyHex) -> Trust.VERIFIED
    verified -> Trust.KEY_CHANGED
    else -> Trust.UNVERIFIED
}

/** Top-level UI phase. */
sealed interface UiState {
    /** First-ever launch: a one-screen "what is Cairn" explainer before setup. */
    data object Welcome : UiState

    /** Before unlock: ask for the passphrase (set it on [firstLaunch]). */
    data class Locked(val firstLaunch: Boolean, val error: String?) : UiState

    /** Bringing up the encrypted session + bundled Tor. */
    data object Starting : UiState

    /** Home: the list of saved conversations. */
    data class ContactList(
        val myKeyHex: String,
        val contacts: List<Contact>,
        /** A non-fatal error (e.g. a malformed pasted invitation) shown inline. */
        val error: String? = null,
        /** Per-contact unread counts (peer key hex → count). */
        val unread: Map<String, Int> = emptyMap(),
    ) : UiState

    /** Your own identity: key QR + fingerprint (reached from the app bar). */
    data class Identity(val myKeyHex: String) : UiState

    /** The add-a-contact screen (invite / scan / paste), behind the FAB. */
    data class AddContact(val myKeyHex: String) : UiState

    /** I created an invitation; show [inviteToShare] as a QR for a contact. */
    data class Inviting(val myKeyHex: String, val inviteToShare: String) : UiState

    /** Accepting / establishing; the SMP handshake is in flight over Tor. */
    data class Connecting(val myKeyHex: String) : UiState

    /** A live conversation with [peerKeyHex] ([displayName]). */
    data class Conversation(
        val myKeyHex: String,
        val peerKeyHex: String,
        val displayName: String,
        /** Verification state of the peer key, surfaced as the trust badge. */
        val trust: Trust,
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

    private val _torStatus = MutableStateFlow("Connecting to the Tor network…")
    val torStatus = _torStatus.asStateFlow()

    private var session: CairnSession? = null
    private var contacts: ContactStore? = null

    @Volatile private var torReady = false
    @Volatile private var appForeground = true
    private var connectionId: String? = null
    private var peerKeyRaw: ByteArray? = null

    /**
     * One receive loop per saved contact (connId → job) — global, not just the
     * open conversation, so messages arrive + notify in the background (C2).
     */
    private val recvJobs = mutableMapOf<String, Job>()
    private var pairingJob: Job? = null
    private var myHex: String = ""
    private val msgIdSeq = AtomicLong(0)
    private val unread = mutableMapOf<String, Int>()

    init {
        // Gate everything behind an unlock passphrase: the at-rest encryption
        // is only meaningful if it's keyed by a user secret. First launch (no
        // store yet) sets the passphrase; later launches must match it.
        val storeExists = java.io.File(getApplication<Application>().filesDir, "store.db").exists()
        _ui.value =
            if (storeExists) UiState.Locked(firstLaunch = false, error = null) else UiState.Welcome
    }

    /** Welcome → passphrase setup: the user tapped "Get started" (C4 onboarding). */
    fun beginSetup() {
        _ui.value = UiState.Locked(firstLaunch = true, error = null)
    }

    /**
     * Unlock (or, on first launch, set up) the encrypted session with
     * [passphrase] — derives the storage KEK + the SQLCipher DB key from it. A
     * wrong passphrase is rejected (the canary fails to decrypt) and returns to
     * the lock screen with an error.
     */
    fun unlock(passphrase: String) {
        if (passphrase.isEmpty() || session != null) return
        val firstLaunch = (ui.value as? UiState.Locked)?.firstLaunch ?: false
        _ui.value = UiState.Starting
        viewModelScope.launch {
            try {
                val s = withContext(Dispatchers.IO) {
                    CairnSession.bootstrap(
                        getApplication<Application>().filesDir,
                        passphrase.toByteArray(),
                    )
                }
                session = s
                contacts = ContactStore(s.storage)
                myHex = s.publicKeyRaw.toHex()
                // A public key, but still identifying metadata — keep it out of
                // release logcat (debug keeps it for the test harnesses).
                if (BuildConfig.DEBUG) Log.i(TAG, "MY_PUBKEY=$myHex")
                showContacts()
            } catch (e: Exception) {
                Log.w(TAG, "unlock failed: ${e.message}")
                _ui.value = UiState.Locked(firstLaunch, error = "Could not unlock — ${e.message}")
            }
        }
    }

    /** Refresh the contact list from the encrypted store + show the home screen. */
    private fun showContacts(error: String? = null) {
        val list = runCatching { contacts?.list() ?: emptyList() }.getOrDefault(emptyList())
        Log.i(TAG, "contacts: ${list.size}")
        _ui.value = UiState.ContactList(myHex, list, error, unread.toMap())
        ensureReceiving()
    }

    /** The Activity signals the bundled Tor is bootstrapped (SOCKS up). */
    fun onTorReady() {
        torReady = true
        _torStatus.value = "Connected to the Tor network"
    }

    fun onTorFailed(message: String) {
        Log.w(TAG, "Tor failed: $message")
        _torStatus.value = "Couldn't connect to the Tor network"
    }

    /** MainActivity reports whole-app foreground state (notify vs. live append). */
    fun onAppForeground(foreground: Boolean) {
        appForeground = foreground
    }

    /** Leave the terminal error screen (C3) — back to contacts if the session is up. */
    fun dismissFailure() {
        if (session != null) showContacts() else _ui.value = UiState.Locked(false, null)
    }

    /** Show the user's own identity screen (key QR + fingerprint). */
    fun showIdentity() {
        _ui.value = UiState.Identity(myHex)
    }

    /** Show the add-a-contact screen (invite / scan / paste). */
    fun showAddContact() {
        _ui.value = UiState.AddContact(myHex)
    }

    /** Cancel a pending invite/connect and return to the contact list (H3). */
    fun cancelPairing() {
        pairingJob?.cancel()
        pairingJob = null
        connectionId = null
        peerKeyRaw = null
        showContacts()
    }

    /**
     * Create an invitation to share (inviter side). The peer's operational key
     * is learned from its first envelope (TOFU, D0026 §12) — one QR/link, no
     * out-of-band swap.
     */
    fun createInvitation() {
        val s = session ?: return
        peerKeyRaw = null
        pairingJob = viewModelScope.launch {
            if (!awaitTor()) return@launch
            try {
                val uri = s.handle.createInvitation()
                // One scheme-validated token carries the SMP link + our key — no
                // fragile "<uri>|<key>" split (a "|" is legal in a URI) (H4).
                val blob = "cairn://invite?k=$myHex&u=" + URLEncoder.encode(uri, "UTF-8")
                if (BuildConfig.DEBUG) Log.i(TAG, "INVITE_BLOB=$blob")
                _ui.value = UiState.Inviting(myHex, blob)
                val connId = s.handle.awaitConnection()
                connectionId = connId
                _ui.value = UiState.Connecting(myHex)
                // Learn the peer from its first (0-length hello) envelope (TOFU).
                val first = s.handle.recvLearningSender(connId)
                val learned = first.senderOperationalPubkey
                if (BuildConfig.DEBUG) Log.i(TAG, "LEARNED peer=${learned.toHex()}")
                goLive(connId, learned, firstInbound = first.payload)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "createInvitation failed", e)
                _ui.value = UiState.Failed("invite: ${e.message}")
            }
        }
    }

    /** Accept a peer's `cairn://invite?k=…&u=…` invitation (acceptor side). */
    fun acceptInvitation(blob: String) {
        val s = session ?: return
        val parsed = parseInvite(blob)
        if (parsed == null) {
            showContacts(error = "That doesn't look like a Cairn invitation.")
            return
        }
        val (uri, peer) = parsed
        pairingJob = viewModelScope.launch {
            if (!awaitTor()) return@launch
            _ui.value = UiState.Connecting(myHex)
            try {
                val connId = s.handle.acceptInvitation(uri)
                connectionId = connId
                // Tell the inviter who we are (0-length hello) so its
                // recvLearningSender learns our key; then go live.
                s.handle.send(connId, peer, ByteArray(0))
                Log.i(TAG, "sent hello so the inviter learns our key")
                goLive(connId, peer, firstInbound = null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "acceptInvitation failed", e)
                _ui.value = UiState.Failed("accept: ${e.message}")
            }
        }
    }

    /**
     * Parse a `cairn://invite?k=<hex>&u=<urlencoded SMP uri>` invitation into the
     * SMP uri + the peer's operational key (H4 — one token, no "|" split, since a
     * "|" is legal in a URI). Tolerates the scheme with or without "//".
     */
    private fun parseInvite(blob: String): Pair<String, ByteArray>? {
        val t = blob.trim()
        val query = when {
            t.startsWith("cairn://invite?") -> t.removePrefix("cairn://invite?")
            t.startsWith("cairn:invite?") -> t.removePrefix("cairn:invite?")
            else -> return null
        }
        val params = query.split("&").mapNotNull {
            val i = it.indexOf('=')
            if (i < 0) null else it.substring(0, i) to it.substring(i + 1)
        }.toMap()
        val keyHex = params["k"] ?: return null
        val uriEnc = params["u"] ?: return null
        val uri = runCatching { URLDecoder.decode(uriEnc, "UTF-8") }.getOrNull() ?: return null
        val peer = runCatching { keyHex.fromHex() }.getOrNull() ?: return null
        return uri to peer
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
        unread.remove(contact.peerKeyHex)
        _messages.value = emptyList()
        viewModelScope.launch {
            val hist = withContext(Dispatchers.IO) {
                runCatching { s.handle.loadMessageHistory(peer) }.getOrDefault(emptyList())
            }
            _messages.value = hist.map {
                ChatMessage(
                    id = msgIdSeq.getAndIncrement(),
                    mine = it.mine,
                    text = String(it.payload),
                    tsUnix = it.timestampUnix.toLong(),
                    status = if (it.mine) SendStatus.SENT else SendStatus.NONE,
                )
            }
            Log.i(TAG, "opened ${contact.displayName}: ${hist.size} history msgs")
            Log.i(TAG, "contact trust=${contact.trust()}")
            _ui.value = UiState.Conversation(
                myHex,
                contact.peerKeyHex,
                contact.displayName,
                trust = contact.trust(),
            )
        }
        // The global receive manager already covers this contact; ensure its
        // loop is running (e.g. the first open right after unlock).
        ensureReceiving()
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

    /** Leave the conversation; keep receiving in the background + show contacts. */
    fun backToContacts() {
        connectionId = null
        peerKeyRaw = null
        _messages.value = emptyList()
        showContacts()
    }

    /**
     * Send [text]: optimistically show it as SENDING, then SENT once the
     * transport accepts it (the FFI send blocks until upload-complete) or FAILED
     * on error — the bubble updates in place, with no fake "[send failed]" line.
     */
    fun send(text: String) {
        val s = session ?: return
        val connId = connectionId ?: return
        val peer = peerKeyRaw ?: return
        if (text.isBlank()) return
        val id = msgIdSeq.getAndIncrement()
        val now = System.currentTimeMillis() / 1000
        _messages.update {
            it + ChatMessage(id, mine = true, text = text, tsUnix = now, status = SendStatus.SENDING)
        }
        viewModelScope.launch {
            try {
                s.handle.send(connId, peer, text.toByteArray())
                Log.i(TAG, "SENT len=${text.length}")
                updateStatus(id, SendStatus.SENT)
            } catch (e: Exception) {
                Log.e(TAG, "send failed", e)
                updateStatus(id, SendStatus.FAILED)
            }
        }
    }

    /** Re-send a failed message's text (tap-to-retry on a FAILED bubble). */
    fun resend(text: String) = send(text)

    private fun updateStatus(id: Long, status: SendStatus) {
        _messages.update { list -> list.map { if (it.id == id) it.copy(status = status) else it } }
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
        // A friendly, deterministic 3-word default name (e.g. "Brave Otter
        // Lantern") derived from the peer key — friendlier than a hex prefix,
        // and identical to the words the peer sees for itself (D0026 §12).
        val name = FriendlyName.of(peerHex)
        Log.i(TAG, "CONNECTED connId=$connId peer=$peerHex")
        runCatching {
            contacts?.save(
                Contact(
                    peerKeyHex = peerHex,
                    connId = connId,
                    displayName = name,
                    pairedAtUnix = System.currentTimeMillis() / 1000,
                ),
            )
        }
        _messages.value = emptyList()
        if (firstInbound != null && firstInbound.isNotEmpty()) {
            val now = System.currentTimeMillis() / 1000
            _messages.value =
                listOf(ChatMessage(msgIdSeq.getAndIncrement(), false, String(firstInbound), now))
        }
        // A freshly-paired contact is TOFU-unverified until the user confirms
        // the safety number out of band (D0006 §70).
        _ui.value = UiState.Conversation(myHex, peerHex, name, Trust.UNVERIFIED)
        ensureReceiving()
    }

    /**
     * Mark the open contact verified via the MANUAL safety-number compare path
     * (the user read the number out of band and asserts it matched, D0006 §70).
     * Prefer [confirmVerificationByScan], which checks the key cryptographically.
     */
    fun markCurrentVerified() {
        val peerHex = peerKeyRaw?.toHex() ?: return
        if (persistVerified(peerHex)) Log.i(TAG, "contact $peerHex VERIFIED (manual compare)")
    }

    /**
     * Verify by SCANNING the peer's key QR: succeeds only if the scanned key
     * equals the key pinned for this conversation (D0006 §70). This is the
     * reliable path — it checks the key bytes, not a human-compared number.
     * Returns false (and does not verify) on any mismatch.
     */
    fun confirmVerificationByScan(scannedKeyHex: String): Boolean {
        val peerHex = peerKeyRaw?.toHex() ?: return false
        val scanned = scannedKeyHex.trim().lowercase()
        if (scanned != peerHex) {
            Log.w(TAG, "verify scan MISMATCH on ${peerHex.take(12)}")
            return false
        }
        val ok = persistVerified(peerHex)
        if (ok) Log.i(TAG, "contact $peerHex VERIFIED by QR scan")
        return ok
    }

    /** Persist verified=true bound to [peerHex] + flip the live badge to green. */
    private fun persistVerified(peerHex: String): Boolean {
        val store = contacts ?: return false
        val existing = runCatching { store.get(peerHex) }.getOrNull() ?: return false
        val updated = existing.copy(verified = true, verifiedKeyHex = peerHex)
        if (runCatching { store.save(updated) }.isFailure) return false
        (_ui.value as? UiState.Conversation)?.let { _ui.value = it.copy(trust = Trust.VERIFIED) }
        return true
    }

    /**
     * A recv signature verify-failure means the channel is presenting a key that
     * no longer matches the one we pinned/verified — a re-pair or an active
     * interception (D0006 §70). Security-conservative response: downgrade the
     * persisted verification and surface the blocking KEY_CHANGED banner. (The
     * downgrade persists as plain unverified across a restart, since a contact
     * record is keyed by its peer key and can't hold a conflicting one.)
     */
    private fun onPeerKeyMismatch(peerHex: String) {
        contacts?.let { store ->
            runCatching { store.get(peerHex) }.getOrNull()?.let { c ->
                runCatching { store.save(c.copy(verified = false)) }
            }
        }
        Log.w(TAG, "PEER KEY MISMATCH on $peerHex — downgraded; surfacing KEY_CHANGED")
        val cur = _ui.value as? UiState.Conversation
        if (cur?.peerKeyHex == peerHex) _ui.value = cur.copy(trust = Trust.KEY_CHANGED)
    }

    /** Driver/testing hook: exercise the key-mismatch handler without a live MITM. */
    fun simulateKeyMismatch() {
        peerKeyRaw?.toHex()?.let { onPeerKeyMismatch(it) }
    }

    /** Rename the open conversation's contact (persisted in the CONTACTS store). */
    fun renameCurrentContact(name: String) {
        val clean = name.trim()
        val peerHex = peerKeyRaw?.toHex() ?: return
        if (clean.isEmpty()) return
        val store = contacts ?: return
        val existing = runCatching { store.get(peerHex) }.getOrNull() ?: return
        runCatching { store.save(existing.copy(displayName = clean)) }
        Log.i(TAG, "contact $peerHex renamed -> $clean")
        (_ui.value as? UiState.Conversation)?.let { _ui.value = it.copy(displayName = clean) }
    }

    /** Delete the open conversation's contact, then return to the contact list. */
    fun deleteCurrentContact() {
        val peerHex = peerKeyRaw?.toHex() ?: return
        runCatching { contacts?.delete(peerHex) }
        Log.i(TAG, "contact $peerHex deleted")
        backToContacts()
    }

    /**
     * Ensure a receive loop is running for EVERY saved contact (not just the open
     * conversation) so messages arrive + notify in the background (C2). Idempotent
     * — skips contacts that already have a live loop.
     */
    private fun ensureReceiving() {
        val list = runCatching { contacts?.list() ?: emptyList() }.getOrDefault(emptyList())
        for (c in list) {
            val job = recvJobs[c.connId]
            if (job == null || !job.isActive) {
                recvJobs[c.connId] = viewModelScope.launch { receiveLoop(c) }
            }
        }
    }

    /**
     * Per-contact receive loop. Routes each message to the live view if that
     * conversation is visible, else to a content-hidden notification (C2). A
     * verify-failure downgrades trust (C1); transient transport errors retry with
     * a backoff, so a Tor blip no longer silently kills reception (was H2).
     */
    private suspend fun receiveLoop(contact: Contact) {
        val s = session ?: return
        val peer = runCatching { contact.peerKeyHex.fromHex() }.getOrNull() ?: return
        if (!awaitTorQuiet()) return
        var failures = 0
        while (true) {
            try {
                val r = s.handle.recv(contact.connId, peer, peer)
                failures = 0
                if (r.payload.isEmpty()) continue // hello/key-exchange marker
                val text = String(r.payload)
                Log.i(TAG, "RECV len=${text.length} from ${contact.peerKeyHex.take(12)}")
                routeIncoming(contact, text, r.receivedAtUnix.toLong())
            } catch (e: CairnFfiException.EnvelopeVerifyFailed) {
                // The envelope did not verify against the pinned peer key — a key
                // change or active interception (D0006 §70).
                Log.e(TAG, "recv VERIFY FAILED on ${contact.peerKeyHex.take(12)} — key change?", e)
                onPeerKeyMismatch(contact.peerKeyHex)
                break
            } catch (e: Exception) {
                failures++
                Log.w(TAG, "recv blip on ${contact.peerKeyHex.take(12)} (#$failures): ${e.message}")
                if (failures >= MAX_RECV_FAILURES) {
                    Log.w(TAG, "recv giving up on ${contact.peerKeyHex.take(12)}")
                    break
                }
                kotlinx.coroutines.delay(RECV_RETRY_MS)
            }
        }
    }

    /** Append to the live view if the conversation is visible, else notify (C2). */
    private fun routeIncoming(contact: Contact, text: String, tsUnix: Long) {
        val cur = _ui.value as? UiState.Conversation
        if (appForeground && cur?.peerKeyHex == contact.peerKeyHex) {
            _messages.update { it + ChatMessage(msgIdSeq.getAndIncrement(), false, text, tsUnix) }
        } else {
            unread[contact.peerKeyHex] = (unread[contact.peerKeyHex] ?: 0) + 1
            Log.i(TAG, "notify: new message from ${contact.peerKeyHex.take(12)}")
            Notifications.postNewMessage(getApplication<Application>(), contact.peerKeyHex)
            // Refresh the home list so the unread badge updates live.
            if (_ui.value is UiState.ContactList) showContacts()
        }
    }

    /** Wait for bundled Tor WITHOUT mutating the UI (for background loops). */
    private suspend fun awaitTorQuiet(): Boolean {
        var waited = 0
        while (!torReady && waited < TOR_WAIT_MS) {
            kotlinx.coroutines.delay(500)
            waited += 500
        }
        return torReady
    }

    /** Wait for bundled Tor; on timeout flip to the (recoverable) error screen. */
    private suspend fun awaitTor(): Boolean {
        if (awaitTorQuiet()) return true
        _ui.value = UiState.Failed("bundled Tor not ready")
        return false
    }

    private companion object {
        const val TAG = "CairnFfi"
        const val TOR_WAIT_MS = 200_000
        const val MAX_RECV_FAILURES = 12
        const val RECV_RETRY_MS = 5_000L
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
