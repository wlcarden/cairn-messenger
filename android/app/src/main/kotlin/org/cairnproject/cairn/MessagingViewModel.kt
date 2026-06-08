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
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.cairn_uniffi.CairnFfiException
import uniffi.cairn_uniffi.IntroductionKindFfi
import uniffi.cairn_uniffi.IntroductionMessageRecord
import uniffi.cairn_uniffi.ShareRecord
import uniffi.cairn_uniffi.StrengthFfi
import uniffi.cairn_uniffi.decodeIntroductionMessage
import uniffi.cairn_uniffi.encodeIntroductionMessage
import uniffi.cairn_uniffi.recoveryDecodeCard
import uniffi.cairn_uniffi.recoveryReconstructAndAttest
import uniffi.cairn_uniffi.recoveryVerifyMasterAttestation

/**
 * Delivery state of an outgoing message (received messages are [SendStatus.NONE]).
 * [READ] is set when the peer sends a read receipt covering this message (D0032),
 * and is only ever shown when the local read-receipts setting is on (reciprocal).
 */
enum class SendStatus { NONE, SENDING, SENT, READ, FAILED }

/**
 * An inbound introduction (D0037 §3) awaiting the user's consent — the only
 * place an introduction ever acts is behind one of these explicit prompts
 * (consent is the whole point, D0037 §2). Two shapes:
 *
 * - [Kind.APPROVE] — a `Request` arrived: "[introducerName] wants to introduce
 *   you to [peerName]." Approving mints a one-time invitation and sends it back;
 *   declining ends it. The introducer's vouch for the peer rides along, so the
 *   resulting contact shows [introducerName]'s provenance (D0036 reuse).
 * - [Kind.CONNECT] — a `Deliver` arrived: "[introducerName] introduced you to
 *   [peerName]; connect?" Connecting redeems the carried invitation; declining
 *   ends it.
 *
 * [vouch] is the introducer's `build_vouch` bytes for [peerKeyHex] (ingested on
 * consent so the new contact carries named provenance). [inviteUri] is the
 * one-time pairing blob (CONNECT only). [introducerConnId] is where an APPROVE's
 * `Response` is sent back.
 */
data class PendingIntroduction(
    val kind: Kind,
    val introducerKeyHex: String,
    val introducerName: String,
    val introducerConnId: String,
    val peerKeyHex: String,
    val peerName: String,
    val vouch: ByteArray?,
    val inviteUri: String?,
) {
    enum class Kind { APPROVE, CONNECT }

    // ByteArray defeats data-class structural equality; introductions are keyed
    // by (kind, introducer, peer) for dedup, not by the vouch bytes.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PendingIntroduction) return false
        return kind == other.kind &&
            introducerKeyHex == other.introducerKeyHex &&
            peerKeyHex == other.peerKeyHex
    }

    override fun hashCode(): Int =
        (kind.hashCode() * 31 + introducerKeyHex.hashCode()) * 31 + peerKeyHex.hashCode()
}

/**
 * An inbound recovery-share-return request (D0038 §7) awaiting the user's manual
 * approval — the holder side. [requesterName]/[requesterKeyHex] is the contact
 * (whose share we hold) asking for it back; [connId] is where the returned share
 * is sent. Manual approval is the whole Stage-2 gate (no cooling-off/challenge
 * yet — that is Stage 3).
 */
data class ShareReturnPrompt(
    val requesterKeyHex: String,
    val requesterName: String,
    val connId: String,
)

/**
 * A single chat line. [tsUnix] is the message wall-clock time; [id] is a local
 * identity so an optimistic send can be updated in place to its [status].
 * [messageNumber] is this message's send-chain position for an outgoing message
 * (`-1` if unknown/received) — compared against the peer's read high-water to
 * flip [status] to [SendStatus.READ] (D0032).
 */
data class ChatMessage(
    val id: Long,
    val mine: Boolean,
    val text: String,
    val tsUnix: Long,
    val status: SendStatus = SendStatus.NONE,
    val messageNumber: Long = -1,
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
    data class Locked(
        val firstLaunch: Boolean,
        val error: String?,
        /** A wrapped-passphrase blob exists → offer "Unlock with fingerprint" (D0029). */
        val quickUnlockEnrolled: Boolean = false,
        /**
         * This passphrase screen begins a RECOVERY (D0038 §5): setting it creates
         * the new device's at-rest storage + persistent operational key, after
         * which the session enters the card-collection [Recovery] flow instead of
         * the contact list. Only meaningful with [firstLaunch].
         */
        val recovering: Boolean = false,
    ) : UiState

    /**
     * Paper-share recovery (D0038 §5): the user enters recovery cards until a
     * threshold reconstructs their master, which re-roots THIS device's
     * persistent operational identity under it. Reached from Welcome →
     * "Recover", after the new device's passphrase + key are bootstrapped.
     */
    data class Recovery(
        /** Distinct cards entered so far (deduped by Shamir id). */
        val collected: Int,
        /** Friendly name of the master the entered cards attest (once ≥1 card). */
        val masterName: String?,
        /** A transient status line (e.g. "Reconstructing…"). */
        val status: String? = null,
        /** A rejected-card / failed-reconstruction message (recoverable). */
        val error: String? = null,
        /** Reconstruction succeeded + the identity was re-rooted under the master. */
        val recovered: Boolean = false,
    ) : UiState

    /** Bringing up the encrypted session + bundled Tor. */
    data object Starting : UiState

    /** Home: the list of saved conversations. */
    data class ContactList(
        val myKeyHex: String,
        /** Contacts, most-recent-activity first; each carries its own preview +
         *  time + unread count (persisted in the CONTACTS record). */
        val contacts: List<Contact>,
        /** A non-fatal error (e.g. a malformed pasted invitation) shown inline. */
        val error: String? = null,
    ) : UiState

    /** Your own identity: key QR + fingerprint (reached from the app bar). */
    data class Identity(
        val myKeyHex: String,
        /** Whether quick unlock is enrolled (to offer turning it off, D0029). */
        val quickUnlockEnrolled: Boolean = false,
        /**
         * The device-key attestation verdict (D0033 §2): proves in Rust that
         * the signing key is hardware-backed + hardware-generated. Advisory.
         */
        val attestation: DeviceAttestation = DeviceAttestation.unattested("unknown"),
        /**
         * Friendly name of the recovered master (D0038 §5) when this identity was
         * re-rooted via paper-share recovery — null when still self-issued. A
         * non-null value surfaces "Recovered identity — master <name>".
         */
        val masterName: String? = null,
    ) : UiState

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
        /**
         * The verification strength ([StrengthFfi] name) when [trust] is
         * `VERIFIED` — distinguishes in-person from channel-verified in the
         * trust label (D0035 §5). Null otherwise.
         */
        val verifiedStrength: String? = null,
        /**
         * Named, depth-1 provenance (D0036 §6): which of the user's verified
         * contacts have vouched for this key, each like "Bob (in person)".
         * Fenced to the user's OWN verified contacts — provenance, not
         * reputation. Empty when none.
         */
        val provenance: List<String> = emptyList(),
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

    /** Recovery shares this device holds for contacts (D0038 §7). Set on unlock. */
    private var recoveryPeers: RecoveryPeerStore? = null

    /** Pending peer-clock cooling-off releases (D0040 §4, 3b). Set on unlock. */
    private var recoverySchedules: RecoveryScheduleStore? = null

    /**
     * Cooling-off window before a phrase-verified share is released (D0040 §4):
     * 48h on the holder's own clock. Debug-overridable via the `coolingoff` driver
     * hook so the 2-device timer can be validated without waiting two days.
     */
    private var coolingOffSeconds: Long = 48L * 3600L

    /**
     * Contacts we've sent a recovery_request to (peerKeyHex) and are awaiting a
     * returned share from (D0038 §7). An inbound recovery_share from a contact in
     * this set is a RETURN (route it to the owner / gather); otherwise it is a
     * peer entrusting us a share to HOLD. Concurrent set: written on request,
     * read+cleared on the recv loop's Main dispatcher.
     */
    private val pendingShareRequests: MutableSet<String> =
        java.util.concurrent.ConcurrentHashMap.newKeySet()

    /**
     * Inbound recovery-share-return requests (D0038 §7) awaiting the user's manual
     * approval — the holder side. A queue (the UI shows the head), mirroring the
     * introduction-consent queue. Main-confined.
     */
    private val _shareReturnPrompts = MutableStateFlow<List<ShareReturnPrompt>>(emptyList())
    val shareReturnPrompts = _shareReturnPrompts.asStateFlow()

    @Volatile private var torReady = false
    @Volatile private var appForeground = true
    private var connectionId: String? = null
    private var peerKeyRaw: ByteArray? = null

    /**
     * Inbound introduction consent prompts (D0037 §3) awaiting the user's
     * decision — the introducee side. A queue (not a single slot) so a second
     * introduction arriving while one is open isn't dropped; the UI shows the
     * head. Main-confined (mutated only from the recv loops' Main updates +
     * the consent handlers).
     */
    private val _pendingIntroductions = MutableStateFlow<List<PendingIntroduction>>(emptyList())
    val pendingIntroductions = _pendingIntroductions.asStateFlow()

    /**
     * Introductions THIS device brokered (D0037 §3) that are awaiting the
     * minter's `Response`: (minterKeyHex, acceptorKeyHex). The relay of a
     * `Response` to the acceptor fires ONLY for a pair in this set, so a contact
     * cannot use this device as an unsolicited relay by sending an unsolicited
     * `Response`. Ephemeral (soft liveness, D0037 §4): lost on restart, which
     * fails the in-flight introduction gracefully rather than relaying stale
     * state. Concurrent set: written on initiate, read+cleared on the recv
     * loop's Main dispatcher.
     */
    private val pendingOutgoingIntroductions: MutableSet<Pair<String, String>> =
        java.util.concurrent.ConcurrentHashMap.newKeySet()

    /**
     * One receive loop per saved contact (connId → job) — global, not just the
     * open conversation, so messages arrive + notify in the background (C2).
     */
    private val recvJobs = mutableMapOf<String, Job>()

    /**
     * connIds whose FIRST recv must re-anchor the chain via `recvLearningSender`
     * instead of strict `recv` (D0031 re-pair fix). Set by the ACCEPTOR on a
     * fresh pairing: a re-pair after a one-sided delete leaves the two sides'
     * `prior_envelope_hash` chains desynced, so the first envelope of a new
     * pairing won't link to the acceptor's (possibly stale) cursor — the
     * learning path re-anchors it. The inviter already re-anchors via its
     * standalone `recvLearningSender`; a RESUME (saved contact, not a fresh
     * pairing) is NOT added, so it keeps the strict steady-state recv (D0026
     * §2.3 preserved). Concurrent set: read on the loop's Main dispatcher,
     * written on the pairing coroutine's Main dispatcher.
     */
    private val reanchorFirstRecv: MutableSet<String> =
        java.util.concurrent.ConcurrentHashMap.newKeySet()
    private var pairingJob: Job? = null
    private var myHex: String = ""
    private val msgIdSeq = AtomicLong(0)

    /**
     * Paper-share recovery (D0038 §5) collection state: the decoded shares plus
     * the single commitment + master every card in a set must agree on. Reset on
     * enter / leave / success. Main-confined (mutated only from the recovery
     * handlers, which run on the Main dispatcher).
     */
    private val recoveryCards = mutableListOf<ShareRecord>()
    private var recoveryCommitment: ByteArray? = null
    private var recoveryMaster: ByteArray? = null

    /**
     * True while a fresh device is recovering and pairs with a recovery peer to
     * pull back a held share (D0040 §7, 3a-ii). It re-routes [goLive] so the
     * pairing returns to the card collector + auto-requests the share, instead of
     * opening a chat. Set by [gatherFromPeer]; cleared on enter/leave recovery.
     */
    private var gatheringFromRecovery = false

    /**
     * Per-requester wrong-phrase attempt counter (D0040 §3, review remediation).
     * The 3a-ii "retry on mismatch" fix removed the de-facto rate limit (a wrong
     * guess used to burn the prompt + force a re-request); without a cap that is an
     * unbounded online guessing oracle against the phrase, contradicting D0005's
     * single-use intent. We cap at [MAX_PHRASE_ATTEMPTS] per prompt: typos are
     * absorbed, but on exhaustion the prompt is dropped so the requester must
     * re-request (re-incurring the Tor round-trip — the restored friction).
     */
    private val phraseAttempts = mutableMapOf<String, Int>()

    /**
     * The in-flight reconstruct/attest/adopt coroutine (D0038 §5), tracked so
     * [leaveRecovery] can cancel it — otherwise a late completion would write a
     * `Recovery` state over the contact list the user already navigated to.
     */
    private var recoveryJob: Job? = null

    init {
        // Gate everything behind an unlock passphrase: the at-rest encryption
        // is only meaningful if it's keyed by a user secret. First launch (no
        // store yet) sets the passphrase; later launches must match it.
        val storeExists = java.io.File(getApplication<Application>().filesDir, "store.db").exists()
        _ui.value =
            if (storeExists) {
                UiState.Locked(firstLaunch = false, error = null, quickUnlockEnrolled = quickUnlockEnrolled())
            } else {
                UiState.Welcome
            }
    }

    /** A wrapped-passphrase blob exists on disk → quick unlock is enrolled (D0029). */
    private fun quickUnlockEnrolled(): Boolean =
        QuickUnlock.isEnrolled(getApplication<Application>().filesDir)

    /** Welcome → passphrase setup: the user tapped "Get started" (C4 onboarding). */
    fun beginSetup() {
        _ui.value = UiState.Locked(firstLaunch = true, error = null)
    }

    /**
     * Welcome → "Recover an existing identity" (D0038 §5). Recovery still needs a
     * NEW local passphrase + a fresh persistent device key for THIS device's
     * at-rest data (which is device-bound, not Shamir-recovered), so it routes
     * through the same first-launch passphrase screen — flagged [recovering] so
     * [unlock] enters the card-collection flow instead of the contact list.
     */
    fun beginRecovery() {
        _ui.value = UiState.Locked(firstLaunch = true, error = null, recovering = true)
    }

    /**
     * Unlock (or, on first launch, set up) the encrypted session with
     * [passphrase] — derives the storage KEK + the SQLCipher DB key from it. A
     * wrong passphrase is rejected (the canary fails to decrypt) and returns to
     * the lock screen with an error.
     */
    fun unlock(passphrase: String, onUnlocked: (() -> Unit)? = null) {
        if (passphrase.isEmpty() || session != null) return
        val locked = ui.value as? UiState.Locked
        val firstLaunch = locked?.firstLaunch ?: false
        val recovering = locked?.recovering ?: false
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
                recoveryPeers = RecoveryPeerStore(s.storage)
                recoverySchedules = RecoveryScheduleStore(s.storage)
                // Lazy cooling-off firing (D0040 §4): on app-launch / unlock, release
                // any cooling-off window that elapsed while we were closed.
                fireDueReleases()
                myHex = s.publicKeyRaw.toHex()
                // A public key, but still identifying metadata — keep it out of
                // release logcat (debug keeps it for the test harnesses).
                if (BuildConfig.DEBUG) Log.i(TAG, "MY_PUBKEY=$myHex")
                // Session up + passphrase known-correct: let the caller enroll
                // quick unlock now, while it still holds the passphrase (D0029) —
                // so the passphrase is never retained in this ViewModel.
                onUnlocked?.invoke()
                // Recovery (D0038 §5): collect cards + re-root, instead of going
                // straight to the (empty) contact list.
                if (recovering) enterRecovery() else showContacts()
            } catch (e: Exception) {
                Log.w(TAG, "unlock failed: ${e.message}")
                _ui.value = UiState.Locked(
                    firstLaunch,
                    error = "Could not unlock — ${e.message}",
                    quickUnlockEnrolled = quickUnlockEnrolled(),
                )
            }
        }
    }

    /** Refresh the contact list from the encrypted store + show the home screen. */
    private fun showContacts(error: String? = null) {
        val list = runCatching { contacts?.list() ?: emptyList() }.getOrDefault(emptyList())
        Log.i(TAG, "contacts: ${list.size}")
        _ui.value = UiState.ContactList(myHex, list, error)
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
        // A gather pairing that Failed: consume the latch and return to the card
        // collector, not the contact list (review remediation — keeps recovery alive
        // and stops a stuck flag from mis-routing the next normal pairing).
        if (gatheringFromRecovery) {
            gatheringFromRecovery = false
            _ui.value = UiState.Recovery(
                collected = recoveryCards.size,
                masterName = recoveryMaster?.let { FriendlyName.of(it.toHex()) },
            )
            return
        }
        if (session != null) showContacts() else _ui.value = UiState.Locked(false, null)
    }

    /**
     * Change the unlock passphrase (D0030 §3): re-key the encrypted store from
     * [current] to [new] off the main thread (Argon2id ×2 + a full re-encrypt,
     * atomic), then invalidate quick unlock — its wrapped blob holds the OLD
     * passphrase. [onResult] (`ok`, `error`) runs on the main thread; a wrong
     * [current] is reported, not applied (the rekey aborts with no mutation).
     */
    fun changePassphrase(current: String, new: String, onResult: (Boolean, String?) -> Unit) {
        val s = session
        if (s == null) {
            onResult(false, "Not unlocked.")
            return
        }
        if (current.isEmpty() || new.isEmpty()) {
            onResult(false, "Enter both passphrases.")
            return
        }
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    s.changePassphrase(current.toByteArray(), new.toByteArray())
                }
                // The quick-unlock blob wraps the OLD passphrase — invalidate it.
                QuickUnlock.disable(getApplication<Application>().filesDir)
                Log.i(TAG, "passphrase changed; quick-unlock invalidated")
                onResult(true, null)
            } catch (e: CairnFfiException.StorageDecryptFailed) {
                Log.w(TAG, "changePassphrase: wrong current passphrase")
                onResult(false, "Your current passphrase is incorrect.")
            } catch (e: Exception) {
                Log.e(TAG, "changePassphrase failed", e)
                onResult(false, "Couldn't change passphrase — ${e.message}")
            }
        }
    }

    /** Show the user's own identity screen (key QR + fingerprint). */
    fun showIdentity() {
        // Surface the recovered master (D0038 §5) when this identity was re-rooted
        // — durable across launches (loaded from the IDENTITY store at bootstrap).
        val masterName = session?.masterPubkey?.let { FriendlyName.of(it.toHex()) }
        _ui.value = UiState.Identity(
            myHex,
            quickUnlockEnrolled = quickUnlockEnrolled(),
            attestation = session?.attestation ?: DeviceAttestation.unattested("no-session"),
            masterName = masterName,
        )
    }

    // ── Paper-share recovery (D0038 §5) ──────────────────────────────────────

    /** Post-bootstrap entry into the card-collection recovery screen. */
    private fun enterRecovery() {
        recoveryCards.clear()
        recoveryCommitment = null
        recoveryMaster = null
        gatheringFromRecovery = false
        pendingShareRequests.clear()
        phraseAttempts.clear()
        _ui.value = UiState.Recovery(collected = 0, masterName = null)
    }

    /**
     * Decode + collect one or more recovery cards (D0038 §5). Tolerates a
     * multi-line/space-separated paste (one card token per line). Each token is
     * decoded in Rust ([recoveryDecodeCard]); all cards in a set must agree on
     * the commitment + master (a card from a different split is rejected), and a
     * duplicate Shamir id is ignored.
     */
    fun addRecoveryCard(text: String) {
        if (ui.value !is UiState.Recovery) return
        val tokens = text.split('\n', '\r', ' ', '\t').map { it.trim() }.filter { it.isNotEmpty() }
        if (tokens.isEmpty()) return
        var added = 0
        var rejected: String? = null
        for (token in tokens) {
            val card = try {
                recoveryDecodeCard(token)
            } catch (e: CairnFfiException) {
                rejected = "That doesn't look like a recovery card."
                continue
            }
            val commit = recoveryCommitment
            if (commit == null) {
                recoveryCommitment = card.commitment
                recoveryMaster = card.masterPubkey
            } else if (!commit.contentEquals(card.commitment) ||
                recoveryMaster?.contentEquals(card.masterPubkey) != true
            ) {
                rejected = "That card is from a different identity — skipped."
                continue
            }
            if (recoveryCards.any { it.id == card.share.id }) continue // duplicate
            recoveryCards.add(card.share)
            added++
        }
        _ui.value = UiState.Recovery(
            collected = recoveryCards.size,
            masterName = recoveryMaster?.let { FriendlyName.of(it.toHex()) },
            error = if (added == 0) (rejected ?: "No new cards in that.") else null,
        )
    }

    /**
     * Reconstruct the master from the collected cards + re-root THIS device's
     * persistent operational identity under it (D0038 §5). On success the signed
     * master attestation + the master pubkey are persisted as the hop-#3
     * credential ([CairnSession.adoptMasterAttestation]); on too-few/wrong cards
     * the screen stays put so the user can add the rest. The reconstruction +
     * zeroization happen entirely in Rust — no secret crosses back.
     */
    fun attemptRecovery() {
        val s = session ?: return
        if (ui.value !is UiState.Recovery) return
        val commit = recoveryCommitment
        val master = recoveryMaster
        if (commit == null || master == null || recoveryCards.size < 2) {
            _ui.value = UiState.Recovery(
                collected = recoveryCards.size,
                masterName = master?.let { FriendlyName.of(it.toHex()) },
                error = "Enter at least two of your recovery cards.",
            )
            return
        }
        val shares = recoveryCards.toList()
        _ui.value = UiState.Recovery(
            collected = shares.size,
            masterName = FriendlyName.of(master.toHex()),
            status = "Reconstructing your identity…",
        )
        // Track the job so leaveRecovery can cancel a slow reconstruction (review
        // F2): cancellation throws at the withContext suspension points, which the
        // CancellationException re-throw below propagates (NOT the generic catch).
        recoveryJob = viewModelScope.launch {
            try {
                val now = (System.currentTimeMillis() / 1000L).toULong()
                val attestation = withContext(Dispatchers.IO) {
                    recoveryReconstructAndAttest(shares, commit, s.publicKeyRaw, now)
                }
                // Verify the attestation binds OUR operational key to the claimed
                // master before adopting it (defense in depth — the FFI already
                // checked the commitment).
                val rec = withContext(Dispatchers.IO) {
                    recoveryVerifyMasterAttestation(attestation, master)
                }
                if (!rec.operationalIdentity.contentEquals(s.publicKeyRaw)) {
                    throw IllegalStateException("attestation does not bind this device")
                }
                withContext(Dispatchers.IO) { s.adoptMasterAttestation(attestation, rec.master) }
                Log.i(TAG, "recovery: identity re-rooted under master ${FriendlyName.of(rec.master.toHex())}")
                // The user may have navigated away (leaveRecovery) during the
                // reconstruction window — if so, don't clobber where they went.
                if (ui.value !is UiState.Recovery) return@launch
                recoveryCards.clear()
                recoveryCommitment = null
                recoveryMaster = null
                gatheringFromRecovery = false // recovery done — drop the gather latch
                pendingShareRequests.clear()
                phraseAttempts.clear()
                _ui.value = UiState.Recovery(
                    collected = shares.size,
                    masterName = FriendlyName.of(rec.master.toHex()),
                    recovered = true,
                )
            } catch (e: CancellationException) {
                throw e // leaveRecovery cancelled us — let it unwind, don't error-write
            } catch (e: CairnFfiException.RecoveryFailed) {
                Log.w(TAG, "recovery: reconstruct failed (insufficient/wrong cards)")
                _ui.value = UiState.Recovery(
                    collected = shares.size,
                    masterName = FriendlyName.of(master.toHex()),
                    error = "Those cards didn't reconstruct your identity yet — add the rest of your recovery cards.",
                )
            } catch (e: Exception) {
                Log.e(TAG, "recovery failed", e)
                _ui.value = UiState.Recovery(
                    collected = shares.size,
                    masterName = FriendlyName.of(master.toHex()),
                    error = "Recovery failed — ${e.message}",
                )
            }
        }
    }

    /** Leave recovery (skip, or continue after success) → the contact list. */
    fun leaveRecovery() {
        recoveryJob?.cancel()
        recoveryJob = null
        recoveryCards.clear()
        recoveryCommitment = null
        recoveryMaster = null
        gatheringFromRecovery = false
        pendingShareRequests.clear()
        phraseAttempts.clear()
        showContacts()
    }

    /**
     * Recovery gather (D0040 §7, 3a-ii): from the card collector, pair with a
     * recovery peer to pull back the share you entrusted them. Creates an
     * invitation (the peer scans/pastes it) and flags [gatheringFromRecovery] so
     * [goLive] auto-requests the share + returns here instead of opening a chat.
     * The peer authenticates you by the challenge phrase (3a-i), not your key —
     * which on this fresh device is new (D0040 §2).
     */
    fun gatherFromPeer() {
        if (ui.value !is UiState.Recovery) return
        // Anti-poisoning (D0040 §8, review): a hostile peer could return a card from
        // a DIFFERENT split; if it were the FIRST card it would anchor reconstruction
        // on the attacker's commitment (denial-of-recovery + a spoofed master name).
        // Require one of YOUR OWN cards first, so the legitimate commitment is the
        // anchor and addRecoveryCard rejects any mismatched peer-returned card.
        if (recoveryCommitment == null) {
            _ui.value = UiState.Recovery(
                collected = recoveryCards.size,
                masterName = null,
                error = "Add one of your own recovery cards first (paste or scan) — that anchors your identity. Then gather the rest from peers.",
            )
            return
        }
        gatheringFromRecovery = true
        createInvitation()
    }

    // ── Peer-share distribution (D0038 §7, Stage 2) ──────────────────────────

    /**
     * Entrust one of YOUR recovery cards ([cardText]) to the OPEN contact as a
     * recovery peer (D0038 §7): the peer holds it and can return it to you later.
     * The card is validated locally before sending. Converts a paper backup share
     * into a peer-held one over the existing authenticated connection.
     */
    fun entrustRecoveryShare(cardText: String) {
        val s = session ?: return
        val connId = connectionId ?: return
        val peer = peerKeyRaw ?: return
        val card = cardText.trim()
        if (runCatching { recoveryDecodeCard(card) }.getOrNull() == null) {
            Log.w(TAG, "entrustRecoveryShare: not a valid recovery card")
            return
        }
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) { s.handle.sendRecoveryShare(connId, peer, card.toByteArray()) }
            }.onSuccess { Log.i(TAG, "recovery: entrusted a share to ${peer.toHex().take(12)}") }
                .onFailure { Log.e(TAG, "entrustRecoveryShare failed: ${it.message}") }
        }
    }

    /**
     * Ask the OPEN contact to return the recovery share they hold for you (D0038
     * §7). Marks them pending so their returned share is routed to the gather (or
     * an active recovery) rather than treated as a new hold.
     */
    fun requestHeldShare() {
        val connId = connectionId ?: return
        val peer = peerKeyRaw ?: return
        requestHeldShareTo(connId, peer)
    }

    /**
     * Send a recovery_request to an EXPLICIT [connId]/[peer] (D0038 §7). Taking the
     * target by parameter — rather than re-reading the shared `connectionId`/
     * `peerKeyRaw` fields — keeps an interleaving pairing (e.g. an introduction
     * accepted mid-gather) from clobbering the recipient (review remediation).
     */
    private fun requestHeldShareTo(connId: String, peer: ByteArray) {
        val s = session ?: return
        val peerHex = peer.toHex()
        pendingShareRequests.add(peerHex)
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) { s.handle.sendRecoveryRequest(connId, peer, ByteArray(0)) }
            }.onSuccess { Log.i(TAG, "recovery: requested our held share back from ${peerHex.take(12)}") }
                .onFailure {
                    Log.e(TAG, "requestHeldShare failed: ${it.message}")
                    pendingShareRequests.remove(peerHex)
                }
        }
    }

    /**
     * Inbound recovery share (D0038 §7): a RETURN of our own share (we requested
     * it) — routed to an active recovery / logged — or a contact entrusting us a
     * share to HOLD — persisted in the [RecoveryPeerStore] keyed by them. The
     * envelope already authenticated the sender. Called from the recv loop.
     */
    private fun handleIncomingRecoveryShare(contact: Contact, share: ByteArray) {
        val giverHex = contact.peerKeyHex
        if (pendingShareRequests.remove(giverHex)) {
            Log.i(TAG, "recovery: ${contact.displayName} RETURNED our held share (${share.size}B)")
            val cardText = runCatching { String(share) }.getOrNull()
            if (cardText != null && ui.value is UiState.Recovery) {
                // Anti-poisoning backstop (D0040 §8): never let a peer-returned card
                // be the FIRST/anchoring card — gatherFromPeer already requires a
                // user-entered anchor, this guards a returned card racing ahead of it.
                if (recoveryCommitment == null) {
                    Log.w(TAG, "recovery: ${contact.displayName}'s returned card arrived with no anchor yet — ignored (add your own card first)")
                } else {
                    addRecoveryCard(cardText)
                }
            }
        } else {
            // HOLD on behalf of the giver. The store write is blocking SQLite — keep
            // it off the recv loop's Main dispatcher — and only log success if it
            // actually persisted (else the giver thinks we hold a share we dropped).
            val peers = recoveryPeers ?: return
            viewModelScope.launch {
                val ok = withContext(Dispatchers.IO) { peers.hold(giverHex, share) }
                if (ok) {
                    Log.i(TAG, "recovery: now HOLDING a recovery share for ${contact.displayName} (${share.size}B)")
                } else {
                    Log.e(TAG, "recovery: FAILED to persist ${contact.displayName}'s share — NOT holding it")
                }
            }
        }
    }

    /**
     * Inbound recovery request (D0038 §7): a contact asks for the share we hold
     * for them back. Enqueue a manual-approval prompt — but only if we actually
     * hold something for them (else ignore). Called from the recv loop.
     */
    private fun handleIncomingRecoveryRequest(contact: Contact) {
        // 3a: gate on holding ANY share — a fresh-device requester's NEW key won't
        // match a specific held share, so the challenge phrase (verified at the
        // approval) is the matcher, not the key (D0040 §2). hasAnyHeld() is blocking
        // SQLite — run it off the recv loop's Main dispatcher.
        val peers = recoveryPeers ?: return
        val prompt = ShareReturnPrompt(contact.peerKeyHex, contact.displayName, contact.connId)
        viewModelScope.launch {
            if (!withContext(Dispatchers.IO) { peers.hasAnyHeld() }) {
                Log.i(TAG, "recovery: ${contact.displayName} requested a share but we hold none — ignored")
                return@launch
            }
            phraseAttempts.remove(prompt.requesterKeyHex) // fresh prompt → fresh attempt budget
            var enqueued = false
            _shareReturnPrompts.update { cur ->
                when {
                    cur.any { it.requesterKeyHex == prompt.requesterKeyHex } -> cur
                    // Anti-flood: bound the queue like the introduction queue does.
                    cur.size >= MAX_PENDING_SHARE_RETURNS -> cur
                    else -> {
                        enqueued = true
                        cur + prompt
                    }
                }
            }
            if (enqueued) {
                Log.i(TAG, "recovery: ${contact.displayName} asked for a held share — verify their phrase to return it")
            } else {
                Log.w(TAG, "recovery: share-return prompt from ${contact.displayName} dropped (already queued or queue full)")
            }
        }
    }

    /** Set the challenge phrase for the share held for [giverKeyHex] (D0040 §3). */
    fun setHeldSharePhrase(giverKeyHex: String, phrase: String) {
        val peers = recoveryPeers ?: return
        // setPhrase runs Argon2id (memory-hard) + scans for duplicate phrases — IO.
        viewModelScope.launch {
            val ok = withContext(Dispatchers.IO) { peers.setPhrase(giverKeyHex, phrase) }
            Log.i(TAG, "recovery: ${if (ok) "set" else "FAILED to set"} challenge phrase for held share ${giverKeyHex.take(12)}")
        }
    }

    /** Driver/convenience: set the phrase for the single held share (D0040 §3). */
    fun setFirstHeldPhrase(phrase: String) {
        val giver = recoveryPeers?.firstHeldGiver()
        if (giver == null) {
            Log.w(TAG, "setFirstHeldPhrase: hold no shares")
            return
        }
        setHeldSharePhrase(giver, phrase)
    }

    /**
     * Approve returning a held share to [prompt] by verifying the [phrase] the
     * requester produced (D0005 / D0040 §3): the phrase is matched against held
     * shares — the fresh-device matcher, since the requester's operational key is
     * new (D0040 §2). Returns `true` if the phrase matched a held share (the prompt
     * is then cleared and the share sent); `false` on no match — the prompt is
     * **kept** so the holder can retry a typo, BUT only up to [MAX_PHRASE_ATTEMPTS]
     * misses, after which the prompt is dropped and the requester must re-request.
     * That bound restores D0005's single-use intent: a wrong guess again *costs* a
     * round-trip, so this is not an unbounded online phrase-guessing oracle.
     * Nothing is sent on no match.
     *
     * Asynchronous: the match runs Argon2id per held share (memory-hard) off the
     * Main thread; [onResult] is invoked on Main with `true` on a verified return,
     * `false` on a mismatch (so the dialog can show its retry error).
     */
    fun returnShareByPhrase(
        prompt: ShareReturnPrompt,
        phrase: String,
        onResult: (Boolean) -> Unit = {},
    ) {
        val peers = recoveryPeers ?: return onResult(false)
        viewModelScope.launch {
            val held = withContext(Dispatchers.IO) { peers.findByPhrase(phrase) }
            if (held == null) {
                val misses = (phraseAttempts[prompt.requesterKeyHex] ?: 0) + 1
                if (misses >= MAX_PHRASE_ATTEMPTS) {
                    phraseAttempts.remove(prompt.requesterKeyHex)
                    _shareReturnPrompts.update { it.filterNot { p -> p.requesterKeyHex == prompt.requesterKeyHex } }
                    Log.w(TAG, "recovery: $MAX_PHRASE_ATTEMPTS wrong phrase attempts for ${prompt.requesterName} — prompt dropped, they must request again")
                } else {
                    phraseAttempts[prompt.requesterKeyHex] = misses
                    if (BuildConfig.DEBUG) {
                        Log.w(TAG, "recovery: phrase did NOT match for ${prompt.requesterName} (attempt $misses/$MAX_PHRASE_ATTEMPTS) — retryable")
                    }
                }
                onResult(false)
                return@launch
            }
            // Matched (D0040 §4, 3b): clear the prompt, then SCHEDULE the release at
            // our OWN clock + the cooling-off window — do NOT send now. The window
            // gives a coerced owner's network time to notice + the holder time to
            // cancel; fireDueReleases() (lazy, on unlock / recv-tick) sends it later.
            phraseAttempts.remove(prompt.requesterKeyHex)
            _shareReturnPrompts.update { it.filterNot { p -> p.requesterKeyHex == prompt.requesterKeyHex } }
            val schedules = recoverySchedules
            if (schedules == null) {
                onResult(false)
                return@launch
            }
            val releaseAt = (System.currentTimeMillis() / 1000) + coolingOffSeconds
            val ok = withContext(Dispatchers.IO) {
                schedules.schedule(prompt.requesterKeyHex, held.giverKeyHex, prompt.connId, releaseAt)
            }
            if (ok) {
                Log.i(TAG, "recovery: phrase verified — release to ${prompt.requesterName} SCHEDULED in ${coolingOffSeconds}s (~${coolingOffSeconds / 3600}h cooling-off, D0040 §4)")
                onResult(true)
                fireDueReleases() // fire now if the window is ~0 (debug/test override)
            } else {
                Log.e(TAG, "returnShareByPhrase: failed to schedule release for ${prompt.requesterName}")
                onResult(false)
            }
        }
    }

    /**
     * Fire any cooling-off release whose window has elapsed (D0040 §4, lazy):
     * re-load each due share from the [RecoveryPeerStore] and send it (key-11) to
     * the requester, then drop the schedule. Called on unlock + recv-loop ticks; a
     * debug driver hook forces it for the 2-device timer test.
     */
    fun fireDueReleases() {
        val s = session ?: return
        val schedules = recoverySchedules ?: return
        val peers = recoveryPeers ?: return
        viewModelScope.launch {
            val due = withContext(Dispatchers.IO) { schedules.due(System.currentTimeMillis() / 1000) }
            for (d in due) {
                val card = withContext(Dispatchers.IO) { peers.held(d.giverKeyHex) }
                val recipient = runCatching { d.requesterKeyHex.fromHex() }.getOrNull()
                if (card == null || recipient == null) {
                    Log.w(TAG, "recovery: due release for ${FriendlyName.of(d.requesterKeyHex)} has no held card — dropping schedule")
                    withContext(Dispatchers.IO) { schedules.remove(d.scheduleId) }
                    continue
                }
                runCatching {
                    withContext(Dispatchers.IO) { s.handle.sendRecoveryShare(d.connId, recipient, card) }
                }.onSuccess {
                    Log.i(TAG, "recovery: cooling-off elapsed — released a held share to ${FriendlyName.of(d.requesterKeyHex)}")
                    viewModelScope.launch { withContext(Dispatchers.IO) { schedules.remove(d.scheduleId) } }
                }.onFailure { Log.e(TAG, "recovery: fireDueReleases send failed: ${it.message}") }
            }
        }
    }

    /** Cancel the FIRST pending cooling-off release — peer-side manual cancel (D0040 §4). */
    fun cancelFirstScheduledRelease() {
        val schedules = recoverySchedules ?: return
        viewModelScope.launch {
            val ok = withContext(Dispatchers.IO) { schedules.cancelFirst() }
            Log.i(TAG, "recovery: ${if (ok) "cancelled a pending cooling-off release" else "no pending release to cancel"}")
        }
    }

    /** Debug: override the cooling-off window so the 2-device timer is testable (D0040 §4). */
    fun setCoolingOffSeconds(seconds: Long) {
        coolingOffSeconds = seconds.coerceAtLeast(0)
        Log.i(TAG, "recovery: cooling-off window set to ${coolingOffSeconds}s")
    }

    /** Decline returning the held share for [prompt] (D0038 §7). */
    fun declineReturnShare(prompt: ShareReturnPrompt) {
        phraseAttempts.remove(prompt.requesterKeyHex)
        _shareReturnPrompts.update { it.filterNot { p -> p.requesterKeyHex == prompt.requesterKeyHex } }
        Log.i(TAG, "recovery: declined returning a share to ${prompt.requesterName}")
    }

    /** Act on the HEAD share-return prompt — for the adb driver (D0040 §3). */
    fun approveFirstShareReturn(phrase: String) {
        _shareReturnPrompts.value.firstOrNull()?.let { returnShareByPhrase(it, phrase) }
    }

    fun declineFirstShareReturn() = _shareReturnPrompts.value.firstOrNull()?.let { declineReturnShare(it) }

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
        // A pairing started from the recovery gather (3a-ii) returns to the card
        // collector, not the (empty, locked-out) contact list. Consume the latch so
        // an abandoned gather can't mis-route a later normal pairing (review remediation).
        val wasGathering = gatheringFromRecovery
        gatheringFromRecovery = false
        if (wasGathering && ui.value !is UiState.Recovery) {
            _ui.value = UiState.Recovery(
                collected = recoveryCards.size,
                masterName = recoveryMaster?.let { FriendlyName.of(it.toHex()) },
            )
            return
        }
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
                // Re-anchor THIS pairing's first inbound (D0031): on a re-pair
                // after a one-sided delete, the inviter may send from a chain
                // we don't link to (it reset; we didn't) — the first recv goes
                // through recvLearningSender to accept + re-anchor, then steady
                // recv resumes. The inviter side already re-anchors separately.
                reanchorFirstRecv.add(connId)
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
        val hadUnread = contact.unread > 0
        runCatching { contacts?.clearUnread(contact.peerKeyHex) }
        _messages.value = emptyList()
        viewModelScope.launch {
            val hist = withContext(Dispatchers.IO) {
                runCatching { s.handle.loadMessageHistory(peer) }.getOrNull()
            }
            // Read-status (D0032) is reciprocal: only reconstruct/display "read"
            // when this device also sends receipts.
            val showRead = readReceiptsEnabled()
            val peerReadUpTo = hist?.peerReadUpTo?.toLong() ?: -1L
            _messages.value = (hist?.messages ?: emptyList()).map {
                val num = it.messageNumber.toLong()
                val outgoingStatus =
                    if (showRead && peerReadUpTo >= 0 && num in 0..peerReadUpTo) SendStatus.READ
                    else SendStatus.SENT
                ChatMessage(
                    id = msgIdSeq.getAndIncrement(),
                    mine = it.mine,
                    text = String(it.payload),
                    tsUnix = it.timestampUnix.toLong(),
                    status = if (it.mine) outgoingStatus else SendStatus.NONE,
                    messageNumber = if (it.mine) num else -1L,
                )
            }
            Log.i(TAG, "opened ${contact.displayName}: ${hist?.messages?.size ?: 0} history msgs")
            Log.i(TAG, "contact trust=${contact.trust()}")
            val prov = withContext(Dispatchers.IO) { computeProvenance(peer) }
            _ui.value = UiState.Conversation(
                myHex,
                contact.peerKeyHex,
                contact.displayName,
                trust = contact.trust(),
                verifiedStrength = contact.verifiedStrength.takeIf { contact.trust() == Trust.VERIFIED },
                provenance = prov,
            )
            // Opening unread messages = reading them → ack the peer (D0032), but
            // only if read receipts are enabled (off by default, reciprocal).
            if (showRead && hadUnread) {
                runCatching {
                    withContext(Dispatchers.IO) { s.handle.sendReadReceipt(contact.connId, peer) }
                }.onFailure { Log.w(TAG, "read-receipt on open failed: ${it.message}") }
            }
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
        // Update the conversation-list preview/time for this contact (my message).
        runCatching { contacts?.recordActivity(peer.toHex(), "You: $text", now, bumpUnread = false) }
        viewModelScope.launch {
            try {
                val sent = s.handle.send(connId, peer, text.toByteArray())
                Log.i(TAG, "SENT len=${text.length}")
                // Stamp the sent message's chain number so an incoming read
                // receipt can later mark it READ (D0032).
                val number = sent.nextMessageNumber.toLong() - 1
                _messages.update { list ->
                    list.map {
                        if (it.id == id) it.copy(status = SendStatus.SENT, messageNumber = number) else it
                    }
                }
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
     * Apply a peer read receipt (D0032): flip every outgoing message whose
     * send-chain number is ≤ [upTo] from SENT to READ. No-op on SENDING/FAILED
     * bubbles. Gated by the caller on the read-receipts setting (reciprocal).
     */
    private fun markReadUpTo(upTo: Long) {
        _messages.update { list ->
            list.map {
                if (it.mine && it.status == SendStatus.SENT && it.messageNumber in 0..upTo) {
                    it.copy(status = SendStatus.READ)
                } else {
                    it
                }
            }
        }
    }

    /** Whether this device sends + displays read receipts (D0032; default OFF). */
    fun readReceiptsEnabled(): Boolean =
        getApplication<Application>()
            .getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
            .getBoolean(KEY_READ_RECEIPTS, false)

    /**
     * Turn read receipts on/off (D0032). Reciprocal: when off this device sends
     * no receipts AND shows no read status. Turning OFF immediately drops any
     * READ ticks in the open conversation back to SENT.
     */
    fun setReadReceiptsEnabled(on: Boolean) {
        getApplication<Application>()
            .getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_READ_RECEIPTS, on)
            .apply()
        Log.i(TAG, "read receipts ${if (on) "ENABLED" else "disabled"}")
        if (!on) {
            _messages.update { list ->
                list.map { if (it.status == SendStatus.READ) it.copy(status = SendStatus.SENT) else it }
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
        ensureReceiving()
        if (gatheringFromRecovery) {
            // Recovery gather (D0040 §7, 3a-ii): we paired with a recovery peer on
            // this fresh device — don't open a chat. Ask them to return the share
            // we entrusted (the peer authenticates us by the challenge phrase, not
            // our NEW key, D0040 §2) and go back to the card collector. The returned
            // card auto-feeds addRecoveryCard (handleIncomingRecoveryShare routes to
            // the collector while we're in Recovery + the request is pending).
            Log.i(TAG, "recovery: paired with peer ${peerHex.take(12)} — requesting our held share back")
            // Single-shot latch: consume it now so a later NORMAL pairing isn't
            // mis-routed into an unsolicited recovery_request (review remediation).
            gatheringFromRecovery = false
            requestHeldShareTo(connId, peer)
            _ui.value = UiState.Recovery(
                collected = recoveryCards.size,
                masterName = recoveryMaster?.let { FriendlyName.of(it.toHex()) },
            )
            return
        }
        // A freshly-paired contact is TOFU-unverified until the user confirms
        // the safety number out of band (D0006 §70).
        _ui.value = UiState.Conversation(myHex, peerHex, name, Trust.UNVERIFIED)
    }

    /**
     * Mark the open contact verified via the MANUAL safety-number compare path
     * (the user read the number out of band and asserts it matched, D0006 §70).
     * Prefer [confirmVerificationByScan], which checks the key cryptographically.
     */
    fun markCurrentVerified() {
        val peerHex = peerKeyRaw?.toHex() ?: return
        // Manual safety-number compare = channel-verified (a separate channel),
        // not the strongest in-person ceremony (D0035 §3).
        if (persistVerified(peerHex, StrengthFfi.CHANNEL_VERIFIED)) {
            Log.i(TAG, "contact $peerHex VERIFIED (manual compare)")
        }
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
        // QR scan checks the key bytes face-to-face = in-person, the strongest
        // verification provenance (D0035 §3).
        val ok = persistVerified(peerHex, StrengthFfi.IN_PERSON)
        if (ok) Log.i(TAG, "contact $peerHex VERIFIED by QR scan")
        return ok
    }

    /**
     * Persist verified=true bound to [peerHex] + flip the live badge to green,
     * then mint a durable signed trust-graph attestation at [strength] (D0035
     * §4 — activation). The mint is best-effort + off-Main: the local verified
     * state above is the UX truth, and a StrongBox-signing failure does not undo
     * it. (Re-pointing the badge onto the chain is Stage 3b.)
     */
    private fun persistVerified(peerHex: String, strength: StrengthFfi): Boolean {
        val store = contacts ?: return false
        val existing = runCatching { store.get(peerHex) }.getOrNull() ?: return false
        val updated = existing.copy(
            verified = true,
            verifiedKeyHex = peerHex,
            verifiedStrength = strength.name,
        )
        if (runCatching { store.save(updated) }.isFailure) return false
        (_ui.value as? UiState.Conversation)?.let {
            _ui.value = it.copy(trust = Trust.VERIFIED, verifiedStrength = strength.name)
        }
        mintAttestation(strength)
        return true
    }

    /**
     * Revoke this contact's verification (D0035 §6): clear the local verified
     * projection (the badge downgrades to UNVERIFIED immediately — the safe
     * direction) and mint a durable revocation op off-Main, best-effort. A
     * `compromise` revoke records a security incident (cascade quarantine,
     * `revoked_as_of = now`); otherwise it is a clean withdrawal. Reversible by
     * re-verifying (a new attestation).
     */
    fun revokeCurrentContact(compromise: Boolean) {
        val peerHex = peerKeyRaw?.toHex() ?: return
        val subject = peerKeyRaw ?: return
        contacts?.let { store ->
            runCatching { store.get(peerHex) }.getOrNull()?.let { c ->
                runCatching { store.save(c.copy(verified = false, verifiedStrength = null)) }
            }
        }
        (_ui.value as? UiState.Conversation)?.let {
            _ui.value = it.copy(trust = Trust.UNVERIFIED, verifiedStrength = null)
        }
        val tg = session?.trustGraph ?: return
        val now = System.currentTimeMillis() / 1000L
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    if (compromise) {
                        tg.compromiseRevoke(subject, now.toULong(), now.toULong())
                    } else {
                        tg.withdrawRevoke(subject, now.toULong())
                    }
                }
            }.onSuccess {
                Log.i(TAG, "trust-graph: revoked ${peerHex.take(12)} (compromise=$compromise) -> ${it.recordId.size}B record")
            }.onFailure {
                Log.w(TAG, "trust-graph: revoke ${peerHex.take(12)} failed (best-effort): ${it.message}")
            }
        }
    }

    /**
     * Mint a signed [strength] attestation for the open contact's operational
     * key (D0035 §3 / §4) off the Main thread, best-effort. The self-issued
     * capability token is minted on first use (an extra StrongBox sign). A
     * failure is logged, never surfaced as a verify failure.
     */
    private fun mintAttestation(strength: StrengthFfi) {
        val tg = session?.trustGraph ?: return
        val subject = peerKeyRaw ?: return
        val subjectTag = subject.toHex().take(12)
        val now = System.currentTimeMillis() / 1000L
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) { tg.attest(subject, strength, now.toULong()) }
            }.onSuccess {
                Log.i(TAG, "trust-graph: attested $subjectTag ($strength) -> ${it.recordId.size}B record")
            }.onFailure {
                Log.w(TAG, "trust-graph: attest $subjectTag failed (best-effort): ${it.message}")
            }
        }
    }

    /**
     * Vouch for the OPEN contact to [recipientKeyHex] (D0036 §1): build a vouch
     * from this identity's attestation chain for the open contact + send it to
     * the recipient. A deliberate, opt-in act — the only thing that reveals to
     * the recipient that this device knows + verified the open contact. Off-Main,
     * best-effort.
     */
    fun vouchCurrentContactTo(recipientKeyHex: String) {
        val subject = peerKeyRaw ?: return
        val store = contacts ?: return
        val tg = session?.trustGraph ?: return
        val handle = session?.handle ?: return
        val recipient = runCatching { store.get(recipientKeyHex) }.getOrNull() ?: return
        val recipientKey = runCatching { recipientKeyHex.fromHex() }.getOrNull() ?: return
        val subjectTag = subject.toHex().take(12)
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    val vouch = tg.buildVouch(subject)
                    handle.sendVouch(recipient.connId, recipientKey, vouch)
                }
            }.onSuccess { Log.i(TAG, "vouched $subjectTag to ${recipientKeyHex.take(12)}") }
                .onFailure { Log.w(TAG, "vouch $subjectTag failed: ${it.message}") }
        }
    }

    /**
     * The user's other contacts (excluding [excludingKeyHex]) — the candidate
     * recipients for a vouch. Returns (displayName, peerKeyHex) pairs.
     */
    fun otherContacts(excludingKeyHex: String): List<Pair<String, String>> =
        runCatching { contacts?.list() }.getOrNull().orEmpty()
            .filter { it.peerKeyHex != excludingKeyHex }
            .map { it.displayName to it.peerKeyHex }

    /**
     * Named, depth-1 provenance for [peerKey] (D0036 §6): which of the user's
     * OWN verified contacts have vouched for this key, each like
     * "Bob (in person)". Fenced to verified contacts — provenance, not
     * reputation. A storage+crypto call; run off the Main thread.
     */
    private fun computeProvenance(peerKey: ByteArray): List<String> {
        val tg = session?.trustGraph ?: return emptyList()
        val store = contacts ?: return emptyList()
        val records = runCatching { tg.provenanceFor(peerKey) }.getOrNull() ?: return emptyList()
        return records.mapNotNull { rec ->
            val voucher = runCatching { store.get(rec.voucherOperationalPubkey.toHex()) }.getOrNull()
            // Fence (D0036 §6): only the user's OWN verified contacts count.
            if (voucher == null || !voucher.verified) return@mapNotNull null
            val strength = when (rec.strength) {
                StrengthFfi.IN_PERSON -> "in person"
                StrengthFfi.CHANNEL_VERIFIED -> "over a channel"
                else -> "asserted"
            }
            "${voucher.displayName} ($strength)"
        }
    }

    /** Recompute the OPEN conversation's provenance (after ingesting a vouch). */
    private fun refreshOpenProvenance() {
        val open = _ui.value as? UiState.Conversation ?: return
        val peerKey = runCatching { open.peerKeyHex.fromHex() }.getOrNull() ?: return
        val prov = computeProvenance(peerKey)
        (_ui.value as? UiState.Conversation)?.let {
            if (it.peerKeyHex == open.peerKeyHex) _ui.value = it.copy(provenance = prov)
        }
    }

    // ===================================================================
    // Introductions (D0037): consent-gated, connection-making, symmetric.
    // The introducer (this device, in `initiateIntroduction`) has verified
    // both parties; each introducee consents before anything happens; both
    // new contacts carry the introducer's named provenance (reusing the
    // D0036 vouch machinery — the vouch rides inside each message).
    // ===================================================================

    /**
     * The contacts THIS user could introduce the open contact to (D0037 §3):
     * the user's OTHER **verified** contacts. Verified-only because an
     * introduction carries this user's vouch for each party, and a vouch
     * requires an attestation chain (`buildVouch` — only verified contacts have
     * one). Returns (displayName, peerKeyHex) pairs.
     */
    fun introducibleContacts(excludingKeyHex: String): List<Pair<String, String>> =
        runCatching { contacts?.list() }.getOrNull().orEmpty()
            .filter { it.peerKeyHex != excludingKeyHex && it.verified }
            .map { it.displayName to it.peerKeyHex }

    /**
     * Introduce the OPEN contact (the **minter**) to [acceptorKeyHex] (the
     * **acceptor**) — D0037 §3 step 1. Sends the minter a `Request` naming the
     * acceptor, carrying this user's vouch FOR the acceptor (so the minter, on
     * approval, gains the acceptor with this user's provenance). The minter will
     * mint a one-time invitation + respond; this device then relays it to the
     * acceptor (`onIntroductionResponse`). Off-Main, best-effort.
     *
     * Both parties must be verified (an unverified one has no attestation chain
     * to vouch from); the picker already fences to verified contacts.
     */
    fun initiateIntroduction(acceptorKeyHex: String) {
        val minterKey = peerKeyRaw ?: return
        val minterHex = minterKey.toHex()
        val store = contacts ?: return
        val tg = session?.trustGraph ?: return
        val handle = session?.handle ?: return
        val minter = runCatching { store.get(minterHex) }.getOrNull() ?: return
        val acceptor = runCatching { store.get(acceptorKeyHex) }.getOrNull() ?: return
        val acceptorKey = runCatching { acceptorKeyHex.fromHex() }.getOrNull() ?: return
        if (!minter.verified || !acceptor.verified) {
            Log.w(TAG, "introduce: both parties must be verified")
            return
        }
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    // The minter is asked to meet the acceptor → carry the
                    // vouch FOR the acceptor (D0037 §6 reuses the vouch).
                    val vouchForAcceptor = tg.buildVouch(acceptorKey)
                    val request = IntroductionMessageRecord(
                        kind = IntroductionKindFfi.REQUEST,
                        peerKey = acceptorKey,
                        vouch = vouchForAcceptor,
                        inviteUri = null,
                        accept = null,
                    )
                    val bytes = encodeIntroductionMessage(request)
                    handle.sendIntroduction(minter.connId, minterKey, bytes)
                }
            }.onSuccess {
                // Remember we brokered this so an unsolicited `Response` cannot
                // make us relay (the relay gate, D0037 §3).
                pendingOutgoingIntroductions.add(minterHex to acceptorKeyHex)
                Log.i(TAG, "introduce: sent Request to ${minterHex.take(12)} re ${acceptorKeyHex.take(12)}")
            }.onFailure { Log.w(TAG, "introduce: Request failed: ${it.message}") }
        }
    }

    /**
     * Route a decoded introduction (D0037 §5) by kind. Called from the recv loop
     * (the carrying envelope already authenticated [sender]). A `Request` /
     * `Deliver` raises a consent prompt; a `Response` is the broker's relay step.
     */
    private fun handleIncomingIntroduction(sender: Contact, bytes: ByteArray) {
        val msg = runCatching { decodeIntroductionMessage(bytes) }.getOrNull()
        if (msg == null) {
            Log.w(TAG, "introduction decode failed from ${sender.peerKeyHex.take(12)}")
            return
        }
        when (msg.kind) {
            IntroductionKindFfi.REQUEST -> onIntroductionRequest(sender, msg)
            IntroductionKindFfi.RESPONSE -> onIntroductionResponse(sender, msg)
            IntroductionKindFfi.DELIVER -> onIntroductionDeliver(sender, msg)
        }
    }

    /**
     * A `Request` arrived (D0037 §3 step 2): the [introducer] proposes meeting
     * `peer_key`. Raise the APPROVE consent prompt — nothing happens until the
     * user approves (consent is the point, D0037 §2).
     */
    private fun onIntroductionRequest(introducer: Contact, msg: IntroductionMessageRecord) {
        val peerHex = msg.peerKey.toHex()
        enqueueIntroduction(
            PendingIntroduction(
                kind = PendingIntroduction.Kind.APPROVE,
                introducerKeyHex = introducer.peerKeyHex,
                introducerName = introducer.displayName,
                introducerConnId = introducer.connId,
                peerKeyHex = peerHex,
                peerName = FriendlyName.of(peerHex),
                vouch = msg.vouch,
                inviteUri = null,
            ),
        )
        Log.i(TAG, "introduction Request from ${introducer.displayName} re ${peerHex.take(12)}")
    }

    /**
     * A `Response` arrived (D0037 §3 step 4): the minter [responder] consented
     * (or declined) to OUR brokered introduction. On accept, relay a `Deliver`
     * (carrying our vouch for the minter + the minter's invitation) to the
     * acceptor. Relay ONLY for an introduction we brokered (the gate), so an
     * unsolicited `Response` cannot weaponize this device as a relay.
     */
    private fun onIntroductionResponse(responder: Contact, msg: IntroductionMessageRecord) {
        val minterHex = responder.peerKeyHex
        val acceptorHex = msg.peerKey.toHex()
        val gateKey = minterHex to acceptorHex
        // Gate: only act on a Response for an introduction WE brokered (so an
        // unsolicited Response cannot weaponize this device as a relay). PEEK
        // membership here; the gate is CONSUMED only once the outcome is known
        // (a genuine decline, or a Deliver that actually shipped) — not eagerly,
        // so a transport blip on the relay stays recoverable (D0037 review F5).
        if (!pendingOutgoingIntroductions.contains(gateKey)) {
            Log.w(TAG, "introduction Response not pending (ignored): ${minterHex.take(12)} -> ${acceptorHex.take(12)}")
            return
        }
        if (msg.accept != true || msg.inviteUri == null) {
            // The authenticated minter declined → the introduction is over; the
            // gate is spent. (Only the minter can produce this — the sender is
            // COSE-authenticated — so it is a genuine decline, not a spoof.)
            pendingOutgoingIntroductions.remove(gateKey)
            Log.i(TAG, "introduction declined by ${responder.displayName}")
            return
        }
        val inviteUri = msg.inviteUri ?: return
        val tg = session?.trustGraph ?: return
        val handle = session?.handle ?: return
        val store = contacts ?: return
        val acceptor = runCatching { store.get(acceptorHex) }.getOrNull() ?: return
        val minterKey = runCatching { minterHex.fromHex() }.getOrNull() ?: return
        val acceptorKey = runCatching { acceptorHex.fromHex() }.getOrNull() ?: return
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    // The acceptor is asked to meet the minter → carry our vouch
                    // FOR the minter + the minter's one-time invitation.
                    val vouchForMinter = tg.buildVouch(minterKey)
                    val deliver = IntroductionMessageRecord(
                        kind = IntroductionKindFfi.DELIVER,
                        peerKey = minterKey,
                        vouch = vouchForMinter,
                        inviteUri = inviteUri,
                        accept = null,
                    )
                    val bytes = encodeIntroductionMessage(deliver)
                    handle.sendIntroduction(acceptor.connId, acceptorKey, bytes)
                }
            }.onSuccess {
                // Consume the gate only AFTER the Deliver shipped, so a relay
                // failure leaves the introduction recoverable (the minter can
                // re-approve and the re-sent Response re-drives it) (F5).
                pendingOutgoingIntroductions.remove(gateKey)
                Log.i(TAG, "introduction: relayed Deliver to ${acceptor.displayName}")
            }.onFailure {
                Log.w(TAG, "introduction: Deliver relay failed, gate kept for retry: ${it.message}")
            }
        }
    }

    /**
     * A `Deliver` arrived (D0037 §3 step 5): the [introducer] says the other
     * party consented + here is their invitation. Raise the CONNECT consent
     * prompt — the user still chooses to connect (symmetric consent, D0037 §2).
     */
    private fun onIntroductionDeliver(introducer: Contact, msg: IntroductionMessageRecord) {
        val peerHex = msg.peerKey.toHex()
        if (msg.inviteUri == null) {
            Log.w(TAG, "introduction Deliver missing invitation (ignored)")
            return
        }
        enqueueIntroduction(
            PendingIntroduction(
                kind = PendingIntroduction.Kind.CONNECT,
                introducerKeyHex = introducer.peerKeyHex,
                introducerName = introducer.displayName,
                introducerConnId = introducer.connId,
                peerKeyHex = peerHex,
                peerName = FriendlyName.of(peerHex),
                vouch = msg.vouch,
                inviteUri = msg.inviteUri,
            ),
        )
        Log.i(TAG, "introduction Deliver from ${introducer.displayName} re ${peerHex.take(12)}")
    }

    /**
     * Approve an APPROVE-kind introduction (D0037 §3 step 3): mint a one-time
     * invitation, send it back to the introducer in a `Response`, ingest the
     * introducer's vouch for the peer (so the resulting contact shows named
     * provenance), then await the peer connecting + pair. The minter side.
     */
    fun approveIntroduction(p: PendingIntroduction) {
        dequeueIntroduction(p)
        if (p.kind != PendingIntroduction.Kind.APPROVE) return
        val s = session ?: return
        val tg = s.trustGraph ?: return
        val handle = s.handle
        val introducerKey = runCatching { p.introducerKeyHex.fromHex() }.getOrNull() ?: return
        val peerKey = runCatching { p.peerKeyHex.fromHex() }.getOrNull() ?: return
        // Track the approval as the pairing job so cancelPairing can reach it and
        // it is not an untracked, uncancellable coroutine (D0037 review F4).
        pairingJob = viewModelScope.launch {
            if (!awaitTor()) return@launch
            // Ingest the introducer's vouch for the peer FIRST, so the new
            // contact carries provenance the moment it pairs (D0036 reuse).
            p.vouch?.let { v ->
                runCatching { withContext(Dispatchers.IO) { tg.ingestVouch(introducerKey, v) } }
                    .onFailure { Log.w(TAG, "introduction: ingest peer vouch failed: ${it.message}") }
            }
            try {
                // Mint the one-time invitation + ship it to the introducer.
                val uri = withContext(Dispatchers.IO) { handle.createInvitation() }
                val blob = "cairn://invite?k=$myHex&u=" + URLEncoder.encode(uri, "UTF-8")
                val response = IntroductionMessageRecord(
                    kind = IntroductionKindFfi.RESPONSE,
                    peerKey = peerKey,
                    vouch = null,
                    inviteUri = blob,
                    accept = true,
                )
                withContext(Dispatchers.IO) {
                    val bytes = encodeIntroductionMessage(response)
                    handle.sendIntroduction(p.introducerConnId, introducerKey, bytes)
                }
                Log.i(TAG, "introduction: approved + sent invitation to ${p.introducerName}")
                // Await the peer connecting (soft liveness, D0037 §4); the first
                // envelope re-anchors via recvLearningSender, then pair. recv is
                // unbounded, so bound the hello wait (F4) — a peer who connects but
                // never sends the hello must not park this coroutine forever.
                val connId = withContext(Dispatchers.IO) { handle.awaitConnection() }
                val first = withTimeoutOrNull(INTRO_HELLO_TIMEOUT_MS) {
                    withContext(Dispatchers.IO) { handle.recvLearningSender(connId) }
                }
                if (first == null) {
                    Log.w(TAG, "introduction: acceptor connected but sent no hello in time; aborting")
                    return@launch
                }
                // Hard-fail if the connected peer is not the expected acceptor (F3):
                // do NOT bind the wrong peer onto this introduction (which would
                // mislabel them as introduced-by/vouched). A concurrent manual pair
                // popping the shared connect queue, or a redeemed-by-other invite,
                // surfaces here — abort rather than pair the wrong party.
                if (!first.senderOperationalPubkey.contentEquals(peerKey)) {
                    Log.w(TAG, "introduction: connected peer != expected acceptor; aborting (not pairing the wrong party)")
                    return@launch
                }
                goLive(connId, peerKey, firstInbound = first.payload)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "introduction: approve/mint failed: ${e.message}")
            }
        }
    }

    /**
     * Connect a CONNECT-kind introduction (D0037 §3 step 5): ingest the
     * introducer's vouch for the peer (named provenance), then redeem the
     * carried invitation to pair. The acceptor side.
     */
    fun connectIntroduction(p: PendingIntroduction) {
        dequeueIntroduction(p)
        if (p.kind != PendingIntroduction.Kind.CONNECT) return
        val invite = p.inviteUri ?: return
        val s = session ?: return
        val tg = s.trustGraph
        val introducerKey = runCatching { p.introducerKeyHex.fromHex() }.getOrNull()
        viewModelScope.launch {
            // Ingest BEFORE pairing so the new contact carries provenance.
            if (tg != null && introducerKey != null) {
                p.vouch?.let { v ->
                    runCatching { withContext(Dispatchers.IO) { tg.ingestVouch(introducerKey, v) } }
                        .onFailure { Log.w(TAG, "introduction: ingest peer vouch failed: ${it.message}") }
                }
            }
            Log.i(TAG, "introduction: connecting to ${p.peerName} (via ${p.introducerName})")
            // Reuse the standard accept-invitation pairing flow.
            acceptInvitation(invite)
        }
    }

    /** Dismiss/decline a pending introduction without acting (D0037 §2). */
    fun declineIntroduction(p: PendingIntroduction) {
        dequeueIntroduction(p)
        Log.i(TAG, "introduction declined: ${p.kind} from ${p.introducerName}")
    }

    /**
     * Driver/testing hooks: act on the HEAD of the introduction-consent queue
     * (a harness can't tap the Compose consent dialog, like [openFirstContact]).
     */
    fun approveFirstIntroduction() =
        _pendingIntroductions.value.firstOrNull()?.let { approveIntroduction(it) }

    fun connectFirstIntroduction() =
        _pendingIntroductions.value.firstOrNull()?.let { connectIntroduction(it) }

    fun declineFirstIntroduction() =
        _pendingIntroductions.value.firstOrNull()?.let { declineIntroduction(it) }

    private fun enqueueIntroduction(p: PendingIntroduction) {
        _pendingIntroductions.update { cur ->
            // REPLACE any existing prompt with the same (kind, introducer, peer)
            // so a re-sent message's fresh vouch/invitation supersedes a stale one
            // (D0037 review F6) instead of being shadowed by the first arrival.
            val deduped = cur.filterNot { it == p }
            // BOUND the queue (F6): beyond the cap, drop the new prompt (a flood of
            // distinct attacker-chosen peer_keys can't grow state without limit).
            // A replacement always fits (deduped shrank), so only genuinely-new
            // prompts at the cap are dropped.
            if (deduped.size >= MAX_PENDING_INTRODUCTIONS) {
                Log.w(TAG, "introduction queue full ($MAX_PENDING_INTRODUCTIONS); dropping prompt from ${p.introducerKeyHex.take(12)}")
                deduped
            } else {
                deduped + p
            }
        }
    }

    private fun dequeueIntroduction(p: PendingIntroduction) {
        _pendingIntroductions.update { cur -> cur.filterNot { it == p } }
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

    /**
     * Delete the open conversation's contact, then return to the contact list.
     *
     * The deeper delete-purge (D0031): beyond removing the contact row, this
     * cancels the contact's background receive loop, then purges the local
     * MESSAGES history AND tears down the SimpleX connection/queue via the
     * messaging handle — off the Main thread, best-effort (a teardown failure
     * still leaves the history purged + the contact gone). The local history
     * purge is the authoritative privacy action; the queue teardown is silent
     * (the peer is not notified).
     */
    fun deleteCurrentContact() {
        val peerHex = peerKeyRaw?.toHex() ?: return
        val peer = peerKeyRaw
        val s = session
        // The connId to tear down: the saved contact's (preferred) else the open
        // conversation's. Captured BEFORE backToContacts() nulls peerKeyRaw.
        val connId = runCatching { contacts?.get(peerHex)?.connId }.getOrNull() ?: connectionId
        // Stop the background recv loop on this connection — it is being torn down.
        connId?.let { recvJobs.remove(it)?.cancel() }
        // Purge local history + tear down the SimpleX queue off the Main thread
        // (the teardown is a network command); best-effort. The captured locals
        // outlive backToContacts()'s state reset.
        if (s != null && peer != null && connId != null) {
            viewModelScope.launch {
                runCatching {
                    withContext(Dispatchers.IO) { s.handle.purgeConversation(connId, peer) }
                }.onFailure { Log.w(TAG, "purge on delete failed: ${it.message}") }
            }
        }
        // Remove the contact row + leave the conversation immediately.
        runCatching { contacts?.delete(peerHex) }
        Log.i(TAG, "contact $peerHex deleted (history+connection purge requested)")
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
                // The blocking FFI recv runs OFF the Main thread, so a stale /
                // invalid connId (whose recv can block, not just suspend) can
                // never hang the UI (would ANR). The state updates below stay on
                // the loop's Main dispatcher, keeping recvJobs + _ui access
                // Main-confined (no concurrent ensureReceiving races).
                // The FIRST recv of a fresh acceptor pairing re-anchors the
                // chain (D0031) via recvLearningSender; everything else is the
                // strict steady-state recv (the set membership is read on Main,
                // before the off-Main recv).
                val reanchor = reanchorFirstRecv.contains(contact.connId)
                val r = withContext(Dispatchers.IO) {
                    if (reanchor) {
                        s.handle.recvLearningSender(contact.connId)
                    } else {
                        s.handle.recv(contact.connId, peer, peer)
                    }
                }
                if (reanchor) {
                    // Bind the re-learned sender to the peer we paired with: a
                    // re-anchoring recv accepts the FIRST envelope on the new
                    // connection, so confirm it is genuinely this contact before
                    // trusting it (TOFU re-pair safety). Only clear the flag on
                    // success, so a transient recv error keeps re-anchoring.
                    if (!r.senderOperationalPubkey.contentEquals(peer)) {
                        Log.e(TAG, "re-anchor: sender != expected peer on ${contact.peerKeyHex.take(12)}")
                        onPeerKeyMismatch(contact.peerKeyHex)
                        break
                    }
                    reanchorFirstRecv.remove(contact.connId)
                }
                failures = 0
                // A read receipt (D0032): empty payload + readUpTo set. Apply it to
                // the OPEN conversation's read-status (only when our setting is on —
                // reciprocal), then continue. It is NOT a message and must NOT be
                // acked back (no ping-pong).
                val readUpTo = r.readUpTo
                if (readUpTo != null) {
                    val open = _ui.value as? UiState.Conversation
                    if (readReceiptsEnabled() && open?.peerKeyHex == contact.peerKeyHex) {
                        markReadUpTo(readUpTo.toLong())
                        Log.i(TAG, "read receipt up to $readUpTo from ${contact.peerKeyHex.take(12)}")
                    }
                    continue
                }
                // A provenance vouch (D0036): empty payload + vouch set. The
                // envelope already authenticated the sender (this contact = the
                // voucher), so verify + ingest the foreign attestation, then
                // refresh the open conversation's provenance. NOT a message.
                val vouch = r.vouch
                if (vouch != null) {
                    session?.trustGraph?.let { tg ->
                        runCatching { tg.ingestVouch(peer, vouch) }
                            .onSuccess {
                                Log.i(TAG, "trust-graph: ingested vouch from ${contact.peerKeyHex.take(12)}")
                                refreshOpenProvenance()
                            }
                            .onFailure { Log.w(TAG, "trust-graph: ingest vouch failed: ${it.message}") }
                    }
                    continue
                }
                // An introduction control message (D0037): empty payload +
                // introduction set. The envelope authenticated the sender (this
                // contact), so route it to the dual-consent flow by kind. NOT a
                // message.
                val intro = r.introduction
                if (intro != null) {
                    handleIncomingIntroduction(contact, intro)
                    continue
                }
                // A recovery share (D0038 §7): empty payload + recoveryShare set.
                // If we requested it (we're gathering), it's a RETURN → surface to
                // the owner; otherwise this contact is entrusting us a share to
                // HOLD → store it keyed by them. NOT a message.
                val share = r.recoveryShare
                if (share != null) {
                    handleIncomingRecoveryShare(contact, share)
                    continue
                }
                // A recovery request (D0038 §7): this contact asks us to return the
                // share we hold for them → surface a manual-approval prompt. NOT a
                // message.
                if (r.recoveryRequest != null) {
                    handleIncomingRecoveryRequest(contact)
                    continue
                }
                if (r.payload.isEmpty()) continue // hello/key-exchange marker
                val text = String(r.payload)
                Log.i(TAG, "RECV len=${text.length} from ${contact.peerKeyHex.take(12)}")
                routeIncoming(contact, text, r.receivedAtUnix.toLong())
                // Actively viewing this conversation = reading the message → ack the
                // peer (D0032), fire-and-forget so the recv loop keeps draining;
                // gated on the setting (off by default, reciprocal).
                val openNow = _ui.value as? UiState.Conversation
                if (readReceiptsEnabled() && appForeground && openNow?.peerKeyHex == contact.peerKeyHex) {
                    viewModelScope.launch {
                        runCatching {
                            withContext(Dispatchers.IO) { s.handle.sendReadReceipt(contact.connId, peer) }
                        }.onFailure { Log.w(TAG, "live read-receipt failed: ${it.message}") }
                    }
                }
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
            // Visible conversation: update the preview/time but don't bump unread.
            runCatching { contacts?.recordActivity(contact.peerKeyHex, text, tsUnix, bumpUnread = false) }
        } else {
            // Not in view: update the preview/time + bump the persisted unread.
            runCatching { contacts?.recordActivity(contact.peerKeyHex, text, tsUnix, bumpUnread = true) }
            Log.i(TAG, "notify: new message from ${contact.peerKeyHex.take(12)}")
            Notifications.postNewMessage(getApplication<Application>(), contact.peerKeyHex)
            // Refresh the home list so the preview + unread badge update live.
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

        /**
         * Cap on outstanding inbound introduction consent prompts (D0037 review
         * F6), so a verified-but-hostile contact cannot flood Requests (each a
         * distinct attacker-chosen `peer_key`) to grow memory/UI state without
         * bound. Generous for honest use; far below an abuse volume.
         */
        const val MAX_PENDING_INTRODUCTIONS = 16

        /** Wrong-phrase guesses tolerated per share-return prompt before it is dropped (D0040 §3). */
        const val MAX_PHRASE_ATTEMPTS = 5

        /** Cap on queued share-return prompts — anti-flood, mirrors [MAX_PENDING_INTRODUCTIONS] (D0040 §3). */
        const val MAX_PENDING_SHARE_RETURNS = 8

        /**
         * Bound on the minter's wait for the acceptor's first (hello) envelope
         * AFTER they connect to the minted invite (D0037 review F4). `recv` itself
         * is unbounded; without this a peer who SMP-connects but never sends the
         * hello would park the approval coroutine indefinitely.
         */
        const val INTRO_HELLO_TIMEOUT_MS = 60_000L

        /** SharedPreferences for non-sensitive UI settings (D0032 read receipts). */
        const val PREFS = "cairn-prefs"
        const val KEY_READ_RECEIPTS = "read_receipts_enabled"
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
