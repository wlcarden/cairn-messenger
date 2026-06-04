// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.util.Log
import org.json.JSONObject
import uniffi.cairn_uniffi.StorageHandle

/**
 * A persisted contact (D0026 §12 contact list): the peer's operational pubkey
 * (also the storage record id), the SimpleX connection id to resume the
 * conversation, an optional display name, and when it was paired.
 */
data class Contact(
    /** Peer operational pubkey, lowercase hex (== the CONTACTS record id). */
    val peerKeyHex: String,
    /** SimpleX connection id, to resume recv after a restart. */
    val connId: String,
    /** User-facing name (defaults to a short key prefix). */
    val displayName: String,
    /** Unix-seconds when this contact was first paired. */
    val pairedAtUnix: Long,
    /**
     * `true` once the user has confirmed the safety number out of band (D0006
     * §70 in-person / channel-verified). `false` = paired but TOFU-unverified.
     */
    val verified: Boolean = false,
    /**
     * The exact peer key the user verified, lowercase hex — binds [verified] to
     * the key it attests (D0006 §70). The green badge shows only while this
     * still equals [peerKeyHex]; a recv verify-failure (a key change /
     * interception) downgrades [verified]. Null = never verified.
     */
    val verifiedKeyHex: String? = null,
    /** Last message's text (truncated) for the conversation-list preview. */
    val lastPreview: String = "",
    /** Unix-seconds of the last message — drives row recency sort + the time. */
    val lastAtUnix: Long = 0,
    /** Unread count (incremented on recv while not open; cleared on open). */
    val unread: Int = 0,
)

/**
 * Persists [Contact]s in the encrypted `CONTACTS` storage category (D0026 §12)
 * via the shared [StorageHandle] — the payload is XChaCha20-encrypted at rest
 * under the category DEK (D0022). The record id is the peer's 32-byte
 * operational pubkey, so a peer maps to exactly one contact. The metadata
 * (connId, name) is a small JSON blob (Android's built-in `org.json`; no extra
 * dependency).
 */
class ContactStore(private val storage: StorageHandle) {

    /** All saved contacts, most-recent-activity first (else pairing time). */
    fun list(): List<Contact> =
        storage.listRecords(CATEGORY)
            .mapNotNull { recordId -> decode(recordId.toHex(), storage.get(CATEGORY, recordId)) }
            .sortedByDescending { maxOf(it.lastAtUnix, it.pairedAtUnix) }

    /** The contact for [peerKeyHex], or null if not paired. */
    fun get(peerKeyHex: String): Contact? =
        decode(peerKeyHex, runCatching { storage.get(CATEGORY, peerKeyHex.fromHex()) }.getOrNull())

    /** Insert or update a contact (keyed by peer pubkey). */
    fun save(contact: Contact) {
        val payload = JSONObject()
            .put("conn", contact.connId)
            .put("name", contact.displayName)
            .put("at", contact.pairedAtUnix)
            .put("v", contact.verified)
            .apply { contact.verifiedKeyHex?.let { put("vk", it) } }
            .put("lp", contact.lastPreview)
            .put("la", contact.lastAtUnix)
            .put("ur", contact.unread)
            .toString()
            .toByteArray()
        runCatching { storage.put(CATEGORY, contact.peerKeyHex.fromHex(), payload) }
            .onFailure { Log.w(TAG, "contact save failed: ${it.message}") }
    }

    /**
     * Record the latest message for [peerKeyHex] (preview + time), optionally
     * bumping the unread count (a message that arrived while not in view). A
     * no-op if the contact isn't saved. Newlines are flattened + the preview is
     * truncated so the row stays a single legible line.
     */
    fun recordActivity(peerKeyHex: String, preview: String, atUnix: Long, bumpUnread: Boolean) {
        val c = get(peerKeyHex) ?: return
        save(
            c.copy(
                lastPreview = preview.replace('\n', ' ').take(PREVIEW_MAX),
                lastAtUnix = atUnix,
                unread = if (bumpUnread) c.unread + 1 else c.unread,
            ),
        )
    }

    /** Clear a contact's unread count (on open). No-op if already zero / absent. */
    fun clearUnread(peerKeyHex: String) {
        val c = get(peerKeyHex) ?: return
        if (c.unread != 0) save(c.copy(unread = 0))
    }

    /**
     * Remove a contact row so it no longer lists. This drops ONLY the CONTACTS
     * record; the conversation's MESSAGES history + the libsimplex connection
     * are purged separately by [MessagingViewModel.deleteCurrentContact] via the
     * messaging handle's deeper delete-purge (D0031), which holds the connId +
     * peer key needed for the teardown.
     */
    fun delete(peerKeyHex: String) {
        runCatching { storage.delete(CATEGORY, peerKeyHex.fromHex()) }
            .onFailure { Log.w(TAG, "contact delete failed: ${it.message}") }
    }

    private fun decode(peerKeyHex: String, bytes: ByteArray?): Contact? {
        if (bytes == null) return null
        return runCatching {
            val o = JSONObject(String(bytes))
            val verified = o.optBoolean("v", false)
            // Migration: records written before key-binding carry no "vk"; a
            // legacy verified record was keyed by the verified key, so backfill
            // verifiedKeyHex = peerKeyHex to preserve its green badge.
            val verifiedKey = o.optString("vk", "").ifEmpty { if (verified) peerKeyHex else null }
            Contact(
                peerKeyHex = peerKeyHex,
                connId = o.getString("conn"),
                displayName = o.optString("name", "").ifEmpty { FriendlyName.of(peerKeyHex) },
                pairedAtUnix = o.optLong("at", 0),
                verified = verified,
                verifiedKeyHex = verifiedKey,
                lastPreview = o.optString("lp", ""),
                lastAtUnix = o.optLong("la", 0),
                unread = o.optInt("ur", 0),
            )
        }.getOrNull()
    }

    private companion object {
        const val TAG = "CairnFfi"

        /** Must match `cairn_storage::categories::CONTACTS`. */
        const val CATEGORY = "contacts"

        /** Max stored preview length — keeps the row a single line + bounds storage. */
        const val PREVIEW_MAX = 120
    }
}
