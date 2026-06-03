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

    /** All saved contacts, most-recently-paired first. */
    fun list(): List<Contact> =
        storage.listRecords(CATEGORY)
            .mapNotNull { recordId -> decode(recordId.toHex(), storage.get(CATEGORY, recordId)) }
            .sortedByDescending { it.pairedAtUnix }

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
            .toString()
            .toByteArray()
        runCatching { storage.put(CATEGORY, contact.peerKeyHex.fromHex(), payload) }
            .onFailure { Log.w(TAG, "contact save failed: ${it.message}") }
    }

    /**
     * Remove a contact so it no longer lists. The conversation's message
     * history records (in the MESSAGES category) are left in place — a deeper
     * purge (history + the libsimplex connection) is a follow-on.
     */
    fun delete(peerKeyHex: String) {
        runCatching { storage.delete(CATEGORY, peerKeyHex.fromHex()) }
            .onFailure { Log.w(TAG, "contact delete failed: ${it.message}") }
    }

    private fun decode(peerKeyHex: String, bytes: ByteArray?): Contact? {
        if (bytes == null) return null
        return runCatching {
            val o = JSONObject(String(bytes))
            Contact(
                peerKeyHex = peerKeyHex,
                connId = o.getString("conn"),
                displayName = o.optString("name", peerKeyHex.take(8)),
                pairedAtUnix = o.optLong("at", 0),
                verified = o.optBoolean("v", false),
            )
        }.getOrNull()
    }

    private companion object {
        const val TAG = "CairnFfi"

        /** Must match `cairn_storage::categories::CONTACTS`. */
        const val CATEGORY = "contacts"
    }
}
