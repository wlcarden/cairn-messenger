// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.util.Log
import java.security.MessageDigest
import java.security.SecureRandom
import uniffi.cairn_uniffi.StorageHandle

/**
 * The recovery shares this device HOLDS on behalf of contacts (D0038 §7 / D0040,
 * Stage 2 + 3a). When a contact entrusts us a recovery card, we persist it here
 * keyed by their operational pubkey; when they later ask for it back, we return it
 * — but only after verifying the **single-use challenge phrase** they agreed with
 * us at distribution (D0005). The phrase is the load-bearing anti-impersonation
 * gate AND the fresh-device matcher: on recovery the owner's device has a NEW
 * operational key, so the share cannot be found by key — it is found by the phrase
 * the owner produces ([findByPhrase]).
 *
 * Backed by the encrypted `recovery_shares` category. The stored value is
 * `[salt(16)][phraseHash(32)][cardText]`; `salt`/`phraseHash` are all-zero until a
 * phrase is set ([setPhrase]). The phrase hash is a salted SHA-256 — sufficient
 * here because it lives inside the already-encrypted store right next to the card
 * it gates, so an at-rest attacker who could brute-force it already holds the card;
 * the phrase defends against LIVE impersonation of an honest peer, not at-rest.
 */
class RecoveryPeerStore(private val storage: StorageHandle) {

    /** A held recovery share: the card we hold + whether a challenge phrase is set. */
    data class Held(val giverKeyHex: String, val card: ByteArray, val hasPhrase: Boolean)

    /**
     * Hold a recovery card [cardText] for [giverKeyHex] (no phrase yet). Returns
     * `true` only if the card actually persisted — a swallowed storage failure here
     * would silently drop a share the giver believes we are holding, so the caller
     * must not log "now HOLDING" on a `false`.
     */
    fun hold(giverKeyHex: String, cardText: ByteArray): Boolean {
        val value = ByteArray(SALT_LEN + HASH_LEN) + cardText // zero salt+hash → "no phrase"
        return runCatching { storage.put(CATEGORY, giverKeyHex.fromHex(), value) }
            .onFailure { Log.e(TAG, "recovery: hold failed (share NOT persisted): ${it.message}") }
            .isSuccess
    }

    /** Set/replace the challenge phrase for the share held for [giverKeyHex] (D0005). */
    fun setPhrase(giverKeyHex: String, phrase: String): Boolean {
        val card = held(giverKeyHex) ?: return false
        val salt = ByteArray(SALT_LEN).also { SecureRandom().nextBytes(it) }
        val hash = phraseHash(salt, phrase)
        val value = salt + hash + card
        return runCatching { storage.put(CATEGORY, giverKeyHex.fromHex(), value) }.isSuccess
    }

    /** The card we hold for [giverKeyHex] (phrase header stripped), or null. */
    fun held(giverKeyHex: String): ByteArray? =
        decode(runCatching { storage.get(CATEGORY, giverKeyHex.fromHex()) }.getOrNull())?.second

    /** True if we hold a recovery share for [giverKeyHex]. */
    fun holds(giverKeyHex: String): Boolean = held(giverKeyHex) != null

    /** True if we hold at least one recovery share (gates the return prompt). */
    fun hasAnyHeld(): Boolean =
        runCatching { storage.listRecords(CATEGORY) }.getOrDefault(emptyList()).isNotEmpty()

    /** The giver key of the first held share, or null — a driver convenience. */
    fun firstHeldGiver(): String? =
        runCatching { storage.listRecords(CATEGORY) }.getOrDefault(emptyList()).firstOrNull()?.toHex()

    /**
     * Find the held share whose challenge phrase matches [phrase] (D0005 / D0040
     * §2): the fresh-device matcher — the requester's operational key is new, so the
     * phrase the owner produces is the only link to which share is theirs. Returns
     * the matching [Held] or null. Shares with no phrase set never match.
     */
    fun findByPhrase(phrase: String): Held? {
        val ids = runCatching { storage.listRecords(CATEGORY) }.getOrDefault(emptyList())
        for (id in ids) {
            val raw = runCatching { storage.get(CATEGORY, id) }.getOrNull() ?: continue
            val (header, card) = decode(raw) ?: continue
            val salt = header.copyOfRange(0, SALT_LEN)
            val hash = header.copyOfRange(SALT_LEN, SALT_LEN + HASH_LEN)
            if (hash.all { it == 0.toByte() }) continue // no phrase set
            if (MessageDigest.isEqual(hash, phraseHash(salt, phrase))) {
                return Held(id.toHex(), card, hasPhrase = true)
            }
        }
        return null
    }

    /** Drop the share we hold for [giverKeyHex]. */
    fun release(giverKeyHex: String) {
        runCatching { storage.delete(CATEGORY, giverKeyHex.fromHex()) }
    }

    /** Split a stored value into (header = salt||hash, cardText), or null if malformed. */
    private fun decode(value: ByteArray?): Pair<ByteArray, ByteArray>? {
        if (value == null || value.size < SALT_LEN + HASH_LEN) return null
        return value.copyOfRange(0, SALT_LEN + HASH_LEN) to value.copyOfRange(SALT_LEN + HASH_LEN, value.size)
    }

    private fun phraseHash(salt: ByteArray, phrase: String): ByteArray =
        MessageDigest.getInstance("SHA-256").run {
            update(DOMAIN)
            update(salt)
            digest(phrase.trim().toByteArray())
        }

    private companion object {
        const val TAG = "CairnFfi"

        /** Must match `cairn_storage::categories::RECOVERY_SHARES`. */
        const val CATEGORY = "recovery_shares"
        const val SALT_LEN = 16
        const val HASH_LEN = 32

        /** Domain-separates the phrase hash from any other SHA-256 use. */
        val DOMAIN = "cairn-v1-recovery-phrase".toByteArray()
    }
}
