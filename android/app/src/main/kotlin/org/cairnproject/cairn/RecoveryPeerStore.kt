// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.util.Log
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.Normalizer
import uniffi.cairn_uniffi.StorageHandle
import uniffi.cairn_uniffi.recoveryPhraseHash

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
 * phrase is set ([setPhrase]). The phrase hash is **Argon2id** (computed in the
 * Rust core, [recoveryPhraseHash]) over the NFC-normalized phrase, keyed by the
 * per-share salt — a memory-hard KDF, so even an attacker who exfiltrates this
 * encrypted store cannot cheaply brute-force a memorable phrase offline (the Stage
 * 3a adversarial-review at-rest finding; the prior bare SHA-256 fell in seconds).
 * Phrases are 1:1 with held shares: [setPhrase] rejects a phrase already in use and
 * [findByPhrase] fails closed on >1 match, so a returned card is never ambiguous.
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

    /**
     * Promote a re-split (D0040 §5, 3c COMMIT): replace the card we hold for
     * [giverKeyHex] with [newCard], **preserving the existing challenge-phrase
     * header** (salt+hash) so the owner↔holder phrase agreement survives the share
     * refresh — the secret is unchanged, only its sharing was re-randomized, so the
     * phrase that gated RETURN before still gates the new card. If we held nothing
     * (a holder added during the re-split), stores [newCard] with no phrase. Returns
     * `false` on a write failure — the caller must not log "promoted" on a `false`.
     */
    fun promote(giverKeyHex: String, newCard: ByteArray): Boolean {
        val raw = runCatching { storage.get(CATEGORY, giverKeyHex.fromHex()) }.getOrNull()
        val header =
            if (raw != null && raw.size >= SALT_LEN + HASH_LEN) {
                raw.copyOfRange(0, SALT_LEN + HASH_LEN) // keep salt+phraseHash
            } else {
                ByteArray(SALT_LEN + HASH_LEN) // no prior share → no phrase
            }
        val value = header + newCard
        return runCatching { storage.put(CATEGORY, giverKeyHex.fromHex(), value) }
            .onFailure { Log.e(TAG, "recovery: promote failed (re-split NOT applied): ${it.message}") }
            .isSuccess
    }

    /**
     * Set/replace the challenge phrase for the share held for [giverKeyHex] (D0005).
     * Rejects a blank phrase, or one already in use by ANOTHER held share — phrases
     * must be 1:1 with shares (D0040 §2) so [findByPhrase] is unambiguous. Returns
     * false if no share is held, the phrase is blank/duplicate, or the write fails.
     * Runs Argon2id (memory-hard) — call off the main thread.
     */
    fun setPhrase(giverKeyHex: String, phrase: String): Boolean {
        val card = held(giverKeyHex) ?: return false
        if (phrase.isBlank()) {
            Log.w(TAG, "recovery: refusing to set a blank challenge phrase")
            return false
        }
        if (phraseUsedByAnother(giverKeyHex, phrase)) {
            Log.w(TAG, "recovery: that phrase is already used by another held share — not set (D0040 §2)")
            return false
        }
        val salt = ByteArray(SALT_LEN).also { SecureRandom().nextBytes(it) }
        val hash = phraseHash(salt, phrase)
        val value = salt + hash + card
        return runCatching { storage.put(CATEGORY, giverKeyHex.fromHex(), value) }.isSuccess
    }

    /** True if any held share OTHER than [exceptGiverKeyHex] already matches [phrase]. */
    private fun phraseUsedByAnother(exceptGiverKeyHex: String, phrase: String): Boolean {
        val except = runCatching { exceptGiverKeyHex.fromHex() }.getOrNull()
        val ids = runCatching { storage.listRecords(CATEGORY) }.getOrDefault(emptyList())
        for (id in ids) {
            if (except != null && id.contentEquals(except)) continue
            val raw = runCatching { storage.get(CATEGORY, id) }.getOrNull() ?: continue
            val (header, _) = decode(raw) ?: continue
            val salt = header.copyOfRange(0, SALT_LEN)
            val hash = header.copyOfRange(SALT_LEN, SALT_LEN + HASH_LEN)
            if (hash.all { it == 0.toByte() }) continue
            if (MessageDigest.isEqual(hash, phraseHash(salt, phrase))) return true
        }
        return false
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
     * the matching [Held], or null if none match. **Fails closed on >1 match**
     * (returns null) — a duplicate phrase must never silently return one of two
     * cards; [setPhrase] already prevents duplicates, this is the backstop. Shares
     * with no phrase set never match. Runs Argon2id per record — call off the main
     * thread.
     */
    fun findByPhrase(phrase: String): Held? {
        val ids = runCatching { storage.listRecords(CATEGORY) }.getOrDefault(emptyList())
        var match: Held? = null
        for (id in ids) {
            val raw = runCatching { storage.get(CATEGORY, id) }.getOrNull() ?: continue
            val (header, card) = decode(raw) ?: continue
            val salt = header.copyOfRange(0, SALT_LEN)
            val hash = header.copyOfRange(SALT_LEN, SALT_LEN + HASH_LEN)
            if (hash.all { it == 0.toByte() }) continue // no phrase set
            if (MessageDigest.isEqual(hash, phraseHash(salt, phrase))) {
                if (match != null) {
                    Log.w(TAG, "recovery: phrase matched >1 held share — refusing to return (fail closed)")
                    return null
                }
                match = Held(id.toHex(), card, hasPhrase = true)
            }
        }
        return match
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

    /**
     * Argon2id commitment of [phrase] under [salt] (computed in the Rust core). The
     * phrase is canonicalized first — **NFC** normalize then trim — so the same
     * human phrase typed on two devices (possibly in different Unicode forms) hashes
     * equal; the Rust side adds domain separation. Memory-hard, so call off-Main.
     */
    private fun phraseHash(salt: ByteArray, phrase: String): ByteArray {
        val canonical = Normalizer.normalize(phrase, Normalizer.Form.NFC).trim()
        return recoveryPhraseHash(salt, canonical)
    }

    private companion object {
        const val TAG = "CairnFfi"

        /** Must match `cairn_storage::categories::RECOVERY_SHARES`. */
        const val CATEGORY = "recovery_shares"
        const val SALT_LEN = 16
        const val HASH_LEN = 32
    }
}
