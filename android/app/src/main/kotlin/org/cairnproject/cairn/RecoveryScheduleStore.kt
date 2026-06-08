// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.util.Log
import java.security.SecureRandom
import uniffi.cairn_uniffi.StorageHandle

/**
 * Pending peer-clock cooling-off releases (D0040 §4 / D0005, Stage 3b). When a
 * holder verifies the challenge phrase (3a), the share is **not** returned
 * immediately — its release is **scheduled** at the holder's own clock + a
 * cooling-off window, and persisted here. The window gives a coerced owner's
 * network time to notice + the holder time to cancel (the owner reaching them out
 * of band: "cancel my recovery"). The fresh device's clock is never trusted — the
 * release time is always the holder's (D0005 H5).
 *
 * Backed by the encrypted `recovery_schedules` category. One record per pending
 * release, keyed by a random 16-byte schedule id; the value is
 * `[releaseAtPeerUnix(8, big-endian)][requesterKey(32)][giverKey(32)][connId(UTF-8)]`.
 * The card itself is NOT duplicated here — it is re-loaded from
 * [RecoveryPeerStore] (keyed by `giverKey`) when the timer fires, so the held
 * share stays the single source of truth.
 */
class RecoveryScheduleStore(private val storage: StorageHandle) {

    /** A scheduled release that is due (window elapsed) and ready to fire. */
    data class Due(
        val scheduleId: ByteArray,
        val requesterKeyHex: String,
        val giverKeyHex: String,
        val connId: String,
    )

    /** A pending release, for the holder's cancel UI + countdown. */
    data class Pending(
        val scheduleId: ByteArray,
        val requesterKeyHex: String,
        val giverKeyHex: String,
        val releaseAtPeerUnix: Long,
    )

    /** Schedule a release of the share held for [giverKeyHex] to [requesterKeyHex]. */
    fun schedule(requesterKeyHex: String, giverKeyHex: String, connId: String, releaseAtPeerUnix: Long): Boolean {
        val requester = runCatching { requesterKeyHex.fromHex() }.getOrNull() ?: return false
        val giver = runCatching { giverKeyHex.fromHex() }.getOrNull() ?: return false
        if (requester.size != KEY_LEN || giver.size != KEY_LEN) return false
        val id = ByteArray(ID_LEN).also { SecureRandom().nextBytes(it) }
        val value = longToBytes(releaseAtPeerUnix) + requester + giver + connId.toByteArray()
        return runCatching { storage.put(CATEGORY, id, value) }
            .onFailure { Log.e(TAG, "recovery: schedule persist failed: ${it.message}") }
            .isSuccess
    }

    /** Releases whose window has elapsed at [nowPeerUnix] (lazy-fire candidates). */
    fun due(nowPeerUnix: Long): List<Due> = all().mapNotNull { (id, p) ->
        if (p.releaseAtPeerUnix <= nowPeerUnix) Due(id, p.requesterKeyHex, p.giverKeyHex, p.connIdOf(id)) else null
    }

    /** All pending releases (for the cancel UI + countdown). */
    fun pending(): List<Pending> = all().map { it.second }

    /** True if any release is pending. */
    fun hasPending(): Boolean =
        runCatching { storage.listRecords(CATEGORY) }.getOrDefault(emptyList()).isNotEmpty()

    /** Drop a scheduled release (fired or cancelled). */
    fun remove(scheduleId: ByteArray) {
        runCatching { storage.delete(CATEGORY, scheduleId) }
    }

    /** Cancel the FIRST pending release — a driver convenience. */
    fun cancelFirst(): Boolean {
        val first = runCatching { storage.listRecords(CATEGORY) }.getOrDefault(emptyList()).firstOrNull()
            ?: return false
        remove(first)
        return true
    }

    // ── internals ────────────────────────────────────────────────────────────

    /** The connId for record [id] — re-read (the Due list needs it but Pending doesn't). */
    private fun Pending.connIdOf(id: ByteArray): String =
        decode(runCatching { storage.get(CATEGORY, id) }.getOrNull())?.connId ?: ""

    private data class Parsed(
        val releaseAtPeerUnix: Long,
        val requesterKeyHex: String,
        val giverKeyHex: String,
        val connId: String,
    )

    private fun all(): List<Pair<ByteArray, Pending>> {
        val ids = runCatching { storage.listRecords(CATEGORY) }.getOrDefault(emptyList())
        return ids.mapNotNull { id ->
            val p = decode(runCatching { storage.get(CATEGORY, id) }.getOrNull()) ?: return@mapNotNull null
            id to Pending(id, p.requesterKeyHex, p.giverKeyHex, p.releaseAtPeerUnix)
        }
    }

    private fun decode(value: ByteArray?): Parsed? {
        if (value == null || value.size < HEADER_LEN) return null
        val release = bytesToLong(value, 0)
        val requester = value.copyOfRange(8, 8 + KEY_LEN)
        val giver = value.copyOfRange(8 + KEY_LEN, 8 + 2 * KEY_LEN)
        val connId = String(value, HEADER_LEN, value.size - HEADER_LEN)
        return Parsed(release, requester.toHex(), giver.toHex(), connId)
    }

    private fun longToBytes(v: Long): ByteArray =
        ByteArray(8) { i -> (v ushr (8 * (7 - i)) and 0xFF).toByte() }

    private fun bytesToLong(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (b[off + i].toLong() and 0xFF)
        return v
    }

    private companion object {
        const val TAG = "CairnFfi"

        /** Must match `cairn_storage::categories::RECOVERY_SCHEDULES`. */
        const val CATEGORY = "recovery_schedules"
        const val ID_LEN = 16
        const val KEY_LEN = 32
        const val HEADER_LEN = 8 + 2 * KEY_LEN // releaseAt + requesterKey + giverKey
    }
}
