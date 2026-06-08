// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.util.Log
import uniffi.cairn_uniffi.StorageHandle

/**
 * PENDING re-split shares a holder has staged but not yet promoted (D0040 §5, the
 * atomic-or-non-leaking re-split, Stage 3c). When a re-splitting owner sends a
 * **PREPARE** (envelope key 13) carrying that holder's NEW recovery card (key 11),
 * the holder stages it HERE — keyed by the 16-byte `resplit_id` — and ACKs. The
 * card is only promoted to active when the owner's **COMMIT** arrives, and dropped
 * on **DISCARD** (or never promoted at all if the owner aborts).
 *
 * Backed by the encrypted `recovery_pending` category. The stored value is
 * `[giverKey(32)][newCardText]`; the key is the `resplit_id`. Durable on purpose:
 * the two-phase protocol runs over store-and-forward Tor, so a PREPARE and its
 * COMMIT can straddle a holder restart — the staged card must survive in between.
 * A holder restart that loses this would silently leave the owner waiting, or drop
 * a COMMIT on the floor; persisting it keeps the protocol consistent.
 *
 * This holds OTHER users' shares-in-transition, exactly like [RecoveryPeerStore]
 * (a single Shamir share is below the reconstruction threshold and reveals nothing
 * about the giver's master), so it crosses + persists as plain card bytes.
 */
class RecoveryPendingStore(private val storage: StorageHandle) {

    /** A staged pending re-split share: the giver it belongs to + the new card. */
    data class Pending(val giverKeyHex: String, val card: ByteArray)

    /**
     * Stage [newCard] for [giverKeyHex] under [resplitId], awaiting the owner's
     * COMMIT/DISCARD. Returns `false` (and does NOT ACK upstream — the caller must
     * not ACK a share it failed to stage) on a bad id length or a write failure.
     */
    fun stage(resplitId: ByteArray, giverKeyHex: String, newCard: ByteArray): Boolean {
        if (resplitId.size != ID_LEN) {
            Log.w(TAG, "resplit: refusing to stage pending under a ${resplitId.size}B id (want $ID_LEN)")
            return false
        }
        val giver = runCatching { giverKeyHex.fromHex() }.getOrNull() ?: return false
        if (giver.size != KEY_LEN) return false
        val value = giver + newCard // [giverKey(32)][newCardText]
        return runCatching { storage.put(CATEGORY, resplitId, value) }
            .onFailure { Log.e(TAG, "resplit: stage pending failed (NOT persisted): ${it.message}") }
            .isSuccess
    }

    /** The pending share staged under [resplitId], or null if none / malformed. */
    fun get(resplitId: ByteArray): Pending? {
        val raw = runCatching { storage.get(CATEGORY, resplitId) }.getOrNull() ?: return null
        if (raw.size <= KEY_LEN) return null
        return Pending(
            giverKeyHex = raw.copyOfRange(0, KEY_LEN).toHex(),
            card = raw.copyOfRange(KEY_LEN, raw.size),
        )
    }

    /** Drop the pending share staged under [resplitId] (after promote or discard). */
    fun drop(resplitId: ByteArray) {
        runCatching { storage.delete(CATEGORY, resplitId) }
    }

    private companion object {
        const val TAG = "CairnFfi"

        /** Must match `cairn_storage::categories::RECOVERY_PENDING`. */
        const val CATEGORY = "recovery_pending"

        /** Operational-pubkey length (the giver key). */
        const val KEY_LEN = 32

        /** Re-split id length (the storage key). */
        const val ID_LEN = 16
    }
}
