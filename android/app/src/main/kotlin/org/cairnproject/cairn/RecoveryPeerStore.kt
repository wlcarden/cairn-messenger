// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.util.Log
import uniffi.cairn_uniffi.StorageHandle

/**
 * The recovery shares this device HOLDS on behalf of contacts (D0038 §7, Stage
 * 2 — peer-share distribution). When a contact entrusts us a recovery card, we
 * persist it here keyed by their operational pubkey; when they later ask for it
 * back (and we manually approve), we return the held card.
 *
 * Backed by the encrypted `recovery_shares` category (`cairn_storage` derives a
 * per-category DEK, so a held share is encrypted at rest under the same
 * passphrase + StrongBox factors as everything else). A held card is one Shamir
 * share + its public commitment + master pubkey — sensitive but
 * transportable-by-design (a single share is below the reconstruction
 * threshold), which is exactly why entrusting it to a peer is safe.
 */
class RecoveryPeerStore(private val storage: StorageHandle) {

    /** Hold a recovery card [cardBytes] (its `CAIRN-RECOVERY-…` text) for [giverKeyHex]. */
    fun hold(giverKeyHex: String, cardBytes: ByteArray) {
        runCatching { storage.put(CATEGORY, giverKeyHex.fromHex(), cardBytes) }
            .onFailure { Log.w(TAG, "recovery: hold failed: ${it.message}") }
    }

    /** The card we hold for [giverKeyHex], or null if none. */
    fun held(giverKeyHex: String): ByteArray? =
        runCatching { storage.get(CATEGORY, giverKeyHex.fromHex()) }
            .getOrNull()
            ?.takeIf { it.isNotEmpty() }

    /** True if we hold a recovery share for [giverKeyHex]. */
    fun holds(giverKeyHex: String): Boolean = held(giverKeyHex) != null

    /** Drop the share we hold for [giverKeyHex] (e.g. the owner asked us to stop). */
    fun release(giverKeyHex: String) {
        runCatching { storage.delete(CATEGORY, giverKeyHex.fromHex()) }
    }

    private companion object {
        const val TAG = "CairnFfi"

        /** Must match `cairn_storage::categories::RECOVERY_SHARES`. */
        const val CATEGORY = "recovery_shares"
    }
}
