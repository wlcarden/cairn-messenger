// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.util.Log
import uniffi.cairn_uniffi.StorageHandle

/**
 * The contacts who hold THIS user's recovery shares (D0040 §5, the owner side of
 * re-split). When the user entrusts one of their own cards to a contact
 * ([MessagingViewModel.entrustRecoveryShare]), that contact is recorded here so a
 * later **atomic re-split** can fan a single fresh kit out to ALL of them at once.
 *
 * This is the dual of [RecoveryPeerStore] (which holds OTHER users' shares): this
 * remembers who holds OURS. It stores only PUBLIC routing data — the peer's
 * operational pubkey (the storage key) + the connection id to reach them — never a
 * share. The card itself lives on the peer, not here.
 *
 * **Why a tracked list matters (correctness, not convenience):** a re-split must
 * fan ONE kit out to all peers in a single event. Re-splitting per-peer would give
 * each peer a card from a DIFFERENT polynomial, and shares from different
 * polynomials cannot reconstruct together (they fail the commitment check) — which
 * would silently break recovery. The list is what lets one re-split reach every
 * holder consistently.
 *
 * Backed by the encrypted `recovery_peers` category. Value = the connection id
 * bytes (UTF-8), keyed by the peer's 32-byte operational pubkey.
 */
class RecoveryOwnerPeerStore(private val storage: StorageHandle) {

    /** A contact who holds one of our recovery shares: where to reach them. */
    data class OwnerPeer(val peerKeyHex: String, val connId: String)

    /**
     * Record (or refresh) that [peerKeyHex] holds one of our shares, reachable over
     * [connId]. Idempotent — re-entrusting to the same peer just updates the connId.
     */
    fun record(peerKeyHex: String, connId: String): Boolean {
        val key = runCatching { peerKeyHex.fromHex() }.getOrNull() ?: return false
        if (key.size != KEY_LEN) return false
        return runCatching { storage.put(CATEGORY, key, connId.toByteArray()) }
            .onFailure { Log.e(TAG, "recovery: failed to record recovery peer ${peerKeyHex.take(12)}: ${it.message}") }
            .isSuccess
    }

    /** All contacts who hold one of our shares (the re-split fan-out targets). */
    fun all(): List<OwnerPeer> =
        runCatching { storage.listRecords(CATEGORY) }.getOrDefault(emptyList()).mapNotNull { id ->
            val connId = runCatching { storage.get(CATEGORY, id) }.getOrNull()?.let { String(it) } ?: return@mapNotNull null
            OwnerPeer(id.toHex(), connId)
        }

    /** How many contacts hold one of our shares (gates the re-split entry point). */
    fun count(): Int =
        runCatching { storage.listRecords(CATEGORY) }.getOrDefault(emptyList()).size

    /** Forget a recovery peer (e.g. on contact delete). */
    fun forget(peerKeyHex: String) {
        val key = runCatching { peerKeyHex.fromHex() }.getOrNull() ?: return
        runCatching { storage.delete(CATEGORY, key) }
    }

    private companion object {
        const val TAG = "CairnFfi"

        /** Must match `cairn_storage::categories::RECOVERY_PEERS`. */
        const val CATEGORY = "recovery_peers"

        /** Operational-pubkey length (the storage key). */
        const val KEY_LEN = 32
    }
}
