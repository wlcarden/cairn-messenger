// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import java.security.MessageDigest

/**
 * A deterministic, human-readable rendering of a key as three BIP-39 words
 * (e.g. "Brave Otter Lantern"). It plays two roles:
 *
 *  1. The **default display name** for a freshly-paired contact — friendlier
 *     and more memorable than a hex prefix like "3f55c833" (D0026 §12). The user
 *     can still rename it.
 *  2. A **stable key fingerprint** shown on the identity + verify screens. Since
 *     it is derived purely from the key (not the editable name), it survives a
 *     rename and gives two people a quick out-loud cross-check — "do you see
 *     'Brave Otter Lantern' for me?" — a friendlier sibling of the safety number
 *     (D0006 §70).
 *
 * This is a DISPLAY fingerprint: 3 words = 33 bits ≈ 8.6×10⁹ — ample to tell
 * contacts apart by eye, but deliberately NOT the verification boundary. A
 * confident key check is still the full-key QR scan / safety number; the words
 * are a secondary signal layered on top. Both devices compile the same wordlist
 * and derive identically, so A's words for B equal the words B sees for itself.
 */
object FriendlyName {

    /**
     * Three capitalised BIP-39 words for the key [keyHex]. Falls back to a short
     * hex prefix if [keyHex] is not valid hex (so a malformed id never crashes a
     * row render).
     */
    fun of(keyHex: String): String {
        val key = runCatching { keyHex.fromHex() }.getOrNull() ?: return keyHex.take(8)
        // Hash first so names distribute well regardless of any key structure,
        // mirroring the safety-number derivation (Verification.safetyNumber).
        val digest = MessageDigest.getInstance("SHA-256").digest(key)
        // Pack the top 40 bits (5 bytes) into a long, then carve three disjoint
        // 11-bit fields (33 bits) — each indexes one of the 2048 BIP-39 words.
        var bits = 0L
        for (i in 0 until 5) bits = (bits shl 8) or (digest[i].toLong() and 0xFF)
        val indices = intArrayOf(
            ((bits ushr 29) and 0x7FF).toInt(), // bits 39..29
            ((bits ushr 18) and 0x7FF).toInt(), // bits 28..18
            ((bits ushr 7) and 0x7FF).toInt(), //  bits 17..7
        )
        val words = Bip39.words
        return indices.joinToString(" ") { i ->
            words[i].replaceFirstChar { c -> c.uppercase() }
        }
    }
}
