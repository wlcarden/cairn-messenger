// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import java.security.MessageDigest

/**
 * Manual key verification (D0006 §70 attestation strength `in-person` /
 * `channel-verified`). One-link pairing is TOFU — the peer key is
 * unauthenticated on first contact — so the honest trust signal until the
 * automated trust graph carries attestations is a human out-of-band check.
 *
 * The **safety number** is a fingerprint of BOTH operational keys, computed
 * identically on both devices (the keys are sorted before hashing, so the order
 * the two users meet in doesn't matter). Two contacts compare the number out of
 * band — read it aloud, compare screens, or compare the key QRs — and, if it
 * matches, mark the contact verified. A mismatch means a different key is in
 * play (a MITM on the pairing, or the wrong contact).
 *
 * `SHA-256(min(a,b) ‖ max(a,b))` rendered as 6 groups of 5 decimal digits (a
 * ~10^30 comparison space, ample for a human side-channel check). This is the
 * human layer; the cryptographic transitive-trust layer is the cairn-trust-graph
 * cascade classifier (a follow-on, once contacts carry attestations).
 */
object Verification {

    /** The shared safety number for the [myKeyHex] ↔ [peerKeyHex] pair. */
    fun safetyNumber(myKeyHex: String, peerKeyHex: String): String {
        val a = runCatching { myKeyHex.fromHex() }.getOrNull() ?: return UNAVAILABLE
        val b = runCatching { peerKeyHex.fromHex() }.getOrNull() ?: return UNAVAILABLE
        val (lo, hi) = if (compareBytes(a, b) <= 0) a to b else b to a
        val digest = MessageDigest.getInstance("SHA-256").run {
            update(lo)
            update(hi)
            digest()
        }
        // 6 groups of 5 digits from the first 30 bytes (each 5-byte chunk mod 1e5).
        return (0 until 6).joinToString(" ") { group ->
            var value = 0L
            for (i in 0 until 5) {
                value = (value shl 8) or (digest[group * 5 + i].toLong() and 0xFF)
            }
            "%05d".format(value % 100_000)
        }
    }

    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    private const val UNAVAILABLE = "(unavailable)"
}
