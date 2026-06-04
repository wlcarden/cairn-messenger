// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host-JVM tests for the [FriendlyName] key-rendering (no Android Context — the
 * wordlist is embedded, so this runs on a plain JVM like [FfiBoundaryTest]).
 * Pins the exact bit-derivation with a golden vector so the names a user sees
 * can't silently drift across a refactor.
 */
class FriendlyNameTest {

    @Test
    fun bip39WordlistHasExactly2048CanonicalWords() {
        assertEquals(2048, Bip39.words.size)
        assertEquals("abandon", Bip39.words.first())
        assertEquals("zoo", Bip39.words.last())
    }

    /**
     * Golden vector: SHA-256 of a 32-byte all-zero key, top 33 bits → BIP-39
     * indices [819, 542, 1371]. Computed independently against the canonical
     * list; a change here means the derivation changed (every contact would be
     * renamed), which must be a deliberate, reviewed decision.
     */
    @Test
    fun zeroKeyDerivesTheGoldenName() {
        assertEquals("Grid Duck Problem", FriendlyName.of("00".repeat(32)))
    }

    @Test
    fun isDeterministicForTheSameKey() {
        val key = "3f55c833".padEnd(64, '0')
        assertEquals(FriendlyName.of(key), FriendlyName.of(key))
    }

    @Test
    fun producesThreeCapitalisedWordsFromTheList() {
        val name = FriendlyName.of("deadbeef".padEnd(64, '1'))
        val tokens = name.split(" ")
        assertEquals(3, tokens.size)
        tokens.forEach { token ->
            // First letter capitalised, the rest a real lowercase BIP-39 word.
            assertTrue("'$token' should be capitalised", token.first().isUpperCase())
            assertTrue("'$token' should be a BIP-39 word", Bip39.words.contains(token.lowercase()))
        }
    }

    @Test
    fun distinctKeysGenerallyProduceDistinctNames() {
        assertNotEquals(
            FriendlyName.of("aa".repeat(32)),
            FriendlyName.of("deadbeef".padEnd(64, '1')),
        )
    }

    @Test
    fun fallsBackToHexPrefixOnMalformedHex() {
        // "zz" is not valid hex → fromHex throws → fall back to the raw prefix.
        assertEquals("zz", FriendlyName.of("zz"))
    }
}
