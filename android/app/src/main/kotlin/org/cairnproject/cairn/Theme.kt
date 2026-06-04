// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * The Cairn brand teal (sampled from the launcher icon, `#19524E`). Used as the
 * fixed status-bar + top-app-bar chrome in BOTH light and dark, so the brand
 * identity stays stable regardless of the system theme; the rest of the UI flows
 * from the [MaterialTheme] colour scheme below, which does flip light/dark.
 */
val CairnTeal = Color(0xFF19524E)

private val LightColors = lightColorScheme(
    primary = CairnTeal,
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFA7F2E8),
    onPrimaryContainer = Color(0xFF00201D),
    secondary = Color(0xFF4A635F),
    onSecondary = Color(0xFFFFFFFF),
    surfaceVariant = Color(0xFFDAE5E1),
    onSurfaceVariant = Color(0xFF3F4946),
    background = Color(0xFFFBFDFB),
    onBackground = Color(0xFF191C1B),
    surface = Color(0xFFFBFDFB),
    onSurface = Color(0xFF191C1B),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF8BD5CC),
    onPrimary = Color(0xFF003733),
    primaryContainer = Color(0xFF00504A),
    onPrimaryContainer = Color(0xFFA7F2E8),
    secondary = Color(0xFFB1CCC6),
    onSecondary = Color(0xFF1C3531),
    surfaceVariant = Color(0xFF3F4946),
    onSurfaceVariant = Color(0xFFBEC9C4),
    background = Color(0xFF191C1B),
    onBackground = Color(0xFFE1E3E0),
    surface = Color(0xFF191C1B),
    onSurface = Color(0xFFE1E3E0),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
)

/** Cairn's Material3 theme — the brand teal, with a dark scheme. */
@Composable
fun CairnTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        content = content,
    )
}
