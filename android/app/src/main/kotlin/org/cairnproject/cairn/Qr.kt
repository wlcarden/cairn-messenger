// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.foundation.Image
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * QR encode for in-app pairing (D0026 §12). Pure-JVM ZXing — no Google Play
 * Services (GrapheneOS-safe). The invitation blob is a ~600-char SMP link, so
 * error-correction level **L** is used to maximize data capacity (higher ECC
 * would overflow the QR version for that payload), with a 1-module quiet zone.
 */
fun encodeQrBitmap(content: String, sizePx: Int = 720): Bitmap {
    val hints = mapOf(
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L,
        EncodeHintType.MARGIN to 1,
    )
    val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
    val width = matrix.width
    val height = matrix.height
    val pixels = IntArray(width * height)
    for (y in 0 until height) {
        val row = y * width
        for (x in 0 until width) {
            pixels[row + x] = if (matrix.get(x, y)) Color.BLACK else Color.WHITE
        }
    }
    return Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888).apply {
        setPixels(pixels, 0, width, 0, 0, width, height)
    }
}

/**
 * Render [content] as a QR code. Falls back to a caption if the payload can't
 * be encoded (e.g. exceeds QR capacity) — the link text is always shown beneath
 * the QR by the caller, so pairing still works by paste.
 */
@Composable
fun QrImage(content: String, modifier: Modifier = Modifier, sizePx: Int = 720) {
    val bitmap = runCatching { encodeQrBitmap(content, sizePx).asImageBitmap() }.getOrNull()
    if (bitmap != null) {
        Image(bitmap = bitmap, contentDescription = "Invitation QR code", modifier = modifier)
    } else {
        Text(
            "(QR unavailable — share the link below)",
            modifier = modifier,
            style = MaterialTheme.typography.bodySmall,
        )
    }
}
