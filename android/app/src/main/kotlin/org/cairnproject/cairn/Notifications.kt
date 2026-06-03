// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat

/**
 * Per-message incoming notifications (C2 — the gap an adversarial UI review
 * flagged: the app posted only an ongoing "connection" status and NEVER told
 * the user a message had arrived, so a backgrounded user missed everything).
 *
 * Privacy-first for the threat model: the notification carries NO sender and NO
 * content ("New secure message") and is [NotificationCompat.VISIBILITY_SECRET]
 * so it is hidden on the lock screen entirely — it only signals that *something*
 * arrived; the user opens (and unlocks) the app to see who and what. A future
 * setting can opt into richer content.
 */
object Notifications {

    /** Post a content-free "new message" notification, keyed per contact. */
    fun postNewMessage(context: Context, contactKeyHex: String) {
        val nm = context.getSystemService(NotificationManager::class.java) ?: return
        ensureChannel(nm)
        val tap = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val pending = PendingIntent.getActivity(context, 0, tap, PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Cairn")
            .setContentText("New secure message")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(pending)
            .setAutoCancel(true)
            .build()
        // Per-contact id so distinct contacts surface as distinct notifications.
        nm.notify(contactKeyHex.hashCode(), notification)
    }

    private fun ensureChannel(nm: NotificationManager) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Messages",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Alerts you when an encrypted message arrives."
            setShowBadge(true)
        }
        nm.createNotificationChannel(channel)
    }

    private const val CHANNEL_ID = "cairn_messages"
}
