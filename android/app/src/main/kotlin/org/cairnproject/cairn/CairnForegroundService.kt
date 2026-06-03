// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors
package org.cairnproject.cairn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat

/**
 * The production foreground service (D0026 §12 — the last gap to a usable app).
 *
 * Cairn runs its OWN Tor ([TorService]) + the in-process `libsimplex` adapter +
 * the recv loop ALL in this one process. Without a foreground service nothing
 * pins the process's importance, so Android (esp. GrapheneOS) reaps it within
 * minutes of the user leaving the screen — and a reaped process can neither
 * receive nor finish sending. This service calls [startForeground] with an
 * ongoing notification, holding the whole process at foreground-service priority
 * so the Tor connection and the SimpleX message queue stay live in the
 * background and messages are delivered while the app is not on screen.
 *
 * It is a *started* (not bound) service — [MainActivity] launches it via
 * `startForegroundService` at bring-up and it runs for the app's lifetime
 * (`START_STICKY` restarts it if the system kills it). The
 * `foregroundServiceType="specialUse"` (manifest) is the honest type for
 * "maintain a privacy-network connection" — none of the predefined Android 14
 * types fit a Tor messenger; Cairn ships sideloaded/F-Droid, not Play, so the
 * special-use subtype declaration is sufficient.
 *
 * NOTE (v1 scope): the messaging session currently lives in the Activity-scoped
 * [MessagingViewModel]; this service keeps the *process* alive, which preserves
 * that session across backgrounding. Hosting the session in the service itself
 * (so it survives Activity *destruction*, not just backgrounding) is a tracked
 * follow-up.
 */
class CairnForegroundService : Service() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Must promote to foreground within ~5s of startForegroundService, else
        // the system throws. Do it first thing.
        startForeground(NOTIF_ID, buildNotification())
        Log.i(TAG, "foreground service started — process pinned at FGS priority")
        // Restart if the system kills us so the connection is re-pinned.
        return START_STICKY
    }

    /** Started, not bound. */
    override fun onBind(intent: Intent?): IBinder? = null

    private fun buildNotification(): Notification {
        // Low-importance channel: an ongoing status notification, not an alert.
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Secure connection",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description =
                "Keeps Cairn connected over Tor so end-to-end encrypted messages " +
                    "arrive while the app is in the background."
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Cairn")
            .setContentText("Maintaining your secure connection over Tor")
            .setSmallIcon(R.drawable.ic_notification)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    companion object {
        private const val TAG = "CairnFgs"
        private const val CHANNEL_ID = "cairn_connection"
        private const val NOTIF_ID = 0x6361 // 'c''a'
    }
}
