// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

/**
 * The Cairn demo chat surface (D0003 Kotlin UI). Renders the [MessagingViewModel]
 * state machine: bring-up → pair (show an invitation QR / scan a contact's) →
 * live 1:1 chat, over the bundled SimpleX-over-Tor transport. Pairing is
 * one-link (D0026 §12): the inviter shares a single QR and learns the peer from
 * its first envelope (TOFU); the acceptor scans once.
 */
@Composable
fun ChatScreen(vm: MessagingViewModel) {
    val ui by vm.ui.collectAsStateWithLifecycle()
    val torStatus by vm.torStatus.collectAsStateWithLifecycle()

    Scaffold { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
        ) {
            Text("Cairn", style = MaterialTheme.typography.headlineSmall)
            Text(torStatus, style = MaterialTheme.typography.labelMedium)
            HorizontalDivider(Modifier.padding(vertical = 8.dp))

            when (val state = ui) {
                is UiState.Starting -> Centered {
                    CircularProgressIndicator()
                    Text("Bringing up encrypted session…", Modifier.padding(top = 12.dp))
                }

                is UiState.Ready -> SetupView(state, vm)

                is UiState.Inviting -> InvitingView(state)

                is UiState.Connecting -> Centered {
                    CircularProgressIndicator()
                    Text(
                        "Connecting over Tor…",
                        Modifier.padding(top = 12.dp),
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(
                        "Establishing the encrypted SMP channel — this can take a minute.",
                        Modifier.padding(top = 4.dp),
                        textAlign = TextAlign.Center,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                is UiState.Connected -> ChatView(state, vm)

                is UiState.Failed -> Centered {
                    Text(
                        "Failed: ${state.message}",
                        color = MaterialTheme.colorScheme.error,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }
}

@Composable
private fun SetupView(state: UiState.Ready, vm: MessagingViewModel) {
    val context = LocalContext.current
    var showPaste by remember { mutableStateOf(false) }
    var pasted by remember { mutableStateOf("") }

    // QR scanner (zxing-android-embedded, GMS-free). A scanned QR is the peer's
    // "<uri>|<key>" invitation blob — hand it straight to acceptInvitation.
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.takeIf { it.isNotBlank() }?.let { vm.acceptInvitation(it) }
    }
    val launchScan = {
        scanLauncher.launch(
            ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt("Scan your contact's Cairn invitation")
                setBeepEnabled(false)
                setOrientationLocked(false)
            },
        )
    }
    val cameraPermLauncher =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) launchScan() else showPaste = true
        }
    val onScanClick = {
        val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        if (granted) launchScan() else cameraPermLauncher.launch(Manifest.permission.CAMERA)
    }

    Column(Modifier.verticalScroll(rememberScrollState())) {
        Text("Your Cairn key", style = MaterialTheme.typography.titleSmall)
        SelectableBlock(state.myKeyHex)

        HorizontalDivider(Modifier.padding(vertical = 12.dp))
        Text("Connect with a contact", style = MaterialTheme.typography.titleMedium)
        Text(
            "Invite shows a QR for your contact to scan; Scan reads theirs. " +
                "You only need ONE side to scan.",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 2.dp),
        )
        Row(Modifier.padding(top = 8.dp)) {
            Button(onClick = { vm.createInvitation() }) { Text("Invite a contact") }
            Spacer(Modifier.size(12.dp))
            OutlinedButton(onClick = onScanClick) { Text("Scan invitation") }
        }

        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = { showPaste = !showPaste }) {
            Text(if (showPaste) "Hide paste option" else "Paste a link instead")
        }
        if (showPaste) {
            OutlinedTextField(
                value = pasted,
                onValueChange = { pasted = it },
                label = { Text("Paste invitation (<uri>|<key>)") },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
            )
            Button(
                onClick = { vm.acceptInvitation(pasted) },
                modifier = Modifier.padding(top = 8.dp),
                enabled = pasted.isNotBlank(),
            ) { Text("Accept pasted invitation") }
        }
    }
}

@Composable
private fun InvitingView(state: UiState.Inviting) {
    val context = LocalContext.current
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Show this to your contact", style = MaterialTheme.typography.titleMedium)
        QrImage(
            state.inviteToShare,
            modifier = Modifier
                .padding(top = 12.dp)
                .size(280.dp),
        )
        Button(
            onClick = {
                val send = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, state.inviteToShare)
                }
                context.startActivity(Intent.createChooser(send, "Share Cairn invitation"))
            },
            modifier = Modifier.padding(top = 12.dp),
        ) { Text("Share link instead") }
        Text(
            "Waiting for your contact to scan…",
            Modifier.padding(top = 16.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
        CircularProgressIndicator(Modifier.padding(top = 8.dp))
    }
}

@Composable
private fun ChatView(state: UiState.Connected, vm: MessagingViewModel) {
    val messages by vm.messages.collectAsStateWithLifecycle()
    var draft by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize()) {
        Text(
            "Connected · peer ${state.peerKeyHex.take(16)}…",
            style = MaterialTheme.typography.labelMedium,
        )
        LazyColumn(
            Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            items(messages) { msg -> MessageBubble(msg) }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = draft,
                onValueChange = { draft = it },
                label = { Text("Message") },
                modifier = Modifier.weight(1f),
            )
            Button(
                onClick = {
                    vm.send(draft)
                    draft = ""
                },
                modifier = Modifier.padding(start = 8.dp),
                enabled = draft.isNotBlank(),
            ) { Text("Send") }
        }
    }
}

@Composable
private fun MessageBubble(msg: ChatMessage) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = if (msg.mine) Arrangement.End else Arrangement.Start,
    ) {
        Card {
            Text(
                msg.text,
                Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                color = if (msg.mine) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
            )
        }
    }
}

@Composable
private fun SelectableBlock(text: String) {
    Card(
        Modifier
            .fillMaxWidth()
            .padding(top = 4.dp),
    ) {
        Text(text, Modifier.padding(12.dp), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun Centered(content: @Composable () -> Unit) {
    Column(
        Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) { content() }
}
