// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

/**
 * The Cairn chat surface (D0003 Kotlin UI). Renders the [MessagingViewModel]
 * state machine: bring-up → contact list (+ one-link QR pairing) → live 1:1
 * chat with persisted history, over the bundled SimpleX-over-Tor transport.
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
                is UiState.Locked -> LockScreen(state, vm)

                is UiState.Starting -> Centered {
                    CircularProgressIndicator()
                    Text("Bringing up encrypted session…", Modifier.padding(top = 12.dp))
                }

                is UiState.ContactList -> ContactListView(state, vm)

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

                is UiState.Conversation -> ChatView(state, vm)

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
private fun LockScreen(state: UiState.Locked, vm: MessagingViewModel) {
    var pass by remember { mutableStateOf("") }
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(top = 40.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            if (state.firstLaunch) "Create a passphrase" else "Enter your passphrase",
            style = MaterialTheme.typography.titleLarge,
        )
        Text(
            if (state.firstLaunch) {
                "This passphrase encrypts your messages, contacts, and keys on " +
                    "this device. There is no way to recover it — write it down " +
                    "somewhere safe."
            } else {
                "Unlock your encrypted data on this device."
            },
            Modifier.padding(top = 8.dp),
            textAlign = TextAlign.Center,
            style = MaterialTheme.typography.bodySmall,
        )
        OutlinedTextField(
            value = pass,
            onValueChange = { pass = it },
            label = { Text("Passphrase") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 20.dp),
        )
        if (state.error != null) {
            Text(
                state.error,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(top = 8.dp),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Button(
            onClick = { vm.unlock(pass) },
            enabled = pass.isNotBlank(),
            modifier = Modifier.padding(top = 20.dp),
        ) { Text(if (state.firstLaunch) "Create & unlock" else "Unlock") }
    }
}

@Composable
private fun ContactListView(state: UiState.ContactList, vm: MessagingViewModel) {
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
        Text("Contacts", style = MaterialTheme.typography.titleMedium)
        if (state.contacts.isEmpty()) {
            Text(
                "No contacts yet — invite someone, or scan their invitation.",
                Modifier.padding(top = 4.dp),
                style = MaterialTheme.typography.bodySmall,
            )
        } else {
            state.contacts.forEach { contact ->
                Card(
                    Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp)
                        .clickable { vm.openContact(contact) },
                ) {
                    Column(Modifier.padding(12.dp)) {
                        Text(contact.displayName, style = MaterialTheme.typography.titleSmall)
                        Text(
                            "peer ${contact.peerKeyHex.take(16)}…",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        TrustBadge(contact.verified)
                    }
                }
            }
        }

        HorizontalDivider(Modifier.padding(vertical = 12.dp))
        Text("Add a contact", style = MaterialTheme.typography.titleMedium)
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
private fun ChatView(state: UiState.Conversation, vm: MessagingViewModel) {
    val messages by vm.messages.collectAsStateWithLifecycle()
    var draft by remember { mutableStateOf("") }
    var showVerify by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = { vm.backToContacts() }) { Text("‹ Contacts") }
            Column(Modifier.weight(1f)) {
                Text(
                    "${state.displayName} · ${state.peerKeyHex.take(12)}…",
                    style = MaterialTheme.typography.labelMedium,
                )
                TrustBadge(state.verified)
            }
            if (!state.verified) {
                TextButton(onClick = { showVerify = true }) { Text("Verify") }
            }
        }
        if (showVerify) {
            VerifyDialog(
                state,
                onConfirm = {
                    vm.markCurrentVerified()
                    showVerify = false
                },
                onDismiss = { showVerify = false },
            )
        }
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

/**
 * Trust badge for a contact (D0006 §70). Green ✓ = the user confirmed the
 * safety number out of band; amber = TOFU-paired but not yet verified. (The
 * automated transitive-trust classification from cairn-trust-graph is a
 * follow-on, once contacts carry attestations.)
 */
@Composable
private fun TrustBadge(verified: Boolean) {
    val (label, color) = if (verified) {
        "✓ Verified" to Color(0xFF2E7D32)
    } else {
        "• Unverified (first contact)" to Color(0xFFB26A00)
    }
    Text(label, color = color, style = MaterialTheme.typography.labelMedium)
}

/**
 * Safety-number comparison dialog: the user compares the shared number with
 * their contact out of band and, if it matches, marks the contact verified.
 */
@Composable
private fun VerifyDialog(
    state: UiState.Conversation,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Verify ${state.displayName}") },
        text = {
            Column {
                Text(
                    "Compare this safety number with your contact — read it aloud, " +
                        "or hold your screens side by side. It is the same on both " +
                        "devices only if no one is intercepting your keys.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    Verification.safetyNumber(state.myKeyHex, state.peerKeyHex),
                    style = MaterialTheme.typography.titleMedium,
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    "If the numbers differ, a different key is in use — do not mark verified.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        },
        confirmButton = { TextButton(onClick = onConfirm) { Text("It matches — mark verified") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
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
