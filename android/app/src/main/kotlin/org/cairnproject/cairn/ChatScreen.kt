// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.launch

/**
 * The Cairn chat surface (D0003 Kotlin UI). Renders the [MessagingViewModel]
 * state machine: bring-up → contact list (+ one-link QR pairing) → live 1:1
 * chat with persisted history, over the bundled SimpleX-over-Tor transport.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(vm: MessagingViewModel) {
    val ui by vm.ui.collectAsStateWithLifecycle()
    val torStatus by vm.torStatus.collectAsStateWithLifecycle()

    Scaffold(
        topBar = { CairnTopBar(torStatus) },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
        ) {
            when (val state = ui) {
                is UiState.Welcome -> WelcomeScreen(vm)

                is UiState.Locked -> LockScreen(state, vm)

                is UiState.Starting -> Centered {
                    CircularProgressIndicator()
                    Text("Bringing up encrypted session…", Modifier.padding(top = 12.dp))
                }

                is UiState.ContactList -> ContactListView(state, vm)

                is UiState.Inviting -> InvitingView(state, vm)

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
                    TextButton(
                        onClick = { vm.cancelPairing() },
                        modifier = Modifier.padding(top = 12.dp),
                    ) { Text("Cancel") }
                }

                is UiState.Conversation -> ChatView(state, vm)

                is UiState.Failed -> Centered {
                    Text(
                        "Something went wrong:\n${state.message}",
                        color = MaterialTheme.colorScheme.error,
                        textAlign = TextAlign.Center,
                    )
                    Button(
                        onClick = { vm.dismissFailure() },
                        modifier = Modifier.padding(top = 16.dp),
                    ) { Text("Back to contacts") }
                }
            }
        }
    }
}

/**
 * The single branded top app bar (replaces the platform ActionBar + the old
 * in-content "Cairn" title): the white cairn glyph, the name, and a compact
 * Tor-connectivity dot — on the fixed brand teal in both light and dark.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CairnTopBar(torStatus: String) {
    TopAppBar(
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    painterResource(R.drawable.ic_notification),
                    contentDescription = null,
                    modifier = Modifier.size(26.dp),
                    tint = Color.White,
                )
                Spacer(Modifier.size(8.dp))
                Text("Cairn")
            }
        },
        actions = {
            TorStatusChip(torStatus)
            Spacer(Modifier.size(12.dp))
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = CairnTeal,
            titleContentColor = Color.White,
            actionIconContentColor = Color.White,
        ),
    )
}

/** A compact Tor-connectivity indicator (a coloured dot + a one-word label). */
@Composable
private fun TorStatusChip(status: String) {
    val (dotColor, label) = when {
        status.startsWith("Connected") -> Color(0xFF7BE0A3) to "Connected"
        status.startsWith("Couldn't") -> Color(0xFFFFB4AB) to "Offline"
        else -> Color(0xFFFFD487) to "Connecting"
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(dotColor),
        )
        Spacer(Modifier.size(6.dp))
        Text(label, style = MaterialTheme.typography.labelMedium, color = Color.White)
    }
}

/** A one-screen "what is Cairn / no account / no reset" explainer (C4 onboarding). */
@Composable
private fun WelcomeScreen(vm: MessagingViewModel) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(top = 40.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Welcome to Cairn", style = MaterialTheme.typography.titleLarge)
        Text(
            "Cairn is a private messenger — no phone number, no account. Your " +
                "messages, contacts, and keys live only on this device, encrypted " +
                "by a passphrase you choose next.",
            Modifier.padding(top = 16.dp),
            textAlign = TextAlign.Center,
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            "There is no server and no password reset: if you forget your " +
                "passphrase, your data can't be recovered. Write it down somewhere safe.",
            Modifier.padding(top = 12.dp),
            textAlign = TextAlign.Center,
            style = MaterialTheme.typography.bodyMedium,
        )
        Button(
            onClick = { vm.beginSetup() },
            modifier = Modifier.padding(top = 24.dp),
        ) { Text("Get started") }
    }
}

/** Minimum first-launch passphrase length (a too-short secret = brute-forceable KEK). */
private const val MIN_PASSPHRASE = 8

@Composable
private fun LockScreen(state: UiState.Locked, vm: MessagingViewModel) {
    var pass by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var reveal by remember { mutableStateOf(false) }
    val transform = if (reveal) VisualTransformation.None else PasswordVisualTransformation()
    val tooShort = pass.length < MIN_PASSPHRASE
    val mismatch = state.firstLaunch && confirm.isNotEmpty() && pass != confirm
    val canSubmit = if (state.firstLaunch) {
        pass.length >= MIN_PASSPHRASE && pass == confirm
    } else {
        pass.isNotBlank()
    }

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
                "This passphrase encrypts everything on this device and can't be " +
                    "reset — pick one you'll remember, and write it down somewhere safe."
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
            visualTransformation = transform,
            trailingIcon = {
                TextButton(onClick = { reveal = !reveal }) {
                    Text(if (reveal) "Hide" else "Show")
                }
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 20.dp),
        )
        if (state.firstLaunch) {
            OutlinedTextField(
                value = confirm,
                onValueChange = { confirm = it },
                label = { Text("Confirm passphrase") },
                singleLine = true,
                isError = mismatch,
                visualTransformation = transform,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 12.dp),
            )
            val (hint, bad) = when {
                pass.isEmpty() -> "At least $MIN_PASSPHRASE characters — there is no reset." to false
                tooShort -> "Too short — at least $MIN_PASSPHRASE characters." to true
                mismatch -> "Passphrases don't match." to true
                else -> "Looks good — remember it, and write it down." to false
            }
            val hintColor = if (bad) {
                MaterialTheme.colorScheme.error
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            }
            Text(
                hint,
                color = hintColor,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                style = MaterialTheme.typography.bodySmall,
            )
        }
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
            enabled = canSubmit,
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
        if (state.error != null) {
            Text(
                state.error,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        }
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
                        TrustBadge(contact.trust())
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
                label = { Text("Paste a Cairn invitation link") },
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
private fun InvitingView(state: UiState.Inviting, vm: MessagingViewModel) {
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
        TextButton(
            onClick = { vm.cancelPairing() },
            modifier = Modifier.padding(top = 12.dp),
        ) { Text("Cancel") }
    }
}

@Composable
private fun ChatView(state: UiState.Conversation, vm: MessagingViewModel) {
    val messages by vm.messages.collectAsStateWithLifecycle()
    var draft by remember { mutableStateOf("") }
    var showVerify by remember { mutableStateOf(false) }
    var menuOpen by remember { mutableStateOf(false) }
    var showRename by remember { mutableStateOf(false) }
    var showDelete by remember { mutableStateOf(false) }
    var verifyScanError by remember { mutableStateOf<String?>(null) }

    // Scan the peer's key QR and confirm it equals the pinned key (D0006 §70).
    // CaptureActivity handles the camera-permission prompt itself.
    val verifyScanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val scanned = result.contents
        if (!scanned.isNullOrBlank()) {
            if (vm.confirmVerificationByScan(scanned)) {
                showVerify = false
                verifyScanError = null
            } else {
                verifyScanError =
                    "Scanned key does NOT match this contact — possible interception. Not verified."
            }
        }
    }
    val onVerifyScan = {
        verifyScanLauncher.launch(
            ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt("Scan your contact's key code")
                setBeepEnabled(false)
                setOrientationLocked(false)
            },
        )
    }
    Column(Modifier.fillMaxSize()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = { vm.backToContacts() }) {
                Text(
                    "‹ Contacts",
                    modifier = Modifier.semantics { contentDescription = "Back to contacts" },
                )
            }
            Column(Modifier.weight(1f)) {
                Text(
                    "${state.displayName} · ${state.peerKeyHex.take(12)}…",
                    style = MaterialTheme.typography.labelMedium,
                )
                TrustBadge(state.trust)
            }
            if (state.trust != Trust.VERIFIED) {
                TextButton(onClick = { showVerify = true }) { Text("Verify") }
            }
            Box {
                TextButton(onClick = { menuOpen = true }) {
                    Text("⋮", modifier = Modifier.semantics { contentDescription = "More options" })
                }
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    DropdownMenuItem(
                        text = { Text("Rename") },
                        onClick = {
                            menuOpen = false
                            showRename = true
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("Delete contact") },
                        onClick = {
                            menuOpen = false
                            showDelete = true
                        },
                    )
                }
            }
        }
        if (state.trust == Trust.KEY_CHANGED) {
            KeyChangedBanner(onReverify = { showVerify = true })
        }
        if (showVerify) {
            VerifyDialog(
                state,
                scanError = verifyScanError,
                onScan = onVerifyScan,
                onConfirmManual = {
                    vm.markCurrentVerified()
                    showVerify = false
                },
                onDismiss = {
                    showVerify = false
                    verifyScanError = null
                },
            )
        }
        if (showRename) {
            RenameDialog(
                current = state.displayName,
                onConfirm = {
                    vm.renameCurrentContact(it)
                    showRename = false
                },
                onDismiss = { showRename = false },
            )
        }
        if (showDelete) {
            AlertDialog(
                onDismissRequest = { showDelete = false },
                title = { Text("Delete ${state.displayName}?") },
                text = {
                    Text(
                        "This removes the contact from your list. Your message " +
                            "history records are not purged.",
                    )
                },
                confirmButton = {
                    TextButton(onClick = {
                        vm.deleteCurrentContact()
                        showDelete = false
                    }) { Text("Delete") }
                },
                dismissButton = { TextButton(onClick = { showDelete = false }) { Text("Cancel") } },
            )
        }
        val listState = rememberLazyListState()
        val scope = rememberCoroutineScope()
        val atBottom by remember {
            derivedStateOf {
                val last = listState.layoutInfo.visibleItemsInfo.lastOrNull()
                last == null || last.index >= messages.lastIndex - 1
            }
        }
        // Auto-scroll to the newest only when already near the bottom (or it's my
        // own send) — don't yank the view while the user reads back history.
        LaunchedEffect(messages.size) {
            if (messages.isNotEmpty() && (atBottom || messages.last().mine)) {
                listState.animateScrollToItem(messages.lastIndex)
            }
        }
        Box(
            Modifier
                .weight(1f)
                .fillMaxWidth(),
        ) {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                itemsIndexed(messages) { i, msg ->
                    val prev = messages.getOrNull(i - 1)
                    if (prev == null || dayKey(prev.tsUnix) != dayKey(msg.tsUnix)) {
                        DateSeparator(msg.tsUnix)
                    }
                    MessageBubble(msg, onRetry = { vm.resend(it.text) })
                }
            }
            if (!atBottom) {
                FilledTonalButton(
                    onClick = { scope.launch { listState.animateScrollToItem(messages.lastIndex) } },
                    modifier = Modifier
                        .align(Alignment.BottomEnd)
                        .padding(8.dp),
                ) { Text("↓ Newest") }
            }
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
 * peer's key out of band (scan or safety number); amber = TOFU-paired, the key
 * is NOT yet authenticated; red = the key changed since it was verified
 * (possible interception). A `contentDescription` carries the state for screen
 * readers, so the signal is never color-only. (The automated transitive-trust
 * classification from cairn-trust-graph is a follow-on, once contacts carry
 * attestations.)
 */
@Composable
private fun TrustBadge(trust: Trust) {
    val (label, color, desc) = when (trust) {
        Trust.VERIFIED -> Triple(
            "✓ Verified",
            Color(0xFF2E7D32),
            "Security status: verified — you confirmed this contact's key.",
        )
        Trust.UNVERIFIED -> Triple(
            "⚠ Unverified — key not authenticated",
            Color(0xFFB26A00),
            "Security status: unverified. This contact's key is not authenticated; " +
                "verify it before sending anything sensitive.",
        )
        Trust.KEY_CHANGED -> Triple(
            "⛔ Key changed — re-verify",
            Color(0xFFC62828),
            "Security status: the key changed since you verified it; possible " +
                "interception. Re-verify before trusting.",
        )
    }
    Text(
        label,
        color = color,
        style = MaterialTheme.typography.labelMedium,
        modifier = Modifier.semantics { contentDescription = desc },
    )
}

/**
 * Verification dialog (D0006 §70). The reliable path is the QR scan: each device
 * shows its own key QR, the user scans the peer's, and the app checks the key
 * bytes match — no human transcription, so a MITM key can't slip past a glance.
 * The numeric safety number is the out-of-band fallback (read aloud on a call).
 */
@Composable
private fun VerifyDialog(
    state: UiState.Conversation,
    scanError: String?,
    onScan: () -> Unit,
    onConfirmManual: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Verify ${state.displayName}") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    "Scan to verify (most reliable). Show your code to your contact " +
                        "and scan theirs — in person, or on a video call you trust.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(12.dp))
                QrImage(
                    state.myKeyHex,
                    modifier = Modifier
                        .align(Alignment.CenterHorizontally)
                        .size(180.dp),
                )
                Spacer(Modifier.height(8.dp))
                Button(onClick = onScan, modifier = Modifier.align(Alignment.CenterHorizontally)) {
                    Text("Scan their code")
                }
                if (scanError != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        scanError,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                HorizontalDivider(Modifier.padding(vertical = 12.dp))
                Text(
                    "Or compare this number out loud — it is identical on both " +
                        "devices only if no one is intercepting your keys:",
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    Verification.safetyNumber(state.myKeyHex, state.peerKeyHex),
                    style = MaterialTheme.typography.titleMedium,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "If it differs, a different key is in use — do not mark verified.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirmManual) { Text("I compared it — mark verified") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/**
 * Blocking banner shown when a verified contact's channel presents a different
 * key (D0006 §70) — driven by the recv signature verify-failure. Loud and
 * red; the user re-verifies (or leaves) rather than silently trusting on.
 */
@Composable
private fun KeyChangedBanner(onReverify: () -> Unit) {
    Card(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFC62828)),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(
                "This contact's key no longer matches the one you verified.",
                color = Color.White,
                style = MaterialTheme.typography.titleSmall,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                "They may have re-paired on a new device — or someone may be " +
                    "intercepting your messages. Do not trust this conversation " +
                    "until you re-verify.",
                color = Color.White,
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = onReverify) { Text("Re-verify") }
        }
    }
}

@Composable
private fun RenameDialog(current: String, onConfirm: (String) -> Unit, onDismiss: () -> Unit) {
    var name by remember { mutableStateOf(current) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Rename contact") },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Name") },
                singleLine = true,
            )
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(name) }, enabled = name.isNotBlank()) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun MessageBubble(msg: ChatMessage, onRetry: (ChatMessage) -> Unit) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val container = if (msg.mine) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val onColor = if (msg.mine) {
        MaterialTheme.colorScheme.onPrimaryContainer
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant
    }
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = if (msg.mine) Arrangement.End else Arrangement.Start,
    ) {
        Card(
            modifier = Modifier.combinedClickable(
                onClick = { if (msg.status == SendStatus.FAILED) onRetry(msg) },
                onLongClick = {
                    clipboard.setText(AnnotatedString(msg.text))
                    Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show()
                },
            ),
            colors = CardDefaults.cardColors(containerColor = container),
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 6.dp)) {
                Text(msg.text, color = onColor)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        formatTime(msg.tsUnix),
                        style = MaterialTheme.typography.labelSmall,
                        color = onColor.copy(alpha = 0.7f),
                    )
                    statusLabel(msg.status)?.let { label ->
                        Spacer(Modifier.size(6.dp))
                        Text(
                            label,
                            style = MaterialTheme.typography.labelSmall,
                            color = if (msg.status == SendStatus.FAILED) {
                                MaterialTheme.colorScheme.error
                            } else {
                                onColor.copy(alpha = 0.7f)
                            },
                        )
                    }
                }
            }
        }
    }
}

/** A centered "Today / Yesterday / date" divider between messages on a new day. */
@Composable
private fun DateSeparator(tsUnix: Long) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
        Text(
            formatDay(tsUnix),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(vertical = 4.dp),
        )
    }
}

private val timeFmt = SimpleDateFormat("HH:mm", Locale.getDefault())
private val dayKeyFmt = SimpleDateFormat("yyyyMMdd", Locale.getDefault())
private val dayLabelFmt = SimpleDateFormat("EEE, MMM d", Locale.getDefault())

private fun formatTime(tsUnix: Long): String = timeFmt.format(Date(tsUnix * 1000))

private fun dayKey(tsUnix: Long): String = dayKeyFmt.format(Date(tsUnix * 1000))

private fun formatDay(tsUnix: Long): String {
    val nowSec = System.currentTimeMillis() / 1000
    return when (dayKey(tsUnix)) {
        dayKey(nowSec) -> "Today"
        dayKey(nowSec - 86_400) -> "Yesterday"
        else -> dayLabelFmt.format(Date(tsUnix * 1000))
    }
}

private fun statusLabel(status: SendStatus): String? = when (status) {
    SendStatus.SENDING -> "sending…"
    SendStatus.SENT -> "sent"
    SendStatus.FAILED -> "failed — tap to retry"
    SendStatus.NONE -> null
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
