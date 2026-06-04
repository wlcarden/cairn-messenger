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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FloatingActionButton
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
import androidx.fragment.app.FragmentActivity
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
        topBar = { CairnTopBar(ui, torStatus, vm) },
        floatingActionButton = {
            if (ui is UiState.ContactList) {
                FloatingActionButton(onClick = { vm.showAddContact() }) {
                    Icon(painterResource(R.drawable.ic_add), contentDescription = "Add a contact")
                }
            }
        },
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

                is UiState.Identity -> IdentityView(state, vm)

                is UiState.AddContact -> AddContactView(vm)

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
private fun CairnTopBar(ui: UiState, torStatus: String, vm: MessagingViewModel) {
    if (ui is UiState.Conversation) {
        // The open conversation gets its own chat app bar (back + contact + verify).
        ChatAppBar(ui, vm)
        return
    }
    val colors = TopAppBarDefaults.topAppBarColors(
        containerColor = CairnTeal,
        titleContentColor = Color.White,
        navigationIconContentColor = Color.White,
        actionIconContentColor = Color.White,
    )
    val subScreenTitle = when (ui) {
        is UiState.Identity -> "My identity"
        is UiState.AddContact -> "Add a contact"
        else -> null
    }
    if (subScreenTitle != null) {
        // A back-navigable sub-screen (identity / add-contact).
        TopAppBar(
            title = { Text(subScreenTitle) },
            navigationIcon = {
                IconButton(onClick = { vm.backToContacts() }) {
                    Icon(painterResource(R.drawable.ic_back), contentDescription = "Back")
                }
            },
            colors = colors,
        )
    } else {
        // The branded home bar: glyph + name + Tor dot (+ a profile action on home).
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
                if (ui is UiState.ContactList) {
                    IconButton(onClick = { vm.showIdentity() }) {
                        Icon(painterResource(R.drawable.ic_person), contentDescription = "My identity")
                    }
                }
                Spacer(Modifier.size(4.dp))
            },
            colors = colors,
        )
    }
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
    val context = LocalContext.current
    val activity = context as? FragmentActivity
    var pass by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var reveal by remember { mutableStateOf(false) }
    var enrollQuick by remember { mutableStateOf(false) }
    // The device can satisfy a Class-3 biometric or the lockscreen credential.
    val quickAvailable = remember(activity) { activity != null && QuickUnlock.isAvailable(activity) }
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
        val act = activity
        // Quick unlock (D0029): a one-tap fingerprint / screen-lock unlock that
        // decrypts the stored passphrase. Shown only when a wrapped blob exists.
        if (state.quickUnlockEnrolled && act != null) {
            Button(
                onClick = {
                    QuickUnlock.unlock(
                        act,
                        onPassphrase = { pp -> vm.unlock(String(pp)) },
                        onError = { msg -> Toast.makeText(context, msg, Toast.LENGTH_LONG).show() },
                    )
                },
                modifier = Modifier.padding(top = 20.dp),
            ) { Text("Unlock with fingerprint or screen lock") }
            Text(
                "or enter your passphrase",
                Modifier.padding(top = 12.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
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
        if (quickAvailable && !state.quickUnlockEnrolled) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(top = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Checkbox(checked = enrollQuick, onCheckedChange = { enrollQuick = it })
                Text(
                    "Unlock with fingerprint or screen lock next time",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
        Button(
            onClick = {
                // Enroll only AFTER a successful unlock, with the known-correct
                // passphrase still in hand (D0029) — never retained in the VM.
                val onUnlocked: (() -> Unit)? =
                    if (enrollQuick && act != null) {
                        {
                            QuickUnlock.enroll(act, pass.toByteArray()) { ok, err ->
                                Toast.makeText(
                                    context,
                                    if (ok) {
                                        "Quick unlock enabled"
                                    } else {
                                        err ?: "Couldn't enable quick unlock"
                                    },
                                    Toast.LENGTH_LONG,
                                ).show()
                            }
                        }
                    } else {
                        null
                    }
                vm.unlock(pass, onUnlocked)
            },
            enabled = canSubmit,
            modifier = Modifier.padding(top = 20.dp),
        ) { Text(if (state.firstLaunch) "Create & unlock" else "Unlock") }
    }
}

/** Home: the conversations list (a messenger's primary screen). Your own key
 *  moved to [IdentityView] (app-bar profile action); adding moved to the FAB. */
@Composable
private fun ContactListView(state: UiState.ContactList, vm: MessagingViewModel) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        if (state.error != null) {
            Text(
                state.error,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(vertical = 8.dp),
            )
        }
        if (state.contacts.isEmpty()) {
            Spacer(Modifier.height(64.dp))
            Column(
                Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text("No conversations yet", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Tap + to invite a contact, or scan their invitation.",
                    Modifier.padding(top = 8.dp),
                    textAlign = TextAlign.Center,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            Spacer(Modifier.height(4.dp))
            state.contacts.forEach { contact ->
                ContactRow(
                    contact = contact,
                    unread = state.unread[contact.peerKeyHex] ?: 0,
                    onClick = { vm.openContact(contact) },
                )
            }
        }
    }
}

/** A single conversation row: monogram avatar · name + trust · unread badge. */
@Composable
private fun ContactRow(contact: Contact, unread: Int, onClick: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Monogram(contact.displayName, contact.peerKeyHex)
        Spacer(Modifier.size(12.dp))
        Column(Modifier.weight(1f)) {
            Text(contact.displayName, style = MaterialTheme.typography.titleMedium)
            TrustBadge(contact.trust())
        }
        if (unread > 0) {
            Box(
                Modifier
                    .size(22.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primary),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    if (unread > 9) "9+" else "$unread",
                    color = MaterialTheme.colorScheme.onPrimary,
                    style = MaterialTheme.typography.labelSmall,
                )
            }
        }
    }
}

private val MONOGRAM_COLORS = listOf(
    Color(0xFF1E6B64), Color(0xFF5B6BBF), Color(0xFF9C5BBF),
    Color(0xFFBF6B5B), Color(0xFF5B9CBF), Color(0xFF6BAA4A),
)

/** A coloured circle with the contact's initial — a per-key visual identity. */
@Composable
private fun Monogram(name: String, keyHex: String) {
    val bg = MONOGRAM_COLORS[(keyHex.hashCode() and 0x7fffffff) % MONOGRAM_COLORS.size]
    val letter = name.trim().firstOrNull()?.uppercase() ?: "?"
    Box(
        Modifier
            .size(44.dp)
            .clip(CircleShape)
            .background(bg),
        contentAlignment = Alignment.Center,
    ) {
        Text(letter, color = Color.White, style = MaterialTheme.typography.titleMedium)
    }
}

/** The user's own identity: a scannable QR of their key + the fingerprint. */
@Composable
private fun IdentityView(state: UiState.Identity, vm: MessagingViewModel) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    var showChangePass by remember { mutableStateOf(false) }
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(16.dp))
        Text(
            "Show this to a contact so they can verify they have your real key.",
            textAlign = TextAlign.Center,
            style = MaterialTheme.typography.bodyMedium,
        )
        QrImage(
            state.myKeyHex,
            modifier = Modifier
                .padding(top = 16.dp)
                .size(240.dp),
        )
        Spacer(Modifier.height(16.dp))
        Text("Your name words", style = MaterialTheme.typography.titleSmall)
        Text(
            FriendlyName.of(state.myKeyHex),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(top = 4.dp),
        )
        Text(
            "A short, memorable fingerprint of your key. Read these to a contact so " +
                "they can confirm they have the right one — they survive a rename.",
            textAlign = TextAlign.Center,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 4.dp),
        )
        Spacer(Modifier.height(16.dp))
        Text("Your key", style = MaterialTheme.typography.titleSmall)
        SelectableBlock(state.myKeyHex)
        OutlinedButton(
            onClick = {
                clipboard.setText(AnnotatedString(state.myKeyHex))
                Toast.makeText(context, "Key copied", Toast.LENGTH_SHORT).show()
            },
            modifier = Modifier.padding(top = 12.dp),
        ) { Text("Copy key") }
        OutlinedButton(
            onClick = { showChangePass = true },
            modifier = Modifier.padding(top = 8.dp),
        ) { Text("Change passphrase") }
        if (showChangePass) {
            ChangePassphraseDialog(vm, onDismiss = { showChangePass = false })
        }
        // Quick unlock on/off (D0029). Enabling happens at the lock screen (the
        // passphrase is in hand there); here we only offer to turn it OFF, which
        // deletes the wrapped blob + the Keystore key — reverting to the
        // strongest posture (no key material on disk).
        if (state.quickUnlockEnrolled) {
            Spacer(Modifier.height(28.dp))
            HorizontalDivider(Modifier.fillMaxWidth())
            Spacer(Modifier.height(12.dp))
            Text("Quick unlock is on", style = MaterialTheme.typography.titleSmall)
            Text(
                "This device can open Cairn with your fingerprint or screen lock. " +
                    "Your passphrase still works and stays your only recovery.",
                textAlign = TextAlign.Center,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
            OutlinedButton(
                onClick = {
                    QuickUnlock.disable(context.filesDir)
                    vm.showIdentity()
                    Toast.makeText(context, "Quick unlock turned off", Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.padding(top = 12.dp),
            ) { Text("Turn off quick unlock") }
        }
    }
}

/** Add-a-contact: create a one-time invitation, or scan / paste a contact's. */
@Composable
private fun AddContactView(vm: MessagingViewModel) {
    val context = LocalContext.current
    var showPaste by remember { mutableStateOf(false) }
    var pasted by remember { mutableStateOf("") }

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

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        Spacer(Modifier.height(8.dp))
        Text(
            "Pair over a one-time invitation. Share yours, or scan / paste theirs.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Button(
            onClick = { vm.createInvitation() },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 16.dp),
        ) { Text("Create an invitation") }
        OutlinedButton(
            onClick = onScanClick,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
        ) { Text("Scan their invitation") }
        OutlinedButton(
            onClick = { showPaste = !showPaste },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
        ) { Text(if (showPaste) "Hide paste" else "Paste a link instead") }
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
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                enabled = pasted.isNotBlank(),
            ) { Text("Accept invitation") }
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

/**
 * The open conversation's app bar (Stage 3): back · monogram + name + trust ·
 * Verify (when not verified) · overflow (rename / delete). Replaces the old
 * cramped inline header row; holds the verify / rename / delete dialogs.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ChatAppBar(state: UiState.Conversation, vm: MessagingViewModel) {
    var menuOpen by remember { mutableStateOf(false) }
    var showVerify by remember { mutableStateOf(false) }
    var showRename by remember { mutableStateOf(false) }
    var showDelete by remember { mutableStateOf(false) }
    var verifyScanError by remember { mutableStateOf<String?>(null) }
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

    TopAppBar(
        navigationIcon = {
            IconButton(onClick = { vm.backToContacts() }) {
                Icon(painterResource(R.drawable.ic_back), contentDescription = "Back to contacts")
            }
        },
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Monogram(state.displayName, state.peerKeyHex)
                Spacer(Modifier.size(10.dp))
                Column {
                    Text(
                        state.displayName,
                        color = Color.White,
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(
                        chatTrustLabel(state.trust),
                        color = Color.White.copy(alpha = 0.85f),
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
        },
        actions = {
            if (state.trust != Trust.VERIFIED) {
                TextButton(onClick = { showVerify = true }) { Text("Verify", color = Color.White) }
            }
            Box {
                IconButton(onClick = { menuOpen = true }) {
                    Text(
                        "⋮",
                        color = Color.White,
                        style = MaterialTheme.typography.titleLarge,
                        modifier = Modifier.semantics { contentDescription = "More options" },
                    )
                }
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    DropdownMenuItem(
                        text = { Text("Rename") },
                        onClick = { menuOpen = false; showRename = true },
                    )
                    DropdownMenuItem(
                        text = { Text("Delete contact") },
                        onClick = { menuOpen = false; showDelete = true },
                    )
                }
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = CairnTeal,
            titleContentColor = Color.White,
            navigationIconContentColor = Color.White,
            actionIconContentColor = Color.White,
        ),
    )

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
}

/** Compact trust label for the chat app bar (the colour-coded badge is on the list). */
private fun chatTrustLabel(trust: Trust): String = when (trust) {
    Trust.VERIFIED -> "✓ Verified"
    Trust.UNVERIFIED -> "Unverified — tap Verify"
    Trust.KEY_CHANGED -> "⛔ Key changed"
}

@Composable
private fun ChatView(state: UiState.Conversation, vm: MessagingViewModel) {
    val messages by vm.messages.collectAsStateWithLifecycle()
    var draft by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize()) {
        if (state.trust == Trust.KEY_CHANGED) {
            KeyChangedBanner()
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
                    "Quick check — these three words are a short fingerprint of this " +
                        "contact's key, and match the words on their identity screen:",
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    FriendlyName.of(state.peerKeyHex),
                    style = MaterialTheme.typography.titleMedium,
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    "For full assurance, compare this number out loud — it is identical " +
                        "on both devices only if no one is intercepting your keys:",
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
private fun KeyChangedBanner() {
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
                    "until you re-verify (tap Verify above).",
                color = Color.White,
                style = MaterialTheme.typography.bodySmall,
            )
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

/**
 * Change-passphrase dialog (D0030 §3). Re-keys the encrypted store from the
 * current passphrase to a new (confirmed, min-length) one; on success quick
 * unlock is invalidated (its blob held the old passphrase). The re-encrypt runs
 * off the main thread — the dialog shows a busy state and blocks dismissal while
 * it runs, so a half-applied change can't be triggered.
 */
@Composable
private fun ChangePassphraseDialog(vm: MessagingViewModel, onDismiss: () -> Unit) {
    val context = LocalContext.current
    var current by remember { mutableStateOf("") }
    var newPass by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val tooShort = newPass.isNotEmpty() && newPass.length < MIN_PASSPHRASE
    val mismatch = confirm.isNotEmpty() && newPass != confirm
    val canSubmit = current.isNotBlank() && newPass.length >= MIN_PASSPHRASE &&
        newPass == confirm && !busy
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Change passphrase") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    "Your new passphrase re-encrypts everything on this device. There " +
                        "is no reset — write it down. Quick unlock will be turned off; " +
                        "you can re-enable it afterward.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(12.dp))
                PasswordField("Current passphrase", current, enabled = !busy) { current = it }
                Spacer(Modifier.height(8.dp))
                PasswordField("New passphrase", newPass, enabled = !busy) { newPass = it }
                Spacer(Modifier.height(8.dp))
                PasswordField(
                    "Confirm new passphrase",
                    confirm,
                    enabled = !busy,
                    isError = mismatch,
                ) { confirm = it }
                (error ?: if (tooShort) {
                    "Too short — at least $MIN_PASSPHRASE characters."
                } else if (mismatch) {
                    "New passphrases don't match."
                } else {
                    null
                })?.let {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        it,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (busy) {
                    Spacer(Modifier.height(12.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.size(18.dp))
                        Spacer(Modifier.size(8.dp))
                        Text("Re-encrypting…", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = canSubmit,
                onClick = {
                    error = null
                    busy = true
                    vm.changePassphrase(current, newPass) { ok, err ->
                        busy = false
                        if (ok) {
                            Toast.makeText(context, "Passphrase changed", Toast.LENGTH_LONG).show()
                            onDismiss()
                        } else {
                            error = err
                        }
                    }
                },
            ) { Text("Change") }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onDismiss) { Text("Cancel") } },
    )
}

/** A masked single-line passphrase field for dialogs. */
@Composable
private fun PasswordField(
    label: String,
    value: String,
    enabled: Boolean = true,
    isError: Boolean = false,
    onValueChange: (String) -> Unit,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        singleLine = true,
        enabled = enabled,
        isError = isError,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        modifier = Modifier.fillMaxWidth(),
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
