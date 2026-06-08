// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.widget.Toast
import androidx.activity.compose.BackHandler
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
import androidx.compose.material3.Switch
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
import androidx.compose.ui.text.style.TextOverflow
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
    // Inbound introduction consent prompts (D0037 §3) — collected at the top so
    // the prompt overlays ANY screen (an introduction can arrive while in the
    // contact list or another conversation).
    val pendingIntros by vm.pendingIntroductions.collectAsStateWithLifecycle()
    val shareReturnPrompts by vm.shareReturnPrompts.collectAsStateWithLifecycle()

    // System BACK navigates WITHIN the app instead of exiting it: a sub-screen
    // goes back to the conversation list (or cancels a pending pair / dismisses a
    // failure). On the home + pre-unlock screens BACK is NOT intercepted, so it
    // falls through to the platform default (background the app) — no back-trap.
    val onBack: (() -> Unit)? = when (ui) {
        is UiState.Conversation, is UiState.Identity, is UiState.AddContact -> vm::backToContacts
        is UiState.Inviting, is UiState.Connecting -> vm::cancelPairing
        is UiState.Failed -> vm::dismissFailure
        else -> null
    }
    BackHandler(enabled = onBack != null) { onBack?.invoke() }

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

                is UiState.Recovery -> RecoveryScreen(state, vm)

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

    // Show the head of the introduction-consent queue over everything (D0037 §2:
    // nothing happens until the user explicitly approves/connects).
    pendingIntros.firstOrNull()?.let { p -> IntroductionConsentDialog(p, vm) }

    // A recovery peer is asking for the share we hold for them back (D0038 §7):
    // manual approval is the whole Stage-2 gate.
    shareReturnPrompts.firstOrNull()?.let { p -> ShareReturnDialog(p, vm) }
}

/**
 * Manual-approval prompt for returning a held recovery share (D0038 §7). The
 * holder decides whether the requester is really the owner before releasing the
 * share they hold — the only release gate in Stage 2 (cooling-off + a challenge
 * phrase are Stage 3).
 */
@Composable
private fun ShareReturnDialog(p: ShareReturnPrompt, vm: MessagingViewModel) {
    var phrase by remember { mutableStateOf("") }
    var mismatch by remember { mutableStateOf(false) }
    var verifying by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = { if (!verifying) vm.declineReturnShare(p) },
        title = { Text("Return recovery share?") },
        text = {
            Column {
                Text(
                    "“${p.requesterName}” is asking for the recovery share you hold for " +
                        "them. Confirm it's really them: ask them for the challenge phrase " +
                        "you agreed — on a channel you trust, NOT here — and enter it below. " +
                        "Don't read the phrase to them; they must produce it (D0005).",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = phrase,
                    onValueChange = {
                        phrase = it
                        mismatch = false
                    },
                    label = { Text("Their challenge phrase") },
                    singleLine = true,
                    isError = mismatch,
                    enabled = !verifying,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp),
                )
                if (mismatch) {
                    Text(
                        "That phrase didn't match. Check it with them and try again.",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(top = 6.dp),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = phrase.isNotBlank() && !verifying,
                // The match runs Argon2id off-Main; on a mismatch the prompt is kept
                // (up to the attempt cap) so a typo is retryable, not a re-request.
                onClick = {
                    verifying = true
                    mismatch = false
                    vm.returnShareByPhrase(p, phrase) { ok ->
                        verifying = false
                        if (!ok) {
                            mismatch = true
                            phrase = ""
                        }
                    }
                },
            ) { Text(if (verifying) "Verifying…" else "Verify + return") }
        },
        dismissButton = {
            TextButton(enabled = !verifying, onClick = { vm.declineReturnShare(p) }) { Text("Not now") }
        },
    )
}

/**
 * The consent prompt for an inbound introduction (D0037 §3) — the ONLY place an
 * introduction ever acts. Two shapes (see [PendingIntroduction]):
 *
 * - APPROVE — a contact wants to introduce you to someone: approving mints a
 *   one-time invitation and sends it back, so they can connect you.
 * - CONNECT — someone consented to meet you: connecting redeems the invitation.
 *
 * Either way the introducer's vouch rides along, so the new contact will show
 * the introducer's named provenance (D0036 reuse).
 */
@Composable
private fun IntroductionConsentDialog(p: PendingIntroduction, vm: MessagingViewModel) {
    val isApprove = p.kind == PendingIntroduction.Kind.APPROVE
    AlertDialog(
        onDismissRequest = { vm.declineIntroduction(p) },
        title = { Text(if (isApprove) "Introduction request" else "Introduction") },
        text = {
            Column {
                Text(
                    if (isApprove) {
                        "${p.introducerName} would like to introduce you to a new contact, " +
                            "“${p.peerName}”."
                    } else {
                        "${p.introducerName} introduced you to “${p.peerName}”, who agreed to connect."
                    },
                )
                // Only claim a vouch when one is actually attached (D0037 review
                // F2): a Deliver/Request may carry no vouch (or ingest may fail),
                // and informed consent must not rest on an unsubstantiated claim.
                if (p.vouch != null) {
                    Spacer(Modifier.size(8.dp))
                    Text(
                        "${p.introducerName} vouches for this person — they'll appear in your " +
                            "contacts as vouched by ${p.introducerName}.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (isApprove) {
                    Spacer(Modifier.size(8.dp))
                    Text(
                        "Approving creates a one-time invitation so they can reach you. " +
                            "You'll connect once they accept.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                if (isApprove) vm.approveIntroduction(p) else vm.connectIntroduction(p)
            }) { Text(if (isApprove) "Approve" else "Connect") }
        },
        dismissButton = {
            TextButton(onClick = { vm.declineIntroduction(p) }) {
                Text(if (isApprove) "Decline" else "Not now")
            }
        },
    )
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
        TextButton(
            onClick = { vm.beginRecovery() },
            modifier = Modifier.padding(top = 4.dp),
        ) { Text("Recover an existing identity") }
    }
}

/**
 * Paper-share recovery (D0038 §5): collect recovery cards until a threshold
 * reconstructs the master, which re-roots THIS device's persistent operational
 * identity under it. Reached from Welcome → "Recover", after the new device's
 * passphrase + key are set up. Cards can be pasted (one per line) or scanned.
 */
@Composable
private fun RecoveryScreen(state: UiState.Recovery, vm: MessagingViewModel) {
    val context = LocalContext.current
    var pasted by remember { mutableStateOf("") }

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.takeIf { it.isNotBlank() }?.let { vm.addRecoveryCard(it) }
    }
    val launchScan = {
        scanLauncher.launch(
            ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt("Scan a recovery card")
                setBeepEnabled(false)
                setOrientationLocked(false)
            },
        )
    }
    val cameraPermLauncher =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) launchScan()
        }
    val onScanClick = {
        val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        if (granted) launchScan() else cameraPermLauncher.launch(Manifest.permission.CAMERA)
    }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(top = 24.dp),
    ) {
        if (state.recovered) {
            Text("Identity recovered", style = MaterialTheme.typography.titleLarge)
            Text(
                "Your identity is restored on this device" +
                    (state.masterName?.let { " as “$it”" } ?: "") +
                    ". Your contacts aren't carried over — you'll re-add them as before.",
                Modifier.padding(top = 12.dp),
                style = MaterialTheme.typography.bodyMedium,
            )
            Button(
                onClick = { vm.leaveRecovery() },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 24.dp),
            ) { Text("Continue") }
        } else {
            Text("Recover your identity", style = MaterialTheme.typography.titleLarge)
            Text(
                "Enter the recovery cards you saved when you set up Cairn. You'll need " +
                    "the number you chose to require (often 3 of 5). Paste them — one per " +
                    "line — or scan each card.",
                Modifier.padding(top = 8.dp),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                "Cards entered: ${state.collected}" +
                    (state.masterName?.let { "  ·  identity “$it”" } ?: ""),
                Modifier.padding(top = 16.dp),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = pasted,
                onValueChange = { pasted = it },
                label = { Text("Paste recovery card(s)") },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 12.dp),
            )
            Button(
                onClick = {
                    vm.addRecoveryCard(pasted)
                    pasted = ""
                },
                enabled = pasted.isNotBlank(),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
            ) { Text("Add card") }
            OutlinedButton(
                onClick = onScanClick,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
            ) { Text("Scan a card") }

            HorizontalDivider(Modifier.padding(top = 20.dp))
            Text(
                "Once you've added at least one of your own cards above, you can pull the " +
                    "rest back from people you entrusted shares to. Pair with them, then ask " +
                    "for the challenge phrase you agreed — on a channel you trust — and their " +
                    "device returns your share into the count above.",
                Modifier.padding(top = 16.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(
                onClick = { vm.gatherFromPeer() },
                // Anti-poisoning (D0040 §8): your own card must anchor the identity
                // before a peer-returned card is accepted.
                enabled = state.collected >= 1,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
            ) { Text("Get a share from a recovery peer") }

            if (state.status != null) {
                Row(
                    Modifier.padding(top = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    Text(state.status, Modifier.padding(start = 8.dp))
                }
            }
            if (state.error != null) {
                Text(
                    state.error,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(top = 12.dp),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Button(
                onClick = { vm.attemptRecovery() },
                enabled = state.collected >= 2 && state.status == null,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 20.dp),
            ) { Text("Recover identity") }
            TextButton(
                onClick = { vm.leaveRecovery() },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 4.dp),
            ) { Text("Skip for now") }
        }
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
                ContactRow(contact = contact, onClick = { vm.openContact(contact) })
            }
        }
    }
}

/**
 * A single conversation row: monogram · name + last-activity time · last-message
 * preview (or the trust badge before any message) · unread badge. Rows sort
 * most-recent-first and persist across restart (the preview/time/unread live in
 * the encrypted CONTACTS record).
 */
@Composable
private fun ContactRow(contact: Contact, onClick: () -> Unit) {
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
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    contact.displayName,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (contact.lastAtUnix > 0) {
                    Spacer(Modifier.size(8.dp))
                    Text(
                        formatRowTime(contact.lastAtUnix),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (contact.lastPreview.isNotEmpty()) {
                Text(
                    contact.lastPreview,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            } else {
                TrustBadge(contact.trust())
            }
        }
        if (contact.unread > 0) {
            Spacer(Modifier.size(8.dp))
            Box(
                Modifier
                    .size(22.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primary),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    if (contact.unread > 9) "9+" else "${contact.unread}",
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
        Spacer(Modifier.height(20.dp))
        DeviceAttestationSection(state.attestation)
        if (state.masterName != null) {
            Spacer(Modifier.height(12.dp))
            Text("Recovered identity ✓", style = MaterialTheme.typography.titleSmall)
            Text(
                "Restored from your recovery cards and re-rooted under your master " +
                    "key “${state.masterName}”.",
                textAlign = TextAlign.Center,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
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
        // Read receipts (D0032): OFF by default, reciprocal. When on, this device
        // BOTH sends read acks AND shows the peer's; when off, neither — a privacy
        // choice (a receipt reveals THAT + WHEN you read, an online-activity signal).
        Spacer(Modifier.height(28.dp))
        HorizontalDivider(Modifier.fillMaxWidth())
        Spacer(Modifier.height(12.dp))
        var receiptsOn by remember { mutableStateOf(vm.readReceiptsEnabled()) }
        Row(
            Modifier.fillMaxWidth().padding(top = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text("Send read receipts", style = MaterialTheme.typography.titleSmall)
                Text(
                    "Off by default. When on, your contacts see when you've read their " +
                        "messages — and you see theirs. When off, neither.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
            Spacer(Modifier.size(12.dp))
            Switch(
                checked = receiptsOn,
                onCheckedChange = {
                    receiptsOn = it
                    vm.setReadReceiptsEnabled(it)
                },
            )
        }
    }
}

/**
 * Device-key attestation surface (D0033 §2). Renders the Rust verifier's
 * verdict: when attested, the signing key is cryptographically proven (chain →
 * Google's hardware-attestation root) to have been generated inside this
 * phone's secure hardware (TEE / StrongBox) and to be non-exportable. When not
 * attested, messaging still works — the key just isn't hardware-proven
 * (advisory posture, §4). The verified-boot line (§3) is informational.
 */
@Composable
private fun DeviceAttestationSection(att: DeviceAttestation) {
    val mutedColor = MaterialTheme.colorScheme.onSurfaceVariant
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        if (att.attested) {
            Text(
                "Device key: hardware-attested ✓  —  ${att.level}",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                textAlign = TextAlign.Center,
            )
            Text(
                buildString {
                    append("This phone proved the signing key was generated inside its ")
                    append(
                        if (att.level == "StrongBox") {
                            "dedicated secure element"
                        } else {
                            "secure hardware (TEE)"
                        },
                    )
                    append(" and can never leave it.")
                    if (att.verifiedBootState.isNotEmpty()) {
                        append("\nVerified boot: ${att.verifiedBootState}")
                        append(if (att.deviceLocked) ", bootloader locked." else ".")
                    }
                },
                style = MaterialTheme.typography.bodySmall,
                color = mutedColor,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 4.dp),
            )
        } else {
            Text(
                "Device key: not hardware-attested",
                style = MaterialTheme.typography.titleSmall,
                color = mutedColor,
                textAlign = TextAlign.Center,
            )
            Text(
                "Messaging still works; this key just isn't proven to live in this " +
                    "phone's secure hardware.",
                style = MaterialTheme.typography.bodySmall,
                color = mutedColor,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 4.dp),
            )
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
    var showVouch by remember { mutableStateOf(false) }
    var showIntroduce by remember { mutableStateOf(false) }
    var showEntrustShare by remember { mutableStateOf(false) }
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
                        chatTrustLabel(state.trust, state.verifiedStrength),
                        color = Color.White.copy(alpha = 0.85f),
                        style = MaterialTheme.typography.labelSmall,
                    )
                    // Named, depth-1 provenance from the user's verified contacts
                    // (D0036 §6) — provenance, not reputation.
                    if (state.provenance.isNotEmpty()) {
                        Text(
                            "✓ Vouched by ${state.provenance.joinToString(", ")}",
                            color = Color.White.copy(alpha = 0.85f),
                            style = MaterialTheme.typography.labelSmall,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
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
                    // Revocation (D0035 §6) — only meaningful once verified. Both
                    // mint a durable revocation op + downgrade the badge; reversible
                    // by re-verifying. "Mark compromised" triggers the cascade.
                    if (state.trust == Trust.VERIFIED) {
                        DropdownMenuItem(
                            text = { Text("Revoke verification") },
                            onClick = { menuOpen = false; vm.revokeCurrentContact(compromise = false) },
                        )
                        DropdownMenuItem(
                            text = { Text("Mark compromised") },
                            onClick = { menuOpen = false; vm.revokeCurrentContact(compromise = true) },
                        )
                        // Vouch (D0036 §1): share this verified contact's
                        // attestation with another contact — a deliberate,
                        // opt-in act (it reveals you know this person).
                        DropdownMenuItem(
                            text = { Text("Vouch for ${state.displayName} to…") },
                            onClick = { menuOpen = false; showVouch = true },
                        )
                        // Introduce (D0037 §3): broker a consent-gated, two-way
                        // connection between this verified contact + another.
                        // Both consent; both gain the other with your provenance.
                        DropdownMenuItem(
                            text = { Text("Introduce ${state.displayName} to…") },
                            onClick = { menuOpen = false; showIntroduce = true },
                        )
                        // Recovery peer (D0038 §7): entrust one of YOUR recovery
                        // shares to this verified contact to hold, or ask for it
                        // back. Only verified contacts (peer-selection discipline).
                        DropdownMenuItem(
                            text = { Text("Entrust a recovery share…") },
                            onClick = { menuOpen = false; showEntrustShare = true },
                        )
                        DropdownMenuItem(
                            text = { Text("Request my held share back") },
                            onClick = { menuOpen = false; vm.requestHeldShare() },
                        )
                    }
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
    if (showVouch) {
        VouchPickerDialog(
            contactName = state.displayName,
            recipients = vm.otherContacts(state.peerKeyHex),
            onPick = { recipientKey ->
                vm.vouchCurrentContactTo(recipientKey)
                showVouch = false
            },
            onDismiss = { showVouch = false },
        )
    }
    if (showIntroduce) {
        IntroducePickerDialog(
            contactName = state.displayName,
            // Only VERIFIED other contacts: an introduction carries your vouch
            // for each party, which requires an attestation chain (D0037 §3).
            candidates = vm.introducibleContacts(state.peerKeyHex),
            onPick = { otherKey ->
                vm.initiateIntroduction(otherKey)
                showIntroduce = false
            },
            onDismiss = { showIntroduce = false },
        )
    }
    if (showEntrustShare) {
        var card by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { showEntrustShare = false },
            title = { Text("Entrust a recovery share") },
            text = {
                Column {
                    Text(
                        "Paste one of your recovery cards to entrust to ${state.displayName}. " +
                            "They'll hold it and can return it if you ever need to recover your " +
                            "identity. Spread your shares across people you trust — a threshold " +
                            "of them together could reconstruct your key (D0038 §7).",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedTextField(
                        value = card,
                        onValueChange = { card = it },
                        label = { Text("Recovery card") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp),
                    )
                }
            },
            confirmButton = {
                TextButton(
                    enabled = card.isNotBlank(),
                    onClick = { vm.entrustRecoveryShare(card); showEntrustShare = false },
                ) { Text("Send") }
            },
            dismissButton = {
                TextButton(onClick = { showEntrustShare = false }) { Text("Cancel") }
            },
        )
    }
}

/**
 * Pick a verified contact to introduce the open contact to (D0037 §3). Sends the
 * open contact a consent request; once they approve, the other contact is asked
 * to connect. Both must already be verified — only verified contacts can be
 * vouched for, which an introduction does for each party.
 */
@Composable
private fun IntroducePickerDialog(
    contactName: String,
    candidates: List<Pair<String, String>>,
    onPick: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Introduce $contactName to…") },
        text = {
            if (candidates.isEmpty()) {
                Text(
                    "You have no other verified contacts to introduce. You can only " +
                        "introduce people you have verified.",
                )
            } else {
                Column {
                    Text(
                        "Both will be asked to consent. Each will see the other as " +
                            "vouched by you.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Spacer(Modifier.size(8.dp))
                    candidates.forEach { (name, key) ->
                        TextButton(
                            onClick = { onPick(key) },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(name, modifier = Modifier.fillMaxWidth()) }
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/**
 * Pick a contact to vouch the open contact to (D0036 §1). Deliberate + opt-in —
 * sharing reveals to the recipient that you know + verified this contact.
 */
@Composable
private fun VouchPickerDialog(
    contactName: String,
    recipients: List<Pair<String, String>>,
    onPick: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Vouch for $contactName to…") },
        text = {
            if (recipients.isEmpty()) {
                Text("You have no other contacts to vouch to.")
            } else {
                Column {
                    Text(
                        "Share your verification of $contactName with a contact — " +
                            "they will see that you vouch for this key.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Spacer(Modifier.size(8.dp))
                    recipients.forEach { (name, key) ->
                        TextButton(
                            onClick = { onPick(key) },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(name, modifier = Modifier.fillMaxWidth()) }
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Compact trust label for the chat app bar (the colour-coded badge is on the list). */
private fun chatTrustLabel(trust: Trust, verifiedStrength: String? = null): String = when (trust) {
    // Show HOW the key was verified (D0035 §5) — in-person is stronger than a
    // safety number compared over a separate channel.
    Trust.VERIFIED -> when (verifiedStrength) {
        "IN_PERSON" -> "✓ Verified in person"
        "CHANNEL_VERIFIED" -> "✓ Verified over a channel"
        else -> "✓ Verified"
    }
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
                            // READ stands out at full alpha (vs the muted "sent");
                            // FAILED is the error color (D0032 + the legibility unit).
                            color = when (msg.status) {
                                SendStatus.FAILED -> MaterialTheme.colorScheme.error
                                SendStatus.READ -> onColor
                                else -> onColor.copy(alpha = 0.7f)
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

private val rowDateFmt = SimpleDateFormat("MMM d", Locale.getDefault())

/** Compact conversation-row timestamp: today → HH:mm, yesterday → "Yesterday", else date. */
private fun formatRowTime(tsUnix: Long): String {
    val nowSec = System.currentTimeMillis() / 1000
    return when (dayKey(tsUnix)) {
        dayKey(nowSec) -> timeFmt.format(Date(tsUnix * 1000))
        dayKey(nowSec - 86_400) -> "Yesterday"
        else -> rowDateFmt.format(Date(tsUnix * 1000))
    }
}

private fun statusLabel(status: SendStatus): String? = when (status) {
    SendStatus.SENDING -> "sending…"
    SendStatus.SENT -> "sent"
    SendStatus.READ -> "read" // D0032: the peer reported reading it (receipts on)
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
