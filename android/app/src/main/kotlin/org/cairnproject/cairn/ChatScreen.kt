// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

package org.cairnproject.cairn

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * The Cairn demo chat surface (D0003 Kotlin UI). Renders the [MessagingViewModel]
 * state machine: bring-up → setup (create/accept invitation) → live 1:1 chat,
 * over the bundled SimpleX-over-Tor transport.
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

                is UiState.Inviting -> Column {
                    Text("Share this invitation:", style = MaterialTheme.typography.titleMedium)
                    SelectableBlock(state.inviteToShare)
                    Text(
                        "Waiting for your contact to accept…",
                        Modifier.padding(top = 12.dp),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    CircularProgressIndicator(Modifier.padding(top = 8.dp))
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
    var peerKey by remember { mutableStateOf("") }
    var inviteBlob by remember { mutableStateOf("") }
    Column(Modifier.verticalScroll(rememberScrollState())) {
        Text("Your public key (share with your contact):", style = MaterialTheme.typography.titleSmall)
        SelectableBlock(state.myKeyHex)

        HorizontalDivider(Modifier.padding(vertical = 12.dp))
        Text("Create an invitation", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = peerKey,
            onValueChange = { peerKey = it },
            label = { Text("Contact's public key (hex)") },
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = { vm.createInvitation(peerKey) },
            modifier = Modifier.padding(top = 8.dp),
            enabled = peerKey.isNotBlank(),
        ) { Text("Create invitation") }

        HorizontalDivider(Modifier.padding(vertical = 12.dp))
        Text("Or accept one", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = inviteBlob,
            onValueChange = { inviteBlob = it },
            label = { Text("Paste invitation (<uri>|<key>)") },
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = { vm.acceptInvitation(inviteBlob) },
            modifier = Modifier.padding(top = 8.dp),
            enabled = inviteBlob.isNotBlank(),
        ) { Text("Accept invitation") }
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
    Card(Modifier.fillMaxWidth().padding(top = 4.dp)) {
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
