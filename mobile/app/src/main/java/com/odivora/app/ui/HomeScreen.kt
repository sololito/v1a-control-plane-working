package com.odivora.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.odivora.app.net.Gateway
import kotlinx.coroutines.launch

@Composable
fun HomeScreen(onOpenSession: (String) -> Unit, onLogout: () -> Unit) {
    var gateways by remember { mutableStateOf<List<Gateway>?>(null) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val client = api

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
    ) {
        Text("Your gateways", style = MaterialTheme.typography.headlineSmall)
        Row(modifier = Modifier.fillMaxWidth()) {
            Text(
                "API: ${prefs.baseUrl}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            OutlinedButton(onClick = onLogout) { Text("Log out") }
        }
        Spacer(Modifier.height(16.dp))
        Button(
            enabled = !busy,
            onClick = {
                scope.launch {
                    busy = true
                    message = null
                    try {
                        gateways = client.gateways()
                    } catch (e: Exception) {
                        message = e.message ?: "unexpected error"
                    } finally {
                        busy = false
                    }
                }
            },
        ) { Text(if (busy) "Loading…" else "Refresh gateways") }

        message?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }

        val list = gateways
        if (list == null) {
            Text("Press Refresh to list your claimed home gateways.", style = MaterialTheme.typography.bodyMedium)
        } else if (list.isEmpty()) {
            Text("No gateways claimed yet.", style = MaterialTheme.typography.bodyMedium)
        } else {
            list.forEach { gw ->
                Text("${gw.id} · ${gw.deviceType} · ${gw.status}", style = MaterialTheme.typography.bodyMedium)
                Text(
                    "last seen ${gw.lastSeen ?: "never"} · fw ${gw.firmwareVersion ?: "—"}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Button(
                    onClick = {
                        scope.launch {
                            busy = true
                            message = null
                            try {
                                onOpenSession(client.openSession(gw.id).id)
                            } catch (e: Exception) {
                                message = e.message ?: "unexpected error"
                            } finally {
                                busy = false
                            }
                        }
                    },
                    enabled = !busy,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp),
                ) { Text("Open tunnel session (relay)") }
                Spacer(Modifier.height(16.dp))
            }
        }
    }
}