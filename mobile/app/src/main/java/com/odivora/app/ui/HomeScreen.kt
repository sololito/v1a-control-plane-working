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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.odivora.app.net.Gateway
import kotlinx.coroutines.launch

@Composable
fun HomeScreen(onOpenSession: (String) -> Unit, onLogout: () -> Unit) {
    var gateways by remember { mutableStateOf<List<Gateway>?>(null) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var claimId by remember { mutableStateOf("") }
    var claimCode by remember { mutableStateOf("") }
    var claimRaw by remember { mutableStateOf("") }
    var notice by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val client = api

    // Prefill the claim box from the server's pending candidates. Only fills
    // while both fields are blank: every fetch re-mints the pairing codes, so
    // re-fetching over a user's typed-in code would invalidate it.
    val fillPending: suspend () -> Boolean = {
        var filled = false
        if (claimId.isBlank() && claimCode.isBlank()) {
            runCatching { client.pendingPairings() }.getOrDefault(emptyList())
                .firstOrNull()?.let { p ->
                    claimId = p.gatewayId
                    claimCode = p.pairingCode
                    filled = true
                }
        }
        filled
    }

    LaunchedEffect(Unit) {
        runCatching { gateways = client.gateways() }
        if (fillPending()) {
            notice = "Gateway ready to claim — tap Claim gateway."
        }
    }

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
                        if (fillPending()) {
                            notice = "Gateway ready to claim — tap Claim gateway."
                        }
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

        Spacer(Modifier.height(24.dp))
        Text("Claim a gateway", style = MaterialTheme.typography.titleMedium)
        Text(
            "Filled in automatically after login while a gateway is waiting to be " +
                "claimed — or paste the pairing info printed by the device " +
                "(15 min TTL, 5 attempts).",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = claimRaw,
            onValueChange = { raw ->
                val parsed = parsePairing(raw)
                if (parsed != null) {
                    claimId = parsed.first
                    claimCode = parsed.second
                    claimRaw = ""
                    notice = "Pairing info filled in below."
                } else {
                    claimRaw = raw
                }
            },
            label = { Text("paste pairing info (gateway id + code)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = claimId,
            onValueChange = { v ->
                val parsed = parsePairing(v)
                if (parsed != null) {
                    claimId = parsed.first
                    claimCode = parsed.second
                } else {
                    claimId = v
                }
            },
            label = { Text("gateway id") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = claimCode,
            onValueChange = { v ->
                val parsed = parsePairing(v)
                if (parsed != null) {
                    claimId = parsed.first
                    claimCode = parsed.second
                } else {
                    claimCode = v
                }
            },
            label = { Text("pairing code") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        notice?.let {
            Text(it, color = MaterialTheme.colorScheme.primary,
                style = MaterialTheme.typography.bodySmall)
        }
        Button(
            enabled = !busy && claimId.isNotBlank() && claimCode.isNotBlank(),
            onClick = {
                scope.launch {
                    busy = true
                    message = null
                    notice = null
                    try {
                        client.claimGateway(claimId.trim(), claimCode.trim())
                        gateways = client.gateways()
                        claimId = ""
                        claimCode = ""
                        notice = "Gateway claimed."
                        if (fillPending()) {
                            notice = "Gateway claimed — next one ready below."
                        }
                    } catch (e: Exception) {
                        message = e.message ?: "unexpected error"
                    } finally {
                        busy = false
                    }
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp),
        ) { Text(if (busy) "Working…" else "Claim gateway") }
    }
}

private val UUID_RE =
    Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
private val LABELED_CODE_RE = Regex("(?i)(?:pairing\\s*code|code)\\D{0,12}(\\d{4,12})")
private val SIX_DIGITS_RE = Regex("\\b\\d{6}\\b")
private val ANY_CODE_RE = Regex("\\d{4,12}")

/** Splits a pasted device line ("gateway_id=... PAIRING CODE: 123456") into (id, code). */
private fun parsePairing(raw: String): Pair<String, String>? {
    val id = UUID_RE.find(raw)?.value ?: return null
    val rest = raw.replace(id, " ")
    val code = LABELED_CODE_RE.find(raw)?.groupValues?.get(1)
        ?: SIX_DIGITS_RE.find(rest)?.value
        ?: ANY_CODE_RE.find(rest)?.value
        ?: return null
    return id to code
}