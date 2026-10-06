package com.odivora.app.ui

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
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
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.odivora.app.net.WgAuth
import com.odivora.app.net.WgConfig
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.File

@Composable
fun SessionScreen(sessionId: String, onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var status by remember { mutableStateOf<String?>(null) }
    var path by remember { mutableStateOf<String?>(null) }
    var auth by remember { mutableStateOf<WgAuth?>(null) }
    var configText by rememberSaveable { mutableStateOf("") }
    var serverConf by remember { mutableStateOf<String?>(null) }
    var wsLog by remember { mutableStateOf<List<String>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var sitesInput by rememberSaveable { mutableStateOf("") }
    var visitNote by remember { mutableStateOf<String?>(null) }
    val client = api

    LaunchedEffect(sessionId) {
        val ws = client.openWs { msg ->
            val log = (wsLog + msg).takeLast(30)
            wsLog = log
        }
        while (true) {
            runCatching { client.sessionStatus(sessionId) }
                .onSuccess {
                    status = it.status
                    path = it.connectionPath
                }
            delay(3000)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth()) {
            OutlinedButton(onClick = onBack) { Text("← Home") }
            Text(
                "session $sessionId",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(start = 12.dp),
            )
        }
        Text(
            "status: ${status ?: "…"} · path: ${path ?: "…"}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Spacer(Modifier.height(8.dp))

        Section("1 · Authorize the phone as a WireGuard peer")
        Text(
            "Server mints a demo keypair so we can test the whole flow before real keygen. " +
                "Your generated private key never has to leave the phone in production.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(
            enabled = !busy,
            onClick = {
                scope.launch {
                    busy = true
                    error = null
                    try {
                        val a = client.authorizeWg(sessionId)
                        auth = a
                        configText = WgConfig.build(
                            gatewayPublicKey = a.gatewayPublicKey,
                            privateKey = a.clientPrivateKey ?: "<generate your own keypair>",
                            address = a.assignedIp,
                            endpoint = WgConfig.defaultEndpoint(a),
                            allowedIps = "0.0.0.0/0",
                            dns = "1.1.1.1",
                        )
                    } catch (e: Exception) {
                        error = e.message ?: "unexpected error"
                    } finally {
                        busy = false
                    }
                }
            },
        ) { Text("Authorize with demo keys") }

        Section("2 · Tunnel config")
        OutlinedTextField(
            value = configText,
            onValueChange = { configText = it },
            label = { Text("odivora .conf (edit here for LAN tests)") },
            minLines = 10,
            modifier = Modifier
                .fillMaxWidth()
                .height(260.dp),
        )
        Row {
            Button(
                enabled = auth != null && configText.isNotBlank(),
                onClick = { openInWireGuard(context, sessionId, configText) },
            ) { Text("Open in WireGuard") }
            OutlinedButton(
                enabled = configText.isNotBlank(),
                onClick = { shareConfig(context, configText) },
            ) { Text("Share") }
            OutlinedButton(
                enabled = configText.isNotBlank(),
                onClick = { copyConfig(context, configText) },
            ) { Text("Copy") }
        }
        OutlinedButton(
            onClick = {
                scope.launch {
                    busy = true
                    error = null
                    try {
                        serverConf = client.serverWgConfig(sessionId).second
                    } catch (e: Exception) {
                        error = e.message ?: "unexpected error"
                    } finally {
                        busy = false
                    }
                }
            },
        ) { Text("Show server-generated .conf (info)") }
        serverConf?.let { conf ->
            Text(
                conf.take(600) + if (conf.length > 600) "…" else "",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Section("3 · Confirm & close")
        Button(
            enabled = !busy,
            onClick = {
                scope.launch {
                    busy = true
                    error = null
                    try {
                        client.handshake(sessionId)
                    } catch (e: Exception) {
                        error = e.message ?: "unexpected error"
                    } finally {
                        busy = false
                    }
                }
            },
        ) { Text("Tunnel is up — confirm handshake") }
        OutlinedButton(
            onClick = {
                scope.launch {
                    busy = true
                    error = null
                    try {
                        client.revokeWg(sessionId)
                        client.closeSession(sessionId)
                        onBack()
                    } catch (e: Exception) {
                        error = e.message ?: "unexpected error"
                    } finally {
                        busy = false
                    }
                }
            },
        ) { Text("Revoke peer & close session") }

        Section("4 · Report visited sites (audit)")
        OutlinedTextField(
            value = sitesInput,
            onValueChange = { sitesInput = it },
            label = { Text("hosts, comma-separated (e.g. example.com, docs.odivora.co)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Row {
            Button(
                enabled = sitesInput.isNotBlank(),
                onClick = {
                    scope.launch {
                        busy = true
                        error = null
                        try {
                            val out = client.visits(sessionId, sitesInput.split(',').map { it.trim() }.filter { it.isNotEmpty() })
                            visitNote = "stored ${out.stored}/${out.total} (limit ${out.limit})"
                        } catch (e: Exception) {
                            error = e.message ?: "unexpected error"
                        } finally {
                            busy = false
                        }
                    }
                },
            ) { Text("Report sites") }
            visitNote?.let { Text(it, modifier = Modifier.padding(start = 12.dp, top = 12.dp)) }
        }

        Section("5 · Signalling (WS /ws/mobile)")
        Text(
            if (wsLog.isEmpty()) "no messages yet" else wsLog.reversed().joinToString("\n"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(24.dp))
        HorizontalDivider()
    }
}

@Composable
private fun Section(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.titleSmall,
        modifier = Modifier.padding(top = 20.dp, bottom = 4.dp),
    )
}

private fun openInWireGuard(context: Context, sessionId: String, configText: String) {
    val dir = File(context.cacheDir, "configs").apply { mkdirs() }
    val file = File(dir, "odivora-$sessionId.conf")
    file.writeText(configText)
    val uri: Uri = FileProvider.getUriForFile(context, "com.odivora.app.fileprovider", file)
    val intent = Intent(Intent.ACTION_VIEW)
        .setDataAndType(uri, "application/x-wireguard-profile")
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    runCatching { context.startActivity(intent) }
        .onFailure { toast(context, "No app opens this profile here — use Share or Copy.") }
}

private fun shareConfig(context: Context, configText: String) {
    val send = Intent(Intent.ACTION_SEND)
        .setType("text/plain")
        .putExtra(Intent.EXTRA_TEXT, configText)
    runCatching { context.startActivity(Intent.createChooser(send, "Send WireGuard config")) }
        .onFailure { toast(context, "No share target available.") }
}

private fun copyConfig(context: Context, configText: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(android.content.ClipData.newPlainText("odivora-wg-config", configText))
    toast(context, "Config copied")
}

private fun toast(context: Context, message: String) {
    Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
}