package com.odivora.app.ui

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.odivora.app.store.Prefs
import kotlinx.coroutines.launch

@Composable
fun SetupScreen(onDone: () -> Unit) {
    val p = prefs
    var url by rememberSaveable { mutableStateOf(p.baseUrl) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    CenteredColumn {
        Text("ODIVORA", style = MaterialTheme.typography.headlineMedium)
        Text("home-connectivity test client", style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(24.dp))
        Text("Server address")
        OutlinedTextField(
            value = url,
            onValueChange = { url = it },
            label = { Text("https://your-ngrok-url.ngrok.io") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Text(
            "The app calls <address>/api/v1/... and opens <ws|wss>://<address>/ws/mobile. " +
                "For an emulator use http://10.0.2.2:8000; for a phone on the same Wi-Fi use " +
                "http://<this-machine-LAN-IP>:8000.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = {
                scope.launch {
                    busy = true
                    error = null
                    try {
                        p.baseUrl = Prefs.normalize(url)
                        onDone()
                    } catch (e: Exception) {
                        error = e.message ?: "unexpected error"
                    } finally {
                        busy = false
                    }
                }
            },
            enabled = !busy && url.isNotBlank(),
        ) { Text(if (busy) "Connecting…" else "Save & continue") }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
}

@Composable
fun AuthFlow(onAuthed: () -> Unit, onBack: () -> Unit) {
    val p = prefs
    var mode by rememberSaveable { mutableStateOf("login") }
    var email by rememberSaveable { mutableStateOf("") }
    var password by rememberSaveable { mutableStateOf("") }
    var deviceName by rememberSaveable { mutableStateOf("ODIVORA phone") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val client = api

    CenteredColumn {
        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = mode == "login", onClick = { mode = "login" })
            Text("Log in")
            RadioButton(selected = mode == "register", onClick = { mode = "register" })
            Text("Register")
        }
        OutlinedTextField(email, { email = it }, label = { Text("email") }, singleLine = true,
            modifier = Modifier.fillMaxWidth())
        OutlinedTextField(password, { password = it }, label = { Text("password (min 10 chars)") },
            singleLine = true, isError = password.isNotEmpty() && password.length < 10,
            modifier = Modifier.fillMaxWidth())
        OutlinedTextField(deviceName, { deviceName = it }, label = { Text("device name") },
            singleLine = true, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(16.dp))
        Button(
            enabled = !busy && email.isNotBlank() && password.isNotBlank() &&
                (mode == "login" || password.length >= 10),
            onClick = {
                scope.launch {
                    busy = true
                    error = null
                    try {
                        if (mode == "login") client.login(email.trim(), password, deviceName.trim())
                        else client.register(email.trim(), password, deviceName.trim())
                        onAuthed()
                    } catch (e: Exception) {
                        error = e.message ?: "unexpected error"
                    } finally {
                        busy = false
                    }
                }
            },
        ) { Text(if (busy) "Working…" else if (mode == "login") "Log in" else "Register") }
        OutlinedButton(onClick = onBack, modifier = Modifier.padding(top = 8.dp)) {
            Text("Change server")
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
}

@Composable
fun CenteredColumn(content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
        content = content,
    )
}