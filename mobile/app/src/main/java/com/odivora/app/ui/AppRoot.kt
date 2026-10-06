package com.odivora.app.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import com.odivora.app.OdivoraApp
import com.odivora.app.net.Api
import com.odivora.app.store.Prefs

@Composable
fun AppRoot() {
    val p = prefs
    var screen by rememberSaveable { mutableStateOf(initialScreen(p)) }

    when {
        screen.startsWith("session:") -> SessionScreen(
            sessionId = screen.removePrefix("session:"),
            onBack = { screen = "home" },
        )
        screen == "home" -> HomeScreen(
            onOpenSession = { screen = "session:$it" },
            onLogout = { screen = "auth" },
        )
        screen == "auth" -> AuthFlow(
            onAuthed = { screen = "home" },
            onBack = { screen = "setup" },
        )
        else -> SetupScreen(
            onDone = { screen = if (p.hasSession) "home" else "auth" },
        )
    }
}

private fun initialScreen(p: Prefs): String = when {
    p.hasSession -> "home"
    p.baseUrl == Prefs.DEFAULT_BASE_URL -> "setup"
    else -> "auth"
}

val prefs: Prefs
    @Composable get() = OdivoraApp.INSTANCE.prefs

val api: Api
    @Composable get() = OdivoraApp.INSTANCE.api