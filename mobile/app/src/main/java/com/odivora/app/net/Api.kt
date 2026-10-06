package com.odivora.app.net

import com.odivora.app.store.Prefs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class ApiException(val code: Int, message: String) : Exception(message)
class AuthException(message: String) : Exception(message)

class Gateway(
    val id: String,
    val deviceType: String,
    val firmwareVersion: String?,
    val status: String,
    val lastSeen: String?,
)

class SessionCreated(
    val id: String,
    val status: String,
    val connectionPath: String,
    val sessionToken: String,
    val tunnel: String?,
)

class SessionStatus(
    val id: String,
    val status: String,
    val connectionPath: String,
    val disconnectReason: String?,
)

class WgAuth(
    val assignedIp: String,
    val gatewayPublicKey: String,
    val listenPort: Int,
    val gatewayTunnelIp: String,
    val tunnelSubnet: String,
    val connectionPath: String,
    val clientPrivateKey: String?,
    val relay: JSONObject?,
)

class VisitsOut(
    val stored: Int,
    val total: Int,
    val limit: Int,
    val sites: List<String>,
    val ignored: List<JSONObject>,
)

class Api(private val prefs: Prefs) {

    private val client = OkHttpClient.Builder()
        .connectTimeout(12, TimeUnit.SECONDS)
        .readTimeout(25, TimeUnit.SECONDS)
        .writeTimeout(25, TimeUnit.SECONDS)
        .build()

    fun apiUrl(path: String): String = prefs.baseUrl.trimEnd('/') + "/api/v1/$path"

    fun wsUrl(): String =
        prefs.baseUrl.trimEnd('/').replaceFirst("http", "ws") + "/ws/mobile?token=" +
            (prefs.accessToken ?: "")

    suspend fun register(email: String, password: String, deviceName: String) {
        val body = JSONObject()
            .put("email", email).put("password", password).put("device_name", deviceName)
            .toString()
        acceptTokens(postJson("auth/register", body))
    }

    suspend fun login(email: String, password: String, deviceName: String) {
        val body = JSONObject()
            .put("email", email).put("password", password).put("device_name", deviceName)
            .toString()
        acceptTokens(postJson("auth/login", body))
    }

    suspend fun logout() {
        try {
            call("auth/logout", "POST", "{}", authed = true)
        } catch (_: ApiException) {
        }
        prefs.clear()
    }

    suspend fun gateways(): List<Gateway> {
        val res = JSONArray(parseObject(call("me/gateways", "GET", null, authed = true)))
        return (0 until res.length()).map { i ->
            val o = res.getJSONObject(i)
            Gateway(
                id = o.getString("id"),
                deviceType = o.optString("device_type", "—"),
                firmwareVersion = o.optString("firmware_version", null),
                status = o.optString("status", "—"),
                lastSeen = o.optString("last_seen", null),
            )
        }
    }

    suspend fun openSession(gatewayId: String, path: String = "relay"): SessionCreated {
        val body = JSONObject()
            .put("gateway_id", gatewayId).put("connection_path", path).toString()
        val o = parseObject(call("connections", "POST", body, authed = true))
        return SessionCreated(
            id = o.getString("id"),
            status = o.optString("status", "authorized"),
            connectionPath = o.optString("connection_path", ""),
            sessionToken = o.optString("session_token", ""),
            tunnel = o.optString("tunnel", null),
        )
    }

    suspend fun sessionStatus(sessionId: String): SessionStatus {
        val o = parseObject(call("connections/$sessionId", "GET", null, authed = true))
        return SessionStatus(
            id = o.getString("id"),
            status = o.optString("status", ""),
            connectionPath = o.optString("connection_path", ""),
            disconnectReason = o.optString("disconnect_reason", null),
        )
    }

    suspend fun closeSession(sessionId: String, reason: String = "app_closed") {
        call("connections/$sessionId", "PATCH", JSONObject()
            .put("status", "disconnected").put("reason", reason).toString(), authed = true)
    }

    suspend fun authorizeWg(sessionId: String): WgAuth {
        val o = parseObject(call("sessions/$sessionId/authorize-wg", "POST", "{}", authed = true))
        return WgAuth(
            assignedIp = o.optString("assigned_ip", ""),
            gatewayPublicKey = o.optString("gateway_public_key", ""),
            listenPort = o.optInt("listen_port", 0),
            gatewayTunnelIp = o.optString("gateway_tunnel_ip", ""),
            tunnelSubnet = o.optString("tunnel_subnet", ""),
            connectionPath = o.optString("connection_path", ""),
            clientPrivateKey = o.optString("client_private_key", null),
            relay = o.optJSONObject("relay"),
        )
    }

    suspend fun serverWgConfig(sessionId: String): Pair<String, String> {
        val o = parseObject(call("sessions/$sessionId/wg-config", "GET", null, authed = true))
        return o.optString("filename", "odivora.conf") to o.optString("config", "")
    }

    suspend fun handshake(sessionId: String) {
        call("sessions/$sessionId/handshake", "POST", "{}", authed = true)
    }

    suspend fun revokeWg(sessionId: String) {
        call("sessions/$sessionId/revoke-wg", "POST", "{}", authed = true)
    }

    suspend fun visits(sessionId: String, sites: List<String>): VisitsOut {
        val arr = JSONArray()
        sites.forEach { arr.put(it) }
        val body = JSONObject().put("session_id", sessionId).put("sites", arr).toString()
        val o = parseObject(call("me/visits", "POST", body, authed = true))
        return VisitsOut(
            stored = o.optInt("stored", 0),
            total = o.optInt("total", 0),
            limit = o.optInt("limit", 10),
            sites = o.optJSONArray("sites")?.let { j ->
                (0 until j.length()).map { j.getString(it) }
            } ?: emptyList(),
            ignored = o.optJSONArray("ignored")?.let { j ->
                (0 until j.length()).map { j.getJSONObject(it) }
            } ?: emptyList(),
        )
    }

    fun openWs(onMessage: (String) -> Unit): WebSocket? {
        val req = Request.Builder().url(wsUrl()).build()
        return client.newWebSocket(req, object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, text: String) {
                onMessage(text)
            }
        })
    }

    private fun acceptTokens(o: JSONObject) {
        prefs.accessToken = o.getString("access_token")
        prefs.refreshToken = o.getString("refresh_token")
        prefs.deviceId = o.getString("device_id")
        prefs.userId = o.getString("user_id")
        prefs.email = ""
    }

    private suspend fun postJson(path: String, body: String): JSONObject {
        val res = call(path, "POST", body, authed = false)
        val text = (res as? String) ?: "{}"
        return parseObject(text)
    }

    private suspend fun call(
        path: String,
        method: String,
        body: String?,
        authed: Boolean,
    ): String = withContext(Dispatchers.IO) {
        var resp = execute(path, method, body, token = if (authed) prefs.accessToken else null)
        if (authed && resp.first == 401 && refreshNow()) {
            resp = execute(path, method, body, token = prefs.accessToken)
        }
        if (resp.first !in 200..299) {
            throw ApiException(resp.first, extractDetail(resp.second))
        }
        resp.second
    }

    @Volatile
    private var refreshing = false

    private suspend fun refreshNow(): Boolean = withContext(Dispatchers.IO) {
        synchronized(this) {
            if (!refreshing) {
                refreshing = true
                try {
                    val rt = prefs.refreshToken
                    if (rt == null) {
                        prefs.clear()
                    } else {
                        val body = JSONObject().put("refresh_token", rt).toString()
                        val (code, raw) = execute("auth/refresh", "POST", body, token = null)
                        if (code in 200..299) {
                            acceptTokens(parseObject(raw))
                        } else {
                            prefs.clear()
                        }
                    }
                } catch (_: Exception) {
                    prefs.clear()
                } finally {
                    refreshing = false
                }
            }
        }
        prefs.accessToken != null
    }

    private fun execute(path: String, method: String, body: String?, token: String?): Pair<Int, String> {
        val b = Request.Builder().url(apiUrl(path))
        if (token != null) b.header("Authorization", "Bearer $token")
        if (body != null) {
            b.method(method, body.toRequestBody("application/json".toMediaTypeOrNull()))
        } else {
            b.method(method, null)
        }
        client.newCall(b.build()).execute().use { r ->
            return r.code to (r.body?.string() ?: "")
        }
    }

    private fun extractDetail(raw: String): String {
        return try {
            val o = JSONObject(raw)
            val d = o.opt("detail")
            when (d) {
                is JSONArray -> (0 until d.length()).joinToString("; ") {
                    val item = d.getJSONObject(it)
                    item.optString("msg", item.toString())
                }
                else -> o.optString("detail", o.optString("message", raw))
            }
        } catch (_: Exception) {
            raw
        }
    }

    private fun parseObject(raw: String): JSONObject = JSONObject(raw)
}