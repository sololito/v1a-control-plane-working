package com.odivora.app.store

import android.content.Context
import android.content.SharedPreferences

class Prefs(context: Context) {
    private val sp: SharedPreferences =
        context.applicationContext.getSharedPreferences("odivora", Context.MODE_PRIVATE)

    var baseUrl: String
        get() = prefsString("base_url") ?: DEFAULT_BASE_URL
        set(v) = sp.edit().putString("base_url", v).apply()

    var accessToken: String?
        get() = prefsString("access_token")
        set(v) = sp.edit().putString("access_token", v).apply()

    var refreshToken: String?
        get() = prefsString("refresh_token")
        set(v) = sp.edit().putString("refresh_token", v).apply()

    var deviceId: String
        get() = prefsString("device_id") ?: ""
        set(v) = sp.edit().putString("device_id", v).apply()

    var userId: String
        get() = prefsString("user_id") ?: ""
        set(v) = sp.edit().putString("user_id", v).apply()

    var email: String
        get() = prefsString("email") ?: ""
        set(v) = sp.edit().putString("email", v).apply()

    val hasSession: Boolean
        get() = !accessToken.isNullOrEmpty() && !refreshToken.isNullOrEmpty()

    fun clear() {
        sp.edit()
            .remove("access_token").remove("refresh_token")
            .remove("device_id").remove("user_id")
            .apply()
    }

    private fun prefsString(key: String): String? = sp.getString(key, null)

    companion object {
        const val DEFAULT_BASE_URL = "https://image-valley-sealed-donald.trycloudflare.com"

        fun normalize(url: String): String {
            var u = url.trim().trimEnd('/')
            if (!u.startsWith("http")) u = "https://$u"
            return u
        }
    }
}