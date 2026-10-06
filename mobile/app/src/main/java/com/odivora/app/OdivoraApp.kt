package com.odivora.app

import android.app.Application
import com.odivora.app.net.Api
import com.odivora.app.store.Prefs

class OdivoraApp : Application() {
    lateinit var prefs: Prefs
        private set
    lateinit var api: Api
        private set

    override fun onCreate() {
        super.onCreate()
        INSTANCE = this
        prefs = Prefs(this)
        api = Api(prefs)
    }

    companion object {
        lateinit var INSTANCE: OdivoraApp
            private set
    }
}