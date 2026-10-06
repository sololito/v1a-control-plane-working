package com.odivora.app.net

object WgConfig {

    fun defaultEndpoint(auth: WgAuth): String {
        auth.relay?.optString("phone_endpoint")?.takeIf { it.isNotBlank() }?.let { return it }
        return "<gateway-public-ip>:${auth.listenPort}"
    }

    fun build(
        gatewayPublicKey: String,
        privateKey: String,
        address: String,
        endpoint: String,
        allowedIps: String,
        dns: String,
    ): String = """
        [Interface]
        PrivateKey = $privateKey
        Address = $address
        DNS = $dns

        [Peer]
        PublicKey = $gatewayPublicKey
        Endpoint = $endpoint
        AllowedIPs = $allowedIps
        PersistentKeepalive = 25
    """.trimIndent()
}