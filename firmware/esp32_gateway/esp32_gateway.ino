/*
 * ODIVORA Home Gateway — ESP32 firmware (V1, signalling only)
 *
 * Board: ESP32 DevKit (Arduino-ESP32 core). Libraries: WiFi, HTTPClient,
 * Preferences (built-in) + ArduinoJson (install via Library Manager).
 *
 * V1 behaviour:
 *  1. First boot: generate an Ed25519 keypair in NVS, POST /gateways/register
 *     with the public key, print the pairing code on Serial. Claim it within
 *     15 min from your phone/laptop.
 *  2. You claim via API, paste the gateway_token over Serial:  TOKEN <jwt>
 *  3. Loop: heartbeat every 60 s (Bearer token + zero-padded monotonic nonce),
 *     fetch configuration, poll session inbox every ~5 min. Outbound HTTPS
 *     only — no port forwarding.
 *
 * Token lifetime: the Cloud issues gateway tokens that expire
 * (GATEWAY_TOKEN_EXPIRE_MINUTES, 60 by default). The device therefore mints
 * its own replacements: on a 401 it runs the Ed25519 challenge/response
 * (POST /gateways/{id}/nonce then /auth/verify) and stores the new token. The
 * private key never leaves the device — only a signature does. Without this an
 * unattended gateway would wedge 401 an hour after provisioning and would need
 * a human at the Serial console to recover.
 *
 * Serial commands (115200 baud):
 *   STATUS            show stored gateway_id / token / identity / wifi state
 *   TOKEN <jwt>       store gateway token (after you claim the gateway)
 *   WIFI <ssid> <pass>  store WiFi credentials (never hardcoded in this file)
 *   SERVER <url>      point the firmware at your Cloud (e.g. https://api.x.com)
 *   RESET             wipe stored credentials (re-register on reboot)
 *
 * Credentials are entered over Serial and kept in NVS, not in this source.
 * Home WiFi passwords and internal server URLs used to live here as literals,
 * which put a real network password in version control.
 *
 * Build note: the Ed25519 calls below are mbedTLS, which the Arduino-ESP32
 * core already links. `mbedtls_ed25519_keypair` is the keypair global that
 * gen_key() fills; if a future core hides it, that one line is what to change.
 */
#include <WiFi.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <base64.h>
#include <esp_system.h>
#include <mbedtls/ed25519.h>
#include <mbedtls/md.h>

#define FIRMWARE_VERSION "1.1.0"
#define HEARTBEAT_MS 60000UL

// Every HTTPClient MUST get an explicit timeout. Without one, a stalled TCP
// connect or a half-open uplink blocks loop() forever, so heartbeats stop and
// the Cloud eventually marks the gateway offline.
#define HTTP_TIMEOUT_MS 8000
#define WIFI_CONNECT_WAIT_MS 15000UL
#define WIFI_MIN_BACKOFF_MS 1000UL
#define WIFI_MAX_BACKOFF_MS 60000UL

// Ed25519 sizes are fixed by the curve: 32-byte public key, 32-byte seed.
// mbedTLS wants the expanded 64-byte private key (seed || public) for signing.
#define ED_PUB_LEN 32
#define ED_PRIV_LEN 64
#define ED_SIG_LEN 64

// Leave these empty: supply them over Serial (WIFI / SERVER) so nothing
// sensitive is baked into the binary or committed to the repo.
const char* WIFI_SSID_DEFAULT = "";
const char* WIFI_PASS_DEFAULT = "";
const char* SERVER_DEFAULT = "";

// WiFi.begin() takes `const char*`, so NVS values are staged here. Holding the
// password in a fixed buffer is fine: it is device-local and already in flash.
char WIFI_SSID_RAM[33] = {0};
char WIFI_PASS_RAM[65] = {0};

// Device identity. The private key stays in NVS and never leaves the flash;
// identityReady says whether a usable keypair is loaded this boot.
uint8_t edPub[ED_PUB_LEN] = {0};
uint8_t edPriv[ED_PRIV_LEN] = {0};
bool identityReady = false;

Preferences prefs;
String gatewayId = "";
String gatewayToken = "";
String server = "";
unsigned long lastBeat = 0;
unsigned long beatCount = 0;
unsigned long nonceCtr = 0;
unsigned long lastWifiAttempt = 0;
unsigned long wifiBackoffMs = WIFI_MIN_BACKOFF_MS;
int wifiFailures = 0;

void log(const String& m) { Serial.println("[GW] " + m); }

// Returns true when the uplink is usable. Backs off exponentially with
// jitter between attempts so a fleet of devices does not retry in lockstep,
// and never blocks longer than WIFI_CONNECT_WAIT_MS.
bool connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    wifiFailures = 0;
    wifiBackoffMs = WIFI_MIN_BACKOFF_MS;
    return true;
  }
  unsigned long now = millis();
  if (wifiFailures > 0 && (now - lastWifiAttempt) < wifiBackoffMs) return false;
  lastWifiAttempt = now;

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID_RAM, WIFI_PASS_RAM);
  Serial.print("[GW] WiFi connecting");
  unsigned long t0 = now;
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < WIFI_CONNECT_WAIT_MS) {
    delay(500); Serial.print(".");
  }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    wifiFailures = 0;
    wifiBackoffMs = WIFI_MIN_BACKOFF_MS;
    log("WiFi up, IP=" + WiFi.localIP().toString());
    return true;
  }

  wifiFailures++;
  // Equal jitter: back off, but spread retries so neighbours on the same
  // AP are not all retrying on the same millisecond.
  unsigned long grown = WiFi.min(WIFI_MAX_BACKOFF_MS, wifiBackoffMs * 2);
  wifiBackoffMs = grown - grown / 4 + random(grown / 4);
  log("WiFi FAILED — next attempt in " + String(wifiBackoffMs) + "ms");
  return false;
}

String apiBase() { return server; }

// --- device identity (Ed25519) -------------------------------------------
//
// The Cloud signs nothing and trusts no client-held secret: it hands out a
// random nonce and the device proves it holds the private half by signing it.
// That is what makes unattended token refresh possible.

int edRng(void* ctx, unsigned char* out, size_t len) {
  (void)ctx;
  // Hardware RNG. Only key generation needs randomness — Ed25519 *signing* is
  // deterministic, so no RNG is involved once the key exists.
  esp_fill_random(out, len);
  return 0;   // mbedTLS treats 0 as success
}

const mbedtls_md_info_t* edMd() {
  return mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
}

// Load the stored keypair, generating one on first boot. Returns false only if
// the device cannot produce usable crypto, which is not recoverable by retry.
bool loadIdentity() {
  size_t n = prefs.getBytesLength("ed_priv");
  if (n == ED_PRIV_LEN) {
    prefs.getBytes("ed_priv", edPriv, ED_PRIV_LEN);
    // The expanded private key carries its own public half in the last 32
    // bytes, so recovering the public key needs no RNG and no extra storage.
    memcpy(edPub, edPriv + 32, ED_PUB_LEN);
    identityReady = true;
    return true;
  }

  log("no Ed25519 key in NVS — generating one");
  if (mbedtls_ed25519_gen_key(edMd(), edRng, nullptr) != 0) {
    log("Ed25519 key generation FAILED");
    return false;
  }
  // gen_key() fills the mbedTLS keypair global; copy the halves out so nothing
  // depends on that global staying put between calls.
  if (mbedtls_ed25519_get_pubkey(&mbedtls_ed25519_keypair, edPub) != 0 ||
      mbedtls_ed25519_get_privkey(&mbedtls_ed25519_keypair, edPriv) != 0) {
    log("Ed25519 key extraction FAILED");
    return false;
  }
  prefs.putBytes("ed_priv", edPriv, ED_PRIV_LEN);
  identityReady = true;
  log("Ed25519 identity created");
  return true;
}

// Base64 of the raw 32-byte public key. The Cloud accepts this form directly
// (app/gateway_crypto.py) and derives the fingerprint from it.
String publicKeyB64() {
  if (!identityReady) return "";
  return base64::encode(edPub, ED_PUB_LEN);
}

// Sign the nonce bytes exactly as received. The server hashes nothing: it
// verifies Ed25519(nonce.encode()), so the signature must cover these raw
// UTF-8 bytes and nothing else.
String signNonce(const String& nonce) {
  uint8_t r[32], s[32];
  if (!identityReady) return "";
  if (mbedtls_ed25519_sign(edMd(), r, s,
                           (const unsigned char*)nonce.c_str(),
                           nonce.length(), edPriv) != 0) {
    log("Ed25519 signing FAILED");
    return "";
  }
  uint8_t sig[ED_SIG_LEN];
  memcpy(sig, r, 32);
  memcpy(sig + 32, s, 32);
  return base64::encode(sig, ED_SIG_LEN);
}

bool doRegister() {
  HTTPClient http;
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.begin(apiBase() + "/api/v1/gateways/register");
  http.addHeader("Content-Type", "application/json");
  JsonDocument d;
  d["device_type"] = "esp32";
  d["public_key"] = publicKeyB64();
  d["algorithm"] = "ed25519";
  d["firmware_version"] = FIRMWARE_VERSION;
  String body; serializeJson(d, body);
  int code = http.POST(body);
  String res = http.getString();
  http.end();
  if (code != 200) { log("register HTTP " + String(code) + " " + res); return false; }
  JsonDocument r;   // NOLINT
  if (deserializeJson(r, res)) { log("register: bad JSON"); return false; }
  gatewayId = r["gateway_id"].as<String>();
  String pairing = r["pairing_code"].as<String>();
  prefs.putString("gw_id", gatewayId);
  log("registered. gateway_id=" + gatewayId);
  log(">>> PAIRING CODE: " + pairing + "  (claim within 15 min, then: TOKEN <jwt>)");
  return true;
}

// Mint a fresh gateway token with the Ed25519 challenge/response.
// POST /gateways/{id}/nonce    -> random nonce
// sign it, POST /gateways/{id}/auth/verify -> new bearer token
bool refreshGatewayToken() {
  if (!identityReady) {
    log("token refresh: no Ed25519 identity — cannot self-heal");
    return false;
  }
  if (gatewayId.length() == 0) return false;

  HTTPClient http;
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.begin(apiBase() + "/api/v1/gateways/" + gatewayId + "/nonce");
  http.addHeader("Content-Type", "application/json");
  int code = http.POST("{}");
  String res = http.getString();
  http.end();
  // 0 means no answer at all — worth another try. Any real HTTP status is
  // authoritative and repeating it would only burn the nonce.
  if (code == 0) { log("token refresh: cloud unreachable"); return false; }
  if (code != 200) { log("token refresh: nonce HTTP " + String(code) + " " + res); return false; }

  JsonDocument n;
  if (deserializeJson(n, res)) { log("token refresh: bad nonce JSON"); return false; }
  String nonce = n["nonce"].as<String>();
  String sig = signNonce(nonce);
  if (sig.length() == 0) return false;

  http.begin(apiBase() + "/api/v1/gateways/" + gatewayId + "/auth/verify");
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.addHeader("Content-Type", "application/json");
  JsonDocument v;
  v["nonce"] = nonce;
  v["signature"] = sig;
  String vbody; serializeJson(v, vbody);
  code = http.POST(vbody);
  res = http.getString();
  http.end();
  if (code != 200) { log("token refresh: verify HTTP " + String(code) + " " + res); return false; }

  JsonDocument r;
  if (deserializeJson(r, res)) { log("token refresh: bad verify JSON"); return false; }
  String fresh = r["gateway_token"].as<String>();
  if (fresh.length() == 0) { log("token refresh: no token in response"); return false; }
  gatewayToken = fresh;
  prefs.putString("gw_tok", gatewayToken);
  log("token refreshed (expiry is server-side; will refresh again)");
  return true;
}

bool doHeartbeat() {
  if (gatewayToken.length() == 0) {
    log("no token yet — claim the gateway, then send:  TOKEN <jwt>");
    return false;
  }
  nonceCtr++;
  char nonceBuf[12];
  snprintf(nonceBuf, sizeof(nonceBuf), "%010lu", nonceCtr);  // zero-padded: sorts = counts
  HTTPClient http;
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.begin(apiBase() + "/api/v1/gateways/heartbeat");
  http.addHeader("Content-Type", "application/json");
  http.addHeader("Authorization", "Bearer " + gatewayToken);
  JsonDocument d;
  d["firmware_version"] = FIRMWARE_VERSION;
  d["nonce"] = String(nonceBuf);
  JsonObject health = d["health"].to<JsonObject>();
  health["heap"] = ESP.getFreeHeap();
  health["rssi"] = WiFi.RSSI();
  String body; serializeJson(d, body);
  int code = http.POST(body);
  String res = http.getString();
  http.end();

  if (code == 401) {
    // Almost always expiry, not revocation: mint a new token and retry once.
    // A revoked gateway fails the refresh too, which is how we tell them apart.
    log("heartbeat 401: token expired — refreshing via Ed25519 challenge");
    if (refreshGatewayToken()) {
      http.begin(apiBase() + "/api/v1/gateways/heartbeat");
      http.setTimeout(HTTP_TIMEOUT_MS);
      http.addHeader("Content-Type", "application/json");
      http.addHeader("Authorization", "Bearer " + gatewayToken);
      d["health"] = health;
      String retryBody; serializeJson(d, retryBody);
      code = http.POST(retryBody);
      res = http.getString();
      http.end();
      if (code == 200) { log("heartbeat ok after refresh (" + String(nonceBuf) + ")"); return true; }
    }
    log("token rejected and refresh failed — gateway may be revoked; "
        "re-claim it or run RESET to register again");
    return false;
  }
  if (code == 409) { log("heartbeat: stale nonce — reboot resyncs server-side, continuing"); return true; }
  if (code != 200) { log("heartbeat HTTP " + String(code) + " " + res); return false; }
  log("heartbeat ok (" + String(nonceBuf) + ")");
  return true;
}

void doFetchConfig() {
  if (gatewayId.length() == 0 || gatewayToken.length() == 0) return;
  HTTPClient http;
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.begin(apiBase() + "/api/v1/gateways/" + gatewayId + "/configuration");
  http.addHeader("Authorization", "Bearer " + gatewayToken);
  int code = http.GET();
  if (code == 200) {
    JsonDocument r;
    if (!deserializeJson(r, http.getString())) {
      log("config: tunnel=" + r["tunnel"]["provider"].as<String>() +
          " relay=" + r["relay"]["mode"].as<String>());
    }
  }
  http.end();
}

// Inbox poll: list sessions the cloud recorded for this gateway and log them.
// (Proves a phone outside the home reached the cloud for THIS device.)
// Full auto-verify needs the phone's session_token, which only the phone
// holds in V1 — that check runs phone-side or via Serial paste until the
// data-plane hands the device its own token copy.
void doPollSessions() {
  if (gatewayId.length() == 0 || gatewayToken.length() == 0) return;
  HTTPClient http;
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.begin(apiBase() + "/api/v1/gateways/" + gatewayId + "/sessions");
  http.addHeader("Authorization", "Bearer " + gatewayToken);
  int code = http.GET();
  String res = http.getString();
  http.end();
  if (code != 200) { log("sessions poll HTTP " + String(code)); return; }
  JsonDocument r;
  if (deserializeJson(r, res)) return;
  JsonArray arr = r.as<JsonArray>();
  if (arr.size() == 0) return;
  log("sessions pending: " + String(arr.size()));
  for (JsonObject s : arr) {
    log(" - " + s["id"].as<String>().substring(0, 8) + " status=" + s["status"].as<String>());
  }
}

void handleSerial() {
  if (!Serial.available()) return;
  String line = Serial.readStringUntil('\n'); line.trim();
  if (line.startsWith("TOKEN ")) {
    gatewayToken = line.substring(6); gatewayToken.trim();
    prefs.putString("gw_tok", gatewayToken);
    log("token stored (" + String(gatewayToken.length()) + " chars). Heartbeat starts.");
  } else if (line.startsWith("WIFI ")) {
    int sp = line.indexOf(' ', 5);
    if (sp < 0) { log("usage: WIFI <ssid> <pass>"); return; }
    prefs.putString("ssid", line.substring(5, sp));
    prefs.putString("pass", line.substring(sp + 1));
    log("WiFi credentials stored — rebooting to apply");
    delay(200);
    ESP.restart();
  } else if (line.startsWith("SERVER ")) {
    server = line.substring(7); server.trim();
    while (server.endsWith("/")) server.remove(server.length() - 1);
    prefs.putString("server", server);
    log("server=" + server);
  } else if (line == "STATUS") {
    log("gateway_id=" + (gatewayId.length() ? gatewayId : "(none)") +
        " token=" + (gatewayToken.length() ? "set" : "(none)") +
        " identity=" + (identityReady ? "ed25519" : "(none)") +
        " server=" + (server.length() ? server : "(none)") +
        " wifi=" + String(WiFi.status() == WL_CONNECTED ? "up" : "down") +
        " wifi_backoff=" + String(wifiBackoffMs) + "ms");
  } else if (line == "RESET") {
    // Wipe registration + link config so the next boot re-registers. The
    // Ed25519 key is deliberately kept: the same identity re-registering is
    // the normal case, and throwing away the private half would need a new
    // pairing round for no benefit.
    prefs.remove("gw_id");
    prefs.remove("gw_tok");
    prefs.remove("server");
    prefs.remove("ssid");
    prefs.remove("pass");
    gatewayId = ""; gatewayToken = ""; server = "";
    nonceCtr = 0;
    memset(WIFI_SSID_RAM, 0, sizeof(WIFI_SSID_RAM));
    memset(WIFI_PASS_RAM, 0, sizeof(WIFI_PASS_RAM));
    log("wiped — reboot, then re-send SERVER and WIFI before registering again.");
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);
  prefs.begin("odivora", false);
  gatewayId = prefs.getString("gw_id", "");
  gatewayToken = prefs.getString("gw_tok", "");
  server = prefs.getString("server", SERVER_DEFAULT);
  while (server.endsWith("/")) server.remove(server.length() - 1);
  // Copy NVS into the RAM slots WiFi.begin() reads. Editing the defaults in
  // this file is still supported for bench builds; Serial is the normal path.
  // Keep the Strings alive: Preferences::getString returns by value, so
  // calling .c_str() on the temporary would leave a dangling pointer.
  String ssid = prefs.getString("ssid", WIFI_SSID_DEFAULT);
  String pass = prefs.getString("pass", WIFI_PASS_DEFAULT);
  strlcpy(WIFI_SSID_RAM, ssid.c_str(), sizeof(WIFI_SSID_RAM));
  strlcpy(WIFI_PASS_RAM, pass.c_str(), sizeof(WIFI_PASS_RAM));

  log("ODIVORA gateway " + String(FIRMWARE_VERSION) + " boot");
  if (server.length() == 0) {
    log("No server URL configured. Send:  SERVER https://your-cloud.example.com");
  }
  if (strlen((const char*)WIFI_SSID_RAM) == 0) {
    log("No WiFi credentials. Send:  WIFI <ssid> <pass>   (then reboot)");
  }
  if (!loadIdentity()) {
    log("FATAL: cannot create Ed25519 identity; rebooting in 10s");
    delay(10000);
    ESP.restart();
    return;
  }
  connectWiFi();
  if (gatewayId.length() == 0) {
    if (server.length() == 0) { log("waiting for SERVER config before registering"); return; }
    if (!doRegister()) log("register failed — will retry (RESET to clear, check SERVER/WiFi)");
  } else {
    log("stored gateway_id=" + gatewayId);
    if (gatewayToken.length() == 0) log("waiting for claim. Run claim API, then: TOKEN <jwt>");
  }
}

void loop() {
  handleSerial();
  if (!connectWiFi()) { delay(200); return; }   // backoff gates the retries
  if (server.length() == 0) { delay(1000); return; }
  if (gatewayId.length() == 0) {
    static unsigned long lastTry = 0;
    if (millis() - lastTry > 15000) { lastTry = millis(); doRegister(); }
    delay(1000); return;
  }
  if (millis() - lastBeat > HEARTBEAT_MS || lastBeat == 0) {
    lastBeat = millis();
    beatCount++;
    if (doHeartbeat()) {
      doFetchConfig();
      if (beatCount % 5 == 0) doPollSessions();  // inbox check every ~5 min
    }
  }
  delay(200);
}
