/*
 * ODIVORA Home Gateway — ESP32 firmware (V1, signalling only)
 *
 * Board: ESP32 DevKit (Arduino-ESP32 core). Libraries: WiFi, HTTPClient,
 * Preferences (built-in) + ArduinoJson (install via Library Manager).
 *
 * V1 behaviour:
 *  1. First boot: POST /gateways/register -> stores gateway_id, prints
 *     pairing code on Serial (claim it within 15 min from your phone/laptop).
 *  2. You claim via API, paste the gateway_token over Serial:  TOKEN <jwt>
 *  3. Loop: heartbeat every 60 s (Bearer token + zero-padded monotonic nonce),
 *     fetch configuration, poll session inbox every ~5 min. Outbound HTTPS
 *     only — no port forwarding.
 *
 * Serial commands (115200 baud):
 *   STATUS            show stored gateway_id / token state
 *   TOKEN <jwt>       store gateway token (after you claim the gateway)
 *   RESET             wipe stored credentials (re-register on reboot)
 *
 * Config: edit WIFI_SSID / WIFI_PASS / SERVER below before flashing.
 */
#include <WiFi.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <ArduinoJson.h>

#define FIRMWARE_VERSION "1.0.0"
#define HEARTBEAT_MS 60000UL

// ---- EDIT THESE ----
const char* WIFI_SSID = "Eng. Solo";
const char* WIFI_PASS = "Bolting@2025";
// Public server URL (sandbox/ngrok or your domain). Must be reachable from home.
// Example: "http://192.168.1.50:8000" (local test) or "https://api.example.com"
const char* SERVER = "http://192.168.1.191:8000";
// --------------------

Preferences prefs;
String gatewayId = "";
String gatewayToken = "";
unsigned long lastBeat = 0;
unsigned long beatCount = 0;
unsigned long nonceCtr = 0;

void log(const String& m) { Serial.println("[GW] " + m); }

void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("[GW] WiFi connecting");
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) {
    delay(500); Serial.print(".");
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) log("WiFi up, IP=" + WiFi.localIP().toString());
  else log("WiFi FAILED — retrying in loop");
}

String devicePublicKey() {
  // V1 bearer flow needs any stable string >= 16 chars. Real Ed25519 key
  // replaces this when the crypto path is enabled (see root doc).
  uint64_t chip = ESP.getEfuseMac();
  char buf[48];
  snprintf(buf, sizeof(buf), "esp32-pubkey-%012llX-0123456789", chip);
  return String(buf);
}

bool doRegister() {
  HTTPClient http;
  http.begin(String(SERVER) + "/api/v1/gateways/register");
  http.addHeader("Content-Type", "application/json");
  JsonDocument d;
  d["device_type"] = "esp32";
  d["public_key"] = devicePublicKey();
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

bool doHeartbeat() {
  if (gatewayToken.length() == 0) {
    log("no token yet — claim the gateway, then send:  TOKEN <jwt>");
    return false;
  }
  nonceCtr++;
  char nonceBuf[12];
  snprintf(nonceBuf, sizeof(nonceBuf), "%010lu", nonceCtr);  // zero-padded: sorts = counts
  HTTPClient http;
  http.begin(String(SERVER) + "/api/v1/gateways/heartbeat");
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
  if (code == 409) { log("heartbeat: stale nonce — reboot resyncs server-side, continuing"); return true; }
  if (code == 401) { log("heartbeat 401: token invalid/revoked — re-claim, then TOKEN <new jwt>"); return false; }
  if (code != 200) { log("heartbeat HTTP " + String(code) + " " + res); return false; }
  log("heartbeat ok (" + String(nonceBuf) + ")");
  return true;
}

void doFetchConfig() {
  if (gatewayId.length() == 0 || gatewayToken.length() == 0) return;
  HTTPClient http;
  http.begin(String(SERVER) + "/api/v1/gateways/" + gatewayId + "/configuration");
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
  http.begin(String(SERVER) + "/api/v1/gateways/" + gatewayId + "/sessions");
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
  } else if (line == "STATUS") {
    log("gateway_id=" + (gatewayId.length() ? gatewayId : "(none)") +
        " token=" + (gatewayToken.length() ? "set" : "(none)") +
        " wifi=" + String(WiFi.status() == WL_CONNECTED ? "up" : "down"));
  } else if (line == "RESET") {
    prefs.clear();
    gatewayId = ""; gatewayToken = ""; nonceCtr = 0;
    log("credentials wiped — reboot to re-register.");
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);
  prefs.begin("odivora", false);
  gatewayId = prefs.getString("gw_id", "");
  gatewayToken = prefs.getString("gw_tok", "");
  log("ODIVORA gateway " + String(FIRMWARE_VERSION) + " boot");
  connectWiFi();
  if (gatewayId.length() == 0) {
    if (!doRegister()) log("register failed — will retry (RESET to clear, check SERVER/WiFi)");
  } else {
    log("stored gateway_id=" + gatewayId);
    if (gatewayToken.length() == 0) log("waiting for claim. Run claim API, then: TOKEN <jwt>");
  }
}

void loop() {
  handleSerial();
  connectWiFi();
  if (WiFi.status() != WL_CONNECTED) { delay(2000); return; }
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
