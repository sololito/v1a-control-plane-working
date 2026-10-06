# ODIVORA mobile app (foundation milestone)

Bare-minimum Android client that proves the control-plane against a real API,
before the WireGuard tunnel is integrated natively. Two-app testing model:
**this app** drives the ODIVORA cloud session, and the **official WireGuard
app** (`com.wireguard.android`, from the Play Store / apk from
wireguard.com) runs the tunnel. We hand it a `.conf` and it imports it.

This is milestone 1 of the plan in `GATEWAY_EVENT_CACHE.md`'s sibling docs —
see `MOBILE_APP_FOUNDATION.md` for the contract the screens implement.

## What works (v0.1.0)

- Server address setting (any HTTP(S) base URL is one endpoint: the app calls
  `<base>/api/v1/...` and opens `ws(s)://<base>/ws/mobile`).
- Register / login / refresh-token rotation (auto-retry once after a 401).
- `GET /me/gateways` → pick a gateway → `POST /connections` (relay path).
- Session screen: status polling (`GET /connections/{id}`, 3 s), live
  `/ws/mobile` message log, `authorize-wg` (server mints a **demo keypair** so
  the whole flow can be tested before real keygen), a hand-editable `.conf`,
  send/copy/share into the WireGuard app, handshake confirm, revoke + close.
- `POST /me/visits` reporting (first-ten audit contract).
- Log out.

## Build

Toolchain used on this machine lives under `.toolchain/` (gitignored;
portable JDK 17 + Android SDK, no root needed). On any machine with Android
Studio, just open `mobile/`:

```bash
# 1. android SDK path (Android Studio sets this automatically):
echo "sdk.dir=/opt/odivora/.toolchain/android-sdk" > local.properties   # adjust
# 2. build the debug apk:
./gradlew :app:assembleDebug
# 3. install on a connected phone/emulator:
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

To reproduce the toolchain from scratch (Linux, no root):

```bash
curl -fsSL -o /tmp/jdk.tgz https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse
mkdir -p .toolchain && tar xzf /tmp/jdk.tgz -C .toolchain
curl -fsSL -o /tmp/clt.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
mkdir -p .toolchain/android-sdk/cmdline-tools && unzip -q /tmp/clt.zip -d .toolchain/android-sdk/cmdline-tools && mv .toolchain/android-sdk/cmdline-tools/cmdline-tools .toolchain/android-sdk/cmdline-tools/latest
export JAVA_HOME=$PWD/.toolchain/jdk-17.* ANDROID_HOME=$PWD/.toolchain/android-sdk
. .toolchain/android-sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root="$ANDROID_HOME" --licenses
. .toolchain/android-sdk/cmdline-tools/latest/bin/sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"
```

The Gradle wrapper (`./gradlew`) is committed, so no separate Gradle install is
needed.

## First run / config

1. Launch → enter the server address:
   - Android emulator + server on this machine: `http://10.0.2.2:8000`
   - Phone on the same Wi-Fi: `http://<machine-LAN-IP>:8000` (server must run
     on `0.0.0.0:8000`, not `127.0.0.1`)
   - Anywhere: your `https://` ngrok URL. **Include the `http://`/`https://`**
     — a bare host is assumed to be HTTPS.
2. Register (password ≥ 10 chars) or log in.
3. Refresh gateways → must be **claimed** and **online** for a session to open
   (`POST /connections` returns `409 gateway offline` otherwise).
4. In the session: *Authorize with demo keys* → the `.conf` appears prefilled
   (demo private key + assigned IP + relay `phone_endpoint`). Edit it if your
   test topologies need a different `Endpoint`/`AllowedIPs`.
5. *Open in WireGuard* imports the profile into the official app → toggle it
   on there → back in ODIVORA tap *Tunnel is up — confirm handshake*.
6. *Report sites* exercises the first-ten audit contract; the WS log shows
   cloud signalling.

## Server side for the full tunnel test

- A claimed gateway with WireGuard configured and a **reachable endpoint**:
  for LAN tests set it to the gateway machine's LAN IP, or use the relay on
  the same box (`relay_public_host` in server `.env`) so `authorize-wg`
  returns a real `phone_endpoint` instead of `<gateway-public-ip>`.
- The full-tunnel `AllowedIPs = 0.0.0.0/0` will route the phone's own cloud
  signalling through the tunnel once connected. That path is the known gap for
  milestone 2 (VpnService + policy-route / pinning), and is why the `.conf` is
  editable — shrink `AllowedIPs` for LAN-only tests.

## Known gaps / roadmap

- [ ] Real keygen on-device (Ed25519/Curve25519 via Android Keystore) instead
      of demo keys.
- [ ] Native tunnel: `VpnService` + WireGuard kernel/userspace lib, dropping
      the two-app model.
- [ ] Keep cloud signalling reachable under a full tunnel (rule 2 in
      `MOBILE_APP_FOUNDATION.md`): policy route or API pinned to the physical
      interface.
- [ ] Encrypt stored tokens (EncryptedSharedPreferences/Keystore) — plain
      SharedPreferences during the logic-test milestone only.
- [ ] Pairing UX for the ESP32 gateway (pairing-code claim flow already works
      server-side).
- [ ] Billing (M-Pesa STK) via `/api/v1/me/billing/mpesa/*`.
- [ ] Release signing + Play internal track once tested.