# 📡 ODIVORA Gateway Claim Guide

## Overview

This guide explains how to claim an ESP32 gateway on the ODIVORA Home Connectivity platform. The claim process registers the gateway to your account and provides a JWT token that enables heartbeats and connection sessions.

### 📋 Prerequisites

- Server running at `http://YOUR_LOCAL_IP:8000` (e.g., `http://192.168.1.191:8000`)
- ESP32 firmware uploaded and running (shows `ODIVORA gateway 1.0.0 boot`)
- Serial Monitor open at **115200 baud**
- Admin user credentials: `admin@example.com` / `Admin12345!`

---

## 🔑 Step-by-Step Claim Process

### Step 1: Get the Gateway ID & Pairing Code

From the ESP32 **Serial Monitor**, you should see:

```
ODIVORA gateway 1.0.0 boot
[GW] WiFi up, IP=192.168.1.59
registered. gateway_id=9f004cfb-6212-4c8d-aaee-d935b5db00f5
>>> PAIRING CODE: 317164  (claim within 15 min, then: TOKEN <jwt>)
```

**Record these values:**

| Value | Example | Where It's Used |
|-------|---------|-----------------|
| **Gateway ID** | `9f004cfb-6212-4c8d-aaee-d935b5db00f5` | API endpoint path |
| **Pairing Code** | `317164` | Claim request body |

*Note: Pairing codes expire in **15 minutes**. If expired, re-register the gateway.*

---

### Step 2: Login to Get Auth Token (via PowerShell or CMD)

You need an auth token to claim the gateway. Use your admin credentials.

#### **Option A: PowerShell (Recommended)**

```powershell
# Login and get access token
$body = '{"email":"admin@example.com","password":"Admin12345!"}'
$resp = Invoke-WebRequest -Uri "http://192.168.1.191:8000/api/v1/auth/login" -Method Post -Body $body -ContentType "application/json"

# Extract the access token from response
$token = ($resp.Content | ConvertFrom-Json).access_token
Write-Host "Your auth token: $token" -ForegroundColor Cyan
```

**Expected output:**
```
Your auth token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzZjgyOGU0OS1kMWZiLTQ0MTItYjU3ZS1iNzExYWFkM2NhMTgiLCJkZXZpY2VfaWQiOiJhNDJhYzQzMS01YjZlLTRlNDAtYjYzZS03MDZkMjkwYzczNjciLCJleHAiOjE3OTA5NjI5MjcsImlhdCI6MTc5MDk2MjAyNywia2luZCI6ImFjY2VzcyIsImp0aSI6ImRlZmU0Y2FmZTI3MzQ0YWE5MjBmOWU2YWNmNzJiNDFhIn0.yC21WIIEouwjJFl1D4LJUZhCMvi6EF819828peppQGI
```

#### **Option B: CMD (Command Prompt)**

```cmd
curl -X POST "http://192.168.1.191:8000/api/v1/auth/login" ^
  -H "Content-Type: application/json" ^
  -d "{\"email\":\"admin@example.com\",\"password\":\"Admin12345!\"}"
```

**Copy the `access_token` value** from the JSON output.

---

### Step 3: Claim the Gateway

Now use the auth token to claim the gateway with the pairing code.

#### **PowerShell Claim Command:**

```powershell
# Replace WITH YOUR VALUES:
$gatewayId = "9f004cfb-6212-4c8d-aaee-d935b5db00f5"
$pairingCode = "317164"
$authToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...(your token here)..."

# Make the claim request
$body = "{`"pairing_code:`"$pairingCode`"}"
$resp = Invoke-WebRequest -Uri "http://192.168.1.191:8000/api/v1/me/gateways/$gatewayId/claim" -Method Post -Body $body -ContentType "application/json" -Headers @{Authorization = "Bearer $authToken"}

# Display result
$result = $resp.Content | ConvertFrom-Json
Write-Host "Claim Status: $($result.ok)" -ForegroundColor Green
Write-Host "Gateway Token: $($result.gateway_token)" -ForegroundColor Yellow
Write-Host "Gateway ID: $($result.gateway_id)" -ForegroundColor Cyan
```

**Expected output:**
```
Claim Status: True
Gateway Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5ZjAwNGNmYi02MjEyLTRjOGQtYWFlZS1kOTM1YjVkYjAwZjUiLCJleHAiOjE3OTA5NjU2NzcsImlhdCI6MTc5MDk2MjA3Nywia2luZCI6ImdhdGV3YXkiLCJqdGkiOiJjOThjZWMwYmI2MWM0OTRjYjNiYWU2Mjk3ZjQ0ODUzNCJ9.3qlVIU19VuGxNrNYNQ1OXIVWm93cd-6zTy02niWfC8I
Gateway ID: 9f004cfb-6212-4c8d-aaee-d935b5db00f5
```

#### **CMD Claim Command:**

```cmd
curl -X POST "http://192.168.1.191:8000/api/v1/me/gateways/9f004cfb-6212-4c8d-aaee-d935b5db00f5/claim" ^
  -H "Content-Type: application/json" ^
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...(your token here)..." ^
  -d "{\"pairing_code\":\"317164\"}"
```

**Copy the `gateway_token`** from the JSON response.

---

### Step 4: Store Token on ESP32

Now store the JWT token on the ESP32 so it can send heartbeats.

**In Arduino IDE Serial Monitor (115200 baud):**

```
TOKEN eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5ZjAwNGNmYi02MjEyLTRjOGQtYWFlZS1kOTM1YjVkYjAwZjUiLCJleHAiOjE3OTA5NjU2NzcsImlhdCI6MTc5MDk2MjA3Nywia2luZCI6ImdhdGV3YXkiLCJqdGkiOiJjOThjZWMwYmI2MWM0OTRjYjNiYWU2Mjk3ZjQ0ODUzNCJ9.3qlVIU19VuGxNrNYNQ1OXIVWm93cd-6zTy02niWfC8I
```

**Press Enter** - you should see:

```
token stored (X chars). Heartbeat starts.
```

*X = number of characters in the JWT token*

---

### Step 5: Verify - Check Status

In Serial Monitor, type:

```
STATUS
```

**Expected output:**

```
gateway_id=9f004cfb-6212-4c8d-aaee-d935b5db00f5 token=set wifi=up
```

**Meaning:**
- `gateway_id`: Your registered gateway identifier
- `token=set`: JWT token is stored and active
- `wifi=up`: WiFi connection is active

---

### Step 6: Watch Heartbeats (Automatic)

After token is stored, the ESP32 automatically sends heartbeats every **60 seconds**. You'll see in the Serial Monitor:

```
heartbeat ok (0000000001)
heartbeat ok (0000000002)
heartbeat ok (0000000003)
...
```

*Every ~5 minutes (after 5 heartbeats), you'll also see:*

```
sessions pending: 0  (or: sessions pending: 2 if phones are connecting)
```

---

### Step 7: Verify in Admin UI

Open your browser and visit:

```
http://192.168.1.191:8000/admin
```

Login with: `admin@example.com` / `Admin12345!`

Go to the **"Gateways"** panel. You should see:

| Field | Expected Value |
|-------|---------------|
| **ID** | `9f004cfb-6212-4c8d-aaee-d935b5db00f5` (first 8 chars) |
| **Status** | `registered` (was `pairing`) |
| **Owner** | Your user ID |
| **Last Seen** | Recent timestamp |

---

## ⚠️ Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `bad pairing code` | Wrong code entered | Use exact code from Serial Monitor registration output |
| `too many pairing attempts` | >5 failed tries | Wait for reset or use `RESET` command in Serial Monitor |
| `gateway not found` | Wrong gateway ID | Use the exact ID from Step 1 |
| `pairing code expired` | >15 minutes since registration | Re-register gateway (Step 1) |
| `heartbeat 401` | Token invalid/revoked | Re-claim gateway (repeat this guide) |
| `cannot connect to server` | Network issue | Ensure ESP32 and server on same WiFi |

---

## 📊 Complete Flow Summary

```
┌─────────────────┐      ┌────────────────────┐
│  ESP32 Serial   │      │  PowerShell/CMD    │
│  Monitor        │      │  (claim command)   │
└─────────────────┘      └────────────────────┘
           │                          │
           │ 1. Shows: gateway_id + │
           │    pairing code        │
           ▼                          ▼
   ┌─────────────────────┐   ┌─────────────────────┐
   │  Step 1: Record IDs │   │  Step 2: Login      │
   └─────────────────────┘   └─────────────────────┘
           │                          │
           │ 2. auth token          │
           ▼                          ▼
   ┌─────────────────────┐   ┌─────────────────────┐
   │  Step 3: Claim GW   │   │  Step 4: Store JWT  │
   │    (API call)       │   │    on ESP32         │
   └─────────────────────┘   └─────────────────────┘
           │                          │
           ▼                          ▼
   ┌─────────────────────┐   ┌─────────────────────┐
   │  Step 5: STATUS     │   │  Step 6: Heartbeats │
   └─────────────────────┘   └─────────────────────┘
           │                          │
           ▼                          ▼
   ┌─────────────────────┐   ┌─────────────────────┐
   │  Step 7: Admin UI   │   │  ✅ Complete!       │
   └─────────────────────┘   └─────────────────────┘
```

---

## 🔄 When to Re-Claim

| Situation | Action |
|-----------|--------|
| Pairing code expired (15 min) | Re-register gateway (go to Step 1) |
| Heartbeat 401 (token invalid) | Re-claim gateway (repeat this guide) |
| ESP32 RESET command used | Re-register automatically on next boot |
| Changing WiFi/network | Re-register with new network info |

---

## 📝 Quick Reference Commands

**PowerShell Full Sequence:**

```powershell
# 1. Login
$body = '{"email":"admin@example.com","password":"Admin12345!"}'
$resp = Invoke-WebRequest -Uri "http://192.168.1.191:8000/api/v1/auth/login" -Method Post -Body $body -ContentType "application/json"
$token = ($resp.Content | ConvertFrom-Json).access_token

# 2. Claim gateway (replace GW_ID and PAIRING_CODE)
$gwId = "9f004cfb-6212-4c8d-aaee-d935b5db00f5"
$pairingCode = "317164"
$body = "{`"pairing_code:`"$pairingCode`"}"
$claim = Invoke-WebRequest -Uri "http://192.168.1.191:8000/api/v1/me/gateways/$gwId/claim" -Method Post -Body $body -ContentType "application/json" -Headers @{Authorization = "Bearer $token"}
$result = $claim.Content | ConvertFrom-Json

# 3. Store token on ESP32 (copy gateway_token from step 2)
Write-Host "Token stored on ESP32 Serial Monitor:"
Write-Host "TOKEN $($result.gateway_token)"

# 4. Verify
Write-Host "In ESP32 Serial Monitor type: STATUS"
```

**CMD Full Sequence:**

```cmd
:: 1. Login
curl -X POST "http://192.168.1.191:8000/api/v1/auth/login" -H "Content-Type: application/json" -d "{\"email\":\"admin@example.com\",\"password\":\"Admin12345!\"}"

:: 2. Claim gateway (copy token from step 1)
curl -X POST "http://192.168.1.191:8000/api/v1/me/gateways/9f004cfb-6212-4c8d-aaee-d935b5db00f5/claim" -H "Content-Type: application/json" -H "Authorization: Bearer EYJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." -d "{\"pairing_code\":\"317164\"}"

:: 3. Store token on ESP32 (copy gateway_token from step 2)
:: In Arduino IDE Serial Monitor: TOKEN eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

:: 4. Verify
:: In ESP32 Serial Monitor: STATUS
```

---

## 🎉 You're Done!

After completing all steps:

- ✅ Gateway is **registered** to your account
- ✅ JWT token is stored on ESP32
- ✅ Heartbeats are flowing every 60 seconds
- ✅ Admin UI shows gateway status: `registered`
- ✅ Ready for connection sessions (Phase 1 development)

**Next:** Explore session creation, configuration fetching, or wait for automatic session polls every ~5 minutes!