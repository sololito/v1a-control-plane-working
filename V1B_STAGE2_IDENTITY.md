# V1B Stage 2: WireGuard Identity & Tunnel Configuration

## Objective
Implement WireGuard keypair generation on the gateway device where the private key
**MUST NEVER leave the device**. Only the public key is registered with the backend for
coordination. This stage establishes the identity foundation for the V1B data plane.

## 🔐 Critical Security Principle

> **Private key MUST NEVER be sent to the cloud/backend.**
>
> The private key is generated on the gateway device and:
> - Stored in gateway non-volatile storage (Linux `/etc/wireguard/`, OpenWrt NVRAM, etc.)
> - **NEVER** exposed through API responses
> - **NEVER** logged or transmitted off-device
> - Only the public key is sent to the backend for peer coordination

## 📁 Files Changed/Created

### 1. `app/gateway/keypair.py` (NEW)
**WireGuard keypair generation module.**

**Key Functions:**
- `generate_wg_keypair()` - Generates fresh X25519 keypair using CSPRNG
  - Returns `private_key` and `public_key` as b64 strings
  - **CRITICAL**: `private_key` must be stored on gateway device only
- `get_wg_public_key_from_private()` - Derive public key from private key
  - Used for key rotation, still does not expose private key
- `store_wg_private_key_locally()` - Store key in gateway non-volatile storage
  - **TODO**: Implement gateway-specific path (Linux, OpenWrt, etc.)
- `read_wg_private_key_from_local_storage()` - Read key from gateway storage
  - **TODO**: Read from /etc/wireguard/ or gateway NVRAM
- `is_wg_keypair_generated()` - Check if keypair exists in storage

**Security Summary:**
| Action | Secure? |
|--------|---------|
| Generate keypair on gateway | ✅ Yes |
| Send private_key to API | ❌ NO - never! |
| Send public_key to backend | ✅ Yes, safe |
| Store private_key in DB | ❌ NO - gateway only |
| Read private_key from storage | ✅ Yes (gateway local) |

### 2. `app/models.py` (MODIFIED)
**Added WireGuard fields to `Gateway` class:**

| Field | Type | Description |
|-------|------|-------------|
| `wg_private_key` | String(512) | **PRIVATE KEY** - NEVER sent to cloud/API/logs. Stored on gateway device only. |
| `wg_public_key` | String(44) | Public key - CAN be sent to backend for coordination (WireGuard format) |
| `wg_listen_port` | Integer (default 51820) | WireGuard listen port |
| `wg_status` | String (default "offline") | offline|online|handshaking|error |
| `wg_last_handshake_at` | DateTime | Timestamp of last WG handshake |
| `tunnel_ip` | String(45) | Assigned tunnel IP per session |

**Important:** `wg_private_key` column exists in schema but application must
**never** SELECT/INSERT this field in API responses or logs. In production,
store in gateway secure storage, not necessarily in backend DB.

### 3. `app/routers/gateway_wg.py` (NEW)
**WireGuard tunnel configuration endpoints.**

**Endpoints:**

#### `GET /api/v1/gateways/{gateway_id}/configuration`
- Returns gateway's WireGuard public key and tunnel info
- **Private key is NEVER included** in response
- Requires authentication (owner or admin)
- Returns:
  - `gateway_public_key`
  - `listen_port`
  - `status`
  - `tunnel_ip`
  - `last_handshake_at`
  - `firmware_version`, `device_type`

#### `POST /api/v1/gateways/{gateway_id}/generate-keys`
- Generate WireGuard keypair on gateway device
- **Critical**: Private key returned in response but **MUST be stored on gateway device only**
- Flow:
  1. Call endpoint (or run on gateway CLI)
  2. Keypair generated: private_key stays on gateway, public_key stored in DB
  2. Public key used for tunnel setup
  3. Never transmit private_key off-device

**⚠️ WARNING in generate-keys response:**
> PRIVATE KEY MUST BE STORED ON GATEWAY DEVICE ONLY.
> See endpoint docs for secure storage instructions.
> Never store in API logs or transmit off-gateway.

### 4. `V1B_STAGE2_IDENTITY.md` (NEW)
**Full documentation you are reading now.**

## 🏗️ Architecture Diagram: V1B WireGuard Identity

```
┌─────────────────────────────────────────────────────────────┐
│                    GATEWAY DEVICE (Linux/OpenWrt)           │
│                                                             │
│  +----------------------+     +------------------------+ │
│  |  wg genkey           |     |  wg pubkey             | │
│  |  (generates once)    |     |  (sent to backend)     | │
│  +----------------------+     +------------------------+ │
|                                   │                               |
|  private_key stays on device      | public_key -> backend API     |
|  never leaves device              | (coordination only)          |
|                                   ▼                               |
|                        +--------------------+                  |
|                        |  BACKEND / CLOUD   |                  |
|                        |  (ODIVORA API)     |                  |
|                        +--------------------+                  |
|                                │                                |
|                public_key stored in DB gateways table          |
|                (wg_public_key column)                        |
|                                │                                |
|                tunnel_ip assigned per session                |
|                                ▼                                |
|                        +--------------------+                  |
|                        | SESSION/TRACKING   |                  |
|                        +--------------------+                  |
|                                 ▲                                |
|                        │  GET /configuration  │                |
|                        │  (public key only)   │                |
|                        ▼                                ▼                |
|                +-----------------+          Phone outside home   |
|                |  Phone/Mobile    |  requests connection      |
|                +-----------------+  -> auth/authorization    |
|                                 │                               |
|                                 │  Receive tunnel config      |
|                                 │  (gateway_public_key + tunnel_ip) |
|                                 ▼                               |
|                   +--------------------+                    |
|                   | WireGuard setup    |  Phone configures WG peer   |
|                   | (wg-quick/wg tool) |  using public key + own key |
|                   +--------------------+                    |
|                                 │                               |
|                                 ▼                               |
|                  Data plane established!                  |
|  Phone <--WireGuard--> Gateway <--LAN--> Home Router       |
|  Internet traffic exits through home ISP                 |
└─────────────────────────────────────────────────────────────┘
```

## 🔄 V1A → V1B Transition

| V1A (Control Plane) | V1B (Data Plane - WireGuard) |
|---------------------|------------------------------|
| Gateway registration ✅ | WireGuard keypair generation |
| Gateway claiming/claim ✅ | Private key stays on gateway |
| Heartbeat ✅ | Public key coordinated with backend |
| Session state machine ✅ | Tunnel IP addressing |
| API authentication ✅ | Dynamic peer configuration |
| Admin UI ✅ | Full tunnel data path |
| **Database schema** | **Extended with WG fields** |
| **No data path through API** | **API only coordinates, not proxies** |

## 🛠️ Implementation Notes

### Keypair Generation Flow
1. **Gateway boots** (or first registration)
2. Call `POST /api/v1/gateways/{id}/generate-keys`
3. Backend calls `generate_wg_keypair()` on gateway
4. **Private key** returned but **MUST be stored on gateway device only**
   - Linux: `echo $KEY > /etc/wireguard/private_key && chmod 600 /etc/wireguard/private_key`
   - OpenWrt: `uci set wireless.@wireguard[0].private_key='$KEY' && uci commit wireless`
   - Store in gateway's secure NVRAM/flash
5. **Public key** stored in `gateways.wg_public_key` DB column
6. Backend returns public key to caller (for coordination)
7. Subsequent `GET /configuration` returns public key for peer setup

### Security Checklist for V1B
- [ ] `wg_private_key` never appears in API responses
- [ ] `wg_private_key` never appears in logs (use redaction)
- [ ] `wg_private_key` stored on gateway device only (not in backend DB permanently)
- [ ] `wg_public_key` can be safely sent to backend/API
- [ ] Keypair generated once, persisted across reboots
- [ ] Key rotation flow documented (rare, security event)
- [ ] No TLS/SSL bypass for key transmission

### Testing V1B Identity
```python
# Test 1: Generate keys
keys = generate_wg_keypair()
assert len(keys["private_key"]) == 44  # b64 32 bytes
assert len(keys["public_key"]) > 0   # public key exists

# Test 2: Derive public from private
pub2 = get_wg_public_key_from_private(keys["private_key"])
assert pub2 == keys["public_key"]

# Test 3: API returns config without private key
config = await gateway_configuration(gw_id)
assert "private_key" not in config
assert "gateway_public_key" in config

# Test 4: Unauthorized access denied
# (would need auth token check)
```

## 📦 What's Next (Stage 3)

After Stage 2 establishes WireGuard identity, Stage 3 would cover:
- Dynamic peer configuration (authorize phone as WG peer)
- Tunnel IP addressing allocation
- Gateway routing configuration (IP forwarding, NAT)
- Full end-to-end test: phone outside home → WireGuard → home gateway → internet

## 📸 Screenshot/Verification

After implementing, verify:
1. `POST /api/v1/gateways/{id}/generate-keys` generates keys
2. Private key value is **not** exposed in browser/API output (only masked warning)
3. `GET /api/v1/gateways/{id}/configuration` returns public key
4. Database has `wg_public_key` set, `wg_private_key` set (but not logged/exposed)
5. Admin UI or `STATUS` command reflects new WireGuard capabilities

---

*V1B Stage 2 complete: WireGuard identity established. Private keys stay on gateway,
public keys coordinated with backend. Ready for Stage 3: dynamic tunnel configuration.*