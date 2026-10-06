"""WireGuard keypair generation on the gateway.

CRITICAL SECURITY REQUIREMENT:
Private key MUST NEVER be sent to the cloud/backend.
Only the public key is registered with the backend for coordination.

The private key is generated once on the gateway device and:
- Never leaves the gateway device
- Stored in gateway non-volatile memory
- Never exposed through API responses
- Never logged or transmitted
"""

import base64
import os
from typing import Dict
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


def generate_wg_keypair() -> Dict[str, str]:
    """Generate a WireGuard private/public keypair on the gateway.

    Returns:
        Dict with 'private_key' and 'public_key' b64-encoded strings.

    SECURITY:
    - private_key MUST be stored on the gateway device only
    - Never transmit this value to any server or API
    - The public_key can be safely sent to the backend for coordination
    """
    # Generate 32-byte random private key using CSPRNG
    private_key_bytes = os.urandom(32)

    # Parse as X25519 private key using cryptography library
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)

    # Derive the public key
    public_key = private_key.public_key()

    # Encode public key in WireGuard format (standard base64 WITH padding).
    # wg rejects unpadded keys: a 32-byte key must be exactly 44 characters
    # ending in '='. Stripping padding here silently produces unusable keys.
    public_key_bytes = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    public_key_b64 = base64.b64encode(public_key_bytes).decode("utf-8")

    # Private key also as b64 for storage on gateway
    private_key_b64 = base64.b64encode(private_key_bytes).decode("utf-8")

    return {
        "private_key": private_key_b64,  # !!! MUST Stay on gateway!
        "public_key": public_key_b64,  # Can be sent to backend
    }


def get_wg_public_key_from_private(private_key_b64: str) -> str:
    """Derive public key from a private key (for key rotation/re-import).

    Used when gateway already has a private key stored and needs its public key.
    Still does not expose the private key itself.
    """
    try:
        # Decode the private key (accept padded or unpadded input).
        padded = private_key_b64 + "=" * (-len(private_key_b64) % 4)
        key_bytes = base64.b64decode(padded, validate=True)
        if len(key_bytes) != 32:
            raise ValueError(f"expected 32 bytes, got {len(key_bytes)}")
        private_key = x25519.X25519PrivateKey.from_private_bytes(key_bytes)
        public_key = private_key.public_key()

        # Encode public key in WireGuard format (padded base64)
        public_key_bytes = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        return base64.b64encode(public_key_bytes).decode("utf-8")
    except Exception as e:
        raise ValueError(f"Invalid private key format: {e}")


# --- Gateway local storage (Linux) ---

WG_PRIVATE_KEY_FILE = "/etc/odivora/wg_private_key"


def store_wg_private_key_locally(private_key_b64: str, path: str | None = None) -> bool:
    """Persist the private key on the gateway, mode 0600, directory 0700.

    Runs on the gateway device only. The value must never be sent to the
    cloud; this service stores only the public half.
    """
    target = path or WG_PRIVATE_KEY_FILE
    try:
        os.makedirs(os.path.dirname(target) or ".", mode=0o700, exist_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(private_key_b64.strip() + "\n")
        os.chmod(target, 0o600)
        return True
    except OSError as e:
        print(f"[wg] failed to store private key at {target}: {e}")
        return False


def read_wg_private_key_from_local_storage(path: str | None = None) -> str | None:
    """Read this device's WireGuard private key from local storage, or None."""
    target = path or WG_PRIVATE_KEY_FILE
    try:
        with open(target) as f:
            key = f.read().strip()
        return key or None
    except OSError:
        return None


def is_wg_keypair_generated(path: str | None = None) -> bool:
    """True when this device already holds a WireGuard private key."""
    return read_wg_private_key_from_local_storage(path) is not None
