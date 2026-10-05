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

    # Encode public key in WireGuard format (base64-encoded, no PEM headers)
    public_key_bytes = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    public_key_b64 = base64.b64encode(public_key_bytes).decode("utf-8").rstrip("=")

    # Private key also as b64 for storage on gateway
    private_key_b64 = base64.b64encode(private_key_bytes).decode("utf-8").rstrip("=")

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
        # Decode the private key
        key_bytes = base64.b64decode(private_key_b64 + "==")
        private_key = x25519.X25519PrivateKey.from_private_bytes(key_bytes)
        public_key = private_key.public_key()

        # Encode public key in WireGuard format
        public_key_bytes = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        return base64.b64encode(public_key_bytes).decode("utf-8").rstrip("=")
    except Exception as e:
        raise ValueError(f"Invalid private key format: {e}")


# --- Gateway local storage placeholders ---

def store_wg_private_key_locally(private_key_b64: str) -> bool:
    """STORE Private key in gateway non-volatile storage.

    In production, this would:
    - Write to /etc/wireguard/private_key on Linux
    - Use OpenWrt uci or system config
    - Or gateway's secure element/flash storage

    For V1B prototype, we note the requirement.

    Args:
        private_key_b64: b64-encoded private key string

    Returns:
        True if storage was attempted (prototype mode).
    """
    # TODO: Implement gateway-specific secure storage
    # - Linux: echo $KEY > /etc/wireguard/private_key
    # - OpenWrt: uci set wireless.@wireguard[0].private_key=$KEY
    # - Or gateway secure storage
    _ = private_key_b64  # Suppress unused variable
    return True


def read_wg_private_key_from_local_storage() -> str | None:
    """READ Private key from gateway secure storage.

    Returns the private key b64 string, or None if not yet generated.

    This is the ONLY way the gateway should obtain its private key after
    initial generation. The key must persist across reboots.

    Returns:
        b64-encoded private key string, or None if not generated.
    """
    # TODO: Read from /etc/wireguard/private_key or gateway NVRAM
    # For V1B prototype demo, return None to indicate "not yet generated"
    return None


def is_wg_keypair_generated() -> bool:
    """Check if WireGuard keypair has been generated and stored.

    Returns True if the gateway has a private key in local storage.

    Returns:
        True if keypair exists in local storage, False otherwise.
    """
    # TODO: Check gateway secure storage
    # For prototype: assume not generated until explicitly set
    return read_wg_private_key_from_local_storage() is not None