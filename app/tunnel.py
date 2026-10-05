"""Tunnel provider abstraction. Null default; WireGuard selectable via TUNNEL_PROVIDER.

WireGuard provider here is *config plumbing* (keygen + peer configs), not a
running daemon — the data-plane/relay daemon lands later. Sessions keep working
on Null; switching provider never changes the session state machine.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any


class TunnelProvider(ABC):
    name: str = "abstract"

    @abstractmethod
    def request_credentials(self, session_id: str) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def revoke_credentials(self, session_id: str) -> None:
        raise NotImplementedError

    def server_config(self) -> Dict[str, Any]:
        return {"provider": self.name}


class NullTunnelProvider(TunnelProvider):
    name = "null"

    def request_credentials(self, session_id: str):
        return {"provider": "null", "session_id": session_id, "note": "wireguard-not-yet-integrated"}

    def revoke_credentials(self, session_id: str):
        return None


class WireGuardProvider(TunnelProvider):
    """Ephemeral per-session X25519 keypair + placeholder endpoint/AllowedIPs."""
    name = "wireguard"

    def request_credentials(self, session_id: str):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        import base64
        priv = X25519PrivateKey.generate()
        pub = priv.public_key()
        from cryptography.hazmat.primitives import serialization
        priv_b = base64.b64encode(priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())).decode()
        pub_b = base64.b64encode(pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        return {"provider": "wireguard", "session_id": session_id,
                "client_private_key": priv_b, "client_public_key": pub_b,
                "server_public_key": "SERVER_PUBKEY_PLACEHOLDER",
                "endpoint": "vpn.odivora.example:51820",
                "allowed_ips": "10.8.0.0/24",
                "note": "daemon/relay not yet running — config plumbing only"}

    def revoke_credentials(self, session_id: str):
        return None


def get_tunnel_provider() -> TunnelProvider:
    from app.config import get_settings
    try:
        which = (get_settings().tunnel_provider or "null").lower()
    except Exception:
        which = "null"
    if which == "wireguard":
        return WireGuardProvider()
    return NullTunnelProvider()
