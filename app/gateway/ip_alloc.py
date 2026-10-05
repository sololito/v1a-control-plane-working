"""Tunnel IP allocation for the V1B WireGuard data plane (Stage 3).

Each gateway owns a private /24 tunnel subnet derived deterministically
from its gateway ID:

    10.<second>.<third>.0/24

- The gateway's own tunnel address is the first host (.1).
- Session peers (phones) are allocated .2 .. .254.

An address counts as "in use" only while its session is in an active
state (requested|authorized|connecting|connected). Terminating,
expiring, or revoking a session therefore frees its address
automatically without a separate release pass. Allocating never hands
out two active peers on the same gateway the same address, and never
collides a peer with the gateway's own .1 address.
"""
import hashlib
import ipaddress

from sqlalchemy.orm import Session as OrmSession

from app import models

_ACTIVE = ("requested", "authorized", "connecting", "connected")


def gateway_tunnel_network(gateway_id) -> ipaddress.IPv4Network:
    """Deterministic per-gateway /24 inside 10.64.0.0/10 (10.64-127.x)."""
    h = hashlib.sha1(str(gateway_id).encode("utf-8")).digest()
    return ipaddress.ip_network("10.%d.%d.0/24" % (64 + (h[0] % 64), h[1]))


def gateway_tunnel_ip(gateway_id) -> str:
    """Gateway's own tunnel address (first host of its subnet)."""
    net = gateway_tunnel_network(gateway_id)
    return str(next(net.hosts()))


def allocate_tunnel_ip(db: OrmSession, gateway: models.Gateway) -> str:
    """Pick the first free tunnel IP for a new peer on this gateway."""
    net = gateway_tunnel_network(gateway.id)
    used = {gateway_tunnel_ip(gateway.id)}  # gateway itself holds .1

    rows = (
        db.query(models.ConnectionSession)
        .filter(
            models.ConnectionSession.gateway_id == gateway.id,
            models.ConnectionSession.status.in_(_ACTIVE),
            models.ConnectionSession.wg_assigned_ip.isnot(None),
        )
        .all()
    )
    for row in rows:
        used.add(row.wg_assigned_ip)

    for addr in net.hosts():
        candidate = str(addr)
        if candidate not in used:
            return candidate
    raise RuntimeError(f"tunnel subnet {net} exhausted for gateway {gateway.id}")
