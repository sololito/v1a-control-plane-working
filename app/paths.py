"""Connection-path abstraction (V1B §12/§13).

DIRECT is the only functional path in this phase. RELAY is modelled so
the session/connection model does not change when a relay is introduced
(e.g. behind CGNAT); today it is an explicit TODO placeholder, never
silently selected.
"""

DIRECT = "direct"
RELAY = "relay"
UNKNOWN = "unknown"


def plan_connection_path(gateway_online: bool, gateway_has_endpoint: bool,
                         relay_available: bool = False) -> dict:
    """Decide how a phone should reach the gateway.

    Returns {"path": ..., "reason": ...}:
    - direct  : gateway online and has a usable endpoint hint (public IP /
                hint from heartbeat metadata). Preferred path.
    - relay   : only when explicitly available; Phase-1 never builds one,
                so this is reserved for the CGNAT/relay phase.
    - unknown : gateway offline or no endpoint info; client should wait /
                retry rather than silently failing.
    """
    if gateway_online and gateway_has_endpoint:
        return {"path": DIRECT, "reason": "gateway online with reachable endpoint"}
    if relay_available and gateway_online:
        return {"path": RELAY, "reason": "direct endpoint unknown; relay fallback"}
    return {"path": UNKNOWN, "reason": "gateway offline or endpoint unknown"}
