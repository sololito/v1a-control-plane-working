"""WebSocket signalling: cloud relays session events, polling stays as fallback.

Channels: gateway:{id} and user:{id}. Broadcast is best-effort (no persistence);
polling GET /connections remains source of truth.
"""
from collections import defaultdict
from typing import Dict, Set
from fastapi import WebSocket

_rooms: Dict[str, Set[WebSocket]] = defaultdict(set)


async def join(room: str, ws: WebSocket):
    await ws.accept()
    _rooms[room].add(ws)


def leave(room: str, ws: WebSocket):
    try:
        _rooms[room].discard(ws)
    except Exception:
        pass


async def broadcast(room: str, message: dict):
    dead = []
    for ws in list(_rooms.get(room, set())):
        try:
            await ws.send_json(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        leave(room, ws)


async def broadcast_session(gateway_id: str, user_id: str, event: str, session_id: str,
                            status: str):
    msg = {"type": "session", "event": event, "session_id": session_id, "status": status}
    await broadcast(f"gateway:{gateway_id}", msg)
    await broadcast(f"user:{user_id}", msg)
