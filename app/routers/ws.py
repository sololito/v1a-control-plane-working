"""WS endpoints: /ws/gateways/{id} (gateway token) + /ws/mobile (user access token)."""
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from app import signalling
from app.db import get_db
from app.deps import get_current_gateway, get_current_user_device

router = APIRouter(tags=["ws"])


@router.websocket("/ws/gateways/{gateway_id}")
async def ws_gateway(websocket: WebSocket, gateway_id: str):
    token = websocket.query_params.get("token", "")
    # Reuse bearer logic without Header dependency.
    from fastapi import HTTPException
    try:
        from app.security import decode_token
        from uuid import UUID
        import jwt as _jwt
        try:
            data = decode_token(token)
        except _jwt.ExpiredSignatureError:
            await websocket.close(code=4401)
            return
        except Exception:
            await websocket.close(code=4401)
            return
        if data.get("kind") != "gateway" or str(data.get("sub")) != str(gateway_id):
            await websocket.close(code=4403)
            return
    except Exception:
        await websocket.close(code=4401)
        return
    room = f"gateway:{gateway_id}"
    await signalling.join(room, websocket)
    try:
        while True:
            await websocket.receive_text()  # keepalive; ignore content
    except WebSocketDisconnect:
        signalling.leave(room, websocket)


@router.websocket("/ws/mobile")
async def ws_mobile(websocket: WebSocket):
    token = websocket.query_params.get("token", "")
    try:
        from app.security import decode_token
        from uuid import UUID
        import jwt as _jwt
        try:
            data = decode_token(token)
        except Exception:
            await websocket.close(code=4401)
            return
        if data.get("kind") != "access":
            await websocket.close(code=4403)
            return
        uid = str(UUID(str(data["sub"])))
    except Exception:
        await websocket.close(code=4401)
        return
    room = f"user:{uid}"
    await signalling.join(room, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        signalling.leave(room, websocket)
