"""Users + devices: profile, per-device revocation."""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import models, schemas
from app.db import get_db
from app.deps import get_current_user_device

router = APIRouter(tags=["users"])


@router.get("/me", response_model=schemas.UserOut)
def me(user_dev=Depends(get_current_user_device)):
    user, _ = user_dev
    return user


@router.get("/me/devices")
def my_devices(user_dev=Depends(get_current_user_device), db: Session = Depends(get_db)):
    user, _ = user_dev
    devs = db.query(models.UserDevice).filter(models.UserDevice.user_id == user.id).all()
    return [{"id": str(d.id), "device_name": d.device_name, "device_type": d.device_type,
             "status": d.status, "last_seen": d.last_seen, "created_at": d.created_at} for d in devs]


@router.post("/me/devices")
def add_device(body: schemas.DeviceCreate, user_dev=Depends(get_current_user_device),
               db: Session = Depends(get_db)):
    user, _ = user_dev
    if body.device_type not in ("mobile", "tablet", "desktop", "other"):
        raise HTTPException(status_code=422, detail="bad device_type")
    count = db.query(models.UserDevice).filter(
        models.UserDevice.user_id == user.id,
        models.UserDevice.status == "active").count()
    if count >= 10:
        raise HTTPException(status_code=403, detail="device limit reached (10)")
    d = models.UserDevice(user_id=user.id, device_name=body.device_name.strip()[:80],
                          device_type=body.device_type)
    db.add(d)
    db.add(models.AuditLog(actor_type="user", actor_id=str(user.id), action="device.register",
                           resource_type="user_device", resource_id=str(d.id)))
    db.commit()
    db.refresh(d)
    return {"id": str(d.id), "status": d.status}


@router.delete("/me/devices/{device_id}")
def revoke_device(device_id: str, user_dev=Depends(get_current_user_device),
                  db: Session = Depends(get_db)):
    user, cur = user_dev
    d = db.query(models.UserDevice).filter(models.UserDevice.id == device_id).first()
    if not d or str(d.user_id) != str(user.id):
        raise HTTPException(status_code=404, detail="device not found")
    d.status = "revoked"
    d.refresh_token_hash = None
    d.revoked_at = datetime.utcnow()
    db.add(models.AuditLog(actor_type="user", actor_id=str(user.id), action="device.revoke",
                           resource_type="user_device", resource_id=str(d.id)))
    db.commit()
    return {"ok": True, "revoked": str(d.id)}
