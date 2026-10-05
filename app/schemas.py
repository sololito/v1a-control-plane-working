"""Pydantic request/response schemas for API v1."""
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    display_name: Optional[str] = Field(default=None, max_length=120)
    device_name: str = Field(default="phone", max_length=80)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    device_name: str = Field(default="phone", max_length=80)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    device_id: UUID
    user_id: UUID


class RefreshRequest(BaseModel):
    refresh_token: str


class UserOut(BaseModel):
    id: UUID
    email: str
    display_name: Optional[str] = None
    is_admin: bool = False
    created_at: datetime
    class Config:
        from_attributes = True


class DeviceOut(BaseModel):
    id: UUID
    device_name: str
    device_type: str
    status: str
    last_seen: Optional[datetime] = None
    created_at: datetime
    class Config:
        from_attributes = True


class DeviceCreate(BaseModel):
    device_name: str = "phone"
    device_type: str = "mobile"


class GatewayRegisterRequest(BaseModel):
    device_type: str = Field(default="esp32", pattern="^(esp32|linux|openwrt|other)$")
    public_key: str = Field(min_length=16, max_length=8000)
    algorithm: str = Field(default="ed25519", pattern="^(ed25519|rsa)$")
    firmware_version: Optional[str] = Field(default=None, max_length=40)


class GatewayOut(BaseModel):
    id: UUID
    device_type: str
    firmware_version: Optional[str] = None
    status: str
    owner_user_id: Optional[UUID] = None
    last_seen: Optional[datetime] = None
    created_at: datetime
    class Config:
        from_attributes = True


class GatewayClaimRequest(BaseModel):
    pairing_code: str = Field(min_length=4, max_length=12, pattern="^[0-9]+$")


class HeartbeatRequest(BaseModel):
    firmware_version: Optional[str] = Field(default=None, max_length=40)
    health: Optional[Dict[str, Any]] = None
    ip_hint: Optional[str] = Field(default=None, max_length=64)
    nonce: Optional[str] = Field(default=None, max_length=80)


class GatewayEventIn(BaseModel):
    event_type: str
    payload: Optional[Dict[str, Any]] = None


class ConnectionCreate(BaseModel):
    gateway_id: UUID
    connection_path: str = "unknown"


class ConnectionOut(BaseModel):
    id: UUID
    status: str
    connection_path: str
    gateway_id: UUID
    expires_at: Optional[datetime] = None
    session_token: Optional[str] = None
    class Config:
        from_attributes = True


class SubscriptionOut(BaseModel):
    plan: str
    status: str
    entitlements: Optional[Dict[str, Any]] = None
    class Config:
        from_attributes = True
