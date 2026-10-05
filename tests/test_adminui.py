"""TODO #15: minimal Admin UI + Prometheus + alerts."""
import os
os.environ["DATABASE_URL"] = "sqlite:///./test_adminui.db"
try:
    if os.path.exists("./test_adminui.db"):
        os.remove("./test_adminui.db")
except PermissionError:
    pass

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db import Base, get_db
from app.main import app

engine = create_engine("sqlite:///./test_adminui.db", connect_args={"check_same_thread": False})
TestingSession = sessionmaker(bind=engine)
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)


def override():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override
c = TestClient(app)

from app import ratelimit
from app.routers import auth as auth_router


@pytest.fixture(autouse=True)
def _clear():
    from app.main import app as _app
    _app.dependency_overrides[get_db] = override
    ratelimit._mem.clear()
    auth_router._fails.clear()
    yield
    ratelimit._mem.clear()


def mk_admin():
    from app.db import SessionLocal  # noqa (ensures tables)
    db = TestingSession()
    from app import models
    from app.security import hash_password
    u = models.User(email="rootadmin@example.com", password_hash=hash_password("Password123!"),
                    is_admin=True)
    db.add(u)
    db.commit()
    db.close()
    r = c.post("/api/v1/auth/login", json={"email": "rootadmin@example.com",
                                           "password": "Password123!"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_admin_ui_served():
    r = c.get("/admin")
    assert r.status_code == 200
    assert "ODIVORA" in r.text and "/api/v1/auth/login" in r.text


def test_active_users_and_alerts_and_prometheus():
    h = mk_admin()
    # active users: admin just logged in -> seen recently
    au = c.get("/api/v1/admin/users/active", headers=h)
    assert au.status_code == 200
    assert any(u["email"] == "rootadmin@example.com" for u in au.json())
    # non-admin forbidden
    r = c.post("/api/v1/auth/register", json={"email": "plain@example.com",
                                              "password": "Password123!"})
    ph = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert c.get("/api/v1/admin/users/active", headers=ph).status_code == 403
    # alerts shape
    al = c.get("/api/v1/admin/alerts", headers=h)
    assert al.status_code == 200 and "alerts" in al.json()
    # prometheus exposition format
    pm = c.get("/metrics/prometheus")
    assert pm.status_code == 200
    assert "odivora_gateways_online" in pm.text
    assert "odivora_sessions_failed_recent" in pm.text
    # JSON /metrics kept for compat
    assert "sessions_active" in c.get("/metrics").json()
