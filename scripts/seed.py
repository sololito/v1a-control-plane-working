"""Dev seed: admin + demo user."""
from app.db import SessionLocal, Base, engine
from app import models
from app.security import hash_password
import json

Base.metadata.create_all(bind=engine)
db = SessionLocal()
if not db.query(models.User).filter(models.User.email == "admin@example.com").first():
    db.add(models.User(email="admin@example.com", password_hash=hash_password("Admin12345!"),
                       display_name="Admin", is_admin=True))
if not db.query(models.User).filter(models.User.email == "demo@example.com").first():
    u = models.User(email="demo@example.com", password_hash=hash_password("Demo12345!"),
                    display_name="Demo")
    db.add(u); db.flush()
    db.add(models.Subscription(user_id=u.id, plan="free", status="active",
                               entitlements=json.dumps({"max_gateways": 2, "max_sessions": 1})))
db.commit()
print("seed ok")
