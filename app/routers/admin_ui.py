"""Root-level minimal Admin UI. Separate from /api/v1/admin JSON API."""
from pathlib import Path
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["admin-ui"])
_HTML = Path(__file__).parent.parent / "static" / "admin.html"


@router.get("/admin", response_class=HTMLResponse)
def admin_ui():
    return _HTML.read_text(encoding="utf-8")
