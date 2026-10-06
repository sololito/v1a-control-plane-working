"""Normalisation + validation for device forensics recorded in the audit trail.

IMEI and MAC are *self-reported* by the mobile app: iOS/Android restrict access
to those identifiers, so they are optional and only syntactically validated —
never treated as proof of identity. The client IP is the only identifier the
server derives itself.
"""
import re

_IMEI_RE = re.compile(r"^[0-9]{14,16}$")
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_MAC_BARE_RE = re.compile(r"^[0-9A-Fa-f]{12}$")
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,252}[a-z0-9])?$", re.IGNORECASE)


def normalize_imei(raw) -> str | None:
    """15-digit IMEI (16 allowed for IMEISV). Returns None when unusable."""
    if not raw:
        return None
    digits = re.sub(r"[^0-9]", "", str(raw))
    return digits if _IMEI_RE.match(digits) else None


def normalize_mac(raw) -> str | None:
    """Colon/dash/bare hex MAC -> canonical uppercase colon form."""
    if not raw:
        return None
    value = str(raw).strip()
    if _MAC_BARE_RE.match(value):
        value = ":".join(value[i:i + 2] for i in range(0, 12, 2))
    if not _MAC_RE.match(value):
        return None
    return value.replace("-", ":").upper()


def normalize_host(raw) -> tuple[str, str | None]:
    """Normalize a reported destination into (host, url).

    Accepts bare hosts ("example.com") and full URLs ("https://a.b/c?q=1").
    Returns ("", None) when nothing printable can be derived, so callers can
    drop the row instead of storing junk in the audit report.
    """
    if not raw:
        return "", None
    value = str(raw).strip()[:2048]
    if not value:
        return "", None
    url = None
    host = value
    if "://" in value or value.startswith("//"):
        url = value
        host = value.split("://", 1)[-1]
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in host:  # strip userinfo
        host = host.rsplit("@", 1)[-1]
    if ":" in host:  # strip port
        host = host.split(":", 1)[0]
    host = host.strip(".").lower()
    if not host or not _HOST_RE.match(host):
        return "", None
    return host[:255], url
