"""Per-tunnel audit report: build (JSON) and render (printable HTML).

A "tunnel" here is the WireGuard tunnel that terminates on one home gateway:
every peer session that rode it, every device that owned a peer, the addresses
and identifiers those devices arrived with, the first sites they reached, and
the audit events tied to any of those objects.

The HTML view is a plain self-contained document with print CSS so an
administrator can print one report per tunnel straight from the browser.
"""
import html
import json
from datetime import datetime

from app.config import get_settings


def _iso(dt) -> str | None:
    if not dt:
        return None
    return dt.isoformat() + "Z" if not dt.tzinfo else dt.isoformat()


def _audit_rows(db, ids: set, actors: set, limit: int):
    from sqlalchemy import or_
    from app.models import AuditLog
    if not ids and not actors:
        return []
    clauses = []
    if ids:
        clauses.append(AuditLog.resource_id.in_([str(i) for i in ids]))
    if actors:
        clauses.append(AuditLog.actor_id.in_([str(a) for a in actors]))
    rows = (db.query(AuditLog).filter(or_(*clauses))
            .order_by(AuditLog.created_at.desc()).limit(limit).all())
    return [{"at": _iso(r.created_at), "action": r.action, "actor_type": r.actor_type,
             "actor": r.actor_id, "resource_type": r.resource_type,
             "resource_id": r.resource_id, "ip": r.ip, "detail": r.detail} for r in rows]


def build_tunnel_report(db, gateway, session=None, audit_limit: int | None = None) -> dict:
    """Assemble the audit report for one gateway (tunnel), optionally narrowed
    to a single peer session."""
    from app.models import (ConnectionSession, DeviceVisit, SessionEvent,
                            User, UserDevice)
    s = get_settings()
    audit_limit = audit_limit or s.audit_page_max

    owner = db.query(User).filter(User.id == gateway.owner_user_id).first() \
        if gateway.owner_user_id else None
    try:
        meta = json.loads(gateway.ip_metadata or "{}") or {}
    except Exception:
        meta = {}

    q = db.query(ConnectionSession).filter(ConnectionSession.gateway_id == gateway.id)
    if session is not None:
        q = q.filter(ConnectionSession.id == session.id)
    sessions = q.order_by(ConnectionSession.requested_at.desc()).all()

    device_ids = {s0.device_id for s0 in sessions if s0.device_id}
    user_ids = {s0.user_id for s0 in sessions}
    if gateway.owner_user_id:
        user_ids.add(gateway.owner_user_id)

    devices = []
    if device_ids:
        devices = (db.query(UserDevice).filter(UserDevice.id.in_(device_ids))
                   .order_by(UserDevice.created_at).all())

    session_ids = [s0.id for s0 in sessions]
    visits = events = []
    if session_ids:
        visits = (db.query(DeviceVisit).filter(DeviceVisit.session_id.in_(session_ids))
                  .order_by(DeviceVisit.session_id, DeviceVisit.rank).all())
        events = (db.query(SessionEvent).filter(SessionEvent.session_id.in_(session_ids))
                  .order_by(SessionEvent.created_at.desc()).limit(audit_limit).all())

    id_set = {str(gateway.id)} | {str(i) for i in session_ids} | \
        {str(d.id) for d in devices} | {str(i) for i in device_ids}
    actor_set = {str(u) for u in user_ids}
    audit = _audit_rows(db, id_set, actor_set, audit_limit)

    visits_by_session: dict = {}
    for v in visits:
        visits_by_session.setdefault(str(v.session_id), []).append(
            {"rank": v.rank, "host": v.host, "url": v.url, "ip": v.client_ip,
             "at": _iso(v.visited_at)})

    active_states = ("requested", "authorized", "connecting", "connected")
    sess_out = []
    for s0 in sessions:
        dev = next((d for d in devices if str(d.id) == str(s0.device_id)), None)
        sess_out.append({
            "id": str(s0.id), "status": s0.status, "path": s0.connection_path,
            "data_plane": s0.data_plane,
            "peer_public_key": s0.wg_peer_public_key,
            "peer_ip": s0.wg_assigned_ip,
            "requested_at": _iso(s0.requested_at), "authorized_at": _iso(s0.authorized_at),
            "connected_at": _iso(s0.connected_at), "handshake_at": _iso(s0.wg_handshake_at),
            "ended_at": _iso(s0.ended_at), "disconnect_reason": s0.wg_disconnect_reason,
            "device": None if not dev else {
                "id": str(dev.id), "name": dev.device_name, "type": dev.device_type,
                "status": dev.status, "ip": dev.ip_address, "imei": dev.imei,
                "mac": dev.mac_address, "user_agent": dev.user_agent,
                "last_seen": _iso(dev.last_seen),
                "identity_updated_at": _iso(dev.identity_updated_at)},
            "visits": visits_by_session.get(str(s0.id), []),
        })

    return {
        "report": "odivora-tunnel-audit",
        "version": 1,
        "generated_at": _iso(datetime.utcnow()),
        "tunnel": {
            "gateway_id": str(gateway.id),
            "status": gateway.status,
            "device_type": gateway.device_type,
            "firmware_version": gateway.firmware_version,
            "wg_status": gateway.wg_status,
            "wg_public_key": gateway.wg_public_key,
            "wg_listen_port": gateway.wg_listen_port,
            "tunnel_ip": gateway.tunnel_ip,
            "wg_last_handshake_at": _iso(gateway.wg_last_handshake_at),
            "last_seen": _iso(gateway.last_seen),
            "created_at": _iso(gateway.created_at),
            "remote_ip": meta.get("remote_ip"),
            "ip_hint": meta.get("ip_hint"),
            "owner": None if not owner else {"id": str(owner.id), "email": owner.email,
                                             "display_name": owner.display_name},
        },
        "summary": {
            "sessions_total": len(sessions),
            "sessions_active": sum(1 for s0 in sessions if s0.status in active_states),
            "devices_total": len(devices),
            "sites_recorded": len(visits),
            "audit_events": len(audit),
        },
        "devices": [{
            "id": str(d.id), "name": d.device_name, "type": d.device_type,
            "status": d.status, "ip": d.ip_address, "imei": d.imei,
            "mac": d.mac_address, "user_agent": d.user_agent,
            "last_seen": _iso(d.last_seen), "created_at": _iso(d.created_at),
            "identity_updated_at": _iso(d.identity_updated_at),
            "user_id": str(d.user_id),
        } for d in devices],
        "sessions": sess_out,
        "session_events": [{"at": _iso(e.created_at), "session": str(e.session_id),
                            "event": e.event, "detail": e.detail} for e in events],
        "audit": audit,
    }


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _kv_table(pairs) -> str:
    return ("<table class='facts'><tbody>" +
            "".join(f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>" for k, v in pairs) +
            "</tbody></table>")


def _grid(headers, rows) -> str:
    if not rows:
        return "<p class='muted'>No records.</p>"
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_report_html(report: dict, *, title: str | None = None,
                       back_url: str = "/admin") -> str:
    """Self-contained printable HTML for a tunnel audit report."""
    t = report.get("tunnel", {})
    summ = report.get("summary", {})
    heading = title or f"Tunnel audit report — {str(t.get('gateway_id', ''))[:8]}"
    owner = t.get("owner") or {}

    meta = _kv_table([
        ("Report generated", report.get("generated_at")),
        ("Tunnel (gateway)", t.get("gateway_id")),
        ("Owner", owner.get("email") or "—"),
        ("Tunnel status", f"{t.get('status')} / wg:{t.get('wg_status')}"),
        ("Tunnel IP", t.get("tunnel_ip") or "—"),
        ("Gateway IP (observed)", t.get("remote_ip") or "—"),
        ("Gateway IP (hint)", t.get("ip_hint") or "—"),
        ("Gateway public key", t.get("wg_public_key") or "—"),
        ("Listen port", t.get("wg_listen_port")),
        ("Last handshake", t.get("wg_last_handshake_at") or "—"),
        ("Gateway last seen", t.get("last_seen") or "—"),
        ("Sessions", f"{summ.get('sessions_total')} total / "
                     f"{summ.get('sessions_active')} active"),
        ("Devices", summ.get("devices_total")),
        ("Sites recorded", summ.get("sites_recorded")),
        ("Audit events", summ.get("audit_events")),
    ])

    dev_rows = [[_esc(d["name"]), _esc(d["type"]), _esc(d["status"]), _esc(d["ip"] or "—"),
                 _esc(d["imei"] or "—"), _esc(d["mac"] or "—"), _esc(d["last_seen"] or "—")]
                for d in report.get("devices", [])]

    sess_html = ""
    for s0 in report.get("sessions", []):
        dev = s0.get("device") or {}
        facts = _kv_table([
            ("Session id", s0["id"]),
            ("Status / path", f"{s0['status']} / {s0.get('path')}"),
            ("Peer tunnel IP", s0.get("peer_ip") or "—"),
            ("Peer public key", s0.get("peer_public_key") or "—"),
            ("Requested", s0.get("requested_at") or "—"),
            ("Connected", s0.get("connected_at") or "—"),
            ("Handshake", s0.get("handshake_at") or "—"),
            ("Ended", s0.get("ended_at") or "—"),
            ("Disconnect reason", s0.get("disconnect_reason") or "—"),
            ("Device", dev.get("name") or "—"),
            ("Device type", dev.get("type") or "—"),
            ("Device IP", dev.get("ip") or "—"),
            ("IMEI", dev.get("imei") or "—"),
            ("MAC", dev.get("mac") or "—"),
            ("User agent", dev.get("user_agent") or "—"),
        ])
        visits = s0.get("visits") or []
        visit_tbl = ("<p class='muted'>No sites recorded for this session.</p>"
                     if not visits else _grid(
                         ["#", "Site", "URL", "Client IP", "Visited at"],
                         [[v["rank"], _esc(v["host"]), _esc(v.get("url") or "—"),
                           _esc(v.get("ip") or "—"), _esc(v.get("at") or "—")]
                          for v in visits]))
        sess_html += (f"<h3>Session {s0['id'][:8]}</h3>" + facts +
                      "<h4>First sites visited</h4>" + visit_tbl)

    audit_rows = [[_esc(a.get("at") or "—"), _esc(a.get("action")),
                   _esc(a.get("actor_type")), _esc((a.get("actor") or "")[:36]),
                   _esc(a.get("resource_type") or "—"), _esc((a.get("resource_id") or "")[:36]),
                   _esc(a.get("ip") or "—"), _esc((a.get("detail") or "")[:120])]
                  for a in report.get("audit", [])]

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{_esc(heading)}</title>
<style>
 body{{font-family:system-ui,Arial,sans-serif;color:#111;margin:24px;font-size:13px}}
 h1{{font-size:20px;margin:0 0 4px}} h2{{font-size:16px;margin:24px 0 6px;border-bottom:1px solid #ccc;padding-bottom:3px}}
 h3{{font-size:14px;margin:18px 0 6px}} h4{{font-size:13px;margin:12px 0 4px}}
 table{{border-collapse:collapse;width:100%;margin:6px 0 14px}}
 th,td{{border:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top;word-break:break-word}}
 th{{background:#f4f4f4}} .facts th{{width:180px;background:#fafafa}}
 .muted{{color:#666;font-size:12px}} .ctl{{margin:10px 0}}
 @media print{{ .ctl{{display:none}} body{{margin:10mm;font-size:11px}}
  h2{{page-break-after:avoid}} tr{{page-break-inside:avoid}} }}
</style></head><body>
<div class="ctl"><button onclick="window.print()">Print this report</button>
 <a href="{_esc(back_url)}">&#8592; Back to admin</a></div>
<h1>ODIVORA — {_esc(heading)}</h1>
<div class="muted">Tunnel {_esc(t.get('gateway_id'))} · generated {_esc(report.get('generated_at'))}</div>
<h2>1. Tunnel &amp; owner</h2>
{meta}
<h2>2. Devices on this tunnel ({len(report.get('devices', []))})</h2>
{_grid(["Device", "Type", "Status", "IP address", "IMEI", "MAC address", "Last seen"], dev_rows)}
<h2>3. Sessions ({len(report.get('sessions', []))})</h2>
{sess_html or "<p class='muted'>No sessions.</p>"}
<h2>4. Audit trail ({len(report.get('audit', []))} events)</h2>
{_grid(["When", "Action", "Actor type", "Actor", "Resource", "Resource id", "IP", "Detail"], audit_rows)}
<p class="muted">IMEI/MAC values are self-reported by the mobile client and are not
verified by ODIVORA. IP addresses are observed by the server. Visited sites are
reported by the client: only the first ten destinations of each session are kept.</p>
</body></html>"""
