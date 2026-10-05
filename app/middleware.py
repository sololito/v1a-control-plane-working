"""Production middleware: request IDs, security headers, no-stack-leak errors."""
import logging
import time
import uuid
from fastapi import Request
from fastapi.responses import JSONResponse

log = logging.getLogger("odivora")


async def request_id_middleware(request: Request, call_next):
    rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    request.state.rid = rid
    t0 = time.time()
    try:
        resp = await call_next(request)
    except Exception:
        log.exception("unhandled rid=%s %s %s", rid, request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "internal error",
                                                      "request_id": rid})
    resp.headers["X-Request-ID"] = rid
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    # HSTS only matters behind TLS; harmless locally.
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    log.info("rid=%s %s %s -> %s %.0fms", rid, request.method, request.url.path,
             resp.status_code, (time.time() - t0) * 1000)
    return resp
