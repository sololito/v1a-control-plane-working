"""Sliding-window rate limiting. Redis when available, in-memory fallback.

Keys are scoped (endpoint + IP [+ user]) so auth endpoints get tight limits
while heartbeats stay usable. Fail-open if Redis is down (log + allow) to avoid
self-DDoS; tighten in strict prod via env later.
"""
import logging
import time
from collections import defaultdict
from fastapi import HTTPException, Request

from app.config import get_settings

log = logging.getLogger("odivora.ratelimit")
_mem: dict = defaultdict(list)
_redis = None

try:
    import redis as _redis_lib

    def _get_redis():
        global _redis
        if _redis is None:
            s = get_settings()
            if s.redis_url:
                try:
                    _redis = _redis_lib.Redis.from_url(s.redis_url, socket_timeout=0.5)
                    _redis.ping()
                except Exception as e:
                    log.warning("redis unavailable, in-memory limiter: %s", e)
                    _redis = False
        return _redis or None
except ImportError:
    def _get_redis():
        return None


def check_rate(scope: str, key: str, limit: int, window_s: int = 60):
    now = time.time()
    r = _get_redis()
    if r is not None:
        try:
            k = f"rl:{scope}:{key}"
            pipe = r.pipeline()
            pipe.zremrangebyscore(k, 0, now - window_s)
            pipe.zadd(k, {str(now): now})
            pipe.zcard(k)
            pipe.expire(k, window_s)
            _, _, count, _ = pipe.execute()
            if int(count) > limit:
                raise HTTPException(status_code=429, detail="rate limited")
            return
        except HTTPException:
            raise
        except Exception as e:
            log.warning("redis limiter fail-open: %s", e)
    arr = _mem[f"{scope}:{key}"]
    arr[:] = [t for t in arr if now - t < window_s]
    if len(arr) >= limit:
        raise HTTPException(status_code=429, detail="rate limited")
    arr.append(now)


def client_ip(request: Request) -> str:
    """Best-effort real client address for audit logs and rate-limit keys.

    Behind a reverse proxy the socket peer is the proxy itself, so the LAST
    X-Forwarded-For entry is taken: that is the one the trusted proxy appended,
    whereas earlier entries are client-controlled and forgeable.

    Never raises — callers use it on the error path too (failed logins), so a
    malformed or peer-less request must still yield a usable string.
    """
    try:
        headers = getattr(request, "headers", None)
        if headers is not None and get_settings().trust_proxy_headers:
            xff = headers.get("x-forwarded-for")
            if xff:
                hops = [h.strip() for h in xff.split(",") if h.strip()]
                if hops:
                    return hops[-1][:64]
            fwd = headers.get("x-real-ip")
            if fwd:
                return fwd.strip()[:64]
    except Exception:
        pass
    client = getattr(request, "client", None)
    return client.host if client else "anon"
