from __future__ import annotations

import threading
import time
from collections import deque

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import settings
from app.core.security import create_timed_token, decode_token, verify_timed_token

WINDOW_SECONDS = 60
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# challenge 端点及其前置依赖（Modal 需要 public-config 拿 site key）必须豁免，
# 否则超限后无法自证解封
CHALLENGE_PATH = "/api/v1/challenge"
EXEMPT_PATHS = {
    "/api/health",
    "/api/docs",
    "/api/openapi.json",
    CHALLENGE_PATH,
    "/api/v1/auth/public-config",
}
# 登录/注册等匿名 POST 由 nginx 的 auth zone 单独限流，不占用写操作配额
AUTH_PREFIX = "/api/v1/auth/"
# 搜索建议是击键级流量（前端 debounce 后仍高频）：独立配额桶，不占通用配额
SUGGEST_PATH = "/api/v1/search/suggest"

EXEMPT_HEADER = "x-challenge-token"
EXEMPT_SALT = "rate-limit-exempt"


class SlidingWindowLimiter:
    """进程内滑动窗口计数器。仅适用于单进程部署；多 worker 时各进程独立计数。"""

    def __init__(self, window_seconds: int = WINDOW_SECONDS) -> None:
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._last_prune = 0.0

    def allow(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            if now - self._last_prune > self.window_seconds:
                self._prune(cutoff)
                self._last_prune = now
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def _prune(self, cutoff: float) -> None:
        stale = [key for key, hits in self._hits.items() if not hits or hits[-1] <= cutoff]
        for key in stale:
            del self._hits[key]


limiter = SlidingWindowLimiter()


def identity_key(request: Request) -> str:
    """有有效 access token 按用户分键，否则按 IP 分键。

    校园 NAT 下大量用户共享出口 IP，按用户分键可避免误伤登录用户。
    """
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer "):
        payload = decode_token(authorization[7:], expected_type="access")
        if payload and payload.get("sub"):
            return f"user:{payload['sub']}"
    # X-Real-IP 由 nginx 设置；仅当 3001 端口不对外暴露时可信
    ip = request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")
    return f"ip:{ip}"


def create_exempt_token(key: str) -> str:
    """签发绑定身份键的豁免凭证；无服务端状态，靠签名 + 时效校验。"""
    return create_timed_token(key, EXEMPT_SALT)


def _is_exempt(request: Request, key: str) -> bool:
    token = request.headers.get(EXEMPT_HEADER)
    if not token:
        return False
    max_age = settings.RATE_LIMIT_EXEMPT_MINUTES * 60
    return verify_timed_token(token, EXEMPT_SALT, max_age) == key


def _too_many_requests() -> JSONResponse:
    body: dict[str, str] = {"detail": "请求过于频繁，请稍后再试"}
    if settings.RATE_LIMIT_CHALLENGE_ENABLED:
        body["challenge"] = "turnstile"
    return JSONResponse(body, status_code=429, headers={"Retry-After": str(WINDOW_SECONDS)})


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        if (
            not settings.RATE_LIMIT_ENABLED
            or not path.startswith("/api/")
            or path in EXEMPT_PATHS
        ):
            return await call_next(request)
        key = identity_key(request)
        if path == SUGGEST_PATH:
            if not limiter.allow(f"suggest:{key}", settings.RATE_LIMIT_SUGGEST_PER_MINUTE) and not _is_exempt(
                request, key
            ):
                return _too_many_requests()
            return await call_next(request)
        limit = (
            settings.RATE_LIMIT_USER_PER_MINUTE
            if key.startswith("user:")
            else settings.RATE_LIMIT_ANON_PER_MINUTE
        )
        if not limiter.allow(key, limit) and not _is_exempt(request, key):
            return _too_many_requests()
        if request.method in WRITE_METHODS and not path.startswith(AUTH_PREFIX):
            if not limiter.allow(f"write:{key}", settings.RATE_LIMIT_WRITE_PER_MINUTE) and not _is_exempt(
                request, key
            ):
                return _too_many_requests()
        return await call_next(request)
