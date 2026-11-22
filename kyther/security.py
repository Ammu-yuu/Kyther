"""Small, dependency-free ASGI hardening middleware for Kyther.

Adds conservative response headers and a per-client sliding-window limit on
``/api/`` calls. The API is intentionally keyless, so this is the only thing
standing between an unauthenticated caller and a burst of upstream requests.
"""
from __future__ import annotations

import os
import time
from collections import deque

from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse

SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
}


def allowed_origins() -> list[str]:
    """Origins permitted to call the API, from ``KYTHER_ALLOWED_ORIGINS``.

    Defaults cover the local UI (served from port 8099) and the ``file://``
    preview path. Tailnet deployments should add their ``http://100.x.y.z:8099``
    origin to the environment variable.
    """
    raw = os.environ.get(
        "KYTHER_ALLOWED_ORIGINS",
        "http://127.0.0.1:8099,http://localhost:8099,null",
    )
    return [item.strip() for item in raw.split(",") if item.strip()]


class KytherMiddleware:
    """Rate-limit API calls and attach security headers to every response."""

    def __init__(self, app, *, limit: int = 60, window: float = 60.0):
        self.app = app
        self.limit = max(1, int(os.environ.get("KYTHER_RATE_LIMIT", str(limit))))
        self.window = window
        self._hits: dict[str, deque[float]] = {}

    def _client_id(self, scope: dict) -> str:
        client = scope.get("client")
        return client[0] if client else "unknown"

    def _allow(self, client: str, now: float) -> int:
        hits = self._hits.setdefault(client, deque())
        cutoff = now - self.window
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) >= self.limit:
            return max(1, int(hits[0] + self.window - now))
        hits.append(now)
        return 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for key, value in SECURITY_HEADERS.items():
                    headers[key] = value
            await send(message)

        path = scope.get("path", "")
        if path.startswith("/api/"):
            retry_after = self._allow(self._client_id(scope), time.monotonic())
            if retry_after:
                response = JSONResponse(
                    {"detail": "Rate limit exceeded. Try again shortly."},
                    status_code=429,
                    headers={"Retry-After": str(retry_after)},
                )
                await response(scope, receive, send_with_headers)
                return
        await self.app(scope, receive, send_with_headers)
