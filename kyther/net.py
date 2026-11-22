"""Shared HTTP client and URL helpers.

Everything that makes an outbound request (analyzers, SSRF-guarded fetches and
the keyless live feeds) should use :func:`get_client` so connections are pooled,
timeouts are consistent and proxy environment variables cannot silently reroute
a request that was validated by the SSRF guard.

:func:`sanitize_public_url` is the server-side counterpart of the UI's
``safeHref()``: third-party data is only ever turned into a clickable http(s)
link if it passes this allowlist.
"""
from __future__ import annotations

from urllib.parse import urlsplit

import httpx

USER_AGENT = "kyther/0.1 (+https://example.local; research use)"

_client: httpx.AsyncClient | None = None


def get_client() -> httpx.AsyncClient:
    """Return the process-wide, non-proxying HTTP client (created lazily)."""
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            headers={"User-Agent": USER_AGENT},
            follow_redirects=False,
            trust_env=False,
        )
    return _client


async def close_client() -> None:
    """Close the shared client (called on app shutdown)."""
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None


def sanitize_public_url(value: object, *, allow_fragment: bool = False) -> str | None:
    """Return ``value`` if it is a safe, absolute http(s) URL, else ``None``.

    Rejects javascript:/data:/file: schemes, URLs with userinfo, and non-default
    ports. ``allow_fragment`` permits harmless in-page anchors such as ``#``.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if allow_fragment and text.startswith("#"):
        return text
    try:
        parts = urlsplit(text)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        if parts.port not in (None, 80, 443):
            return None
        if parts.scheme == "https" and parts.port == 80:
            return None
        if parts.scheme == "http" and parts.port == 443:
            return None
    except ValueError:
        return None
    return text
