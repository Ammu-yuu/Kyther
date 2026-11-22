"""SSRF guard for analyzers that fetch user-controlled hosts.

Adapted (in spirit) from the OSIRIS project's `ssrf-guard.ts`. Any analyzer
that turns user input into an outbound request should route it through
:func:`safe_get` so a target that resolves to a private / reserved / cloud-
metadata address is refused before a socket is opened.

We lean on the stdlib ``ipaddress`` module: an address is only allowed if it is
*globally routable* (``is_global``). That single check rejects loopback,
RFC1918, CGNAT/Tailscale (100.64/10), link-local (incl. 169.254.169.254 cloud
metadata), unique-local IPv6, multicast, and reserved ranges in one shot.

The validated IP is also *pinned* for the real connection (Host/SNI preserved),
which closes the DNS-rebinding gap between "check" and "connect". Responses are
streamed with a byte cap so a hostile server cannot exhaust memory before the
caller's own size check runs.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
from urllib.parse import urljoin

import httpx

from ..net import get_client

USER_AGENT = "kyther/0.1 (+https://example.local; research use)"

# Names that must never be treated as scan targets regardless of resolution.
_NAME_BLOCKLIST = [
    re.compile(r"^localhost$", re.I),
    re.compile(r"\.localhost$", re.I),
    re.compile(r"^host\.docker\.internal$", re.I),
    re.compile(r"\.local$", re.I),
    re.compile(r"\.internal$", re.I),
    re.compile(r"^metadata\.google\.internal$", re.I),
]

DEFAULT_MAX_BYTES = 25 * 1024 * 1024


class BlockedTargetError(Exception):
    """Raised when a host or response fails SSRF/size validation."""


def _ip_allowed(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # is_global is False for private, loopback, link-local, reserved, CGNAT,
    # unique-local, and unspecified addresses.
    return ip.is_global and not ip.is_multicast


async def _resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None)
    return list({info[4][0] for info in infos})


async def _validate(host: str) -> tuple[bool, str, list[str]]:
    """Return (ok, reason, globally-routable addresses)."""
    h = (host or "").strip().strip("[]")
    if not h:
        return False, "empty host", []

    if any(rx.search(h) for rx in _NAME_BLOCKLIST):
        return False, "hostname matches reserved name pattern", []

    # Literal IP? Check it directly (also rejects non-canonical forms, which
    # ipaddress refuses to parse — e.g. decimal '2130706433' or '0x7f.0.0.1').
    try:
        ipaddress.ip_address(h)
        return (True, "ok", [h]) if _ip_allowed(h) else (False, f"IP in reserved range: {h}", [])
    except ValueError:
        pass

    try:
        answers = await _resolve(h)
    except Exception as exc:
        return False, f"DNS lookup failed: {exc}", []
    if not answers:
        return False, "host has no A/AAAA records", []
    for addr in answers:
        if not _ip_allowed(addr):
            return False, f"resolves to reserved address {addr}", []
    return True, "ok", answers


async def validate_host(host: str) -> tuple[bool, str]:
    """Return (ok, reason). ok=True means the host is safe to fetch."""
    ok, reason, _ = await _validate(host)
    return ok, reason


async def safe_get(
    url: str,
    *,
    timeout: float = 15.0,
    max_redirects: int = 3,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> httpx.Response:
    """GET ``url``, validating the host of every hop (initial + each redirect).

    The connection is made to a validated IP with the original Host/SNI, so a
    short-TTL DNS rebinding attack cannot swap in a private address after the
    check. Raises :class:`BlockedTargetError` for blocked schemes/addresses,
    URLs with credentials or non-default ports, and oversized responses.
    """
    current = url
    for _ in range(max_redirects + 1):
        parsed = httpx.URL(current)
        if parsed.scheme not in ("http", "https"):
            raise BlockedTargetError(f"blocked scheme {parsed.scheme!r}")
        if parsed.username or parsed.password:
            raise BlockedTargetError("URL credentials are not allowed")
        if parsed.port not in (None, 80, 443):
            raise BlockedTargetError(f"non-default port {parsed.port} is not allowed")

        host = parsed.host or ""
        ok, reason, addresses = await _validate(host)
        if not ok:
            raise BlockedTargetError(reason)
        if not addresses:
            raise BlockedTargetError("host has no usable address")

        pinned = parsed.copy_with(host=addresses[0])
        headers = {"Host": host, "Accept": "*/*"}
        extensions = {"sni_hostname": host} if parsed.scheme == "https" else None

        async with get_client().stream(
            "GET", pinned, headers=headers, extensions=extensions, timeout=timeout
        ) as resp:
            if resp.is_redirect and resp.has_redirect_location:
                # Resolve relative Locations against the *original* host, not
                # the pinned IP URL, then validate the next hop normally.
                current = str(httpx.URL(urljoin(str(parsed), resp.headers["location"])))
                continue

            body = bytearray()
            async for chunk in resp.aiter_bytes():
                if len(body) + len(chunk) > max_bytes:
                    raise BlockedTargetError(f"response too large (>{max_bytes} bytes)")
                body.extend(chunk)
            resp._content = bytes(body)
            return resp
    raise BlockedTargetError("too many redirects")
