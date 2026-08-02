"""SSRF guard for analyzers that fetch user-controlled hosts.

Adapted (in spirit) from the OSIRIS project's `ssrf-guard.ts`. Any analyzer
that turns user input into an outbound request should route it through
:func:`safe_get` so a target that resolves to a private / reserved / cloud-
metadata address is refused before a socket is opened.

We lean on the stdlib ``ipaddress`` module: an address is only allowed if it is
*globally routable* (``is_global``). That single check rejects loopback,
RFC1918, CGNAT/Tailscale (100.64/10), link-local (incl. 169.254.169.254 cloud
metadata), unique-local IPv6, multicast, and reserved ranges in one shot.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re

import httpx

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


class BlockedTargetError(Exception):
    """Raised when a host fails SSRF validation."""


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


async def validate_host(host: str) -> tuple[bool, str]:
    """Return (ok, reason). ok=True means the host is safe to fetch."""
    h = host.strip().strip("[]")
    if not h:
        return False, "empty host"

    if any(rx.search(h) for rx in _NAME_BLOCKLIST):
        return False, "hostname matches reserved name pattern"

    # Literal IP? Check it directly (also rejects non-canonical forms, which
    # ipaddress refuses to parse — e.g. decimal '2130706433' or '0x7f.0.0.1').
    try:
        ipaddress.ip_address(h)
        return (True, "ok") if _ip_allowed(h) else (False, f"IP in reserved range: {h}")
    except ValueError:
        pass

    try:
        answers = await _resolve(h)
    except Exception as exc:
        return False, f"DNS lookup failed: {exc}"
    if not answers:
        return False, "host has no A/AAAA records"
    for addr in answers:
        if not _ip_allowed(addr):
            return False, f"resolves to reserved address {addr}"
    return True, "ok"


async def safe_get(url: str, *, timeout: float = 15.0, max_redirects: int = 3) -> httpx.Response:
    """GET ``url``, validating the host of every hop (initial + each redirect).

    Raises :class:`BlockedTargetError` if any hop targets a non-global address
    or a non-http(s) scheme.
    """
    current = url
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, headers={"User-Agent": USER_AGENT}
    ) as client:
        for _ in range(max_redirects + 1):
            parsed = httpx.URL(current)
            if parsed.scheme not in ("http", "https"):
                raise BlockedTargetError(f"blocked scheme {parsed.scheme!r}")
            ok, reason = await validate_host(parsed.host)
            if not ok:
                raise BlockedTargetError(reason)

            resp = await client.get(current)
            if resp.is_redirect and resp.has_redirect_location:
                current = str(resp.next_request.url)
                continue
            return resp
    raise BlockedTargetError("too many redirects")
