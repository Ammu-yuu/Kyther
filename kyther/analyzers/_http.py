"""Shared async HTTP helper for analyzers.

Keeps the old ``async with client(timeout) as http:`` call shape while handing
out the process-wide pooled client from :mod:`kyther.net`. Exiting the context
does *not* close the shared client — that happens on app shutdown. Each call
still carries the analyzer's own timeout, and redirects stay enabled as before.
"""
from __future__ import annotations

from ..net import get_client

USER_AGENT = "kyther/0.1 (+https://example.local; research use)"


class _SharedClient:
    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("follow_redirects", True)
        return await get_client().get(url, **kwargs)


def client(timeout: float = 15.0) -> _SharedClient:
    return _SharedClient(timeout)
