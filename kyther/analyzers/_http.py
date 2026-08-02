"""Shared async HTTP helpers.

A single client factory so every analyzer uses the same polite defaults:
a descriptive User-Agent, redirects followed, and a sane timeout.
"""
from __future__ import annotations

import httpx

USER_AGENT = "kyther/0.1 (+https://example.local; research use)"


def client(timeout: float = 15.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )
