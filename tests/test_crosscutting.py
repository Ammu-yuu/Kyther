"""Regression tests for the shared hardening layer.

Run with: .venv/bin/python -m unittest discover -s tests -v
All tests are offline; no upstream service is contacted.
"""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import httpx
from fastapi import FastAPI

from kyther.api import _footprint_risk, _pulse_read, _rss_articles
from kyther.core.netguard import (
    BlockedTargetError,
    _ip_allowed,
    safe_get,
    validate_host,
)
from kyther.imageintel import assess, og_image
from kyther.net import get_client, sanitize_public_url
from kyther.security import KytherMiddleware, SECURITY_HEADERS


class UrlSafetyTests(unittest.TestCase):
    def test_sanitize_public_url_allows_only_safe_absolute_urls(self):
        self.assertEqual(
            sanitize_public_url("https://example.com/a?b=1"),
            "https://example.com/a?b=1",
        )
        self.assertEqual(sanitize_public_url("http://example.com/"), "http://example.com/")
        for bad in (
            "javascript:alert(1)", "data:text/html,x", "file:///etc/passwd",
            "//example.com/x", "/relative", "https://u:p@example.com/",
            "https://example.com:8443/", "https://example.com:abc/", None, "",
        ):
            self.assertIsNone(sanitize_public_url(bad), bad)

    def test_fragments_are_opt_in(self):
        self.assertIsNone(sanitize_public_url("#"))
        self.assertEqual(sanitize_public_url("#", allow_fragment=True), "#")

    def test_shared_client_is_a_singleton_with_redirects_off(self):
        client = get_client()
        self.assertIs(client, get_client())
        self.assertFalse(client.is_closed)
        self.assertFalse(client.follow_redirects)


class NetguardTests(unittest.IsolatedAsyncioTestCase):
    def test_ip_allowlist(self):
        self.assertTrue(_ip_allowed("8.8.8.8"))
        self.assertTrue(_ip_allowed("2606:4700::1111"))
        for private in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::1"):
            self.assertFalse(_ip_allowed(private), private)

    async def test_validate_host_rejects_reserved_names_and_ips(self):
        for host in ("localhost", "x.local", "metadata.google.internal", "10.0.0.5"):
            ok, _ = await validate_host(host)
            self.assertFalse(ok, host)
        ok, _ = await validate_host("8.8.8.8")
        self.assertTrue(ok)

    async def test_safe_get_rejects_unsafe_urls_without_network(self):
        for url in (
            "file:///etc/passwd", "https://user:pass@example.com/",
            "https://example.com:8443/", "data:text/plain,hello",
        ):
            with self.assertRaises(BlockedTargetError, msg=url):
                await safe_get(url)


class AnalyzerClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_analyzer_context_keeps_timeout_without_closing_shared_client(self):
        from kyther.analyzers._http import client as analyzer_client

        class FakeClient:
            def __init__(self):
                self.kwargs = None
                self.closed = False

            async def get(self, url, **kwargs):
                self.kwargs = kwargs
                return "ok"

            async def aclose(self):
                self.closed = True

        fake = FakeClient()
        with patch("kyther.analyzers._http.get_client", return_value=fake):
            async with analyzer_client(3.0) as http:
                self.assertEqual(await http.get("https://example.test"), "ok")
        self.assertEqual(fake.kwargs["timeout"], 3.0)
        self.assertTrue(fake.kwargs["follow_redirects"])
        self.assertFalse(fake.closed)


class MiddlewareTests(unittest.IsolatedAsyncioTestCase):
    async def test_rate_limit_and_security_headers(self):
        app = FastAPI()

        @app.get("/api/ping")
        async def ping():
            return {"ok": True}

        with patch.dict(os.environ, {"KYTHER_RATE_LIMIT": "2"}):
            app.add_middleware(KytherMiddleware, limit=2, window=60)
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                first = await client.get("/api/ping")
                second = await client.get("/api/ping")
                third = await client.get("/api/ping")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(third.status_code, 429)
        self.assertTrue(int(third.headers["retry-after"]) >= 1)
        for key, value in SECURITY_HEADERS.items():
            self.assertEqual(first.headers[key], value)


class PureLogicTests(unittest.TestCase):
    def test_rss_articles_drop_unsafe_links(self):
        xml = """<?xml version="1.0"?><rss><channel>
          <item><title>Bad - Source</title><source>Source</source>
            <link>javascript:alert(1)</link><pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate></item>
          <item><title>Good - Source</title><source>Source</source>
            <link>https://example.com/story</link><pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate></item>
        </channel></rss>"""
        articles = _rss_articles(xml)
        self.assertEqual(len(articles), 1)
        self.assertEqual(articles[0]["title"], "Good")
        self.assertEqual(articles[0]["url"], "https://example.com/story")

    def test_footprint_risk_marks_exposed_database(self):
        risk = _footprint_risk([{"ip": "8.8.8.8", "hosts": ["db.example.com"],
                                 "ports": [3306], "vulns": []}])
        self.assertEqual(risk["posture"], "exposed")
        self.assertEqual(risk["counts"]["high"], 1)

    def test_pulse_read_handles_zero_and_single_story(self):
        sides = [{"label": "United States", "articles": []},
                 {"label": "United Kingdom", "articles": []},
                 {"label": "India", "articles": []}]
        self.assertIsNone(_pulse_read(sides))
        sides[0]["articles"] = [{"title": "one"}]
        self.assertIn("1 story", _pulse_read(sides)[0])
        self.assertNotIn("1 stories", " ".join(_pulse_read(sides)))

    def test_image_assess_and_og_image(self):
        stripped = assess({"format": "JPEG", "exif": {}, "gps": None})
        self.assertIn("Metadata stripped", stripped["verdict"])
        edited = assess({"format": "JPEG", "exif": {"Software": "Adobe Photoshop"}, "gps": None})
        self.assertIn("Edited in", edited["verdict"])
        page = '<html><head><meta property="og:image" content="https://x.test/a.png"></head></html>'
        self.assertEqual(og_image(page), "https://x.test/a.png")


if __name__ == "__main__":
    unittest.main()
