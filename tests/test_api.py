"""Offline API tests: every route is exercised through ASGI with patched upstreams.

Run with: .venv/bin/python -m unittest discover -s tests -v
"""
from __future__ import annotations

import importlib
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from httpx import ASGITransport

from kyther.api import app
from kyther.core.entities import Entity, EntityType, ScanResult

feeds = importlib.import_module("kyther.api.feeds")
footprint_mod = importlib.import_module("kyther.api.footprint")
image_mod = importlib.import_module("kyther.api.image")
pulse = importlib.import_module("kyther.api.pulse")
scan_mod = importlib.import_module("kyther.api.scan")
threats = importlib.import_module("kyther.api.threats")


class _Response:
    """Minimal httpx-like response for patched get_client() calls."""

    def __init__(self, data, status_code=200):
        self._data = data
        self.status_code = status_code

    def json(self):
        return self._data


class ApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        feeds._NEWS_CACHE.clear()
        pulse._PULSE_CACHE.clear()
        threats._THREATS_CACHE.clear()

    async def _client(self):
        transport = ASGITransport(app=app)
        return httpx.AsyncClient(transport=transport, base_url="http://testserver")

    async def test_startup_hook_uses_threat_module(self):
        import kyther.api as api_pkg
        with patch.object(threats, "load_persisted") as load, \
             patch.object(threats, "start_refresher", new=AsyncMock()) as start:
            await api_pkg._threats_startup()
        load.assert_called_once_with()
        start.assert_awaited_once_with()

    async def test_shell_and_split_assets_are_served(self):
        async with await self._client() as c:
            html = await c.get("/")
            self.assertEqual(html.status_code, 200)
            self.assertIn("/assets/js/app.js", html.text)
            self.assertIn("/assets/base.css", html.text)

            js = await c.get("/assets/js/app.js")
            self.assertEqual(js.status_code, 200)
            self.assertIn("AbortController", (await c.get("/assets/js/core.js")).text)
            self.assertEqual(js.headers["cache-control"], "no-cache")

    async def test_news_is_cached_and_single_flight(self):
        client = AsyncMock()
        client.get.return_value = _Response({"hits": [
            {"title": "A real story", "points": 10, "url": "https://example.com/a",
             "objectID": "1", "created_at_i": 1700000000},
        ]})
        with patch.object(feeds, "get_client", return_value=client):
            async with await self._client() as c:
                first = (await c.get("/api/news")).json()
                second = (await c.get("/api/news")).json()
        self.assertEqual(first, second)
        self.assertEqual(first[0]["title"], "A real story")
        self.assertEqual(client.get.call_count, 1)

    async def test_threats_endpoint_uses_cached_feeds(self):
        threats._THREATS_CACHE.set("actors", [
            {"name": "APT Test", "aliases": [], "motive": "espionage"}], 60)
        threats._THREATS_CACHE.set("groups", [], 60)
        threats._THREATS_CACHE.set("attacks", [
            {"victim": "Acme", "group": "APT Test", "date": "2026-01-01"}], 60)
        async with await self._client() as c:
            data = (await c.get("/api/threats")).json()
        self.assertEqual(data["counts"], {"actors": 1, "attacks": 1})
        self.assertEqual(data["actors"][0]["name"], "APT Test")

    async def test_pulse_trending_and_topic(self):
        client = AsyncMock()
        client.get.return_value = _Response({"items": [{
            "articles": [{"article": "Open_Source", "views": 42}]}]})
        with patch.object(pulse, "get_client", return_value=client), \
             patch.object(pulse, "_gnews_search",
                          new=AsyncMock(return_value=([], None))):
            async with await self._client() as c:
                trending = (await c.get("/api/pulse/trending?region=en")).json()
                topic = (await c.get("/api/pulse/topic?q=Open%20Source")).json()
        self.assertTrue(trending["ok"])
        self.assertEqual(trending["topics"][0]["topic"], "Open Source")
        self.assertTrue(topic["ok"])
        self.assertEqual(topic["total"], 0)  # valid zero result, not a failure

    async def test_analyzers_catalog(self):
        async with await self._client() as c:
            data = (await c.get("/api/analyzers")).json()
        self.assertTrue(data)
        self.assertIn("name", data[0])

    async def test_scan_and_report(self):
        seed = Entity.make(EntityType.DOMAIN, "example.com")
        result = ScanResult(seed=seed)
        result.add_entity(seed)
        with patch.object(scan_mod, "scan", new=AsyncMock(return_value=result)), \
             patch.object(scan_mod, "Report") as report:
            report.return_value.generate.return_value = b"%PDF-1.4 fake"
            async with await self._client() as c:
                scan = (await c.post("/api/scan", json={
                    "target": "example.com", "type": "domain", "depth": 0})).json()
                pdf = await c.post("/api/report", json={
                    "target": "example.com", "type": "domain", "depth": 0})
        self.assertEqual(scan["seed"]["value"], "example.com")
        self.assertEqual(scan["errors"], [])
        self.assertEqual(pdf.status_code, 200)
        self.assertTrue(pdf.content.startswith(b"%PDF"))

    async def test_footprint_reports_incomplete_without_sources(self):
        with patch.object(footprint_mod, "_analyzer", return_value=None), \
             patch.object(footprint_mod, "_resolve_ips",
                          new=AsyncMock(return_value=[])):
            async with await self._client() as c:
                data = (await c.get("/api/footprint?target=example.com")).json()
        self.assertFalse(data["ok"])
        self.assertIn("No source returned data", data["errors"][-1])

    async def test_image_rejects_bad_payload(self):
        async with await self._client() as c:
            data = (await c.post("/api/image", json={"data": "not base64!!"})).json()
        self.assertFalse(data["ok"])
        self.assertIn("base64", data["error"])

    async def test_reddit_route_is_reachable(self):
        with patch("kyther.analyzers.reddit.reddit_dossier", new=AsyncMock(
                return_value={"found": False, "message": "nothing"})):
            async with await self._client() as c:
                data = (await c.get("/api/reddit?u=someone")).json()
        self.assertFalse(data["found"])


if __name__ == "__main__":
    unittest.main()
