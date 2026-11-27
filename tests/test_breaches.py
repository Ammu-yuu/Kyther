"""Offline tests for the keyless public breach analyzers."""
from __future__ import annotations

import importlib
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from kyther.core.entities import Entity, EntityType

breaches = importlib.import_module("kyther.analyzers.breaches")


class _Response:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data

    def json(self):
        return self._data


class BreachAnalyzerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        breaches._CACHE.clear()

    @staticmethod
    def _patch_client(response):
        """model the shared `async with client(...) as http` helper"""
        http = AsyncMock()
        http.get.return_value = response
        cm = AsyncMock()
        cm.__aenter__.return_value = http
        cm.__aexit__.return_value = False
        factory = MagicMock(return_value=cm)
        return patch.object(breaches, "client", factory), http

    async def test_xposedornot_reports_named_breaches(self):
        patcher, http = self._patch_client(_Response(200, {
            "status": "success",
            "breaches": [["Tesco", "Adobe"], "LinkedIn", ["Tesco"]],
        }))
        entity = Entity.make(EntityType.EMAIL, "Test@Example.com")
        with patcher:
            result = await breaches.XposedOrNot().run(entity)

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.data["count"], 3)
        self.assertEqual([b["name"] for b in finding.data["breaches"]],
                         ["Tesco", "Adobe", "LinkedIn"])
        self.assertIsNone(result.error)
        url = http.get.await_args.args[0]
        self.assertIn("/v1/check-email/test@example.com", url)

    async def test_zero_results_are_not_failures_and_are_cached(self):
        patcher, http = self._patch_client(
            _Response(200, {"Error": "Not found", "email": None}))
        analyzer = breaches.XposedOrNot()
        entity = Entity.make(EntityType.EMAIL, "nobody@example.com")
        with patcher:
            first = await analyzer.run(entity)
            second = await analyzer.run(entity)

        self.assertEqual(first.findings, [])
        self.assertEqual(second.findings, [])
        self.assertIsNone(first.error)
        self.assertEqual(http.get.await_count, 1)  # cached, quota not burned twice

    async def test_xposedornot_rate_limit_is_an_explicit_error(self):
        patcher, _ = self._patch_client(_Response(429, {}))
        with patcher:
            result = await breaches.XposedOrNot().run(
                Entity.make(EntityType.EMAIL, "someone@example.com"))
        self.assertIn("rate limited", result.error)
        self.assertEqual(result.findings, [])

    async def test_leakcheck_accepts_email_and_username(self):
        patcher, http = self._patch_client(_Response(200, {
            "success": True, "found": 2,
            "fields": ["username", "password"],
            "sources": [{"name": "Evony.com", "date": "2016-07"}, {"name": "Zynga.com"}],
        }))
        for etype, value in ((EntityType.EMAIL, "Someone@Example.com"),
                             (EntityType.USERNAME, "someone")):
            with patcher:
                result = await breaches.LeakCheck().run(Entity.make(etype, value))
            self.assertEqual(len(result.findings), 1)
            finding = result.findings[0]
            self.assertEqual(finding.data["count"], 2)
            self.assertEqual(finding.data["sources"][0],
                             {"name": "Evony.com", "date": "2016-07"})
            self.assertEqual(finding.data["fields"], ["username", "password"])
            self.assertIn("https://leakcheck.io/api/public?check=",
                          http.get.await_args.args[0])

    async def test_leakcheck_not_found_is_valid_zero(self):
        patcher, _ = self._patch_client(
            _Response(200, {"success": False, "error": "Not found"}))
        with patcher:
            result = await breaches.LeakCheck().run(
                Entity.make(EntityType.USERNAME, "totally-unique-handle-zz1847"))
        self.assertEqual(result.findings, [])
        self.assertIsNone(result.error)


if __name__ == "__main__":
    unittest.main()
