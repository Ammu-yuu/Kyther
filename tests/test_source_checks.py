"""The first page must distinguish 'checked, nothing found' from 'never checked'."""
from __future__ import annotations

import importlib
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from httpx import ASGITransport

from kyther.api import app
from kyther.api.builders import build_source_checks
from kyther.core.base import Analyzer
from kyther.core.entities import (
    AnalyzerResult, Entity, EntityType, Finding, ScanResult,
)
from kyther.core.orchestrator import _run_one

scan_module = importlib.import_module("kyther.api.scan")


class _Found(Analyzer):
    name = "xposedornot"
    accepts = {EntityType.EMAIL}

    async def run(self, entity):
        return AnalyzerResult(findings=[
            Finding(self.name, entity, "Found in 4 public breach(es)")
        ])


class _Empty(Analyzer):
    name = "leakcheck"
    accepts = {EntityType.EMAIL}

    async def run(self, entity):
        return AnalyzerResult()


class SourceCheckTests(unittest.IsolatedAsyncioTestCase):
    async def test_orchestrator_records_found_and_empty_outcomes(self):
        entity = Entity.make(EntityType.EMAIL, "someone@example.com")
        result = ScanResult(seed=entity)
        result.add_entity(entity)

        await _run_one(_Found(), entity, result)
        await _run_one(_Empty(), entity, result)

        self.assertEqual(result.checks["xposedornot"]["status"], "found")
        self.assertEqual(result.checks["leakcheck"]["status"], "not_found")

    def test_identity_ledger_marks_gaps_and_skips(self):
        seed = {"type": "email", "value": "someone@gmail.com"}
        checks = {
            "xposedornot": {"status": "found", "detail": "Found in 4 public breach(es)",
                            "entity": "email:someone@gmail.com"},
            "leakcheck": {"status": "not_found", "detail": "no match returned",
                          "entity": "email:someone@gmail.com"},
            "username": {"status": "unavailable", "detail": "timed out",
                         "entity": "username:someone"},
        }
        ledger = build_source_checks(seed, checks)
        self.assertEqual(ledger["Public breach index (XposedOrNot)"]["status"], "found")
        self.assertEqual(ledger["Breach lookup (LeakCheck)"]["status"], "not_found")
        self.assertEqual(ledger["Account handles (WhatsMyName + Sherlock)"]["status"],
                         "unavailable")
        self.assertEqual(ledger["Breach lookup (HIBP)"]["status"], "manual")
        self.assertIn("HIBP_API_KEY", ledger["Breach lookup (HIBP)"]["detail"])
        self.assertEqual(ledger["Domain records"]["status"], "not_run")
        self.assertIn("Free-mail", ledger["Domain records"]["detail"])

    async def test_scan_response_exposes_the_ledger(self):
        seed = Entity.make(EntityType.EMAIL, "someone@example.com")
        result = ScanResult(seed=seed)
        result.add_entity(seed)
        result.checks["xposedornot"] = {
            "status": "found", "detail": "Found in 1 public breach(es)", "entity": seed.key,
        }
        with patch.object(scan_module, "scan", new=AsyncMock(return_value=result)):
            async with httpx.AsyncClient(transport=ASGITransport(app=app),
                                         base_url="http://testserver") as client:
                data = (await client.post("/api/scan", json={
                    "target": "someone@example.com", "type": "email", "depth": 0,
                })).json()
        self.assertEqual(
            data["source_checks"]["Public breach index (XposedOrNot)"]["status"],
            "found",
        )


if __name__ == "__main__":
    unittest.main()
