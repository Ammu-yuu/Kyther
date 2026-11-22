"""Offline regression tests for the correctness pass.

No upstream service is contacted: every network boundary is patched.

Run with: .venv/bin/python -m unittest discover -s tests -v
"""
from __future__ import annotations

import asyncio
import base64
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from kyther.api import (
    _PULSE_CACHE,
    ImageRequest,
    _decode_image_data,
    _footprint_risk,
    _parse_rss,
    _pulse_read,
    _run_safe,
    footprint,
    image_intel,
    pulse_topic,
    pulse_trending,
)
from kyther.imageintel import _to_degrees, assess, detect_format


class _FailingAnalyzer:
    def __init__(self, name: str):
        self.name = name

    async def run(self, entity):
        raise RuntimeError("offline")


class _SlowAnalyzer:
    name = "slow"

    async def run(self, entity):
        await asyncio.sleep(5)
        return None


class _FakeResponse:
    def __init__(self, content: bytes, ctype: str = "text/html"):
        self.content = content
        self.headers = {"content-type": ctype}

    def raise_for_status(self):
        return None


class FootprintCorrectnessTests(unittest.IsolatedAsyncioTestCase):
    def test_risk_is_incomplete_when_checks_failed_or_no_host_resolved(self):
        failed = _footprint_risk([], errors=["crtsh: timed out after 30s"])
        self.assertEqual(failed["posture"], "incomplete")
        self.assertIn("Can't judge", failed["headline"])

        unresolved = _footprint_risk([], mapped=0)
        self.assertEqual(unresolved["posture"], "incomplete")
        self.assertIn("No host resolved", unresolved["headline"])

        # Real findings still win, but are labelled as partial when sources failed.
        found = _footprint_risk(
            [{"ip": "8.8.8.8", "hosts": ["db.example.com"], "ports": [3306], "vulns": []}],
            errors=["ip_geo: failed"],
        )
        self.assertEqual(found["posture"], "exposed")
        self.assertTrue(found["partial"])

    async def test_run_safe_reports_timeout_instead_of_silent_none(self):
        with patch("kyther.api._FOOTPRINT_TIMEOUT", 0.01):
            result, err = await _run_safe(_SlowAnalyzer(), None, "slow")
        self.assertIsNone(result)
        self.assertIsNotNone(err)
        self.assertIn("timed out", err)

        result, err = await _run_safe(None, None, "missing")
        self.assertIsNone(result)
        self.assertIn("unavailable", err)

    async def test_footprint_reports_failures_instead_of_clean(self):
        with patch("kyther.api._analyzer",
                   side_effect=lambda name: _FailingAnalyzer(name)), \
             patch("kyther.api._resolve_ips", new=AsyncMock(return_value=[])):
            out = await footprint("example.com")

        self.assertFalse(out["ok"])
        self.assertIn("risk", out)
        self.assertEqual(out["risk"]["posture"], "incomplete")
        self.assertTrue(any("jobs:" in e for e in out["errors"]))
        self.assertTrue(any("crtsh:" in e for e in out["errors"]))
        self.assertTrue(any("resolve:" in e for e in out["errors"]))


class PulseCorrectnessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        _PULSE_CACHE.clear()

    def test_empty_feed_is_valid_but_html_is_not(self):
        articles, valid = _parse_rss(
            '<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>'
        )
        self.assertEqual(articles, [])
        self.assertTrue(valid)

        articles, valid = _parse_rss("<html><body>consent interstitial</body></html>")
        self.assertEqual(articles, [])
        self.assertFalse(valid)

    def test_pulse_read_grammar_and_no_overclaims(self):
        sides = [
            {"label": "United States", "articles": [{"title": "one"}]},
            {"label": "United Kingdom", "articles": []},
        ]
        read = " ".join(_pulse_read(sides))
        self.assertIn("1 story", read)
        self.assertNotIn("1 stories", read)
        self.assertNotIn("domestic story", read)
        self.assertNotIn("visible gap", read)

    async def test_zero_results_are_ok_not_source_busy(self):
        async def empty(_q, _edition, limit=8):
            return [], None

        with patch("kyther.api._gnews_search", new=empty):
            out = await pulse_topic("zero-results-are-valid")

        self.assertTrue(out["ok"])
        self.assertEqual(out["total"], 0)
        self.assertNotEqual(out.get("error"), "source_busy")
        self.assertTrue(any("zero-result" in line for line in out["read"]))

    async def test_empty_trending_payload_is_ok_not_source_busy(self):
        response = SimpleNamespace(status_code=200, json=lambda: {"items": [{"articles": []}]})
        client = SimpleNamespace(get=AsyncMock(return_value=response))
        with patch("kyther.api.get_client", return_value=client):
            out = await pulse_trending("en")
        self.assertTrue(out["ok"])
        self.assertEqual(out["topics"], [])
        self.assertNotIn("error", out)

    async def test_partial_edition_failures_are_surfaced(self):
        calls = 0

        async def partial(_q, _edition, limit=8):
            nonlocal calls
            calls += 1
            if calls == 1:
                return [{"title": "story", "url": "https://example.com/story"}], None
            return None, "HTTP 503"

        with patch("kyther.api._gnews_search", new=partial):
            out = await pulse_topic("partial-editions-are-visible")

        self.assertTrue(out["ok"])
        self.assertTrue(out["partial"])
        self.assertEqual(out["total"], 1)
        self.assertEqual(out["available"], 1)
        self.assertEqual(len(out["failed"]), 2)
        self.assertTrue(out["sides"][1]["error"])
        # Failed editions must not be described as "silent" in the coverage read.
        self.assertNotIn("United Kingdom", " ".join(out["read"]))


class ImageCorrectnessTests(unittest.IsolatedAsyncioTestCase):
    def test_gps_ref_is_never_assumed(self):
        self.assertIsNone(_to_degrees((40, 0, 0), None, ("N", "S")))
        self.assertIsNone(_to_degrees((40, 0, 0), "", ("N", "S")))
        self.assertIsNone(_to_degrees((40, 0, 0), "E", ("N", "S")))
        self.assertEqual(_to_degrees((40, 30, 0), "N", ("N", "S")), 40.5)
        self.assertEqual(_to_degrees((40, 30, 0), "S", ("N", "S")), -40.5)

        warning = assess({"format": "JPEG", "exif": {},
                          "gps": {"exact": False, "lat_magnitude": 40.5}})
        self.assertTrue(any("hemisphere" in s["text"].lower() for s in warning["signals"]))

    def test_data_urls_must_be_base64_images(self):
        raw, err = _decode_image_data("data:text/html;base64,PHNjcmlwdD4=")
        self.assertIsNone(raw)
        self.assertIn("image", err)

        raw, err = _decode_image_data("data:image/png;base64,!!!!")
        self.assertIsNone(raw)
        self.assertIn("base64", err)

        payload = base64.b64encode(b"\x89PNG\r\n\x1a\nrest").decode()
        raw, err = _decode_image_data("data:image/png;base64," + payload)
        self.assertIsNone(err)
        self.assertEqual(raw, b"\x89PNG\r\n\x1a\nrest")

    def test_format_comes_from_magic_bytes(self):
        self.assertEqual(detect_format(b"\xff\xd8\xff\xe0jpeg"), "JPEG")
        self.assertEqual(detect_format(b"\x89PNG\r\n\x1a\nrest"), "PNG")
        self.assertEqual(detect_format(b"RIFF????WEBPvp8 "), "WEBP")
        self.assertIsNone(detect_format(b"<!doctype html>"))

    async def test_html_page_without_main_image_is_reported(self):
        async def fake_get(_url, **_kwargs):
            return _FakeResponse(b"<!doctype html><html><body>no og:image</body></html>")

        with patch("kyther.core.netguard.safe_get", new=fake_get):
            out = await image_intel(ImageRequest(url="https://example.com/page"))
        self.assertFalse(out["ok"])
        self.assertTrue(out.get("page"))
        self.assertIn("web page", out["error"])

    async def test_unrecognised_bytes_are_rejected_even_with_image_mime(self):
        async def fake_get(_url, **_kwargs):
            return _FakeResponse(b"not really an image", ctype="image/png")

        with patch("kyther.core.netguard.safe_get", new=fake_get):
            out = await image_intel(ImageRequest(url="https://example.com/fake.png"))
        self.assertFalse(out["ok"])
        self.assertIn("unrecognised image format", out["error"])


if __name__ == "__main__":
    unittest.main()
