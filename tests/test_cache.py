"""Unit tests for the bounded, single-flight TTL cache.

Run with: .venv/bin/python -m unittest discover -s tests -v
"""
from __future__ import annotations

import asyncio
import time
import unittest

from kyther.cache import TTLCache


class CacheUnitTests(unittest.TestCase):
    def test_bounded_lru_eviction(self):
        cache = TTLCache(maxsize=2)
        cache.set("a", 1)
        cache.set("b", 2)
        self.assertEqual(cache.get("a"), 1)   # 'a' is now most-recent
        cache.set("c", 3)
        self.assertIsNone(cache.get("b"))     # 'b' was the LRU victim
        self.assertEqual(cache.get("a"), 1)
        self.assertEqual(cache.get("c"), 3)

    def test_ttl_expiry_and_snapshot(self):
        cache = TTLCache(maxsize=4)
        cache.set("x", {"v": 1}, ttl=0.01)
        self.assertEqual(cache.get("x"), {"v": 1})
        time.sleep(0.02)
        self.assertIsNone(cache.get("x"))
        self.assertEqual(cache.peek("x"), {"v": 1})  # stale value still available

        restored = TTLCache(maxsize=4)
        restored.load_snapshot(cache.snapshot())
        self.assertIsNone(restored.get("x"))         # already expired on load
        fresh = TTLCache(maxsize=4)
        fresh.set("ok", [1, 2], ttl=60)
        restored.load_snapshot(fresh.snapshot())
        self.assertEqual(restored.get("ok"), [1, 2])

    def test_snapshot_rejects_garbage(self):
        cache = TTLCache(maxsize=2)
        cache.load_snapshot({"bad": {"data": 1, "ts": "nope", "ttl": 10},
                             "no-data": {"ts": time.time(), "ttl": 10},
                             "not-a-dict": 3})
        self.assertEqual(len(cache), 0)


class CacheAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_single_flight_shares_one_load(self):
        cache = TTLCache(maxsize=4)
        calls = 0
        release = asyncio.Event()

        async def loader():
            nonlocal calls
            calls += 1
            await release.wait()
            return {"n": calls}

        tasks = [asyncio.create_task(cache.get_or_load("k", loader, 60))
                 for _ in range(5)]
        await asyncio.sleep(0)  # let the first loader start
        release.set()
        values = await asyncio.gather(*tasks)
        self.assertEqual(calls, 1)
        self.assertTrue(all(v == {"n": 1} for v in values))
        self.assertEqual(cache.get("k"), {"n": 1})

    async def test_stale_on_error_and_default(self):
        cache = TTLCache(maxsize=4)
        cache.set("k", "good", ttl=0.01)
        await asyncio.sleep(0.02)

        async def boom():
            raise RuntimeError("upstream down")

        self.assertEqual(
            await cache.get_or_load("k", boom, 60, stale_on_error=True), "good"
        )
        self.assertEqual(
            await cache.get_or_load("missing", boom, 60, default="fallback"),
            "fallback",
        )
        with self.assertRaises(RuntimeError):
            await cache.get_or_load("missing", boom, 60)

    async def test_should_cache_rejects_failed_payload(self):
        cache = TTLCache(maxsize=4)
        calls = 0

        async def loader():
            nonlocal calls
            calls += 1
            return {"ok": calls == 2}

        for _ in range(2):
            await cache.get_or_load("k", loader, 60,
                                    should_cache=lambda v: v["ok"])
        self.assertEqual(calls, 2)


if __name__ == "__main__":
    unittest.main()
