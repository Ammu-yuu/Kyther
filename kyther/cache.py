"""Small TTL cache used by the keyless live feeds.

Two properties matter for an unauthenticated web app:

* **Bounded** — entries are evicted in LRU order, so a caller cannot grow the
  process without limit by varying a query string.
* **Single-flight** — concurrent callers asking for the same expired key share
  one upstream load. Without this, a refresh burst (e.g. ten tabs opening the
  dashboard) turns into ten identical third-party requests and rate-limits us.

A failed refresh can optionally serve the previous value, which keeps the UI
useful when an upstream feed is briefly down. No network code lives here.
"""
from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Optional


class TTLCache:
    """LRU-bounded TTL cache with per-key single-flight loading."""

    def __init__(self, maxsize: int = 64, name: str = "cache"):
        if maxsize < 1:
            raise ValueError("maxsize must be positive")
        self.maxsize = maxsize
        self.name = name
        self._data: "OrderedDict[str, tuple[float, Any, float]]" = OrderedDict()
        self._inflight: dict[str, asyncio.Future] = {}

    def __len__(self) -> int:
        return len(self._data)

    def clear(self) -> None:
        self._data.clear()
        # Waiters keep their future; it resolves when the in-flight load ends.
        self._inflight.clear()

    def get(self, key: str, ttl: Optional[float] = None) -> Any | None:
        """Return a fresh value (and mark it recently used), else ``None``."""
        entry = self._data.get(key)
        if entry is None:
            return None
        ts, value, stored_ttl = entry
        if time.time() - ts >= (stored_ttl if ttl is None else ttl):
            # Keep the expired value so stale-on-error can still serve it. It is
            # replaced on the next successful load and bounded by maxsize.
            return None
        self._data.move_to_end(key)
        return value

    def peek(self, key: str) -> Any | None:
        """Return a value even if expired — used as stale-on-error fallback."""
        entry = self._data.get(key)
        return None if entry is None else entry[1]

    def age(self, key: str) -> float | None:
        """Seconds since this key was stored, or ``None`` if never stored."""
        entry = self._data.get(key)
        return None if entry is None else time.time() - entry[0]

    def set(self, key: str, value: Any, ttl: float = 60.0) -> Any:
        self._data[key] = (time.time(), value, ttl)
        self._data.move_to_end(key)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)
        return value

    def snapshot(self) -> dict:
        """Serializable view for on-disk persistence (threat feeds)."""
        return {
            key: {"ts": ts, "ttl": ttl, "data": value}
            for key, (ts, value, ttl) in self._data.items()
        }

    def load_snapshot(self, raw: object) -> None:
        """Restore a :meth:`snapshot`; malformed/expired entries are ignored."""
        if not isinstance(raw, dict):
            return
        for key, item in raw.items():
            if not isinstance(item, dict) or "data" not in item:
                continue
            try:
                ts = float(item.get("ts", 0))
                ttl = float(item.get("ttl", 60))
            except (TypeError, ValueError):
                continue
            if ts <= 0 or time.time() - ts >= ttl:
                continue
            self._data[key] = (ts, item["data"], ttl)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)

    async def get_or_load(
        self,
        key: str,
        loader: Callable[[], Awaitable[Any]],
        ttl: float = 60.0,
        *,
        should_cache: Callable[[Any], bool] = lambda value: True,
        stale_on_error: bool = False,
        default: Any = None,
    ) -> Any:
        """Get a fresh entry, loading it once even if many callers race.

        ``should_cache`` can reject transient payloads (e.g. a failed feed
        response). ``stale_on_error`` returns the previous value when the
        loader raises, falling back to ``default`` when there is none.
        """
        hit = self.get(key)
        if hit is not None:
            return hit

        future = self._inflight.get(key)
        if future is None:
            loop = asyncio.get_event_loop()
            future = loop.create_future()
            self._inflight[key] = future

            async def run() -> None:
                try:
                    value = await loader()
                    if should_cache(value):
                        self.set(key, value, ttl)
                    if not future.done():
                        future.set_result(value)
                except Exception as exc:
                    stale = self.peek(key) if stale_on_error else None
                    if stale is not None and not future.done():
                        future.set_result(stale)
                    elif default is not None and not future.done():
                        future.set_result(default)
                    elif not future.done():
                        future.set_exception(exc)
                finally:
                    if self._inflight.get(key) is future:
                        self._inflight.pop(key, None)

            asyncio.ensure_future(run())
        return await future
