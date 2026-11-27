"""Keyless public breach lookups — the IntelBase-style part Kyther can do free.

Two public APIs answer "has this identifier appeared in a known breach?" without
a key or signup:

* **XposedOrNot** — email only, open-source service, 25 requests/hour per IP.
* **LeakCheck** — email *or* username, public endpoint, 1 request/second.

Both return breach *names* and data categories, never the leaked values. Results
are cached briefly in-process: repeated scans of the same identifier do not burn
the shared per-IP quota. A rate-limit or outage becomes an explicit source
error, never a silent "not found".

Attribution: LeakCheck's terms ask for a "Powered by LeakCheck" link; the UI and
README include one. No passwords, pastes or private records are queried.
"""
from __future__ import annotations

from urllib.parse import quote

from ..cache import TTLCache
from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding, Severity
from ..core.registry import register
from ._http import client

_CACHE = TTLCache(maxsize=128, name="breach-lookups")
_CACHE_TTL = 15 * 60.0  # per-IP free quotas are hourly/daily; 15 min is plenty
_MAX_BREACHES = 40      # keep the response and terminal output bounded


async def _cached(key: str, loader):
    """Return a cached payload, loading at most once per key (TTL-bounded)."""
    hit = _CACHE.get(key)
    if hit is not None:
        return hit
    value = await loader()
    if value is not None:
        _CACHE.set(key, value, _CACHE_TTL)
    return value


def _names(raw) -> list[str]:
    """Normalise the different breach-list shapes into plain names."""
    out: list[str] = []
    for row in raw or []:
        if isinstance(row, str):
            out.append(row)
        elif isinstance(row, dict):
            name = row.get("name") or row.get("Name")
            if name:
                out.append(str(name))
        elif isinstance(row, (list, tuple)):
            out.extend(str(part) for part in row if part)
    return list(dict.fromkeys(n for n in out if n))


@register
class XposedOrNot(Analyzer):
    name = "xposedornot"
    description = "Keyless public breach check for an email (XposedOrNot)."
    accepts = {EntityType.EMAIL}
    timeout = 20.0

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        email = entity.value
        safe = quote(email, safe="@.+_-")

        async def load():
            async with client(self.timeout) as http:
                resp = await http.get(
                    f"https://api.xposedornot.com/v1/check-email/{safe}"
                )
            if resp.status_code == 429:
                result.error = "XposedOrNot rate limited — try again later"
                return None
            if resp.status_code == 404:
                return {"breaches": []}
            if resp.status_code != 200:
                result.error = f"XposedOrNot HTTP {resp.status_code}"
                return None
            try:
                payload = resp.json()
            except Exception:
                result.error = "XposedOrNot returned invalid JSON"
                return None
            if not isinstance(payload, dict):
                result.error = "XposedOrNot returned an unexpected payload"
                return None
            # Unknown addresses come back 200 with {"Error": "Not found"}.
            if payload.get("Error") or payload.get("status") != "success":
                return {"breaches": []}
            return {"breaches": _names(payload.get("breaches"))}

        data = await _cached(f"xon:{email.lower()}", load)
        if data is None or not data.get("breaches"):
            return result

        names = data["breaches"]
        result.findings.append(
            Finding(
                self.name, entity,
                f"Found in {len(names)} public breach(es) (XposedOrNot)",
                data={
                    "source": "XposedOrNot",
                    "source_url": "https://xposedornot.com",
                    "count": len(names),
                    "breaches": [{"name": n} for n in names[:_MAX_BREACHES]],
                    "truncated": len(names) > _MAX_BREACHES,
                },
                severity=Severity.HIGH,
            )
        )
        return result


@register
class LeakCheck(Analyzer):
    name = "leakcheck"
    description = "Keyless public breach check for an email or username (LeakCheck)."
    accepts = {EntityType.EMAIL, EntityType.USERNAME}
    timeout = 20.0

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        safe = quote(entity.value, safe="@.+_-")

        async def load():
            async with client(self.timeout) as http:
                resp = await http.get(f"https://leakcheck.io/api/public?check={safe}")
            if resp.status_code == 429:
                result.error = "LeakCheck rate limited — try again later"
                return None
            if resp.status_code != 200:
                result.error = f"LeakCheck HTTP {resp.status_code}"
                return None
            try:
                payload = resp.json()
            except Exception:
                result.error = "LeakCheck returned invalid JSON"
                return None
            if not isinstance(payload, dict):
                result.error = "LeakCheck returned an unexpected payload"
                return None
            if not payload.get("success"):
                # {"success": false, "error": "Not found"} is a valid zero result.
                return {"found": 0, "sources": [], "fields": []}
            return {
                "found": int(payload.get("found") or 0),
                "sources": payload.get("sources") or [],
                "fields": payload.get("fields") or [],
            }

        data = await _cached(f"leakcheck:{entity.type}:{entity.value.lower()}", load)
        if data is None or not data.get("found"):
            return result

        sources = []
        for src in data["sources"][:_MAX_BREACHES]:
            if isinstance(src, dict) and src.get("name"):
                sources.append({"name": str(src["name"]), "date": src.get("date") or None})
        result.findings.append(
            Finding(
                self.name, entity,
                f"Found in {data['found']} leaked record(s) (LeakCheck)",
                data={
                    "source": "LeakCheck",
                    "source_url": "https://leakcheck.io",
                    "count": int(data["found"]),
                    "sources": sources,
                    "fields": [str(f) for f in data["fields"][:_MAX_BREACHES]],
                    "truncated": len(data["sources"]) > _MAX_BREACHES,
                },
                severity=Severity.HIGH,
            )
        )
        return result
