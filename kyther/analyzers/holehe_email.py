"""Email -> accounts enumeration via Holehe. OPT-IN.

Wraps the third-party `holehe` project (megadose/holehe), which checks whether
an email is registered on ~120 sites by probing their signup / password-reset
flows. This is account enumeration: it hits third-party auth endpoints from your
IP and is against many sites' ToS, so it is DISABLED unless you explicitly set
OSINT_ENABLE_HOLEHE=1, and should only be run against emails you're authorized
to investigate (e.g. your own).

Some modules also surface masked recovery hints (partial recovery email / phone)
that the site exposes during the check.
"""
from __future__ import annotations

import asyncio
import importlib
import os

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding, Severity
from ._http import client
from ..core.registry import register

_CONCURRENCY = 25
_PER_MODULE_TIMEOUT = 12.0
_module_cache: list | None = None


def _load_holehe_modules() -> list:
    """Import every holehe check by explicit dotted path (avoids holehe's own
    walk_packages auto-discovery, which collides with our `osint` package)."""
    global _module_cache
    if _module_cache is not None:
        return _module_cache
    funcs = []
    try:
        import holehe
    except ImportError:
        _module_cache = []
        return _module_cache
    base = os.path.dirname(holehe.__file__)
    modroot = os.path.join(base, "modules")
    for root, _dirs, files in os.walk(modroot):
        for f in files:
            if not f.endswith(".py") or f == "__init__.py":
                continue
            rel = os.path.relpath(os.path.join(root, f), base)[:-3]
            dotted = "holehe." + rel.replace(os.sep, ".")
            fn = f[:-3]
            try:
                mod = importlib.import_module(dotted)
                if hasattr(mod, fn):
                    funcs.append(getattr(mod, fn))
            except Exception:
                continue  # a broken/optional module must not sink the set
    _module_cache = funcs
    return funcs


@register
class HoleheEmail(Analyzer):
    name = "holehe"
    description = "Enumerate which sites an email is registered on (opt-in; account enumeration)."
    accepts = {EntityType.EMAIL}
    env_key = "OSINT_ENABLE_HOLEHE"  # disabled unless explicitly enabled
    timeout = 150.0

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        modules = _load_holehe_modules()
        if not modules:
            result.error = "holehe not installed"
            return result

        sem = asyncio.Semaphore(_CONCURRENCY)
        out: list[dict] = []

        async with client(_PER_MODULE_TIMEOUT) as http:
            async def run_module(fn) -> None:
                async with sem:
                    try:
                        await asyncio.wait_for(fn(entity.value, http, out), timeout=_PER_MODULE_TIMEOUT)
                    except Exception:
                        pass  # per-site failure/timeout is normal

            await asyncio.gather(*(run_module(fn) for fn in modules))

        hits = []
        rate_limited = 0
        for r in out:
            if r.get("rateLimit"):
                rate_limited += 1
                continue
            if r.get("exists") is True:
                hits.append({
                    "site": r.get("name"),
                    "domain": r.get("domain"),
                    "recovery_email": r.get("emailrecovery"),
                    "recovery_phone": r.get("phoneNumber"),
                })

        if not hits:
            if rate_limited:
                result.error = f"all {rate_limited} responsive sites rate-limited this IP"
            return result

        hits.sort(key=lambda h: (h.get("site") or ""))
        note = f"Registered on {len(hits)} site(s) via email enumeration"
        if rate_limited:
            note += f" ({rate_limited} sites rate-limited, unknown)"
        result.findings.append(
            Finding(self.name, entity, note, data={"count": len(hits), "sites": hits},
                    severity=Severity.MEDIUM)
        )
        return result
