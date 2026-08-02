"""Username check using the Sherlock project's site database.

Uses Sherlock's curated `data.json` (413 sites) with its own three detection
methods — status_code, message (a "no such user" string), and response_url
(redirect to an error page). Vendored so it needs no incompatible package
(upstream sherlock-project requires Python 3.10+).

Runs on every username scan alongside WhatsMyName; the two overlap heavily, so
confirmed hits merge into one account list, deduplicated by site host in the UI.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding
from ..core.registry import register
from ._http import client

_SITES = {
    k: v for k, v in
    json.loads((Path(__file__).parent.parent / "data" / "sherlock.json").read_text()).items()
    if isinstance(v, dict)
}
_CONCURRENCY = 50
_PER_SITE_TIMEOUT = 6.0


def _status_ok(code: int) -> bool:
    return 200 <= code < 300


@register
class Sherlock(Analyzer):
    name = "sherlock"
    description = "Username check across Sherlock's 413-site database."
    accepts = {EntityType.USERNAME}
    timeout = 120.0

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        user = entity.value
        sem = asyncio.Semaphore(_CONCURRENCY)
        found: list[dict] = []

        async with client(_PER_SITE_TIMEOUT) as http:
            async def check(name: str, site: dict) -> None:
                rx = site.get("regexCheck")
                if rx and not re.match(rx, user):
                    return  # username can't be valid on this site
                url = site["url"].replace("{}", user)
                try:
                    resp = await http.get(url)
                except Exception:
                    return

                et = site.get("errorType")
                claimed = False
                if et == "status_code":
                    err = site.get("errorCode")
                    if err is not None:
                        err = [err] if isinstance(err, int) else err
                        claimed = resp.status_code not in err
                    else:
                        claimed = _status_ok(resp.status_code)
                elif et == "message":
                    msgs = site.get("errorMsg")
                    msgs = [msgs] if isinstance(msgs, str) else (msgs or [])
                    claimed = not any(m in resp.text for m in msgs)
                elif et == "response_url":
                    err_url = (site.get("errorUrl") or "").replace("{}", user)
                    claimed = _status_ok(resp.status_code) and (not err_url or err_url not in str(resp.url))

                if claimed:
                    found.append({"platform": name, "url": url, "category": "other", "nsfw": False})

            async def guarded(item) -> None:
                async with sem:
                    await check(*item)

            await asyncio.gather(*(guarded(it) for it in _SITES.items()))

        if found:
            found.sort(key=lambda f: f["platform"].lower())
            result.findings.append(
                Finding(
                    self.name, entity,
                    f"Sherlock: found on {len(found)} of {len(_SITES)} sites",
                    data={"count": len(found), "checked": len(_SITES), "profiles": found},
                )
            )
        return result
