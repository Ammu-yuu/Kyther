"""Username presence across 700+ platforms via the WhatsMyName dataset. Keyless.

WhatsMyName (github.com/WebBreacher/WhatsMyName) is a community-maintained list
where each site carries a *positive* detection rule: an `e_string` that only
appears on a page when the account genuinely exists, plus the `e_code` status to
expect. Requiring that exact string be present is far more reliable than the old
"error message absent" guessing — it removes the flightradar-style false
positives and, with 700+ curated sites, improves coverage at the same time.
"""
from __future__ import annotations

import asyncio
import json
import secrets
from pathlib import Path

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding
from ..core.registry import register
from ._http import client

_SITES = json.loads(
    (Path(__file__).parent.parent / "data" / "whatsmyname.json").read_text()
)["sites"]
_CONCURRENCY = 60
_PER_SITE_TIMEOUT = 6.0


@register
class UsernameAnalyzer(Analyzer):
    name = "username"
    description = "Check a username across 700+ platforms (WhatsMyName positive-match detection)."
    accepts = {EntityType.USERNAME}
    timeout = 120.0

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        sem = asyncio.Semaphore(_CONCURRENCY)
        control = "zq" + secrets.token_hex(7)  # improbable handle, for verification

        async with client(_PER_SITE_TIMEOUT) as http:
            async def matches(site: dict, username: str) -> bool:
                url = site["uri_check"].replace("{account}", username)
                try:
                    resp = await http.get(url)
                except Exception:
                    return False
                if resp.status_code != site.get("e_code", 200):
                    return False
                e_string = site.get("e_string") or ""
                return not e_string or e_string in resp.text

            # Pass 1: positive match of the real handle across every site.
            async def probe(site: dict):
                async with sem:
                    return site if await matches(site, entity.value) else None

            hits = [s for s in await asyncio.gather(*(probe(s) for s in _SITES)) if s]

            # Pass 2: re-check each hit with a random handle. If the site "matches"
            # that too, its marker is unreliable -> drop it (kills false positives
            # like flightradar without touching genuine hits).
            async def verify(site: dict):
                async with sem:
                    return site if not await matches(site, control) else None

            confirmed = [s for s in await asyncio.gather(*(verify(s) for s in hits)) if s]

        if confirmed:
            profiles = sorted(
                ({"platform": s["name"],
                  "url": s["uri_check"].replace("{account}", entity.value),
                  "category": s.get("cat"),
                  "nsfw": "nsfw" in (s.get("cat") or "").lower(),
                  # control-probe verified positive match -> trust it
                  "confidence": "confirmed"} for s in confirmed),
                key=lambda f: f["platform"].lower(),
            )
            discarded = len(hits) - len(confirmed)
            note = f"Found on {len(profiles)} of {len(_SITES)} platforms"
            if discarded:
                note += f" ({discarded} unreliable dropped)"
            result.findings.append(
                Finding(
                    self.name, entity, note,
                    data={"count": len(profiles), "checked": len(_SITES),
                          "discarded": discarded, "profiles": profiles},
                )
            )
        return result
