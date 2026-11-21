"""Public job postings from a company's ATS (Greenhouse, Lever). Keyless.

Job ads are rich OSINT: they leak the internal tech stack and tool names, the
company's office locations, and its team structure. Greenhouse and Lever both
expose a company's live postings through public, keyless JSON endpoints keyed
on the company's slug (its name/domain label), so no scraping or key is needed.
"""
from __future__ import annotations

import re

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Confidence, Entity, EntityType, Finding
from ..core.registry import register
from ._http import client

_GREENHOUSE = "https://boards-api.greenhouse.io/v1/boards/{slug}/jobs"
_LEVER = "https://api.lever.co/v0/postings/{slug}?mode=json"
_MAX = 60  # cap postings returned


def _slug(entity: Entity) -> str:
    """Derive an ATS board slug from a company name or domain.

    "Stripe" -> "stripe"; "stripe.com" -> "stripe" (second-level label).
    """
    v = entity.value
    if entity.type == EntityType.DOMAIN:
        v = v.split(".")[0]
    return re.sub(r"[^a-z0-9]", "", v.lower())


@register
class JobsAnalyzer(Analyzer):
    name = "jobs"
    description = "Public job postings (Greenhouse/Lever) — tech stack, offices, teams."
    accepts = {EntityType.COMPANY, EntityType.DOMAIN}
    timeout = 15.0

    async def run(self, entity: Entity) -> AnalyzerResult:
        slug = _slug(entity)
        result = AnalyzerResult()
        if not slug:
            return result

        postings: list[dict] = []
        source: str | None = None
        async with client(self.timeout) as http:
            # --- Greenhouse ---
            try:
                r = await http.get(_GREENHOUSE.format(slug=slug))
                if r.status_code == 200:
                    for j in (r.json() or {}).get("jobs", []):
                        postings.append(
                            {
                                "title": j.get("title"),
                                "location": (j.get("location") or {}).get("name"),
                                "department": None,
                                "url": j.get("absolute_url"),
                                "updated": j.get("updated_at"),
                            }
                        )
                    if postings:
                        source = "greenhouse"
            except Exception:
                pass
            # --- Lever (fallback) ---
            if not postings:
                try:
                    r = await http.get(_LEVER.format(slug=slug))
                    data = r.json() if r.status_code == 200 else None
                    if isinstance(data, list):
                        for j in data:
                            cats = j.get("categories") or {}
                            postings.append(
                                {
                                    "title": j.get("text"),
                                    "location": cats.get("location"),
                                    "department": cats.get("team") or cats.get("department"),
                                    "url": j.get("hostedUrl"),
                                    "updated": None,
                                }
                            )
                        if postings:
                            source = "lever"
                except Exception:
                    pass

        if not postings:
            return result

        # Aggregate the OSINT-relevant signals.
        locations = sorted({p["location"] for p in postings if p.get("location")})
        departments = sorted({p["department"] for p in postings if p.get("department")})
        result.findings.append(
            Finding(
                self.name,
                entity,
                f"{len(postings)} public job postings ({source})",
                data={
                    "source": source,
                    "slug": slug,
                    "count": len(postings),
                    "postings": postings[:_MAX],
                    "locations": locations,
                    "departments": departments,
                },
                confidence=Confidence.CONFIRMED,  # the company's own ATS
            )
        )
        return result
