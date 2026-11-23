"""Public job postings from a company's ATS (Greenhouse, Lever). Keyless.

Job ads are rich OSINT: they leak the internal tech stack and tool names, the
company's office locations, and its team structure. Greenhouse and Lever both
expose a company's live postings through public, keyless JSON endpoints keyed
on the company's slug (its name/domain label), so no scraping or key is needed.
"""
from __future__ import annotations

import asyncio
import html
import re
from collections import Counter

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Confidence, Entity, EntityType, Finding
from ..core.registry import register
from ..net import sanitize_public_url
from ._http import client

_GREENHOUSE = "https://boards-api.greenhouse.io/v1/boards/{slug}/jobs"
_GREENHOUSE_DETAIL = "https://boards-api.greenhouse.io/v1/boards/{slug}/jobs/{job_id}"
_LEVER = "https://api.lever.co/v0/postings/{slug}?mode=json"
_MAX = 60  # cap postings returned

# Job descriptions are unusually good tech-stack intel. Match a small, explicit
# catalogue rather than trying to infer meaning from arbitrary prose.
_TECH_PATTERNS = {
    "AWS": r"\baws\b|amazon web services",
    "Azure": r"\bazure\b",
    "GCP": r"\bgcp\b|google cloud",
    "Kubernetes": r"\bkubernetes\b|\bk8s\b",
    "Docker": r"\bdocker\b",
    "Terraform": r"\bterraform\b",
    "Python": r"\bpython\b",
    "Go": r"\bgolang\b|\bgo lang\b|\bgo\b",
    "Rust": r"\brust\b",
    "Java": r"\bjava\b",
    "TypeScript": r"\btypescript\b",
    "React": r"\breact(\.js)?\b",
    "Node.js": r"\bnode(\.js)?\b",
    "GraphQL": r"\bgraphql\b",
    "PostgreSQL": r"\bpostgres(ql)?\b",
    "MySQL": r"\bmysql\b",
    "MongoDB": r"\bmongodb\b",
    "Redis": r"\bredis\b",
    "Kafka": r"\bkafka\b",
    "TensorFlow": r"\btensorflow\b",
    "PyTorch": r"\bpytorch\b",
    "Salesforce": r"\bsalesforce\b",
    "SAP": r"\bsap\b",
}


_TAG_RE = re.compile(r"<[^>]+>")


def _plain_text(value, limit: int = 700) -> str:
    """Strip HTML from a job description; cap only the displayed snippet."""
    text = _TAG_RE.sub(" ", str(value or ""))
    plain = re.sub(r"\s+", " ", html.unescape(text)).strip()
    return plain[:limit] if limit else plain


def _skills(value) -> list[str]:
    text = _plain_text(value, limit=0).lower()
    return sorted(name for name, pattern in _TECH_PATTERNS.items()
                  if re.search(pattern, text))[:24]


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
                        description = j.get("content") or ""
                        postings.append(
                            {
                                "id": j.get("id"),
                                "title": j.get("title"),
                                "location": (j.get("location") or {}).get("name"),
                                "department": None,
                                "url": sanitize_public_url(j.get("absolute_url")),
                                "updated": j.get("updated_at"),
                                "summary": _plain_text(description),
                                "skills": _skills(description),
                            }
                        )
                    if postings:
                        source = "greenhouse"
            except Exception:
                pass

            # Greenhouse's list endpoint omits descriptions. Fetch a small,
            # bounded number of job details so the tech stack is still visible.
            if source == "greenhouse":
                async def _detail(posting: dict) -> None:
                    if posting.get("skills") or not posting.get("id"):
                        return
                    try:
                        detail = await http.get(_GREENHOUSE_DETAIL.format(
                            slug=slug, job_id=posting["id"]))
                        if detail.status_code == 200:
                            description = (detail.json() or {}).get("content") or ""
                            posting["summary"] = _plain_text(description)
                            posting["skills"] = _skills(description)
                    except Exception:
                        pass

                # Prefer engineering/data/security roles: their descriptions
                # actually name the stack, unlike most sales/HR openings.
                tech_titles = ("engineer", "developer", "sre", "site reliability",
                               "machine learning", "data scientist", "data engineer",
                               "security engineer", "solutions architect")
                relevant = [p for p in postings
                            if any(k in str(p.get("title") or "").lower()
                                   for k in tech_titles)][:8] or postings[:6]
                await asyncio.gather(*(_detail(p) for p in relevant),
                                     return_exceptions=True)

            # --- Lever (fallback) ---
            if not postings:
                try:
                    r = await http.get(_LEVER.format(slug=slug))
                    data = r.json() if r.status_code == 200 else None
                    if isinstance(data, list):
                        for j in data:
                            cats = j.get("categories") or {}
                            description = j.get("descriptionPlain") or j.get("description") or ""
                            postings.append(
                                {
                                    "title": j.get("text"),
                                    "location": cats.get("location"),
                                    "department": cats.get("team") or cats.get("department"),
                                    "url": sanitize_public_url(j.get("hostedUrl")),
                                    "updated": None,
                                    "summary": _plain_text(description),
                                    "skills": _skills(description),
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
        skill_counts = Counter(skill for p in postings for skill in (p.get("skills") or []))
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
                    "skills": [{"name": name, "count": count}
                               for name, count in skill_counts.most_common(24)],
                },
                confidence=Confidence.CONFIRMED,  # the company's own ATS
            )
        )
        return result
