"""US SEC filings for a company via EDGAR full-text search. Keyless.

EDGAR's full-text search covers filings since 2001. A company-name query returns
the entities that filed (with ticker + CIK) and the matching documents — useful
for confirming a company is a US filer and finding its registrant identity.

SEC's fair-access policy asks for a descriptive User-Agent with contact info.
"""
from __future__ import annotations

from urllib.parse import quote_plus

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding
from ..core.registry import register
from ._http import client

_UA = {"User-Agent": "kyther research contact@example.com"}


@register
class SecEdgar(Analyzer):
    name = "sec_edgar"
    description = "Find US SEC filings and filer identity for a company (EDGAR)."
    accepts = {EntityType.COMPANY}

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        q = quote_plus(f'"{entity.value}"')
        async with client(self.timeout) as http:
            resp = await http.get(f"https://efts.sec.gov/LATEST/search-index?q={q}", headers=_UA)
            if resp.status_code != 200:
                return result
            hits = (resp.json().get("hits") or {}).get("hits") or []

        if not hits:
            return result

        filers: list[str] = []
        recent: list[dict] = []
        for h in hits:
            src = h.get("_source") or {}
            for name in src.get("display_names") or []:
                if name not in filers:
                    filers.append(name)
            if src.get("file_date"):
                recent.append({"type": src.get("file_type"), "date": src.get("file_date")})

        result.findings.append(
            Finding(
                self.name, entity,
                f"{len(filers)} SEC filer(s) match “{entity.value}”",
                data={
                    "filers": filers[:8],
                    "recent_filings": recent[:6],
                    "search": f"https://efts.sec.gov/LATEST/search-index?q={q}",
                },
            )
        )
        return result
