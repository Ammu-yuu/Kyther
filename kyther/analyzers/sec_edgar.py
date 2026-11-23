"""US SEC filings for a company via EDGAR full-text search. Keyless.

EDGAR's full-text search covers filings since 2001. A company-name query returns
the entities that filed (with ticker + CIK) and the matching documents — useful
for confirming a company is a US filer and finding its registrant identity.

SEC's fair-access policy asks for a descriptive User-Agent with contact info.
"""
from __future__ import annotations

import re
from urllib.parse import quote_plus

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding
from ..core.registry import register
from ._http import client

_UA = {"User-Agent": "kyther research contact@example.com"}


def _norm(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", str(value or "").lower())).strip()


def _name_matches(name: str, query: str) -> bool:
    """EDGAR full-text hits include filings that merely mention the name."""
    candidate, wanted = _norm(name), _norm(query)
    if not candidate or not wanted:
        return False
    if wanted in candidate or candidate in wanted:
        return True
    wanted_tokens = set(wanted.split())
    return (bool(wanted_tokens) and
            len(wanted_tokens & set(candidate.split())) / len(wanted_tokens) >= 0.6)


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
        ciks: list[str] = []
        tickers: list[str] = []
        recent: list[dict] = []
        for h in hits:
            src = h.get("_source") or {}
            names = [n for n in (src.get("display_names") or [])
                     if _name_matches(n, entity.value)]
            if not names:
                continue  # a filing mentioned the words, but is not this company
            for name in names:
                if name not in filers:
                    filers.append(name)
            hit_ciks = [str(c) for c in (src.get("ciks") or []) if c]
            for cik in hit_ciks:
                if cik not in ciks:
                    ciks.append(cik)
            for ticker in src.get("tickers") or []:
                if ticker and ticker not in tickers:
                    tickers.append(ticker)
            if src.get("file_date"):
                recent.append({
                    "type": src.get("file_type"),
                    "date": src.get("file_date"),
                    "cik": hit_ciks[0] if hit_ciks else None,
                })

        if not filers:
            return result
        result.findings.append(
            Finding(
                self.name, entity,
                f"{len(filers)} SEC filer(s) match “{entity.value}”",
                data={
                    "filers": filers[:8],
                    "ciks": ciks[:8],
                    "tickers": tickers[:8],
                    "recent_filings": recent[:6],
                    "search": f"https://efts.sec.gov/LATEST/search-index?q={q}",
                },
            )
        )
        return result
