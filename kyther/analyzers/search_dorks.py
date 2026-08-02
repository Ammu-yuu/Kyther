"""Investigative search links for people and companies. Keyless, no execution.

Person/company OSINT is hard to automate without paid data brokers (and doing
so raises real privacy/legal issues). Instead of scraping, this analyzer builds
ready-to-click search-engine and public-registry queries the investigator runs
themselves — a lead generator, not an automated harvester.
"""
from __future__ import annotations

from urllib.parse import quote_plus

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding
from ..core.registry import register


def _person_links(name: str) -> dict[str, str]:
    q = quote_plus(f'"{name}"')
    return {
        "Google": f"https://www.google.com/search?q={q}",
        "LinkedIn": f'https://www.google.com/search?q=site:linkedin.com/in+{q}',
        "Filetype PDF/Docs": f'https://www.google.com/search?q={q}+filetype:pdf',
        "Bing": f"https://www.bing.com/search?q={q}",
    }


def _company_links(name: str) -> dict[str, str]:
    q = quote_plus(name)
    return {
        "Google": f"https://www.google.com/search?q={quote_plus(chr(34) + name + chr(34))}",
        "OpenCorporates": f"https://opencorporates.com/companies?q={q}",
        "SEC EDGAR": f"https://efts.sec.gov/LATEST/search-index?q={q}",
        "LinkedIn Company": f"https://www.google.com/search?q=site:linkedin.com/company+{q}",
    }


@register
class SearchDorksAnalyzer(Analyzer):
    name = "search_dorks"
    description = "Generate investigative search links for a person or company."
    accepts = {EntityType.PERSON, EntityType.COMPANY}

    async def run(self, entity: Entity) -> AnalyzerResult:
        links = (
            _person_links(entity.value)
            if entity.type == EntityType.PERSON
            else _company_links(entity.value)
        )
        return AnalyzerResult(
            findings=[
                Finding(
                    self.name, entity,
                    f"Investigative search links for {entity.value}",
                    data={"links": links, "note": "Run these manually; no data is fetched."},
                )
            ]
        )
