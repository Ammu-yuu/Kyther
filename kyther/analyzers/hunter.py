"""Domain -> staff emails via Hunter.io. OPT-IN (needs key).

Hunter's domain-search returns the email addresses it has found for a domain
plus the detected address pattern (e.g. {first}.{last}@). Requires a free/paid
HUNTER_API_KEY, so it's disabled by default. Discovered emails pivot back in.
"""
from __future__ import annotations

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding, Severity
from ..core.registry import register
from ._http import client


@register
class Hunter(Analyzer):
    name = "hunter"
    description = "Find email addresses for a domain (Hunter.io)."
    accepts = {EntityType.DOMAIN}
    env_key = "HUNTER_API_KEY"

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        params = {"domain": entity.value, "api_key": self.api_key or "", "limit": "50"}
        async with client(self.timeout) as http:
            resp = await http.get("https://api.hunter.io/v2/domain-search", params=params)
            if resp.status_code != 200:
                result.error = f"hunter HTTP {resp.status_code}"
                return result
            data = (resp.json() or {}).get("data") or {}

        emails = data.get("emails") or []
        if not emails:
            return result

        found = [
            {"email": e.get("value"), "name": " ".join(filter(None, [e.get("first_name"), e.get("last_name")])) or None,
             "position": e.get("position"), "confidence": e.get("confidence")}
            for e in emails if e.get("value")
        ]
        result.findings.append(
            Finding(
                self.name, entity,
                f"{len(found)} email(s) for {entity.value} (pattern: {data.get('pattern') or 'n/a'})",
                data={"pattern": data.get("pattern"), "emails": found},
                severity=Severity.MEDIUM,
            )
        )
        for e in found:
            result.discovered.append(Entity.make(EntityType.EMAIL, e["email"], source=self.name))
        return result
