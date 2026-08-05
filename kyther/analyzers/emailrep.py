"""Email reputation + linked profiles via EmailRep.io. OPT-IN (needs key).

EmailRep summarises what's publicly known about an email: reputation, whether
it's been seen in breaches / on suspicious infra, and which online profiles it's
associated with. The unauthenticated API was retired, so this is disabled unless
EMAILREP_API_KEY is set (free keys available at emailrep.io).
"""
from __future__ import annotations

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Confidence, Entity, EntityType, Finding, Severity
from ..core.registry import register
from ._http import client


@register
class EmailRep(Analyzer):
    name = "emailrep"
    description = "Email reputation and associated profiles (EmailRep.io)."
    accepts = {EntityType.EMAIL}
    env_key = "EMAILREP_API_KEY"

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        headers = {"Key": self.api_key or "", "User-Agent": "kyther"}
        async with client(self.timeout) as http:
            resp = await http.get(f"https://emailrep.io/{entity.value}", headers=headers)
            if resp.status_code != 200:
                result.error = f"emailrep HTTP {resp.status_code}"
                return result
            d = resp.json()

        details = d.get("details") or {}
        # Data-dependent confidence: a breach/suspicious flag is a strong signal
        # (PROBABLE); a clean reputation record is only a weak association (POSSIBLE).
        flagged = bool(d.get("suspicious") or details.get("data_breach"))
        result.findings.append(
            Finding(
                self.name, entity,
                f"Reputation: {d.get('reputation', 'unknown')}"
                + (" (suspicious)" if d.get("suspicious") else ""),
                data={
                    "reputation": d.get("reputation"),
                    "suspicious": d.get("suspicious"),
                    "references": d.get("references"),
                    "profiles": details.get("profiles"),
                    "credentials_leaked": details.get("credentials_leaked"),
                    "data_breach": details.get("data_breach"),
                },
                severity=Severity.HIGH if d.get("suspicious") else Severity.INFO,
                confidence=Confidence.PROBABLE if flagged else Confidence.POSSIBLE,
            )
        )
        return result
