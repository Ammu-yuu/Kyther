"""Subdomain discovery via Certificate Transparency logs (crt.sh). Keyless.

Every TLS cert issued for a name is logged publicly; crt.sh indexes them, so
querying it surfaces subdomains an org has certs for. Each unique subdomain is
emitted as a domain entity to pivot on.
"""
from __future__ import annotations

from ..core.base import Analyzer
from ..core.entities import _DOMAIN_RE, AnalyzerResult, Entity, EntityType, Finding
from ..core.registry import register
from ._http import client

MAX_SUBDOMAINS = 200  # cap the pivot fan-out


@register
class CrtShAnalyzer(Analyzer):
    name = "crtsh"
    description = "Discover subdomains from Certificate Transparency logs."
    accepts = {EntityType.DOMAIN}
    timeout = 25.0  # crt.sh can be slow

    async def run(self, entity: Entity) -> AnalyzerResult:
        url = "https://crt.sh/"
        params = {"q": f"%.{entity.value}", "output": "json"}
        result = AnalyzerResult()

        async with client(self.timeout) as http:
            resp = await http.get(url, params=params)
            if resp.status_code != 200 or not resp.text.strip():
                return result
            rows = resp.json()

        base = entity.value
        suffix = "." + base  # enforce a real label boundary, so "testexample.com" is rejected
        names: set[str] = set()
        cert_dates: list[str] = []
        for row in rows:
            nb = (row.get("not_before") or "").strip()
            if nb:
                cert_dates.append(nb)
            for n in (row.get("name_value") or "").splitlines():
                n = n.strip().lstrip("*.").lower()
                # Must be a syntactically valid domain that is a true subdomain of the base.
                if n.endswith(suffix) and n != base and _DOMAIN_RE.match(n):
                    names.add(n)

        if not names:
            return result

        ordered = sorted(names)[:MAX_SUBDOMAINS]
        data = {"count": len(names), "subdomains": ordered}
        # Certificate Transparency timestamps make a cheap infrastructure
        # timeline: when this name first and most recently appeared in a cert.
        if cert_dates:
            data["first_seen"] = min(cert_dates)
            data["last_seen"] = max(cert_dates)
        result.findings.append(
            Finding(self.name, entity, f"{len(names)} subdomains via CT logs", data=data)
        )
        for n in ordered:
            result.discovered.append(Entity.make(EntityType.DOMAIN, n, source=self.name))
        return result
