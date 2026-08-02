"""Host exposure via Shodan InternetDB. Keyless.

InternetDB is Shodan's free, no-key endpoint: given an IP it returns the open
ports, hostnames, detected software (CPEs), tags, and known CVEs Shodan has
observed. Great for turning a bare IP into an exposure snapshot.
"""
from __future__ import annotations

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding, Severity
from ..core.registry import register
from ._http import client


@register
class ShodanInternetDB(Analyzer):
    name = "shodan_internetdb"
    description = "Open ports, hostnames, software and CVEs for an IP (Shodan InternetDB)."
    accepts = {EntityType.IP}

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        async with client(self.timeout) as http:
            resp = await http.get(f"https://internetdb.shodan.io/{entity.value}")
            if resp.status_code == 404:
                return result  # no data for this IP is normal
            resp.raise_for_status()
            d = resp.json()

        ports = d.get("ports") or []
        vulns = d.get("vulns") or []
        if not ports and not vulns and not d.get("hostnames"):
            return result

        data = {
            "ports": ports,
            "hostnames": d.get("hostnames") or [],
            "software": d.get("cpes") or [],
            "tags": d.get("tags") or [],
            "vulns": vulns,
        }
        result.findings.append(
            Finding(
                self.name, entity,
                f"{len(ports)} open port(s)" + (f", {len(vulns)} known CVE(s)" if vulns else ""),
                data=data,
                severity=Severity.HIGH if vulns else Severity.INFO,
            )
        )
        for host in data["hostnames"]:
            result.discovered.append(Entity.make(EntityType.DOMAIN, host, source=self.name))
        return result
