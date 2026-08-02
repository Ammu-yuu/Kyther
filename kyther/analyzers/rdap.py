"""Registration data via RDAP (modern, JSON WHOIS). Keyless.

rdap.org bootstraps to the authoritative registry for domains and IPs, so one
endpoint covers both. Returns registrar, key dates, and abuse/registrant
contacts where published.
"""
from __future__ import annotations

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding
from ..core.registry import register
from ._http import client


def _events(obj: dict) -> dict[str, str]:
    return {e.get("eventAction", "?"): e.get("eventDate", "") for e in obj.get("events", [])}


def _entities(obj: dict) -> list[dict]:
    out = []
    for ent in obj.get("entities", []):
        roles = ent.get("roles", [])
        name = ent.get("handle", "")
        # vCard array is a nested list; pull the "fn" (full name) if present.
        for item in ent.get("vcardArray", [None, []])[1]:
            if item and item[0] == "fn":
                name = item[3]
        out.append({"roles": roles, "name": name})
    return out


@register
class RdapAnalyzer(Analyzer):
    name = "rdap"
    description = "Domain/IP registration data via RDAP (JSON WHOIS)."
    accepts = {EntityType.DOMAIN, EntityType.IP}

    async def run(self, entity: Entity) -> AnalyzerResult:
        kind = "domain" if entity.type == EntityType.DOMAIN else "ip"
        url = f"https://rdap.org/{kind}/{entity.value}"
        result = AnalyzerResult()

        async with client(self.timeout) as http:
            resp = await http.get(url)
            if resp.status_code == 404:
                return result
            resp.raise_for_status()
            obj = resp.json()

        data = {
            "handle": obj.get("handle"),
            "name": obj.get("name") or obj.get("ldhName"),
            "status": obj.get("status"),
            "events": _events(obj),
            "contacts": _entities(obj),
        }
        result.findings.append(
            Finding(self.name, entity, f"RDAP registration for {entity.value}", data=data)
        )

        # Pivot: registrant/registrar org name -> company entity.
        for c in data["contacts"]:
            if c["name"] and "registrant" in [r.lower() for r in c["roles"]]:
                result.discovered.append(
                    Entity.make(EntityType.COMPANY, c["name"], source=self.name)
                )
        return result
