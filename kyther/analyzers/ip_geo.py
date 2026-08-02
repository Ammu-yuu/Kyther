"""IP geolocation + network ownership via ip-api.com. Keyless (rate-limited).

Free tier is HTTP-only and ~45 req/min; fine for interactive scans. Emits the
hosting org as a company entity and the ASN as its own entity.
"""
from __future__ import annotations

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding
from ..core.registry import register
from ._http import client

_FIELDS = "status,message,country,regionName,city,lat,lon,isp,org,as,asname,reverse,query"


@register
class IpGeoAnalyzer(Analyzer):
    name = "ip_geo"
    description = "Geolocation and network ownership for an IP address."
    accepts = {EntityType.IP}

    async def run(self, entity: Entity) -> AnalyzerResult:
        url = f"http://ip-api.com/json/{entity.value}"
        result = AnalyzerResult()

        async with client(self.timeout) as http:
            resp = await http.get(url, params={"fields": _FIELDS})
            resp.raise_for_status()
            obj = resp.json()

        if obj.get("status") != "success":
            result.error = obj.get("message", "lookup failed")
            return result

        result.findings.append(
            Finding(self.name, entity, f"Geolocation for {entity.value}", data=obj)
        )

        if obj.get("org"):
            result.discovered.append(Entity.make(EntityType.COMPANY, obj["org"], source=self.name))
        if obj.get("as"):
            asn = obj["as"].split()[0]  # "AS15169 Google LLC"
            if asn.upper().startswith("AS"):
                result.discovered.append(Entity.make(EntityType.ASN, asn, source=self.name))
        return result
