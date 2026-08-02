"""DNS records for a domain. Keyless.

Resolves the common record types and pivots: A/AAAA -> IP entities,
MX/NS -> domain entities.
"""
from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.resolver

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding
from ..core.registry import register

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


@register
class DnsAnalyzer(Analyzer):
    name = "dns"
    description = "Resolve common DNS record types for a domain."
    accepts = {EntityType.DOMAIN}

    async def run(self, entity: Entity) -> AnalyzerResult:
        resolver = dns.asyncresolver.Resolver()
        result = AnalyzerResult()
        records: dict[str, list[str]] = {}

        async def query(rtype: str) -> None:
            try:
                answer = await resolver.resolve(entity.value, rtype)
                records[rtype] = [r.to_text() for r in answer]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass

        await asyncio.gather(*(query(rt) for rt in _RECORD_TYPES))

        if not records:
            return result

        result.findings.append(
            Finding(self.name, entity, f"DNS records for {entity.value}", data=records)
        )

        for ip in records.get("A", []) + records.get("AAAA", []):
            result.discovered.append(Entity.make(EntityType.IP, ip, source=self.name))
        for mx in records.get("MX", []):
            host = mx.split()[-1].rstrip(".")  # "10 mail.example.com."
            if host:
                result.discovered.append(Entity.make(EntityType.DOMAIN, host, source=self.name))
        for ns in records.get("NS", []):
            host = ns.rstrip(".")
            if host:
                result.discovered.append(Entity.make(EntityType.DOMAIN, host, source=self.name))

        return result
