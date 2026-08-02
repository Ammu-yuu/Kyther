"""Email-based lookups.

Two analyzers live here:
  * EmailBasic — keyless: extracts the domain (a pivot) and checks Gravatar,
    which exposes a public avatar/profile for an email's MD5 hash.
  * HibpBreach — optional: queries Have I Been Pwned for breach membership.
    Skipped unless HIBP_API_KEY is set (HIBP requires a paid key).
"""
from __future__ import annotations

import hashlib

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding, Severity
from ..core.registry import register
from ._http import client


# Free-mail providers: scanning their infrastructure (subdomains, IPs, ASNs)
# tells you nothing about the person, so we don't pivot the domain for these.
_FREE_MAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "icloud.com", "me.com", "aol.com",
    "proton.me", "protonmail.com", "pm.me", "gmx.com", "mail.com", "zoho.com",
    "yandex.com", "tutanota.com", "fastmail.com",
}


@register
class EmailBasic(Analyzer):
    name = "email_basic"
    description = "Derive an account handle, check Gravatar, and (for custom domains) pivot the domain."
    accepts = {EntityType.EMAIL}

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        local, _, domain = entity.value.partition("@")

        # Treat the local part as a candidate handle so the account sweep runs.
        if local:
            result.discovered.append(Entity.make(EntityType.USERNAME, local, source=self.name))

        # Only pivot the domain when it's a custom/vanity domain — never a big
        # free-mail provider, whose infrastructure is irrelevant noise.
        if domain and domain.lower() not in _FREE_MAIL:
            result.discovered.append(Entity.make(EntityType.DOMAIN, domain, source=self.name))

        md5 = hashlib.md5(entity.value.encode()).hexdigest()
        async with client(self.timeout) as http:
            resp = await http.get(f"https://www.gravatar.com/{md5}.json")
            if resp.status_code == 200:
                result.findings.append(
                    Finding(
                        self.name, entity, "Public Gravatar profile found",
                        data={"profile": f"https://gravatar.com/{md5}", "raw": resp.json()},
                        severity=Severity.LOW,
                    )
                )
        return result


@register
class HibpBreach(Analyzer):
    name = "hibp"
    description = "Check Have I Been Pwned for breach membership (requires key)."
    accepts = {EntityType.EMAIL}
    env_key = "HIBP_API_KEY"

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{entity.value}"
        headers = {"hibp-api-key": self.api_key or "", "User-Agent": "kyther"}
        async with client(self.timeout) as http:
            resp = await http.get(url, headers=headers, params={"truncateResponse": "false"})
            if resp.status_code == 404:
                return result  # not found in any breach
            resp.raise_for_status()
            breaches = resp.json()

        result.findings.append(
            Finding(
                self.name, entity, f"Found in {len(breaches)} breach(es)",
                data={"breaches": [
                    {"name": b.get("Name"), "date": b.get("BreachDate")} for b in breaches
                ]},
                severity=Severity.HIGH,
            )
        )
        return result
