"""Passive HTTP fingerprint of a domain. Keyless.

Fetches the site root and records status, server/tech headers, and page title.
Read-only GET of a public homepage — no crawling, no auth, no fuzzing.
"""
from __future__ import annotations

import re

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding, Severity
from ..core.netguard import BlockedTargetError, safe_get
from ..core.registry import register

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_INTERESTING_HEADERS = [
    "server", "x-powered-by", "via", "x-generator",
    "content-type", "strict-transport-security",
]


@register
class HttpProbeAnalyzer(Analyzer):
    name = "http_probe"
    description = "Fetch a domain's homepage and fingerprint server/tech headers."
    accepts = {EntityType.DOMAIN}

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        try:
            # SSRF guard: refuse targets resolving to private/reserved/metadata
            # addresses, re-validating every redirect hop.
            resp = await safe_get(f"https://{entity.value}/", timeout=self.timeout)
        except BlockedTargetError as exc:
            result.findings.append(
                Finding(
                    self.name, entity,
                    f"Blocked internal target: {entity.value}",
                    data={"reason": str(exc)}, severity=Severity.MEDIUM,
                )
            )
            return result
        except Exception:
            return result  # no reachable web server is a normal outcome

        headers = {h: resp.headers[h] for h in _INTERESTING_HEADERS if h in resp.headers}
        title_match = _TITLE_RE.search(resp.text[:20000])
        title = title_match.group(1).strip()[:200] if title_match else None

        result.findings.append(
            Finding(
                self.name,
                entity,
                f"HTTP {resp.status_code} — {entity.value}",
                data={
                    "status": resp.status_code,
                    "final_url": str(resp.url),
                    "title": title,
                    "headers": headers,
                },
            )
        )
        return result
