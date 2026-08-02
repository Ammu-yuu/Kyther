"""Email discovery from public GitHub commit metadata. Keyless.

Every git commit records the author's name + email. GitHub's events API no
longer includes commit details, but the per-repo commits API still does — so we
list the user's recently-pushed repos and read the author/committer email off
their commits (matched by GitHub login so we don't attribute a collaborator's
address). Developers routinely leak their real personal email this way unless
they've enabled the noreply address. This reads only already-public data.

Unauthenticated GitHub API allows ~60 requests/hour per IP; we cap the work at a
handful of repos so one lookup stays well within budget.
"""
from __future__ import annotations

import asyncio

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding, Severity
from ..core.registry import register
from ._http import client

_MAX_REPOS = 5      # keep API calls modest against the 60/hr unauth limit
_COMMITS_PER_REPO = 30


def _is_noreply(email: str) -> bool:
    return email.endswith("@users.noreply.github.com") or email.endswith("@noreply.github.com")


@register
class GithubEmails(Analyzer):
    name = "github_emails"
    description = "Extract author emails from a user's public GitHub commits."
    accepts = {EntityType.USERNAME}
    timeout = 20.0

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        user = entity.value
        found: dict[str, dict] = {}

        async with client(self.timeout) as http:
            repos_resp = await http.get(
                f"https://api.github.com/users/{user}/repos",
                params={"sort": "pushed", "per_page": 30, "type": "owner"},
            )
            if repos_resp.status_code != 200:
                return result
            repos = [r["name"] for r in repos_resp.json() if not r.get("fork")][:_MAX_REPOS]
            if not repos:
                return result

            async def scan_repo(repo: str) -> None:
                r = await http.get(
                    f"https://api.github.com/repos/{user}/{repo}/commits",
                    params={"per_page": _COMMITS_PER_REPO},
                )
                if r.status_code != 200:
                    return
                for c in r.json():
                    for role in ("author", "committer"):
                        gh = c.get(role) or {}
                        git = (c.get("commit") or {}).get(role) or {}
                        # Only count the email when the commit's GitHub login is
                        # this user — avoids harvesting collaborators' addresses.
                        if (gh.get("login") or "").lower() != user.lower():
                            continue
                        email = (git.get("email") or "").strip().lower()
                        if not email or "@" not in email:
                            continue
                        rec = found.setdefault(email, {"email": email, "name": git.get("name"),
                                                       "count": 0, "noreply": _is_noreply(email)})
                        rec["count"] += 1

            await asyncio.gather(*(scan_repo(r) for r in repos))

        if not found:
            return result

        emails = sorted(found.values(), key=lambda r: (r["noreply"], -r["count"]))
        personal = [e for e in emails if not e["noreply"]]
        result.findings.append(
            Finding(
                self.name, entity,
                f"{len(personal)} personal email(s) in public commits"
                if personal else f"{len(emails)} GitHub noreply address(es)",
                data={"emails": emails},
                severity=Severity.MEDIUM if personal else Severity.INFO,
            )
        )
        # Pivot real emails back in so they can be checked for breaches/gravatar.
        for e in personal:
            result.discovered.append(Entity.make(EntityType.EMAIL, e["email"], source=self.name))
        return result
