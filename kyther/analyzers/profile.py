"""Profile enrichment for a username. Keyless (public profile JSON).

Existence checks tell you *where* an account is; this tells you *who's behind
it*. For platforms that expose structured public profile data, we pull the real
fields — display name, bio, location, avatar, links, join date — and normalise
them into a common shape the API layer folds into a person dossier.

Keybase is especially valuable: its `proofs` are user-verified links between a
handle and their other accounts (Twitter, GitHub, websites…), which is real
identity correlation rather than guesswork.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding
from ..core.registry import register
from ._http import client

_IG_APP_ID = "936619743392459"  # Instagram's public web app id


def _epoch(ts) -> str | None:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).date().isoformat()
    except Exception:
        return None


def _profile(platform, **kw) -> dict:
    """Normalised profile record; drops empty fields."""
    rec = {"platform": platform}
    rec.update({k: v for k, v in kw.items() if v})
    return rec


async def _github(http, u):
    r = await http.get(f"https://api.github.com/users/{u}")
    if r.status_code != 200:
        return None
    d = r.json()
    links = [d.get("blog")] if d.get("blog") else []
    if d.get("twitter_username"):
        links.append(f"https://twitter.com/{d['twitter_username']}")
    return _profile("GitHub", display_name=d.get("name"), bio=d.get("bio"),
                    location=d.get("location"), company=d.get("company"),
                    avatar=d.get("avatar_url"), url=d.get("html_url"),
                    email=d.get("email"),  # public profile email (set manually, ≠ commit email)
                    joined=(d.get("created_at") or "")[:10] or None, links=links)


async def _reddit(http, u):
    r = await http.get(f"https://www.reddit.com/user/{u}/about.json")
    if r.status_code != 200:
        return None
    d = (r.json() or {}).get("data") or {}
    sub = d.get("subreddit") or {}
    return _profile("Reddit", display_name=sub.get("title") or d.get("name"),
                    bio=sub.get("public_description"),
                    avatar=(d.get("icon_img") or "").split("?")[0] or None,
                    url=f"https://www.reddit.com/user/{u}", joined=_epoch(d.get("created_utc")))


async def _keybase(http, u):
    r = await http.get(f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}")
    if r.status_code != 200:
        return None
    them = (r.json() or {}).get("them") or []
    if not them:
        return None
    d = them[0]
    prof = d.get("profile") or {}
    pics = (d.get("pictures") or {}).get("primary") or {}
    proofs = [
        {"service": p.get("proof_type"), "handle": p.get("nametag"), "url": p.get("service_url")}
        for p in ((d.get("proofs_summary") or {}).get("all") or [])
    ]
    return _profile("Keybase", display_name=prof.get("full_name"), bio=prof.get("bio"),
                    location=prof.get("location"), avatar=pics.get("url"),
                    url=f"https://keybase.io/{u}", joined=_epoch((d.get("basics") or {}).get("ctime")),
                    linked_accounts=proofs)


async def _hackernews(http, u):
    r = await http.get(f"https://hacker-news.firebaseio.com/v0/user/{u}.json")
    if r.status_code != 200 or r.text.strip() in ("", "null"):
        return None
    d = r.json() or {}
    if not d.get("id"):
        return None
    return _profile("HackerNews", bio=d.get("about"), url=f"https://news.ycombinator.com/user?id={u}",
                    joined=_epoch(d.get("created")), karma=d.get("karma"))


async def _instagram(http, u):
    r = await http.get(
        f"https://i.instagram.com/api/v1/users/web_profile_info/?username={u}",
        headers={"x-ig-app-id": _IG_APP_ID},
    )
    if r.status_code != 200:
        return None
    user = ((r.json() or {}).get("data") or {}).get("user")
    if not user:
        return None
    return _profile("Instagram", display_name=user.get("full_name"),
                    bio=user.get("biography"), avatar=user.get("profile_pic_url_hd"),
                    url=f"https://www.instagram.com/{u}/",
                    links=[user.get("external_url")] if user.get("external_url") else [],
                    followers=(user.get("edge_followed_by") or {}).get("count"),
                    verified=user.get("is_verified"))


@register
class ProfileEnrich(Analyzer):
    name = "profile_enrich"
    description = "Pull real profile details (name, bio, location, links) from public APIs."
    accepts = {EntityType.USERNAME}
    timeout = 30.0

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        sources = [_github, _reddit, _keybase, _hackernews, _instagram]

        async with client(10.0) as http:
            async def fetch(fn):
                try:
                    return await fn(http, entity.value)
                except Exception:
                    return None
            profiles = await asyncio.gather(*(fetch(fn) for fn in sources))

        for p in profiles:
            if not p:
                continue
            result.findings.append(
                Finding(self.name, entity, f"{p['platform']} profile", data=p)
            )
        return result
