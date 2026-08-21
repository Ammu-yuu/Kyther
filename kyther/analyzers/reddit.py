"""Reddit OSINT for a username — public data, keyless (rosint.dev-style).

Reddit publishes every user's activity as public JSON: their profile
(``about.json``), submitted posts, comments and trophies. From those four
endpoints we assemble a compact dossier — karma breakdown, cake day, the
subreddits they're most active in and when they post — the same signals a
Reddit-focused OSINT lookup surfaces, with no API key.

The heavy fetch lives in :func:`reddit_dossier`, which the ``/api/reddit``
endpoint calls directly for the dedicated Reddit section. The registered
:class:`RedditAnalyzer` reuses it to lightly enrich ordinary username scans.
"""
from __future__ import annotations

import os
import time
from collections import Counter
from datetime import datetime, timezone

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding
from ..core.registry import register
from ._http import client

_BASE = "https://www.reddit.com"
_OAUTH = "https://oauth.reddit.com"
_LIMIT = 100  # Reddit's max page size for listings
# Reddit requires a unique, descriptive User-Agent and (now) OAuth for JSON.
_UA = "kyther/0.2 (OSINT research; +https://github.com/Ammu-yuu/Kyther)"
_ENV_KEY = "REDDIT_CLIENT_ID"  # free "installed app" client id — no secret needed

# App-only bearer token, cached in-process until it nears expiry.
_TOKEN: dict = {"value": None, "exp": 0.0}


async def _app_token(http, client_id: str) -> str | None:
    """Fetch/refresh an app-only OAuth token (installed-client grant, keyless)."""
    now = time.time()
    if _TOKEN["value"] and now < _TOKEN["exp"] - 30:
        return _TOKEN["value"]
    r = await http.post(
        f"{_BASE}/api/v1/access_token",
        data={"grant_type": "https://oauth.reddit.com/grants/installed_client",
              "device_id": "DO_NOT_TRACK_THIS_DEVICE"},
        auth=(client_id, ""),
        headers={"User-Agent": _UA},
    )
    if r.status_code != 200:
        return None
    tok = (r.json() or {}).get("access_token")
    if tok:
        _TOKEN.update(value=tok, exp=now + float((r.json() or {}).get("expires_in", 3600)))
    return tok


async def _fetch_user(http, u: str, token: str | None):
    """Pull about/submitted/comments/trophies via OAuth when we have a token,
    else best-effort public JSON. Raises RuntimeError('blocked'|'rate_limited')."""
    if token:
        base, suffix = _OAUTH, ""
        trophies_path = f"/api/v1/user/{u}/trophies"
        headers = {"User-Agent": _UA, "Authorization": f"Bearer {token}"}
    else:
        base, suffix = _BASE, ".json"
        trophies_path = f"/user/{u}/trophies.json"
        headers = {"User-Agent": _UA}

    async def g(path: str, **params):
        r = await http.get(base + path, params={**params, "raw_json": 1}, headers=headers)
        if r.status_code == 429:
            raise RuntimeError("rate_limited")
        if r.status_code in (401, 403):
            raise RuntimeError("blocked")
        if r.status_code != 200:
            return None  # 404 etc. -> genuinely absent
        try:
            return r.json()
        except Exception:
            return None

    about = await g(f"/user/{u}/about{suffix}")
    submitted = await g(f"/user/{u}/submitted{suffix}", limit=_LIMIT, sort="new")
    comments = await g(f"/user/{u}/comments{suffix}", limit=_LIMIT, sort="new")
    trophies = await g(trophies_path)
    return about, submitted, comments, trophies


def _dt(ts) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except Exception:
        return None


def _date(ts) -> str | None:
    d = _dt(ts)
    return d.date().isoformat() if d else None


def _iso(ts) -> str | None:
    d = _dt(ts)
    return d.isoformat() if d else None


def normalize_username(raw: str) -> str:
    """Accept a bare handle, ``u/name``, ``user/name`` or a full profile URL."""
    u = (raw or "").strip()
    low = u.lower()
    for pre in ("https://www.reddit.com/", "https://reddit.com/",
                "http://www.reddit.com/", "www.reddit.com/", "reddit.com/"):
        if low.startswith(pre):
            u = u[len(pre):]
            break
    u = u.strip("/")
    for pre in ("user/", "u/"):
        if u.lower().startswith(pre):
            u = u[len(pre):]
            break
    return u.split("/")[0].split("?")[0].lstrip("@")


def _children(listing) -> list[dict]:
    return [c.get("data", {}) for c in ((listing or {}).get("data", {}) or {}).get("children", [])]


async def reddit_dossier(username: str, full: bool = False) -> dict:
    """Fetch and assemble a public Reddit dossier for ``username``.

    Returns ``{"found": False, ...}`` when there's no such public account, or a
    ``rate_limited`` marker when Reddit throttles us. With ``full=True`` the
    dossier carries the longer recent-posts/comments lists for the UI; the
    lighter default is what scans embed.
    """
    u = normalize_username(username)
    if not u:
        return {"found": False, "error": "empty", "message": "Enter a Reddit username."}

    client_id = os.environ.get(_ENV_KEY)
    async with client(12.0) as http:
        token = None
        if client_id:
            try:
                token = await _app_token(http, client_id)
            except Exception:
                token = None
            if not token:
                return {"found": False, "error": "auth_failed", "username": u,
                        "message": f"{_ENV_KEY} is set but Reddit rejected it — confirm the client ID is "
                                   "from a Reddit app of type 'installed app'."}
        try:
            about, submitted, comments, trophies = await _fetch_user(http, u, token)
        except RuntimeError as e:
            if str(e) == "rate_limited":
                return {"found": False, "error": "rate_limited", "username": u,
                        "message": "Reddit is rate-limiting requests right now — try again in a minute."}
            # blocked (401/403): unauthenticated JSON is no longer allowed
            msg = ("Reddit blocked the request even with credentials — try again shortly."
                   if client_id else
                   "Reddit no longer allows anonymous profile reads. Set a free "
                   f"{_ENV_KEY} (Reddit → preferences → apps → create an 'installed app', "
                   "copy the id under the app name) and restart the server.")
            return {"found": False, "error": "blocked", "username": u, "needs_key": not client_id,
                    "message": msg}

    data = (about or {}).get("data") or {}
    if not about or not data:
        return {"found": False, "username": u,
                "message": f"No public Reddit account named u/{u} (it may be private, banned, or misspelled)."}
    if data.get("is_suspended"):
        return {"found": True, "suspended": True, "username": data.get("name") or u,
                "url": f"{_BASE}/user/{u}",
                "message": f"u/{u} is suspended — profile data is unavailable."}

    sub = data.get("subreddit") or {}
    posts = _children(submitted)
    cmts = _children(comments)

    def _post_rec(p: dict) -> dict:
        return {"title": p.get("title"), "subreddit": p.get("subreddit"),
                "score": p.get("score"), "num_comments": p.get("num_comments"),
                "created": _iso(p.get("created_utc")),
                "url": _BASE + (p.get("permalink") or ""),
                "link": p.get("url"), "nsfw": bool(p.get("over_18")),
                "flair": p.get("link_flair_text")}

    def _cmt_rec(c: dict) -> dict:
        body = (c.get("body") or "").strip().replace("\n", " ")
        return {"body": body[:280] + ("…" if len(body) > 280 else ""),
                "subreddit": c.get("subreddit"), "score": c.get("score"),
                "created": _iso(c.get("created_utc")),
                "url": _BASE + (c.get("permalink") or ""),
                "link_title": c.get("link_title")}

    post_recs = [_post_rec(p) for p in posts]
    cmt_recs = [_cmt_rec(c) for c in cmts]

    # Aggregate where and when they're active, across posts + comments.
    sub_counter: Counter = Counter()
    hours = [0] * 24
    weekdays = [0] * 7
    for it in posts + cmts:
        s = it.get("subreddit")
        if s:
            sub_counter[s] += 1
        d = _dt(it.get("created_utc"))
        if d:
            hours[d.hour] += 1
            weekdays[d.weekday()] += 1
    top_subs = [{"subreddit": s, "count": n} for s, n in sub_counter.most_common(12)]

    created = data.get("created_utc")
    cd = _dt(created)
    age_days = (datetime.now(timezone.utc) - cd).days if cd else None

    trophy_names = [t.get("data", {}).get("name")
                    for t in ((trophies or {}).get("data", {}) or {}).get("trophies", [])]
    trophy_names = [t for t in trophy_names if t]

    dossier = {
        "found": True,
        "username": data.get("name") or u,
        "url": f"{_BASE}/user/{u}",
        "id": data.get("id"),
        "avatar": (data.get("snoovatar_img") or data.get("icon_img") or "").split("?")[0] or None,
        "created": _date(created),
        "created_iso": _iso(created),
        "age_days": age_days,
        "karma": {
            "total": data.get("total_karma"),
            "post": data.get("link_karma"),
            "comment": data.get("comment_karma"),
            "awardee": data.get("awardee_karma"),
            "awarder": data.get("awarder_karma"),
        },
        "flags": {
            "gold": bool(data.get("is_gold")),
            "mod": bool(data.get("is_mod")),
            "employee": bool(data.get("is_employee")),
            "verified": bool(data.get("verified")),
            "verified_email": bool(data.get("has_verified_email")),
            "nsfw": bool(sub.get("over_18")),
        },
        "bio": sub.get("public_description") or None,
        "profile_title": sub.get("title") or None,
        "trophies": trophy_names,
        "counts": {
            "posts_fetched": len(posts), "comments_fetched": len(cmts),
            "posts_capped": len(posts) >= _LIMIT, "comments_capped": len(cmts) >= _LIMIT,
        },
        "top_subreddits": top_subs,
        "activity_by_hour": hours,
        "activity_by_weekday": weekdays,
        "nsfw_posts": sum(1 for p in posts if p.get("over_18")),
    }
    limit = 40 if full else 5
    dossier["recent_posts"] = post_recs[:limit]
    dossier["recent_comments"] = cmt_recs[:limit]
    return dossier


@register
class RedditAnalyzer(Analyzer):
    name = "reddit"
    description = "Public Reddit OSINT for a username — karma, cake day, top subreddits, activity."
    accepts = {EntityType.USERNAME}
    env_key = _ENV_KEY  # Reddit requires a free app client id; skip scans without one
    timeout = 25.0

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        try:
            d = await reddit_dossier(entity.value, full=False)
        except Exception:
            return result
        if not d.get("found") or d.get("suspended"):
            return result
        k = d.get("karma") or {}
        title = f"Reddit u/{d['username']} — {k.get('total') or 0} karma, cake day {d.get('created')}"
        result.findings.append(Finding(self.name, entity, title, data=d))
        return result
