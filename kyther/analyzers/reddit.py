"""Reddit OSINT for a username — keyless, via public Reddit archives.

Reddit itself now blocks anonymous JSON reads, so — like the Rosint project
(github.com/zuxu4n/Rosint) this mirrors — we read from two public archive
services instead, no API key or OAuth required:

* **Arctic Shift** (arctic-shift.photon-reddit.com) — its ``users/search``
  endpoint returns karma and first/last-activity stats, and ``posts``/
  ``comments`` return the full history (including removed/deleted content).
* **PullPush** (api.pullpush.io) — a fallback archive for posts and comments.

From those we assemble a compact dossier — karma, cake day, most-active
subreddits and posting-time patterns. The heavy fetch lives in
:func:`reddit_dossier`, which ``/api/reddit`` calls directly; the registered
:class:`RedditAnalyzer` reuses it to enrich ordinary username scans.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime, timezone

from ..core.base import Analyzer
from ..core.entities import AnalyzerResult, Entity, EntityType, Finding
from ..core.registry import register
from ._http import client

_ARCTIC = "https://arctic-shift.photon-reddit.com/api"
_PULLPUSH = "https://api.pullpush.io/reddit/search"
_LIMIT = 100  # max page size both archives honour
_WWW = "https://www.reddit.com"


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


async def _arctic_user(http, u: str):
    """Karma + first/last-activity aggregate for a user, or None."""
    try:
        r = await http.get(f"{_ARCTIC}/users/search", params={"author": u})
    except Exception:
        return None
    if r.status_code != 200:
        return None
    items = (r.json() or {}).get("data") or []
    return items[0] if items else None


async def _arctic_list(http, kind: str, u: str):
    """kind in {'posts','comments'} -> list of records (None on transport error)."""
    try:
        r = await http.get(f"{_ARCTIC}/{kind}/search",
                           params={"author": u, "limit": _LIMIT, "sort": "desc"})
    except Exception:
        return None
    if r.status_code != 200:
        return None
    return (r.json() or {}).get("data") or []


async def _pullpush(http, kind: str, u: str):
    """Fallback archive. kind in {'submission','comment'} -> list or None."""
    try:
        r = await http.get(f"{_PULLPUSH}/{kind}/",
                           params={"author": u, "size": _LIMIT, "sort": "desc"})
    except Exception:
        return None
    if r.status_code != 200:
        return None
    return (r.json() or {}).get("data") or []


def _perma(rec: dict) -> str:
    p = rec.get("permalink") or ""
    if p.startswith("/"):
        return _WWW + p
    return p or rec.get("full_link") or rec.get("url") or ""


def _post_rec(p: dict) -> dict:
    return {"title": p.get("title"), "subreddit": p.get("subreddit"),
            "score": p.get("score"), "num_comments": p.get("num_comments"),
            "created": _iso(p.get("created_utc")), "url": _perma(p),
            "link": p.get("url"), "nsfw": bool(p.get("over_18")),
            "flair": p.get("link_flair_text")}


def _cmt_rec(c: dict) -> dict:
    body = (c.get("body") or "").strip().replace("\n", " ")
    return {"body": body[:280] + ("…" if len(body) > 280 else ""),
            "subreddit": c.get("subreddit"), "score": c.get("score"),
            "created": _iso(c.get("created_utc")), "url": _perma(c),
            "link_title": c.get("link_title")}


async def reddit_dossier(username: str, full: bool = False) -> dict:
    """Assemble a public Reddit dossier for ``username`` from the archives.

    Keyless. Returns ``{"found": False, ...}`` when no archived activity exists.
    With ``full=True`` the dossier carries the longer recent-posts/comments
    lists for the UI; the lighter default is what scans embed.
    """
    u = normalize_username(username)
    if not u:
        return {"found": False, "error": "empty", "message": "Enter a Reddit username."}

    async with client(15.0) as http:
        meta, posts, comments = await asyncio.gather(
            _arctic_user(http, u),
            _arctic_list(http, "posts", u),
            _arctic_list(http, "comments", u),
        )
        source = "Arctic Shift"
        # If Arctic Shift's history calls both failed, fall back to PullPush.
        if posts is None and comments is None:
            posts, comments = await asyncio.gather(
                _pullpush(http, "submission", u),
                _pullpush(http, "comment", u),
            )
            source = "PullPush"

    posts = posts or []
    comments = comments or []
    if not meta and not posts and not comments:
        return {"found": False, "username": u,
                "message": f"No archived Reddit activity for u/{u}. The public archives "
                           "may not have indexed this account, or it has no posts/comments."}

    post_recs = [_post_rec(p) for p in posts]
    cmt_recs = [_cmt_rec(c) for c in comments]

    # Where and when they're active, across everything we fetched.
    sub_counter: Counter = Counter()
    hours = [0] * 24
    weekdays = [0] * 7
    for it in posts + comments:
        s = it.get("subreddit")
        if s:
            sub_counter[s] += 1
        d = _dt(it.get("created_utc"))
        if d:
            hours[d.hour] += 1
            weekdays[d.weekday()] += 1
    top_subs = [{"subreddit": s, "count": n} for s, n in sub_counter.most_common(12)]

    m = (meta or {}).get("_meta") or {}
    # Cake day: earliest known activity (from meta if present, else our sample).
    fetched_created = [_dt(it.get("created_utc")) for it in posts + comments]
    fetched_created = [d for d in fetched_created if d]
    earliest_epochs = [e for e in (m.get("earliest_post_at"), m.get("earliest_comment_at")) if e]
    if earliest_epochs:
        created = min(earliest_epochs)
    elif fetched_created:
        created = min(fetched_created).timestamp()
    else:
        created = None
    last_epochs = [e for e in (m.get("last_post_at"), m.get("last_comment_at")) if e]
    last_active = max(last_epochs) if last_epochs else (
        max(fetched_created).timestamp() if fetched_created else None)
    cd = _dt(created)
    age_days = (datetime.now(timezone.utc) - cd).days if cd else None

    karma = {"total": m.get("total_karma"), "post": m.get("post_karma"),
             "comment": m.get("comment_karma"), "awardee": None, "awarder": None}
    total_posts = m.get("num_posts")
    total_comments = m.get("num_comments")

    dossier = {
        "found": True,
        "username": (meta or {}).get("author") or u,
        "url": f"{_WWW}/user/{u}",
        "id": (meta or {}).get("id"),
        "source": source,
        "avatar": None,          # archives don't carry profile media
        "created": _date(created),
        "created_iso": _iso(created),
        "age_days": age_days,
        "last_active": _date(last_active),
        "karma": karma,
        "karma_known": any(v is not None for v in (karma["total"], karma["post"], karma["comment"])),
        "flags": {},             # archives don't expose gold/mod/verified flags
        "bio": None,
        "trophies": [],
        "counts": {
            "posts_fetched": len(posts), "comments_fetched": len(comments),
            "posts_total": total_posts, "comments_total": total_comments,
            "posts_capped": len(posts) >= _LIMIT, "comments_capped": len(comments) >= _LIMIT,
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
    description = "Public Reddit OSINT for a username (keyless, via Arctic Shift / PullPush archives)."
    accepts = {EntityType.USERNAME}
    timeout = 30.0

    async def run(self, entity: Entity) -> AnalyzerResult:
        result = AnalyzerResult()
        try:
            d = await reddit_dossier(entity.value, full=False)
        except Exception:
            return result
        if not d.get("found"):
            return result
        k = d.get("karma") or {}
        karma = k.get("total")
        bits = [f"cake day {d.get('created')}"] if d.get("created") else []
        if karma is not None:
            bits.insert(0, f"{karma} karma")
        title = f"Reddit u/{d['username']}" + (" — " + ", ".join(bits) if bits else "")
        result.findings.append(Finding(self.name, entity, title, data=d))
        return result
