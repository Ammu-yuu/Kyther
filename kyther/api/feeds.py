"""Security news feed + dedicated Reddit lookup (keyless)."""
from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import APIRouter, Query

from ..cache import TTLCache
from ..net import get_client, sanitize_public_url

router = APIRouter()

_NEWS_CACHE = TTLCache(maxsize=8, name="news")
_NEWS_TTL = 3600  # 1 hour


async def _load_news() -> list[dict]:
    """Fetch + normalise one page of Hacker News stories (single-flight)."""
    r = await get_client().get(
        "https://hn.algolia.com/api/v1/search_by_date",
        params={"tags": "story", "query": "security", "hitsPerPage": "30"},
        timeout=10,
    )
    hits = (r.json() or {}).get("hits", [])
    out = []
    for h in hits:
        title = h.get("title")
        if not title or (h.get("points") or 0) < 2:
            continue
        url = sanitize_public_url(h.get("url")) or f"https://news.ycombinator.com/item?id={h.get('objectID')}"
        source = urlsplit(url).netloc.replace("www.", "") or "ycombinator.com"
        out.append({"title": title, "source": source, "url": url, "ts": h.get("created_at_i")})
    return out[:15]


@router.get("/api/news")
async def news() -> list[dict]:
    """Live security news for the feed (Hacker News, keyless). Cached for 1 hour.

    Concurrent callers share one upstream request; if it fails we keep serving
    the last good page rather than blanking the feed.
    """
    return await _NEWS_CACHE.get_or_load(
        "latest", _load_news, _NEWS_TTL, stale_on_error=True, default=[]
    )


@router.get("/api/reddit")
async def reddit_lookup(u: str = Query(..., min_length=1, max_length=64)) -> dict:
    """Dedicated Reddit OSINT lookup — keyless public dossier for a username."""
    from ..analyzers.reddit import reddit_dossier
    try:
        return await reddit_dossier(u, full=True)
    except Exception as exc:  # never 500 the UI; surface a soft error
        return {"found": False, "error": "fetch_failed", "message": str(exc)}
