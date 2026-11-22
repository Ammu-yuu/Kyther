"""World Pulse: Wikipedia trending + cross-edition news coverage."""
from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, Query

from ..cache import TTLCache
from ..net import get_client, sanitize_public_url
from .threats import _TI_UA

router = APIRouter()


# ── World Pulse: trending topics + cross-edition news coverage ─
# Keyless. Trending = Wikipedia's most-read articles (fast, reliable). Per-topic
# coverage = Google News RSS from a few country editions. There is no tone or
# sentiment analysis here: this compares *which editions ran stories*, never
# "public opinion" or "framing". Every call has a timeout, one retry and a
# descriptive UA; failures are reported per edition, and a valid zero-result
# feed is reported as zero coverage — not as a source failure.
_GNEWS = "https://news.google.com/rss/search"
_WIKI_TOP = "https://wikimedia.org/api/rest_v1/metrics/pageviews/top/{proj}.wikipedia/all-access/{y}/{m:02d}/{d:02d}"
# Country editions of Google News used to show a topic's "sides" — how the same
# story surfaces in different countries' press (English editions).
PULSE_EDITIONS = {
    "US": {"label": "United States", "hl": "en-US", "gl": "US", "ceid": "US:en"},
    "GB": {"label": "United Kingdom", "hl": "en-GB", "gl": "GB", "ceid": "GB:en"},
    "IN": {"label": "India", "hl": "en-IN", "gl": "IN", "ceid": "IN:en"},
}
_SIDES_ORDER = ["US", "GB", "IN"]
# Bounded + single-flight: ten clients refreshing the same topic share one load.
_PULSE_CACHE = TTLCache(maxsize=64, name="pulse")
_PULSE_TTL = 1800                # 30 min for topics
_TREND_TTL = 3600                # 1 h for trending
# Wikipedia language editions offered as "regions" (language ≈ audience).
PULSE_REGIONS = {"en": "Global (English)", "es": "Spanish", "hi": "Hindi / India",
                 "ar": "Arabic", "fr": "French", "de": "German", "pt": "Portuguese",
                 "ja": "Japanese", "ru": "Russian", "zh": "Chinese"}
_WIKI_SKIP = ("Main_Page", "Special:", "Wikipedia:", "Portal:", "Help:",
              "Category:", "Template:", "File:", "Talk:", "Draft:", "User:")
# Keep trending "general" — drop graphic / adult / gratuitously disturbing reads
# that spike on Wikipedia but aren't what this section is for.
_WIKI_BLOCK = ("cannibal", "pornograph", "onlyfans", "hentai", "incest",
               "bestiality", "pedophil", "molestation", "sex tape", "sextape",
               "revenge porn", "nude", "xxx", "erotic", "brothel", "prostitut",
               "necrophil", "gore", "snuff")


def _pulse_cached(key: str, ttl: int):
    """Compatibility helper: read a still-fresh cached payload."""
    return _PULSE_CACHE.get(key, ttl=ttl)


def _parse_rss(xml_text: str, limit: int = 8) -> tuple[list, bool]:
    """Parse Google News RSS. Returns (articles, valid_feed).

    An empty <channel> is a valid zero-result feed; an HTML error/interstitial
    is not. Keeping those distinct is the whole point of this helper.
    """
    import xml.etree.ElementTree as ET
    out: list = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return out, False
    if root.tag.lower() != "rss" and root.find(".//channel") is None:
        return out, False
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        src_el = item.find("source")
        source = (src_el.text.strip() if src_el is not None and src_el.text else None)
        if source and title.endswith(" - " + source):
            title = title[: -(len(source) + 3)].strip()
        pub = (item.findtext("pubDate") or "")[:16]
        url = sanitize_public_url(item.findtext("link"))
        if not url:
            continue
        out.append({"title": title, "source": source, "url": url, "date": pub})
        if len(out) >= limit:
            break
    return out, True


def _rss_articles(xml_text: str, limit: int = 8) -> list:
    """Compatibility wrapper: articles only, no feed-validity flag."""
    return _parse_rss(xml_text, limit)[0]


async def _gnews_search(q: str, edition: dict, limit: int = 8) -> tuple[list | None, str | None]:
    """Search one country edition. Returns (articles, error).

    ``([], None)`` means the feed answered with zero stories. ``(None, reason)``
    means the source failed — those are different states and are reported
    separately by /api/pulse/topic. The CONSENT cookie skips Google's consent
    interstitial (which otherwise returns an item-less page).
    """
    params = {"q": q.strip(), "hl": edition["hl"], "gl": edition["gl"], "ceid": edition["ceid"]}
    headers = {"User-Agent": _TI_UA, "Cookie": "CONSENT=YES+cb.20210328-17-p0.en+FX+"}
    last_error = "unknown error"
    for attempt in range(2):
        try:
            r = await get_client().get(
                _GNEWS, params=params, headers=headers,
                timeout=12, follow_redirects=True,
            )
            if r.status_code != 200:
                last_error = f"HTTP {r.status_code}"
            else:
                articles, valid = _parse_rss(r.text, limit)
                if valid:
                    return articles, None
                last_error = "unexpected feed response"
        except Exception as e:
            last_error = f"{type(e).__name__}: {str(e)[:100]}"
        if attempt == 0:
            await asyncio.sleep(1)
    return None, last_error


async def _load_trending(region: str) -> dict:
    y = time.gmtime(time.time() - 86400)  # yesterday (last complete day, UTC)
    url = _WIKI_TOP.format(proj=region, y=y.tm_year, m=y.tm_mon, d=y.tm_mday)
    topics: list = []
    error = None
    try:
        r = await get_client().get(url, timeout=15)
        if r.status_code != 200:
            error = f"HTTP {r.status_code}"
        else:
            items = ((r.json() or {}).get("items") or [{}])[0].get("articles", [])
            for a in items:
                t = a.get("article") or ""
                if any(t.startswith(p) or p in t for p in _WIKI_SKIP):
                    continue
                if any(b in t.lower().replace("_", " ") for b in _WIKI_BLOCK):
                    continue
                topics.append({"topic": t.replace("_", " "), "views": a.get("views"),
                               "url": f"https://{region}.wikipedia.org/wiki/{t}"})
                if len(topics) >= 20:
                    break
    except Exception as e:
        error = f"{type(e).__name__}: {str(e)[:100]}"
    # A correctly-parsed feed with no topics is still a successful (if empty)
    # fetch; only transport/HTTP/parse failures set ok=False.
    payload = {"ok": error is None, "region": region, "regions": PULSE_REGIONS,
               "topics": topics}
    if error:
        payload["error"] = "source_busy"
        payload["message"] = f"Couldn't load trending topics ({error}). Try refresh."
    elif not topics:
        payload["message"] = "No trending topics published for this edition right now."
    return payload


@router.get("/api/pulse/trending")
async def pulse_trending(region: str = Query("en", max_length=8)) -> dict:
    """Most-read Wikipedia topics for a language edition — 'what the world is
    reading about'. Reliable and fast. Failed fetches are never cached, so a
    refresh actually retries them."""
    region = region if region in PULSE_REGIONS else "en"

    async def load() -> dict:
        return await _load_trending(region)

    return await _PULSE_CACHE.get_or_load(
        f"trend:{region}", load, _TREND_TTL,
        should_cache=lambda payload: bool(payload.get("topics")),
    )


def _pulse_read(sides: list[dict]) -> list[str] | None:
    """Short *coverage read* from per-edition article counts.

    Strictly about coverage volume — no claims about opinion, domestic-ness or
    'gaps' when an edition simply happened to return no stories in this sample.
    """
    counts = [(s["label"], len(s.get("articles") or [])) for s in sides]
    nonzero = sorted([c for c in counts if c[1] > 0], key=lambda c: -c[1])
    if not nonzero:
        return None
    silent = [label for label, n in counts if n == 0]
    total = sum(n for _, n in counts)
    top = nonzero[0]
    lines = [f"Most coverage in {top[0]} ({top[1]} {'story' if top[1] == 1 else 'stories'})."]
    if top[1] >= 0.6 * total and len(nonzero) > 1:
        lines.append("Coverage is concentrated in one edition — compare it with the others before calling it a global story.")
    elif len(nonzero) == len(counts):
        lines.append("At least one story in every edition sampled in this feed set.")
    if silent:
        lines.append(f"No recent articles in: {', '.join(silent)} (in this sample).")
    return lines


async def _load_topic(q: str) -> dict:
    results = await asyncio.gather(*[_gnews_search(q, PULSE_EDITIONS[c]) for c in _SIDES_ORDER])
    sides: list[dict] = []
    failed: list[dict] = []
    total = 0
    for code, (arts, err) in zip(_SIDES_ORDER, results):
        label = PULSE_EDITIONS[code]["label"]
        if err:
            failed.append({"code": code, "label": label, "error": err})
            sides.append({"code": code, "label": label, "articles": [], "error": err})
            continue
        total += len(arts or [])
        sides.append({"code": code, "label": label, "articles": arts or [], "error": None})
    if failed and total == 0:
        return {"ok": False, "error": "source_busy",
                "message": "Couldn't reach any news edition right now — try again in a moment.",
                "failed": failed, "sides": sides}
    ok_sides = [s for s in sides if not s.get("error")]
    read = _pulse_read(ok_sides)
    if total == 0:
        read = ["No recent articles in any edition — a valid zero-result fetch, not a source failure."]
    return {"ok": True, "q": q, "total": total, "sides": sides,
            "available": len(ok_sides), "failed": failed,
            "partial": bool(failed), "read": read}


@router.get("/api/pulse/topic")
async def pulse_topic(q: str = Query(..., min_length=2, max_length=100)) -> dict:
    """How a topic is covered across different countries' press (Google News
    editions), shown side by side. Coverage & attention — not public opinion."""

    async def load() -> dict:
        return await _load_topic(q)

    return await _PULSE_CACHE.get_or_load(
        f"topic:{q.lower().strip()}", load, _PULSE_TTL,
        should_cache=lambda payload: bool(payload.get("ok")),
    )
