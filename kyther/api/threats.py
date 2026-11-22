"""Threat-actor profiles + live ransomware attack timeline."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import APIRouter

from ..cache import TTLCache
from ..net import get_client, sanitize_public_url

router = APIRouter()

# Descriptive UA — the default "python-httpx/..." is blocked by many WAFs.
_TI_UA = "kyther/0.2 (OSINT research; +https://github.com/Ammu-yuu/Kyther)"


# ── Threat intelligence: actor profiles + a live global attack timeline ──────
# Both keyless. MISP galaxy changes slowly (24h cache); ransomware.live updates
# constantly (1h cache), so the feed reflects new threats as they emerge.
_MISP_ACTORS_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
_RANSOMWARE_URL = "https://api.ransomware.live/v2/recentvictims"
_GROUPS_URL = "https://api.ransomware.live/v2/groups"
_THREATS_CACHE = TTLCache(maxsize=8, name="threats")
_ACTORS_TTL = 86400
_GROUPS_TTL = 43200   # 12h — the ransomware gang roster changes slowly
_ATTACKS_TTL = 3600


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _norm_key(s) -> str:
    return "".join(c for c in str(s or "").lower() if c.isalnum())


def _trim_actor(v: dict) -> dict:
    m = v.get("meta") or {}
    targets = _as_list(m.get("cfr-target-category")) or _as_list(m.get("targeted-sector"))
    motive = m.get("cfr-type-of-incident")
    if isinstance(motive, list):
        motive = " / ".join(str(x) for x in motive if x) or None
    return {
        "name": (v.get("value") or "").strip(),
        "description": (v.get("description") or "").strip()[:800],
        "aliases": [a for a in _as_list(m.get("synonyms")) if a][:12],
        "motive": motive,
        "origin": m.get("country"),
        "sponsor": m.get("cfr-suspected-state-sponsor"),
        "targets": [t for t in targets if t][:6],
        "ref": sanitize_public_url((_as_list(m.get("refs")) or [None])[0]),
    }


async def _load_actors() -> list:
    r = await get_client().get(_MISP_ACTORS_URL, timeout=25)
    values = (r.json() or {}).get("values", [])
    out = [_trim_actor(v) for v in values
           if v.get("value") and (v.get("description") or (v.get("meta") or {}).get("cfr-type-of-incident"))]
    # actors with a stated motive first, then alphabetical
    out.sort(key=lambda a: (a["motive"] is None, (a["name"] or "").lower()))
    return out


async def _fetch_actors() -> list:
    """Cached + single-flight; a failed refresh keeps the last good data."""
    return await _THREATS_CACHE.get_or_load(
        "actors", _load_actors, _ACTORS_TTL, stale_on_error=True, default=[]
    )


def _trim_group(g: dict) -> dict:
    """A ransomware.live gang, shaped like a threat-actor card. MISP is
    APT/nation-state heavy and misses most (esp. new) ransomware crews, so we
    fold these in — motive is financial extortion by definition."""
    name = (g.get("name") or "").strip()
    if name and name == name.lower():   # gang names arrive lowercased ("anubis")
        name = name.title()
    alt = g.get("altname")
    return {
        "name": name,
        "description": (g.get("description") or "").strip()[:800],
        "aliases": [alt.strip()] if isinstance(alt, str) and alt.strip() else [],
        "motive": "Financial Crime / Extortion",
        "origin": None,
        "sponsor": None,
        "targets": [],
        # ransomware.live group page — safe; never the gang's onion leak site
        "ref": sanitize_public_url(g.get("url")),
        "source": "ransomware.live",
    }


async def _rl_fetch_json(url: str, tries: int = 2):
    """GET a ransomware.live endpoint as JSON, riding out transient rate-limits.
    When throttled the API replies with a 404 / HTML page instead of a clean
    429, so we only accept a 200 with a JSON content-type and otherwise back off
    and retry. Returns the parsed JSON, or None if every attempt failed."""
    for i in range(tries):
        try:
            r = await get_client().get(
                url, timeout=25, follow_redirects=True,
                headers={"User-Agent": _TI_UA},
            )
            if r.status_code == 200 and "json" in r.headers.get("content-type", "").lower():
                return r.json()
        except Exception:
            pass
        await asyncio.sleep(1.5 * (i + 1))  # 1.5s, 3s, 4.5s backoff
    return None


async def _load_groups() -> list:
    data = await _rl_fetch_json(_GROUPS_URL)
    if data is None:
        raise RuntimeError("ransomware.live groups unavailable")
    items = data if isinstance(data, list) else (data.get("data", []) if isinstance(data, dict) else [])
    return [_trim_group(g) for g in items if g.get("name")]


async def _fetch_groups() -> list:
    return await _THREATS_CACHE.get_or_load(
        "groups", _load_groups, _GROUPS_TTL, stale_on_error=True, default=[]
    )


def _merge_actors(misp: list, gangs: list) -> list:
    """MISP actors + ransomware gangs, de-duplicated. A gang already covered by
    a MISP actor (by name or alias, e.g. Akira == Storm-1567) keeps MISP's
    richer profile; the rest are added so every gang in the feed is findable."""
    known: set = set()
    for a in misp:
        known.add(_norm_key(a["name"]))
        known.update(_norm_key(x) for x in (a.get("aliases") or []))
    merged = list(misp)
    for g in gangs:
        keys = {_norm_key(g["name"])} | {_norm_key(x) for x in (g.get("aliases") or [])}
        if keys & known:
            continue
        merged.append(g)
        known |= keys
    merged.sort(key=lambda a: (a.get("motive") is None, (a.get("name") or "").lower()))
    return merged


async def _load_attacks() -> list:
    data = await _rl_fetch_json(_RANSOMWARE_URL)
    if data is None:
        raise RuntimeError("ransomware.live attacks unavailable")
    items = data if isinstance(data, list) else (data.get("data", []) if isinstance(data, dict) else [])
    out = []
    for a in items:
        press = a.get("press")
        press_out = None
        if isinstance(press, dict) and press.get("source"):
            press_out = {"url": sanitize_public_url(press.get("source")),
                         "summary": (press.get("summary") or "").strip()[:400]}
        out.append({
            "victim": a.get("victim") or a.get("post_title") or a.get("victim_name"),
            "group": a.get("group") or a.get("group_name"),
            "date": (a.get("discovered") or a.get("attackdate") or a.get("published") or "")[:10],
            "country": a.get("country"),
            "sector": a.get("activity"),
            "description": (a.get("description") or "").strip()[:400],
            "domain": a.get("domain") or None,
            # neutral ransomware.live incident page — never the gang's leak site
            "ref": sanitize_public_url(a.get("url")),
            "press": press_out,
        })
    out.sort(key=lambda x: x["date"] or "", reverse=True)
    return out[:80]


async def _fetch_attacks() -> list:
    return await _THREATS_CACHE.get_or_load(
        "attacks", _load_attacks, _ATTACKS_TTL, stale_on_error=True, default=[]
    )


@router.get("/api/threats")
async def threats() -> dict:
    """Threat actors (MISP galaxy APTs + ransomware.live gangs, merged) plus a
    live ransomware attack timeline. Served straight from cache — a background
    task keeps it fresh (see _threat_refresher), so this never blocks on the
    rate-limited upstream."""
    misp = _THREATS_CACHE.peek("actors") or []
    gangs = _THREATS_CACHE.peek("groups") or []
    attacks = _THREATS_CACHE.peek("attacks") or []
    actors = _merge_actors(misp, gangs) if (misp or gangs) else []
    return {"actors": actors, "attacks": attacks,
            "counts": {"actors": len(actors), "attacks": len(attacks)}}


# ── Threat cache: persist to disk + refresh in the background ────────────────
# ransomware.live rate-limits to roughly one request/minute (serving throttled
# requests as 404/HTML). We therefore never fetch it on the request path;
# instead a background loop refreshes one source per cycle, and the cache is
# saved to disk so a restart doesn't blank the feed.
_THREATS_FILE = Path.home() / ".kyther" / "threats_cache.json"


def _save_threats() -> None:
    try:
        _THREATS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _THREATS_FILE.write_text(json.dumps(_THREATS_CACHE.snapshot()))
    except Exception:
        pass


def _load_threats() -> None:
    try:
        if _THREATS_FILE.exists():
            _THREATS_CACHE.load_snapshot(json.loads(_THREATS_FILE.read_text()))
    except Exception:
        pass


async def _threat_refresher() -> None:
    """Keep the threat cache fresh with at most ~one ransomware.live call per
    cycle, so we stay under its rate limit. MISP (no limit) refreshes freely."""
    while True:
        try:
            ac_age = _THREATS_CACHE.age("actors")
            if ac_age is None or ac_age > _ACTORS_TTL:
                await _fetch_actors()
                _save_threats()
            # one rate-limited source per cycle: attacks first (the live feed),
            # then the gang roster.
            at_age = _THREATS_CACHE.age("attacks")
            gr_age = _THREATS_CACHE.age("groups")
            if at_age is None or at_age > _ATTACKS_TTL:
                await _fetch_attacks()
                _save_threats()
            elif gr_age is None or gr_age > _GROUPS_TTL:
                await _fetch_groups()
                _save_threats()
        except Exception:
            pass
        await asyncio.sleep(60)  # ≤ ~1 ransomware.live request per 60s

# Called from the app's startup hook; see kyther/api/__init__.py.
def load_persisted() -> None:
    _load_threats()


async def start_refresher() -> None:
    asyncio.create_task(_threat_refresher())
