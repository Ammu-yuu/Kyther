"""FastAPI service exposing the orchestration engine + the web UI.

    uvicorn kyther.api:app --reload --port 8099

Endpoints:
    GET  /                -> the single-page frontend
    GET  /api/analyzers   -> registered analyzers and their status
    POST /api/scan        -> run an orchestrated scan, return the entity graph
"""
from __future__ import annotations

import asyncio
import base64
import json
import math
import sys
import time
from typing import Optional
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .core import registry
from .core.entities import (
    _DOMAIN_RE,
    AnalyzerResult,
    Confidence,
    Entity,
    EntityType,
    Finding,
    RiskScore,
    detect_type,
)
from .core.orchestrator import scan
from .net import close_client, get_client, sanitize_public_url
from .report import Report
from .security import KytherMiddleware, allowed_origins

app = FastAPI(title="Kyther", version="0.1.0")

# Only the local UI (or an explicitly configured tailnet origin) may call the
# API cross-origin. Same-origin requests are unaffected. Override with
# KYTHER_ALLOWED_ORIGINS="http://100.x.y.z:8099,..." when running on the tailnet.
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Per-IP rate limit + conservative response headers for every endpoint.
app.add_middleware(KytherMiddleware)


@app.on_event("shutdown")
async def _shutdown_http() -> None:
    await close_client()

WEB_DIR = Path(__file__).parent / "web"
MAX_DEPTH = 3  # guard against runaway pivots from the public UI


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=256)
    type: str = "auto"
    depth: int = Field(1, ge=0, le=MAX_DEPTH)


# Which dashboard section each analyzer's findings belong to.
_CATEGORY = {
    "username": "accounts",
    "sherlock": "accounts",
    "reddit": "reddit",
    "profile_enrich": "profile",
    "github_emails": "emails",
    "holehe": "email_accounts",
    "hunter": "emails",
    "emailrep": "identity",
    "sec_edgar": "identity",
    "jobs": "footprint",
    "shodan_internetdb": "infrastructure",
    "phone_intel": "identity",
    "email_basic": "identity",
    "hibp": "breaches",
    "search_dorks": "leads",
    "dns": "infrastructure",
    "rdap": "infrastructure",
    "crtsh": "infrastructure",
    "http_probe": "infrastructure",
    "ip_geo": "infrastructure",
}

# Default trust level per analyzer — same pattern as _CATEGORY. This is the
# fallback: an analyzer can override per-finding (Finding.confidence) when the
# right level depends on the data (e.g. EmailRep). Anything unlisted -> PROBABLE.
_CONFIDENCE = {
    # authoritative / control-verified -> CONFIRMED
    "dns": Confidence.CONFIRMED,
    "rdap": Confidence.CONFIRMED,
    "crtsh": Confidence.CONFIRMED,
    "http_probe": Confidence.CONFIRMED,
    "ip_geo": Confidence.CONFIRMED,
    "shodan_internetdb": Confidence.CONFIRMED,
    "phone_intel": Confidence.CONFIRMED,     # offline libphonenumber
    "hibp": Confidence.CONFIRMED,            # authoritative breach source
    "github_emails": Confidence.CONFIRMED,   # read straight from commit metadata
    "email_basic": Confidence.CONFIRMED,     # a Gravatar hit is a real account
    "profile_enrich": Confidence.CONFIRMED,  # structured API profile data
    "username": Confidence.CONFIRMED,        # WhatsMyName positive-match + control-probe
    "jobs": Confidence.CONFIRMED,            # the company's own public ATS board
    "reddit": Confidence.CONFIRMED,          # Reddit's own public profile/activity JSON
    # strong-but-not-authoritative -> PROBABLE
    "holehe": Confidence.PROBABLE,
    "hunter": Confidence.PROBABLE,
    "sec_edgar": Confidence.PROBABLE,        # name/entity correlation
    "emailrep": Confidence.PROBABLE,
    # scraped / loose -> POSSIBLE
    "sherlock": Confidence.POSSIBLE,         # HTTP status-code only
    "search_dorks": Confidence.POSSIBLE,     # generated leads, not verified hits
}
_DEFAULT_CONFIDENCE = Confidence.PROBABLE


def _confidence_for(f: Finding) -> Confidence:
    """Explicit per-finding value wins; otherwise fall back to the central map."""
    if f.confidence is not None:
        return f.confidence
    return _CONFIDENCE.get(f.analyzer, _DEFAULT_CONFIDENCE)


# ── Risk scoring ────────────────────────────────────────────────────────────
_SENSITIVITY = {"phone": 10, "address": 9, "email": 6, "username": 3, "social": 1}
_CONF_MULT = {"confirmed": 1.0, "probable": 0.6, "possible": 0.2}


def _risk_tier(s: int) -> str:
    return "Critical" if s >= 75 else "High" if s >= 50 else "Medium" if s >= 25 else "Low"


def _build_risk(findings: list[dict], dossier: dict, seed: dict) -> RiskScore:
    """Quantified exposure = Σ(sensitivity × confidence) + log breadth + scaled bonuses."""
    factors: list[tuple[str, float]] = []

    # PII exposures — counted once per type, at full (confirmed) weight when present.
    if dossier.get("emails"):
        factors.append(("Email address exposed", _SENSITIVITY["email"] * _CONF_MULT["confirmed"]))
    if seed["type"] == "phone" or any(f["analyzer"] == "phone_intel" for f in findings):
        factors.append(("Phone number exposed", _SENSITIVITY["phone"] * _CONF_MULT["confirmed"]))
    if seed["type"] == "username":
        factors.append(("Username publicly linkable", _SENSITIVITY["username"] * _CONF_MULT["confirmed"]))

    # Account breadth — dedupe by host, keep the best confidence, weight, log-scale.
    best: dict[str, str] = {}
    for f in findings:
        if f["category"] != "accounts":
            continue
        for p in f["data"].get("profiles", []):
            host = urlsplit(p["url"]).netloc.replace("www.", "") or p["url"]
            c = p.get("confidence", "possible")
            if _CONF_MULT.get(c, 0) > _CONF_MULT.get(best.get(host, ""), -1):
                best[host] = c
    eff = sum(_CONF_MULT[c] for c in best.values())
    if eff:
        factors.append((f"Account footprint ({len(best)} sites)", 5 * math.log(1 + eff)))

    # Bonuses — confidence-scaled, to stay consistent with the rest of the model.
    breach = next((f for f in findings
                   if f["category"] == "breaches"
                   or (f["analyzer"] == "emailrep" and f["data"].get("data_breach"))), None)
    if breach:
        factors.append(("Email found in a data breach", 15 * _CONF_MULT[breach["confidence"]]))
    if dossier.get("primary_name") and dossier.get("locations"):
        factors.append(("Real-name deanonymization (name + location)", 15.0))

    score = min(100, round(sum(p for _, p in factors)))
    top3 = sorted(factors, key=lambda x: -x[1])[:3]
    return RiskScore(
        score=score,
        tier=_risk_tier(score),
        factors=[{"label": lbl, "points": round(p, 1)} for lbl, p in top3],
    )


def _build_timeline(findings: list[Finding]) -> list[dict]:
    """Collect dated events across analyzers into one chronological timeline."""
    events: list[dict] = []
    for f in findings:
        d = f.data
        if f.analyzer == "rdap":
            noun = "IP" if f.entity.type == EntityType.IP else "Domain"
            for action, when in (d.get("events") or {}).items():
                if when:
                    events.append({"date": when, "label": f"{noun} {action}",
                                   "kind": "domain", "entity": f.entity.key})
        elif f.analyzer == "crtsh":
            if d.get("first_seen"):
                events.append({"date": d["first_seen"], "label": "First TLS certificate",
                               "kind": "cert", "entity": f.entity.key})
            if d.get("last_seen"):
                events.append({"date": d["last_seen"], "label": "Most recent TLS certificate",
                               "kind": "cert", "entity": f.entity.key})
        elif f.analyzer == "hibp":
            for b in d.get("breaches") or []:
                if isinstance(b, dict) and b.get("date"):
                    events.append({"date": b["date"], "label": f"Breach: {b.get('name')}",
                                   "kind": "breach", "entity": f.entity.key})
        elif f.analyzer == "profile_enrich":
            if d.get("joined"):
                events.append({"date": d["joined"], "label": f"Joined {d.get('platform')}",
                               "kind": "account", "entity": f.entity.key})
    # ISO-ish date strings sort chronologically as text (all start YYYY-MM-DD).
    events.sort(key=lambda e: str(e["date"]))
    return events


def _build_dossier(findings: list[Finding]) -> dict:
    """Fuse enriched profile records into a single 'who is this' summary."""
    from collections import Counter

    profs = [f.data for f in findings if f.analyzer == "profile_enrich"]
    names: Counter = Counter()
    locations: Counter = Counter()
    companies: set[str] = set()
    bios: list[dict] = []
    avatars: list[dict] = []
    links: set[str] = set()
    linked: list[dict] = []
    emails: list[dict] = []

    for f in findings:
        if f.analyzer == "github_emails":
            emails.extend(f.data.get("emails") or [])
        elif f.analyzer == "hunter":
            for e in f.data.get("emails") or []:
                emails.append({"email": e.get("email"), "name": e.get("name"), "noreply": False, "source": "hunter"})
        elif f.analyzer == "email_basic" and f.entity.type == EntityType.EMAIL:
            emails.append({"email": f.entity.value, "name": None, "noreply": False, "source": "seed"})
        elif f.analyzer == "profile_enrich" and f.data.get("email"):
            emails.append({"email": f.data["email"], "name": f.data.get("display_name"),
                           "noreply": False, "source": f.data.get("platform")})

    for p in profs:
        if p.get("display_name"):
            names[p["display_name"].strip()] += 1
        if p.get("location"):
            locations[p["location"].strip()] += 1
        if p.get("company"):
            companies.add(p["company"].strip())
        if p.get("bio"):
            bios.append({"platform": p["platform"], "text": p["bio"]})
        if p.get("avatar"):
            avatars.append({"platform": p["platform"], "url": p["avatar"]})
        for lk in p.get("links") or []:
            if lk:
                links.add(lk)
        for la in p.get("linked_accounts") or []:
            linked.append(la)

    # De-dup emails by address, keeping the richest record.
    email_map: dict[str, dict] = {}
    for e in emails:
        addr = (e.get("email") or "").lower()
        if addr and addr not in email_map:
            email_map[addr] = e

    return {
        "primary_name": names.most_common(1)[0][0] if names else None,
        "names": [n for n, _ in names.most_common()],
        "locations": [l for l, _ in locations.most_common()],
        "companies": sorted(companies),
        "bios": bios,
        "avatars": avatars,
        "links": sorted(links),
        "linked_accounts": linked,
        "emails": list(email_map.values()),
        "enriched_platforms": [p["platform"] for p in profs],
    }


_ACCOUNTS_IN_GRAPH = 18  # cap so the graph stays readable


def _build_graph(seed: Entity, result) -> dict:
    """Nodes + links connecting name <-> emails <-> handles <-> accounts."""
    nodes: dict[str, dict] = {}

    def node(nid: str, label: str, ntype: str) -> str:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "label": label, "type": ntype}
        return nid

    # Core entities discovered during the scan.
    for e in result.entities.values():
        node(e.key, e.value, "seed" if e.key == seed.key else str(e.type))

    links = [{"source": s, "target": t, "rel": r} for (s, t, r) in result.edges
             if s in nodes and t in nodes]

    for f in result.findings:
        if f.analyzer == "profile_enrich" and f.data.get("display_name"):
            nm = node(f"name:{f.data['display_name']}", f.data["display_name"], "name")
            links.append({"source": f.entity.key, "target": nm, "rel": "identity"})
        elif f.analyzer == "username":  # sampled account nodes for the swept handle
            for p in (f.data.get("profiles") or [])[:_ACCOUNTS_IN_GRAPH]:
                aid = node(f"acct:{p['url']}", p["platform"], "account")
                links.append({"source": f.entity.key, "target": aid, "rel": "account"})
        elif f.analyzer == "holehe":  # email -> registered sites
            for s in (f.data.get("sites") or [])[:_ACCOUNTS_IN_GRAPH]:
                sid = node(f"site:{s['domain']}", s.get("site") or s["domain"], "account")
                links.append({"source": f.entity.key, "target": sid, "rel": "registered"})

    return {"nodes": list(nodes.values()), "links": links}


def _finding_dict(f: Finding) -> dict:
    return {
        "analyzer": f.analyzer,
        "entity": f.entity.key,
        "title": f.title,
        "severity": str(f.severity),
        "category": _CATEGORY.get(f.analyzer, "other"),
        "confidence": str(_confidence_for(f)),
        "data": f.data,
    }


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


# ── PWA: manifest, service worker, and app icons (for add-to-home-screen) ────
@app.get("/manifest.webmanifest")
async def manifest() -> FileResponse:
    return FileResponse(WEB_DIR / "manifest.webmanifest",
                        media_type="application/manifest+json")


@app.get("/sw.js")
async def service_worker() -> FileResponse:
    # served from the site root so its scope covers the whole app
    return FileResponse(WEB_DIR / "sw.js", media_type="application/javascript",
                        headers={"Cache-Control": "no-cache"})


app.mount("/icons", StaticFiles(directory=WEB_DIR / "icons"), name="icons")


_NEWS_CACHE: dict = {"ts": 0.0, "data": []}
_NEWS_TTL = 3600  # 1 hour


@app.get("/api/news")
async def news() -> list[dict]:
    """Live security news for the feed (Hacker News, keyless). Cached for 1 hour."""
    now = time.time()
    if _NEWS_CACHE["data"] and now - _NEWS_CACHE["ts"] < _NEWS_TTL:
        return _NEWS_CACHE["data"]
    try:
        r = await get_client().get(
            "https://hn.algolia.com/api/v1/search_by_date",
            params={"tags": "story", "query": "security", "hitsPerPage": "30"},
            timeout=10,
        )
        hits = (r.json() or {}).get("hits", [])
    except Exception:
        return _NEWS_CACHE["data"]  # serve stale cache on error, or [] if never fetched
    out = []
    for h in hits:
        title = h.get("title")
        if not title or (h.get("points") or 0) < 2:
            continue
        url = sanitize_public_url(h.get("url")) or f"https://news.ycombinator.com/item?id={h.get('objectID')}"
        source = urlsplit(url).netloc.replace("www.", "") or "ycombinator.com"
        out.append({"title": title, "source": source, "url": url, "ts": h.get("created_at_i")})
    out = out[:15]
    _NEWS_CACHE.update(ts=now, data=out)
    return out


@app.get("/api/reddit")
async def reddit_lookup(u: str = Query(..., min_length=1, max_length=64)) -> dict:
    """Dedicated Reddit OSINT lookup — keyless public dossier for a username."""
    from .analyzers.reddit import reddit_dossier
    try:
        return await reddit_dossier(u, full=True)
    except Exception as exc:  # never 500 the UI; surface a soft error
        return {"found": False, "error": "fetch_failed", "message": str(exc)}


# ── Threat intelligence: actor profiles + a live global attack timeline ──────
# Both keyless. MISP galaxy changes slowly (24h cache); ransomware.live updates
# constantly (1h cache), so the feed reflects new threats as they emerge.
_MISP_ACTORS_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
_RANSOMWARE_URL = "https://api.ransomware.live/v2/recentvictims"
_GROUPS_URL = "https://api.ransomware.live/v2/groups"
# A descriptive UA — the default "python-httpx/..." is blocked by many WAFs.
_TI_UA = "kyther/0.2 (OSINT research; +https://github.com/Ammu-yuu/Kyther)"
_THREATS_CACHE = {"actors": {"ts": 0.0, "data": []},
                  "groups": {"ts": 0.0, "data": []},
                  "attacks": {"ts": 0.0, "data": []}}
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


async def _fetch_actors() -> list:
    now = time.time()
    c = _THREATS_CACHE["actors"]
    if c["data"] and now - c["ts"] < _ACTORS_TTL:
        return c["data"]
    try:
        r = await get_client().get(_MISP_ACTORS_URL, timeout=25)
        values = (r.json() or {}).get("values", [])
    except Exception:
        return c["data"]
    out = [_trim_actor(v) for v in values
           if v.get("value") and (v.get("description") or (v.get("meta") or {}).get("cfr-type-of-incident"))]
    # actors with a stated motive first, then alphabetical
    out.sort(key=lambda a: (a["motive"] is None, (a["name"] or "").lower()))
    c.update(ts=now, data=out)
    return out


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


async def _fetch_groups() -> list:
    now = time.time()
    c = _THREATS_CACHE["groups"]
    if c["data"] and now - c["ts"] < _GROUPS_TTL:
        return c["data"]
    data = await _rl_fetch_json(_GROUPS_URL)
    if data is None:
        return c["data"]  # keep whatever we had rather than blanking the gallery
    items = data if isinstance(data, list) else (data.get("data", []) if isinstance(data, dict) else [])
    out = [_trim_group(g) for g in items if g.get("name")]
    c.update(ts=now, data=out)
    return out


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


async def _fetch_attacks() -> list:
    now = time.time()
    c = _THREATS_CACHE["attacks"]
    if c["data"] and now - c["ts"] < _ATTACKS_TTL:
        return c["data"]
    data = await _rl_fetch_json(_RANSOMWARE_URL)
    if data is None:
        return c["data"]  # keep stale timeline rather than blanking it
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
    out = out[:80]
    c.update(ts=now, data=out)
    return out


@app.get("/api/threats")
async def threats() -> dict:
    """Threat actors (MISP galaxy APTs + ransomware.live gangs, merged) plus a
    live ransomware attack timeline. Served straight from cache — a background
    task keeps it fresh (see _threat_refresher), so this never blocks on the
    rate-limited upstream."""
    misp = _THREATS_CACHE["actors"]["data"]
    gangs = _THREATS_CACHE["groups"]["data"]
    attacks = _THREATS_CACHE["attacks"]["data"]
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
        _THREATS_FILE.write_text(json.dumps(_THREATS_CACHE))
    except Exception:
        pass


def _load_threats() -> None:
    try:
        if _THREATS_FILE.exists():
            saved = json.loads(_THREATS_FILE.read_text())
            for k in ("actors", "groups", "attacks"):
                if isinstance(saved.get(k), dict) and isinstance(saved[k].get("data"), list):
                    _THREATS_CACHE[k] = saved[k]
    except Exception:
        pass


async def _threat_refresher() -> None:
    """Keep the threat cache fresh with at most ~one ransomware.live call per
    cycle, so we stay under its rate limit. MISP (no limit) refreshes freely."""
    while True:
        try:
            now = time.time()
            ac = _THREATS_CACHE["actors"]
            if not ac["data"] or now - ac["ts"] > _ACTORS_TTL:
                await _fetch_actors()
                _save_threats()
            # one rate-limited source per cycle: attacks first (the live feed),
            # then the gang roster.
            at, gr = _THREATS_CACHE["attacks"], _THREATS_CACHE["groups"]
            if not at["data"] or now - at["ts"] > _ATTACKS_TTL:
                await _fetch_attacks()
                _save_threats()
            elif not gr["data"] or now - gr["ts"] > _GROUPS_TTL:
                await _fetch_groups()
                _save_threats()
        except Exception:
            pass
        await asyncio.sleep(60)  # ≤ ~1 ransomware.live request per 60s


@app.on_event("startup")
async def _threats_startup() -> None:
    _load_threats()
    asyncio.create_task(_threat_refresher())


# ── World Pulse: trending topics + how a topic is covered across regions/tone ─
# Keyless. Trending = Wikipedia's most-read articles (fast, reliable).
# Per-topic discourse = GDELT (global news in 100+ languages, with source
# country + tone). GDELT is powerful but slow/flaky, so every call has a tight
# timeout, one retry, a descriptive UA, and results are cached; failures return
# a soft "source busy" rather than hanging. Everything is framed as *coverage &
# attention*, never as "public opinion".
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
_PULSE_CACHE: dict = {}          # key -> (ts, payload)
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
    hit = _PULSE_CACHE.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    return None


def _rss_articles(xml_text: str, limit: int = 8) -> list:
    """Parse a Google News RSS feed into article dicts. Google News titles end
    in ' - Source'; we split that off and use the <source> element."""
    import xml.etree.ElementTree as ET
    out = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return out
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
    return out


async def _gnews_search(q: str, edition: dict, limit: int = 8):
    """Search Google News RSS for a topic in one country edition. Fast, keyless.
    Returns a list of articles, or None on failure. The CONSENT cookie skips
    Google's consent interstitial (which otherwise returns an item-less page)."""
    params = {"q": q.strip(), "hl": edition["hl"], "gl": edition["gl"], "ceid": edition["ceid"]}
    headers = {"User-Agent": _TI_UA, "Cookie": "CONSENT=YES+cb.20210328-17-p0.en+FX+"}
    for attempt in range(2):
        try:
            r = await get_client().get(
                _GNEWS, params=params, headers=headers,
                timeout=12, follow_redirects=True,
            )
            if r.status_code == 200 and "<item>" in r.text:
                return _rss_articles(r.text, limit)
        except Exception:
            pass
        if attempt == 0:
            await asyncio.sleep(1)
    return None


@app.get("/api/pulse/trending")
async def pulse_trending(region: str = Query("en", max_length=8)) -> dict:
    """Most-read Wikipedia topics for a language edition — 'what the world is
    reading about'. Reliable and fast."""
    region = region if region in PULSE_REGIONS else "en"
    key = f"trend:{region}"
    cached = _pulse_cached(key, _TREND_TTL)
    if cached is not None:
        return cached
    y = time.gmtime(time.time() - 86400)  # yesterday (last complete day, UTC)
    url = _WIKI_TOP.format(proj=region, y=y.tm_year, m=y.tm_mon, d=y.tm_mday)
    topics: list = []
    try:
        r = await get_client().get(url, timeout=15)
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
    except Exception:
        pass
    payload = {"region": region, "regions": PULSE_REGIONS, "topics": topics}
    if topics:
        _PULSE_CACHE[key] = (time.time(), payload)
    return payload


def _pulse_read(sides: list[dict]) -> list[str] | None:
    """Synthesise a short *coverage read* from the per-edition article counts —
    where attention is concentrated and where it is absent. Strictly about
    coverage volume, never 'opinion'."""
    counts = [(s["label"], len(s.get("articles") or [])) for s in sides]
    nonzero = sorted([c for c in counts if c[1] > 0], key=lambda c: -c[1])
    if not nonzero:
        return None
    silent = [label for label, n in counts if n == 0]
    total = sum(n for _, n in counts)
    lines = [f"Most coverage in {nonzero[0][0]} ({nonzero[0][1]} stories)."]
    if nonzero[0][1] >= 0.6 * total and len(nonzero) > 1:
        lines.append("Attention is concentrated in one edition — reads as a domestic story more than a global one.")
    elif len(nonzero) == len(counts):
        lines.append("Picked up across every edition — broad international attention.")
    if silent:
        lines.append(f"Little to no coverage in: {', '.join(silent)} — a visible gap.")
    return lines


@app.get("/api/pulse/topic")
async def pulse_topic(q: str = Query(..., min_length=2, max_length=100)) -> dict:
    """How a topic is covered across different countries' press (Google News
    editions), shown side by side. Coverage & attention — not public opinion."""
    key = f"topic:{q.lower().strip()}"
    cached = _pulse_cached(key, _PULSE_TTL)
    if cached is not None:
        return cached
    results = await asyncio.gather(*[_gnews_search(q, PULSE_EDITIONS[c]) for c in _SIDES_ORDER])
    sides = []
    total = 0
    for code, arts in zip(_SIDES_ORDER, results):
        arts = arts or []
        total += len(arts)
        sides.append({"code": code, "label": PULSE_EDITIONS[code]["label"], "articles": arts})
    if total == 0:
        return {"ok": False, "error": "source_busy",
                "message": "Couldn't reach the news source right now — try again in a moment."}
    payload = {"ok": True, "q": q, "total": total, "sides": sides,
               "read": _pulse_read(sides)}
    _PULSE_CACHE[key] = (time.time(), payload)
    return payload


@app.get("/api/analyzers")
async def list_analyzers() -> list[dict]:
    registry.load_builtins()
    return [
        {
            "name": a.name,
            "description": a.description,
            "accepts": sorted(str(t) for t in a.accepts),
            "available": a.available(),
            "env_key": a.env_key,
        }
        for a in registry.all_analyzers()
    ]


async def _perform_scan(req: ScanRequest) -> dict:
    """Run a scan and assemble the full response dict (shared by /scan and /report)."""
    etype = EntityType(req.type) if req.type != "auto" else detect_type(req.target)
    seed = Entity.make(etype, req.target)
    result = await scan(seed, max_depth=req.depth)

    seed_out = {"type": str(seed.type), "value": seed.value, "key": seed.key}
    findings_out = [_finding_dict(f) for f in result.findings]
    dossier = _build_dossier(result.findings)
    # Risk scoring runs after the dossier — it needs the fused name/email/location
    # plus the confidence-tagged findings and the seed's type.
    dossier["risk"] = asdict(_build_risk(findings_out, dossier, seed_out))

    return {
        "seed": seed_out,
        "entities": [
            {"type": str(e.type), "value": e.value, "key": e.key, "source": e.source}
            for e in result.entities.values()
        ],
        "findings": findings_out,
        "timeline": _build_timeline(result.findings),
        "dossier": dossier,
        "graph": _build_graph(seed, result),
        "errors": result.errors,
    }


@app.post("/api/scan")
async def run_scan(req: ScanRequest) -> dict:
    return await _perform_scan(req)


# --------------------------------------------------------------------------
# Company Footprint — aggregates a company's external surface (subdomains, DNS,
# tech, exposed services) plus its public hiring signals (job postings) into
# one company-centric view. All keyless, built from existing analyzers + jobs.
# --------------------------------------------------------------------------
def _analyzer(name: str):
    return next((a for a in registry.all_analyzers() if a.name == name), None)


async def _run_safe(analyzer, entity) -> "AnalyzerResult | None":
    if analyzer is None:
        return None
    try:
        return await analyzer.run(entity)
    except Exception:
        return None


async def _resolve_ips(host: str) -> list[str]:
    """Resolve a hostname to its IPv4 addresses (best-effort, bounded)."""
    loop = asyncio.get_event_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None), timeout=5)
    except Exception:
        return []
    return sorted({i[4][0] for i in infos if ":" not in i[4][0]})


# Attack-surface risk catalog: internet-exposed ports that warrant attention,
# with a severity and a plain-language reason. This is what turns a port list
# into a prioritised "fix this first" assessment.
_PORT_RISK: dict[int, tuple[str, str, str]] = {
    23: ("high", "Telnet", "Unencrypted remote login — credentials travel in clear text."),
    3389: ("high", "RDP", "Remote Desktop on the public internet — a top ransomware/brute-force entry point."),
    445: ("high", "SMB", "Windows file sharing exposed — wormable (EternalBlue class)."),
    139: ("high", "NetBIOS", "Legacy Windows sharing exposed."),
    5900: ("high", "VNC", "Remote desktop, frequently left unauthenticated."),
    3306: ("high", "MySQL", "Database reachable directly from the internet."),
    5432: ("high", "PostgreSQL", "Database reachable directly from the internet."),
    27017: ("high", "MongoDB", "Database exposed — historically shipped with no auth."),
    6379: ("high", "Redis", "In-memory store, default no-auth — a common breach vector."),
    9200: ("high", "Elasticsearch", "Data store exposed — the classic open-data leak."),
    11211: ("high", "Memcached", "Exposed — used for DDoS amplification and data exposure."),
    2375: ("high", "Docker API", "Unauthenticated Docker daemon = full host takeover."),
    10250: ("high", "Kubelet", "Kubernetes node API exposed."),
    21: ("medium", "FTP", "Often anonymous and/or unencrypted file access."),
    5601: ("medium", "Kibana", "Elasticsearch dashboard exposed."),
    9000: ("medium", "Admin/app", "Management or app port exposed — confirm what it serves."),
    25: ("low", "SMTP", "Mail server — verify it is not an open relay."),
    8080: ("low", "HTTP-alt", "Secondary web service — check what it hosts."),
    8443: ("low", "HTTPS-alt", "Secondary web service — check what it hosts."),
}
_RISK_ORDER = {"high": 0, "medium": 1, "low": 2}


def _footprint_risk(services: list[dict]) -> dict:
    """Score the mapped services into a prioritised attack-surface assessment."""
    findings: list[dict] = []
    for s in services:
        host = (s.get("hosts") or [None])[0] or s.get("ip")
        for p in (s.get("ports") or []):
            info = _PORT_RISK.get(p)
            if info:
                lvl, name, why = info
                findings.append({"level": lvl, "ip": s.get("ip"), "host": host,
                                 "port": p, "service": name, "why": why})
        for v in (s.get("vulns") or []):
            findings.append({"level": "high", "ip": s.get("ip"), "host": host,
                             "port": None, "service": str(v),
                             "why": "Known CVE flagged by Shodan InternetDB — patch or take offline."})
    findings.sort(key=lambda f: (_RISK_ORDER.get(f["level"], 9), f.get("port") or 0))
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["level"]] = counts.get(f["level"], 0) + 1
    if counts["high"]:
        posture, headline = "exposed", f"{counts['high']} high-risk exposure(s) — address these first."
    elif counts["medium"]:
        posture, headline = "review", f"{counts['medium']} medium-risk service(s) to review."
    elif findings:
        posture, headline = "ok", "Only low-risk secondary services are exposed."
    else:
        posture, headline = "clean", "No notably risky ports or CVEs on the hosts I could resolve."
    return {"posture": posture, "headline": headline, "counts": counts,
            "findings": findings[:40]}


async def _reverse_geocode(lat, lon) -> str | None:
    """Coordinates → a human place name (OpenStreetMap Nominatim, keyless).
    Best-effort: a failure just means the map links still work without a name."""
    try:
        r = await get_client().get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"lat": lat, "lon": lon, "format": "jsonv2", "zoom": 16},
            timeout=8,
        )
        if r.status_code == 200:
            return ((r.json() or {}).get("display_name")) or None
    except Exception:
        pass
    return None


@app.get("/api/footprint")
async def footprint(target: str = Query(..., min_length=1, max_length=253)) -> dict:
    """Map a company's external footprint: subdomains, DNS, services, job posts."""
    registry.load_builtins()
    t = target.strip().lower()
    is_domain = bool(_DOMAIN_RE.match(t))
    domain = t if is_domain else None
    out: dict = {
        "target": target,
        "domain": domain,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "subdomains": [],
        "dns": {},
        "tech": {},
        "services": [],
        "jobs": None,
    }

    # Job postings run for either a company name or a domain (slug-derived).
    seed_type = EntityType.DOMAIN if is_domain else EntityType.COMPANY
    jr = await _run_safe(_analyzer("jobs"), Entity.make(seed_type, t))
    if jr and jr.findings:
        out["jobs"] = jr.findings[0].data

    # Infrastructure mapping needs a domain.
    if not domain:
        out["note"] = "Give a domain (e.g. acme.com) to map subdomains and services."
        return out

    dent = Entity.make(EntityType.DOMAIN, domain)
    crt, dnsr, tech = await asyncio.gather(
        _run_safe(_analyzer("crtsh"), dent),
        _run_safe(_analyzer("dns"), dent),
        _run_safe(_analyzer("http_probe"), dent),
    )
    subs: list[str] = []
    if crt and crt.findings:
        subs = crt.findings[0].data.get("subdomains", [])
        out["subdomains"] = subs
        for k in ("first_seen", "last_seen", "count"):
            if k in crt.findings[0].data:
                out.setdefault("ct", {})[k] = crt.findings[0].data[k]
    if dnsr and dnsr.findings:
        out["dns"] = dnsr.findings[0].data
    if tech and tech.findings:
        out["tech"] = {"title": tech.findings[0].title, **tech.findings[0].data}

    # Resolve the apex + a capped set of subdomains, then enrich unique IPs with
    # geolocation (for the map) and Shodan InternetDB (exposed ports/CVEs).
    hosts = [domain] + subs[:12]
    resolved = await asyncio.gather(*[_resolve_ips(h) for h in hosts])
    host_ips: dict[str, list[str]] = {}
    uniq: list[str] = []
    for h, ips in zip(hosts, resolved):
        if ips:
            host_ips[h] = ips
            for ip in ips:
                if ip not in uniq:
                    uniq.append(ip)
    uniq = uniq[:15]

    geo, sho = _analyzer("ip_geo"), _analyzer("shodan_internetdb")

    async def _ip_info(ip: str) -> dict:
        g, s = await asyncio.gather(
            _run_safe(geo, Entity.make(EntityType.IP, ip)),
            _run_safe(sho, Entity.make(EntityType.IP, ip)),
        )
        gd = g.findings[0].data if g and g.findings else {}
        sd = s.findings[0].data if s and s.findings else {}
        return {
            "ip": ip,
            "hosts": [h for h, ips in host_ips.items() if ip in ips],
            "geo": {k: gd.get(k) for k in ("city", "regionName", "country", "lat", "lon", "org", "isp", "as")},
            "ports": sd.get("ports", []),
            "vulns": sd.get("vulns", []),
            "software": sd.get("software", []),
        }

    out["services"] = await asyncio.gather(*[_ip_info(ip) for ip in uniq])
    out["risk"] = _footprint_risk(out["services"])
    return out


# --------------------------------------------------------------------------
# Image Intelligence — assisted verification & geolocation of a photo.
# EXIF/metadata + GPS extraction (keyless), a provenance *verdict* that reads
# the signals and says what to do next, GPS → place (reverse geocode) + map
# links, and reverse-image-search launchers (manual, no scraping). Full auto
# earliest-upload / visual geolocation needs a paid key or vision AI and is
# deliberately out of scope.
# --------------------------------------------------------------------------
class ImageRequest(BaseModel):
    url: Optional[str] = Field(None, max_length=2048)
    data: Optional[str] = None  # base64 (optionally a data: URL) for local uploads


_IMG_MAX_BYTES = 25 * 1024 * 1024


@app.post("/api/image")
async def image_intel(req: ImageRequest) -> dict:
    """Extract EXIF/metadata + GPS and build reverse-search launchers for an image."""
    from . import imageintel
    from .core import netguard

    raw: bytes | None = None
    resolved_url = req.url
    resolved_from_page = False
    if req.url:
        try:
            resp = await netguard.safe_get(req.url, timeout=15, max_bytes=_IMG_MAX_BYTES)
            resp.raise_for_status()
        except netguard.BlockedTargetError as e:
            return {"ok": False, "error": f"blocked target: {e}"}
        except Exception as e:
            return {"ok": False, "error": f"could not fetch URL: {e}"}
        raw = resp.content
        ctype = resp.headers.get("content-type", "").lower()
        looks_html = "html" in ctype or raw.lstrip()[:15].lower().startswith((b"<!doctype", b"<html"))
        if looks_html and "image" not in ctype:
            # It's a web page — find its main image (og:image) and analyse that.
            # Use the original page URL as the base: the guarded response was
            # fetched from a pinned IP, so resp.url is not a usable base.
            img_url = imageintel.og_image(raw.decode("utf-8", "ignore"), base_url=req.url)
            if not img_url:
                return {
                    "ok": False,
                    "error": "That's a web page, not an image, and I couldn't find a main image (og:image) on it. "
                    "Open the image directly — right-click it → Copy image address — and paste that URL.",
                    "page": True,
                }
            try:
                resp2 = await netguard.safe_get(img_url, timeout=15, max_bytes=_IMG_MAX_BYTES)
                resp2.raise_for_status()
            except netguard.BlockedTargetError as e:
                return {"ok": False, "error": f"blocked target (page image): {e}"}
            except Exception as e:
                return {"ok": False, "error": f"could not fetch the page's image: {e}"}
            raw = resp2.content
            resolved_url = img_url
            resolved_from_page = True
    elif req.data:
        d = req.data.strip()
        if d.startswith("data:") and "," in d:
            d = d.split(",", 1)[1]
        try:
            raw = base64.b64decode(d)
        except Exception:
            return {"ok": False, "error": "invalid base64 image data"}

    if not raw:
        return {"ok": False, "error": "provide an image 'url' or base64 'data'"}
    if len(raw) > _IMG_MAX_BYTES:
        return {"ok": False, "error": "image too large (>25MB)"}

    try:
        meta = await asyncio.to_thread(imageintel.extract_metadata, raw)
    except Exception as e:
        return {"ok": False, "error": f"could not read image: {e}"}

    meta["ok"] = True
    meta["bytes"] = len(raw)
    meta["assessment"] = imageintel.assess(meta)
    meta["reverse_search"] = imageintel.reverse_search_links(
        sanitize_public_url(resolved_url) if req.url else None
    )
    if resolved_from_page:
        meta["resolved_image"] = resolved_url
    if meta.get("gps"):
        g = meta["gps"]
        g["maps"] = imageintel.map_links(g["lat"], g["lon"])
        place = await _reverse_geocode(g["lat"], g["lon"])
        if place:
            g["place"] = place
    return meta


# --------------------------------------------------------------------------
# Security self-audit — runs the same open-source scanners we recommend
# (Bandit for the Python source, pip-audit for dependency CVEs) against
# Kyther's own package and returns structured results for the UI.
#
# The scan target is fixed to this package directory — no user input is ever
# passed to the subprocess, and both tools run via `sys.executable -m ...` so
# we use whatever is installed in the active venv, never a shell.
# --------------------------------------------------------------------------
_PKG_DIR = Path(__file__).parent            # the kyther/ package (audit target)
_REPO_DIR = _PKG_DIR.parent                 # repo root, for trimming paths


async def _run_tool(args: list[str], timeout: float) -> tuple[int, str, str]:
    """Run a subprocess and capture (returncode, stdout, stderr). Never raises."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except (FileNotFoundError, OSError) as e:
        return (127, "", str(e))
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return (124, "", "timeout")
    return (proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))


async def _audit_bandit() -> dict:
    """Static-analysis pass over the Python source. Non-zero exit is normal
    (Bandit returns 1 when it finds issues), so we parse the JSON regardless."""
    code, out, err = await _run_tool(
        [sys.executable, "-m", "bandit", "-r", str(_PKG_DIR), "-f", "json", "-q"], 45
    )
    if code == 124:
        return {"available": True, "error": "timed out"}
    try:
        data = json.loads(out)
    except Exception:
        if "No module named" in err or code == 127:
            return {"available": False}
        return {"available": True, "error": (err.strip() or "could not parse output")[:200]}
    tot = data.get("metrics", {}).get("_totals", {})
    rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings = sorted(
        (
            {
                "id": r.get("test_id"),
                "sev": r.get("issue_severity"),
                "file": str(r.get("filename", "")).replace(str(_REPO_DIR) + "/", ""),
                "line": r.get("line_number"),
                "text": " ".join((r.get("issue_text") or "").split())[:96],
            }
            for r in data.get("results", [])
        ),
        key=lambda r: rank.get(r["sev"], 9),
    )
    return {
        "available": True,
        "loc": int(tot.get("loc", 0) or 0),
        "high": int(tot.get("SEVERITY.HIGH", 0) or 0),
        "medium": int(tot.get("SEVERITY.MEDIUM", 0) or 0),
        "low": int(tot.get("SEVERITY.LOW", 0) or 0),
        "findings": findings,
    }


async def _audit_deps() -> dict:
    """Dependency vulnerability pass (pip-audit). Needs network for the advisory
    DB, so it gets a generous timeout and degrades gracefully when offline."""
    code, out, err = await _run_tool([sys.executable, "-m", "pip_audit", "-f", "json"], 90)
    if code == 124:
        return {"available": True, "error": "timed out (offline?)"}
    try:
        data = json.loads(out)
    except Exception:
        if "No module named" in err or code == 127:
            return {"available": False}
        return {"available": True, "error": (err.strip() or "could not parse output")[:200]}
    deps = data.get("dependencies", []) if isinstance(data, dict) else data
    pkgs, total = [], 0
    for d in deps:
        vulns = d.get("vulns") or []
        if not vulns:
            continue
        total += len(vulns)
        fixes = sorted({v for x in vulns for v in (x.get("fix_versions") or [])})
        pkgs.append(
            {
                "name": d.get("name"),
                "version": d.get("version"),
                "count": len(vulns),
                "fix": fixes[-1] if fixes else None,
                "ids": [x.get("id") for x in vulns][:8],
            }
        )
    pkgs.sort(key=lambda p: p["count"], reverse=True)
    return {"available": True, "vuln_count": total, "pkg_count": len(pkgs), "packages": pkgs}


@app.post("/api/audit")
async def run_audit() -> dict:
    """Self-audit Kyther: Bandit (source) + pip-audit (dependencies), in parallel."""
    bandit, deps = await asyncio.gather(_audit_bandit(), _audit_deps())
    return {
        "ok": True,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "bandit": bandit,
        "deps": deps,
    }


@app.post("/api/report")
async def make_report(req: ScanRequest) -> Response:
    """Run a scan and return a professional PDF report."""
    scan_dict = await _perform_scan(req)
    # reportlab is synchronous/CPU-bound — keep it off the event loop.
    pdf = await asyncio.to_thread(Report(scan_dict).generate)
    fname = f"kyther-{scan_dict['seed']['type']}-report.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
