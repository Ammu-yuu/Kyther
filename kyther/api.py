"""FastAPI service exposing the orchestration engine + the web UI.

    uvicorn kyther.api:app --reload --port 8099

Endpoints:
    GET  /                -> the single-page frontend
    GET  /api/analyzers   -> registered analyzers and their status
    POST /api/scan        -> run an orchestrated scan, return the entity graph
"""
from __future__ import annotations

import asyncio
import math
import time
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from .core import registry
from .core.entities import Confidence, Entity, EntityType, Finding, RiskScore, detect_type
from .core.orchestrator import scan
from .report import Report

app = FastAPI(title="Kyther", version="0.1.0")

# Allow the UI to call the API when it's opened from a different origin than the
# server (e.g. a file:// page or an embedded preview frame).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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


_NEWS_CACHE: dict = {"ts": 0.0, "data": []}
_NEWS_TTL = 3600  # 1 hour


@app.get("/api/news")
async def news() -> list[dict]:
    """Live security news for the feed (Hacker News, keyless). Cached for 1 hour."""
    now = time.time()
    if _NEWS_CACHE["data"] and now - _NEWS_CACHE["ts"] < _NEWS_TTL:
        return _NEWS_CACHE["data"]
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                "https://hn.algolia.com/api/v1/search_by_date",
                params={"tags": "story", "query": "security", "hitsPerPage": "30"},
            )
            hits = (r.json() or {}).get("hits", [])
    except Exception:
        return _NEWS_CACHE["data"]  # serve stale cache on error, or [] if never fetched
    out = []
    for h in hits:
        title = h.get("title")
        if not title or (h.get("points") or 0) < 2:
            continue
        url = h.get("url") or f"https://news.ycombinator.com/item?id={h.get('objectID')}"
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
_THREATS_CACHE = {"actors": {"ts": 0.0, "data": []}, "attacks": {"ts": 0.0, "data": []}}
_ACTORS_TTL = 86400
_ATTACKS_TTL = 3600


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _trim_actor(v: dict) -> dict:
    m = v.get("meta") or {}
    targets = _as_list(m.get("cfr-target-category")) or _as_list(m.get("targeted-sector"))
    return {
        "name": (v.get("value") or "").strip(),
        "description": (v.get("description") or "").strip()[:800],
        "aliases": [a for a in _as_list(m.get("synonyms")) if a][:12],
        "motive": m.get("cfr-type-of-incident"),
        "origin": m.get("country"),
        "sponsor": m.get("cfr-suspected-state-sponsor"),
        "targets": [t for t in targets if t][:6],
        "ref": (_as_list(m.get("refs")) or [None])[0],
    }


async def _fetch_actors() -> list:
    now = time.time()
    c = _THREATS_CACHE["actors"]
    if c["data"] and now - c["ts"] < _ACTORS_TTL:
        return c["data"]
    try:
        async with httpx.AsyncClient(timeout=25) as h:
            r = await h.get(_MISP_ACTORS_URL)
            values = (r.json() or {}).get("values", [])
    except Exception:
        return c["data"]
    out = [_trim_actor(v) for v in values
           if v.get("value") and (v.get("description") or (v.get("meta") or {}).get("cfr-type-of-incident"))]
    # actors with a stated motive first, then alphabetical
    out.sort(key=lambda a: (a["motive"] is None, (a["name"] or "").lower()))
    c.update(ts=now, data=out)
    return out


async def _fetch_attacks() -> list:
    now = time.time()
    c = _THREATS_CACHE["attacks"]
    if c["data"] and now - c["ts"] < _ATTACKS_TTL:
        return c["data"]
    try:
        async with httpx.AsyncClient(timeout=20) as h:
            r = await h.get(_RANSOMWARE_URL)
            items = r.json() or []
    except Exception:
        return c["data"]
    out = []
    for a in items:
        out.append({
            "victim": a.get("victim"),
            "group": a.get("group"),
            "date": (a.get("discovered") or a.get("attackdate") or "")[:10],
            "country": a.get("country"),
            "sector": a.get("activity"),
            "url": a.get("claim_url") or a.get("url") or None,
            "description": (a.get("description") or "").strip()[:220],
        })
    out.sort(key=lambda x: x["date"] or "", reverse=True)
    out = out[:80]
    c.update(ts=now, data=out)
    return out


@app.get("/api/threats")
async def threats() -> dict:
    """Threat-actor profiles (MISP galaxy) + a live ransomware attack timeline
    (ransomware.live). Keyless; cached (actors 24h, attacks 1h)."""
    actors = await _fetch_actors()
    attacks = await _fetch_attacks()
    return {"actors": actors, "attacks": attacks,
            "counts": {"actors": len(actors), "attacks": len(attacks)}}


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
