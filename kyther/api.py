"""FastAPI service exposing the orchestration engine + the web UI.

    uvicorn kyther.api:app --reload --port 8099

Endpoints:
    GET  /                -> the single-page frontend
    GET  /api/analyzers   -> registered analyzers and their status
    POST /api/scan        -> run an orchestrated scan, return the entity graph
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .core import registry
from .core.entities import Entity, EntityType, Finding, detect_type
from .core.orchestrator import scan

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
        "data": f.data,
    }


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/api/news")
async def news() -> list[dict]:
    """Live security news for the feed (Hacker News, keyless)."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                "https://hn.algolia.com/api/v1/search_by_date",
                params={"tags": "story", "query": "security", "hitsPerPage": "20"},
            )
            hits = (r.json() or {}).get("hits", [])
    except Exception:
        return []
    out = []
    for h in hits:
        title = h.get("title")
        if not title or (h.get("points") or 0) < 2:
            continue
        url = h.get("url") or f"https://news.ycombinator.com/item?id={h.get('objectID')}"
        source = urlsplit(url).netloc.replace("www.", "") or "ycombinator.com"
        out.append({"title": title, "source": source, "url": url, "ts": h.get("created_at_i")})
    return out[:12]


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


@app.post("/api/scan")
async def run_scan(req: ScanRequest) -> dict:
    etype = EntityType(req.type) if req.type != "auto" else detect_type(req.target)
    seed = Entity.make(etype, req.target)
    result = await scan(seed, max_depth=req.depth)

    return {
        "seed": {"type": str(seed.type), "value": seed.value, "key": seed.key},
        "entities": [
            {"type": str(e.type), "value": e.value, "key": e.key, "source": e.source}
            for e in result.entities.values()
        ],
        "findings": [_finding_dict(f) for f in result.findings],
        "timeline": _build_timeline(result.findings),
        "dossier": _build_dossier(result.findings),
        "graph": _build_graph(seed, result),
        "errors": result.errors,
    }
