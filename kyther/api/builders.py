"""Pure helpers that turn scan results into the dashboard payload."""
from __future__ import annotations

import math
from dataclasses import asdict
from urllib.parse import urlsplit

from ..core.entities import Confidence, Entity, EntityType, Finding, RiskScore


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
    "xposedornot": "breaches",
    "leakcheck": "breaches",
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
    "xposedornot": Confidence.CONFIRMED,     # public breach index, keyless
    "leakcheck": Confidence.CONFIRMED,       # public breach index, keyless
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


# Per-seed-type ledger: what a person can reasonably expect an identity scan to
# check. A source is listed even when it returned nothing, so "no hits" is never
# confused with "nothing was queried". (label, analyzers, empty-detail, env key)
_IDENTITY_CHECKS: dict[str, list[tuple]] = {
    "email": [
        ("Gravatar profile", ("email_basic",), "No public Gravatar profile", None),
        ("Public breach index (XposedOrNot)", ("xposedornot",),
         "No breach record in this index", None),
        ("Breach lookup (LeakCheck)", ("leakcheck",),
         "No breach record in this index", None),
        ("Account handles (WhatsMyName + Sherlock)", ("username", "sherlock"),
         "No public accounts for this email's local part", None),
        ("Public profile details", ("profile_enrich", "reddit"),
         "No public profile details for this handle", None),
        ("Public commit emails", ("github_emails",),
         "No matching public commit emails", None),
        ("Domain records", ("dns", "rdap", "crtsh", "http_probe"),
         "No public domain records returned", None),
        ("Registered-site check (Holehe)", ("holehe",),
         "Opt-in account enumeration — set OSINT_ENABLE_HOLEHE=1", "OSINT_ENABLE_HOLEHE"),
        ("Breach lookup (HIBP)", ("hibp",),
         "Keyed source — set HIBP_API_KEY", "HIBP_API_KEY"),
        ("Email reputation (EmailRep)", ("emailrep",),
         "Keyed source — set EMAILREP_API_KEY", "EMAILREP_API_KEY"),
    ],
    "username": [
        ("Account handles (WhatsMyName + Sherlock)", ("username", "sherlock"),
         "No public accounts for this handle", None),
        ("Public profile details", ("profile_enrich", "reddit"),
         "No public profile details", None),
        ("Public commit emails", ("github_emails",),
         "No matching public commit emails", None),
        ("Breach lookup (LeakCheck)", ("leakcheck",),
         "No breach record in this index", None),
    ],
    "phone": [
        ("Offline phone intelligence", ("phone_intel",),
         "Number could not be parsed", None),
    ],
}


def build_source_checks(seed: dict, checks: dict,
                        errors: list[str] | None = None) -> dict:
    """Turn per-analyzer outcomes into an honest, human-readable source ledger."""
    specs = _IDENTITY_CHECKS.get(str(seed.get("type")))
    if not specs:
        return {}

    empty_note: dict[str, str] = {}
    if seed.get("type") == "email":
        from ..analyzers.email import _FREE_MAIL  # local import: keeps builders light
        domain = str(seed.get("value", "")).partition("@")[2].lower()
        if domain in _FREE_MAIL:
            empty_note["Domain records"] = (
                "Free-mail provider — company infrastructure skipped on purpose"
            )

    ledger: dict[str, dict] = {}
    for label, analyzers, miss, env_key in specs:
        rows = [checks[name] for name in analyzers if name in checks]
        found = [r for r in rows if r.get("status") == "found"]
        unavailable = [r for r in rows if r.get("status") == "unavailable"]
        if found:
            status = "found"
            detail = " · ".join(dict.fromkeys(str(r.get("detail", "")) for r in found))
        elif unavailable:
            status = "unavailable"
            detail = " · ".join(dict.fromkeys(str(r.get("detail", "")) for r in unavailable))
        elif rows:
            status = "not_found"
            detail = empty_note.get(label, miss)
        elif env_key:
            status = "manual"
            detail = miss
        else:
            status = "not_run"
            detail = empty_note.get(label, miss)

        ledger[label] = {
            "status": status,
            "detail": detail,
            "analyzers": list(analyzers),
        }
    return ledger


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
