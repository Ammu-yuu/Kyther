"""Company Footprint: identity, registration, attack surface and hiring signals."""
from __future__ import annotations

import asyncio
import time
from typing import Optional
from urllib.parse import urlsplit

from fastapi import APIRouter

from ..company import (clean_terms, github_org, pivot_links, search_terms,
                       slug_candidates, verify_organisation, wayback_summary,
                       wikidata_facts, wikipedia_profile)
from ..core import registry
from ..core.entities import AnalyzerResult, Entity, EntityType, _DOMAIN_RE
from .models import FootprintRequest
from ..net import get_client

router = APIRouter()


# --------------------------------------------------------------------------
# Company Footprint — aggregates public company identity (Wikipedia/Wikidata,
# SEC, GitHub), domain registration, subdomains, DNS, exposed services and
# hiring signals into one company-centric view. All keyless; the richer
# identity/archive sources run when ``deep`` is requested by the UI.
# --------------------------------------------------------------------------
def _analyzer(name: str):
    return next((a for a in registry.all_analyzers() if a.name == name), None)


# A slow source must not hang the whole footprint request forever. Individual
# analyzers keep their own timeouts; this is a final backstop, and failures are
# returned to the caller instead of being swallowed as "no data".
_FOOTPRINT_TIMEOUT = 30.0


async def _run_safe(analyzer, entity, name: str) -> tuple["AnalyzerResult | None", str | None]:
    """Run one analyzer, returning (result, error). Never raises."""
    if analyzer is None:
        return None, f"{name}: analyzer unavailable"
    try:
        return await asyncio.wait_for(analyzer.run(entity), timeout=_FOOTPRINT_TIMEOUT), None
    except asyncio.TimeoutError:
        return None, f"{name}: timed out after {_FOOTPRINT_TIMEOUT:g}s"
    except Exception as e:
        return None, f"{name}: failed ({type(e).__name__}: {str(e)[:160]})"


def _add_error(errors: list[str], message: str) -> None:
    if message not in errors:
        errors.append(message)


async def _resolve_ips(host: str) -> list[str]:
    """Resolve a hostname to its IPv4 addresses (best-effort, bounded)."""
    loop = asyncio.get_event_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None), timeout=5)
    except Exception:
        return []
    return sorted({i[4][0] for i in infos if ":" not in i[4][0]})


def _domain_from(value: str) -> str | None:
    """Accept a bare domain or a URL and return the validated host."""
    text = str(value or "").strip().lower().rstrip("/")
    if not text:
        return None
    if "://" in text:
        text = urlsplit(text).netloc.lower()
    text = text.split("/", 1)[0].split("?", 1)[0]
    return text if _DOMAIN_RE.match(text) else None


def _unique(values) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        value = str(value or "").strip()
        if value and value.lower() not in seen:
            seen.add(value.lower())
            out.append(value)
    return out


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


def _footprint_risk(services: list[dict], errors: list[str] | None = None,
                    mapped: int | None = None) -> dict:
    """Score the mapped services into a prioritised attack-surface assessment.

    An empty result is only "clean" when the checks actually completed. If a
    source failed — or no host could be resolved for port/CVE checks — say so
    rather than presenting absence of data as absence of risk.
    """
    errors = errors or []
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
    partial = " (partial — some checks failed)" if errors and findings else ""
    if counts["high"]:
        posture, headline = "exposed", f"{counts['high']} high-risk exposure(s) — address these first."
    elif counts["medium"]:
        posture, headline = "review", f"{counts['medium']} medium-risk service(s) to review."
    elif findings:
        posture, headline = "ok", "Only low-risk secondary services are exposed."
    elif errors:
        posture, headline = "incomplete", "Can't judge exposure — some checks failed; see the notes below."
    elif mapped is not None and mapped == 0:
        posture, headline = "incomplete", "No host resolved to an IP — ports and CVEs could not be checked."
    else:
        posture, headline = "clean", "No notably risky ports or CVEs on the hosts I could resolve."
    return {"posture": posture, "headline": headline + partial, "counts": counts,
            "findings": findings[:40], "partial": bool(errors and findings)}


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


async def _build_footprint(target: str = "", name: str = "", domains=None,
                           aliases=None, country: str = "", deep: bool = False) -> dict:
    """Shared implementation for the legacy GET and structured POST endpoints."""
    registry.load_builtins()
    target = str(target or "").strip()
    domains = _unique([_domain_from(d) for d in (domains or [])])[:5]
    target_domain = _domain_from(target)
    if target_domain and target_domain not in domains:
        domains.insert(0, target_domain)

    company_name = str(name or "").strip()
    if not company_name and not target_domain:
        company_name = target[:200]
    if not company_name and domains:
        company_name = domains[0].split(".")[0].replace("-", " ").title()
    alias_terms = clean_terms(aliases)
    display_aliases = _unique([company_name, *alias_terms])
    terms = search_terms(company_name, alias_terms, country)

    out: dict = {
        "ok": True,
        "target": target or company_name or (domains[0] if domains else ""),
        "name": company_name,
        "domain": domains[0] if domains else None,
        "domains": domains,
        "aliases": display_aliases,
        "country": country.strip() or None,
        "deep": bool(deep),
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "subdomains": [],
        "dns": {},
        "tech": {},
        "services": [],
        "jobs": None,
        "hiring": None,
        "registration": {},
        "profile": None,
        "filings": None,
        "github": None,
        "archive": None,
        "pivots": [],
        "manual_lookups": [],
        "errors": [],
    }
    succeeded = 0

    # A transparent ledger of what actually happened. The UI uses this to show
    # "checked, no verified match" instead of silently omitting a source, and
    # to keep manual search links completely separate from discovered data.
    _sources = ("jobs", "sec_edgar", "wikipedia", "wikidata", "github",
                "linkedin", "wayback", "rdap", "crtsh", "dns", "http_probe",
                "ip_geo", "shodan_internetdb")
    out["source_checks"] = {s: {"status": "not_run", "detail": ""} for s in _sources}
    out["source_checks"]["linkedin"] = {
        "status": "manual",
        "detail": "No keyless public API — manual search link only; no LinkedIn data was fetched.",
    }

    def _check(source: str, status: str, detail: str = "") -> None:
        out["source_checks"][source] = {"status": status, "detail": str(detail)[:240]}

    def _record(result, err) -> None:
        nonlocal succeeded
        if err:
            _add_error(out["errors"], err)
        else:
            succeeded += 1

    def _record_data(label: str, data, err) -> None:
        nonlocal succeeded
        if err:
            _add_error(out["errors"], f"{label}: {err}")
        elif data is not None:
            succeeded += 1

    def _finish() -> dict:
        out["ok"] = succeeded > 0
        if not out["ok"]:
            _add_error(out["errors"], "No source returned data for this target.")
        return out

    if not company_name and not domains:
        out["errors"].append("Enter a company name or domain to map.")
        return _finish()

    out["pivots"] = pivot_links(terms, domains, company_name)
    out["manual_lookups"] = out["pivots"]

    # Job postings work for a company name or a domain-derived ATS slug.
    seed = Entity.make(EntityType.DOMAIN if domains else EntityType.COMPANY,
                       domains[0] if domains else company_name)
    jr, jerr = await _run_safe(_analyzer("jobs"), seed, "jobs")
    _record(jr, jerr)
    if jr and jr.findings:
        job_data = jr.findings[0].data
        out["jobs"] = job_data
        out["hiring"] = {
            "source": job_data.get("source"),
            "slug": job_data.get("slug"),
            "count": job_data.get("count"),
            "locations": job_data.get("locations", []),
            "departments": job_data.get("departments", []),
            "skills": job_data.get("skills", []),
            "postings": (job_data.get("postings") or [])[:20],
        }
        _check("jobs", "found",
               f"{job_data.get('count', 0)} live posts via {job_data.get('source')} "
               f"(board {job_data.get('slug')})")
    else:
        _check("jobs", "unavailable" if jerr else "not_found", jerr or "No public ATS board found")

    # Public filings confirm the legal entity, CIK and ticker for US companies.
    for term in terms[:3]:
        sr, serr = await _run_safe(_analyzer("sec_edgar"),
                                   Entity.make(EntityType.COMPANY, term),
                                   f"sec_edgar ({term})")
        _record(sr, serr)
        if sr and sr.findings and not out["filings"]:
            out["filings"] = sr.findings[0].data
    if out["filings"]:
        f = out["filings"]
        _check("sec_edgar", "verified",
               f"{(f.get('filers') or [])[:2]} · CIK {(f.get('ciks') or [])[:1]}")
    else:
        _check("sec_edgar", "not_found", "No filing naming this company was found")

    # Richer identity sources are opt-in because they add several HTTP calls.
    if deep:
        profile, perr = await wikipedia_profile(terms, country, domains, company_name)
        _record_data("wikipedia", profile, perr)
        facts = None
        if profile and profile.get("wikidata_id"):
            facts, ferr = await wikidata_facts(profile["wikidata_id"])
            _record_data("wikidata", facts, ferr)
            if facts:
                profile["facts"] = facts.get("facts", {})
                profile["wikidata_url"] = facts.get("url")
                _check("wikidata", "verified",
                       f"{facts.get('label')} · {len(facts.get('facts') or {})} attributes")
            else:
                _check("wikidata", "unavailable" if ferr else "not_found",
                       ferr or "No linked Wikidata entity")
        else:
            _check("wikidata", "not_run", "No Wikipedia identity to resolve")

        if profile:
            # Only a cross-checked article becomes a data panel. A similar name
            # alone is never enough to claim it describes this company.
            verified, reason = verify_organisation(profile, company_name, domains)
            profile["verified"] = verified
            profile["match"] = reason
            if verified:
                out["profile"] = profile
                _check("wikipedia", "verified", reason)
            else:
                out["profile"] = None
                _check("wikipedia", "unverified",
                       f"{profile.get('title')}: {reason}")
                _add_error(out["errors"],
                           f"wikipedia: discarded {profile.get('title')!r} — {reason}")
        else:
            _check("wikipedia", "unavailable" if perr else "not_found",
                   perr or "No matching Wikipedia article")

        org, oerr = await github_org(slug_candidates(company_name, domains),
                                     company_name, domains)
        if org:
            verified = org.get("verified")
            reason = org.get("match") or ""
            if verified is None:
                verified, reason = verify_organisation(org, company_name, domains)
            if verified:
                org["verified"] = True
                org["match"] = reason
                out["github"] = org
                _check("github", "verified", reason)
            else:
                _check("github", "unverified", reason)
                _add_error(out["errors"], f"github: no organisation verified — {reason}")
        else:
            _check("github", "not_found", oerr or "No matching public GitHub organisation")

        if domains:
            archive, aerr = await wayback_summary(domains)
            _record_data("wayback", archive, aerr)
            out["archive"] = archive
            _check("wayback", "found" if archive and archive.get("count") else
                   ("unavailable" if aerr else "not_found"),
                   aerr or (f"{archive.get('count')} snapshots" if archive else
                            "No archived pages"))

    if not domains:
        out["note"] = "Add a domain (e.g. acme.com) to map subdomains, registration and services."
        return _finish()

    domain = domains[0]
    dent = Entity.make(EntityType.DOMAIN, domain)

    # Registration data: registrar, dates, status and published contacts.
    rerr = None
    for d in domains[:3]:
        rr, rerr = await _run_safe(_analyzer("rdap"),
                                   Entity.make(EntityType.DOMAIN, d), f"rdap ({d})")
        _record(rr, rerr)
        if rr and rr.findings:
            out["registration"][d] = rr.findings[0].data
    _check("rdap", "found" if out["registration"] else
           ("unavailable" if rerr else "not_found"),
           rerr or (", ".join(out["registration"]) if out["registration"] else
                    "No public registration record"))

    (crt, crterr), (dnsr, dnserr), (tech, techerr) = await asyncio.gather(
        _run_safe(_analyzer("crtsh"), dent, "crtsh"),
        _run_safe(_analyzer("dns"), dent, "dns"),
        _run_safe(_analyzer("http_probe"), dent, "http_probe"),
    )
    for result, err in ((crt, crterr), (dnsr, dnserr), (tech, techerr)):
        _record(result, err)
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
    _check("crtsh", "found" if subs else ("unavailable" if crterr else "not_found"),
           crterr or (f"{len(subs)} certificate names" if subs else "No certificate names"))
    _check("dns", "found" if out["dns"] else ("unavailable" if dnserr else "not_found"),
           dnserr or ("DNS records returned" if out["dns"] else "No DNS records"))
    _check("http_probe", "found" if out["tech"] else ("unavailable" if techerr else "not_found"),
           techerr or (out["tech"].get("title") if out["tech"] else "No homepage response"))

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
    out["checked_ips"] = len(uniq)
    if not uniq:
        _add_error(out["errors"],
                   "resolve: no apex/subdomain IP resolved — ports and CVEs could not be checked")

    geo, sho = _analyzer("ip_geo"), _analyzer("shodan_internetdb")

    async def _ip_info(ip: str) -> dict:
        (g, gerr), (s, serr) = await asyncio.gather(
            _run_safe(geo, Entity.make(EntityType.IP, ip), f"ip_geo ({ip})"),
            _run_safe(sho, Entity.make(EntityType.IP, ip), f"shodan_internetdb ({ip})"),
        )
        _record(g, gerr)
        _record(s, serr)
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
    with_geo = any(any((s.get("geo") or {}).values()) for s in out["services"])
    with_ports = any((s.get("ports") or s.get("vulns")) for s in out["services"])
    _check("ip_geo", "found" if with_geo else "not_found",
           "IP location data" if with_geo else "No IP location data returned")
    _check("shodan_internetdb", "found" if with_ports else "not_found",
           "Ports/CVEs returned" if with_ports else "No exposed ports or CVEs reported")
    out["risk"] = _footprint_risk(out["services"], out["errors"], mapped=len(uniq))
    return _finish()


@router.get("/api/footprint")
async def footprint(target: str = "", name: str = "",
                    domains: Optional[list[str]] = None,
                    aliases: Optional[list[str]] = None,
                    country: str = "", deep: bool = False) -> dict:
    """Map a company's footprint from the legacy single-target query string.

    Plain defaults keep direct calls (used by the CLI/tests) working while
    FastAPI still exposes each parameter as an optional query parameter.
    """
    return await _build_footprint(target, name, domains, aliases, country, deep)


@router.post("/api/footprint")
async def footprint_post(body: FootprintRequest) -> dict:
    """Structured company intake used by the expanded footprint UI."""
    return await _build_footprint(
        body.target, body.name, body.domains, body.aliases, body.country, body.deep
    )
