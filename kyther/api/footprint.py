"""Company Footprint: subdomains, DNS, exposed services and jobs."""
from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, Query

from ..core import registry
from ..core.entities import AnalyzerResult, Entity, EntityType, _DOMAIN_RE
from ..net import get_client

router = APIRouter()


# --------------------------------------------------------------------------
# Company Footprint — aggregates a company's external surface (subdomains, DNS,
# tech, exposed services) plus its public hiring signals (job postings) into
# one company-centric view. All keyless, built from existing analyzers + jobs.
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


@router.get("/api/footprint")
async def footprint(target: str = Query(..., min_length=1, max_length=253)) -> dict:
    """Map a company's external footprint: subdomains, DNS, services, job posts."""
    registry.load_builtins()
    t = target.strip().lower()
    is_domain = bool(_DOMAIN_RE.match(t))
    domain = t if is_domain else None
    out: dict = {
        "ok": True,
        "target": target,
        "domain": domain,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "subdomains": [],
        "dns": {},
        "tech": {},
        "services": [],
        "jobs": None,
        "errors": [],
    }
    succeeded = 0

    def _record(result, err) -> None:
        nonlocal succeeded
        if err:
            _add_error(out["errors"], err)
        else:
            succeeded += 1

    def _finish() -> dict:
        out["ok"] = succeeded > 0
        if not out["ok"]:
            _add_error(out["errors"], "No source returned data for this target.")
        return out

    # Job postings run for either a company name or a domain (slug-derived).
    seed_type = EntityType.DOMAIN if is_domain else EntityType.COMPANY
    jr, jerr = await _run_safe(_analyzer("jobs"), Entity.make(seed_type, t), "jobs")
    _record(jr, jerr)
    if jr and jr.findings:
        out["jobs"] = jr.findings[0].data

    # Infrastructure mapping needs a domain.
    if not domain:
        out["note"] = "Give a domain (e.g. acme.com) to map subdomains and services."
        return _finish()

    dent = Entity.make(EntityType.DOMAIN, domain)
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
    out["risk"] = _footprint_risk(out["services"], out["errors"], mapped=len(uniq))
    return _finish()
