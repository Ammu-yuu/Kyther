"""Keyless public-source enrichment for Company Footprint.

Only fixed, public endpoints are contacted. User input is passed as a query
term or a GitHub slug; it never becomes an arbitrary host. Every third-party
URL that reaches the browser is run through :func:`sanitize_public_url`.
"""
from __future__ import annotations

import html
import re
from urllib.parse import quote, urlsplit

from .net import get_client, sanitize_public_url

# Legal suffixes are useful for deriving search/slug candidates but should not
# be stripped from the name shown back to the user.
_LEGAL_SUFFIX = re.compile(
    r"\b(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|gmbh|"
    r"plc|bv|sa|sas|ag|pty|holdings|group)\b",
    re.IGNORECASE,
)
_TAG_RE = re.compile(r"<[^>]+>")
_SPACE_RE = re.compile(r"\s+")


def _uniq(values) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        v = str(v or "").strip()
        if v and v.lower() not in seen:
            seen.add(v.lower())
            out.append(v)
    return out


def clean_terms(values) -> list[str]:
    """Split comma/newline/semicolon input into unique display terms."""
    if isinstance(values, str):
        parts = re.split(r"[,;\n]+", values)
    elif values:
        parts = list(values)
    else:
        parts = []
    return _uniq(_SPACE_RE.sub(" ", str(p)) for p in parts)[:12]


def search_terms(name: str, aliases=None, country: str = "") -> list[str]:
    """Names to try against public search APIs, including suffix-free variants."""
    out: list[str] = []
    for term in _uniq([name, *(aliases or [])])[:5]:
        term = term.strip(" ,.;:-")
        if term:
            out.append(term)
        short = _LEGAL_SUFFIX.sub("", term).strip(" ,.;:-")
        if short and short.lower() != term.lower():
            out.append(short)
    # A country hint disambiguates common names, but exact names come first so
    # a generic "Robot" match never outranks "Alias Robotics".
    if country:
        out = out[:3] + [f"{t} {country.strip()}" for t in out[:3]]
    return _uniq(out)[:6]


def slug_candidates(name: str, domains=None) -> list[str]:
    """Likely GitHub organisation slugs from domain labels and company names."""
    out: list[str] = []
    for domain in domains or []:
        label = domain.split(".")[0].lower()
        out.append(re.sub(r"[^a-z0-9]", "", label))
    for term in search_terms(name, [], "")[:4]:
        out.append(re.sub(r"[^a-z0-9]", "", term.lower()))
    return [s for s in _uniq(out) if 2 <= len(s) <= 39][:4]


def _http_url(value) -> str | None:
    """Normalise a source-provided URL before it can become a link."""
    text = str(value or "").strip()
    if not text:
        return None
    if not text.startswith(("http://", "https://")):
        text = "https://" + text.lstrip("/")
    return sanitize_public_url(text)


async def _get_json(url: str, *, params: dict | None = None,
                    headers: dict | None = None, timeout: float = 10.0):
    """GET JSON from a fixed endpoint, returning (payload, error)."""
    try:
        resp = await get_client().get(url, params=params, headers=headers, timeout=timeout)
    except Exception as exc:
        return None, f"{urlsplit(url).netloc}: request failed ({type(exc).__name__})"
    if resp.status_code != 200:
        return None, f"{urlsplit(url).netloc}: HTTP {resp.status_code}"
    try:
        return resp.json(), None
    except ValueError:
        return None, f"{urlsplit(url).netloc}: invalid JSON"


# ---------------------------------------------------------------------------
# Wikipedia + Wikidata: identity, sector, HQ, people and public filings metadata
# ---------------------------------------------------------------------------
def _norm_text(value) -> str:
    return _SPACE_RE.sub(" ", re.sub(r"[^a-z0-9]+", " ", str(value or "").lower())).strip()


def _host(value) -> str:
    """Return the hostname of a URL-ish value, without port or leading www."""
    try:
        host = urlsplit(str(value or "").strip()).netloc.lower()
    except Exception:
        return ""
    return host.split(":")[0].lstrip("www.")


def _registrable(host: str) -> str:
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _names_match(candidate, primary) -> tuple[bool, str]:
    """Strict-ish identity check: strip legal suffixes, then compare names."""
    candidate = str(candidate or "")
    primary = str(primary or "")
    short_c = _norm_text(_LEGAL_SUFFIX.sub("", candidate))
    short_p = _norm_text(_LEGAL_SUFFIX.sub("", primary))
    full_c, full_p = _norm_text(candidate), _norm_text(primary)
    if not short_c or not short_p:
        return False, ""
    if short_c == short_p or full_c == full_p:
        return True, f"name matches {candidate!r}"
    if short_p in short_c or short_c in short_p:
        # 'Acme' inside 'Acme Robotics' is fine; guard against tiny generic stems.
        if min(len(short_c), len(short_p)) >= 4:
            return True, f"name matches {candidate!r}"
    p_tokens, c_tokens = set(short_p.split()), set(short_c.split())
    if p_tokens and c_tokens and len(p_tokens & c_tokens) / len(p_tokens) >= 0.6:
        return True, f"name matches {candidate!r}"
    return False, ""


def verify_organisation(candidate: dict | None, name: str,
                        domains=None) -> tuple[bool, str]:
    """Cross-check a public-source candidate against what the user entered.

    A result is only shown as *data* when its official website matches a known
    domain, or its name clearly matches the company. This stops a same-slug
    GitHub org or a similar-sounding Wikipedia article being presented as fact.
    """
    if not candidate:
        return False, "no candidate returned"

    domain_bases = {_registrable(_host(d) or str(d).lower()) for d in (domains or [])}
    websites = [candidate.get(k) for k in ("official_website", "blog", "url", "website")]
    websites += ((candidate.get("facts") or {}).get("Official website") or [])
    hosts = {_registrable(_host(v)) for v in websites if _host(v)}
    shared = (hosts & domain_bases) - {""}
    if shared:
        return True, f"official website matches {sorted(shared)[0]}"

    for key in ("title", "name", "login", "label"):
        ok, reason = _names_match(candidate.get(key), name)
        if ok:
            return True, reason

    text = " ".join(str(candidate.get(k) or "") for k in ("description", "summary"))
    if len(_norm_text(name)) >= 6:
        ok, reason = _names_match(text, name)
        if ok:
            return True, f"profile text mentions {name!r}"

    return False, "no matching name or official website"


def _profile_score(page: dict, primary: str, domains=None) -> float:
    """Reject lookalike articles ('Robot' for 'Alias Robotics')."""
    title = _norm_text(page.get("title"))
    base = _norm_text(primary)
    score = 0.0
    if base:
        if base in title:
            score += 100
        elif title and title in base:
            score += 80
        base_tokens, title_tokens = set(base.split()), set(title.split())
        if base_tokens:
            score += 50 * len(base_tokens & title_tokens) / len(base_tokens)
    domain_tokens: set[str] = set()
    for domain in domains or []:
        domain_tokens.update(_norm_text(str(domain).split(".")[0]).split())
    if domain_tokens and set(title.split()) & domain_tokens:
        score += 30
    if re.search(r"\b(fictional|character|film|series|song|album)\b", title):
        score -= 60
    return score


async def wikipedia_profile(terms: list[str], country: str = "",
                            domains=None, primary: str = ""):
    """Find a Wikipedia article that actually matches the company name."""
    last_error = None
    base = _norm_text(primary or (terms[0] if terms else ""))
    queries: list[str] = []
    for term in _uniq([primary, *(terms or [])])[:4]:
        queries.extend([f'"{term}"', term])
    best, best_score = None, 0.0

    for query in _uniq(queries)[:6]:
        data, err = await _get_json(
            "https://en.wikipedia.org/w/api.php",
            params={
                "action": "query", "generator": "search", "gsrsearch": query,
                "gsrnamespace": 0, "gsrlimit": 5, "prop": "extracts|pageprops|info",
                "exintro": 1, "explaintext": 1, "inprop": "url", "format": "json",
            },
            timeout=10,
        )
        if err:
            last_error = err
            continue
        pages = (((data or {}).get("query") or {}).get("pages") or {}).values()
        for page in sorted(pages, key=lambda p: p.get("index", 99)):
            summary = str(page.get("extract") or "").strip()
            if not summary or "may refer to" in summary[:160].lower():
                continue
            score = _profile_score(page, base, domains)
            if score > best_score and score >= 25:
                best_score = score
                best = {
                    "query": query,
                    "title": page.get("title"),
                    "summary": summary[:1600],
                    "url": sanitize_public_url(page.get("fullurl")),
                    "wikidata_id": ((page.get("pageprops") or {}).get("wikibase_item")),
                }
        if best_score >= 100:
            break
    return best, None if best else last_error


_WIKIDATA_PROPS = {
    "Country": "P17",
    "Headquarters": "P159",
    "Founded": "P571",
    "Founder": "P112",
    "CEO": "P169",
    "Industry": "P452",
    "Employees": "P1128",
    "Official website": "P856",
    "Parent organisation": "P749",
    "Subsidiaries": "P355",
    "Stock exchange": "P249",
    "Ticker symbol": "P1994",
    "Legal form": "P1454",
}


def _claim_values(claims: list) -> list[str]:
    out: list[str] = []
    for claim in claims or []:
        value = (((claim or {}).get("mainsnak") or {}).get("datavalue") or {}).get("value")
        if isinstance(value, dict):
            if value.get("id"):
                out.append(str(value["id"]))
            elif value.get("time"):
                out.append(str(value["time"])[1:11])
            elif value.get("text"):
                out.append(str(value["text"])[:200])
            elif value.get("amount") is not None:
                out.append(str(value["amount"]).lstrip("+")[:40])
            elif "latitude" in value and "longitude" in value:
                out.append(f"{value['latitude']}, {value['longitude']}")
        elif isinstance(value, (str, int, float)):
            out.append(str(value)[:200])
    return out


async def wikidata_facts(qid: str):
    """Turn a Wikidata entity's claims into labelled, source-linked facts."""
    entity, err = await _get_json(
        f"https://www.wikidata.org/wiki/Special:EntityData/{quote(qid, safe='')}.json",
        timeout=10,
    )
    if err:
        return None, err
    ent = (((entity or {}).get("entities") or {}).get(qid) or {})
    if not ent:
        return None, None

    raw: dict[str, list[str]] = {}
    refs: list[str] = []
    for label, prop in _WIKIDATA_PROPS.items():
        values = _uniq(_claim_values((ent.get("claims") or {}).get(prop)))
        if not values:
            continue
        raw[label] = values[:8]
        refs.extend(v for v in values if re.fullmatch(r"Q\d+", v))

    labels: dict[str, str] = {}
    if refs:
        lookup, _ = await _get_json(
            "https://www.wikidata.org/w/api.php",
            params={
                "action": "wbgetentities", "ids": "|".join(_uniq(refs)[:40]),
                "props": "labels", "languages": "en", "format": "json",
            },
            timeout=10,
        )
        for ref, obj in (((lookup or {}).get("entities") or {}).items()):
            label = (((obj.get("labels") or {}).get("en") or {}).get("value"))
            if label:
                labels[ref] = label

    facts = {
        label: _uniq(labels.get(v, v) for v in values)
        for label, values in raw.items()
    }
    return {
        "id": qid,
        "label": (((ent.get("labels") or {}).get("en") or {}).get("value")) or qid,
        "facts": facts,
        "url": sanitize_public_url(f"https://www.wikidata.org/wiki/{quote(qid, safe='')}"),
    }, None


# ---------------------------------------------------------------------------
# GitHub organisation profile and public repositories
# ---------------------------------------------------------------------------
async def github_org(slugs: list[str], name: str = "", domains=None):
    """Find a public GitHub org that actually matches the company.

    A slug existing is not proof it belongs to the target, so each candidate is
    cross-checked against the entered name/domain before it becomes data.
    """
    headers = {"Accept": "application/vnd.github+json"}
    last_error = None
    for slug in (slugs or [])[:4]:
        obj, err = await _get_json(
            f"https://api.github.com/orgs/{quote(slug, safe='')}",
            headers=headers, timeout=8,
        )
        if err:
            if "HTTP 404" not in err:
                last_error = err
            continue
        if not isinstance(obj, dict) or not obj.get("login"):
            continue
        repos_obj, _ = await _get_json(
            f"https://api.github.com/orgs/{quote(slug, safe='')}/repos",
            params={"per_page": 20, "sort": "updated", "direction": "desc"},
            headers=headers, timeout=8,
        )
        repos = []
        languages: set[str] = set()
        for repo in (repos_obj if isinstance(repos_obj, list) else [])[:20]:
            if not isinstance(repo, dict):
                continue
            if repo.get("language"):
                languages.add(repo["language"])
            repos.append({
                "name": repo.get("name"),
                "description": str(repo.get("description") or "")[:300],
                "language": repo.get("language"),
                "url": sanitize_public_url(repo.get("html_url")),
                "updated": repo.get("updated_at"),
                "stars": repo.get("stargazers_count"),
                "forks": repo.get("forks_count"),
                "topics": (repo.get("topics") or [])[:8],
            })
        candidate = {
            "login": obj.get("login"),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "blog": _http_url(obj.get("blog")),
            "location": obj.get("location"),
            "email": obj.get("email"),
            "public_repos": obj.get("public_repos"),
            "followers": obj.get("followers"),
            "created": obj.get("created_at"),
            "url": sanitize_public_url(obj.get("html_url")),
            "languages": sorted(languages),
            "repos": repos,
        }
        verified, reason = verify_organisation(candidate, name or slug, domains)
        if not verified:
            last_error = f"github: no organisation verified for {slug!r} ({reason})"
            continue
        candidate["verified"] = True
        candidate["match"] = reason
        return candidate, None
    return None, last_error or "github: no public organisation found"


# ---------------------------------------------------------------------------
# Internet Archive: how long a domain has been publishing, and where
# ---------------------------------------------------------------------------
async def wayback_summary(domains: list[str]):
    """Summarise archived pages for a domain, with a lightweight fallback."""
    last_error = None
    for domain in (domains or [])[:2]:
        rows, err = await _get_json(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{domain}/*", "output": "json", "fl": "timestamp,original",
                "filter": "statuscode:200", "filter": "mimetype:text/html",
                "collapse": "timestamp:6", "limit": 120, "from": 2015,
            },
            timeout=15,
        )
        if not err:
            if not isinstance(rows, list) or len(rows) <= 1:
                return {"domain": domain, "count": 0, "first": None, "last": None,
                        "samples": []}, None
            entries = [r for r in rows[1:] if isinstance(r, list) and len(r) >= 2]
            stamps = sorted(str(r[0]) for r in entries)
            samples = []
            for stamp, original in entries[:8]:
                link = sanitize_public_url(
                    f"https://web.archive.org/web/{stamp}/{original}"
                )
                if link:
                    samples.append({"date": stamp[:8], "url": link,
                                    "original": str(original)[:200]})
            return {
                "domain": domain,
                "count": len(entries),
                "first": stamps[0][:8] if stamps else None,
                "last": stamps[-1][:8] if stamps else None,
                "samples": samples,
            }, None

        # Some networks cannot complete TLS to web.archive.org's CDX host.
        # archive.org's availability endpoint is smaller and often reachable.
        last_error = err
        avail, aerr = await _get_json(
            "https://archive.org/wayback/available",
            params={"url": domain}, timeout=10,
        )
        if aerr:
            last_error = aerr
            continue
        snap = (((avail or {}).get("archived_snapshots") or {}).get("closest") or {})
        if not snap.get("available"):
            return {"domain": domain, "count": 0, "first": None, "last": None,
                    "samples": []}, None
        stamp = str(snap.get("timestamp") or "")[:8] or None
        link = sanitize_public_url(snap.get("url"))
        return {
            "domain": domain,
            "count": 1,
            "first": stamp,
            "last": stamp,
            "samples": ([{"date": stamp, "url": link, "original": domain}] if link else []),
            "partial": True,
            "note": "CDX index unavailable — showing the closest archived snapshot only.",
        }, None
    return None, last_error


# ---------------------------------------------------------------------------
# Manual pivots: fixed-host search launchers, never fetched by Kyther
# ---------------------------------------------------------------------------
def pivot_links(terms: list[str], domains: list[str], name: str = "") -> list[dict]:
    """Ready-made external searches so a user can continue the investigation."""
    primary = name or (terms[0] if terms else "")
    if not primary and domains:
        primary = domains[0]
    if not primary:
        return []
    q = quote(f'"{primary}"', safe="")
    plain = quote(primary, safe="")
    links: list[dict] = []

    def add(label: str, url: str, group: str) -> None:
        safe = sanitize_public_url(url)
        if safe:
            links.append({"label": label, "url": safe, "group": group, "manual": True})

    # Every label says "Search" — these are launchers for the user to open, not
    # data Kyther fetched. LinkedIn in particular has no keyless public API.
    add("Google", f"https://www.google.com/search?q={q}", "Search engines (manual)")
    add("Bing", f"https://www.bing.com/search?q={q}", "Search engines (manual)")
    add("DuckDuckGo", f"https://duckduckgo.com/?q={q}", "Search engines (manual)")
    add("News", f"https://www.google.com/search?q={q}&tbm=nws", "Search engines (manual)")
    add("Search LinkedIn", f"https://www.linkedin.com/company/?keywords={plain}",
        "Profiles (manual)")
    add("Search GitHub", f"https://github.com/search?q={plain}&type=repositories",
        "Code (manual)")
    add("Search SEC EDGAR",
        f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company={plain}"
        "&owner=include&count=40", "Filings (manual)")
    add("Search Wikidata", f"https://www.wikidata.org/w/index.php?search={plain}",
        "Identity (manual)")

    for domain in (domains or [])[:3]:
        safe_domain = quote(domain, safe=".")
        add(f"crt.sh · {domain}", f"https://crt.sh/?q=%.{safe_domain}",
            "Infrastructure (manual)")
        add(f"Wayback · {domain}", f"https://web.archive.org/web/*/{safe_domain}/*",
            "Infrastructure (manual)")
        add(f"Google docs · {domain}",
            f"https://www.google.com/search?q={quote(f'site:{domain} filetype:pdf', safe='')}",
            "Documents (manual)")
    return links[:18]
