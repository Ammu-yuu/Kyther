# Kyther

A plugin-based **OSINT orchestration engine** with a terminal-style web console.
Seed it with an entity — a username, email, domain, IP, phone, person, or company
— and it runs every compatible analyzer concurrently, then *pivots* on what it
discovers (username → email → domain, domain → IPs → ASNs, …) up to a
configurable depth. That entity-correlation loop is what makes it an
orchestrator rather than a one-shot lookup.

> **Scope & ethics.** Analyzers use only **public, no-auth data** (or an optional
> bring-your-own key you supply). No auth bypass, no paywalled scraping, no
> captcha-solving. Use it only against targets you're authorized to investigate —
> authorized security research, CTFs, and education.

## Install

```bash
cd Kyther
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Web console

```bash
uvicorn kyther.api:app --port 8099
# then open http://127.0.0.1:8099
```

The **Kyther** terminal lets you run `search --username <x>` (or `--email`,
`--domain`, `--ip`, `--phone`), with a quick-search bar, a live dashboard,
a persistent search log, and a Hacker News security feed.

Opt-in heavy analyzers are enabled via env vars, e.g.:

```bash
OSINT_ENABLE_HOLEHE=1 uvicorn kyther.api:app --port 8099
```

## CLI

```bash
python -m kyther.cli scan example.com --depth 2
python -m kyther.cli scan someone@example.com --json
python -m kyther.cli sherlock SakuraSnowAngelAiko   # Sherlock-only username check
python -m kyther.cli holehe test@example.com        # Holehe-only email check
python -m kyther.cli list                           # registered analyzers
```

## Analyzers (18)

| Input | Analyzers |
|-------|-----------|
| username | WhatsMyName (719 sites) · Sherlock (413) · profile enrichment · GitHub-commit emails |
| email | Gravatar · GitHub pivot · Holehe* · HIBP* · EmailRep* |
| domain / IP | DNS · RDAP · crt.sh · HTTP probe · Shodan InternetDB · geolocation · Hunter* |
| phone | offline `phonenumbers` intelligence |
| company | SEC EDGAR |
| person | investigative search links |

`*` = needs a free key or an opt-in flag; off by default.

## Architecture

```
seed entity ─► orchestrator ─► [analyzers accepting this type] ─► findings
                    ▲                                              │
                    └──────────── discovered entities ◄────────────┘
                              (depth-limited BFS pivot)
```

- **`kyther/core/`** — entity model, plugin registry, async pivot engine, SSRF guard.
- **`kyther/analyzers/`** — one file per source. Add a plugin by dropping a module here.
- **`kyther/api.py`** — FastAPI service + the terminal web UI.
- **`kyther/web/index.html`** — the Kyther console (self-contained).
