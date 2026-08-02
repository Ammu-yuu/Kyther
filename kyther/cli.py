"""Command-line entrypoint.

    python -m kyther.cli scan example.com --depth 2
    python -m kyther.cli scan someone@example.com --json
    python -m kyther.cli sherlock SakuraSnowAngelAiko   # Sherlock-only check
    python -m kyther.cli list          # show registered analyzers
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict

from .core import registry
from .core.entities import Entity, EntityType, detect_type
from .core.orchestrator import scan

try:
    from rich.console import Console
    from rich.tree import Tree
    _console = Console()
except ImportError:  # rich is optional; degrade to plain output
    _console = None


def _print_plain(result) -> None:
    print(f"\nScan of {result.seed}  ({len(result.entities)} entities, "
          f"{len(result.findings)} findings)\n")
    for f in result.findings:
        print(f"[{f.severity}] {f.analyzer} :: {f.entity}")
        print(f"    {f.title}")
        print("    " + json.dumps(f.data, default=str)[:500])
    if result.errors:
        print(f"\n{len(result.errors)} errors (use --json to inspect)")


def _print_rich(result) -> None:
    tree = Tree(
        f"[bold]{result.seed}[/bold]  "
        f"[dim]{len(result.entities)} entities · {len(result.findings)} findings[/dim]"
    )
    by_entity: dict[str, list] = {}
    for f in result.findings:
        by_entity.setdefault(f.entity.key, []).append(f)

    for key, findings in by_entity.items():
        node = tree.add(f"[cyan]{key}[/cyan]")
        for f in findings:
            color = {"info": "white", "low": "yellow",
                     "medium": "orange3", "high": "red"}.get(f.severity, "white")
            leaf = node.add(f"[{color}]{f.title}[/{color}] [dim]({f.analyzer})[/dim]")
            for k, v in f.data.items():
                leaf.add(f"[dim]{k}[/dim]: {str(v)[:160]}")
    _console.print(tree)
    if result.errors:
        _console.print(f"\n[dim]{len(result.errors)} non-fatal errors[/dim]")


def _cmd_scan(args) -> int:
    etype = EntityType(args.type) if args.type != "auto" else detect_type(args.target)
    seed = Entity.make(etype, args.target)

    def progress(analyzer: str, entity) -> None:
        if _console and not args.json:
            _console.log(f"[dim]running[/dim] {analyzer} [dim]on[/dim] {entity}")

    result = asyncio.run(scan(seed, max_depth=args.depth, progress=progress))

    if args.json:
        print(json.dumps({
            "seed": seed.key,
            "entities": list(result.entities.keys()),
            "findings": [asdict(f) for f in result.findings],
            "errors": result.errors,
        }, default=str, indent=2))
    elif _console:
        _print_rich(result)
    else:
        _print_plain(result)
    return 0


def _cmd_list(args) -> int:
    registry.load_builtins()
    for a in registry.all_analyzers():
        status = "ok" if a.available() else f"needs ${a.env_key}"
        accepts = ", ".join(sorted(str(t) for t in a.accepts))
        line = f"{a.name:14} [{status:16}] accepts: {accepts}\n    {a.description}"
        print(line)
    return 0


def _cmd_sherlock(args) -> int:
    """Run only the Sherlock analyzer on a username (a focused, fast check)."""
    from .analyzers.sherlock import Sherlock

    ent = Entity.make(EntityType.USERNAME, args.target)
    result = asyncio.run(Sherlock().run(ent))
    profiles = [p for f in result.findings for p in f.data.get("profiles", [])]

    if args.json:
        print(json.dumps(profiles, indent=2))
        return 0
    header = f"Sherlock — {args.target}: {len(profiles)} of 413 sites"
    if _console:
        _console.print(f"[bold]{header}[/bold]")
    else:
        print(header)
    for p in sorted(profiles, key=lambda x: x["platform"].lower()):
        print(f"  {p['platform']:26} {p['url']}")
    if result.error:
        print(f"\nnote: {result.error}")
    return 0


def _cmd_holehe(args) -> int:
    """Run only Holehe on an email: which sites it's registered on."""
    from .analyzers.holehe_email import HoleheEmail

    if "@" not in args.target:
        print(f"holehe needs an email address, not '{args.target}'")
        return 2

    ent = Entity.make(EntityType.EMAIL, args.target)
    result = asyncio.run(HoleheEmail().run(ent))
    sites = [s for f in result.findings for s in f.data.get("sites", [])]

    if args.json:
        print(json.dumps(sites, indent=2))
        return 0
    header = f"Holehe — {args.target}: registered on {len(sites)} site(s)"
    if _console:
        _console.print(f"[bold]{header}[/bold]")
    else:
        print(header)
    for s in sorted(sites, key=lambda x: (x.get("site") or "")):
        extra = ""
        if s.get("recovery_email"):
            extra += f"  recovery: {s['recovery_email']}"
        if s.get("recovery_phone"):
            extra += f"  phone: {s['recovery_phone']}"
        print(f"  {(s.get('site') or s.get('domain') or '?'):22}{extra}")
    if result.error:
        print(f"\nnote: {result.error}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kyther", description="OSINT orchestration engine.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Run an orchestrated scan on a target.")
    p_scan.add_argument("target", help="domain / ip / email / username / name")
    p_scan.add_argument("--type", default="auto",
                        choices=["auto"] + [t.value for t in EntityType],
                        help="override entity-type detection")
    p_scan.add_argument("--depth", type=int, default=2, help="pivot recursion depth")
    p_scan.add_argument("--json", action="store_true", help="machine-readable output")
    p_scan.set_defaults(func=_cmd_scan)

    p_list = sub.add_parser("list", help="List registered analyzers.")
    p_list.set_defaults(func=_cmd_list)

    p_sher = sub.add_parser("sherlock", help="Run only the Sherlock username check.")
    p_sher.add_argument("target", help="username to check")
    p_sher.add_argument("--json", action="store_true", help="machine-readable output")
    p_sher.set_defaults(func=_cmd_sherlock)

    p_hole = sub.add_parser("holehe", help="Run only Holehe: which sites an email is registered on.")
    p_hole.add_argument("target", help="email address to check")
    p_hole.add_argument("--json", action="store_true", help="machine-readable output")
    p_hole.set_defaults(func=_cmd_holehe)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
