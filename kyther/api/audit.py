"""Security self-audit (Bandit + pip-audit) endpoint."""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

from fastapi import APIRouter

router = APIRouter()


# --------------------------------------------------------------------------
# Security self-audit — runs the same open-source scanners we recommend
# (Bandit for the Python source, pip-audit for dependency CVEs) against
# Kyther's own package and returns structured results for the UI.
#
# The scan target is fixed to this package directory — no user input is ever
# passed to the subprocess, and both tools run via `sys.executable -m ...` so
# we use whatever is installed in the active venv, never a shell.
# --------------------------------------------------------------------------
_PKG_DIR = Path(__file__).parent.parent      # the kyther/ package (audit target)
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


@router.post("/api/audit")
async def run_audit() -> dict:
    """Self-audit Kyther: Bandit (source) + pip-audit (dependencies), in parallel."""
    bandit, deps = await asyncio.gather(_audit_bandit(), _audit_deps())
    return {
        "ok": True,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "bandit": bandit,
        "deps": deps,
    }
