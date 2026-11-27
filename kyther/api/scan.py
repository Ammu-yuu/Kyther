"""Orchestrated scan, analyzer catalog and PDF report endpoints."""
from __future__ import annotations

import asyncio
import time
from dataclasses import asdict

from fastapi import APIRouter
from fastapi.responses import Response

from ..core import registry
from ..core.entities import Confidence, Entity, EntityType, Finding, detect_type
from ..core.orchestrator import scan
from ..report import Report
from .builders import (
    _build_dossier, _build_graph, _build_risk, _build_timeline, _finding_dict,
    build_source_checks,
)
from .models import ScanRequest

router = APIRouter()


@router.get("/api/analyzers")
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
        "source_checks": build_source_checks(seed_out, result.checks, result.errors),
        "errors": result.errors,
    }


@router.post("/api/scan")
async def run_scan(req: ScanRequest) -> dict:
    return await _perform_scan(req)

@router.post("/api/report")
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
