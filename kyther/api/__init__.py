"""FastAPI service exposing the orchestration engine + the web UI.

    uvicorn kyther.api:app --reload --port 8099

The application is assembled here from focused routers (``scan``, ``feeds``,
``threats``, ``pulse``, ``footprint``, ``image``, ``audit``, ``static``).
The well-known symbols are re-exported so existing imports keep working.
"""
from __future__ import annotations

import importlib

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from ..net import close_client, get_client, sanitize_public_url
from ..security import KytherMiddleware, allowed_origins

app = FastAPI(title="Kyther", version="0.1.0")

# Only the local UI (or an explicitly configured tailnet origin) may call the
# API cross-origin. Same-origin requests are unaffected. Override with
# KYTHER_ALLOWED_ORIGINS="http://100.x.y.z:8099,..." when running on the tailnet.
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Per-IP rate limit + conservative response headers for every endpoint.
app.add_middleware(KytherMiddleware)

from . import audit, feeds, footprint, image, pulse, scan, static, threats  # noqa: E402

for _router in (static.router, feeds.router, threats.router, pulse.router,
                scan.router, footprint.router, image.router, audit.router):
    app.include_router(_router)

# Mounted here (not on the router) so FastAPI actually registers them. CSS +
# ES modules are rebuilt per deploy; no-cache prevents a stale JS shell.
app.mount("/icons", StaticFiles(directory=static.WEB_DIR / "icons"), name="icons")
app.mount("/assets", static.RevalidatedStaticFiles(directory=static.WEB_DIR / "assets"),
          name="assets")


@app.on_event("shutdown")
async def _shutdown_http() -> None:
    await close_client()


@app.on_event("startup")
async def _threats_startup() -> None:
    # The package re-exports `threats` as the endpoint function below, so fetch
    # the real module for startup hooks instead of using the shadowed name.
    module = importlib.import_module(".threats", __package__)
    module.load_persisted()
    await module.start_refresher()


# Backwards-compatible imports for callers that used the old single module.
from .builders import (  # noqa: E402
    _CATEGORY, _CONFIDENCE, _build_dossier, _build_graph, _build_risk,
    _build_timeline, _confidence_for, _finding_dict,
)
from .feeds import _NEWS_CACHE, news, reddit_lookup  # noqa: E402
from .footprint import (  # noqa: E402
    _FOOTPRINT_TIMEOUT, _add_error, _analyzer, _footprint_risk, _resolve_ips,
    _run_safe, footprint,
)
from .image import _IMG_MAX_BYTES, _decode_image_data, image_intel  # noqa: E402
from .models import ImageRequest, MAX_DEPTH, ScanRequest  # noqa: E402
from .pulse import (  # noqa: E402
    PULSE_EDITIONS, PULSE_REGIONS, _PULSE_CACHE, _gnews_search, _parse_rss,
    _pulse_cached, _pulse_read, _rss_articles, pulse_topic, pulse_trending,
)
from .scan import _perform_scan, list_analyzers, make_report, run_scan  # noqa: E402
from .threats import _THREATS_CACHE, threats  # noqa: E402

__all__ = [
    "app", "ScanRequest", "ImageRequest", "MAX_DEPTH",
    "news", "reddit_lookup", "threats", "pulse_trending", "pulse_topic",
    "list_analyzers", "run_scan", "footprint", "image_intel", "make_report",
    "_parse_rss", "_rss_articles", "_pulse_read", "_footprint_risk",
    "_decode_image_data", "_perform_scan", "get_client", "close_client",
    "sanitize_public_url", "allowed_origins", "KytherMiddleware",
]
