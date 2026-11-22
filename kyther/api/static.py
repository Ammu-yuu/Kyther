"""App shell + PWA static assets."""
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import MutableHeaders

router = APIRouter()
WEB_DIR = Path(__file__).parent.parent / "web"


class RevalidatedStaticFiles(StaticFiles):
    """Serve split JS/CSS with no-cache so a redeploy never serves stale code."""

    async def __call__(self, scope, receive, send):
        async def send_with_cache(message):
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["Cache-Control"] = "no-cache"
            await send(message)
        await super().__call__(scope, receive, send_with_cache)


@router.get("/")
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


# ── PWA: manifest, service worker, and app icons (for add-to-home-screen) ────
@router.get("/manifest.webmanifest")
async def manifest() -> FileResponse:
    return FileResponse(WEB_DIR / "manifest.webmanifest",
                        media_type="application/manifest+json")


@router.get("/sw.js")
async def service_worker() -> FileResponse:
    # served from the site root so its scope covers the whole app
    return FileResponse(WEB_DIR / "sw.js", media_type="application/javascript",
                        headers={"Cache-Control": "no-cache"})


# Static mounts are attached to the FastAPI app in kyther/api/__init__.py —
# APIRouter.include_router() does not carry Mount routes across.
