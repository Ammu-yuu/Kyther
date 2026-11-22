"""Image Intelligence: EXIF/GPS extraction and verification launchers."""
from __future__ import annotations

import asyncio
import base64
import binascii

from fastapi import APIRouter

from .. import imageintel
from ..core import netguard
from ..net import sanitize_public_url
from .models import ImageRequest

router = APIRouter()


# --------------------------------------------------------------------------
# Image Intelligence — assisted verification & geolocation of a photo.
# EXIF/metadata + GPS extraction (keyless), a provenance *verdict* that reads
# the signals and says what to do next, GPS → place (reverse geocode) + map
# links, and reverse-image-search launchers (manual, no scraping). Full auto
# earliest-upload / visual geolocation needs a paid key or vision AI and is
# deliberately out of scope.
# --------------------------------------------------------------------------

_IMG_MAX_BYTES = 25 * 1024 * 1024
_CORE_IMAGE_FORMATS = {"JPEG", "PNG", "GIF", "WEBP", "BMP", "TIFF"}


def _decode_image_data(value: str) -> tuple[bytes | None, str | None]:
    """Strictly decode base64 (optionally an image/* data: URL)."""
    data = (value or "").strip()
    if data.lower().startswith("data:"):
        header, sep, payload = data.partition(",")
        if not sep:
            return None, "invalid data URL (missing ',')"
        parts = [p.strip() for p in header[5:].split(";")]
        mime = parts[0].lower()
        if "/" not in mime:
            return None, "invalid data URL MIME type"
        if not mime.startswith("image/"):
            return None, f"data URL must be an image (got {mime})"
        if "base64" not in [p.lower() for p in parts[1:]]:
            return None, "data URL must be base64 encoded"
        data = payload.strip()
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        return None, "invalid base64 image data"
    if not raw:
        return None, "empty image data"
    return raw, None


@router.post("/api/image")
async def image_intel(req: ImageRequest) -> dict:
    """Extract EXIF/metadata + GPS and build reverse-search launchers for an image."""
    raw: bytes | None = None
    resolved_url = req.url
    resolved_from_page = False
    if req.url:
        try:
            resp = await netguard.safe_get(req.url, timeout=15, max_bytes=_IMG_MAX_BYTES)
            resp.raise_for_status()
        except netguard.BlockedTargetError as e:
            return {"ok": False, "error": f"blocked target: {e}"}
        except Exception as e:
            return {"ok": False, "error": f"could not fetch URL: {e}"}
        raw = resp.content
        ctype = resp.headers.get("content-type", "").lower()
        # Trust the bytes, not the header: an "image/png" response can still be
        # an HTML error page, and a mislabelled JPEG is still a JPEG.
        if imageintel.detect_format(raw) is None:
            looks_html = "html" in ctype or raw.lstrip()[:15].lower().startswith((b"<!doctype", b"<html"))
            if looks_html:
                # It's a web page — find its main image (og:image) and analyse that.
                # Use the original page URL as the base: the guarded response was
                # fetched from a pinned IP, so resp.url is not a usable base.
                img_url = imageintel.og_image(raw.decode("utf-8", "ignore"), base_url=req.url)
                if not img_url:
                    return {
                        "ok": False,
                        "error": "That's a web page, not an image, and I couldn't find a main image (og:image) on it. "
                        "Open the image directly — right-click it → Copy image address — and paste that URL.",
                        "page": True,
                    }
                try:
                    resp2 = await netguard.safe_get(img_url, timeout=15, max_bytes=_IMG_MAX_BYTES)
                    resp2.raise_for_status()
                except netguard.BlockedTargetError as e:
                    return {"ok": False, "error": f"blocked target (page image): {e}"}
                except Exception as e:
                    return {"ok": False, "error": f"could not fetch the page's image: {e}"}
                raw = resp2.content
                if imageintel.detect_format(raw) is None:
                    return {"ok": False, "error": "The page's main image wasn't in a recognised image format."}
                resolved_url = img_url
                resolved_from_page = True
            else:
                return {"ok": False, "error": "unrecognised image format — expected JPEG, PNG, GIF, WEBP, BMP or TIFF bytes"}
    elif req.data:
        raw, err = _decode_image_data(req.data)
        if err:
            return {"ok": False, "error": err}

    if not raw:
        return {"ok": False, "error": "provide an image 'url' or base64 'data'"}
    if len(raw) > _IMG_MAX_BYTES:
        return {"ok": False, "error": "image too large (>25MB)"}
    detected = imageintel.detect_format(raw)
    if not detected:
        return {"ok": False, "error": "unrecognised image format — expected JPEG, PNG, GIF, WEBP, BMP or TIFF bytes"}

    try:
        meta = await asyncio.to_thread(imageintel.extract_metadata, raw)
    except Exception as e:
        return {"ok": False, "error": f"could not read image: {e}"}

    decoded = str(meta.get("format") or "").upper()
    if (detected in _CORE_IMAGE_FORMATS and decoded in _CORE_IMAGE_FORMATS
            and detected != decoded):
        return {"ok": False, "error": f"image bytes look like {detected} but decoded as {decoded} — refusing an ambiguous file"}
    meta["ok"] = True
    meta["detected_format"] = detected
    meta["bytes"] = len(raw)
    meta["assessment"] = imageintel.assess(meta)
    meta["reverse_search"] = imageintel.reverse_search_links(
        sanitize_public_url(resolved_url) if req.url else None
    )
    if resolved_from_page:
        meta["resolved_image"] = resolved_url
    g = meta.get("gps")
    if g and g.get("exact"):
        # Only signed, fully referenced coordinates get a map or a place name.
        # Guessing N/E from an unsigned EXIF pair would put the pin in the wrong
        # hemisphere with no warning — worse than saying "incomplete".
        g["maps"] = imageintel.map_links(g["lat"], g["lon"])
        place = await _reverse_geocode(g["lat"], g["lon"])
        if place:
            g["place"] = place
    return meta
