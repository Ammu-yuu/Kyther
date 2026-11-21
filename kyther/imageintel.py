"""Image intelligence: EXIF/metadata + GPS extraction, a provenance *verdict*,
map/reverse-geocode links, and reverse-image-search launchers.

This is deliberately an *assistant*, not an automated oracle. Reverse image
search and visual geolocation (signage/architecture/road markings) are human or
paid-AI tasks — there is no keyless API for them. So Kyther extracts what it can
for free, then does the one thing a data dump never does: it *reads the signals
and tells the analyst what they mean and what to do next* (:func:`assess`).
"""
from __future__ import annotations

import html as _html
import io
import re
from urllib.parse import quote_plus, urljoin

from PIL import ExifTags, Image

_META_RE = re.compile(r"<meta\b[^>]*>", re.I)
# og:image is the canonical share image; twitter:image is the fallback.
_OG_ORDER = {
    "og:image": 0, "og:image:url": 1, "og:image:secure_url": 2,
    "twitter:image": 3, "twitter:image:src": 4,
}


def og_image(html_text: str, base_url: str = "") -> str | None:
    """Extract a page's primary share image (og:image / twitter:image).

    Lets the analyst paste an article/page URL and have Kyther find the image,
    rather than requiring a direct image link.
    """
    found: list[tuple[int, str]] = []
    for tag in _META_RE.findall(html_text or ""):
        key_m = re.search(r'(?:property|name)\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        if not key_m:
            continue
        key = key_m.group(1).lower()
        if key not in _OG_ORDER:
            continue
        con_m = re.search(r'content\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        if con_m:
            url = _html.unescape(con_m.group(1)).strip()
            if url:
                found.append((_OG_ORDER[key], url))
    if not found:
        return None
    found.sort(key=lambda kv: kv[0])
    url = found[0][1]
    return urljoin(base_url, url) if base_url else url

# EXIF fields worth surfacing (identity/provenance signals, not every tag).
_WANT = {
    "Make", "Model", "LensModel", "Software", "Artist", "Copyright",
    "DateTime", "DateTimeOriginal", "DateTimeDigitized", "Orientation",
}


def _to_degrees(value, ref: str) -> float | None:
    try:
        d, m, s = (float(x) for x in value)
    except Exception:
        return None
    dec = d + m / 60.0 + s / 3600.0
    if str(ref).upper() in ("S", "W"):
        dec = -dec
    return round(dec, 6)


def extract_metadata(data: bytes) -> dict:
    """Pull format, dimensions, selected EXIF tags, and GPS from image bytes."""
    out: dict = {"format": None, "width": None, "height": None, "exif": {}, "gps": None}
    img = Image.open(io.BytesIO(data))
    out["format"] = img.format
    out["width"], out["height"] = img.size

    exif = img.getexif()
    if not exif:
        return out

    base = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
    for name in _WANT:
        if name in base:
            out["exif"][name] = str(base[name])

    # The Exif sub-IFD holds DateTimeOriginal / LensModel on many cameras.
    try:
        for k, v in exif.get_ifd(0x8769).items():
            nm = ExifTags.TAGS.get(k)
            if nm in _WANT:
                out["exif"].setdefault(nm, str(v))
    except Exception:
        pass

    # GPS sub-IFD -> decimal lat/lon.
    try:
        gps = exif.get_ifd(0x8825)
        if gps:
            g = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps.items()}
            if "GPSLatitude" in g and "GPSLongitude" in g:
                lat = _to_degrees(g["GPSLatitude"], g.get("GPSLatitudeRef", "N"))
                lon = _to_degrees(g["GPSLongitude"], g.get("GPSLongitudeRef", "E"))
                if lat is not None and lon is not None:
                    out["gps"] = {"lat": lat, "lon": lon}
                    if "GPSDateStamp" in g:
                        out["gps"]["timestamp"] = str(g["GPSDateStamp"])
    except Exception:
        pass
    return out


def reverse_search_links(image_url: str | None) -> dict:
    """Ready-to-click reverse-image-search queries. TinEye sorts oldest-first,
    which is how you find the *earliest* upload of a viral image."""
    if not image_url:
        return {}
    u = quote_plus(image_url)
    return {
        "Google Lens": f"https://lens.google.com/uploadbyurl?url={u}",
        "Yandex (best for faces/places)": f"https://yandex.com/images/search?rpt=imageview&url={u}",
        "Bing Visual": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{u}",
        "TinEye (earliest upload)": f"https://tineye.com/search?url={u}&sort=crawl_date&order=asc",
    }


def map_links(lat, lon) -> dict:
    """Turn coordinates into one-click verification surfaces. Street View is the
    useful one — it lets you confirm the place actually looks like the photo."""
    return {
        "OpenStreetMap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}",
        "Google Maps": f"https://www.google.com/maps?q={lat},{lon}",
        "Street View": f"https://www.google.com/maps?q=&layer=c&cbll={lat},{lon}",
    }


# Software tags that mean the pixels went through an editor (not just a camera
# app or OS). Matched as substrings, case-insensitively.
_EDITORS = {
    "photoshop": "Adobe Photoshop", "lightroom": "Adobe Lightroom",
    "gimp": "GIMP", "affinity": "Affinity Photo", "pixelmator": "Pixelmator",
    "snapseed": "Snapseed", "canva": "Canva", "paint.net": "Paint.NET",
    "picsart": "PicsArt", "facetune": "Facetune", "topaz": "Topaz",
    "capcut": "CapCut", "luminar": "Luminar", "photoscape": "PhotoScape",
}


def _editor(software: str | None) -> str | None:
    s = (software or "").lower()
    return next((name for key, name in _EDITORS.items() if key in s), None)


def assess(meta: dict) -> dict:
    """Read extracted metadata and return a provenance *verdict* + next steps.

    This is the 'action, not static' layer: instead of just listing EXIF, it
    classifies the image (camera original / edited / stripped / screenshot) and
    tells the analyst what that implies and what to do next. Pure logic over
    already-extracted fields, so it never makes a network call and never lies
    about certainty — absence of metadata is reported as *inconclusive*, not
    as proof of anything.
    """
    fmt = (meta.get("format") or "").upper()
    ex = meta.get("exif") or {}
    gps = meta.get("gps")
    signals: list[dict] = []

    def sig(level: str, text: str) -> None:
        signals.append({"level": level, "text": text})

    has_camera = bool(ex.get("Make") or ex.get("Model"))
    dto = ex.get("DateTimeOriginal")
    dt = ex.get("DateTime")
    software = ex.get("Software")
    editor = _editor(software)

    if gps:
        sig("strong", "GPS coordinates are embedded — the file claims an exact "
                      "capture location. Verify it fits the story (place below).")
    if editor:
        sig("warn", f"Last saved by {editor} — the image has been through a photo "
                    "editor, so pixels and metadata may be altered.")
    elif software:
        sig("info", f"Software tag: {software}.")
    if dto and dt and dto[:10] != dt[:10]:
        sig("warn", f"Timestamps disagree — captured {dto}, last modified {dt}. "
                    "Normal for an edit, a red flag for a claimed 'original'.")

    if has_camera and dto and not editor:
        cam = " ".join(x for x in (ex.get("Make", ""), ex.get("Model", "")) if x).strip()
        verdict, confidence = "Camera original — metadata intact", "probable"
        sig("strong", f"Full camera metadata present ({cam or 'device'}, shot {dto}). "
                      "Consistent with an unedited file straight off a device.")
        steps = ["If location matters, verify the GPS place below (Street View).",
                 "Check the device and time fit the claimed story.",
                 "Still reverse-search — originals get re-shared too."]
    elif editor:
        verdict, confidence = f"Edited in {editor}", "probable"
        steps = ["Treat the pixels as potentially altered — not raw evidence.",
                 "Reverse-search to find an unedited original.",
                 "Use TinEye (oldest-first) to find the earliest copy."]
    elif fmt == "PNG" and not ex:
        verdict, confidence = "Screenshot or graphic — not a camera photo", "probable"
        sig("info", "PNG with no camera metadata — typical of a screenshot, export "
                    "or made graphic, not a photo off a camera.")
        steps = ["Reverse-search to find what it was captured from.",
                 "If it's a screenshot of a post, trace the original post."]
    elif not ex:
        verdict, confidence = "Metadata stripped — origin unverifiable from the file", "possible"
        sig("info", "No EXIF at all. Social platforms and messengers re-encode images "
                    "and strip metadata, so absence here proves nothing about origin.")
        steps = ["The file can't tell you where/when — use reverse image search.",
                 "Find the earliest upload (TinEye, oldest-first) to date it.",
                 "Do the visual read: signage, plates, architecture, shadows."]
    else:
        verdict, confidence = "Partial metadata — leads, not proof", "possible"
        steps = ["Use the EXIF below as leads, then corroborate with reverse search."]

    return {"verdict": verdict, "confidence": confidence,
            "signals": signals, "next_steps": steps}
