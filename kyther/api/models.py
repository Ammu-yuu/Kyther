"""Request models shared by the API routers."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

MAX_DEPTH = 3  # guard against runaway pivots from the public UI


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=256)
    type: str = "auto"
    depth: int = Field(1, ge=0, le=MAX_DEPTH)


class ImageRequest(BaseModel):
    url: Optional[str] = Field(None, max_length=2048)
    data: Optional[str] = None  # base64 (optionally a data: URL) for local uploads
