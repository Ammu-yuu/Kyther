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


class FootprintRequest(BaseModel):
    """Structured company intake for the expanded footprint view.

    ``target`` is kept for the old one-box flow; the other fields are optional
    so a caller can gradually add what they already know about the company.
    """
    target: str = Field("", max_length=253)
    name: str = Field("", max_length=200)
    domains: list[str] = Field(default_factory=list, max_length=8)
    aliases: list[str] = Field(default_factory=list, max_length=12)
    country: str = Field("", max_length=80)
    deep: bool = False
