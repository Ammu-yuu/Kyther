"""Base class every analyzer plugin inherits from."""
from __future__ import annotations

import os
from abc import ABC, abstractmethod

from .entities import AnalyzerResult, Entity, EntityType


class Analyzer(ABC):
    """A single OSINT source or technique.

    Subclasses declare which entity types they ``accepts`` and implement
    :meth:`run`. If ``env_key`` is set, the analyzer is skipped automatically
    unless that environment variable is present — this is how we keep
    bring-your-own-key sources optional and off by default.
    """

    name: str = "unnamed"
    description: str = ""
    accepts: set[EntityType] = set()
    #: Name of an env var holding an API key, or None for keyless sources.
    env_key: str | None = None
    #: Soft per-request timeout in seconds.
    timeout: float = 15.0

    def available(self) -> bool:
        return self.env_key is None or bool(os.environ.get(self.env_key))

    @property
    def api_key(self) -> str | None:
        return os.environ.get(self.env_key) if self.env_key else None

    @abstractmethod
    async def run(self, entity: Entity) -> AnalyzerResult:
        """Analyze ``entity`` and return findings + discovered entities."""
        raise NotImplementedError
