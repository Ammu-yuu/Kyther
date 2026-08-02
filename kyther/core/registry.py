"""Global plugin registry.

Analyzers register themselves via the :func:`register` decorator. The
orchestrator queries the registry for every analyzer that accepts a given
entity type.
"""
from __future__ import annotations

from typing import Iterable, Type

from .base import Analyzer
from .entities import EntityType

_REGISTRY: list[Analyzer] = []


def register(cls: Type[Analyzer]) -> Type[Analyzer]:
    """Class decorator that instantiates and registers an analyzer."""
    _REGISTRY.append(cls())
    return cls


def all_analyzers() -> list[Analyzer]:
    return list(_REGISTRY)


def analyzers_for(entity_type: EntityType, include_unavailable: bool = False) -> list[Analyzer]:
    out = []
    for a in _REGISTRY:
        if entity_type not in a.accepts:
            continue
        if not include_unavailable and not a.available():
            continue
        out.append(a)
    return out


def load_builtins() -> None:
    """Import the analyzers package so decorators run and populate the registry."""
    from .. import analyzers  # noqa: F401  (import side effect)


def clear() -> None:  # test helper
    _REGISTRY.clear()
