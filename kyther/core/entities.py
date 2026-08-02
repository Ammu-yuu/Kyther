"""Core data model: entities, findings, and scan results.

An *entity* is any observable of interest (a domain, IP, email, etc.). Analyzers
consume entities and emit *findings* (facts learned) plus zero or more newly
*discovered* entities, which the orchestrator can feed back in to pivot on.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EntityType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    USERNAME = "username"
    PERSON = "person"
    COMPANY = "company"
    URL = "url"
    ASN = "asn"
    PHONE = "phone"

    def __str__(self) -> str:  # nicer CLI output
        return self.value


# Regexes are intentionally conservative; detection prefers precision.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)
_USERNAME_RE = re.compile(r"^@?[A-Za-z0-9._-]{2,40}$")
_PHONE_RE = re.compile(r"^\+?[\d\s().-]{7,20}$")


def detect_type(value: str) -> EntityType:
    """Best-effort inference of an entity type from a raw string.

    Order matters: an email contains an '@', a URL contains a scheme, etc.
    Falls back to USERNAME, since that is the least structured input.
    """
    v = value.strip()
    if v.startswith(("http://", "https://")):
        return EntityType.URL
    if _EMAIL_RE.match(v):
        return EntityType.EMAIL
    try:
        ipaddress.ip_address(v)
        return EntityType.IP
    except ValueError:
        pass
    if v.upper().startswith("AS") and v[2:].isdigit():
        return EntityType.ASN
    # Phone: only digits/separators (no letters, so never eats a domain), with
    # a plausible 7–15 digit count.
    _digits = re.sub(r"\D", "", v)
    if _PHONE_RE.match(v) and 7 <= len(_digits) <= 15:
        return EntityType.PHONE
    if _DOMAIN_RE.match(v):
        return EntityType.DOMAIN
    if " " in v:  # "John Smith" / "Acme Corp" — ambiguous, caller can override
        return EntityType.PERSON
    if _USERNAME_RE.match(v):
        return EntityType.USERNAME
    return EntityType.USERNAME


def normalize(entity_type: EntityType, value: str) -> str:
    v = value.strip()
    if entity_type in (EntityType.DOMAIN, EntityType.EMAIL):
        return v.lower()
    if entity_type == EntityType.USERNAME:
        return v.lstrip("@")
    if entity_type == EntityType.PHONE:
        return re.sub(r"[\s().-]", "", v)  # keep leading +, drop separators
    return v


@dataclass(frozen=True)
class Entity:
    type: EntityType
    value: str
    # Where this entity came from, for provenance in the graph.
    source: str = "seed"

    @classmethod
    def make(cls, type: EntityType, value: str, source: str = "seed") -> "Entity":
        return cls(type=type, value=normalize(type, value), source=source)

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value}"

    def __str__(self) -> str:
        return f"{self.type}={self.value}"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    def __str__(self) -> str:  # so str()/JSON give "info", not "Severity.INFO"
        return self.value


@dataclass
class Finding:
    """A single fact learned about an entity."""

    analyzer: str
    entity: Entity
    title: str
    data: dict[str, Any] = field(default_factory=dict)
    severity: Severity = Severity.INFO


@dataclass
class AnalyzerResult:
    findings: list[Finding] = field(default_factory=list)
    discovered: list[Entity] = field(default_factory=list)
    error: str | None = None


@dataclass
class ScanResult:
    """Everything gathered for one orchestrated scan."""

    seed: Entity
    findings: list[Finding] = field(default_factory=list)
    entities: dict[str, Entity] = field(default_factory=dict)
    # Directed pivot edges: (parent_key, child_key, relation).
    edges: list[tuple[str, str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_entity(self, entity: Entity) -> bool:
        """Register an entity. Returns True if it was newly seen."""
        if entity.key in self.entities:
            return False
        self.entities[entity.key] = entity
        return True
