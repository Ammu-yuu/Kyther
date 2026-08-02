"""The orchestration engine.

Given a seed entity, run every compatible analyzer concurrently, collect their
findings, and feed newly discovered entities back in — depth-limited, so a
single domain can pivot to its IPs, those IPs to their ASNs, and so on, without
runaway recursion.
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from . import registry
from .base import Analyzer
from .entities import Entity, ScanResult

# Called with (analyzer_name, entity) as each unit of work starts. Lets the CLI
# show live progress without the engine depending on any UI.
ProgressHook = Callable[[str, Entity], None]


async def _run_one(analyzer: Analyzer, entity: Entity, result: ScanResult) -> list[Entity]:
    """Run a single analyzer against a single entity, folding output into result."""
    try:
        ar = await asyncio.wait_for(analyzer.run(entity), timeout=analyzer.timeout)
    except asyncio.TimeoutError:
        result.errors.append(f"{analyzer.name} timed out on {entity}")
        return []
    except Exception as exc:  # a bad plugin must not sink the whole scan
        result.errors.append(f"{analyzer.name} failed on {entity}: {exc!r}")
        return []

    if ar.error:
        result.errors.append(f"{analyzer.name} on {entity}: {ar.error}")
    result.findings.extend(ar.findings)

    fresh: list[Entity] = []
    for disc in ar.discovered:
        # Record the link regardless of whether the node is new, so the graph
        # captures every relationship the analyzers surfaced.
        result.edges.append((entity.key, disc.key, analyzer.name))
        if result.add_entity(disc):
            fresh.append(disc)
    return fresh


async def scan(
    seed: Entity,
    max_depth: int = 2,
    concurrency: int = 10,
    progress: ProgressHook | None = None,
) -> ScanResult:
    """Run an orchestrated, correlated scan starting from ``seed``.

    ``max_depth`` bounds how many pivots deep we follow discovered entities.
    Depth 0 = only analyze the seed; depth 1 = also analyze its discoveries; etc.
    """
    registry.load_builtins()
    result = ScanResult(seed=seed)
    result.add_entity(seed)

    sem = asyncio.Semaphore(concurrency)

    async def guarded(analyzer: Analyzer, entity: Entity) -> list[Entity]:
        async with sem:
            if progress:
                progress(analyzer.name, entity)
            return await _run_one(analyzer, entity, result)

    frontier = [seed]
    for _ in range(max_depth + 1):
        tasks: list[Awaitable[list[Entity]]] = []
        for entity in frontier:
            for analyzer in registry.analyzers_for(entity.type):
                tasks.append(guarded(analyzer, entity))
        if not tasks:
            break

        discovered_batches = await asyncio.gather(*tasks)
        # Next frontier = all newly discovered entities across this level.
        next_frontier: list[Entity] = []
        seen_this_level: set[str] = set()
        for batch in discovered_batches:
            for ent in batch:
                if ent.key not in seen_this_level:
                    seen_this_level.add(ent.key)
                    next_frontier.append(ent)
        if not next_frontier:
            break
        frontier = next_frontier

    return result
