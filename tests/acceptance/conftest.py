"""Fixtures for the acceptance scenarios: a seeded world per session (read-only scenarios) and a fresh one per mutating test."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from tests._harness.pgfixtures import PgServer, _clone
from tests.acceptance._world import World, build_world


@pytest.fixture(scope="session")
def world(pg_server: PgServer, template_db: str) -> Iterator[World]:
    """The seeded dataset in one private database. Scenarios using it must not change business data."""
    for handle in _clone(pg_server, template_db):
        w = build_world(handle)
        try:
            yield w
        finally:
            w.database.dispose()


@pytest.fixture
def fresh_world(pg_server: PgServer, template_db: str) -> Iterator[World]:
    """A world of its own (own seeded clone) for scenarios that change state."""
    for handle in _clone(pg_server, template_db):
        w = build_world(handle)
        try:
            yield w
        finally:
            w.database.dispose()
