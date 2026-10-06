"""Fixtures for the acceptance scenarios: a seeded world per session (read-only scenarios) and a fresh one per mutating test."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests._harness.pgfixtures import PgServer, _clone
from tests.acceptance._scene import FakeScene, RealScene, Scene
from tests.acceptance._world import World, build_world
from tests.integration.edge._support import ew  # noqa: F401  (fixture for the real-cloud scenes)
from tests.integration.edge_e2e._cloud import commissioned_site


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


@pytest.fixture(params=["fakecloud", "realcloud"])
def cloud(request: pytest.FixtureRequest) -> str:
    """Which cloud the edge scenario talks to: the in-process FakeCloud or the REAL API over real HTTP (simulation either way)."""
    return str(request.param)


@pytest.fixture
def scene(
    cloud: str, request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Scene]:
    """The same scenario world against either cloud. ``realcloud`` builds a private database, the real app, a loopback server and a
    gateway commissioned through the real enrolment routes; ``fakecloud`` is the in-process contract fake."""
    if cloud == "fakecloud":
        fake = FakeScene(tmp_path)
        fake.add_milk_rule()
        try:
            yield fake
        finally:
            fake.close()
        return
    world = request.getfixturevalue("ew")  # a database is needed for this leg only
    with commissioned_site(world, tmp_path, monkeypatch, virtual=True) as site:
        real = RealScene(world, site)
        real.add_milk_rule()
        yield real
