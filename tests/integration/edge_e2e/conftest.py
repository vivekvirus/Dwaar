"""Fixtures for the real edge <-> cloud integration tests (see ``_cloud``)."""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.integration.edge._support import EdgeWorld, ew  # noqa: F401  (``ew`` is re-exported)
from tests.integration.edge_e2e._cloud import Site, commissioned_site


@pytest.fixture
def site(ew: EdgeWorld, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Site]:  # noqa: F811
    """A commissioned gateway against the real cloud on a VIRTUAL clock shared by both sides (labelled simulation)."""
    with commissioned_site(ew, tmp_path, monkeypatch, virtual=True) as s:
        yield s


@pytest.fixture
def real_clock_site(
    ew: EdgeWorld,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Site]:
    """Same, on the machine clock (the real HTTP ``Date`` header; nothing patched)."""
    with commissioned_site(ew, tmp_path, monkeypatch, virtual=False) as s:
        yield s
