"""Fixtures for the community module tests: a world with a stub scanner and a temporary object store, and one with NO scanner."""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from pathlib import Path

import pytest

from dwaar_api.modules.community.config import CommunityConfig
from dwaar_api.modules.community.scanner import StubScanner, UnconfiguredScanner
from dwaar_api.modules.community.storage import LocalDiskStore
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import make_settings
from tests.integration.helpdesk._support import COMMUNITY_SHIM, World, world


def make_config(db: DbHandle, root: Path, **over: object) -> CommunityConfig:
    settings = make_settings(db)
    cfg = CommunityConfig.from_environment(
        settings,
        {"DWAAR_COMMUNITY_STORAGE_DIR": str(root), "DWAAR_COMMUNITY_SCANNER": "stub"},
    )
    return dataclasses.replace(cfg, **over)  # type: ignore[arg-type]


@pytest.fixture
def cw(db: DbHandle, tmp_path: Path) -> Iterator[World]:
    store = LocalDiskStore(tmp_path / "objects")
    with world(
        db,
        COMMUNITY_SHIM,
        community_config=make_config(db, tmp_path / "objects"),
        community_store=store,
        community_scanner=StubScanner(),
    ) as w:
        yield w


@pytest.fixture
def cw_noscan(db: DbHandle, tmp_path: Path) -> Iterator[World]:
    """No scanner is configured: the default of the module (fail closed)."""
    store = LocalDiskStore(tmp_path / "objects")
    cfg = dataclasses.replace(make_config(db, tmp_path / "objects"), scanner_kind="unconfigured")
    with world(
        db,
        COMMUNITY_SHIM,
        community_config=cfg,
        community_store=store,
        community_scanner=UnconfiguredScanner(),
    ) as w:
        yield w
