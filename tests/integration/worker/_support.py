"""Harness for the worker tests: the real identity + visits + edge modules (``EdgeWorld``) plus the worker role and the job runtime."""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from dwaar_api.core.db import Database
from dwaar_api.modules.edge.config import EdgeConfig
from dwaar_worker.actors import Runtime
from tests.integration.edge._support import EdgeWorld, ew  # noqa: F401  (ew is re-exported)


@pytest.fixture
def worker_db(ew: EdgeWorld) -> Database:  # noqa: F811
    """The same database through the WORKER role (``dwaar_worker``): what a job process really has."""
    assert ew.database is not None
    return ew.database


@pytest.fixture
def edge_cfg(ew: EdgeWorld) -> EdgeConfig:  # noqa: F811
    cfg: Any = ew.app.state.edge_config
    assert isinstance(cfg, EdgeConfig)
    return cfg


@pytest.fixture
def runtime(worker_db: Database, edge_cfg: EdgeConfig) -> Iterator[Runtime]:
    yield Runtime(worker_db, edge_cfg)
