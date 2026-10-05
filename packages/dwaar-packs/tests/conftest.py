from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

import pytest

from dwaar_packs import LegalPack, approval_pin, load_pack
from dwaar_packs.approvals import APPROVALS_ENV
from dwaar_packs.paths import legal_packs_dir


@pytest.fixture(scope="session")
def mh() -> LegalPack:
    p = load_pack(legal_packs_dir() / "packs" / "maharashtra-chs.yaml")
    assert isinstance(p, LegalPack)
    return p


@pytest.fixture(scope="session")
def approve() -> Iterator[Callable[[Any], Any]]:
    """Simulate counsel approval (an external step in reality) on a copy of a pack.

    A claim in the pack is not enough (GOV-01): like a real approval, this also records the registry pin
    for the exact content in DWAAR_PACK_APPROVALS, which is removed again at the end of the session.
    """
    previous = os.environ.get(APPROVALS_ENV)

    def _approve(pack: Any) -> Any:
        approved = pack.model_copy(
            update={
                "status": "approved",
                "approved_by": "test-counsel",
                "approved_at": datetime(2026, 10, 6, tzinfo=UTC),
            }
        )
        current = os.environ.get(APPROVALS_ENV, "")
        pin = approval_pin(approved)
        os.environ[APPROVALS_ENV] = f"{current};{pin}" if current else pin
        return approved

    yield _approve
    if previous is None:
        os.environ.pop(APPROVALS_ENV, None)
    else:
        os.environ[APPROVALS_ENV] = previous
