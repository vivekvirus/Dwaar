"""The AI part of the synthetic seed (steps/s700_ai.py): only the budget is seeded, nothing is invented, and it is idempotent.

REQ: ARCH-05 (per-society AI budgets), BUILD_BRIEF 7 (no fabricated results).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from dwaar_api import seed
from dwaar_api.seed.steps import s700_ai
from tests._harness.pgfixtures import PgServer, _clone
from tests.acceptance._world import World, build_world, seed_environment

pytestmark = pytest.mark.req("ARCH-05", "AI-SYS-06")


@pytest.fixture(scope="module")
def seeded(pg_server: PgServer, template_db: str) -> Iterator[World]:
    """The seed with the AI step ONLY (the other steps are other teams' and are not what this test is about)."""
    only = {"s010_packs", "s100_organisation", "s200_staff", "s300_residents", "s700_ai"}
    original = seed.discover_steps
    seed.discover_steps = lambda: [m for m in original() if m.__name__.rsplit(".", 1)[-1] in only]  # type: ignore[assignment]
    try:
        for handle in _clone(pg_server, template_db):
            w = build_world(handle)
            try:
                yield w
            finally:
                w.database.dispose()
    finally:
        seed.discover_steps = original  # type: ignore[assignment]


def test_both_societies_get_the_daily_allowance_and_nothing_else_is_invented(seeded: World) -> None:
    rows = seeded.admin_rows(
        "SELECT s.state, q.ai_requests_per_day FROM society_quotas q JOIN societies s ON s.id = q.society_id ORDER BY 1"
    )
    assert rows == [
        ("Karnataka", s700_ai.DAILY_ALLOWANCE),
        ("Maharashtra", s700_ai.DAILY_ALLOWANCE),
    ]
    for table in (
        "ai_runs",
        "action_proposals",
        "ai_drafts",
        "ai_feedback",
        "ai_society_controls",
        "ai_feature_controls",
    ):
        assert seeded.admin_rows(f"SELECT count(*) FROM {table}")[0][0] == 0, (
            table
        )  # no fabricated run, draft or 'result'
    ops = seeded.admin_rows(
        "SELECT count(*) FROM audit_log WHERE operation = 'society.quotas.set'"
    )[0][0]
    assert ops >= 2  # through the service function: audited


def test_running_the_seed_again_changes_nothing(seeded: World) -> None:
    before = seeded.admin_rows("SELECT count(*) FROM audit_log")[0][0]
    result = seed.run(seed_environment(seeded.db), say=lambda _l: None)
    assert result.counts.get("ai_quota_set", 0) == 0
    assert (
        seeded.admin_rows("SELECT count(*) FROM audit_log WHERE operation = 'society.quotas.set'")[
            0
        ][0]
        >= 2
    )
    assert (
        seeded.admin_rows("SELECT ai_requests_per_day FROM society_quotas ORDER BY 1")[0][0]
        == s700_ai.DAILY_ALLOWANCE
    )
    assert before <= seeded.admin_rows("SELECT count(*) FROM audit_log")[0][0]
