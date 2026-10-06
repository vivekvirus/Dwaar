"""The community part of the synthetic seed (steps/s570_community.py): shape, honesty about simulation, idempotency.

REQ: COM-01..COM-04, COM-06, PRD 8.3, BUILD_BRIEF 7.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from tests._harness.pgfixtures import PgServer, _clone
from tests.acceptance._world import World, build_world, seed_environment
from tests.integration.helpdesk._seedsteps import run_steps

pytestmark = [pytest.mark.req("COM-01", "COM-02", "COM-03", "COM-04", "COM-06")]


@pytest.fixture(scope="module")
def seeded(pg_server: PgServer, template_db: str) -> Iterator[World]:
    for handle in _clone(pg_server, template_db):
        w = build_world(handle, run_seed=False)
        run_steps(seed_environment(handle), {"community"})
        try:
            yield w
        finally:
            w.database.dispose()


def rows(w: World, sql: str, *params: Any) -> list[tuple[Any, ...]]:
    return w.admin_rows(sql, params)


def test_notices_cover_published_legal_and_the_ai_draft_awaiting_a_person(seeded: World) -> None:
    got = {
        r[0]: r[1:]
        for r in rows(
            seeded,
            "SELECT v.title, n.state, v.state, v.drafted_by_ai, v.approved_by IS NOT NULL FROM notices n JOIN notice_versions v ON v.notice_id = n.id",
        )
    }
    assert got["Water tank cleaning on Saturday"] == ("published", "published", False, True)
    assert got["Notice of the annual general meeting"] == ("published", "published", False, True)
    assert got["Lift servicing schedule for October"] == (
        "draft",
        "draft",
        True,
        False,
    )  # COM-03: nobody approved it, so it is not public


def test_the_legal_notice_was_published_only_after_human_review(seeded: World) -> None:
    got = rows(
        seeded,
        "SELECT language, review_state, origin, reviewed_by IS NOT NULL, translated_by IS NOT NULL FROM notice_translations ORDER BY language",
    )
    assert got == [("hi", "reviewed", "human", True, True), ("mr", "reviewed", "human", True, True)]
    assert (
        rows(
            seeded,
            "SELECT count(*) FROM notice_translations t JOIN notice_versions v ON v.id = t.notice_version_id WHERE t.reviewed_by = v.created_by",
        )[0][0]
        == 0
    )


def test_the_document_is_hashed_stub_scanned_and_labelled_as_simulation(seeded: World) -> None:
    got = rows(
        seeded,
        "SELECT d.doc_type, v.state, v.scan_state, v.scanner_simulation, v.storage_simulation, length(v.sha256) FROM documents d JOIN document_versions v ON v.document_id = d.id",
    )
    assert got == [("bye_laws", "published", "clean", True, True, 64)]


def test_the_poll_is_open_non_binding_and_has_three_answers(seeded: World) -> None:
    got = rows(seeded, "SELECT state, is_binding, (SELECT count(*) FROM poll_responses) FROM polls")
    assert got == [("open", False, 3)]


def test_second_run_changes_nothing(seeded: World) -> None:
    tables = ("notices", "notice_versions", "notice_translations", "documents", "document_versions", "polls", "poll_options",
              "poll_responses", "audit_log", "outbox")  # fmt: skip
    sql = "SELECT " + ", ".join(f"(SELECT count(*) FROM {t})" for t in tables)  # noqa: S608
    before = seeded.admin_rows(sql)
    again = run_steps(seed_environment(seeded.db), {"community"})
    assert seeded.admin_rows(sql) == before
    assert not {
        k: v
        for k, v in again.items()
        if v and k in {"notices_created", "documents_created", "polls_created"}
    }
