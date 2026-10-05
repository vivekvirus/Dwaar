"""Keyset pagination over HTTP: limits, opaque signed cursors, allow-listed filters, society binding."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from dwaar_api.core.authz import Grant
from tests.integration.core._support import COMMITTEE_A, SOCIETY_A, SOCIETY_B, CoreHarness

# PRD 7.4 conventions (cursor pagination, 100 rows max, allow-listed filters) carries no requirement ID of its own.
pytestmark = pytest.mark.req("ARCH-03", "INV-01")

URL = f"/v1/probe/{SOCIETY_A}/things"
SAME_TS = "2026-01-01T10:00:00+00:00"


def seed(
    core: CoreHarness, society: Any, count: int, *, prefix: str = "t", same_ts: bool = False
) -> None:
    with core.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(society),))
        for i in range(count):
            if same_ts:
                conn.execute(
                    "INSERT INTO probe_things (society_id, name, created_at) VALUES (%s, %s, %s)",
                    (society, f"{prefix}-{i:03d}", SAME_TS),
                )
            else:
                conn.execute(
                    "INSERT INTO probe_things (society_id, name) VALUES (%s, %s)",
                    (society, f"{prefix}-{i:03d}"),
                )


def get(
    client: TestClient, core: CoreHarness, query: str = "", url: str = URL, who: Any = COMMITTEE_A
) -> Any:
    return client.get(f"{url}{query}", headers=core.auth(who))


def walk(client: TestClient, core: CoreHarness, query: str = "") -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(50):
        sep = "&" if query else ""
        extra = f"{sep}cursor={cursor}" if cursor else ""
        res = get(client, core, f"?{query}{extra}" if (query or cursor) else "")
        assert res.status_code == 200, res.text
        body = res.json()
        items.extend(body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            return items
    raise AssertionError("pagination did not terminate")


def test_default_page_is_50_and_cursor_walk_visits_every_row_once_in_order(
    core: CoreHarness,
) -> None:
    seed(core, SOCIETY_A, 120)
    seed(core, SOCIETY_B, 30, prefix="other")
    with core.client() as client:
        first = get(client, core).json()
        assert len(first["items"]) == 50
        assert first["next_cursor"]
        everything = walk(client, core, "limit=37")
    ids = [i["id"] for i in everything]
    assert len(ids) == 120
    assert len(set(ids)) == 120
    assert all(i["name"].startswith("t-") for i in everything)  # never the other society's rows
    stamps = [i["created_at"] for i in everything]
    assert stamps == sorted(stamps, reverse=True)


def test_limit_is_validated_not_clamped(core: CoreHarness) -> None:
    seed(core, SOCIETY_A, 105)
    with core.client() as client:
        assert len(get(client, core, "?limit=100").json()["items"]) == 100
        assert len(get(client, core, "?limit=1").json()["items"]) == 1
        for bad in ("101", "0", "-5", "abc", "1000000"):
            res = get(client, core, f"?limit={bad}")
            assert res.status_code == 400, bad
            assert res.json()["code"] == "invalid_schema"


def test_keyset_is_stable_when_many_rows_share_the_sort_key(core: CoreHarness) -> None:
    seed(core, SOCIETY_A, 25, same_ts=True)
    with core.client() as client:
        names = [i["name"] for i in walk(client, core, "limit=10")]
    assert len(names) == 25
    assert len(set(names)) == 25  # the unique id tie-breaker prevents skips and repeats


def test_last_page_has_no_cursor_and_empty_society_is_empty(core: CoreHarness) -> None:
    seed(core, SOCIETY_A, 3)
    with core.client() as client:
        exact = get(client, core, "?limit=3").json()
        assert len(exact["items"]) == 3
        assert exact["next_cursor"] is None
    with core.db.admin_conn() as conn:
        conn.execute("DELETE FROM probe_things")
    with core.client() as client:
        assert get(client, core).json() == {"items": [], "next_cursor": None}


def _cursor(
    core: CoreHarness,
    client: TestClient,
    query: str = "?limit=2",
    url: str = URL,
    who: Any = COMMITTEE_A,
) -> str:
    res = get(client, core, query, url=url, who=who)
    cursor = res.json()["next_cursor"]
    assert cursor
    return str(cursor)


def test_cursor_is_opaque_signed_and_every_invalid_form_is_the_same_400(core: CoreHarness) -> None:
    seed(core, SOCIETY_A, 10)
    core.resolver.add(COMMITTEE_A, Grant("committee", SOCIETY_B))
    seed(core, SOCIETY_B, 10, prefix="b")
    with core.client() as client:
        cursor = _cursor(core, client)
        assert "created_at" not in cursor  # not plain JSON a client can read or hand-edit
        body_part, sig_part = cursor.split(".")
        payload = json.loads(base64.urlsafe_b64decode(body_part + "=" * (-len(body_part) % 4)))
        forged_payload = {**payload, "k": ["2000-01-01T00:00:00+00:00", payload["k"][1]]}
        forged_b64 = (
            base64.urlsafe_b64encode(json.dumps(forged_payload).encode()).rstrip(b"=").decode()
        )
        bad = {
            "tampered_payload": f"{forged_b64}.{sig_part}",
            "tampered_signature": f"{body_part}.{sig_part[:-3]}AAA",
            "garbage": "not-a-cursor",
            "empty_parts": ".",
            "other_society": _cursor(core, client, "?limit=2", url=f"/v1/probe/{SOCIETY_B}/things"),
        }
        replies = []
        for label, token in bad.items():
            if token is None:
                continue
            res = get(client, core, f"?cursor={token}")
            assert res.status_code == 400, label
            replies.append({k: v for k, v in res.json().items() if k != "request_id"})
        assert all(r == replies[0] for r in replies)
        assert replies[0]["details"] == {"fields": [{"field": "cursor", "issue": "invalid_cursor"}]}


def test_cursor_cannot_be_reused_with_different_filters(core: CoreHarness) -> None:
    seed(core, SOCIETY_A, 10)
    with core.client() as client:
        cursor = _cursor(core, client, "?limit=2")
        reused = get(client, core, f"?limit=2&name=t-003&cursor={cursor}")
    assert reused.status_code == 400
    assert reused.json()["details"]["fields"][0]["issue"] == "invalid_cursor"


def test_unknown_filters_are_rejected_and_values_are_bound_not_interpolated(
    core: CoreHarness,
) -> None:
    seed(core, SOCIETY_A, 4)
    with core.client() as client:
        unknown = get(client, core, "?society_id=" + str(SOCIETY_B))
        unknown_sort = get(client, core, "?order_by=name;drop%20table%20probe_things")
        bad_enum = get(client, core, "?kind=z")
        long_value = get(client, core, "?name=" + "x" * 80)
        injection = get(client, core, "?name=%27%20OR%201%3D1%20--")
        exact = get(client, core, "?name=t-002")
    assert unknown.status_code == 400
    assert unknown.json()["details"]["fields"] == [
        {"field": "society_id", "issue": "unknown_filter"}
    ]
    assert unknown_sort.status_code == 400
    assert bad_enum.json()["details"]["fields"] == [{"field": "kind", "issue": "invalid_value"}]
    assert long_value.json()["details"]["fields"] == [{"field": "name", "issue": "too_long"}]
    assert injection.status_code == 200
    assert injection.json()["items"] == []  # treated as a literal string
    assert [i["name"] for i in exact.json()["items"]] == ["t-002"]
    with core.db.admin_conn() as conn:
        assert conn.execute("SELECT count(*) FROM probe_things").fetchone() == (4,)  # table intact
