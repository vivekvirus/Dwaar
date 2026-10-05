"""Fix round 1: behaviour that is not already pinned by the W1 regression tests in tests/security/test_w1_*.py.

REQ: INV-01, INV-02, DB-02, OBS-01, IAM-08, PRD 7.4, PRD 8.2, PRD 12.4.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import text

from dwaar_api.core.audit import (
    MutationResult,
    emit_event,
    mask_payload,
    masked_diff,
    mutation,
    record_audit,
)
from dwaar_api.core.authn import JwtVerifier
from dwaar_api.core.db import Database, RequestContext
from dwaar_api.core.idempotency import encode_response
from dwaar_api.core.pagination import PageParams, Paginator, SortColumn
from dwaar_common.errors import Unauthenticated
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import (
    COMMITTEE_A,
    SOCIETY_A,
    CoreHarness,
    TestIssuer,
    core_harness,
)

pytestmark = pytest.mark.req("INV-01", "INV-02", "DB-02", "OBS-01", "IAM-08")

CTX = RequestContext(SOCIETY_A, COMMITTEE_A, "committee", uuid.UUID(int=77))


@pytest.fixture
def core(db: DbHandle) -> Iterator[CoreHarness]:
    with core_harness(db) as harness:
        yield harness


# ----------------------------------------------------------------------------- F06: pool reset
def test_pool_reset_clears_session_level_state_before_the_next_borrower(db: DbHandle) -> None:
    database = Database(db.app_dsn, pool_size=1, max_overflow=0)
    try:
        with database.app_engine.connect() as conn:
            conn.execute(text(f"SET app.society_id = '{SOCIETY_A}'"))
            conn.execute(text("SET statement_timeout = 1"))
            conn.commit()
        with (
            database.app_engine.connect() as conn
        ):  # the same physical connection, no apply_context
            assert conn.execute(
                text("SELECT current_setting('app.society_id', true)")
            ).scalar() in (
                None,
                "",
            )
            assert (
                conn.execute(text("SHOW statement_timeout")).scalar() == "30s"
            )  # startup default back
            conn.rollback()
    finally:
        database.dispose()


def test_empty_context_writes_all_four_settings_as_empty() -> None:
    assert RequestContext().all_settings() == {
        "app.society_id": "",
        "app.person_id": "",
        "app.actor_role": "",
        "app.request_id": "",
    }


# ----------------------------------------------------------------------------- Q-06: common columns lint
#: tables that legitimately have no retention_class / legal_hold_id (reason each one).
COMMON_COLUMNS_ALLOWLIST = {
    "schema_migrations": "migration ledger, not data",
    "rate_limit_buckets": "platform-level counters, no personal or society data",
    "dwaar_migration_lock": "empty lock table held by the migration runner; no data, no runtime privileges",
    "idempotency_keys": "short-lived replay cache; retention is expires_at plus the cleanup job",
    "purge_log": "evidence of purges; must never be purged or held (itself the retention record)",
}


def test_every_public_table_carries_retention_class_and_legal_hold_id(db: DbHandle) -> None:
    """PRD 8.2 puts retention_class and legal_hold_id on every table. Future migrations that add a table
    without them turn this red unless the table is added to the documented allow-list above."""
    with db.admin_conn() as conn:
        tables = [
            r[0]
            for r in conn.execute(
                "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
                " WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition"
                " ORDER BY 1"
            ).fetchall()
        ]
        columns = {
            (t, c)
            for t, c in conn.execute(
                "SELECT table_name, column_name FROM information_schema.columns"
                " WHERE table_schema = 'public'"
            ).fetchall()
        }
    missing = [
        f"{t}.{c}"
        for t in tables
        if t not in COMMON_COLUMNS_ALLOWLIST
        for c in ("retention_class", "legal_hold_id")
        if (t, c) not in columns
    ]
    assert missing == [], (
        f"add the PRD 8.2 common columns or allow-list the table with a reason: {missing}"
    )
    assert {"audit_log", "outbox"} <= set(tables)


def test_runtime_roles_cannot_set_retention_hold_or_server_time_columns(db: DbHandle) -> None:
    from psycopg import errors

    with pytest.raises(errors.InsufficientPrivilege), db.app_conn(society_id=SOCIETY_A) as conn:
        conn.execute(
            "INSERT INTO audit_log (society_id, effective_role, operation, object_type, legal_hold_id)"
            " VALUES (%s, 'committee', 'x.y', 'x', %s)",
            (SOCIETY_A, uuid.uuid4()),
        )
    with db.app_conn(society_id=SOCIETY_A) as conn:  # a retention CLASS may be chosen by the writer
        conn.execute(
            "INSERT INTO audit_log (society_id, effective_role, operation, object_type, retention_class)"
            " VALUES (%s, 'committee', 'x.y', 'x', 'FIN')",
            (SOCIETY_A,),
        )
        row = conn.execute("SELECT retention_class, legal_hold_id FROM audit_log").fetchone()
        assert row == ("FIN", None)
    with pytest.raises(errors.CheckViolation), db.app_conn(society_id=SOCIETY_A) as conn:
        conn.execute(
            "INSERT INTO audit_log (society_id, effective_role, operation, object_type, retention_class)"
            " VALUES (%s, 'committee', 'x.y', 'x', 'not a class')",
            (SOCIETY_A,),
        )


# ----------------------------------------------------------------------------- F12: body size limit
def _post(core: CoreHarness, content: Any, headers: dict[str, str] | None = None) -> Any:
    return core.client().post(
        f"/v1/probe/{SOCIETY_A}/things",
        headers={**core.auth(COMMITTEE_A), "Idempotency-Key": "body-limit-0001", **(headers or {})},
        content=content,
    )


def test_declared_oversize_body_is_refused_with_413_and_the_standard_error_body(
    core: CoreHarness,
) -> None:
    limit = core.settings.max_request_body_bytes
    resp = _post(core, b"x" * (limit + 1), {"Content-Type": "application/json"})
    assert resp.status_code == 413
    body = resp.json()
    assert body["code"] == "invalid_schema"
    assert body["details"]["reason"] == "payload_too_large"
    assert body["request_id"] == resp.headers["x-request-id"]


def test_streamed_oversize_body_without_content_length_is_cut_off(core: CoreHarness) -> None:
    limit = core.settings.max_request_body_bytes

    def chunks() -> Iterator[bytes]:
        for _ in range(limit // 4096 + 8):
            yield b"a" * 4096

    resp = _post(core, chunks(), {"Content-Type": "application/json"})
    assert resp.status_code == 413


def test_body_at_the_limit_is_still_processed_and_overrides_apply_per_prefix(
    core: CoreHarness,
) -> None:
    small = b'{"name": "ok"}'
    assert _post(core, small, {"Content-Type": "application/json"}).status_code == 201
    core.app.state.body_limits[f"/v1/probe/{SOCIETY_A}/things"] = 8  # tighter override wins
    resp = _post(
        core, small, {"Content-Type": "application/json", "Idempotency-Key": "body-limit-0002"}
    )
    assert resp.status_code == 413


# ----------------------------------------------------------------------------- Q-05: NULL-safe keyset
def _scored_table(db: DbHandle, scores: list[int | None]) -> None:
    with db.owner_conn() as conn:
        conn.execute(
            "CREATE TABLE fr1_scored (id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),"
            " society_id uuid NOT NULL, score integer, label text)"
        )
        conn.execute("SELECT dwaar_enable_society_rls('fr1_scored')")
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_A),))
        for i, score in enumerate(scores):
            conn.execute(
                "INSERT INTO fr1_scored (society_id, score, label) VALUES (%s, %s, %s)",
                (SOCIETY_A, score, f"row-{i}"),
            )


def _walk(database: Database, *, limit: int, descending: bool) -> list[dict[str, Any]]:
    paginator = Paginator(b"fr1-key")
    seen: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(50):
        with database.app_tx(RequestContext(SOCIETY_A, None, "committee")) as conn:
            page = paginator.fetch(
                conn,
                select_sql="SELECT id, score, label FROM fr1_scored",
                where=[],
                params={},
                sort=[SortColumn("score", "integer"), SortColumn("id", "uuid", nullable=False)],
                page=PageParams(limit=limit, cursor=cursor),
                society_id=SOCIETY_A,
                descending=descending,
            )
        seen.extend(page.items)
        cursor = page.next_cursor
        if cursor is None:
            return seen
    raise AssertionError("pagination did not terminate")


@pytest.mark.parametrize("descending", [True, False])
@pytest.mark.parametrize("limit", [1, 2, 3, 5])
def test_keyset_walk_returns_every_row_once_in_order_with_null_sort_values(
    db: DbHandle, descending: bool, limit: int
) -> None:
    scores = [5, None, 3, None, None, 3, 1, 2, None, 4, 5]
    _scored_table(db, scores)
    database = Database(db.app_dsn, pool_size=1, max_overflow=0)
    try:
        rows = _walk(database, limit=limit, descending=descending)
    finally:
        database.dispose()
    assert len(rows) == len(scores)
    assert len({r["id"] for r in rows}) == len(scores)
    non_null = [r["score"] for r in rows if r["score"] is not None]
    assert non_null == sorted(non_null, reverse=descending)
    assert [r["score"] for r in rows[len(non_null) :]] == [None] * scores.count(None)  # NULLs last


# ----------------------------------------------------------------------------- F13: responses
def test_encode_response_keeps_decimals_exact_and_refuses_floats() -> None:
    body = encode_response(
        {"litres": Decimal("12345678901234567.89"), "paise": 10**18, "ids": [uuid.UUID(int=1)]}
    )
    assert body == {
        "litres": "12345678901234567.89",
        "paise": 10**18,
        "ids": [str(uuid.UUID(int=1))],
    }
    with pytest.raises(TypeError, match="float"):
        encode_response({"x": {"y": [1.5]}})


# ----------------------------------------------------------------------------- F15: token lifetime
@pytest.fixture(scope="module")
def issuer() -> TestIssuer:
    return TestIssuer()


def _verifier(issuer: TestIssuer, **kw: Any) -> JwtVerifier:
    return issuer.verifier(**kw)


def test_token_lifetime_is_capped_and_iat_is_required(issuer: TestIssuer) -> None:
    person = uuid.UUID(int=5)
    assert _verifier(issuer).verify(issuer.mint(person, ttl=3600))  # exactly the 1 h default cap
    for bad in (issuer.mint(person, ttl=3601), issuer.mint(person, ttl=10 * 365 * 86400)):
        with pytest.raises(Unauthenticated):
            _verifier(issuer).verify(bad)
    with pytest.raises(Unauthenticated):
        _verifier(issuer).verify(issuer.mint(person, omit=("iat",)))
    assert _verifier(issuer, max_lifetime_seconds=86_400).verify(issuer.mint(person, ttl=7200))
    with pytest.raises(Unauthenticated):
        _verifier(issuer, max_lifetime_seconds=60).verify(issuer.mint(person, ttl=600))


# ----------------------------------------------------------------------------- F04 / Q-03: masking
def test_mask_payload_masks_identity_fields_numbers_nested_lists_and_text() -> None:
    out = mask_payload(
        {
            "email": "ravi.kumar@example.org",
            "pan": "ABCDE1234F",
            "vpa": "ravi@okhdfc",
            "ifsc": "HDFC0001234",
            "dob": "1990-01-01",
            "visitor_name": "Ravi",
            "full_name": "Ravi Kumar",
            "address": "Flat 4, Tower B",
            "vehicle_plate": "MH12AB1234",
            "name": "Gate pass",
            "status": "approved",
            "contact": 9999900123,
            "amount_paise": 1_500_000_000,
            "members": [[{"phone": "9999900123"}], [{"note": "call +91 99999 00123"}]],
        }
    )
    for key in (
        "email",
        "pan",
        "vpa",
        "ifsc",
        "dob",
        "visitor_name",
        "full_name",
        "address",
        "vehicle_plate",
    ):
        assert out[key] == "[REDACTED]", key
    assert out["name"] == "Gate pass"  # a bare label is not personal data
    assert out["status"] == "approved"
    assert out["contact"] == "[REDACTED]"
    assert out["amount_paise"] == 1_500_000_000
    rendered = str(out)
    assert "9999900123" not in rendered
    assert "99999 00123" not in rendered


def test_masked_diff_hides_changed_identity_fields_but_shows_that_they_changed() -> None:
    diff = masked_diff(
        {"email": "a@example.org", "status": "x"}, {"email": "b@example.org", "status": "y"}
    )
    assert diff["changed"]["email"] == {"before": "[REDACTED]", "after": "[REDACTED]"}
    assert diff["changed"]["status"] == {"before": "x", "after": "y"}


def test_outbox_payload_and_explicit_audit_diff_are_masked_in_the_database(
    core: CoreHarness,
) -> None:
    def apply(conn: Any) -> MutationResult:
        return MutationResult(
            uuid.uuid4(),
            1,
            event_payload={
                "thing_id": "t-1",
                "note": "otp=123456 from +91 99999 00123",
                "email": "a@example.org",
            },
        )

    with core.database.app_tx(CTX) as conn:
        outcome = mutation(
            conn,
            CTX,
            operation="probe.x",
            object_type="probe_thing",
            event_type="ThingCreated",
            apply=apply,
        )
        record_audit(
            conn,
            CTX,
            operation="probe.y",
            object_type="probe_thing",
            diff={"op": "update", "changed": {"note": {"after": "aadhaar 1234 5678 9012"}}},
        )
    with core.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_A),))
        payload = conn.execute("SELECT payload::text FROM outbox").fetchone()
        audits = [r[0] for r in conn.execute("SELECT diff_masked::text FROM audit_log").fetchall()]
    assert payload is not None
    for needle in ("123456", "99999 00123", "a@example.org"):
        assert needle not in payload[0], payload[0]
    assert "t-1" in payload[0]  # ids and state survive
    assert all("1234 5678 9012" not in a for a in audits)
    assert outcome.event.payload["thing_id"] == "t-1"
    assert "123456" not in str(
        outcome.event.payload
    )  # the returned event is the stored (masked) one


def test_emit_event_payload_hash_is_over_the_masked_payload(core: CoreHarness) -> None:
    with core.database.app_tx(CTX) as conn:
        event = emit_event(
            conn,
            CTX,
            aggregate_type="probe_thing",
            aggregate_id=uuid.uuid4(),
            aggregate_version=1,
            event_type="ThingCreated",
            payload={"phone": "+91 99999 00123"},
        )
        stored = conn.execute(text("SELECT payload_hash FROM outbox")).scalar_one()
    assert stored == event.payload_hash()
    assert event.payload == {"phone": "[REDACTED]"}


# ----------------------------------------------------------------------------- F10: bounded claim
def test_expired_key_with_a_different_payload_is_reclaimed_and_same_payload_replays(
    core: CoreHarness,
) -> None:
    def post(name: str) -> Any:
        return core.client().post(
            f"/v1/probe/{SOCIETY_A}/things",
            headers={**core.auth(COMMITTEE_A), "Idempotency-Key": "claim-key-0001"},
            json={"name": name},
        )

    first = post("one")
    with core.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_A),))
        conn.execute("UPDATE idempotency_keys SET expires_at = now() - interval '1 hour'")
    same = post("one")  # expired but the row still exists: replay, never a second effect
    assert same.status_code == 201
    assert same.headers.get("idempotent-replayed") == "true"
    assert same.json()["id"] == first.json()["id"]
    other = post("two")  # a different payload may reclaim an expired key
    assert other.status_code == 201
    assert other.json()["id"] != first.json()["id"]
