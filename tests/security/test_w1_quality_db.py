"""Regression tests from W1 verification and fix round 1, lens REQUIREMENTS FIDELITY / ENGINEERING QUALITY
(real PostgreSQL). Fixed in round 1: Q-03 (audit identity/bank masking, scrubber patterns), Q-05 (NULL-safe
keyset pagination), Q-06 (retention_class and legal_hold_id on audit_log and outbox)."""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest

from dwaar_api.core.audit import masked_diff
from dwaar_api.core.db import Database, RequestContext
from dwaar_api.core.pagination import PageParams, Paginator, SortColumn
from dwaar_common.events import EdgeEvent
from dwaar_common.ids import is_uuid7, uuid7_timestamp_ms
from dwaar_common.logging import scrub_text
from dwaar_common.signing import Signer, VerifierRing
from tests._harness.pgfixtures import DbHandle

pytestmark = pytest.mark.req("ARCH-01", "ARCH-03", "DB-02")

SOCIETY = uuid.UUID("0192f300-0000-7000-8000-00000000000a")


@pytest.fixture
def database(db: DbHandle) -> Iterator[Database]:
    database = Database(db.app_dsn, db.worker_dsn, pool_size=1, max_overflow=0)
    try:
        yield database
    finally:
        database.dispose()


# --------------------------------------------------------------------------- PRD 7.4 identifiers
def test_database_side_uuid_v7_default_is_a_real_time_ordered_uuid_v7(db: DbHandle) -> None:
    with db.app_conn() as conn:
        rows = conn.execute(
            "SELECT uuid_generate_v7()::text, (extract(epoch FROM clock_timestamp()) * 1000)::bigint"
            " FROM generate_series(1, 200)"
        ).fetchall()
    ids = [r[0] for r in rows]
    assert all(is_uuid7(i) for i in ids)
    assert len(set(ids)) == len(ids)
    for value, now_ms in rows:
        assert abs(now_ms - uuid7_timestamp_ms(value)) < 5_000  # embedded time is the real clock
    stamps = [uuid7_timestamp_ms(i) for i in ids]
    assert stamps == sorted(stamps)  # ms-prefix is monotone within one statement


# --------------------------------------------------------------------------- PRD 7.4 + 8.2 conventions lint
def test_every_timestamp_column_is_timestamptz_and_no_money_column_is_float(db: DbHandle) -> None:
    with db.admin_conn() as conn:
        naive = conn.execute(
            "SELECT table_name, column_name FROM information_schema.columns"
            " WHERE table_schema = 'public' AND data_type = 'timestamp without time zone'"
        ).fetchall()
        money = conn.execute(
            "SELECT table_name, column_name, data_type FROM information_schema.columns"
            " WHERE table_schema = 'public'"
            " AND (column_name ~ '(_paise|_amount|amount_)' OR column_name = 'amount')"
            " AND data_type <> 'bigint'"
        ).fetchall()
    assert naive == []
    assert money == []


def test_every_table_uses_native_uuid_ids_and_the_dwaar_app_role_is_restricted(
    db: DbHandle,
) -> None:
    with db.admin_conn() as conn:
        bad_pk = conn.execute(
            "SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod)"
            " FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid"
            " JOIN pg_namespace n ON n.oid = c.relnamespace"
            " JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY (i.indkey)"
            " WHERE n.nspname = 'public' AND i.indisprimary AND c.relname <> 'schema_migrations'"
            " AND c.relkind = 'r' AND format_type(a.atttypid, a.atttypmod) NOT IN ('uuid', 'text')"
        ).fetchall()
        role = conn.execute(
            "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = 'dwaar_app'"
        ).fetchone()
    assert bad_pk == []
    assert role == (False, False, False, False)


def test_audit_log_and_outbox_carry_retention_class_and_legal_hold_id(db: DbHandle) -> None:
    with db.admin_conn() as conn:
        cols = {
            (t, c)
            for t, c in conn.execute(
                "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public'"
            ).fetchall()
        }
    missing = [
        (t, c)
        for t in ("audit_log", "outbox")
        for c in ("retention_class", "legal_hold_id")
        if (t, c) not in cols
    ]
    assert missing == []


# --------------------------------------------------------------------------- PRD 7.4 cursor pagination
def _make_scored_table(db: DbHandle) -> None:
    with db.owner_conn() as conn:
        conn.execute(
            "CREATE TABLE verify_scored (id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),"
            " society_id uuid NOT NULL, score integer)"
        )
        conn.execute("SELECT dwaar_enable_society_rls('verify_scored')")
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY),))
        for score in (5, None, 3, None, 1, 2, None, 4):
            conn.execute(
                "INSERT INTO verify_scored (society_id, score) VALUES (%s, %s)", (SOCIETY, score)
            )


def _walk(database: Database, paginator: Paginator, *, limit: int) -> list[dict[str, object]]:
    seen: list[dict[str, object]] = []
    cursor: str | None = None
    for _ in range(20):
        with database.app_tx(RequestContext(SOCIETY, None, "committee")) as conn:
            page = paginator.fetch(
                conn,
                select_sql="SELECT id, score FROM verify_scored",
                where=[],
                params={},
                sort=[SortColumn("score", "integer"), SortColumn("id", "uuid")],
                page=PageParams(limit=limit, cursor=cursor),
                society_id=SOCIETY,
            )
        seen.extend(page.items)
        cursor = page.next_cursor
        if cursor is None:
            return seen
    raise AssertionError("did not terminate")


def test_keyset_walk_over_a_non_null_column_returns_every_row_once(
    db: DbHandle, database: Database
) -> None:
    _make_scored_table(db)
    with db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY),))
        conn.execute("DELETE FROM verify_scored WHERE score IS NULL")
    rows = _walk(database, Paginator(b"verify-key"), limit=2)
    assert sorted(r["score"] for r in rows) == [1, 2, 3, 4, 5]  # type: ignore[type-var]


def test_keyset_walk_with_nullable_sort_column_does_not_lose_rows(
    db: DbHandle, database: Database
) -> None:
    _make_scored_table(db)
    rows = _walk(database, Paginator(b"verify-key"), limit=2)
    assert len(rows) == 8
    assert len({r["id"] for r in rows}) == 8


# --------------------------------------------------------------------------- PRD 12.4 audit text hygiene
def test_masked_diff_masks_identity_and_bank_fields_by_default() -> None:
    values = {
        "email": "ravi.kumar@example.org",
        "pan": "ABCDE1234F",
        "upi": "ravi@okhdfc",
        "ifsc": "HDFC0001234",
    }
    diff = masked_diff(None, values)
    leaked = {k: v["after"] for k, v in diff["changed"].items() if v["after"] == values[k]}
    assert leaked == {}


def test_scrubber_redacts_pan_in_free_text() -> None:
    assert "ABCDE1234F" not in scrub_text("deducted TDS for PAN ABCDE1234F yesterday")


# --------------------------------------------------------------------------- signing hygiene
def test_signature_over_an_event_with_an_inconsistent_payload_hash_is_rejected() -> None:
    """A signer bug (hash not matching payload) must not verify: payload_hash_matches() is part of verification."""
    signer = Signer.generate("edge-verify-1")
    good = EdgeEvent.build(
        society_id=uuid.uuid4(),
        device_id=uuid.uuid4(),
        seq=1,
        entity_id=uuid.uuid4(),
        entity_version=1,
        type="EntryObserved",
        policy_version=1,
        payload={"lane_id": "l1"},
    )
    broken = good.model_copy(update={"payload_hash": "sha256:" + "0" * 64})
    signed = signer.sign_event(broken)
    ring = VerifierRing({signer.key_id: signer.public_key})
    assert ring.verify_event(signer.key_id, signer.sign_event(good)) is True
    assert ring.verify_event(signer.key_id, signed) is False
