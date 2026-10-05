"""Database-level guarantees of the visits schema (migrations 0200-0205): RLS on every society table, composite foreign keys,
append-only history, the single valid first decision, device sequence and event id uniqueness, no fabricated exit time and
no raw visitor number anywhere.

REQ: ARCH-01, INV-01, DB-02, INV-07, GATE-03, GATE-05, GATE-13, PRD 8.2.
"""

from __future__ import annotations

import uuid
from typing import Any

import psycopg
import pytest

from dwaar_common.ids import uuid7
from tests.integration.identity._support import IdentityHarness
from tests.integration.visits._support import VW, new_key

pytestmark = [pytest.mark.req("ARCH-01", "INV-01", "INV-07", "DB-02")]

VISIT_TABLES = (
    "gates",
    "lanes",
    "devices",
    "gate_policies",
    "invitations",
    "invitation_windows",
    "visits",
    "visit_stops",
    "approval_requests",
    "approval_decisions",
    "access_events",
    "exceptions",
)


def _owner(idh: IdentityHarness, society: uuid.UUID, sql: str, params: tuple[Any, ...] = ()) -> Any:
    with idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(society),))
        return (
            conn.execute(sql, params).fetchall()
            if sql.lstrip().upper().startswith("SELECT")
            else conn.execute(sql, params)
        )  # type: ignore[call-overload]


def _gate(idh: IdentityHarness, society: uuid.UUID, name: str = "G") -> uuid.UUID:
    gid = uuid7()
    _owner(
        idh,
        society,
        "INSERT INTO gates (id, society_id, name, kind) VALUES (%s, %s, %s, 'mixed')",
        (gid, society, name),
    )
    return gid


def _person(idh: IdentityHarness) -> uuid.UUID:
    return idh.system_person()


def _visit(idh: IdentityHarness, society: uuid.UUID, by: uuid.UUID, **cols: Any) -> uuid.UUID:
    vid = uuid7()
    values = {"kind": "guest", "state": "requested", "visitor_alias": "V", **cols}
    names = ", ".join(["id", "society_id", "created_by", *values])
    marks = ", ".join(["%s"] * (3 + len(values)))
    _owner(
        idh,
        society,
        f"INSERT INTO visits ({names}) VALUES ({marks})",
        (vid, society, by, *values.values()),
    )
    return vid


@pytest.mark.req("ARCH-01", "ARCH-03")
def test_every_visits_table_is_force_rls_with_a_society_policy(vw: VW) -> None:
    rows = vw.rows(
        "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,"
        " (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid AND pg_get_expr(p.polqual, p.polrelid) LIKE '%%app.society_id%%'),"
        " (SELECT a.attnotnull FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'society_id')"
        " FROM pg_class c WHERE c.relname = ANY(%s) AND c.relkind = 'r'",
        (list(VISIT_TABLES),),
    )
    assert {r[0] for r in rows} == set(VISIT_TABLES)
    for name, enabled, forced, policies, notnull in rows:
        assert enabled and forced and policies >= 1 and notnull, name


def test_a_society_context_sees_none_of_the_other_societys_rows(vw: VW) -> None:
    idh = vw.idh
    other = idh.society("Other Towers", units=("Z-1",))
    mine = _gate(idh, vw.soc.id, "Mine")
    theirs = _gate(idh, other.id, "Theirs")
    with idh.db.app_conn(vw.soc.id) as conn:
        seen = {r[0] for r in conn.execute("SELECT id FROM gates").fetchall()}
    assert mine in seen and theirs not in seen
    with idh.db.app_conn() as conn:  # no context at all: zero rows, never all rows
        assert conn.execute("SELECT count(*) FROM gates").fetchone() == (0,)
    with idh.db.app_conn(vw.soc.id) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(
            "INSERT INTO gates (id, society_id, name, kind) VALUES (%s, %s, 'sneaky', 'mixed')",
            (uuid7(), other.id),
        )


@pytest.mark.req("ARCH-01")
def test_composite_foreign_keys_refuse_references_into_another_society(vw: VW) -> None:
    idh = vw.idh
    other = idh.society("Other Towers", units=("Z-1",))
    foreign_gate = _gate(idh, other.id)
    foreign_unit = other.units["Z-1"]
    me = _person(idh)
    gid = _gate(idh, vw.soc.id)
    # a lane of my society on THEIR gate
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _owner(
            idh,
            vw.soc.id,
            "INSERT INTO lanes (id, society_id, gate_id, label, direction) VALUES (%s, %s, %s, 'x', 'in')",
            (uuid7(), vw.soc.id, foreign_gate),
        )
    # an invitation of my society for THEIR unit
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _owner(
            idh,
            vw.soc.id,
            "INSERT INTO invitations (id, society_id, host_person_id, unit_id, purpose, people_count, window_start,"
            " window_end, max_uses, token_nonce, created_by) VALUES (%s, %s, %s, %s, 'p', 1, now(), now() + interval '1 hour',"
            " 1, 'nonce-nonce', %s)",
            (uuid7(), vw.soc.id, me, foreign_unit, me),
        )
    # a visit at THEIR gate
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _visit(idh, vw.soc.id, me, gate_id=foreign_gate)
    # a stop for THEIR unit, an approval request for THEIR unit
    visit = _visit(idh, vw.soc.id, me, gate_id=gid)
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _owner(
            idh,
            vw.soc.id,
            "INSERT INTO visit_stops (id, society_id, visit_id, unit_id, seq) VALUES (%s, %s, %s, %s, 1)",
            (uuid7(), vw.soc.id, visit, foreign_unit),
        )
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _owner(
            idh,
            vw.soc.id,
            "INSERT INTO approval_requests (id, society_id, unit_id, visit_id, expires_at, requested_by)"
            " VALUES (%s, %s, %s, %s, now() + interval '90 seconds', %s)",
            (uuid7(), vw.soc.id, foreign_unit, visit, me),
        )


def _request(vw: VW) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """An approval request with its visit, inserted directly (owner role): returns (request, visit, person)."""
    idh = vw.idh
    me = _person(idh)
    visit = _visit(idh, vw.soc.id, me)
    request = uuid7()
    _owner(
        idh,
        vw.soc.id,
        "INSERT INTO approval_requests (id, society_id, unit_id, visit_id, expires_at, requested_by)"
        " VALUES (%s, %s, %s, %s, now() + interval '90 seconds', %s)",
        (request, vw.soc.id, vw.unit("A-101"), visit, me),
    )
    return request, visit, me


@pytest.mark.req("GATE-03", "DB-02")
def test_only_one_valid_first_decision_per_request_and_decisions_are_append_only(vw: VW) -> None:
    request, _visit_id, me = _request(vw)
    other = _person(vw.idh)

    def decision(by: uuid.UUID, valid: bool = True, kind: str = "approve") -> None:
        _owner(
            vw.idh,
            vw.soc.id,
            "INSERT INTO approval_decisions (id, society_id, request_id, decided_by, decider_role, decision, client_action_id,"
            " valid, request_version) VALUES (%s, %s, %s, %s, 'owner_occ', %s, %s, %s, 2)",
            (uuid7(), vw.soc.id, request, by, kind, uuid.uuid4(), valid),
        )

    decision(me)
    with pytest.raises(psycopg.errors.UniqueViolation):
        decision(other)  # a second FIRST decision is impossible whoever writes it
    with vw.idh.db.app_conn(vw.soc.id) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE approval_decisions SET decision = 'deny'")
    with vw.idh.db.app_conn(vw.soc.id) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM approval_decisions")
    with pytest.raises(psycopg.errors.Error, match="append-only"):
        _owner(
            vw.idh, vw.soc.id, "DELETE FROM approval_decisions"
        )  # even the owner role: trigger DW001


@pytest.mark.req("DB-02", "INV-07")
def test_access_events_are_append_only_and_device_sequence_and_event_id_are_unique(vw: VW) -> None:
    vw.setup_gate()
    h = vw.household("A-101")
    _req, canon = vw.approved_visit(h.unit, h.owner)
    visit_id = vw.rows(
        "SELECT visit_id FROM approval_requests WHERE id = %s", (canon["request_id"],)
    )[0][0]
    r = vw.observe(visit_id, "entry", seq=5)
    assert r.status_code == 201, r.text
    event_id = r.json()["event"]["event_id"]
    with vw.idh.db.app_conn(vw.soc.id) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE access_events SET seq = 99")
    with pytest.raises(psycopg.errors.Error, match="append-only"):
        _owner(vw.idh, vw.soc.id, "DELETE FROM access_events")
    # same device + same seq, different event id: the second observation is refused (409, nothing written)
    clash = vw.observe(visit_id, "entry", seq=5)
    assert clash.status_code == 409 and clash.json()["code"] == "stale_version"
    assert vw.rows("SELECT count(*) FROM access_events")[0][0] == 1
    assert event_id  # the first event id stays unique per society
    with pytest.raises(psycopg.errors.UniqueViolation):
        _owner(
            vw.idh,
            vw.soc.id,
            "INSERT INTO access_events (id, society_id, device_id, seq, event_id, event_type, gate_id, credential_kind,"
            " decision_source, occurred_at, payload_hash) SELECT %s, society_id, device_id, seq + 100, event_id, event_type,"
            " gate_id, credential_kind, decision_source, occurred_at, payload_hash FROM access_events",
            (uuid7(),),
        )


@pytest.mark.req("GATE-05", "INV-07")
def test_the_database_refuses_a_manufactured_exit_time(vw: VW) -> None:
    me = _person(vw.idh)
    entered = "now() - interval '5 minutes'"
    for cols, ok in (
        ({"state": "exited", "exit_basis": "scanned"}, False),  # a scanned exit needs a time
        (
            {
                "state": "exited",
                "exit_basis": "reconciled_unknown",
                "exited_at": "now()",
                "exit_reconciled_at": "now()",
            },
            False,
        ),
        (
            {"state": "exited", "exit_basis": "reconciled_unknown"},
            False,
        ),  # reconciled needs the reconciliation instant
        (
            {
                "state": "exited",
                "exit_basis": "reconciled_unknown",
                "exit_reconciled_at": "now()",
                "confidence_inside": "unknown",
            },
            True,
        ),
        (
            {
                "state": "exited",
                "exit_basis": "observed",
                "exited_at": "now()",
                "confidence_inside": "none",
            },
            True,
        ),
    ):
        names = [
            "id",
            "society_id",
            "kind",
            "visitor_alias",
            "created_by",
            "authorised_at",
            "entered_at",
            *cols,
        ]
        values = ", ".join(
            [
                "%s",
                "%s",
                "'guest'",
                "'V'",
                "%s",
                "now() - interval '10 minutes'",
                entered,
                *(
                    f"'{v}'" if isinstance(v, str) and not v.startswith("now") else str(v)
                    for v in cols.values()
                ),
            ]
        )
        sql = f"INSERT INTO visits ({', '.join(names)}) VALUES ({values})"  # noqa: S608
        if ok:
            _owner(vw.idh, vw.soc.id, sql, (uuid7(), vw.soc.id, me))
        else:
            with pytest.raises(psycopg.errors.CheckViolation):
                _owner(vw.idh, vw.soc.id, sql, (uuid7(), vw.soc.id, me))


@pytest.mark.req("GATE-01")
def test_a_pass_cannot_be_open_ended(vw: VW) -> None:
    """'Never a permanent OTP': the window, the span and the uses are bounded by CHECK constraints."""
    me = _person(vw.idh)
    base = (
        "INSERT INTO invitations (id, society_id, host_person_id, unit_id, purpose, people_count, window_start,"
        " window_end, max_uses, token_nonce, created_by) VALUES (%s, %s, %s, %s, 'p', 1, now(), now() + {span}, {uses},"
        " 'nonce-nonce', %s)"
    )
    unit = vw.unit("A-101")
    ok = base.format(span="interval '2 days'", uses=3)
    _owner(vw.idh, vw.soc.id, ok, (uuid7(), vw.soc.id, me, unit, me))
    for span, uses in (
        ("interval '400 days'", 1),
        ("interval '1 day'", 101),
        ("interval '1 day'", 0),
    ):
        with pytest.raises(psycopg.errors.CheckViolation):
            _owner(
                vw.idh,
                vw.soc.id,
                base.format(span=span, uses=uses),
                (uuid7(), vw.soc.id, me, unit, me),
            )


@pytest.mark.req("GATE-13")
def test_no_visitor_number_column_exists_only_the_keyed_token(vw: VW) -> None:
    rows = vw.rows(
        "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public'"
        " AND table_name = ANY(%s) AND (column_name ILIKE %s OR column_name ILIKE %s OR column_name ILIKE %s)",
        (list(VISIT_TABLES), "%phone%", "%mobile%", "%msisdn%"),
    )
    assert rows == []
    tokens = vw.rows(
        "SELECT table_name FROM information_schema.columns WHERE table_schema = 'public' AND column_name = 'visitor_contact_token'"
    )
    assert {r[0] for r in tokens} == {"invitations", "visits"}


def test_devices_enrolment_record_is_per_society_and_maker_checker(vw: VW) -> None:
    me = _person(vw.idh)
    other = _person(vw.idh)
    key = new_key()
    sql = (
        "INSERT INTO devices (id, society_id, kind, name, public_key, key_id, requested_by, {extra}) VALUES"
        " (%s, %s, 'terminal', 'T', %s, 'k1', %s, {vals})"
    )
    with pytest.raises(psycopg.errors.CheckViolation):  # decided by the requester
        _owner(
            vw.idh,
            vw.soc.id,
            sql.format(extra="state, decided_by, decided_at", vals="'active', %s, now()"),
            (uuid7(), vw.soc.id, key, me, me),
        )
    _owner(
        vw.idh,
        vw.soc.id,
        sql.format(extra="state, decided_by, decided_at", vals="'active', %s, now()"),
        (uuid7(), vw.soc.id, key, me, other),
    )
    with pytest.raises(psycopg.errors.UniqueViolation):  # the same key twice in one society
        _owner(
            vw.idh,
            vw.soc.id,
            sql.format(extra="simulation", vals="false"),
            (uuid7(), vw.soc.id, key, me),
        )
