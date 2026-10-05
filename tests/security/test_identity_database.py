# ruff: noqa: PT018, PT012, F811
"""Database-level guarantees of the identity schema, proven with the REAL restricted roles (dwaar_app / dwaar_worker).

REQ: ARCH-02 (persons global; vault separated and encrypted), ARCH-03, INV-01, IAM-06, IAM-08.
The core catalog tests only scan schema ``public`` for SECURITY DEFINER functions; the identity tables and functions live in
schema ``iam`` (migration 0130), so the equivalent review is repeated here for that schema.
"""

from __future__ import annotations

import uuid
from typing import Any

import psycopg
import pytest
from psycopg import errors

from tests._harness.pgfixtures import DbHandle
from tests.integration.identity._support import IdentityHarness, idh  # noqa: F401  (fixture)
from tests.security.test_core_rls_isolation import find_rls_violations

pytestmark = pytest.mark.req("ARCH-02", "ARCH-03", "INV-01")

IAM_TABLES = (
    "persons", "person_vault", "otp_challenges", "otp_deliveries", "auth_sessions", "refresh_tokens", "mfa_factors",
    "person_access_index",
)  # fmt: skip
#: SECURITY DEFINER functions the runtime roles may execute. Each is reviewed: pinned search_path, gated on the
#: transaction context (iam.ctx_*) or on a proof (a consumed OTP challenge), and returning only what its caller may see.
REVIEWED_RUNTIME_DEFINERS = {
    "iam.effective_grants(uuid)", "iam.access_overview(uuid)", "iam.locate_membership(uuid)", "iam.society_people(uuid[])",
    "iam.person_profile(uuid)", "iam.update_profile(uuid,text,text)", "iam.vault_get(uuid)", "iam.vault_put(uuid,text,text)",
    "iam.change_phone(uuid,uuid,text,text)", "iam.session_is_active(uuid,uuid)", "iam.sweep_expired_grants()",
    "iam.ensure_person(uuid,text,text,text)", "iam.login_person(uuid,text,text,text,interval)",
    "iam.session_create(uuid,uuid,uuid,text,text,text,uuid,text,integer,integer)", "iam.session_rotate(text,uuid,text,integer)",
    "iam.session_list(uuid)", "iam.session_revoke(uuid,uuid,text)", "iam.session_revoke_others(uuid,uuid,text)",
    "iam.mfa_enrol(uuid,uuid,text)", "iam.mfa_get(uuid)", "iam.mfa_use_step(uuid,uuid,bigint,boolean)",
    "iam.session_mark_mfa(uuid,uuid)", "iam.session_mfa_fresh(uuid,uuid,integer)", "iam.otp_issue(uuid,text,text,uuid,text,integer,integer,uuid,text,text,boolean)",
    "iam.otp_attempt(text,text)", "iam.otp_consume(uuid)", "iam.otp_purge_expired()", "iam.dev_otp_latest(text)",
}  # fmt: skip
#: functions that must NOT be callable by the runtime roles at all (triggers, internal helpers)
OWNER_ONLY = {
    "iam.index_membership()", "iam.index_role_grant()", "iam.sweep_person(uuid)", "iam.revoke_all_sessions_internal(uuid,text)",
    "iam.verification_appeal_guard()", "iam.role_grant_immutable()",
}  # fmt: skip


def person_ctx(
    db: DbHandle,
    person: uuid.UUID | None,
    society: uuid.UUID | None = None,
    role: str | None = None,
) -> Any:
    return db.app_conn(society_id=society, person_id=person, actor_role=role)


def test_no_runtime_role_has_any_privilege_on_an_iam_table(db: DbHandle) -> None:
    # REQ: ARCH-02
    with db.admin_conn() as conn:
        for table in IAM_TABLES:
            for role in ("dwaar_app", "dwaar_worker", "public"):
                row = conn.execute(
                    "SELECT has_any_column_privilege(%s::name, %s::regclass, 'SELECT, INSERT, UPDATE, REFERENCES'),"
                    " has_table_privilege(%s::name, %s::regclass, 'DELETE, TRUNCATE, TRIGGER')",
                    (role, f"iam.{table}", role, f"iam.{table}"),
                ).fetchone()
                assert row == (False, False), f"{role} can reach iam.{table}"
        assert conn.execute(
            "SELECT has_schema_privilege('dwaar_app', 'iam', 'CREATE'), has_schema_privilege('dwaar_worker', 'iam', 'CREATE'),"
            " has_schema_privilege('public'::name, 'iam', 'USAGE')"
        ).fetchone() == (False, False, False)


def test_every_iam_security_definer_is_reviewed_and_locked_down(db: DbHandle) -> None:
    # REQ: ARCH-03
    with db.admin_conn() as conn:
        rows = conn.execute(
            """
            SELECT p.oid::regprocedure::text, p.prosecdef, p.proconfig,
                   has_function_privilege('dwaar_app', p.oid, 'EXECUTE'),
                   has_function_privilege('dwaar_worker', p.oid, 'EXECUTE'),
                   has_function_privilege('public'::name, p.oid, 'EXECUTE'),
                   pg_get_userbyid(p.proowner)
            FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = 'iam'
            """
        ).fetchall()
    assert rows
    runtime = set()
    for sig, secdef, config, app, worker, public, owner in rows:
        assert not public, f"{sig} is executable by PUBLIC"
        assert config and any(c.startswith("search_path=") for c in config), (
            f"{sig}: no pinned search_path"
        )
        assert owner == "dwaar_owner"
        if secdef and (app or worker):
            runtime.add(sig)
    assert runtime == REVIEWED_RUNTIME_DEFINERS, runtime ^ REVIEWED_RUNTIME_DEFINERS
    by_sig = {r[0]: r for r in rows}
    for sig in OWNER_ONLY:
        assert sig in by_sig and not by_sig[sig][3] and not by_sig[sig][4], (
            f"{sig} must not be callable by runtime roles"
        )
    # the worker only runs housekeeping
    worker_ok = {r[0] for r in rows if r[4] and r[1]}
    assert worker_ok <= {"iam.sweep_expired_grants()", "iam.otp_purge_expired()"}


def test_catalog_guard_still_passes_with_the_identity_tables(db: DbHandle) -> None:
    # REQ: ARCH-01 ARCH-03 INV-01
    with db.admin_conn() as conn:
        assert find_rls_violations(conn) == []
        society_tables = {
            r[0]
            for r in conn.execute(
                "SELECT c.relname FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'society_id'"
                " WHERE c.relkind = 'r' AND c.relnamespace = 'public'::regnamespace"
            )
        }
    assert {
        "memberships",
        "verification_cases",
        "membership_holds",
        "role_grants",
    } <= society_tables


def test_direct_reads_of_the_vault_and_other_global_tables_are_refused(
    idh: IdentityHarness,
) -> None:
    # REQ: ARCH-02
    p = idh.login(1)
    for table in IAM_TABLES:
        with person_ctx(idh.db, p.id) as conn, pytest.raises(errors.InsufficientPrivilege):
            conn.execute(f"SELECT * FROM iam.{table}")  # type: ignore[call-overload]  # noqa: S608
    with person_ctx(idh.db, p.id) as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute("UPDATE iam.persons SET display_name = 'x'")
    with idh.db.worker_conn() as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute("SELECT phone_enc FROM iam.person_vault")
    with idh.db.worker_conn() as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute("SELECT iam.vault_get(%s)", (p.id,))  # no EXECUTE for the worker either


def test_vault_ciphertext_is_reachable_only_on_a_designed_path(idh: IdentityHarness) -> None:
    # REQ: ARCH-02
    a, b = idh.society("A"), idh.society("B")
    in_a, in_b, nobody = idh.login(10), idh.login(11), idh.login(12)
    idh.seed_membership(a.id, in_a.id, a.units["A-101"], "tenant")
    idh.seed_membership(b.id, in_b.id, b.units["A-101"], "tenant")
    sql = "SELECT person_id, phone_enc FROM iam.vault_get(%s)"
    # (1) the person themself
    with person_ctx(idh.db, in_a.id) as conn:
        row = conn.execute(sql, (in_a.id,)).fetchone()
        assert (
            row is not None and row[1].startswith("v1:") and in_a.phone not in row[1]
        )  # ciphertext, never the number
        assert conn.execute(sql, (in_b.id,)).fetchall() == []  # another person: nothing
    # (2) a secretary acting in society A: persons of A yes, persons only in B no, strangers no
    with person_ctx(idh.db, nobody.id, a.id, "secretary") as conn:
        assert len(conn.execute(sql, (in_a.id,)).fetchall()) == 1
        assert conn.execute(sql, (in_b.id,)).fetchall() == []
        assert conn.execute(sql, (nobody.id,)).fetchall() == [
            (nobody.id, conn.execute(sql, (nobody.id,)).fetchone()[1])
        ]  # type: ignore[index]
    # (3) the same society context WITHOUT the secretary role: nothing about other people
    with person_ctx(idh.db, nobody.id, a.id, "tenant") as conn:
        assert conn.execute(sql, (in_a.id,)).fetchall() == []
    # (4) no context at all
    with idh.db.app_conn() as conn:
        assert conn.execute(sql, (in_a.id,)).fetchall() == []


def test_person_scoped_functions_answer_only_for_the_context_person(idh: IdentityHarness) -> None:
    # REQ: ARCH-02 IAM-08
    a, b = idh.login(20), idh.login(21)
    with person_ctx(idh.db, a.id) as conn:
        assert conn.execute("SELECT count(*) FROM iam.session_list(%s)", (a.id,)).fetchone() == (1,)
        assert conn.execute("SELECT count(*) FROM iam.session_list(%s)", (b.id,)).fetchone() == (0,)
        assert conn.execute(
            "SELECT iam.session_revoke(%s, %s, 'x')", (b.id, b.session_id)
        ).fetchone() == (False,)
        assert conn.execute(
            "SELECT iam.session_revoke_others(%s, %s, 'x')", (b.id, b.session_id)
        ).fetchone() == (0,)
        assert conn.execute(
            "SELECT count(*) FROM iam.effective_grants(%s)", (b.id,)
        ).fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM iam.access_overview(%s)", (b.id,)).fetchone() == (
            0,
        )
        assert conn.execute("SELECT count(*) FROM iam.mfa_get(%s)", (b.id,)).fetchone() == (0,)
        assert conn.execute(
            "SELECT iam.mfa_enrol(%s, %s, 'v1:x')", (b.id, uuid.uuid4())
        ).fetchone() == (False,)
        assert conn.execute(
            "SELECT iam.session_mark_mfa(%s, %s)", (b.id, b.session_id)
        ).fetchone() == (False,)
        assert conn.execute("SELECT count(*) FROM iam.person_profile(%s)", (b.id,)).fetchone() == (
            0,
        )
        assert conn.execute(
            "SELECT iam.update_profile(%s, 'Hacked', NULL)", (b.id,)
        ).fetchone() == (False,)
    assert idh.admin_rows("SELECT display_name FROM iam.persons WHERE id = %s", (b.id,)) == [
        ("Resident",)
    ]
    assert idh.admin_rows(
        "SELECT revoked_at IS NULL FROM iam.auth_sessions WHERE id = %s", (b.session_id,)
    ) == [(True,)]


def test_a_session_cannot_be_minted_without_proof_of_a_fresh_login_otp(
    idh: IdentityHarness,
) -> None:
    # REQ: IAM-08 IAM-06
    victim = idh.login(30)
    with idh.db.app_conn() as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute(
            "SELECT iam.session_create(%s, %s, %s, 'd', 'l', NULL, %s, %s, 3600, 5)",
            (uuid.uuid4(), victim.id, uuid.uuid4(), uuid.uuid4(), "0" * 64),
        )
    # a challenge that exists but was already used for a session cannot be replayed either
    cid = idh.admin_rows("SELECT id FROM iam.otp_challenges")[0][0]
    with idh.db.app_conn() as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute(
            "SELECT iam.session_create(%s, %s, %s, 'd', 'l', NULL, %s, %s, 3600, 5)",
            (uuid.uuid4(), victim.id, cid, uuid.uuid4(), "1" * 64),
        )


def test_access_index_is_written_only_by_triggers(idh: IdentityHarness) -> None:
    # REQ: IAM-01 IAM-02
    soc = idh.society()
    p = idh.login(40)
    mid = idh.seed_membership(soc.id, p.id, soc.units["A-101"], "tenant")
    rows = idh.admin_rows(
        "SELECT role, effective, verification FROM iam.person_access_index WHERE source_id = %s",
        (mid,),
    )
    assert rows == [("tenant", True, "verified")]
    with idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(soc.id),))
        conn.execute("UPDATE memberships SET verification = 'rejected' WHERE id = %s", (mid,))
    assert idh.admin_rows(
        "SELECT effective FROM iam.person_access_index WHERE source_id = %s", (mid,)
    ) == [(False,)]
    with idh.db.app_conn(society_id=soc.id) as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute("UPDATE iam.person_access_index SET effective = true")


def test_society_tables_are_force_rls_and_isolated_between_societies(idh: IdentityHarness) -> None:
    # REQ: INV-01 ARCH-01
    a, b = idh.society("A"), idh.society("B")
    pa, pb = idh.login(50), idh.login(51)
    mem_a = idh.seed_membership(a.id, pa.id, a.units["A-101"], "tenant")
    mem_b = idh.seed_membership(b.id, pb.id, b.units["A-101"], "tenant")
    idh.seed_grant(a.id, pa.id, "guard")
    idh.seed_grant(b.id, pb.id, "guard")
    with idh.db.admin_conn() as conn:
        for table in ("memberships", "verification_cases", "membership_holds", "role_grants"):
            assert conn.execute(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = %s::regclass",
                (table,),
            ).fetchone() == (True, True), table
    for table in ("memberships", "role_grants"):
        with idh.db.app_conn(society_id=a.id) as conn:
            ids = {r[0] for r in conn.execute(f"SELECT society_id FROM {table}")}  # type: ignore[call-overload]  # noqa: S608
            assert ids == {a.id}, table
        with idh.db.app_conn() as conn:  # no context: zero rows, never all rows
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)  # type: ignore[call-overload]  # noqa: S608
    with idh.db.app_conn(society_id=a.id) as conn:
        assert (
            conn.execute(
                "UPDATE memberships SET evidence_ref = 'x' WHERE id = %s", (mem_b,)
            ).rowcount
            == 0
        )
        assert conn.execute(
            "SELECT count(*) FROM memberships WHERE id = %s", (mem_a,)
        ).fetchone() == (1,)
        with pytest.raises(errors.InsufficientPrivilege):
            conn.execute("DELETE FROM memberships")
    with idh.db.app_conn(society_id=a.id) as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute(
            "INSERT INTO memberships (society_id, person_id, unit_id, kind, created_by) VALUES (%s, %s, %s, 'tenant', %s)",
            (b.id, pa.id, b.units["A-101"], pa.id),
        )
    # the composite foreign key refuses a unit of another society even for a row of one's own society
    with idh.db.owner_conn() as conn, pytest.raises(errors.ForeignKeyViolation):
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(a.id),))
        conn.execute(
            "INSERT INTO memberships (society_id, person_id, unit_id, kind, created_by) VALUES (%s, %s, %s, 'tenant', %s)",
            (a.id, pa.id, b.units["B-201"], pa.id),
        )
    with idh.db.worker_conn(a.id) as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute(
            "UPDATE memberships SET evidence_ref = 'w'"
        )  # the worker reads, it does not write identity data


def test_application_role_cannot_forge_a_grant_or_change_its_history(idh: IdentityHarness) -> None:
    # REQ: IAM-02 IAM-03
    soc = idh.society()
    p = idh.login(60)
    gid = idh.seed_grant(soc.id, p.id, "guard")
    with (
        idh.db.app_conn(society_id=soc.id) as conn,
        pytest.raises(psycopg.Error, match="immutable"),
    ):
        conn.execute("UPDATE role_grants SET role = 'secretary' WHERE id = %s", (gid,))
    with (
        idh.db.app_conn(society_id=soc.id) as conn,
        pytest.raises(psycopg.Error, match="role_grants_no_self_grant"),
    ):
        conn.execute(
            "INSERT INTO role_grants (society_id, person_id, role, issued_by, reason) VALUES (%s, %s, 'secretary', %s, 'self grant')",
            (soc.id, p.id, p.id),
        )
