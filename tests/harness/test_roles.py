"""Role model: restricted app/worker roles, RLS enforcement, request-context helper."""

from __future__ import annotations

import uuid

import psycopg
import pytest
from psycopg import errors

from tests._harness.pgfixtures import ROLES, DbHandle, PgServer

SOCIETY_A = uuid.UUID("0192f300-0000-7000-8000-00000000000a")
SOCIETY_B = uuid.UUID("0192f300-0000-7000-8000-00000000000b")


def test_roles_exist_with_restricted_attributes(pg_server: PgServer) -> None:
    with pg_server.admin_conn() as conn:
        rows = conn.execute(
            "SELECT rolname, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolreplication, rolcanlogin "
            "FROM pg_roles WHERE rolname = ANY(%s) ORDER BY rolname",
            (list(ROLES),),
        ).fetchall()
    assert [r[0] for r in rows] == sorted(ROLES)
    for name, superuser, bypass, createdb, createrole, replication, can_login in rows:
        assert not superuser, name
        assert not bypass, name
        assert not createdb, name
        assert not createrole, name
        assert not replication, name
        assert can_login, name


def test_bootstrap_is_idempotent_and_reasserts_attributes(pg_server: PgServer) -> None:
    with pg_server.admin_conn() as conn:
        conn.execute("ALTER ROLE dwaar_app BYPASSRLS CREATEDB")  # simulate drift
    pg_server.bootstrap_roles()
    pg_server.bootstrap_roles()
    with pg_server.admin_conn() as conn:
        assert conn.execute(
            "SELECT rolbypassrls, rolcreatedb FROM pg_roles WHERE rolname = 'dwaar_app'"
        ).fetchone() == (False, False)
        assert conn.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'dwaar\\_%'"
        ).fetchone() == (3,)


def test_app_role_cannot_create_objects(bare_db: DbHandle) -> None:
    for role_conn in (bare_db.app_conn, bare_db.worker_conn):
        with pytest.raises(errors.InsufficientPrivilege), role_conn() as conn:
            conn.execute("CREATE TABLE sneaky (id int)")
        with pytest.raises(errors.InsufficientPrivilege), role_conn() as conn:
            conn.execute("CREATE SCHEMA sneaky")
        with pytest.raises(errors.InsufficientPrivilege), role_conn() as conn:
            conn.execute("CREATE EXTENSION IF NOT EXISTS hstore")


def test_app_role_cannot_become_owner_or_superuser(bare_db: DbHandle) -> None:
    with pytest.raises(errors.InsufficientPrivilege), bare_db.app_conn() as conn:
        conn.execute("SET ROLE dwaar_owner")
    with pytest.raises(errors.InsufficientPrivilege), bare_db.app_conn() as conn:
        conn.execute("SET ROLE postgres")
    with pytest.raises(errors.InsufficientPrivilege), bare_db.app_conn() as conn:
        conn.execute("CREATE ROLE evil SUPERUSER")


def _make_probe_table(db: DbHandle) -> None:
    with db.owner_conn() as conn:
        conn.execute(
            "CREATE TABLE rls_probe (id serial PRIMARY KEY, society_id uuid NOT NULL, note text)"
        )
        conn.execute("ALTER TABLE rls_probe ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE rls_probe FORCE ROW LEVEL SECURITY")
        conn.execute(
            "CREATE POLICY society_isolation ON rls_probe "
            "USING (society_id = nullif(current_setting('app.society_id', true), '')::uuid) "
            "WITH CHECK (society_id = nullif(current_setting('app.society_id', true), '')::uuid)"
        )
        conn.execute("GRANT SELECT, INSERT ON rls_probe TO dwaar_app")
        conn.execute("GRANT USAGE ON SEQUENCE rls_probe_id_seq TO dwaar_app")


def test_rls_isolates_societies_for_app_role(bare_db: DbHandle) -> None:
    _make_probe_table(bare_db)
    with bare_db.app_conn(society_id=SOCIETY_A) as conn:
        conn.execute(
            "INSERT INTO rls_probe (society_id, note) VALUES (%s, 'a1'), (%s, 'a2')",
            (SOCIETY_A, SOCIETY_A),
        )
    with bare_db.app_conn(society_id=SOCIETY_B) as conn:
        conn.execute("INSERT INTO rls_probe (society_id, note) VALUES (%s, 'b1')", (SOCIETY_B,))

    with bare_db.app_conn(society_id=SOCIETY_A) as conn:
        assert conn.execute("SELECT note FROM rls_probe ORDER BY note").fetchall() == [
            ("a1",),
            ("a2",),
        ]
    with bare_db.app_conn(society_id=SOCIETY_B) as conn:
        assert conn.execute("SELECT note FROM rls_probe").fetchall() == [("b1",)]


def test_missing_context_yields_zero_rows_never_all_rows(bare_db: DbHandle) -> None:
    _make_probe_table(bare_db)
    with bare_db.app_conn(society_id=SOCIETY_A) as conn:
        conn.execute("INSERT INTO rls_probe (society_id, note) VALUES (%s, 'a1')", (SOCIETY_A,))
    with bare_db.app_conn() as conn:
        assert conn.execute("SELECT count(*) FROM rls_probe").fetchone() == (0,)
    with bare_db.app_conn(person_id=uuid.uuid4(), actor_role="guard") as conn:
        assert conn.execute("SELECT count(*) FROM rls_probe").fetchone() == (0,)
    # the owner is also bound by FORCE ROW LEVEL SECURITY
    with bare_db.owner_conn() as conn:
        assert conn.execute("SELECT count(*) FROM rls_probe").fetchone() == (0,)


def test_app_cannot_write_other_societys_rows_or_bypass_rls(bare_db: DbHandle) -> None:
    _make_probe_table(bare_db)
    with (
        pytest.raises(errors.InsufficientPrivilege),
        bare_db.app_conn(society_id=SOCIETY_A) as conn,
    ):
        conn.execute("INSERT INTO rls_probe (society_id, note) VALUES (%s, 'cross')", (SOCIETY_B,))
    with bare_db.app_conn(society_id=SOCIETY_A) as conn:
        conn.execute("SET row_security = off")
        with pytest.raises(errors.InsufficientPrivilege):
            conn.execute("SELECT * FROM rls_probe")
    with (
        pytest.raises(errors.InsufficientPrivilege),
        bare_db.app_conn(society_id=SOCIETY_A) as conn,
    ):
        conn.execute("ALTER TABLE rls_probe DISABLE ROW LEVEL SECURITY")
    with (
        pytest.raises(errors.InsufficientPrivilege),
        bare_db.app_conn(society_id=SOCIETY_A) as conn,
    ):
        conn.execute("DROP POLICY society_isolation ON rls_probe")
    with (
        pytest.raises(errors.InsufficientPrivilege),
        bare_db.app_conn(society_id=SOCIETY_A) as conn,
    ):
        conn.execute("DELETE FROM rls_probe")  # not granted


def test_app_conn_sets_request_context_transaction_locally(bare_db: DbHandle) -> None:
    person = uuid.uuid4()
    request = uuid.uuid4()
    with bare_db.app_conn(SOCIETY_A, person, "guard", request_id=request) as conn:
        row = conn.execute(
            "SELECT current_setting('app.society_id'), current_setting('app.person_id'), "
            "current_setting('app.actor_role'), current_setting('app.request_id')"
        ).fetchone()
        assert row == (str(SOCIETY_A), str(person), "guard", str(request))
        assert conn.execute("SELECT current_user").fetchone() == ("dwaar_app",)
    with bare_db.app_conn() as conn:
        assert conn.execute("SELECT current_setting('app.society_id', true)").fetchone() in {
            (None,),
            ("",),
        }


def test_context_does_not_survive_commit_like_production(bare_db: DbHandle) -> None:
    with bare_db.app_conn(SOCIETY_A, commit=False) as conn:
        conn.commit()
        assert conn.execute(
            "SELECT nullif(current_setting('app.society_id', true), '')"
        ).fetchone() == (None,)


def test_worker_conn_uses_worker_role(bare_db: DbHandle) -> None:
    with bare_db.worker_conn(SOCIETY_A, actor_role="worker") as conn:
        assert conn.execute("SELECT current_user").fetchone() == ("dwaar_worker",)
        assert conn.execute("SELECT current_setting('app.actor_role')").fetchone() == ("worker",)


def test_public_cannot_connect_but_roles_can(pg_server: PgServer, bare_db: DbHandle) -> None:
    with pg_server.admin_conn() as conn:
        conn.execute("DROP ROLE IF EXISTS stranger")
        conn.execute("CREATE ROLE stranger LOGIN PASSWORD 'x'")
    try:
        dsn = bare_db.owner_dsn.replace("dwaar_owner:test-only-owner-pw", "stranger:x")
        with pytest.raises(psycopg.OperationalError):
            psycopg.connect(dsn)
        with bare_db.owner_conn() as conn, bare_db.app_conn() as other:
            assert conn.execute("SELECT 1").fetchone() == (1,)
            assert other.execute("SELECT 1").fetchone() == (1,)
    finally:
        with pg_server.admin_conn() as conn:
            conn.execute("DROP ROLE IF EXISTS stranger")


def test_extensions_are_available_without_superuser(bare_db: DbHandle) -> None:
    with bare_db.app_conn() as conn:
        names = {r[0] for r in conn.execute("SELECT extname FROM pg_extension").fetchall()}
        assert {"pgcrypto", "pg_trgm", "btree_gist"} <= names
        assert conn.execute("SELECT length(gen_random_uuid()::text)").fetchone() == (36,)
        assert conn.execute(
            "SELECT encode(digest('x', 'sha256'), 'hex') IS NOT NULL"
        ).fetchone() == (True,)
