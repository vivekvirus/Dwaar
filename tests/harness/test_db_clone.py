"""Template/clone fixtures: isolation, ownership, cleanup, and the lazy-migration contract."""

from __future__ import annotations

import uuid
from pathlib import Path

import psycopg
import pytest

from tests._harness.pgfixtures import DbHandle, PgServer, _clone
from tests.harness._support import run_pytest


def _table_exists(db: DbHandle, table: str) -> bool:
    with db.owner_conn() as conn:
        row = conn.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{table}",)).fetchone()
        return bool(row and row[0])


def test_clones_are_isolated_from_each_other_and_from_the_template(
    pg_server: PgServer, bare_template_db: str, bare_db: DbHandle
) -> None:
    other_name = f"dwaar_t_{uuid.uuid4().hex[:10]}"
    pg_server.clone_database(other_name, bare_template_db)
    other = pg_server.handle_for(other_name)
    try:
        with bare_db.owner_conn() as conn:
            conn.execute("CREATE TABLE only_here (id int)")
            conn.execute("INSERT INTO only_here VALUES (1)")
        assert _table_exists(bare_db, "only_here")
        assert not _table_exists(other, "only_here")
        # a second clone made after the write still starts from the pristine template
        third_name = f"dwaar_t_{uuid.uuid4().hex[:10]}"
        pg_server.clone_database(third_name, bare_template_db)
        try:
            assert not _table_exists(pg_server.handle_for(third_name), "only_here")
        finally:
            pg_server.drop_database(third_name)
    finally:
        pg_server.drop_database(other_name)


def test_template_is_not_connectable(pg_server: PgServer, bare_template_db: str) -> None:
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(pg_server.admin_dsn(bare_template_db))


def test_clone_is_owned_by_dwaar_owner_with_public_locked_out(
    bare_db: DbHandle, pg_server: PgServer
) -> None:
    with pg_server.admin_conn() as conn:
        row = conn.execute(
            "SELECT pg_get_userbyid(datdba), "
            "has_database_privilege('dwaar_app', datname, 'CONNECT'), "
            "has_database_privilege('dwaar_worker', datname, 'CONNECT'), "
            "coalesce((SELECT bool_or(a.grantee = 0) FROM aclexplode(datacl) a), false) "
            "FROM pg_database WHERE datname = %s",
            (bare_db.name,),
        ).fetchone()
    assert row == ("dwaar_owner", True, True, False)  # grantee 0 would be PUBLIC


def test_clone_fixture_drops_the_database_afterwards(
    pg_server: PgServer, bare_template_db: str
) -> None:
    generator = _clone(pg_server, bare_template_db)
    handle = next(generator)
    with pg_server.admin_conn() as conn:
        assert conn.execute(
            "SELECT count(*) FROM pg_database WHERE datname = %s", (handle.name,)
        ).fetchone() == (1,)
    # leave a connection open: teardown must still succeed (DROP ... WITH FORCE)
    lingering = psycopg.connect(handle.owner_dsn)
    try:
        assert next(generator, None) is None
    finally:
        lingering.close()
    with pg_server.admin_conn() as conn:
        assert conn.execute(
            "SELECT count(*) FROM pg_database WHERE datname = %s", (handle.name,)
        ).fetchone() == (0,)
    assert handle.name not in pg_server._created


def test_dropping_clones_removes_them_from_the_server(
    pg_server: PgServer, bare_template_db: str
) -> None:
    names = [f"dwaar_t_{uuid.uuid4().hex[:10]}" for _ in range(2)]
    for name in names:
        pg_server.clone_database(name, bare_template_db)
    for name in names:
        pg_server.drop_database(name)
    with pg_server.admin_conn() as conn:
        left = conn.execute(
            "SELECT datname FROM pg_database WHERE datname = ANY(%s)", (names,)
        ).fetchall()
    assert left == []


def test_owner_can_run_ddl_in_clone_but_app_sees_only_granted(bare_db: DbHandle) -> None:
    with bare_db.owner_conn() as conn:
        conn.execute("CREATE TABLE t_priv (id int)")
        conn.execute("CREATE TABLE t_open (id int)")
        conn.execute("GRANT SELECT ON t_open TO dwaar_app")
    with bare_db.app_conn() as conn:
        assert conn.execute("SELECT count(*) FROM t_open").fetchone() == (0,)
    with pytest.raises(psycopg.errors.InsufficientPrivilege), bare_db.app_conn() as conn:
        conn.execute("SELECT count(*) FROM t_priv")


# --------------------------------------------------------------------------- lazy migrations

FAKE_MIGRATE_CONFTEST = """
import sys, types
import psycopg

fake = types.ModuleType("dwaar_api.core.migrate")

def run_migrations(owner_dsn):
    with psycopg.connect(owner_dsn, autocommit=True) as conn:
        conn.execute("CREATE TABLE migrated_marker (society_id uuid NOT NULL, v int)")
        conn.execute("ALTER TABLE migrated_marker ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE migrated_marker FORCE ROW LEVEL SECURITY")
        conn.execute(
            "CREATE POLICY p ON migrated_marker USING "
            "(society_id = nullif(current_setting('app.society_id', true), '')::uuid)"
        )
        conn.execute("GRANT SELECT, INSERT ON migrated_marker TO dwaar_app")

fake.run_migrations = run_migrations
sys.modules["dwaar_api"] = types.ModuleType("dwaar_api")
sys.modules["dwaar_api.core"] = types.ModuleType("dwaar_api.core")
sys.modules["dwaar_api.core.migrate"] = fake
"""

BLOCKED_MIGRATE_CONFTEST = """
import sys
sys.modules["dwaar_api.core.migrate"] = None  # import raises ModuleNotFoundError
"""


def test_db_fixture_skips_with_clear_message_when_migrate_module_is_missing(tmp_path: Path) -> None:
    result = run_pytest(
        tmp_path,
        {
            "conftest.py": BLOCKED_MIGRATE_CONFTEST,
            "test_x.py": "def test_needs_db(db):\n    raise AssertionError('must not run')\n",
        },
        "-rs",
    )
    assert result.returncode == 0, result.output
    assert "1 skipped" in result.output
    assert "dwaar_api.core.migrate is not available yet" in result.output


def test_db_fixture_runs_migrations_lazily_and_clones_per_test(tmp_path: Path) -> None:
    result = run_pytest(
        tmp_path,
        {
            "conftest.py": FAKE_MIGRATE_CONFTEST,
            "test_x.py": """
                import uuid

                A = uuid.uuid4()

                def test_one(db):
                    with db.app_conn(society_id=A) as conn:
                        conn.execute("INSERT INTO migrated_marker VALUES (%s, 1)", (A,))
                    with db.app_conn(society_id=A) as conn:
                        assert conn.execute("SELECT count(*) FROM migrated_marker").fetchone() == (1,)

                def test_two_sees_a_fresh_clone(db):
                    with db.app_conn(society_id=A) as conn:
                        assert conn.execute("SELECT count(*) FROM migrated_marker").fetchone() == (0,)
            """,
        },
    )
    assert result.returncode == 0, result.output
    assert "2 passed" in result.output
