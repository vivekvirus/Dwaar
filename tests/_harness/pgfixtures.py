"""PostgreSQL fixtures: `pg_server`, `template_db`, `db` (+ `bare_*` variants without migrations).

Production parity rules baked in:
* the API/worker roles are the real restricted roles from infra/db/bootstrap_roles.sql
  (NOSUPERUSER NOBYPASSRLS), never the superuser;
* `app_conn()` sets `app.society_id` / `app.person_id` / `app.actor_role` with
  `set_config(..., true)` inside a transaction, exactly like the API does per request;
* migrations run as `dwaar_owner` through `dwaar_api.core.migrate.run_migrations(owner_dsn)`
  (imported lazily; DB-backed tests skip with a clear message until that module exists).
"""

from __future__ import annotations

import contextlib
import importlib
import os
import signal
import subprocess
import uuid
from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import psycopg
import pytest
from psycopg import sql
from psycopg.rows import RowFactory, tuple_row

from tests._harness.pgcluster import PgCluster, find_pg_bin, find_psql

REPO_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_ROLES_SQL = REPO_ROOT / "infra" / "db" / "bootstrap_roles.sql"
CREATE_DATABASE_SQL = REPO_ROOT / "infra" / "db" / "create_database.sql"

# Test-only credentials for disposable databases. Not secrets; real environments get theirs
# from the environment (see .env.example).
TEST_PASSWORDS: dict[str, str] = {
    "dwaar_owner": "test-only-owner-pw",
    "dwaar_app": "test-only-app-pw",
    "dwaar_worker": "test-only-worker-pw",
}
ROLES = tuple(TEST_PASSWORDS)

#: Filled by `pg_server`; read by the evidence writer.
RUN_INFO: dict[str, Any] = {"postgres": None, "pg_mode": None}


def make_dsn(
    url: str, *, user: str | None = None, password: str | None = None, dbname: str | None = None
) -> str:
    """Rewrite a postgresql:// URL with another user/password/database."""
    parts = urlsplit(url)
    host = parts.hostname or "127.0.0.1"
    port = f":{parts.port}" if parts.port else ""
    cred_user = user if user is not None else unquote(parts.username or "")
    cred_pw = (
        password if password is not None else (unquote(parts.password) if parts.password else None)
    )
    auth = quote(cred_user, safe="")
    if cred_pw is not None:
        auth += ":" + quote(cred_pw, safe="")
    path = "/" + quote(dbname, safe="") if dbname is not None else parts.path
    return urlunsplit((parts.scheme or "postgresql", f"{auth}@{host}{port}", path, "", ""))


@contextlib.contextmanager
def _session(
    dsn: str,
    settings: Mapping[str, str] | None = None,
    *,
    commit: bool = True,
    row_factory: RowFactory[Any] = tuple_row,
) -> Iterator[psycopg.Connection[Any]]:
    """Open a connection with an open transaction; `set_config(..., true)` for each setting."""
    conn = psycopg.connect(dsn, row_factory=row_factory)
    try:
        if settings:
            with conn.cursor() as cur:
                for name, value in settings.items():
                    cur.execute("SELECT set_config(%s, %s, true)", (name, value))
        yield conn
        conn.commit() if commit else conn.rollback()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


@dataclass(frozen=True)
class DbHandle:
    """A private cloned database plus the four ways to reach it."""

    name: str
    admin_dsn: str
    owner_dsn: str
    app_dsn: str
    worker_dsn: str

    def admin_conn(
        self, *, commit: bool = True, row_factory: RowFactory[Any] = tuple_row
    ) -> AbstractContextManager[psycopg.Connection[Any]]:
        """Superuser connection (fixtures/diagnostics only; never what production code uses)."""
        return _session(self.admin_dsn, commit=commit, row_factory=row_factory)

    def owner_conn(
        self, *, commit: bool = True, row_factory: RowFactory[Any] = tuple_row
    ) -> AbstractContextManager[psycopg.Connection[Any]]:
        """Connection as `dwaar_owner` (DDL, seeding that bypasses nothing: RLS is FORCEd)."""
        return _session(self.owner_dsn, commit=commit, row_factory=row_factory)

    def app_conn(
        self,
        society_id: uuid.UUID | str | None = None,
        person_id: uuid.UUID | str | None = None,
        actor_role: str | None = None,
        *,
        request_id: uuid.UUID | str | None = None,
        commit: bool = True,
        row_factory: RowFactory[Any] = tuple_row,
    ) -> AbstractContextManager[psycopg.Connection[Any]]:
        """Connection as `dwaar_app` with the request context set transaction-locally.

        Settings only live until the first commit/rollback, exactly as in production; do not
        call `conn.commit()` yourself mid-test if you still need the context afterwards.
        Unset arguments are not set at all (=> RLS sees no society => zero rows).
        """
        return _session(
            self.app_dsn,
            _context_settings(society_id, person_id, actor_role, request_id),
            commit=commit,
            row_factory=row_factory,
        )

    def worker_conn(
        self,
        society_id: uuid.UUID | str | None = None,
        person_id: uuid.UUID | str | None = None,
        actor_role: str | None = None,
        *,
        request_id: uuid.UUID | str | None = None,
        commit: bool = True,
        row_factory: RowFactory[Any] = tuple_row,
    ) -> AbstractContextManager[psycopg.Connection[Any]]:
        """Connection as `dwaar_worker`; per-society context for society data."""
        return _session(
            self.worker_dsn,
            _context_settings(society_id, person_id, actor_role, request_id),
            commit=commit,
            row_factory=row_factory,
        )


def _context_settings(
    society_id: object, person_id: object, actor_role: object, request_id: object
) -> dict[str, str]:
    values = {
        "app.society_id": society_id,
        "app.person_id": person_id,
        "app.actor_role": actor_role,
        "app.request_id": request_id,
    }
    return {name: str(value) for name, value in values.items() if value is not None}


@dataclass
class PgServer:
    """A reachable PostgreSQL server (ephemeral private cluster or CI service container)."""

    admin_url: str
    external: bool
    cluster: PgCluster | None = None
    version: str = ""
    _created: list[str] = field(default_factory=list)

    # ---------------------------------------------------------------- connections

    def admin_dsn(self, dbname: str = "postgres") -> str:
        return make_dsn(self.admin_url, dbname=dbname)

    def dsn(self, role: str, dbname: str) -> str:
        return make_dsn(self.admin_url, user=role, password=TEST_PASSWORDS[role], dbname=dbname)

    def admin_conn(
        self, dbname: str = "postgres", *, autocommit: bool = True
    ) -> psycopg.Connection[Any]:
        return psycopg.connect(self.admin_dsn(dbname), autocommit=autocommit)

    # ---------------------------------------------------------------- psql-driven bootstrap

    def psql_file(self, path: Path, variables: Mapping[str, str], dbname: str = "postgres") -> None:
        cmd = [find_psql(), "-X", "-q", "-v", "ON_ERROR_STOP=1"]
        for key, value in variables.items():
            cmd += ["-v", f"{key}={value}"]
        cmd += ["-d", self.admin_dsn(dbname), "-f", str(path)]
        proc = subprocess.run(
            cmd, check=False, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL
        )
        if proc.returncode != 0:
            raise RuntimeError(f"psql {path.name} failed: {proc.stderr.strip()}")

    def bootstrap_roles(self) -> None:
        self.psql_file(
            BOOTSTRAP_ROLES_SQL,
            {
                "owner_pw": TEST_PASSWORDS["dwaar_owner"],
                "app_pw": TEST_PASSWORDS["dwaar_app"],
                "worker_pw": TEST_PASSWORDS["dwaar_worker"],
            },
        )

    # ---------------------------------------------------------------- databases

    def create_bare_database(self, name: str) -> None:
        """Empty database owned by dwaar_owner with extensions and role grants (create_database.sql)."""
        self.psql_file(CREATE_DATABASE_SQL, {"dbname": name})
        self._created.append(name)

    def clone_database(self, name: str, template: str) -> None:
        with self.admin_conn() as conn:
            conn.execute(
                sql.SQL("CREATE DATABASE {} TEMPLATE {} OWNER dwaar_owner").format(
                    sql.Identifier(name), sql.Identifier(template)
                )
            )
            self._created.append(name)
            conn.execute(
                sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(name))
            )
            conn.execute(
                sql.SQL(
                    "GRANT CONNECT ON DATABASE {} TO dwaar_owner, dwaar_app, dwaar_worker"
                ).format(sql.Identifier(name))
            )

    def set_allow_connections(self, name: str, allow: bool) -> None:
        with self.admin_conn() as conn:
            conn.execute(
                sql.SQL("ALTER DATABASE {} ALLOW_CONNECTIONS {}").format(
                    sql.Identifier(name), sql.SQL("true" if allow else "false")
                )
            )

    def drop_database(self, name: str) -> None:
        with contextlib.suppress(Exception), self.admin_conn() as conn:
            conn.execute(
                sql.SQL("ALTER DATABASE {} ALLOW_CONNECTIONS true").format(sql.Identifier(name))
            )
        with self.admin_conn() as conn:
            conn.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )
        if name in self._created:
            self._created.remove(name)

    def handle_for(self, name: str) -> DbHandle:
        return DbHandle(
            name=name,
            admin_dsn=self.admin_dsn(name),
            owner_dsn=self.dsn("dwaar_owner", name),
            app_dsn=self.dsn("dwaar_app", name),
            worker_dsn=self.dsn("dwaar_worker", name),
        )

    def cleanup(self) -> None:
        for name in list(self._created):
            with contextlib.suppress(Exception):
                self.drop_database(name)


def _connect_external(url: str) -> PgServer:
    server = PgServer(admin_url=url, external=True)
    with server.admin_conn() as conn:
        row = conn.execute("SHOW server_version").fetchone()
        server.version = str(row[0]) if row else "unknown"
    return server


@pytest.fixture(scope="session")
def pg_server() -> Iterator[PgServer]:
    """PostgreSQL for the whole session.

    `DWAAR_TEST_PG_ADMIN_URL` (superuser URL, e.g. a CI service container) is used as-is;
    otherwise a private ephemeral cluster is started and always torn down.
    """
    external_url = os.environ.get("DWAAR_TEST_PG_ADMIN_URL")
    cluster: PgCluster | None = None
    previous_term = signal.getsignal(signal.SIGTERM)
    server: PgServer | None = None
    try:
        if external_url:
            server = _connect_external(external_url)
            RUN_INFO["pg_mode"] = "external"
        else:
            find_pg_bin()  # fail early with a clear message
            cluster = PgCluster.create()
            if previous_term == signal.SIG_DFL:
                signal.signal(signal.SIGTERM, _raise_exit)
            server = PgServer(admin_url=cluster.admin_url, external=False, cluster=cluster)
            with server.admin_conn() as conn:
                row = conn.execute("SHOW server_version").fetchone()
                server.version = str(row[0]) if row else "unknown"
            RUN_INFO["pg_mode"] = "ephemeral"
        RUN_INFO["postgres"] = server.version
        server.bootstrap_roles()
        yield server
    finally:
        if server is not None:
            with contextlib.suppress(Exception):
                server.cleanup()
        if cluster is not None:
            cluster.stop()
            if signal.getsignal(signal.SIGTERM) is _raise_exit:
                signal.signal(signal.SIGTERM, previous_term)


def _raise_exit(signum: int, frame: object) -> None:
    raise SystemExit(128 + signum)


def _token() -> str:
    return uuid.uuid4().hex[:10]


@pytest.fixture(scope="session")
def bare_template_db(pg_server: PgServer) -> str:
    """Template database with extensions and grants but no application schema."""
    name = f"dwaar_bare_{_token()}"
    pg_server.create_bare_database(name)
    pg_server.set_allow_connections(name, False)
    return name


@pytest.fixture(scope="session")
def template_db(pg_server: PgServer) -> str:
    """Template database with all migrations applied (as `dwaar_owner`).

    Skips (with a clear message) while `dwaar_api.core.migrate` does not exist yet.
    """
    try:
        migrate = importlib.import_module("dwaar_api.core.migrate")
    except ModuleNotFoundError as exc:
        if exc.name in {"dwaar_api", "dwaar_api.core", "dwaar_api.core.migrate"}:
            pytest.skip(
                "dwaar_api.core.migrate is not available yet: DB-backed tests skip until the "
                "API core step provides run_migrations(owner_dsn)"
            )
        raise
    runner = getattr(migrate, "run_migrations", None)
    if runner is None:
        pytest.fail("dwaar_api.core.migrate has no run_migrations(owner_dsn)")
    name = f"dwaar_tpl_{_token()}"
    pg_server.create_bare_database(name)
    runner(pg_server.dsn("dwaar_owner", name))
    pg_server.set_allow_connections(name, False)
    return name


def _clone(pg_server: PgServer, template: str) -> Iterator[DbHandle]:
    name = f"dwaar_t_{_token()}"
    pg_server.clone_database(name, template)
    try:
        yield pg_server.handle_for(name)
    finally:
        pg_server.drop_database(name)


@pytest.fixture
def db(pg_server: PgServer, template_db: str) -> Iterator[DbHandle]:
    """Function-scoped clone of the migrated template. Dropped (FORCE) afterwards."""
    yield from _clone(pg_server, template_db)


@pytest.fixture
def bare_db(pg_server: PgServer, bare_template_db: str) -> Iterator[DbHandle]:
    """Function-scoped clone of the bare template (no migrations); used by harness self-tests."""
    yield from _clone(pg_server, bare_template_db)
