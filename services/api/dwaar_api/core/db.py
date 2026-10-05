"""Database access: engines per role and the per-transaction request context.

REQ: ARCH-03 (restricted DB role; transaction-scoped society and user context drives RLS), INV-01.

* ``Database`` owns one engine for the ``dwaar_app`` role (the API) and, optionally, one for
  ``dwaar_worker``. There is deliberately no owner/superuser engine here: only the migration CLI
  (``dwaar_api.core.migrate``) ever connects as ``dwaar_owner``.
* Every pooled connection is pinned at connect time (startup ``options``: ``row_security=on``,
  ``default_transaction_read_only=off``, ``lock_timeout``, ``statement_timeout``, ``search_path``). Startup options
  outrank role-level defaults, so a statement such as ``ALTER ROLE dwaar_app SET row_security = off`` (any role may
  alter its OWN settings) cannot persistently poison the API (R2-02). The pool reset is ``DISCARD ALL``: session
  advisory locks, LISTEN registrations, temp tables and every ``SET`` die with the request (R2-11).
* Every NEW connection re-checks its role: a superuser or BYPASSRLS role is refused on connect, whatever the role is
  called and whether or not the boot-time check could reach the database (ARCH-03, R2-03).
* ``transaction()`` opens ONE transaction and sets the request context with
  ``set_config(name, value, true)`` (transaction-local), so the context can never leak to the next
  user of a pooled connection. A missing society means RLS returns zero rows.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Connection, Engine, create_engine, event, text
from sqlalchemy.engine import make_url

from .config import ConfigError, Settings

_ROLE_NAME: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}\Z")  # \Z: `$` accepts a trailing newline
SETTING_SOCIETY: Final = "app.society_id"
SETTING_PERSON: Final = "app.person_id"
SETTING_ROLE: Final = "app.actor_role"
SETTING_REQUEST: Final = "app.request_id"


@dataclass(frozen=True)
class RequestContext:
    """Who is acting, for which society, in which request. All ids come from server-side state."""

    society_id: uuid.UUID | None = None
    person_id: uuid.UUID | None = None
    actor_role: str | None = None
    request_id: uuid.UUID | None = None

    def __post_init__(self) -> None:
        for name in ("society_id", "person_id", "request_id"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, uuid.UUID):
                raise TypeError(f"RequestContext.{name} must be a uuid.UUID")
        if self.actor_role is not None and not _ROLE_NAME.match(self.actor_role):
            raise ValueError("RequestContext.actor_role must match ^[a-z][a-z0-9_]{0,63}$")

    def _pairs(self) -> dict[str, object | None]:
        return {
            SETTING_SOCIETY: self.society_id,
            SETTING_PERSON: self.person_id,
            SETTING_ROLE: self.actor_role,
            SETTING_REQUEST: self.request_id,
        }

    def settings(self) -> dict[str, str]:
        """GUC name -> value for every field that is set."""
        return {name: str(value) for name, value in self._pairs().items() if value is not None}

    def all_settings(self) -> dict[str, str]:
        """All four GUCs; a field that is not set is the empty string (never "unchanged").

        Writing every GUC on every transaction means a value planted at SESSION level on a pooled
        connection (a bug or SQL injection running ``SET app.society_id = ...``) is always shadowed
        by this transaction's own, society-less, values.
        """
        return {name: "" if value is None else str(value) for name, value in self._pairs().items()}

    @property
    def actor_ref(self) -> str:
        """Stable reference for events: ``person:<uuid>`` or ``system``."""
        return f"person:{self.person_id}" if self.person_id else "system"

    def with_society(self, society_id: uuid.UUID) -> RequestContext:
        return RequestContext(society_id, self.person_id, self.actor_role, self.request_id)


def apply_context(conn: Connection, ctx: RequestContext | None) -> None:
    """Set the transaction-local context. Must run inside the transaction it is meant for.

    ``None`` means "no society, no person": all four values are still written (empty), so the
    transaction can never inherit state from the pooled connection (INV-01: missing context = zero rows).
    """
    for name, value in (ctx or RequestContext()).all_settings().items():
        conn.execute(text("SELECT set_config(:name, :value, true)"), {"name": name, "value": value})


def to_sqlalchemy_url(url: str) -> str:
    """Accept postgresql:// or postgres:// URLs and force the psycopg 3 driver."""
    parsed = make_url(url)
    if parsed.get_backend_name() not in {"postgresql", "postgres"}:
        raise ConfigError("database URL must be a PostgreSQL URL")
    return parsed.set(drivername="postgresql+psycopg").render_as_string(hide_password=False)


def _reset_session(dbapi_connection: Any, connection_record: Any, reset_state: Any) -> None:
    """Pool "reset": roll back, then ``DISCARD ALL`` so NOTHING survives into the next borrower.

    ``RESET ALL`` alone leaves session-level advisory locks, ``LISTEN`` registrations, temp tables and prepared
    statements behind: a lock taken in one request would stay held by the pooled connection. ``DISCARD ALL``
    releases all of them and also performs ``RESET ALL`` / ``RESET SESSION AUTHORIZATION``. It cannot run inside a
    transaction block, so autocommit is switched on around it. Server-side prepared statements are disabled on the
    engine (``prepare_threshold=None``), so the driver never holds a handle that ``DISCARD`` just dropped.
    """
    dbapi_connection.rollback()
    previous = dbapi_connection.autocommit
    dbapi_connection.autocommit = True
    try:
        with dbapi_connection.cursor() as cursor:
            cursor.execute("DISCARD ALL")
    finally:
        dbapi_connection.autocommit = previous


def check_connection_role(dbapi_connection: Any, connection_record: Any) -> None:
    """Engine ``connect`` hook: refuse a superuser or BYPASSRLS role on EVERY new connection (ARCH-03).

    The config guard only knows a few role NAMES and the boot-time check is skipped when the database is down at
    boot; this check cannot be skipped because no connection reaches a request without passing it.
    """
    try:
        with dbapi_connection.cursor() as cursor:
            cursor.execute(
                "SELECT r.rolsuper OR r.rolbypassrls, current_setting('is_superuser') = 'on'"
                " FROM pg_roles r WHERE r.rolname = current_user"
            )
            row = cursor.fetchone()
        dbapi_connection.rollback()
    except Exception:
        dbapi_connection.close()
        raise
    if row is None or row[0] or row[1]:
        dbapi_connection.close()
        raise ConfigError("the database role must not be a superuser or BYPASSRLS role")


def pinned_options(statement_timeout_ms: int, lock_timeout_ms: int) -> str:
    """Startup ``options`` that role-level ``ALTER ROLE ... SET`` defaults cannot override."""
    pins = {
        "statement_timeout": int(statement_timeout_ms),
        "lock_timeout": int(lock_timeout_ms),
        "idle_in_transaction_session_timeout": 60_000,
        "row_security": "on",
        "default_transaction_read_only": "off",
        "search_path": "public",
    }
    return " ".join(f"-c {name}={value}" for name, value in pins.items())


def make_engine(
    url: str,
    *,
    application_name: str,
    pool_size: int = 5,
    max_overflow: int = 10,
    statement_timeout_ms: int = 30_000,
    lock_timeout_ms: int = 15_000,
) -> Engine:
    engine = create_engine(
        to_sqlalchemy_url(url),
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=True,
        hide_parameters=True,  # bound values (names, phones) never appear in exception text or logs
        pool_recycle=1800,
        pool_reset_on_return=None,  # replaced by _reset_session (rollback + DISCARD ALL)
        connect_args={
            "application_name": application_name,
            "options": pinned_options(statement_timeout_ms, lock_timeout_ms),
            "prepare_threshold": None,  # DISCARD ALL drops server-side prepared statements
        },
    )
    event.listen(engine, "connect", check_connection_role)
    event.listen(engine, "reset", _reset_session)
    return engine


@contextmanager
def transaction(engine: Engine, ctx: RequestContext | None = None) -> Iterator[Connection]:
    """One transaction with the request context applied; commit on success, roll back on any error."""
    with engine.connect() as conn, conn.begin():
        apply_context(conn, ctx)
        yield conn


class Database:
    """Engines for the restricted runtime roles."""

    def __init__(
        self,
        app_url: str,
        worker_url: str | None = None,
        *,
        pool_size: int = 5,
        max_overflow: int = 10,
        statement_timeout_ms: int = 30_000,
        lock_timeout_ms: int = 15_000,
    ) -> None:
        self._app = make_engine(
            app_url,
            application_name="dwaar-api",
            pool_size=pool_size,
            max_overflow=max_overflow,
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
        )
        self._worker: Engine | None = (
            make_engine(
                worker_url,
                application_name="dwaar-worker",
                pool_size=pool_size,
                max_overflow=max_overflow,
                statement_timeout_ms=statement_timeout_ms,
                lock_timeout_ms=lock_timeout_ms,
            )
            if worker_url
            else None
        )

    @classmethod
    def from_settings(cls, settings: Settings) -> Database:
        if settings.database_url is None:
            raise ConfigError("DWAAR_DATABASE_URL is required")
        return cls(
            settings.database_url.get_secret_value(),
            settings.database_worker_url.get_secret_value()
            if settings.database_worker_url
            else None,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            statement_timeout_ms=settings.db_statement_timeout_ms,
            lock_timeout_ms=settings.db_lock_timeout_ms,
        )

    @property
    def app_engine(self) -> Engine:
        return self._app

    @property
    def worker_engine(self) -> Engine:
        if self._worker is None:
            raise ConfigError("no worker database URL configured")
        return self._worker

    def app_tx(self, ctx: RequestContext | None = None) -> AbstractContextManager[Connection]:
        return transaction(self._app, ctx)

    def worker_tx(self, ctx: RequestContext | None = None) -> AbstractContextManager[Connection]:
        return transaction(self.worker_engine, ctx)

    def ping(self) -> None:
        """Raise if the application role cannot run a trivial query."""
        with self._app.connect() as conn:
            conn.execute(text("SELECT 1"))
            conn.rollback()

    def assert_restricted_role(self) -> None:
        """Refuse to run as a superuser or BYPASSRLS role (ARCH-03). Raises ConfigError."""
        for label, engine in (("application", self._app), ("worker", self._worker)):
            if engine is None:
                continue
            with engine.connect() as conn:
                row = conn.execute(
                    text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
                ).one()
                conn.rollback()
            if row[0] or row[1]:
                raise ConfigError(
                    f"the {label} database role must not be a superuser or BYPASSRLS role"
                )

    def role_default_settings(self) -> dict[str, list[str]]:
        """Role-level defaults (``pg_db_role_setting``) found for the runtime roles, by engine label.

        Runtime roles carry NO role-level defaults: every setting that matters is pinned in the connection options.
        Anything listed here is drift (possibly a planted ``ALTER ROLE <self> SET ...``) and fails readiness.
        """
        drift: dict[str, list[str]] = {}
        for label, engine in (("application", self._app), ("worker", self._worker)):
            if engine is None:
                continue
            with engine.connect() as conn:
                rows = conn.execute(
                    text(
                        "SELECT s.setconfig FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole"
                        " WHERE r.rolname = current_user"
                    )
                ).all()
                conn.rollback()
            names = sorted({str(item).split("=", 1)[0] for row in rows for item in (row[0] or [])})
            if names:
                drift[label] = names
        return drift

    def dispose(self) -> None:
        self._app.dispose()
        if self._worker is not None:
            self._worker.dispose()
