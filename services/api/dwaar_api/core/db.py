"""Database access: engines per role and the per-transaction request context.

REQ: ARCH-03 (restricted DB role; transaction-scoped society and user context drives RLS), INV-01.

* ``Database`` owns one engine for the ``dwaar_app`` role (the API) and, optionally, one for
  ``dwaar_worker``. There is deliberately no owner/superuser engine here: only the migration CLI
  (``dwaar_api.core.migrate``) ever connects as ``dwaar_owner``.
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

_ROLE_NAME: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
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
    """Pool "reset": roll back, then RESET ALL so no session-level SET survives into the next borrower.

    Replaces the default rollback-only reset (``reset_on_return=None`` below). ``RESET ALL`` returns every
    run-time parameter, including custom ``app.*`` placeholders, to its connection default.
    """
    dbapi_connection.rollback()
    with dbapi_connection.cursor() as cursor:
        cursor.execute("RESET ALL")
    dbapi_connection.commit()


def make_engine(
    url: str,
    *,
    application_name: str,
    pool_size: int = 5,
    max_overflow: int = 10,
    statement_timeout_ms: int = 30_000,
) -> Engine:
    options = f"-c statement_timeout={int(statement_timeout_ms)} -c idle_in_transaction_session_timeout=60000"
    engine = create_engine(
        to_sqlalchemy_url(url),
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=True,
        hide_parameters=True,  # bound values (names, phones) never appear in exception text or logs
        pool_recycle=1800,
        pool_reset_on_return=None,  # replaced by _reset_session (rollback + RESET ALL)
        connect_args={"application_name": application_name, "options": options},
    )
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
    ) -> None:
        self._app = make_engine(
            app_url,
            application_name="dwaar-api",
            pool_size=pool_size,
            max_overflow=max_overflow,
            statement_timeout_ms=statement_timeout_ms,
        )
        self._worker: Engine | None = (
            make_engine(
                worker_url,
                application_name="dwaar-worker",
                pool_size=pool_size,
                max_overflow=max_overflow,
                statement_timeout_ms=statement_timeout_ms,
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

    def dispose(self) -> None:
        self._app.dispose()
        if self._worker is not None:
            self._worker.dispose()
