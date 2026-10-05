"""Plain, ordered, checksummed SQL migrations.

REQ: RUN-01 (expand and contract; never destructive on posted data), ADR-0002 (plain SQL files),
ADR-0004 (roles come from infra/db/bootstrap_roles.sql; objects are owned by ``dwaar_owner``).

* Files: ``services/api/migrations/NNNN_name.sql`` (4-digit version, unique, any gaps allowed).
  Number ranges per area are listed in docs/BUILD_BRIEF.md.
* Ledger: table ``schema_migrations`` (version, name, sha256 checksum, applied_at, applied_by).
* Tamper detection: an applied file whose checksum changed, or that disappeared, is a hard error and
  NOTHING further is applied. Fix forward with a new migration, never by editing an applied one.
* Concurrency: a second connection holds an ACCESS EXCLUSIVE lock on the owner-only table
  ``dwaar_migration_lock`` for the whole run; the second runner waits, then finds everything applied and does
  nothing. It is a TABLE lock, not an advisory lock: advisory lock keys are one global namespace that every
  database role can take (``dwaar_app`` could hold the key and block every deploy), whereas the runtime roles
  have no privilege on this table at all (not even LOCK).
* Atomicity: every migration runs in its own transaction together with its ledger row. Migration files
  must not contain their own BEGIN/COMMIT.
* Late-arriving versions (a lower number than the highest applied one, added by a parallel branch)
  are applied in version order; the ledger is not required to be a prefix.

CLI:  ``python -m dwaar_api.core.migrate up|status [--dsn DSN]``  (DSN defaults to DWAAR_DATABASE_OWNER_URL).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import re
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

import psycopg

MIGRATIONS_DIR: Final = Path(__file__).resolve().parents[2] / "migrations"
_FILENAME: Final = re.compile(r"^(\d{4})_([a-z0-9][a-z0-9_]*)\.sql$")
# A statement that starts with one of these controls the transaction the runner wrapped around the file.
_TX_CONTROL: Final = re.compile(
    r"(?is)^\s*(begin|commit|rollback|abort|end|start\s+transaction|prepare\s+transaction"
    r"|commit\s+prepared|rollback\s+prepared)\b"
)
_DOLLAR_TAG: Final = re.compile(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$")
LOCK_TABLE: Final = "dwaar_migration_lock"
REQUIRED_ROLES: Final = ("dwaar_owner", "dwaar_app", "dwaar_worker")

LEDGER_DDL: Final = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version integer PRIMARY KEY CHECK (version > 0),
    name text NOT NULL,
    checksum text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    applied_at timestamptz NOT NULL DEFAULT now(),
    applied_by text NOT NULL DEFAULT current_user,
    execution_ms integer NOT NULL DEFAULT 0
)
"""


class MigrationError(Exception):
    """A migration cannot be applied or the ledger is inconsistent with the files."""


class MigrationTamperError(MigrationError):
    """An applied migration file was edited or removed."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path
    sql: str
    checksum: str

    @property
    def label(self) -> str:
        return f"{self.version:04d}_{self.name}"


@dataclass(frozen=True)
class MigrationStatus:
    version: int
    name: str
    state: str  # applied | pending | tampered | missing
    checksum: str | None = None


def checksum_of(sql_bytes: bytes) -> str:
    return hashlib.sha256(sql_bytes).hexdigest()


def _strip_literals(sql: str) -> str:
    """``sql`` with comments, quoted strings and dollar-quoted bodies blanked out (statement structure only).

    So a ``BEGIN`` inside a PL/pgSQL body or a string never counts as transaction control, while a
    ``...; COMMIT; ...`` smuggled onto one line does.
    """
    out: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j == -1 else j
        elif sql.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if sql.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif sql.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            out.append(" ")
        elif ch in ("'", '"'):
            backslash_escapes = ch == "'" and i > 0 and sql[i - 1] in "eE"  # E'...' strings
            j = i + 1
            while j < n:
                if backslash_escapes and sql[j] == "\\":
                    j += 2
                    continue
                if sql[j] == ch:
                    if sql.startswith(ch * 2, j):  # a doubled quote is an escaped quote
                        j += 2
                        continue
                    break
                j += 1
            out.append(ch + ch)
            i = j + 1
        elif ch == "$":
            after_identifier = i > 0 and (sql[i - 1].isalnum() or sql[i - 1] == "_")
            tag = None if after_identifier else _DOLLAR_TAG.match(sql, i)
            if tag is None:
                out.append(ch)
                i += 1
                continue
            end = sql.find(tag.group(0), tag.end())
            out.append("$$")
            i = n if end == -1 else end + len(tag.group(0))
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def has_transaction_control(sql: str) -> bool:
    """True if any top-level statement of ``sql`` is BEGIN/COMMIT/ROLLBACK/END/ABORT/START TRANSACTION ..."""
    return any(_TX_CONTROL.match(statement) for statement in _strip_literals(sql).split(";"))


def discover(directory: Path | None = None) -> list[Migration]:
    """Read and validate the migration files, ordered by version."""
    root = directory or MIGRATIONS_DIR
    if not root.is_dir():
        raise MigrationError(f"migrations directory not found: {root}")
    found: dict[int, Migration] = {}
    for path in sorted(root.iterdir()):
        if path.is_dir() or path.name.startswith("."):
            continue
        match = _FILENAME.match(path.name)
        if not match:
            raise MigrationError(
                f"bad migration file name {path.name!r} (expected NNNN_snake_case.sql)"
            )
        version = int(match.group(1))
        if version == 0:
            raise MigrationError(f"migration version must be > 0: {path.name}")
        if version in found:
            raise MigrationError(
                f"duplicate migration version {version:04d}: {found[version].path.name}, {path.name}"
            )
        raw = path.read_bytes()
        try:
            sql = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MigrationError(f"{path.name} is not valid UTF-8") from exc
        if not sql.strip():
            raise MigrationError(f"{path.name} is empty")
        if has_transaction_control(sql):
            raise MigrationError(
                f"{path.name} contains its own transaction control; the runner wraps each file in a transaction"
            )
        found[version] = Migration(version, match.group(2), path, sql, checksum_of(raw))
    return [found[v] for v in sorted(found)]


def _applied(conn: psycopg.Connection[Any]) -> dict[int, tuple[str, str]]:
    exists = conn.execute("SELECT to_regclass('public.schema_migrations') IS NOT NULL").fetchone()
    if not exists or not exists[0]:
        return {}
    rows = conn.execute("SELECT version, name, checksum FROM schema_migrations").fetchall()
    return {int(r[0]): (str(r[1]), str(r[2])) for r in rows}


def _verify(applied: dict[int, tuple[str, str]], migrations: Sequence[Migration]) -> None:
    by_version = {m.version: m for m in migrations}
    for version, (name, checksum) in sorted(applied.items()):
        local = by_version.get(version)
        if local is None:
            raise MigrationTamperError(
                f"applied migration {version:04d}_{name} is missing from the migrations directory"
            )
        if local.checksum != checksum:
            raise MigrationTamperError(
                f"applied migration {version:04d}_{name} was modified after it was applied "
                f"(recorded sha256 {checksum[:12]}..., file {local.checksum[:12]}...). "
                "Never edit an applied migration; add a new one."
            )
        if local.name != name:
            raise MigrationTamperError(
                f"applied migration {version:04d} was renamed ({name} -> {local.name})"
            )


def _check_roles(conn: psycopg.Connection[Any]) -> None:
    rows = conn.execute(
        "SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (list(REQUIRED_ROLES),)
    ).fetchall()
    missing = sorted(set(REQUIRED_ROLES) - {r[0] for r in rows})
    if missing:
        raise MigrationError(
            "database roles missing: "
            + ", ".join(missing)
            + " (run infra/db/bootstrap_roles.sql first)"
        )


def run_migrations(
    owner_dsn: str, migrations_dir: Path | None = None, *, target_version: int | None = None
) -> list[str]:
    """Apply all pending migrations as ``dwaar_owner``. Returns the labels applied by THIS call."""
    migrations = discover(migrations_dir)
    applied_now: list[str] = []
    conn = psycopg.connect(owner_dsn, autocommit=True)
    lock_conn = _hold_migration_lock(owner_dsn)
    try:
        try:
            _check_roles(conn)
            conn.execute(LEDGER_DDL)
            conn.execute("GRANT SELECT ON schema_migrations TO dwaar_app, dwaar_worker")
            applied = _applied(conn)
            _verify(applied, migrations)
            for migration in migrations:
                if migration.version in applied:
                    continue
                if target_version is not None and migration.version > target_version:
                    break
                _apply_one(conn, migration)
                applied_now.append(migration.label)
        finally:
            lock_conn.close()  # rolls back its transaction: the table lock is released
    finally:
        conn.close()
    return applied_now


def _hold_migration_lock(owner_dsn: str) -> psycopg.Connection[Any]:
    """Serialise runners: hold ACCESS EXCLUSIVE on the owner-only ``dwaar_migration_lock`` table on a SECOND
    connection (open transaction) until it is closed. Blocks while another runner holds it."""
    lock_conn = psycopg.connect(owner_dsn, autocommit=True)
    try:
        # two first-ever runners can race to create it; the loser simply uses the winner's table
        with contextlib.suppress(psycopg.errors.UniqueViolation, psycopg.errors.DuplicateTable):
            lock_conn.execute(
                f"CREATE TABLE IF NOT EXISTS {LOCK_TABLE} (id integer PRIMARY KEY CHECK (id = 1))"
            )
        lock_conn.execute(f"REVOKE ALL ON TABLE {LOCK_TABLE} FROM PUBLIC")
        lock_conn.autocommit = False
        lock_conn.execute(f"LOCK TABLE {LOCK_TABLE} IN ACCESS EXCLUSIVE MODE")
    except BaseException:
        lock_conn.close()
        raise
    return lock_conn


def _apply_one(conn: psycopg.Connection[Any], migration: Migration) -> None:
    started = time.monotonic()
    try:
        with conn.transaction():
            # No parameters => simple query protocol => the file may hold many statements.
            conn.execute(migration.sql)
            conn.execute(
                "INSERT INTO schema_migrations (version, name, checksum, execution_ms) VALUES (%s, %s, %s, %s)",
                (
                    migration.version,
                    migration.name,
                    migration.checksum,
                    int((time.monotonic() - started) * 1000),
                ),
            )
    except psycopg.Error as exc:
        detail = getattr(exc.diag, "message_primary", None) or type(exc).__name__
        raise MigrationError(
            f"migration {migration.label} failed and was rolled back: {detail}"
        ) from exc


def migration_status(owner_dsn: str, migrations_dir: Path | None = None) -> list[MigrationStatus]:
    """Read-only report. A tampered or missing applied migration is reported, not raised."""
    migrations = discover(migrations_dir)
    by_version = {m.version: m for m in migrations}
    with psycopg.connect(owner_dsn, autocommit=True) as conn:
        applied = _applied(conn)
    report: list[MigrationStatus] = []
    for migration in migrations:
        recorded = applied.get(migration.version)
        if recorded is None:
            report.append(MigrationStatus(migration.version, migration.name, "pending"))
        elif recorded[1] != migration.checksum or recorded[0] != migration.name:
            report.append(
                MigrationStatus(migration.version, migration.name, "tampered", recorded[1])
            )
        else:
            report.append(
                MigrationStatus(migration.version, migration.name, "applied", recorded[1])
            )
    for version, (name, checksum) in sorted(applied.items()):
        if version not in by_version:
            report.append(MigrationStatus(version, name, "missing", checksum))
    return sorted(report, key=lambda s: s.version)


@lru_cache(maxsize=1)
def shipped_versions() -> frozenset[int]:
    """Versions of the migration files shipped with this build (default directory)."""
    return frozenset(m.version for m in discover())


def _out(message: str) -> None:
    sys.stdout.write(message + "\n")


def _err(message: str) -> None:
    sys.stderr.write(message + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m dwaar_api.core.migrate",
        description=__doc__.split("\n")[0] if __doc__ else None,
    )
    parser.add_argument("command", choices=("up", "status"))
    parser.add_argument(
        "--dsn", default=None, help="owner DSN (default: $DWAAR_DATABASE_OWNER_URL)"
    )
    parser.add_argument(
        "--dir",
        default=None,
        type=Path,
        help="migrations directory (default: services/api/migrations)",
    )
    args = parser.parse_args(argv)
    dsn = args.dsn or os.environ.get("DWAAR_DATABASE_OWNER_URL")
    if not dsn:
        _err("error: no DSN (use --dsn or DWAAR_DATABASE_OWNER_URL)")
        return 2
    try:
        if args.command == "up":
            done = run_migrations(dsn, args.dir)
            _out(f"applied {len(done)} migration(s)" + (": " + ", ".join(done) if done else ""))
            return 0
        report = migration_status(dsn, args.dir)
    except MigrationError as exc:
        _err(f"error: {exc}")
        return 1
    except psycopg.Error as exc:
        _err(f"error: database unavailable ({type(exc).__name__})")
        return 1
    bad = False
    for item in report:
        _out(f"{item.version:04d}  {item.state:<9} {item.name}")
        bad = bad or item.state in ("tampered", "missing")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
