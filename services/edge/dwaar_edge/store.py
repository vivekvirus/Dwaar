"""Encrypted SQLite store (WAL, synchronous=FULL, single writer process).

REQ: EDGE-01 (SQLite WAL with synchronous=FULL, encrypted sensitive fields, backups, one process owns writes,
never on a network share), EDGE-02 (event, local projection and outbox persist in ONE transaction before any
success is shown), EDGE-09 (no inbound ports: nothing here listens), D-12.

Design notes
* One process owns the file: an exclusive ``flock`` on ``<db>.lock`` is taken at open and held until close. A
  second process fails fast with ``StoreLockedError``. Terminals never open the file; they use the local API.
* One connection, serialised by an RLock. ``transaction()`` is re-entrant (the outermost call commits).
* Sensitive columns are sealed with the AES-256-GCM envelope from ``dwaar_common.crypto``; the additional
  authenticated data binds each value to society, table, column and row so a value cannot be moved.
* Startup runs the migrations (checksummed, in order), ``PRAGMA integrity_check`` and the invariants a torn
  write would break (outbox sequence never behind the device counter, pragmas actually in force).
* ``fsync`` really reaching stable media cannot be proven in software: ``fsync_probe`` measures latency so an
  installer can notice an implausibly fast (cached) device. Real verification needs the actual hardware (EDGE-01).
"""

# REQ: EDGE-01, EDGE-02, EDGE-09, NFR-09

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from dwaar_common.crypto import EnvelopeCipher, KeyRing, build_aad
from dwaar_common.timeutil import format_iso_utc

from .errors import MigrationError, StoreCorruptError, StoreLockedError

SCHEMA: Final[tuple[tuple[int, str, str], ...]] = (
    (
        1,
        "base",
        """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE outbox (
    seq INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    entity_version INTEGER NOT NULL,
    occurred_at TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    wire_enc TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'acked', 'quarantined', 'rejected')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT,
    acked_at TEXT,
    reason TEXT
);
CREATE INDEX outbox_state_idx ON outbox (state, seq);

CREATE TABLE policy_snapshots (
    seq INTEGER PRIMARY KEY,
    issued_at TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    received_at TEXT NOT NULL,
    issuer_key_id TEXT NOT NULL,
    blob_enc TEXT NOT NULL
);
CREATE TABLE known_revocations (ref TEXT PRIMARY KEY, version INTEGER NOT NULL);
CREATE TABLE revocation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_seq INTEGER NOT NULL,
    ref TEXT NOT NULL,
    version INTEGER NOT NULL
);

CREATE TABLE pass_uses (
    id TEXT PRIMARY KEY,
    invitation_id TEXT NOT NULL,
    gate_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('held', 'consumed', 'released')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    movement_id TEXT
);
CREATE INDEX pass_uses_inv_idx ON pass_uses (invitation_id, state);
CREATE TABLE quota_escrow (
    invitation_id TEXT NOT NULL,
    gate_id TEXT NOT NULL,
    allocated INTEGER NOT NULL CHECK (allocated >= 0),
    PRIMARY KEY (invitation_id, gate_id)
);

CREATE TABLE movements (
    entity_id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('inside', 'exited')),
    gate_id TEXT NOT NULL,
    lane_id TEXT,
    credential_kind TEXT NOT NULL,
    decision_source TEXT NOT NULL,
    invitation_id TEXT,
    alias_enc TEXT,
    entered_at TEXT,
    entered_uncertainty_ms INTEGER,
    exited_at TEXT,
    exit_basis TEXT,
    version INTEGER NOT NULL,
    review INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX movements_state_idx ON movements (state);

CREATE TABLE pending_items (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'resolved', 'expired', 'cancelled')),
    gate_id TEXT NOT NULL,
    lane_id TEXT,
    reason_code TEXT NOT NULL,
    requires_role TEXT NOT NULL CHECK (requires_role IN ('guard', 'supervisor')),
    detail_enc TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    resolved_at TEXT,
    resolution TEXT
);
CREATE INDEX pending_state_idx ON pending_items (state, created_at);

CREATE TABLE decision_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    device_id TEXT NOT NULL,
    gate_id TEXT NOT NULL,
    lane_id TEXT NOT NULL,
    credential_kind TEXT NOT NULL,
    outcome TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    policy_seq INTEGER,
    clock_uncertainty_ms INTEGER NOT NULL,
    review INTEGER NOT NULL,
    evidence_enc TEXT
);

CREATE TABLE overrides (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    supervisor_ref TEXT NOT NULL,
    gate_id TEXT,
    reason_enc TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE review_items (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    entity_id TEXT,
    detail_enc TEXT,
    created_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closed'))
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    object TEXT,
    detail TEXT
);
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TABLE client_actions (
    client_action_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE lan_feed (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    kind TEXT NOT NULL,
    gate_id TEXT,
    body TEXT NOT NULL
);

CREATE TABLE terminal_state (
    device_id TEXT PRIMARY KEY,
    last_seen TEXT NOT NULL,
    acked_policy_seq INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE terminal_tokens (
    jti TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    role TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE TABLE terminal_observations (
    device_id TEXT NOT NULL,
    tseq INTEGER NOT NULL,
    event_id TEXT NOT NULL,
    PRIMARY KEY (device_id, tseq)
);
""",
    ),
)

_BUSY_TIMEOUT_MS: Final = 5000


class FieldCipher:
    """Seals sensitive column values; AAD binds society, table, column and row id."""

    def __init__(self, keyring: KeyRing, society_id: uuid.UUID) -> None:
        self._cipher = EnvelopeCipher(keyring)
        self._society = society_id

    def _aad(self, table: str, column: str, row_id: object) -> bytes:
        return build_aad(self._society, table, column, row_id)

    def seal(self, table: str, column: str, row_id: object, plaintext: str) -> str:
        return self._cipher.encrypt(plaintext, self._aad(table, column, row_id))

    def open(self, table: str, column: str, row_id: object, token: str) -> str:
        return self._cipher.decrypt(token, self._aad(table, column, row_id))

    def seal_json(self, table: str, column: str, row_id: object, value: Any) -> str:
        return self.seal(
            table, column, row_id, json.dumps(value, separators=(",", ":"), sort_keys=True)
        )

    def open_json(self, table: str, column: str, row_id: object, token: str) -> Any:
        return json.loads(self.open(table, column, row_id, token))


def iso(value: datetime) -> str:
    return format_iso_utc(value)


class EdgeStore:
    """The one SQLite file of the gateway."""

    def __init__(
        self,
        path: Path,
        *,
        keyring: KeyRing,
        society_id: uuid.UUID,
        device_id: uuid.UUID,
        full_integrity_on_open: bool = True,
    ) -> None:
        self.path = Path(path)
        self.society_id = society_id
        self.device_id = device_id
        self.cipher = FieldCipher(keyring, society_id)
        self._full_integrity = full_integrity_on_open
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._lock_fd: int | None = None
        self._depth = 0
        # Test seam: called with a label at named points inside a transaction (crash tests SIGKILL here).
        self.crash_hook: Callable[[str], None] | None = None

    # ---- lifecycle ---------------------------------------------------------------------------
    def open(self) -> EdgeStore:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if str(self.path.resolve()).startswith(("//", "\\\\")):
            raise StoreCorruptError("network paths are prohibited for the edge database (EDGE-01)")
        fd = os.open(str(self.path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise StoreLockedError("another process owns the edge database") from None
        self._lock_fd = fd
        try:
            conn = sqlite3.connect(
                str(self.path),
                isolation_level=None,
                check_same_thread=False,
                timeout=_BUSY_TIMEOUT_MS / 1000,
            )
            conn.row_factory = sqlite3.Row
            self._conn = conn
            self._configure(conn)
            self._migrate(conn)
            self._startup_checks(conn)
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None
            if self._lock_fd is not None:
                os.close(self._lock_fd)  # releases the flock
                self._lock_fd = None

    def __enter__(self) -> EdgeStore:
        return self.open()

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("store is not open")
        return self._conn

    def _configure(self, conn: sqlite3.Connection) -> None:
        mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA secure_delete=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        sync = conn.execute("PRAGMA synchronous").fetchone()[0]
        if str(mode).lower() != "wal" or sync != 2:
            raise StoreCorruptError(
                f"durability pragmas not in force (journal_mode={mode}, synchronous={sync})"
            )

    def pragmas(self) -> dict[str, Any]:
        with self._lock:
            return {
                "journal_mode": self.conn.execute("PRAGMA journal_mode").fetchone()[0],
                "synchronous": self.conn.execute("PRAGMA synchronous").fetchone()[0],  # 2 == FULL
                "foreign_keys": self.conn.execute("PRAGMA foreign_keys").fetchone()[0],
            }

    # ---- migrations --------------------------------------------------------------------------
    def _migrate(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)"
        )
        applied = {
            int(r["version"]): str(r["checksum"])
            for r in conn.execute("SELECT version, checksum FROM schema_migrations")
        }
        for version, name, sql in SCHEMA:
            checksum = hashlib.sha256(sql.encode()).hexdigest()
            if version in applied:
                if applied[version] != checksum:
                    raise MigrationError(
                        f"migration {version} {name} was edited after it was applied"
                    )
                continue
            if applied and version < max(applied):
                raise MigrationError(f"migration {version} is older than the applied head")
            try:
                conn.execute("BEGIN IMMEDIATE")
                for statement in _split_sql(sql):
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                    (version, name, checksum, iso(datetime.now(UTC))),
                )
                conn.execute("COMMIT")
            except sqlite3.Error as exc:
                conn.execute("ROLLBACK") if conn.in_transaction else None
                raise MigrationError(f"migration {version} {name} failed: {exc}") from exc
        unknown = set(applied) - {v for v, _n, _s in SCHEMA}
        if unknown:
            raise MigrationError(f"database is from a newer gateway (migrations {sorted(unknown)})")

    # ---- startup checks ----------------------------------------------------------------------
    def integrity_problems(self, *, full: bool) -> list[str]:
        with self._lock:
            pragma = "integrity_check" if full else "quick_check"
            problems = [str(r[0]) for r in self.conn.execute(f"PRAGMA {pragma}")]
            problems = [p for p in problems if p != "ok"]
            problems += [
                f"foreign key violation in {r[0]}"
                for r in self.conn.execute("PRAGMA foreign_key_check")
            ]
            last_seq = (
                int(self.conn.execute("SELECT value FROM meta WHERE key='last_seq'").fetchone()[0])
                if (self.conn.execute("SELECT 1 FROM meta WHERE key='last_seq'").fetchone())
                else 0
            )
            max_row = self.conn.execute("SELECT COALESCE(MAX(seq), 0) FROM outbox").fetchone()[0]
            if max_row > last_seq:
                problems.append(
                    f"outbox seq {max_row} is ahead of the device counter {last_seq} (torn write)"
                )
            return problems

    def _startup_checks(self, conn: sqlite3.Connection) -> None:
        with self._lock:
            conn.execute("BEGIN IMMEDIATE")
            try:
                for key, val in (
                    ("society_id", str(self.society_id)),
                    ("device_id", str(self.device_id)),
                ):
                    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
                    if row is None:
                        conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)", (key, val))
                    elif row[0] != val:
                        raise StoreCorruptError(f"database belongs to another {key}")
                if conn.execute("SELECT 1 FROM meta WHERE key='last_seq'").fetchone() is None:
                    conn.execute("INSERT INTO meta (key, value) VALUES ('last_seq', '0')")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        problems = self.integrity_problems(full=self._full_integrity)
        if problems:
            raise StoreCorruptError("integrity check failed: " + "; ".join(problems[:3]))

    # ---- transactions ------------------------------------------------------------------------
    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """BEGIN IMMEDIATE ... COMMIT. Re-entrant. Success may be shown to a caller only AFTER this exits."""
        with self._lock:
            conn = self.conn
            outer = self._depth == 0
            if outer:
                conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield conn
            except BaseException:
                self._depth -= 1
                if outer:
                    conn.execute("ROLLBACK")
                raise
            self._depth -= 1
            if outer:
                conn.execute("COMMIT")

    def crash_point(self, label: str) -> None:
        if self.crash_hook is not None:
            self.crash_hook(label)

    def one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self.conn.execute(sql, params).fetchone()  # type: ignore[no-any-return]

    def all(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    # ---- meta --------------------------------------------------------------------------------
    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self.one("SELECT value FROM meta WHERE key=?", (key,))
        return default if row is None else str(row[0])

    def set_meta(self, key: str, value: str) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def audit(
        self, actor: str, action: str, obj: str | None, detail: dict[str, Any] | None, at: datetime
    ) -> None:
        """Append an audit row. Must be called inside ``transaction()`` so it commits with the change."""
        self.conn.execute(
            "INSERT INTO audit_log (at, actor, action, object, detail) VALUES (?, ?, ?, ?, ?)",
            (
                iso(at),
                actor,
                action,
                obj,
                json.dumps(detail or {}, sort_keys=True, separators=(",", ":")),
            ),
        )

    # ---- backup ------------------------------------------------------------------------------
    def backup(self, dest: Path) -> Path:
        """Consistent online copy (sqlite backup API), fsynced, then integrity-checked. Fields stay encrypted."""
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".partial")
        tmp.unlink(missing_ok=True)
        with self._lock:
            target = sqlite3.connect(str(tmp))
            try:
                self.conn.backup(target)
            finally:
                target.close()
        fd = os.open(str(tmp), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        check = sqlite3.connect(str(tmp))
        try:
            result = check.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            check.close()
        if result != "ok":
            tmp.unlink(missing_ok=True)
            raise StoreCorruptError("backup copy failed its integrity check")
        os.replace(tmp, dest)
        return dest

    def fsync_probe(self, rounds: int = 20) -> dict[str, float]:
        """Latency of write+fsync on the volume that holds the database (EDGE-01 hardware check input).

        This does NOT prove durability; it only exposes volumes where fsync returns implausibly fast.
        """
        probe = self.path.parent / f".fsync-probe-{uuid.uuid4().hex}"
        samples: list[float] = []
        try:
            fd = os.open(str(probe), os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                for i in range(rounds):
                    t0 = time.perf_counter()
                    os.write(fd, b"x" * 4096 + str(i).encode())
                    os.fsync(fd)
                    samples.append((time.perf_counter() - t0) * 1000)
            finally:
                os.close(fd)
        finally:
            probe.unlink(missing_ok=True)
        samples.sort()
        return {"p50_ms": samples[len(samples) // 2], "max_ms": samples[-1]}


def restore_backup(backup: Path, dest: Path) -> None:
    """Copy a verified backup into place (the gateway must be stopped)."""
    check = sqlite3.connect(str(backup))
    try:
        if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise StoreCorruptError("backup is not intact")
    finally:
        check.close()
    for suffix in ("", "-wal", "-shm"):
        Path(str(dest) + suffix).unlink(missing_ok=True)
    src = sqlite3.connect(str(backup))
    dst = sqlite3.connect(str(dest))
    try:
        src.backup(dst)
    finally:
        src.close()
        dst.close()


def _split_sql(script: str) -> list[str]:
    """Split a script into statements (triggers contain ';' inside BEGIN..END)."""
    statements: list[str] = []
    buf: list[str] = []
    in_trigger = False
    for line in script.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        buf.append(line)
        upper = stripped.upper()
        if upper.startswith("CREATE TRIGGER"):
            in_trigger = True
        if in_trigger:
            if upper.endswith("END;"):
                statements.append("\n".join(buf))
                buf, in_trigger = [], False
        elif stripped.endswith(";"):
            statements.append("\n".join(buf))
            buf = []
    if buf:
        statements.append("\n".join(buf))
    return statements
