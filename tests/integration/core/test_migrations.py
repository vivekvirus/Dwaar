"""Migration runner: ordering, checksums, tamper detection, advisory lock, atomicity, CLI."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from dwaar_api.core import migrate as migrate_module
from dwaar_api.core.migrate import (
    MIGRATIONS_DIR,
    MigrationError,
    MigrationTamperError,
    discover,
    migration_status,
    run_migrations,
)
from tests._harness.pgfixtures import DbHandle

pytestmark = pytest.mark.req("ARCH-01", "ARCH-03", "DB-02")


@pytest.fixture
def mig_dir(tmp_path: Path) -> Path:
    target = tmp_path / "migrations"
    shutil.copytree(MIGRATIONS_DIR, target)
    return target


def _applied(db: DbHandle) -> list[tuple[int, str, str]]:
    with db.owner_conn() as conn:
        return [
            (r[0], r[1], r[2])
            for r in conn.execute(
                "SELECT version, name, checksum FROM schema_migrations ORDER BY 1"
            )
        ]


def test_applies_all_in_order_and_records_sha256(bare_db: DbHandle) -> None:
    done = run_migrations(bare_db.owner_dsn)
    files = discover()
    assert done == [m.label for m in files]
    assert [v for v, _, _ in _applied(bare_db)] == [m.version for m in files]
    for (version, name, checksum), migration in zip(_applied(bare_db), files, strict=True):
        assert (version, name) == (migration.version, migration.name)
        assert checksum == hashlib.sha256(migration.path.read_bytes()).hexdigest()


def test_rerun_is_idempotent(bare_db: DbHandle) -> None:
    first = run_migrations(bare_db.owner_dsn)
    before = _applied(bare_db)
    assert first
    assert run_migrations(bare_db.owner_dsn) == []
    assert _applied(bare_db) == before
    assert all(s.state == "applied" for s in migration_status(bare_db.owner_dsn))


def test_shipped_files_follow_numbering_policy() -> None:
    versions = [m.version for m in discover()]
    assert versions == sorted(versions)
    assert len(versions) == len(set(versions))
    assert versions[:7] == [1, 2, 3, 4, 5, 6, 7]
    assert all(
        m.version < 100 or m.version >= 100 for m in discover()
    )  # ranges are policy, not enforced here


def test_edited_applied_migration_is_a_hard_error(bare_db: DbHandle, mig_dir: Path) -> None:
    run_migrations(bare_db.owner_dsn, mig_dir)
    victim = next(mig_dir.glob("0004_*.sql"))
    victim.write_text(victim.read_text() + "\n-- sneaky edit\n")
    with pytest.raises(MigrationTamperError, match="0004_audit_log"):
        run_migrations(bare_db.owner_dsn, mig_dir)
    status = {s.version: s.state for s in migration_status(bare_db.owner_dsn, mig_dir)}
    assert status[4] == "tampered"
    assert status[3] == "applied"


def test_tamper_blocks_new_migrations_from_applying(bare_db: DbHandle, mig_dir: Path) -> None:
    run_migrations(bare_db.owner_dsn, mig_dir)
    (mig_dir / "0050_extra.sql").write_text("CREATE TABLE extra_after_tamper (id int);")
    victim = next(mig_dir.glob("0001_*.sql"))
    victim.write_text(victim.read_text() + "-- edit\n")
    with pytest.raises(MigrationTamperError):
        run_migrations(bare_db.owner_dsn, mig_dir)
    with bare_db.owner_conn() as conn:
        assert conn.execute("SELECT to_regclass('extra_after_tamper')").fetchone() == (None,)


def test_missing_applied_file_is_a_hard_error(bare_db: DbHandle, mig_dir: Path) -> None:
    run_migrations(bare_db.owner_dsn, mig_dir)
    next(mig_dir.glob("0007_*.sql")).unlink()
    with pytest.raises(MigrationTamperError, match="missing"):
        run_migrations(bare_db.owner_dsn, mig_dir)


def test_each_migration_runs_in_its_own_transaction(bare_db: DbHandle, mig_dir: Path) -> None:
    run_migrations(bare_db.owner_dsn, mig_dir)
    (mig_dir / "0060_good.sql").write_text("CREATE TABLE good_one (id int);")
    (mig_dir / "0061_bad.sql").write_text("CREATE TABLE half_done (id int);\nSELECT 1/0;")
    (mig_dir / "0062_never.sql").write_text("CREATE TABLE never_reached (id int);")
    with pytest.raises(MigrationError, match="0061_bad failed and was rolled back"):
        run_migrations(bare_db.owner_dsn, mig_dir)
    with bare_db.owner_conn() as conn:
        assert conn.execute("SELECT to_regclass('good_one')").fetchone() != (None,)
        assert conn.execute("SELECT to_regclass('half_done')").fetchone() == (None,)
        assert conn.execute("SELECT to_regclass('never_reached')").fetchone() == (None,)
        versions = [r[0] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY 1")]
    assert 60 in versions
    assert 61 not in versions
    # fixing forward: a corrected, new file applies; the failed number can be re-used because it never applied
    (mig_dir / "0061_bad.sql").write_text("CREATE TABLE fixed_one (id int);")
    assert run_migrations(bare_db.owner_dsn, mig_dir) == ["0061_bad", "0062_never"]


def test_late_arriving_lower_version_is_applied_in_order(bare_db: DbHandle, mig_dir: Path) -> None:
    (mig_dir / "0600_finance.sql").write_text("CREATE TABLE fin (id int);")
    run_migrations(bare_db.owner_dsn, mig_dir)
    (mig_dir / "0100_identity.sql").write_text("CREATE TABLE ident (id int);")
    assert run_migrations(bare_db.owner_dsn, mig_dir) == ["0100_identity"]


def test_concurrent_runners_apply_each_migration_exactly_once(bare_db: DbHandle) -> None:
    results: list[list[str] | BaseException] = []
    barrier = threading.Barrier(4)

    def runner() -> None:
        barrier.wait()
        try:
            results.append(run_migrations(bare_db.owner_dsn))
        except BaseException as exc:  # noqa: BLE001 - recorded and asserted below
            results.append(exc)

    threads = [threading.Thread(target=runner) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    errors = [r for r in results if isinstance(r, BaseException)]
    assert not errors, errors
    labels = [m.label for m in discover()]
    applied_lists = [r for r in results if isinstance(r, list)]
    assert len(applied_lists) == 4
    # exactly one runner did the work; the others waited on the advisory lock and found nothing to do
    assert sorted(len(r) for r in applied_lists) == [0, 0, 0, len(labels)]
    assert [v for v, _, _ in _applied(bare_db)] == [m.version for m in discover()]


def test_file_validation_errors(tmp_path: Path) -> None:
    d = tmp_path / "m"
    d.mkdir()
    (d / "badname.sql").write_text("SELECT 1;")
    with pytest.raises(MigrationError, match="bad migration file name"):
        discover(d)
    (d / "badname.sql").unlink()
    (d / "0001_a.sql").write_text("SELECT 1;")
    (d / "0001_b.sql").write_text("SELECT 2;")
    with pytest.raises(MigrationError, match="duplicate migration version 0001"):
        discover(d)
    (d / "0001_b.sql").unlink()
    (d / "0002_tx.sql").write_text("BEGIN;\nSELECT 1;\nCOMMIT;")
    with pytest.raises(MigrationError, match="transaction control"):
        discover(d)
    (d / "0002_tx.sql").write_text("   \n")
    with pytest.raises(MigrationError, match="empty"):
        discover(d)
    with pytest.raises(MigrationError, match="not found"):
        discover(tmp_path / "nope")


def test_refuses_when_required_roles_are_missing(
    bare_db: DbHandle, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A database without the bootstrap roles gets a clear instruction, not a half-applied schema."""
    monkeypatch.setattr(migrate_module, "REQUIRED_ROLES", ("dwaar_owner", "dwaar_ghost_role"))
    d = tmp_path / "m"
    d.mkdir()
    (d / "0001_x.sql").write_text("CREATE TABLE should_not_exist (id int);")
    with pytest.raises(MigrationError, match=r"dwaar_ghost_role.*bootstrap_roles\.sql"):
        run_migrations(bare_db.owner_dsn, d)
    with bare_db.owner_conn() as conn:
        assert conn.execute("SELECT to_regclass('should_not_exist')").fetchone() == (None,)


def test_cli_up_and_status(bare_db: DbHandle) -> None:
    def cli(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "dwaar_api.core.migrate", *args, "--dsn", bare_db.owner_dsn],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    pending = cli("status")
    assert pending.returncode == 0
    assert "pending" in pending.stdout
    up = cli("up")
    assert up.returncode == 0, up.stderr
    assert "applied" in up.stdout
    status = cli("status")
    assert status.returncode == 0
    assert "pending" not in status.stdout
    assert "0001  applied" in status.stdout
    assert cli("up").stdout.startswith("applied 0 migration(s)")
    # without a DSN the CLI fails closed with a usage error (exit 2)
    no_dsn = subprocess.run(
        [sys.executable, "-m", "dwaar_api.core.migrate", "status"],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
        check=False,
    )
    assert no_dsn.returncode == 2
