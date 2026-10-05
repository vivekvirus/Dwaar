"""The ephemeral cluster starts, serves, stops, and leaves nothing behind."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import psycopg

from tests._harness.pgcluster import PgCluster, pid_alive, sweep_stale_clusters
from tests._harness.pgfixtures import PgServer
from tests.harness._support import processes_in_dir, run_pytest


def test_cluster_starts_serves_and_stops_cleanly() -> None:
    cluster = PgCluster.create()
    base: Path = cluster.base_dir
    pid = cluster.pid()
    try:
        assert pid is not None
        assert pid_alive(pid)
        assert cluster.admin_url.startswith("postgresql://postgres@127.0.0.1:")
        with psycopg.connect(cluster.admin_url) as conn:
            version = conn.execute("SHOW server_version").fetchone()
            assert version is not None
            assert str(version[0]).startswith("16.")
            assert conn.execute("SHOW listen_addresses").fetchone() == ("127.0.0.1",)
        assert processes_in_dir(base), "expected postgres processes while running"
    finally:
        cluster.stop()
    assert pid is not None
    assert not pid_alive(pid)
    assert not base.exists()
    assert processes_in_dir(base) == []
    cluster.stop()  # idempotent


def test_two_clusters_get_distinct_ports_and_dirs() -> None:
    first, second = PgCluster.create(), PgCluster.create()
    try:
        assert first.port != second.port
        assert first.base_dir != second.base_dir
    finally:
        first.stop()
        second.stop()


def test_process_postgres_runs_unprivileged() -> None:
    cluster = PgCluster.create()
    try:
        pid = cluster.pid()
        assert pid is not None
        uid = int(
            next(
                line.split()[1]
                for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                if line.startswith("Uid:")
            )
        )
        assert uid != 0, "PostgreSQL must never run as root"
    finally:
        cluster.stop()


def test_sweep_kills_clusters_whose_owner_died() -> None:
    """Simulates `kill -9` of the pytest process: the next session sweeps the leftover cluster."""
    cluster = PgCluster.create()
    base = cluster.base_dir
    pid = cluster.pid()
    assert pid is not None
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    (base / "owner.pid").write_text(f"{dead.pid}\n", encoding="ascii")
    try:
        assert sweep_stale_clusters() >= 1
        assert not pid_alive(pid)
        assert not base.exists()
    finally:
        cluster.stop()


def test_sweep_leaves_live_owners_alone() -> None:
    cluster = PgCluster.create()
    try:
        sweep_stale_clusters()
        pid = cluster.pid()
        assert pid is not None
        assert pid_alive(pid)
        assert cluster.base_dir.exists()
    finally:
        cluster.stop()


def test_session_fixture_info(pg_server: PgServer) -> None:
    assert pg_server.version.startswith("16.")
    with pg_server.admin_conn() as conn:
        assert conn.execute(
            "SELECT current_setting('server_version_num')::int >= 160000"
        ).fetchone() == (True,)
    if not pg_server.external:
        assert pg_server.cluster is not None
        assert pg_server.cluster.pid() is not None


def test_pytest_session_leaves_no_postgres_behind(tmp_path: Path) -> None:
    """A whole pytest session that uses `pg_server` exits with its cluster gone."""
    if os.environ.get("DWAAR_TEST_PG_ADMIN_URL"):
        return  # external server: nothing is started by the harness
    # postgres (a different OS user when running as root) must be able to traverse the path,
    # which pytest's tmp_path (0700) does not allow.
    scratch = Path(tempfile.mkdtemp(prefix="dwaar-harness-scratch-", dir=tempfile.gettempdir()))
    os.chmod(scratch, 0o755)
    result = run_pytest(
        tmp_path / "proj",
        {"test_x.py": "def test_ok(pg_server):\n    assert pg_server.version\n"},
        env={"DWAAR_TEST_PG_TMPDIR": str(scratch)},
    )
    try:
        assert result.returncode == 0, result.output
        assert list(scratch.iterdir()) == [], "cluster directory must be removed"
        assert processes_in_dir(scratch) == []
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
