"""Private, ephemeral PostgreSQL 16 cluster for tests (and nothing else).

* Trust auth on 127.0.0.1, random free port, data dir under a private temp directory.
* Running as root: every PostgreSQL process runs as the `postgres` OS user via `runuser`
  (root cannot run postgres). Otherwise the current user runs it directly.
* Torn down by (1) the pytest fixture finalizer, (2) `atexit`, (3) a SIGTERM handler
  installed by the fixture, and (4) a startup sweep that kills clusters whose owning
  pytest process died (SIGKILL) using the postmaster pidfile. Nothing may leak.
* Durability is deliberately disabled (fsync=off ...): this cluster is disposable.
"""

from __future__ import annotations

import atexit
import contextlib
import glob
import os
import pwd
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

CLUSTER_PREFIX = "dwaar-pg-"
OWNER_FILE = "owner.pid"
PG_USER = "postgres"


class PgClusterError(RuntimeError):
    pass


def find_pg_bin() -> Path:
    """Directory holding initdb/pg_ctl/psql: $DWAAR_PG_BIN, newest /usr/lib/postgresql/*/bin, PATH."""
    override = os.environ.get("DWAAR_PG_BIN")
    if override:
        return Path(override)
    candidates = sorted(
        (Path(p) for p in glob.glob("/usr/lib/postgresql/*/bin")),
        key=lambda p: int(p.parent.name) if p.parent.name.isdigit() else 0,
        reverse=True,
    )
    # prefer 16, then anything newer, then older
    for path in candidates:
        if path.parent.name == "16" and (path / "initdb").exists():
            return path
    for path in candidates:
        if (path / "initdb").exists():
            return path
    initdb = shutil.which("initdb")
    if initdb:
        return Path(initdb).parent
    raise PgClusterError("PostgreSQL binaries not found; set DWAAR_PG_BIN")


def find_psql() -> str:
    """psql executable (needed for bootstrap SQL that uses \\gexec and variables)."""
    try:
        candidate = find_pg_bin() / "psql"
        if candidate.exists():
            return str(candidate)
    except PgClusterError:
        pass
    found = shutil.which("psql")
    if not found:
        raise PgClusterError("psql not found; install postgresql-client or set DWAAR_PG_BIN")
    return found


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie still answers kill(0); treat it as dead.
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as handle:
            return handle.read().rsplit(")", 1)[1].split()[0] != "Z"
    except (FileNotFoundError, IndexError):
        return False


def _children_of(pid: int) -> list[int]:
    found: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text(encoding="ascii")
            if int(stat.rsplit(")", 1)[1].split()[1]) == pid:
                found.append(int(entry.name))
        except (OSError, ValueError, IndexError):
            continue
    return found


def _kill_tree(pid: int) -> None:
    kids = _children_of(pid)
    for target in [pid, *kids]:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(target, signal.SIGKILL)


def _postmaster_pid(data_dir: Path) -> int | None:
    try:
        first = (data_dir / "postmaster.pid").read_text(encoding="ascii").splitlines()[0]
        return int(first)
    except (OSError, ValueError, IndexError):
        return None


def _as_pg_user_prefix() -> list[str]:
    if os.geteuid() != 0:
        return []
    if not shutil.which("runuser"):
        raise PgClusterError("running as root requires `runuser` to start PostgreSQL as 'postgres'")
    return ["runuser", "-u", PG_USER, "--"]


def base_tmp_root() -> str:
    """Root can only use a directory the postgres user can traverse: default /tmp."""
    override = os.environ.get("DWAAR_TEST_PG_TMPDIR")
    if override:
        return override
    return "/tmp" if os.geteuid() == 0 else tempfile.gettempdir()  # noqa: S108


@dataclass
class PgCluster:
    bin_dir: Path
    base_dir: Path
    port: int
    data_dir: Path = field(init=False)
    sock_dir: Path = field(init=False)
    log_file: Path = field(init=False)
    started: bool = False
    stopped: bool = False
    proc: subprocess.Popen[bytes] | None = None

    def __post_init__(self) -> None:
        self.data_dir = self.base_dir / "data"
        self.sock_dir = self.base_dir / "sock"
        self.log_file = self.base_dir / "log" / "postgres.log"

    # ---------------------------------------------------------------- creation

    @classmethod
    def create(cls, bin_dir: Path | None = None, tries: int = 4) -> PgCluster:
        """initdb + start on a free port; retries if the port is taken in the race window."""
        sweep_stale_clusters()
        bin_path = bin_dir or find_pg_bin()
        last_error: Exception | None = None
        for _ in range(tries):
            base = Path(tempfile.mkdtemp(prefix=CLUSTER_PREFIX, dir=base_tmp_root()))
            os.chmod(base, 0o755)
            cluster = cls(bin_path, base, free_port())
            cluster._write_owner_marker()
            atexit.register(cluster.stop)
            try:
                cluster._initdb()
                cluster._start()
                return cluster
            except PgClusterError as exc:
                last_error = exc
                cluster.stop()
                if "address already in use" not in str(exc).lower():
                    break
        raise PgClusterError(f"could not start PostgreSQL test cluster: {last_error}")

    def _write_owner_marker(self) -> None:
        (self.base_dir / OWNER_FILE).write_text(f"{os.getpid()}\n", encoding="ascii")

    def _chown(self, path: Path) -> None:
        if os.geteuid() == 0:
            info = pwd.getpwnam(PG_USER)
            shutil.chown(path, user=info.pw_uid, group=info.pw_gid)

    def _run(self, args: list[str], timeout: float = 120) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*_as_pg_user_prefix(), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            cwd="/",
        )

    def _initdb(self) -> None:
        for directory in (self.data_dir, self.sock_dir, self.log_file.parent):
            directory.mkdir(parents=True, exist_ok=True)
            self._chown(directory)
        os.chmod(self.data_dir, 0o700)
        result = self._run(
            [
                str(self.bin_dir / "initdb"),
                "-D",
                str(self.data_dir),
                "-A",
                "trust",
                "-U",
                PG_USER,
                "-E",
                "UTF8",
                "--no-locale",
                "--no-sync",
            ]
        )
        if result.returncode != 0:
            raise PgClusterError(f"initdb failed: {result.stderr.strip() or result.stdout.strip()}")

    def _start(self) -> None:
        """Run `postgres` as a direct child (via runuser when root) so we can reap it: no
        orphaned daemon, no zombie left behind for PID 1."""
        settings = {
            "listen_addresses": "127.0.0.1",
            "unix_socket_directories": str(self.sock_dir),
            "fsync": "off",
            "synchronous_commit": "off",
            "full_page_writes": "off",
            "max_connections": "200",
            "shared_buffers": "64MB",
            "timezone": "UTC",
            "log_timezone": "UTC",
            "log_min_messages": "warning",
        }
        cmd = [
            *_as_pg_user_prefix(),
            str(self.bin_dir / "postgres"),
            "-D",
            str(self.data_dir),
            "-p",
            str(self.port),
        ]
        for key, value in settings.items():
            cmd += ["-c", f"{key}={value}"]
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_file, "ab") as log:
            self.proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                cwd="/",
                start_new_session=True,
            )
        self.started = True
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise PgClusterError(f"postgres exited during start: {self.log_tail()}")
            ready = subprocess.run(
                [str(self.bin_dir / "pg_isready"), "-h", "127.0.0.1", "-p", str(self.port), "-q"],
                check=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=10,
            )
            if ready.returncode == 0:
                return
            time.sleep(0.05)
        raise PgClusterError(f"postgres did not become ready in 60s: {self.log_tail()}")

    def log_tail(self, lines: int = 15) -> str:
        try:
            return "\n".join(self.log_file.read_text(errors="replace").splitlines()[-lines:])
        except OSError:
            return "(no log)"

    # ---------------------------------------------------------------- connection info

    @property
    def admin_url(self) -> str:
        return f"postgresql://{PG_USER}@127.0.0.1:{self.port}/postgres"

    # ---------------------------------------------------------------- teardown

    def pid(self) -> int | None:
        return _postmaster_pid(self.data_dir)

    def _wait_exit(self, timeout: float) -> bool:
        """True once the child (or, without one, the postmaster) is gone."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc is not None:
                if self.proc.poll() is not None:
                    return True
            else:
                pid = self.pid()
                if pid is None or not pid_alive(pid):
                    return True
            time.sleep(0.05)
        return False

    def stop(self) -> None:
        """Idempotent: fast shutdown (SIGINT), then immediate (SIGQUIT), then SIGKILL; reap
        the child; delete the directory."""
        if self.stopped:
            return
        self.stopped = True
        with contextlib.suppress(Exception):
            atexit.unregister(self.stop)
        pid = self.pid()
        running = (self.proc is not None and self.proc.poll() is None) or (
            pid is not None and pid_alive(pid)
        )
        if running and pid is not None:
            for sig, wait in ((signal.SIGINT, 30.0), (signal.SIGQUIT, 15.0)):
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.kill(pid, sig)
                if self._wait_exit(wait):
                    break
            else:
                _kill_tree(pid)
                self._wait_exit(10.0)
        elif running and self.proc is not None:
            self.proc.kill()
        if self.proc is not None:
            with contextlib.suppress(Exception):
                self.proc.wait(timeout=10)
        shutil.rmtree(self.base_dir, ignore_errors=True)


def sweep_stale_clusters() -> int:
    """Kill and delete clusters whose owning pytest process is gone. Returns how many."""
    swept = 0
    for path in glob.glob(os.path.join(base_tmp_root(), CLUSTER_PREFIX + "*")):
        base = Path(path)
        marker = base / OWNER_FILE
        try:
            owner = int(marker.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            # No readable marker: only touch it once it is clearly abandoned.
            try:
                if time.time() - base.stat().st_mtime < 300:
                    continue
            except OSError:
                continue
            owner = -1
        if owner > 0 and pid_alive(owner):
            continue
        pid = _postmaster_pid(base / "data")
        if pid is not None and pid_alive(pid):
            _kill_tree(pid)
            deadline = time.monotonic() + 5
            while pid_alive(pid) and time.monotonic() < deadline:
                time.sleep(0.05)
        shutil.rmtree(base, ignore_errors=True)
        swept += 1
    return swept
