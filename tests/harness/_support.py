"""Helpers for harness self-tests: run pytest in a scratch project with the real plugin."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class PytestRun:
    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return self.stdout + self.stderr


def run_pytest(
    project: Path,
    files: dict[str, str],
    *args: str,
    env: dict[str, str] | None = None,
) -> PytestRun:
    """Write `files` into `project`, then run `python -m pytest` there with the harness plugin."""
    for name, body in files.items():
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(textwrap.dedent(body), encoding="utf-8")
    (project / "pytest.ini").write_text(
        "[pytest]\naddopts = -p tests._harness.plugin --strict-markers -p no:cacheprovider\n",
        encoding="utf-8",
    )
    full_env = {
        **os.environ,
        "PYTHONPATH": str(REPO_ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
        **(env or {}),
    }
    full_env.pop("PYTEST_ADDOPTS", None)
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            str(project / "pytest.ini"),
            "--rootdir",
            str(project),
            *args,
        ],
        cwd=project,
        env=full_env,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    return PytestRun(proc.returncode, proc.stdout, proc.stderr)


def processes_in_dir(path: Path) -> list[int]:
    """PIDs whose working directory or command line is under `path` (any user)."""
    prefix = str(path)
    found: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if os.readlink(entry / "cwd").startswith(prefix):
                found.append(int(entry.name))
                continue
            cmdline = (entry / "cmdline").read_bytes().decode(errors="replace")
        except OSError:
            continue
        if prefix in cmdline:
            found.append(int(entry.name))
    return found
