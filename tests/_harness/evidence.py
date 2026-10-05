"""Acceptance evidence + requirement run report + marker validation.

Markers (all registered here and in pyproject so `--strict-markers` is satisfied either way):
  @pytest.mark.req("GATE-03", "GATE-04")     requirement IDs a test evidences
  @pytest.mark.at("AT-04", dataset="...")    acceptance test ID (PRD section 16 matrix)
  @pytest.mark.milestone("M0")               optional; derived from the matrix when omitted
  @pytest.mark.simulation                    simulator-backed (labelled in evidence)
  @pytest.mark.slow

Invalid marker arguments abort collection (exit code 4): unknown/ill-formed AT or requirement
IDs, bad milestones, an explicit milestone that contradicts the acceptance matrix, and `at`
IDs that are absent from a non-empty matrix.

With `--evidence`, after the session this writes docs/evidence/<AT-ID>.json for every AT that
had at least one test run, docs/evidence/INDEX.md (every AT in the matrix; ATs without a run
say so honestly) and docs/evidence/_run.json (all req/at tests). `--milestone M1` selects the
`at` tests whose matrix milestone is <= M1 (cumulative: an M1 run re-proves M0).
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

MILESTONES = ("M0", "M1", "M2", "M3", "M4")
AT_ID = re.compile(r"^AT-\d{2}$")
REQ_ID = re.compile(r"^[A-Z]{1,6}(?:-[A-Z]{1,6})?-\d{1,3}[a-z]?$")
TESTER = "automated/claude-code"
DEFAULT_DATASET = "synthetic data created by the test itself (invented identities, no real PII)"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX = REPO_ROOT / "docs" / "traceability" / "acceptance_matrix.yaml"
DEFAULT_EVIDENCE_DIR = REPO_ROOT / "docs" / "evidence"


# --------------------------------------------------------------------------- matrix


def load_matrix(path: Path) -> dict[str, dict[str, Any]]:
    """acceptance_matrix.yaml -> {AT-ID: item}. Missing or malformed files yield {} (warned)."""
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        items = data["items"]
        return {str(item["id"]): item for item in items}
    except (OSError, yaml.YAMLError, KeyError, TypeError) as exc:
        warnings.warn(
            f"acceptance matrix {path} unreadable ({exc}); AT validation skipped", stacklevel=2
        )
        return {}


def milestone_rank(name: str) -> int:
    return MILESTONES.index(name)


# --------------------------------------------------------------------------- git / environment


def git_info(cwd: Path) -> tuple[str, bool]:
    """(commit sha or 'uncommitted', working-tree dirty). Read-only git only."""

    def run(*args: str) -> str | None:
        try:
            proc = subprocess.run(
                ["git", *args], cwd=cwd, check=False, capture_output=True, text=True, timeout=20
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return proc.stdout.strip() if proc.returncode == 0 else None

    sha = run("rev-parse", "HEAD")
    if not sha:
        return "uncommitted", True
    dirty = bool(run("status", "--porcelain"))
    return sha, dirty


def environment_info(simulation: bool, cwd: Path) -> dict[str, Any]:
    from tests._harness.pgfixtures import RUN_INFO

    _, dirty = git_info(cwd)
    return {
        "python": platform.python_version(),
        "postgres": RUN_INFO.get("postgres") or "not used in this run",
        "postgres_mode": RUN_INFO.get("pg_mode"),
        "DWAAR_ENV": os.environ.get("DWAAR_ENV", "unset"),
        "simulation": simulation,
        "platform": platform.platform(),
        "tree_dirty": dirty,
    }


# --------------------------------------------------------------------------- records


@dataclass
class TestRecord:
    __test__ = False  # not a pytest test class

    nodeid: str
    reqs: list[str]
    ats: list[str]
    milestone: str | None
    simulation: bool
    dataset: str | None
    phases: dict[str, str] = field(default_factory=dict)
    duration_s: float = 0.0
    message: str | None = None
    wasxfail: bool = False

    @property
    def outcome(self) -> str:
        setup = self.phases.get("setup")
        call = self.phases.get("call")
        teardown = self.phases.get("teardown")
        if setup == "failed":
            return "error"
        if setup == "skipped":
            return "skipped"
        if call is None:
            return "not-run"
        if call == "failed":
            return "failed"
        if call == "skipped":
            return "xfailed" if self.wasxfail else "skipped"
        if teardown == "failed":
            return "error"
        return "xpassed" if self.wasxfail else "passed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "nodeid": self.nodeid,
            "outcome": self.outcome,
            "duration_s": round(self.duration_s, 4),
            "reqs": self.reqs,
            "ats": self.ats,
            "milestone": self.milestone,
            "simulation": self.simulation,
            "message": self.message,
        }


def aggregate_outcome(outcomes: list[str]) -> str:
    """One verdict for an AT that may be covered by several tests."""
    if not outcomes:
        return "not-run"
    if "failed" in outcomes:
        return "failed"
    if "error" in outcomes:
        return "error"
    passing = [o for o in outcomes if o in ("passed", "xpassed")]
    if len(passing) == len(outcomes):
        return "passed"
    if passing:
        return "partial"
    return "skipped"


def _failure_message(report: pytest.TestReport) -> str | None:
    longrepr = report.longrepr
    if longrepr is None:
        return None
    if isinstance(longrepr, tuple) and len(longrepr) == 3:  # skip: (path, lineno, reason)
        return str(longrepr[2])
    crash = getattr(longrepr, "reprcrash", None)
    text = getattr(crash, "message", None) or str(longrepr)
    return text[:2000]


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


# --------------------------------------------------------------------------- writers


def build_at_evidence(
    at_id: str,
    records: list[TestRecord],
    matrix: dict[str, dict[str, Any]],
    *,
    commit: str,
    environment: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    item = matrix.get(at_id, {})
    outcomes = [r.outcome for r in records]
    verdict = aggregate_outcome(outcomes)
    failing = [r for r in records if r.outcome in ("failed", "error")]
    message = None
    if failing:
        message = "; ".join(f"{r.nodeid}: {r.message}" for r in failing if r.message) or None
    elif verdict in ("skipped", "partial"):
        reasons = [r.message for r in records if r.outcome == "skipped" and r.message]
        message = "; ".join(dict.fromkeys(reasons)) or None
    milestones = [r.milestone for r in records if r.milestone]
    datasets = list(dict.fromkeys(r.dataset for r in records if r.dataset))
    simulation = any(r.simulation for r in records)
    return {
        "id": at_id,
        "milestone": item.get("milestone") or (milestones[0] if milestones else None),
        "scenario": item.get("scenario"),
        "expected": item.get("expected"),
        "observed": {"outcome": verdict, "message": message},
        "commit": commit,
        "environment": {**environment, "simulation": simulation},
        "dataset": "; ".join(datasets) if datasets else DEFAULT_DATASET,
        "trace": {
            "pytest_nodeids": [r.nodeid for r in records],
            "duration_s": round(sum(r.duration_s for r in records), 4),
            "tests": [
                {"nodeid": r.nodeid, "outcome": r.outcome, "duration_s": round(r.duration_s, 4)}
                for r in records
            ],
        },
        "tester": TESTER,
        "date": now.isoformat(timespec="seconds"),
    }


def render_index(matrix: dict[str, dict[str, Any]], evidence_dir: Path, now: datetime) -> str:
    on_disk: dict[str, dict[str, Any]] = {}
    for path in sorted(evidence_dir.glob("AT-*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            on_disk[str(data["id"])] = data
        except (OSError, ValueError, KeyError):
            continue
    ids = sorted(set(matrix) | set(on_disk))
    lines = [
        "# Acceptance evidence index",
        "",
        f"Generated {now.isoformat(timespec='seconds')} by `tests/_harness/evidence.py` "
        "(`make acceptance MILESTONE=...`). Do not edit by hand. Simulated, staging and field results "
        "are different evidence classes: the `sim` column marks simulator-backed runs.",
        "",
        "| AT | Milestone | Scenario | Outcome | sim | Commit | Date | Evidence |",
        "|---|---|---|---|---|---|---|---|",
    ]
    counts: dict[str, int] = {}
    for at_id in ids:
        item = matrix.get(at_id, {})
        data = on_disk.get(at_id)
        scenario = str(item.get("scenario") or (data or {}).get("scenario") or "").replace("|", "/")
        milestone = item.get("milestone") or (data or {}).get("milestone") or ""
        if data:
            outcome = data["observed"]["outcome"]
            sim = "yes" if data["environment"].get("simulation") else "no"
            commit = str(data["commit"])[:10]
            lines.append(
                f"| {at_id} | {milestone} | {scenario} | {outcome} | {sim} | {commit} | "
                f"{data['date']} | [{at_id}.json]({at_id}.json) |"
            )
        else:
            outcome = "no evidence yet"
            lines.append(f"| {at_id} | {milestone} | {scenario} | {outcome} | | | | |")
        counts[outcome] = counts.get(outcome, 0) + 1
    summary = (
        ", ".join(f"{n} {k}" for k, n in sorted(counts.items())) or "no acceptance tests listed"
    )
    lines.insert(2, f"Summary: {summary}.")
    lines.insert(3, "")
    return "\n".join(lines) + "\n"


def write_outputs(
    records: list[TestRecord],
    matrix: dict[str, dict[str, Any]],
    evidence_dir: Path,
    *,
    commit: str,
    environment: dict[str, Any],
    now: datetime,
    milestone_filter: str | None,
    write_evidence_files: bool = True,
    run_json: Path | None = None,
) -> list[Path]:
    written: list[Path] = []
    if write_evidence_files:
        by_at: dict[str, list[TestRecord]] = {}
        for record in records:
            for at_id in record.ats:
                by_at.setdefault(at_id, []).append(record)
        for at_id, recs in sorted(by_at.items()):
            doc = build_at_evidence(
                at_id, recs, matrix, commit=commit, environment=environment, now=now
            )
            target = evidence_dir / f"{at_id}.json"
            atomic_write(target, json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
            written.append(target)
        index = evidence_dir / "INDEX.md"
        atomic_write(index, render_index(matrix, evidence_dir, now))
        written.append(index)
        if run_json is None:
            run_json = evidence_dir / "_run.json"
    if run_json is not None:
        report = {
            "generated_at": now.isoformat(timespec="seconds"),
            "commit": commit,
            "environment": environment,
            "milestone_filter": milestone_filter,
            "results": [r.as_dict() for r in records],
        }
        atomic_write(run_json, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        written.append(run_json)
    return written


# --------------------------------------------------------------------------- pytest hooks


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("dwaar", "Dwaar harness")
    group.addoption("--evidence", action="store_true", help="write acceptance evidence files")
    group.addoption(
        "--evidence-dir", default=None, help="evidence output dir (default docs/evidence)"
    )
    group.addoption("--acceptance-matrix", default=None, help="acceptance matrix YAML path")
    group.addoption(
        "--milestone",
        default=None,
        choices=MILESTONES,
        help="run `at` tests whose matrix milestone is <= this milestone",
    )
    group.addoption("--run-json", default=None, help="write the req/at run report to this path")


def pytest_configure(config: pytest.Config) -> None:
    for line in (
        "req(*ids): PRD requirement ID(s) this test evidences, e.g. req('GATE-03')",
        "at(id, dataset=None): PRD acceptance test ID this test evidences, e.g. at('AT-04')",
        "milestone(name): milestone M0..M4 (derived from the acceptance matrix when omitted)",
        "simulation: test exercises a labelled simulator, never a real provider or hardware",
        "slow: slow test (excluded by `-m 'not slow'`)",
    ):
        config.addinivalue_line("markers", line)
    matrix_opt = config.getoption("--acceptance-matrix")
    matrix_path = Path(matrix_opt) if matrix_opt else DEFAULT_MATRIX
    out_opt = config.getoption("--evidence-dir")
    config.pluginmanager.register(
        EvidencePlugin(
            config,
            matrix=load_matrix(matrix_path),
            evidence_dir=Path(out_opt) if out_opt else DEFAULT_EVIDENCE_DIR,
        ),
        "dwaar-evidence-collector",
    )


class EvidencePlugin:
    def __init__(
        self, config: pytest.Config, matrix: dict[str, dict[str, Any]], evidence_dir: Path
    ):
        self.config = config
        self.matrix = matrix
        self.evidence_dir = evidence_dir
        self.records: dict[str, TestRecord] = {}

    # ---- collection

    def _inspect(
        self, item: pytest.Item
    ) -> tuple[list[str], list[str], str | None, str | None, list[str]]:
        problems: list[str] = []
        reqs: list[str] = []
        for marker in item.iter_markers("req"):
            if not marker.args or marker.kwargs:
                problems.append("req() takes one or more ID strings")
            for arg in marker.args:
                if not isinstance(arg, str) or not REQ_ID.match(arg):
                    problems.append(f"invalid requirement ID {arg!r}")
                else:
                    reqs.append(arg)
        ats: list[str] = []
        dataset: str | None = None
        for marker in item.iter_markers("at"):
            if len(marker.args) != 1 or set(marker.kwargs) - {"dataset"}:
                problems.append("at() takes exactly one ID and optional dataset=")
                continue
            arg = marker.args[0]
            if not isinstance(arg, str) or not AT_ID.match(arg):
                problems.append(f"invalid acceptance test ID {arg!r} (expected AT-NN)")
                continue
            if self.matrix and arg not in self.matrix:
                problems.append(f"{arg} is not in the acceptance matrix")
            ats.append(arg)
            dataset = marker.kwargs.get("dataset", dataset)
        milestone: str | None = None
        for marker in item.iter_markers("milestone"):
            arg = marker.args[0] if len(marker.args) == 1 and not marker.kwargs else None
            if arg not in MILESTONES:
                problems.append(f"invalid milestone {marker.args!r} (expected one of {MILESTONES})")
            else:
                milestone = arg
                break
        matrix_milestones = {
            str(self.matrix[a]["milestone"])
            for a in ats
            if a in self.matrix and self.matrix[a].get("milestone")
        }
        if milestone and matrix_milestones and matrix_milestones != {milestone}:
            problems.append(
                f"milestone {milestone} contradicts the acceptance matrix {sorted(matrix_milestones)}"
            )
        if milestone is None and len(matrix_milestones) == 1:
            milestone = next(iter(matrix_milestones))
        return reqs, ats, milestone, dataset, problems

    def pytest_collection_modifyitems(
        self, config: pytest.Config, items: list[pytest.Item]
    ) -> None:
        errors: list[str] = []
        selected: list[pytest.Item] = []
        deselected: list[pytest.Item] = []
        limit = config.getoption("--milestone")
        for item in items:
            reqs, ats, milestone, dataset, problems = self._inspect(item)
            errors.extend(f"{item.nodeid}: {p}" for p in problems)
            if limit and ats and milestone and milestone_rank(milestone) > milestone_rank(limit):
                deselected.append(item)
                continue
            selected.append(item)
            if reqs or ats:
                self.records[item.nodeid] = TestRecord(
                    nodeid=item.nodeid,
                    reqs=reqs,
                    ats=ats,
                    milestone=milestone,
                    simulation=item.get_closest_marker("simulation") is not None,
                    dataset=dataset,
                )
        if errors:
            raise pytest.UsageError("invalid test markers:\n  " + "\n  ".join(errors))
        if deselected:
            config.hook.pytest_deselected(items=deselected)
            items[:] = selected

    # ---- execution

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        record = self.records.get(report.nodeid)
        if record is None:
            return
        record.phases[report.when] = report.outcome
        record.duration_s += report.duration
        if hasattr(report, "wasxfail"):
            record.wasxfail = True
        if report.outcome in ("failed", "skipped"):
            message = _failure_message(report)
            if message and (record.message is None or report.outcome == "failed"):
                record.message = message

    # ---- output

    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        config = self.config
        evidence_on = bool(config.getoption("--evidence"))
        run_json_opt = config.getoption("--run-json")
        if not evidence_on and not run_json_opt:
            return
        if getattr(config, "workerinput", None) is not None:  # xdist worker
            return
        records = [r for r in self.records.values() if r.phases]
        commit, _ = git_info(REPO_ROOT)
        environment = environment_info(any(r.simulation for r in records), REPO_ROOT)
        write_outputs(
            records,
            self.matrix,
            self.evidence_dir,
            commit=commit,
            environment=environment,
            now=datetime.now(UTC),
            milestone_filter=config.getoption("--milestone"),
            write_evidence_files=evidence_on,
            run_json=Path(run_json_opt) if run_json_opt else None,
        )

    def pytest_terminal_summary(self, terminalreporter: Any) -> None:
        if self.config.getoption("--evidence"):
            terminalreporter.write_line(f"evidence written to {self.evidence_dir}")
        if sys.flags.dev_mode:  # pragma: no cover
            terminalreporter.write_line("python dev mode")
