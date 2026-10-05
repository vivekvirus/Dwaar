"""Evidence writer: unit tests with a temp output dir plus a real end-to-end pytest run."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from tests._harness.evidence import (
    TestRecord,
    aggregate_outcome,
    build_at_evidence,
    load_matrix,
    render_index,
    write_outputs,
)
from tests.harness._support import run_pytest

NOW = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)
MATRIX: dict[str, dict[str, Any]] = {
    "AT-01": {
        "id": "AT-01",
        "milestone": "M0",
        "scenario": "Two societies cannot see each other",
        "expected": "Zero cross rows",
        "prd_page": 46,
    },
    "AT-02": {
        "id": "AT-02",
        "milestone": "M0",
        "scenario": "Role expiry",
        "expected": "Access revoked",
        "prd_page": 46,
    },
    "AT-05": {
        "id": "AT-05",
        "milestone": "M1",
        "scenario": "Edge offline entry",
        "expected": "Cached policy decides",
        "prd_page": 47,
    },
}
ENV = {"python": "3.12.x", "postgres": "16.x", "DWAAR_ENV": "local", "simulation": False}


def record(nodeid: str, ats: list[str], outcome_phases: dict[str, str], **kw: Any) -> TestRecord:
    rec = TestRecord(
        nodeid=nodeid, reqs=kw.pop("reqs", []), ats=ats, milestone=kw.pop("milestone", None),
        simulation=kw.pop("simulation", False), dataset=kw.pop("dataset", None),
    )  # fmt: skip
    rec.phases = outcome_phases
    rec.duration_s = kw.pop("duration_s", 0.5)
    rec.message = kw.pop("message", None)
    rec.wasxfail = kw.pop("wasxfail", False)
    return rec


PASS = {"setup": "passed", "call": "passed", "teardown": "passed"}
FAIL = {"setup": "passed", "call": "failed", "teardown": "passed"}


def test_record_outcome_mapping() -> None:
    assert record("a", [], PASS).outcome == "passed"
    assert record("a", [], FAIL).outcome == "failed"
    assert record("a", [], {"setup": "failed"}).outcome == "error"
    assert record("a", [], {"setup": "skipped"}).outcome == "skipped"
    assert (
        record("a", [], {"setup": "passed", "call": "skipped", "teardown": "passed"}).outcome
        == "skipped"
    )
    assert (
        record("a", [], {"setup": "passed", "call": "passed", "teardown": "failed"}).outcome
        == "error"
    )
    assert (
        record("a", [], {"setup": "passed", "call": "skipped"}, wasxfail=True).outcome == "xfailed"
    )
    assert (
        record("a", [], {"setup": "passed", "call": "passed"}, wasxfail=True).outcome == "xpassed"
    )
    assert record("a", [], {}).outcome == "not-run"


def test_aggregate_outcome() -> None:
    assert aggregate_outcome([]) == "not-run"
    assert aggregate_outcome(["passed", "passed"]) == "passed"
    assert aggregate_outcome(["passed", "failed"]) == "failed"
    assert aggregate_outcome(["passed", "error"]) == "error"
    assert aggregate_outcome(["passed", "skipped"]) == "partial"
    assert aggregate_outcome(["skipped", "skipped"]) == "skipped"
    assert aggregate_outcome(["xfailed"]) == "skipped"


def test_build_at_evidence_has_every_required_field() -> None:
    rec = record(
        "tests/acceptance/test_at01.py::test_isolation", ["AT-01"], PASS,
        milestone="M0", dataset="synthetic seed v1", duration_s=1.25, reqs=["INV-01"],
    )  # fmt: skip
    doc = build_at_evidence("AT-01", [rec], MATRIX, commit="abc123", environment=ENV, now=NOW)
    assert set(doc) == {
        "id", "milestone", "scenario", "expected", "observed", "commit", "environment",
        "dataset", "trace", "tester", "date",
    }  # fmt: skip
    assert doc["id"] == "AT-01"
    assert doc["milestone"] == "M0"
    assert doc["scenario"] == "Two societies cannot see each other"
    assert doc["expected"] == "Zero cross rows"
    assert doc["observed"] == {"outcome": "passed", "message": None}
    assert doc["commit"] == "abc123"
    assert doc["environment"]["python"] == "3.12.x"
    assert doc["environment"]["simulation"] is False
    assert doc["dataset"] == "synthetic seed v1"
    assert doc["trace"]["pytest_nodeids"] == ["tests/acceptance/test_at01.py::test_isolation"]
    assert doc["trace"]["duration_s"] == 1.25
    assert doc["tester"] == "automated/claude-code"
    assert doc["date"] == "2026-10-05T12:00:00+00:00"
    json.dumps(doc)


def test_failure_message_and_simulation_flag_are_recorded() -> None:
    failing = record("t::f", ["AT-02"], FAIL, message="AssertionError: expected 0 rows, got 3")
    sim = record("t::s", ["AT-02"], PASS, simulation=True)
    doc = build_at_evidence(
        "AT-02", [failing, sim], MATRIX, commit="uncommitted", environment=ENV, now=NOW
    )
    assert doc["observed"]["outcome"] == "failed"
    assert "expected 0 rows, got 3" in doc["observed"]["message"]
    assert doc["environment"]["simulation"] is True
    assert doc["commit"] == "uncommitted"


def test_skip_reason_is_surfaced() -> None:
    skipped = record("t::k", ["AT-05"], {"setup": "skipped"}, message="edge service not built yet")
    doc = build_at_evidence("AT-05", [skipped], MATRIX, commit="c", environment=ENV, now=NOW)
    assert doc["observed"] == {"outcome": "skipped", "message": "edge service not built yet"}


def test_write_outputs_to_temp_dir(tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    records = [
        record("t::a", ["AT-01"], PASS, reqs=["INV-01"], milestone="M0"),
        record("t::b", ["AT-01"], PASS, milestone="M0"),
        record("t::c", ["AT-02"], FAIL, message="boom", milestone="M0"),
        record("t::d", [], PASS, reqs=["GATE-03"]),
    ]
    written = write_outputs(
        records, MATRIX, out, commit="deadbeef", environment=ENV, now=NOW, milestone_filter="M0"
    )
    names = sorted(p.name for p in written)
    assert names == ["AT-01.json", "AT-02.json", "INDEX.md", "_run.json"]
    assert not (out / "AT-05.json").exists()  # never run -> no fabricated evidence

    at1 = json.loads((out / "AT-01.json").read_text())
    assert at1["trace"]["pytest_nodeids"] == ["t::a", "t::b"]
    assert at1["observed"]["outcome"] == "passed"

    run = json.loads((out / "_run.json").read_text())
    assert run["commit"] == "deadbeef"
    assert run["milestone_filter"] == "M0"
    assert [r["nodeid"] for r in run["results"]] == ["t::a", "t::b", "t::c", "t::d"]
    assert run["results"][3]["reqs"] == ["GATE-03"]
    assert run["results"][2]["outcome"] == "failed"

    index = (out / "INDEX.md").read_text()
    assert "| AT-01 | M0 | Two societies cannot see each other | passed |" in index
    assert "| AT-02 | M0 | Role expiry | failed |" in index
    assert "| AT-05 | M1 | Edge offline entry | no evidence yet |" in index
    assert "1 failed" in index
    assert "1 no evidence yet" in index


def test_index_merges_existing_evidence_from_earlier_runs(tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    write_outputs(
        [record("t::a", ["AT-01"], PASS)],
        MATRIX,
        out,
        commit="c1",
        environment=ENV,
        now=NOW,
        milestone_filter=None,
    )
    write_outputs(
        [record("t::c", ["AT-02"], PASS)],
        MATRIX,
        out,
        commit="c2",
        environment=ENV,
        now=NOW,
        milestone_filter=None,
    )
    index = render_index(MATRIX, out, NOW)
    assert "| AT-01 |" in index
    assert "passed | no | c1 |" in index
    assert "passed | no | c2 |" in index


def test_run_json_only_mode_writes_no_evidence_files(tmp_path: Path) -> None:
    target = tmp_path / "run.json"
    written = write_outputs(
        [record("t::a", ["AT-01"], PASS)], MATRIX, tmp_path / "ev", commit="c", environment=ENV,
        now=NOW, milestone_filter=None, write_evidence_files=False, run_json=target,
    )  # fmt: skip
    assert written == [target]
    assert not (tmp_path / "ev").exists()


def test_load_matrix_handles_missing_and_malformed(tmp_path: Path) -> None:
    assert load_matrix(tmp_path / "absent.yaml") == {}
    good = tmp_path / "m.yaml"
    good.write_text(
        yaml.safe_dump({"version": 1, "items": list(MATRIX.values())}), encoding="utf-8"
    )
    assert set(load_matrix(good)) == {"AT-01", "AT-02", "AT-05"}
    bad = tmp_path / "bad.yaml"
    bad.write_text("items: [unclosed", encoding="utf-8")
    import warnings

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert load_matrix(bad) == {}
    assert caught


# --------------------------------------------------------------------------- end to end

E2E_MATRIX = yaml.safe_dump({"version": 1, "items": list(MATRIX.values())})
E2E_TESTS = """
import pytest

@pytest.mark.at("AT-01", dataset="synthetic e2e")
@pytest.mark.req("INV-01")
def test_passes():
    pass

@pytest.mark.at("AT-02")
def test_fails():
    assert 1 == 2, "role expiry not enforced"

@pytest.mark.at("AT-05")
@pytest.mark.simulation
def test_m1_sim():
    pass

@pytest.mark.req("GATE-03")
def test_req_only():
    pass

def test_unmarked():
    pass
"""


def test_end_to_end_evidence_run(tmp_path: Path) -> None:
    out = tmp_path / "out"
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(E2E_MATRIX, encoding="utf-8")
    result = run_pytest(
        tmp_path / "proj", {"test_e2e.py": E2E_TESTS},
        "--evidence", "--evidence-dir", str(out), "--acceptance-matrix", str(matrix), "-m", "at",
    )  # fmt: skip
    assert result.returncode == 1, result.output  # the AT-02 test fails on purpose
    assert "evidence written to" in result.output
    assert sorted(p.name for p in out.iterdir()) == [
        "AT-01.json",
        "AT-02.json",
        "AT-05.json",
        "INDEX.md",
        "_run.json",
    ]

    at1 = json.loads((out / "AT-01.json").read_text())
    assert at1["observed"]["outcome"] == "passed"
    assert at1["dataset"] == "synthetic e2e"
    assert at1["scenario"] == MATRIX["AT-01"]["scenario"]
    assert at1["environment"]["python"].startswith("3.12")
    assert at1["commit"]
    assert at1["trace"]["tests"][0]["nodeid"].endswith("test_e2e.py::test_passes")

    at2 = json.loads((out / "AT-02.json").read_text())
    assert at2["observed"]["outcome"] == "failed"
    assert "role expiry not enforced" in at2["observed"]["message"]

    at5 = json.loads((out / "AT-05.json").read_text())
    assert at5["environment"]["simulation"] is True

    run = json.loads((out / "_run.json").read_text())
    assert len(run["results"]) == 3  # -m at: req-only/unmarked tests were deselected


def test_end_to_end_req_tests_feed_run_json_without_evidence_flag(tmp_path: Path) -> None:
    run_json = tmp_path / "run.json"
    result = run_pytest(
        tmp_path / "proj", {"test_e2e.py": E2E_TESTS},
        "--run-json", str(run_json), "--evidence-dir", str(tmp_path / "ev"), "-k", "req_only or passes",
        "--acceptance-matrix", str(tmp_path / "none.yaml"),
    )  # fmt: skip
    assert result.returncode == 0, result.output
    data = json.loads(run_json.read_text())
    by_node = {r["nodeid"].split("::")[-1]: r for r in data["results"]}
    assert by_node["test_req_only"]["reqs"] == ["GATE-03"]
    assert by_node["test_passes"]["ats"] == ["AT-01"]
    assert not (tmp_path / "ev").exists()


def test_without_flags_nothing_is_written(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = run_pytest(
        tmp_path / "proj", {"test_e2e.py": E2E_TESTS}, "--evidence-dir", str(out), "-k", "passes",
        "--acceptance-matrix", str(tmp_path / "none.yaml"),
    )  # fmt: skip
    assert result.returncode == 0, result.output
    assert not out.exists()
