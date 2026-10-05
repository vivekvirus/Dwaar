"""Marker registration and validation."""

from __future__ import annotations

from pathlib import Path

import yaml

from tests.harness._support import run_pytest

MATRIX = yaml.safe_dump(
    {
        "version": 1,
        "items": [
            {"id": "AT-01", "milestone": "M0", "scenario": "s1", "expected": "e1", "prd_page": 46},
            {"id": "AT-05", "milestone": "M1", "scenario": "s5", "expected": "e5", "prd_page": 47},
        ],
    }
)


def run(tmp_path: Path, body: str, *args: str, matrix: bool = True):  # type: ignore[no-untyped-def]
    path = tmp_path / "matrix.yaml"
    if matrix:
        path.write_text(MATRIX, encoding="utf-8")
    return run_pytest(
        tmp_path / "proj", {"test_m.py": body}, "--acceptance-matrix", str(path),
        "--evidence-dir", str(tmp_path / "ev"), *args,
    )  # fmt: skip


def test_all_five_markers_are_registered_and_valid(tmp_path: Path) -> None:
    result = run(
        tmp_path,
        """
        import pytest

        @pytest.mark.req("GATE-03", "AI-SYS-04", "D-10")
        @pytest.mark.at("AT-01")
        @pytest.mark.milestone("M0")
        @pytest.mark.simulation
        @pytest.mark.slow
        def test_ok():
            pass
        """,
    )
    assert result.returncode == 0, result.output
    assert "1 passed" in result.output


def test_unknown_marker_is_rejected_by_strict_markers(tmp_path: Path) -> None:
    result = run(tmp_path, "import pytest\n@pytest.mark.bogus\ndef test_x():\n    pass\n")
    assert result.returncode != 0
    assert "'bogus' not found in `markers`" in result.output


def test_invalid_at_ids_abort_collection(tmp_path: Path) -> None:
    for bad in ('"AT-1"', '"at-01"', '"AT-001"', "1", '"AT-01", "AT-02"'):
        result = run(tmp_path, f"import pytest\n@pytest.mark.at({bad})\ndef test_x():\n    pass\n")
        assert result.returncode == 4, (bad, result.output)
        assert "invalid test markers" in result.output
        assert "test_m.py::test_x" in result.output


def test_at_id_missing_from_matrix_aborts(tmp_path: Path) -> None:
    result = run(tmp_path, 'import pytest\n@pytest.mark.at("AT-99")\ndef test_x():\n    pass\n')
    assert result.returncode == 4
    assert "AT-99 is not in the acceptance matrix" in result.output


def test_at_id_not_checked_when_there_is_no_matrix(tmp_path: Path) -> None:
    result = run(
        tmp_path, 'import pytest\n@pytest.mark.at("AT-99")\ndef test_x():\n    pass\n', matrix=False
    )
    assert result.returncode == 0, result.output


def test_invalid_requirement_ids_abort(tmp_path: Path) -> None:
    for bad in ('"gate-03"', '"GATE03"', '"GATE-"', "42", ""):
        result = run(tmp_path, f"import pytest\n@pytest.mark.req({bad})\ndef test_x():\n    pass\n")
        assert result.returncode == 4, (bad, result.output)
        assert "invalid" in result.output or "takes one or more" in result.output


def test_invalid_milestone_aborts(tmp_path: Path) -> None:
    result = run(tmp_path, 'import pytest\n@pytest.mark.milestone("M9")\ndef test_x():\n    pass\n')
    assert result.returncode == 4
    assert "invalid milestone" in result.output


def test_milestone_must_agree_with_matrix(tmp_path: Path) -> None:
    result = run(
        tmp_path,
        'import pytest\n@pytest.mark.at("AT-05")\n@pytest.mark.milestone("M0")\ndef test_x():\n    pass\n',
    )
    assert result.returncode == 4
    assert "contradicts the acceptance matrix" in result.output


def test_milestone_option_is_cumulative_and_deselects_later_ats(tmp_path: Path) -> None:
    body = """
        import pytest

        @pytest.mark.at("AT-01")
        def test_m0():
            pass

        @pytest.mark.at("AT-05")
        def test_m1():
            pass

        @pytest.mark.req("INV-01")
        def test_req_only():
            pass
    """
    only_m0 = run(tmp_path, body, "--milestone", "M0", "-v")
    assert only_m0.returncode == 0, only_m0.output
    assert "test_m0 PASSED" in only_m0.output
    assert "test_m1" not in only_m0.output.replace("deselected", "")
    assert "test_req_only PASSED" in only_m0.output  # not an AT test: unaffected
    both = run(tmp_path, body, "--milestone", "M1", "-v")
    assert "test_m0 PASSED" in both.output
    assert "test_m1 PASSED" in both.output


def test_at_marker_milestone_is_derived_from_matrix(tmp_path: Path) -> None:
    run_json = tmp_path / "run.json"
    result = run(
        tmp_path,
        'import pytest\n@pytest.mark.at("AT-05")\ndef test_x():\n    pass\n',
        "--run-json",
        str(run_json),
    )
    assert result.returncode == 0, result.output
    import json

    assert json.loads(run_json.read_text())["results"][0]["milestone"] == "M1"
