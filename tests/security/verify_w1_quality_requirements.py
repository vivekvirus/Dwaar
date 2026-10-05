"""OPEN findings from W1 verification (requirements fidelity / engineering quality, no database).

Not collected by ``make test`` (file name does not match ``test_*.py``); run explicitly:

    uv run --no-sync pytest tests/security/verify_w1_quality_requirements.py -p no:cacheprovider

Every test here is a strict ``xfail`` for a finding that is NOT fixed yet: it XPASSes (and therefore turns red)
the day the defect is fixed, which is the signal to move it to ``test_w1_quality_requirements.py`` and delete
the marker. Tests for fixed findings live in ``tests/security/test_w1_*.py``.
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from dwaar_api.core.config import Settings

ROOT = Path(__file__).resolve().parents[2]
PRD = ROOT / "docs" / "prd" / "Dwaar_Master_PRD_v2.0.txt"
TRACE = ROOT / "docs" / "traceability"
LOCALES = ROOT / "packages" / "i18n" / "locales"

needs_prd = pytest.mark.skipif(not PRD.exists(), reason="PRD text is local-only and not present")


def _prd_lines() -> list[str]:
    # NOT str.splitlines(): the PRD text contains form feeds that splitlines() would treat as breaks.
    return PRD.read_text(encoding="utf-8").split("\n")


def _register() -> dict[str, dict[str, object]]:
    data = yaml.safe_load((TRACE / "requirements.yaml").read_text(encoding="utf-8"))
    return {item["id"]: item for item in data["items"]}


_ID_ROW = re.compile(
    r"^\s{2,}([A-Z][A-Za-z]*(?:-[A-Z0-9]+)*-\d+[A-Za-z]?|AI-[A-Z]+\d+|AI-SYS-\d+)\b\s*(.*)$"
)
_PRI_REL = re.compile(r"\b(P[0-3])\s+(M\d)\b[^\n]*$")


# --------------------------------------------------------------------------- register accuracy


# --------------------------------------------------------------------------- BLOCKING_DECISIONS honesty
@pytest.mark.xfail(
    strict=True,
    reason="BLOCKING_DECISIONS.md Q6/Q7 say the Karnataka and Haryana packs are 'not built' but all three ship in packages/legal-packs/packs",
)
def test_blocking_decisions_does_not_claim_packs_are_unbuilt_when_they_ship() -> None:
    packs = {p.stem for p in (ROOT / "packages" / "legal-packs" / "packs").glob("*.yaml")}
    doc = (TRACE / "BLOCKING_DECISIONS.md").read_text(encoding="utf-8")
    if "karnataka-aoa-1972" in packs:
        assert "Karnataka pack not built" not in doc
    if "haryana-group-housing" in packs:
        assert "Haryana pack not built" not in doc


@pytest.mark.xfail(
    strict=True,
    reason="D-03, D-26, D-27 (target size, pricing tiers, billing unit) are in the PRD register but absent from BLOCKING_DECISIONS.md",
)
def test_blocking_decisions_mentions_every_prd_decision_and_question() -> None:
    doc = (TRACE / "BLOCKING_DECISIONS.md").read_text(encoding="utf-8")
    ids = [f"D-{i:02d}" for i in range(1, 29)] + [f"Q{i}" for i in range(1, 15)]
    assert [i for i in ids if not re.search(rf"\b{i}\b", doc)] == []


@pytest.mark.xfail(
    strict=True,
    reason="README still says tests using `db` are skipped until dwaar_api.core.migrate exists, and that `make migrate` "
    "may report the runner as unbuilt; it exists. README also omits packages/dwaar-packs and lists packages/prompts, "
    "which does not exist",
)
def test_readme_matches_the_repository() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Until `dwaar_api.core.migrate` exists" not in readme
    assert "dwaar-packs" in readme
    assert (ROOT / "packages" / "prompts").exists() or "prompts" not in readme.split(
        "packages/", 1
    )[1].split("\n", 1)[0]


# --------------------------------------------------------------------------- configuration completeness
@pytest.mark.xfail(
    strict=True,
    reason=".env.example omits 9 Settings fields, including DWAAR_CURSOR_SIGNING_KEY which is REQUIRED outside local",
)
def test_env_example_documents_every_settings_field() -> None:
    documented = {
        m.group(1)
        for ln in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
        if (m := re.match(r"^#?\s*(DWAAR_[A-Z0-9_]+)=", ln))
    }
    fields = {f"DWAAR_{name.upper()}" for name in Settings.model_fields}
    assert sorted(fields - documented) == []


# --------------------------------------------------------------------------- logging (OBS-01)


# --------------------------------------------------------------------------- i18n
def _flat(lang: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted((LOCALES / lang).glob("*.json")):
        for key, value in json.loads(path.read_text(encoding="utf-8")).items():
            out[f"{path.stem}.{key}"] = value
    return out


def _placeholders(text: str) -> set[str]:
    return set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", text))


# --------------------------------------------------------------------------- freshness of generated files
@pytest.mark.xfail(
    strict=False,
    reason="TRACEABILITY.json in the tree was generated before the foundation landed (67 files / 7 annotations scanned vs ~160 / ~117)",
)
def test_committed_traceability_report_is_current(tmp_path: Path) -> None:
    committed = json.loads((TRACE / "TRACEABILITY.json").read_text(encoding="utf-8"))
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "tools" / "trace_check.py"),
            "--out-dir",
            str(tmp_path),
            "--format",
            "json",
            "--quiet",
        ],
        check=True,
        cwd=ROOT,
    )
    fresh = json.loads((tmp_path / "TRACEABILITY.json").read_text(encoding="utf-8"))
    assert fresh == committed
