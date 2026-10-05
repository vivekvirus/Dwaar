"""OPEN findings from the round-2 W1 verification (requirements fidelity, completeness, engineering quality).

Not collected by ``make test`` (file name does not match ``test_*.py``); run explicitly:

    uv run --no-sync pytest tests/security/verify_w1_quality_r2.py -p no:cacheprovider

Every test here is a strict ``xfail`` for a finding that is NOT fixed yet: it XPASSes (and therefore turns
red) the day the defect is fixed, which is the signal to move it to a ``test_w1_*.py`` file and delete the
marker. Fixed findings (Q2-01 wheels, Q2-02 access log, Q2-03 traceability honesty, Q2-04 brand translation,
Q2-05 BLOCKING_DECISIONS, the README and ``.env.example`` drift) live in ``test_w1_quality_r2.py``.
"""

# ruff: noqa: PT011, S603, S607, E501, PLC0415, RUF001, RUF002, RUF003, S310, BLE001, SIM117

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LOCALES = ROOT / "packages" / "i18n" / "locales"


def _clean_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("DWAAR_")}
    env.update(extra)
    return env


PRD_ROLE_CODES = [
    "OWNER_OCC", "OWNER_NR", "TENANT", "FAMILY", "GUARD", "GUARD_SUP", "ESTATE_MGR", "TECHNICIAN",
    "VENDOR_TECH", "TREASURER", "SECRETARY", "COMMITTEE", "AUDITOR", "ORG_ADMIN", "STAFF",
]  # fmt: skip


@pytest.mark.xfail(
    strict=True,
    reason="API `message` (dwaar_common.errors default_message) and the reviewed en catalogue text differ for 11 of 13 codes: "
    "two sources of truth for the same user-facing sentence (the catalogue is the one under COM-02 review).",
)
def test_api_default_messages_equal_the_english_catalogue_text() -> None:
    from dwaar_common.errors import ERROR_CLASSES

    catalogue = json.loads((LOCALES / "en" / "errors.json").read_text(encoding="utf-8"))
    drift = [c.code for c in ERROR_CLASSES if catalogue.get(c.code) != c.default_message]
    assert drift == []


@pytest.mark.xfail(
    strict=True,
    reason="`make acceptance MILESTONE=M0` with no acceptance tests exits 5 (pytest 'no tests collected') and prints nothing about "
    "the four required M0 ATs; the failing exit code is accidental, not a deliberate 'acceptance not passed: AT-01..AT-04 missing'",
)
def test_make_acceptance_without_any_at_tests_says_which_ats_are_missing(tmp_path: Path) -> None:
    if (ROOT / "tests" / "acceptance").exists():
        pytest.skip("acceptance tests exist; the scenario no longer applies")
    run = subprocess.run(
        [
            "make",
            "-C",
            str(ROOT),
            "acceptance",
            "MILESTONE=M0",
            f"PYTEST_ARGS=--evidence-dir {tmp_path}",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        env=_clean_env(PATH=os.environ["PATH"], HOME=os.environ.get("HOME", "/root")),
    )
    out = run.stdout + run.stderr
    assert "AT-01" in out, out[-600:]


@pytest.mark.xfail(
    strict=True,
    reason="`make migrate` (tools/dev/migrate.py) prints a raw Python traceback when the database is down, and "
    "'migrations applied' even when it applied none; dwaar_api.core.migrate's own CLI already handles both properly",
)
def test_make_migrate_with_database_down_is_a_one_line_error_not_a_traceback() -> None:
    run = subprocess.run(
        [sys.executable, "-m", "tools.dev.migrate"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=ROOT,
        env=_clean_env(
            PATH=os.environ["PATH"],
            DWAAR_DATABASE_OWNER_URL="postgresql://dwaar_owner:x@127.0.0.1:1/dwaar",
        ),
    )
    assert run.returncode != 0
    assert "Traceback" not in run.stderr


@pytest.mark.xfail(
    strict=True,
    reason="CI node SBOM step produces an EMPTY CycloneDX document (0 components): cyclonedx-npm at a pnpm workspace root "
    "sees only the root package, not packages/i18n. The job is green and the artifact is hollow",
)
def test_node_sbom_command_used_in_ci_lists_the_workspace_dependencies(tmp_path: Path) -> None:
    if shutil.which("npx") is None:
        pytest.skip("npx not available")
    target = tmp_path / "node.cdx.json"
    run = subprocess.run(
        [
            "npx",
            "--yes",
            "@cyclonedx/cyclonedx-npm",
            "--ignore-npm-errors",
            "--output-format",
            "JSON",
            "--spec-version",
            "1.5",
            "--output-file",
            str(target),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=ROOT,
    )
    if not target.exists():
        pytest.skip(f"cyclonedx-npm could not run here: {run.stderr[-200:]}")
    assert len(json.loads(target.read_text()).get("components", [])) > 0


@pytest.mark.xfail(
    strict=True,
    reason="requirements.yaml header says 'Conventions are documented in docs/traceability/README.md'; the file does not exist "
    "(also: ADR numbers jump from 0007 to 0009)",
)
def test_documents_referenced_by_the_register_exist() -> None:
    header = (ROOT / "docs" / "traceability" / "requirements.yaml").read_text(encoding="utf-8")[
        :1500
    ]
    referenced = re.findall(r"(docs/[A-Za-z0-9_./-]+\.md)", header)
    assert referenced, "register no longer references a doc"
    assert [p for p in referenced if not (ROOT / p).exists()] == []
    adrs = sorted(
        int(p.name[:4]) for p in (ROOT / "docs" / "adr").glob("[0-9][0-9][0-9][0-9]-*.md")
    )
    assert adrs == list(range(adrs[0], adrs[-1] + 1)), f"ADR numbering has gaps: {adrs}"


@pytest.mark.xfail(
    strict=True,
    reason="PRD 5.1 role codes are upper case (OWNER_OCC, GUARD_SUP ...). Permission/RequestContext only accept ^[a-z][a-z0-9_]{0,63}$, "
    "so the PRD codes cannot be used, audit_log.effective_role will not equal the PRD code, and no mapping or role/action matrix "
    "(PRD 19.4) is documented anywhere (grep OWNER_OCC finds nothing in the repo)",
)
@pytest.mark.parametrize("code", PRD_ROLE_CODES)
def test_prd_role_codes_are_accepted_as_roles(code: str) -> None:
    from dwaar_api.core.authz import Permission
    from dwaar_api.core.db import RequestContext

    Permission("probe.read", frozenset({code}))
    RequestContext(actor_role=code)
