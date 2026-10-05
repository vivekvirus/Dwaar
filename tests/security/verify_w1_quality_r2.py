"""OPEN findings from the round-2 W1 verification (requirements fidelity, completeness, engineering quality).

Not collected by ``make test`` (file name does not match ``test_*.py``); run explicitly:

    uv run --no-sync pytest tests/security/verify_w1_quality_r2.py -p no:cacheprovider

Every test here is a strict ``xfail`` for a finding that is NOT fixed yet: it XPASSes (and therefore turns
red) the day the defect is fixed, which is the signal to move it to a ``test_w1_*.py`` file and delete the
marker. Findings that round 1 already tracks in ``verify_w1_quality_requirements.py`` (README drift, the
incomplete ``.env.example``, stale TRACEABILITY files, BLOCKING_DECISIONS Q6/Q7 and D-03/D-26/D-27) are still
open and are NOT repeated here.
"""

# ruff: noqa: PT011, S603, S607, E501, PLC0415, RUF001, RUF002, RUF003, S310, BLE001, SIM117

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from tests._harness.pgfixtures import DbHandle

ROOT = Path(__file__).resolve().parents[2]
LOCALES = ROOT / "packages" / "i18n" / "locales"


def _clean_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("DWAAR_")}
    env.update(extra)
    return env


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# --------------------------------------------------------------------------- OBS-01: logging
@pytest.mark.xfail(
    strict=True,
    reason="`uvicorn --no-access-log` (what `make api` runs) does NOT suppress request lines: harden_server_loggers() sets "
    "uvicorn.access propagate=True again, so every request is logged as '127.0.0.1:port - \"GET /v1/<raw path> HTTP/1.1\" 404' "
    "(raw path, client address). README and DECISIONS B-009 claim 'request lines never reach the log'. Only the query string is stripped.",
)
def test_make_api_flag_no_access_log_keeps_raw_request_paths_out_of_the_log(tmp_path: Path) -> None:
    port = _free_port()
    logfile = tmp_path / "api.log"
    with logfile.open("wb") as out:
        proc = subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-m",
                "uvicorn",
                "dwaar_api.main:app",
                "--no-access-log",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            stdout=out,
            stderr=subprocess.STDOUT,
            env=_clean_env(DWAAR_ENV="local"),
            cwd=ROOT,
        )
        try:
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1).read()
                    break
                except Exception:
                    time.sleep(0.3)
            with contextlib.suppress(urllib.error.HTTPError):
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/v1/invitations/SECRETPATHTOKEN9876/x", timeout=3
                ).read()
            time.sleep(0.5)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    text = logfile.read_text()
    assert "/v1/invitations/" in text or "healthz" in text or "request" in text, (
        "no log captured at all"
    )
    assert "SECRETPATHTOKEN9876" not in text
    assert '"GET /' not in text, "uvicorn.access request lines still reach the log"


# --------------------------------------------------------------------------- i18n correctness
@pytest.mark.xfail(
    strict=True,
    reason="hi/mr `approval.request.lockscreen.body` renders 'Open Dwaar to respond.' as 'open the gate/door to respond' "
    "(द्वार खोलें / द्वार उघडा) on a LOCK SCREEN of a gate-access product: the brand name was translated as the common noun. "
    "Keep the brand ('Dwaar' or an unambiguous transliteration) or use a {app_name} placeholder.",
)
@pytest.mark.parametrize("lang", ["hi", "mr"])
def test_brand_name_is_not_translated_into_an_instruction_to_open_the_gate(lang: str) -> None:
    text = json.loads((LOCALES / lang / "notifications.json").read_text(encoding="utf-8"))[
        "approval.request.lockscreen.body"
    ]
    assert not re.search(r"द्वार\s+(खोल|उघड)", text), text


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


# --------------------------------------------------------------------------- traceability honesty
def _trace_report() -> dict[str, object]:
    out = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "trace_check.py"),
            "--stdout",
            "--format",
            "json",
            "--quiet",
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
    ).stdout
    return json.loads(out)  # type: ignore[no-any-return]


@pytest.mark.xfail(
    strict=True,
    reason="trace_check counts tests/security/verify_w1_*.py (not collected by pytest, contain open failing repros) "
    "as `tested_by` evidence for 9 requirements (INV-01, INV-02, IAM-08, IAM-13, IAM-14, ARCH-01, ARCH-03, DB-02, OBS-01)",
)
def test_requirement_evidence_never_cites_files_pytest_does_not_collect() -> None:
    report = _trace_report()
    cited = [
        r["id"]
        for r in report["requirements"]  # type: ignore[attr-defined]
        if any("/verify_" in t for t in r["tested_by"])
    ]
    assert cited == []


@pytest.mark.xfail(
    strict=True,
    reason="`done` is computed from the presence of annotations only (any implemented-in file + any test file + tagged gates), "
    "never from test results: ARCH-04 (service-role credentials only in workers) is `done` on a module-level marker in "
    "test_config.py although there is no worker, no client and no test of the claim",
)
def test_done_requires_at_least_one_function_level_test_not_only_a_module_marker() -> None:
    report = _trace_report()
    weak = [
        r["id"]
        for r in report["requirements"]  # type: ignore[attr-defined]
        if r["status"] == "done" and all(t.endswith("::<module>") for t in r["tested_by"])
    ]
    assert weak == []


# --------------------------------------------------------------------------- platform behaviour
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


# --------------------------------------------------------------------------- documentation completeness
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
    reason="PRD 16 makes AT-47 (DB-05 constraint on an essential amenity) an M1 gate, but amenities (AMEN-01..03) are M2 / slice 7 "
    "in the register while DB-05 is assigned to slice 4: the dependency needs an amenities table at M1. Neither DECISIONS.md "
    "nor BLOCKING_DECISIONS.md records how this is resolved",
)
def test_the_m1_gate_that_depends_on_an_m2_table_is_recorded_as_a_decision() -> None:
    text = (ROOT / "DECISIONS.md").read_text(encoding="utf-8") + (
        ROOT / "docs" / "traceability" / "BLOCKING_DECISIONS.md"
    ).read_text(encoding="utf-8")
    assert "AT-47" in text or "DB-05" in text


@pytest.mark.xfail(
    strict=True,
    reason="Variables read by code but absent from .env.example: DWAAR_LOCALES_DIR (dwaar_common.i18n), DWAAR_PG_ROOT (tools/dev/pg.sh). "
    "(.env.example also lists ~15 variables no code reads yet, e.g. DWAAR_ACCESS_TOKEN_TTL_SECONDS; harmless but unlabelled)",
)
def test_env_example_documents_every_variable_the_non_settings_code_reads() -> None:
    documented = set(
        re.findall(r"^#?\s*(DWAAR_[A-Z0-9_]+)=", (ROOT / ".env.example").read_text(), re.M)
    )
    used: set[str] = set()
    for pattern in ("packages/dwaar-common/dwaar_common/*.py", "tools/dev/*.py", "tools/dev/*.sh"):
        for path in ROOT.glob(pattern):
            used |= set(re.findall(r"\b(DWAAR_[A-Z0-9_]+)\b", path.read_text(encoding="utf-8")))
    used -= {"DWAAR_"}
    assert sorted(used - documented) == []


# --------------------------------------------------------------------------- PRD 5.1 / 7.4 fidelity
PRD_ROLE_CODES = [
    "OWNER_OCC", "OWNER_NR", "TENANT", "FAMILY", "GUARD", "GUARD_SUP", "ESTATE_MGR", "TECHNICIAN",
    "VENDOR_TECH", "TREASURER", "SECRETARY", "COMMITTEE", "AUDITOR", "ORG_ADMIN", "STAFF",
]  # fmt: skip


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


# --------------------------------------------------------------------------- mutation-testing gaps (guards, expected to PASS today)
def test_token_bucket_never_accumulates_more_than_its_capacity(db: DbHandle) -> None:
    """Mutation survivor: deleting ``least(p_capacity, ...)`` from dwaar_rate_limit_take (0007) left the whole suite green.

    Without the cap an idle OTP key banks unlimited tokens, so a long-quiet phone number can be hammered with a burst.
    Capacity 2, refill 20/s: after 1 s idle an uncapped bucket holds ~20 tokens, a capped one holds 2.
    """

    def take(key: str) -> bool:
        with db.app_conn() as conn:
            row = conn.execute(
                "SELECT allowed FROM dwaar_rate_limit_take(%s, 2, 20.0, 1)", (key,)
            ).fetchone()
        assert row is not None
        return bool(row[0])

    assert take("idle-key") is True  # creates the bucket (starts full) and spends one token
    time.sleep(1.0)
    burst = [take("idle-key") for _ in range(6)]
    # capacity 2, plus at most ~2 tokens refilled while the six calls run (100 ms at 20/s)
    assert burst.count(True) <= 4, burst
    assert burst[0] is True


# --------------------------------------------------------------------------- packaging (deployability, RUN-01)
def _wheel_names(project: str, tmp_path: Path) -> list[str]:
    import zipfile

    if shutil.which("uv") is None:
        pytest.skip("uv not available")
    run = subprocess.run(
        ["uv", "build", "--wheel", str(ROOT / project), "-o", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    wheels = list(tmp_path.glob("*.whl"))
    if run.returncode != 0 or not wheels:
        pytest.skip(f"wheel build not possible here: {run.stderr[-200:]}")
    with zipfile.ZipFile(wheels[0]) as archive:
        return archive.namelist()


@pytest.mark.xfail(
    strict=True,
    reason="The dwaar-api wheel contains no .sql files: services/api/migrations/ sits outside the `dwaar_api` package that hatch ships. "
    "In a non-editable install (production image) MIGRATIONS_DIR resolves to site-packages/migrations, which does not exist: "
    "`python -m dwaar_api.core.migrate up` cannot run and /readyz reports migrations=fail (503) forever",
)
def test_api_wheel_ships_the_sql_migrations(tmp_path: Path) -> None:
    names = _wheel_names("services/api", tmp_path)
    assert any(n.endswith("0001_extensions.sql") for n in names), "no migration file in the wheel"


@pytest.mark.xfail(
    strict=True,
    reason="The dwaar-common wheel contains no i18n catalogues (packages/i18n/locales is outside the package) and find_locales_dir() "
    "only searches parent directories of the module for packages/i18n/locales: in a wheel install every message resolves to the raw key "
    "unless DWAAR_LOCALES_DIR is set (which .env.example does not document)",
)
def test_common_wheel_ships_the_i18n_catalogues(tmp_path: Path) -> None:
    names = _wheel_names("packages/dwaar-common", tmp_path)
    assert any(n.endswith("errors.json") for n in names), "no catalogue in the wheel"
