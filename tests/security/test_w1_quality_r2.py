"""W1 fix round 2: regression tests for the requirements-fidelity and engineering-quality findings Q2-01..Q2-05
and the documentation findings of verification round 1 (README drift, ``.env.example`` completeness,
BLOCKING_DECISIONS honesty, a current TRACEABILITY report).

They started as strict-xfail repros in ``verify_w1_quality_r2.py`` / ``verify_w1_quality_requirements.py`` and were
moved here when the defects were fixed; each asserts the corrected behaviour.
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
import zipfile
from pathlib import Path

import pytest

from dwaar_api.core.config import Settings
from tests._harness.pgfixtures import DbHandle

ROOT = Path(__file__).resolve().parents[2]
LOCALES = ROOT / "packages" / "i18n" / "locales"
TRACE = ROOT / "docs" / "traceability"


def _clean_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("DWAAR_")}
    env.update(extra)
    return env


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# --------------------------------------------------------------------------- Q2-02 / OBS-01: logging
@pytest.mark.parametrize("extra_args", [[], ["--no-access-log"]], ids=["default", "make-api"])
def test_uvicorn_never_writes_the_raw_request_line_to_the_log(
    tmp_path: Path, extra_args: list[str]
) -> None:
    """``uvicorn --no-access-log`` (what ``make api`` runs) used to be undone by ``harden_server_loggers``: every request
    was logged as ``127.0.0.1:port - "GET /v1/<raw path> HTTP/1.1" 404`` (raw path, client address). The access
    logger is dropped now, with or without the flag; ``dwaar_api.access`` records the route TEMPLATE only."""
    port = _free_port()
    logfile = tmp_path / "api.log"
    env = _clean_env(DWAAR_ENV="local", NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env.pop(var, None)
    with logfile.open("wb") as out:
        proc = subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-m",
                "uvicorn",
                "dwaar_api.main:app",
                *extra_args,
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            stdout=out,
            stderr=subprocess.STDOUT,
            env=env,
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
                    f"http://127.0.0.1:{port}/v1/invitations/SECRETPATHTOKEN9876/x?otp=482913",
                    timeout=3,
                ).read()
            time.sleep(0.5)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    text = logfile.read_text()
    assert '"route":"/healthz"' in text.replace(" ", ""), "the app's own access record is missing"
    assert "SECRETPATHTOKEN9876" not in text
    assert "482913" not in text
    assert '"GET /' not in text, "uvicorn.access request lines still reach the log"
    assert "127.0.0.1:" not in text.replace("http://127.0.0.1:", ""), "client ip:port logged"


# --------------------------------------------------------------------------- Q2-04 i18n correctness
@pytest.mark.parametrize("lang", ["hi", "mr"])
def test_brand_name_is_not_translated_into_an_instruction_to_open_the_gate(lang: str) -> None:
    """On a LOCK SCREEN of a gate-access product, 'Open Dwaar to respond.' must not read 'open the gate/door'."""
    text = json.loads((LOCALES / lang / "notifications.json").read_text(encoding="utf-8"))[
        "approval.request.lockscreen.body"
    ]
    assert not re.search(r"द्वार\s+(खोल|उघड)", text), text
    assert "Dwaar" in text, "keep the brand in Latin script next to the word for 'app'"


@pytest.mark.parametrize(
    ("lang", "namespace", "key", "bad"),
    [
        ("hi", "guard", "handover.confirm", "सौंपना पुष्ट करें"),
        ("hi", "visitor", "notice.title", "मेहमान सूचना"),
        ("hi", "finance", "status.unpaid", "अदत्त"),
        ("mr", "visitor", "notice.title", "पाहुणे सूचना"),
        ("mr", "guard", "training.banner", "सराव मोड. कोणतीही खरी नोंद होत नाही."),
    ],
)
def test_reviewed_machine_translation_defects_stay_fixed(
    lang: str, namespace: str, key: str, bad: str
) -> None:
    value = json.loads((LOCALES / lang / f"{namespace}.json").read_text(encoding="utf-8"))[key]
    assert value != bad
    audio = (ROOT / "packages" / "i18n" / "audio" / "prompts.yaml").read_text(encoding="utf-8")
    assert f"spoken: {bad}" not in audio  # the audio script follows the catalogue


# --------------------------------------------------------------------------- Q2-03 traceability honesty
def _trace_report() -> dict[str, object]:
    out = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "trace_check.py"),
            "--stdout",
            "--format",
            "json",
            "--quiet",
            "--no-run-json",
        ],
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
    ).stdout
    return json.loads(out)  # type: ignore[no-any-return]


def test_requirement_evidence_never_cites_files_pytest_does_not_collect() -> None:
    report = _trace_report()
    cited = [
        r["id"]
        for r in report["requirements"]  # type: ignore[attr-defined]
        if any("/verify_" in t for t in r["tested_by"])
    ]
    assert cited == []


def test_done_requires_at_least_one_function_level_test_not_only_a_module_marker() -> None:
    report = _trace_report()
    weak = [
        r["id"]
        for r in report["requirements"]  # type: ignore[attr-defined]
        if r["status"] == "done" and all(t.endswith("::<module>") for t in r["tested_by"])
    ]
    assert weak == []
    by_id = {r["id"]: r for r in report["requirements"]}  # type: ignore[attr-defined]
    assert (
        by_id["ARCH-04"]["status"] != "done"
    )  # nothing tests "service-role credentials only in workers" yet


def test_the_report_says_done_is_not_verified_and_shows_no_verification_without_a_run() -> None:
    report = _trace_report()
    assert report["test_run"] is None
    assert all(r["verified"] is None for r in report["requirements"])  # type: ignore[attr-defined]


def test_committed_traceability_report_is_current(tmp_path: Path) -> None:
    committed = json.loads((TRACE / "TRACEABILITY.json").read_text(encoding="utf-8"))
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "trace_check.py"),
            "--out-dir",
            str(tmp_path),
            "--format",
            "json",
            "--quiet",
            "--no-run-json",
        ],
        check=True,
        cwd=ROOT,
    )
    fresh = json.loads((tmp_path / "TRACEABILITY.json").read_text(encoding="utf-8"))
    assert fresh == committed, "run `make trace` and commit the regenerated TRACEABILITY.md/.json"


# --------------------------------------------------------------------------- Q2-01 packaging (RUN-01)
def _build_wheel(project: str, tmp_path: Path) -> Path:
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
    return wheels[0]


def test_api_wheel_ships_the_sql_migrations(tmp_path: Path) -> None:
    names = zipfile.ZipFile(_build_wheel("services/api", tmp_path)).namelist()
    shipped = {Path(n).name for n in names if "/migrations/" in n and n.endswith(".sql")}
    source = {p.name for p in (ROOT / "services" / "api" / "migrations").glob("*.sql")}
    assert source, "no migrations in the source tree?"
    assert shipped == source, "the wheel must carry exactly the shipped migrations"


def test_common_wheel_ships_the_i18n_catalogues(tmp_path: Path) -> None:
    names = zipfile.ZipFile(_build_wheel("packages/dwaar-common", tmp_path)).namelist()
    shipped = {
        n.split("dwaar_common/locales/", 1)[1] for n in names if "dwaar_common/locales/" in n
    }
    source = {f"{p.parent.name}/{p.name}" for p in (LOCALES).glob("*/*.json")}
    assert source, "no catalogues in the source tree?"
    assert shipped == source


def test_a_non_editable_install_finds_its_migrations_and_catalogues(tmp_path: Path) -> None:
    """The failure of Q2-01 only shows in a real non-editable layout: unpack both wheels into a bare directory
    (a wheel is a zip; pure Python needs nothing more to be 'installed'), put it FIRST on the path and ask the
    modules where they look."""
    site = tmp_path / "site"
    for project, where in (("services/api", "api"), ("packages/dwaar-common", "common")):
        build_dir = tmp_path / where
        build_dir.mkdir()
        zipfile.ZipFile(_build_wheel(project, build_dir)).extractall(site)
    code = (
        "import dwaar_api.core.migrate as m, dwaar_common.i18n as i, sys;"
        "from dwaar_common.i18n import Translator;"
        "print(m.__file__);"
        "print(m.MIGRATIONS_DIR);"
        "print(len(m.shipped_versions()));"
        "print(i.find_locales_dir());"
        "print(Translator().t('errors.not_found', 'hi'))"
    )
    env = _clean_env(PATH=os.environ["PATH"], PYTHONPATH=str(site))
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        check=True,
    ).stdout.splitlines()
    assert out[0].startswith(str(site)), f"imported the editable tree, not the wheel: {out[0]}"
    assert out[1] == str(site / "dwaar_api" / "migrations")
    assert int(out[2]) >= 9
    assert out[3] == str(site / "dwaar_common" / "locales")
    assert out[4] != "errors.not_found", "the message resolved to the raw key"
    assert out[4]


# --------------------------------------------------------------------------- documentation honesty
def test_blocking_decisions_does_not_claim_packs_are_unbuilt_when_they_ship() -> None:
    packs = {p.stem for p in (ROOT / "packages" / "legal-packs" / "packs").glob("*.yaml")}
    doc = (TRACE / "BLOCKING_DECISIONS.md").read_text(encoding="utf-8")
    if "karnataka-aoa-1972" in packs:
        assert "Karnataka pack not built" not in doc
        assert "`karnataka-aoa-1972`" in doc
    if "haryana-group-housing" in packs:
        assert "Haryana pack not built" not in doc
        assert "`haryana-group-housing`" in doc
    assert "not built" not in doc.lower()


def test_blocking_decisions_mentions_every_prd_decision_and_question() -> None:
    doc = (TRACE / "BLOCKING_DECISIONS.md").read_text(encoding="utf-8")
    ids = [f"D-{i:02d}" for i in range(1, 29)] + [f"Q{i}" for i in range(1, 15)]
    assert [i for i in ids if not re.search(rf"\b{i}\b", doc)] == []


def test_blocking_decisions_stays_short_and_says_what_blocks() -> None:
    doc = (TRACE / "BLOCKING_DECISIONS.md").read_text(encoding="utf-8")
    assert len(doc.splitlines()) <= 90
    section_one = doc.split("## 1.", 1)[1].split("## 2.", 1)[0]
    assert "**Nothing.**" in section_one
    assert len(section_one.splitlines()) <= 8


def test_the_m1_gate_that_depends_on_an_m2_table_is_recorded_as_a_decision() -> None:
    text = (ROOT / "DECISIONS.md").read_text(encoding="utf-8") + (
        TRACE / "BLOCKING_DECISIONS.md"
    ).read_text(encoding="utf-8")
    assert "AT-47" in text
    assert "DB-05" in text


def test_readme_matches_the_repository() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Until `dwaar_api.core.migrate` exists" not in readme
    assert "says so if the migration runner is not built yet" not in readme
    assert "dwaar-packs" in readme
    assert "request lines never reach the log" not in readme  # B-009 overstated this (Q2-02)
    layout = next(ln for ln in readme.splitlines() if ln.startswith("packages/"))
    assert "prompts" not in layout or (ROOT / "packages" / "prompts").exists()


def test_env_example_documents_every_settings_field() -> None:
    documented = {
        m.group(1)
        for ln in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
        if (m := re.match(r"^#?\s*(DWAAR_[A-Z0-9_]+)=", ln))
    }
    fields = {f"DWAAR_{name.upper()}" for name in Settings.model_fields}
    assert sorted(fields - documented) == []


def test_env_example_documents_every_variable_the_non_settings_code_reads() -> None:
    documented = set(
        re.findall(r"^#?\s*(DWAAR_[A-Z0-9_]+)=", (ROOT / ".env.example").read_text(), re.M)
    )
    used: set[str] = set()
    for pattern in (
        "packages/dwaar-common/dwaar_common/*.py",
        "services/api/dwaar_api/core/migrate.py",
        "tools/dev/*.py",
        "tools/dev/*.sh",
    ):
        for path in ROOT.glob(pattern):
            used |= set(re.findall(r"\b(DWAAR_[A-Z0-9_]+)\b", path.read_text(encoding="utf-8")))
    used -= {"DWAAR_"}
    assert sorted(used - documented) == []


def test_an_empty_dot_env_value_does_not_boot_with_an_empty_signing_key() -> None:
    """``.env.example`` documents DWAAR_CURSOR_SIGNING_KEY commented out: an empty assignment must never reach
    the application as an empty (accepted) secret."""
    lines = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    assert "DWAAR_CURSOR_SIGNING_KEY=" not in [ln.strip() for ln in lines]


# --------------------------------------------------------------------------- mutation-testing gap (guard)
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
