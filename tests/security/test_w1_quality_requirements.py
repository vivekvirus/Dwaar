"""Regression tests from W1 verification and fix round 1, lens REQUIREMENTS FIDELITY / ENGINEERING QUALITY
(no database). Fixed in round 1: Q-02 (API message keys resolve in the i18n catalogs), Q-04 (`make api` does not
write raw paths and queries to the log)."""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from dwaar_common.errors import ERROR_CLASSES, NotAuthorised, NotFound
from dwaar_common.i18n import Translator

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
@needs_prd
def test_register_priority_and_release_match_every_prd_row() -> None:
    reg = _register()
    compared = 0
    mismatches: list[str] = []
    for line in _prd_lines():
        m = _ID_ROW.match(line)
        if not m or m.group(1) not in reg:
            continue
        pr = _PRI_REL.search(m.group(2))
        if not pr:
            continue
        item = reg[m.group(1)]
        compared += 1
        if (pr.group(1), pr.group(2)) != (item["priority"], item["release"]):
            mismatches.append(
                f"{m.group(1)}: prd {pr.groups()} register {item['priority']}/{item['release']}"
            )
    assert compared >= 200, f"parser only matched {compared} rows"
    assert not mismatches, mismatches


@needs_prd
def test_register_ai_feature_release_and_class_match_prd() -> None:
    reg = _register()
    row = re.compile(
        r"^   (AI-[GRCAFISDP]\d+)\s+.*?\s{2,}([ABC](?:/[ABC])?|n/a[^M]*?)\s+(M\d)\+?\s"
    )
    seen = 0
    for line in _prd_lines():
        m = row.match(line + " ")
        if not m:
            continue
        rid, cls, rel = m.groups()
        item = reg[rid]
        seen += 1
        assert item["release"] == rel, (rid, rel, item["release"])
        wanted = re.search(r"class=([^;]+)", str(item["release_notes"] or ""))
        if wanted and not cls.startswith("n/a"):
            assert wanted.group(1).strip() == cls, (rid, cls, wanted.group(1))
    assert seen >= 55, seen


@needs_prd
def test_register_contains_every_requirement_id_printed_in_the_prd() -> None:
    reg = _register()
    text = PRD.read_text(encoding="utf-8")
    tokens = set(re.findall(r"\b([A-Z]{2,6}(?:-[A-Z]{1,3})?-\d{1,2}[a-z]?)\b", text))
    aliases = {
        t for t in tokens if re.fullmatch(r"AI-\d\d", t)
    }  # AI-01..AI-30 are aliases kept in release_notes
    assert sorted(t for t in tokens - aliases if t not in reg) == []
    recorded: set[str] = set()
    for item in reg.values():
        found = re.search(r"alias=([A-Z0-9,-]+)", str(item["release_notes"] or ""))
        if found:
            recorded.update(found.group(1).split(","))
    assert sorted(aliases - recorded) == []


@needs_prd
def test_acceptance_matrix_has_all_48_rows_with_the_prd_milestone() -> None:
    lines = _prd_lines()
    start = next(
        i
        for i, ln in enumerate(lines)
        if "16. End-to-End Acceptance Test Matrix" in ln and i > 2000
    )
    prd: dict[str, str] = {}
    for ln in lines[start : start + 170]:
        m = re.match(r"\s+(AT-\d\d)\s+(M\d)\s+", ln)
        if m:
            prd[m.group(1)] = m.group(2)
    assert len(prd) == 48
    items = yaml.safe_load((TRACE / "acceptance_matrix.yaml").read_text(encoding="utf-8"))["items"]
    assert {i["id"] for i in items} == set(prd)
    assert {i["id"]: i["milestone"] for i in items} == prd
    reg = _register()
    assert {k: v["release"] for k, v in reg.items() if k.startswith("AT-")} == prd


def test_acceptance_matrix_key_numbers_are_the_prd_numbers() -> None:
    by_id = {
        i["id"]: i
        for i in yaml.safe_load((TRACE / "acceptance_matrix.yaml").read_text(encoding="utf-8"))[
            "items"
        ]
    }
    assert "12 percent" in by_id["AT-37"]["expected"] and "18 percent" in by_id["AT-37"]["scenario"]
    assert "200" in by_id["AT-38"]["expected"] and "300" in by_id["AT-38"]["scenario"]
    assert "2,988" in by_id["AT-46"]["expected"] and "12" in by_id["AT-46"]["expected"]
    for needle in ("10 s", "20 s", "35 s", "90 s"):
        assert needle in by_id["AT-40"]["expected"]
    assert "60 seconds" in by_id["AT-39"]["expected"] and "60 seconds" in by_id["AT-44"]["expected"]
    assert "DB-05" in by_id["AT-47"]["expected"]


# --------------------------------------------------------------------------- BLOCKING_DECISIONS honesty


def test_environment_limits_are_disclosed_in_decisions_log() -> None:
    """No Android SDK (B-006) and no pgvector (B-004) are recorded, so the build does not overclaim."""
    doc = (ROOT / "DECISIONS.md").read_text(encoding="utf-8").lower()
    assert "android sdk" in doc
    assert "pgvector" in doc


def test_migrations_never_contain_destructive_statements_on_data() -> None:
    """RUN-01: expand-and-contract only. The audited purge helper (dynamic EXECUTE format) is the one exception."""
    destructive = re.compile(r"(?i)\b(drop\s+table|drop\s+column|truncate\s+table|delete\s+from)\b")
    offenders: dict[str, list[str]] = {}
    for path in sorted((ROOT / "services" / "api" / "migrations").glob("*.sql")):
        for line in path.read_text(encoding="utf-8").splitlines():
            code = line.split("--", 1)[0]
            if destructive.search(code) and "EXECUTE format" not in code:
                offenders.setdefault(path.name, []).append(line.strip())
    assert offenders == {}


# --------------------------------------------------------------------------- configuration completeness


# --------------------------------------------------------------------------- logging (OBS-01)
def test_make_api_does_not_write_raw_paths_and_queries_to_the_log() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    recipe = next(ln for ln in makefile.splitlines() if "uvicorn dwaar_api.main:app" in ln)
    assert "--no-access-log" in recipe or "--log-config" in recipe


# --------------------------------------------------------------------------- i18n
def _flat(lang: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted((LOCALES / lang).glob("*.json")):
        for key, value in json.loads(path.read_text(encoding="utf-8")).items():
            out[f"{path.stem}.{key}"] = value
    return out


def _placeholders(text: str) -> set[str]:
    return set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", text))


@pytest.mark.parametrize("lang", ["hi", "mr"])
def test_catalog_keys_and_placeholders_match_english(lang: str) -> None:
    en, other = _flat("en"), _flat(lang)
    assert set(en) == set(other)
    bad = {
        k: (_placeholders(en[k]), _placeholders(other[k]))
        for k in en
        if _placeholders(en[k]) != _placeholders(other[k])
    }
    assert not bad, bad


@pytest.mark.parametrize("lang", ["hi", "mr"])
def test_hindi_and_marathi_strings_are_really_translated(lang: str) -> None:
    en, other = _flat("en"), _flat(lang)
    devanagari = re.compile("[ऀ-ॿ]")
    allowed_latin = {
        "common.language.en"
    }  # the language's own name stays in its own script (English)
    own_names = {
        "common.language.en",
        "common.language.hi",
        "common.language.mr",
    }  # same in every locale
    untranslated = [
        k for k, v in other.items() if k not in allowed_latin and not devanagari.search(v)
    ]
    assert untranslated == []
    identical = [k for k in en if en[k] == other[k] and k not in own_names]
    assert identical == []


@pytest.mark.parametrize("lang", ["en", "hi", "mr"])
def test_no_catalog_string_relies_on_colour_words(lang: str) -> None:
    colours = {
        "red",
        "green",
        "amber",
        "orange",
        "yellow",
        "blue",
        "लाल",
        "हरा",
        "हरी",
        "पीला",
        "नीला",
        "नारंगी",
        "हिरवा",
        "हिरवी",
        "पिवळा",
        "निळा",
    }
    hits = {
        k: v
        for k, v in _flat(lang).items()
        if colours & {tok.lower() for tok in re.findall(r"[\w\u0900-\u097f]+", v)}
    }
    assert hits == {}


def test_allow_and_deny_use_different_icons_and_both_have_text() -> None:
    icons = yaml.safe_load((ROOT / "packages" / "i18n" / "icons.yaml").read_text(encoding="utf-8"))
    mapping = icons["icons"]
    assert mapping["guard.decision.allow"] != mapping["guard.decision.deny"]
    en = _flat("en")
    assert en["guard.decision.allow"] and en["guard.decision.deny"]
    assert set(icons["colour_independent"]) >= {"guard.decision.allow", "guard.decision.deny"}


def test_every_guard_string_has_an_icon_and_an_audio_prompt_in_all_three_languages() -> None:
    guard_keys = [k for k in _flat("en") if k.startswith("guard.")]
    icons = yaml.safe_load((ROOT / "packages" / "i18n" / "icons.yaml").read_text(encoding="utf-8"))[
        "icons"
    ]
    audio = yaml.safe_load(
        (ROOT / "packages" / "i18n" / "audio" / "prompts.yaml").read_text(encoding="utf-8")
    )["prompts"]
    assert [k for k in guard_keys if k not in icons] == []
    assert [k for k in guard_keys if k not in audio] == []
    for key, clip in audio.items():
        assert set(clip) >= {"en", "hi", "mr"}, key
        for lang in ("en", "hi", "mr"):
            assert not _placeholders(clip[lang]["spoken"]), (key, lang)
            assert clip[lang]["status"] == "unrecorded"  # honest: nothing is recorded yet


def test_error_catalog_has_a_message_for_every_prd_12_2_code_in_every_language() -> None:
    for lang in ("en", "hi", "mr"):
        flat = _flat(lang)
        for cls in ERROR_CLASSES:
            assert f"errors.{cls.code}" in flat, (lang, cls.code)


def test_error_messages_never_distinguish_membership() -> None:
    """404 and 403 texts must not say anything about belonging, membership, existence or access to a society."""
    leaky = re.compile(r"member|belong|resident of|exist|society|not part|access", re.I)
    for lang in ("en", "hi", "mr"):
        flat = _flat(lang)
        assert not leaky.search(flat["errors.not_found"]), lang
    assert not leaky.search(NotFound().message)
    assert not leaky.search(NotAuthorised().message)


def test_api_error_message_keys_resolve_in_the_catalogs() -> None:
    translator = Translator()
    unresolved = []
    for cls in ERROR_CLASSES:
        err = cls(retry_after=3) if cls.__name__ == "RateLimited" else cls()
        if translator.lookup(err.message_key, "en") is None:
            unresolved.append(err.message_key)
    assert unresolved == []


# --------------------------------------------------------------------------- freshness of generated files


def test_trace_check_is_deterministic(tmp_path: Path) -> None:
    outputs: list[bytes] = []
    for run in ("a", "b"):
        out = tmp_path / run
        subprocess.run(  # noqa: S603
            [
                sys.executable,
                str(ROOT / "tools" / "trace_check.py"),
                "--out-dir",
                str(out),
                "--quiet",
            ],
            check=True,
            cwd=ROOT,
        )
        outputs.append(
            (out / "TRACEABILITY.json").read_bytes() + (out / "TRACEABILITY.md").read_bytes()
        )
    assert outputs[0] == outputs[1]


def test_trace_report_never_claims_done_for_requirements_without_a_test(tmp_path: Path) -> None:
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
    report = json.loads((tmp_path / "TRACEABILITY.json").read_text(encoding="utf-8"))
    done = [i for i in report["requirements"] if i["status"] == "done"]
    assert done, "expected at least one done item to examine"
    for item in done:
        assert item.get("tested_by"), item["id"]
        assert item.get("implemented_in"), item["id"]


def test_api_error_message_placeholders_are_supplied_by_the_error_details() -> None:
    """Every placeholder in an emitted error's catalog text is a key of that error's details (or request_id)."""
    translator = Translator()
    for cls in ERROR_CLASSES:
        err = cls(retry_after=3) if cls.__name__ == "RateLimited" else cls()
        for lang in ("en", "hi", "mr"):
            template = translator.lookup(err.message_key, lang)
            assert template is not None, (cls.__name__, lang)
            assert _placeholders(template) <= set(err.details) | {"request_id"}, (
                cls.__name__,
                lang,
            )
