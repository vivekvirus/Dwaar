"""Tests for tools/i18n_check.py. REQ: UX-08, INV-11, COM-02."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

TOOL = Path(__file__).resolve().parents[1] / "i18n_check.py"
REAL = Path(__file__).resolve().parents[2] / "packages" / "i18n"
spec = importlib.util.spec_from_file_location("i18n_check", TOOL)
assert spec is not None
assert spec.loader is not None
chk = importlib.util.module_from_spec(spec)
sys.modules["i18n_check"] = chk
spec.loader.exec_module(chk)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    dst = tmp_path / "i18n"
    shutil.copytree(REAL, dst, ignore=shutil.ignore_patterns("node_modules", "dist", "src", "test"))
    return dst


def _edit(path: Path, fn: Callable[[Any], object]) -> None:
    data = json.loads(path.read_text("utf-8"))
    fn(data)
    path.write_text(json.dumps(data, ensure_ascii=False), "utf-8")


def test_real_catalogs_pass() -> None:
    errs, report = chk.run(REAL)
    assert errs == []
    assert any("hi/guard" in r and "LEGAL/SAFETY" in r for r in report)
    assert not any(r.startswith("en/") and "machine-drafted" in r for r in report)


def test_main_exit_codes(root: Path) -> None:
    assert chk.main(["--root", str(root)]) == 0
    _edit(root / "locales/hi/common.json", lambda d: d.pop("action.ok"))
    assert chk.main(["--root", str(root)]) == 1


def test_missing_and_extra_keys(root: Path) -> None:
    _edit(root / "locales/mr/common.json", lambda d: (d.pop("action.ok"), d.update({"zzz": "x"})))
    errs, _ = chk.run(root)
    assert any("mr] common.action.ok: missing" in e for e in errs)
    assert any("mr] common.zzz: extra" in e for e in errs)


def test_placeholder_parity(root: Path) -> None:
    _edit(root / "locales/hi/common.json", lambda d: d.update({"unit.label": "यूनिट"}))
    errs, _ = chk.run(root)
    assert any("common.unit.label: placeholders" in e for e in errs)


def test_empty_value(root: Path) -> None:
    _edit(root / "locales/en/common.json", lambda d: d.update({"action.ok": "  "}))
    errs, _ = chk.run(root)
    assert any("common.action.ok: empty" in e for e in errs)


def test_missing_prd_error_code(root: Path) -> None:
    for lang in ("en", "hi", "mr"):
        _edit(root / f"locales/{lang}/errors.json", lambda d: d.pop("rate_limited"))
    errs, _ = chk.run(root)
    assert any("errors.rate_limited" in e for e in errs)


def test_audio_coverage_and_placeholders(root: Path) -> None:
    p = root / "audio/prompts.yaml"
    doc = yaml.safe_load(p.read_text("utf-8"))
    del doc["prompts"]["guard.tile.guest"]
    doc["prompts"]["guard.nav.scan"]["hi"]["spoken"] = "स्कैन {x}"
    doc["prompts"]["guard.nav.shift"]["mr"]["status"] = "bogus"
    p.write_text(yaml.safe_dump(doc, allow_unicode=True), "utf-8")
    errs, _ = chk.run(root)
    assert any("guard.tile.guest: no prompt" in e for e in errs)
    assert any("guard.nav.scan[hi]" in e and "placeholders" in e for e in errs)
    assert any("guard.nav.shift[mr]: invalid status" in e for e in errs)


def test_icons_required_and_distinct(root: Path) -> None:
    p = root / "icons.yaml"
    doc = yaml.safe_load(p.read_text("utf-8"))
    del doc["icons"]["guard.nav.scan"]
    doc["icons"]["guard.decision.deny"] = doc["icons"]["guard.decision.allow"]
    p.write_text(yaml.safe_dump(doc), "utf-8")
    errs, _ = chk.run(root)
    assert any("guard.nav.scan: no icon" in e for e in errs)
    assert any("share an icon" in e for e in errs)


def test_review_status_rules(root: Path) -> None:
    p = root / "review_status.json"
    _edit(p, lambda d: d["locales"]["hi"]["guard"].update({"machine_drafted": False}))
    errs, _ = chk.run(root)
    assert any("hi/guard: not machine_drafted yet not human_reviewed" in e for e in errs)
    _edit(p, lambda d: d["locales"]["en"]["guard"].update({"machine_drafted": True}))
    errs, _ = chk.run(root)
    assert any("en/guard: source must have machine_drafted=false" in e for e in errs)


def test_review_status_missing_namespace(root: Path) -> None:
    _edit(root / "review_status.json", lambda d: d["locales"]["mr"].pop("ops"))
    errs, _ = chk.run(root)
    assert any("mr/ops: missing machine_drafted" in e for e in errs)


def test_invalid_json_reported(root: Path) -> None:
    (root / "locales/hi/ops.json").write_text("{bad", "utf-8")
    errs, _ = chk.run(root)
    assert any("invalid JSON" in e for e in errs)
