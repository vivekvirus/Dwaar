#!/usr/bin/env python3
"""Validate the @dwaar/i18n catalogs, audio prompt manifest and icon map.

REQ: UX-08, INV-11, UX-02, COM-02, UX-04

Errors (exit 1): missing/extra keys between languages, {placeholder} mismatch, empty values, missing audio or
icon for a guard key, audio spoken text with placeholders/empty, missing PRD 12.2 error messages, missing or
inconsistent review_status.json. Warnings (exit 0): unreviewed strings report.

Usage: python tools/i18n_check.py [--root packages/i18n] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

SOURCE = "en"
LANGS = ("en", "hi", "mr")
PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
PRD_ERROR_CODES = (
    "invalid_schema",
    "unauthenticated",
    "not_authorised",
    "not_found",
    "stale_version",
    "duplicate_payload_mismatch",
    "already_decided",
    "request_expired",
    "policy_violation",
    "missing_tax_config",
    "legal_pack_not_approved",
    "rate_limited",
    "dependency_unavailable",
)  # PRD 12.2
REQUIRED_GUARD_KEYS = (
    "tile.guest",
    "tile.delivery",
    "tile.service",
    "nav.scan",
    "nav.parcels",
    "nav.inside",
    "nav.incident",
    "nav.shift",
    "decision.allow",
    "decision.deny",
)
DEFAULT_ROOT = Path(__file__).resolve().parent.parent / "packages" / "i18n"


def load_catalogs(root: Path) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Return {lang: {full_key: value}} and structural errors."""
    errors: list[str] = []
    out: dict[str, dict[str, str]] = {}
    for lang in LANGS:
        d = root / "locales" / lang
        out[lang] = {}
        if not d.is_dir():
            errors.append(f"[{lang}] locale directory missing: {d}")
            continue
        for f in sorted(d.glob("*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                errors.append(f"[{lang}] {f.name}: invalid JSON: {e}")
                continue
            if not isinstance(data, dict):
                errors.append(f"[{lang}] {f.name}: top level must be an object")
                continue
            for k, v in data.items():
                full = f"{f.stem}.{k}"
                if not isinstance(v, str):
                    errors.append(f"[{lang}] {full}: value must be a string")
                    continue
                out[lang][full] = v
    return out, errors


def check_catalogs(cats: dict[str, dict[str, str]]) -> list[str]:
    errs: list[str] = []
    src = cats[SOURCE]
    for lang in LANGS:
        for key, val in cats[lang].items():
            if not val.strip():
                errs.append(f"[{lang}] {key}: empty value")
    for lang in LANGS:
        if lang == SOURCE:
            continue
        for key in sorted(set(src) - set(cats[lang])):
            errs.append(f"[{lang}] {key}: missing (present in {SOURCE})")
        for key in sorted(set(cats[lang]) - set(src)):
            errs.append(f"[{lang}] {key}: extra (absent from {SOURCE})")
        for key in sorted(set(src) & set(cats[lang])):
            a, b = set(PLACEHOLDER.findall(src[key])), set(PLACEHOLDER.findall(cats[lang][key]))
            if a != b:
                errs.append(
                    f"[{lang}] {key}: placeholders {sorted(b)} differ from {SOURCE} {sorted(a)}"
                )
    for code in PRD_ERROR_CODES:
        if f"errors.{code}" not in src:
            errs.append(f"[{SOURCE}] errors.{code}: PRD 12.2 error code has no message")
    for k in REQUIRED_GUARD_KEYS:
        if f"guard.{k}" not in src:
            errs.append(f"[{SOURCE}] guard.{k}: required primary action missing")
    return errs


def _load_yaml(path: Path, errs: list[str]) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        errs.append(f"{path.name}: cannot read: {e}")
        return {}
    return data if isinstance(data, dict) else {}


def check_audio(root: Path, cats: dict[str, dict[str, str]]) -> list[str]:
    errs: list[str] = []
    prompts = _load_yaml(root / "audio" / "prompts.yaml", errs).get("prompts") or {}
    guard_keys = sorted(k for k in cats[SOURCE] if k.startswith("guard."))
    for key in guard_keys:
        entry = prompts.get(key)
        if not isinstance(entry, dict):
            errs.append(f"audio: {key}: no prompt entry")
            continue
        for lang in LANGS:
            e = entry.get(lang)
            if not isinstance(e, dict):
                errs.append(f"audio: {key}[{lang}]: missing")
                continue
            spoken = e.get("spoken")
            if not isinstance(spoken, str) or not spoken.strip():
                errs.append(f"audio: {key}[{lang}]: empty spoken text")
            elif "{" in spoken or "}" in spoken:
                errs.append(f"audio: {key}[{lang}]: spoken text must not contain placeholders")
            dur = e.get("duration_hint_s")
            if not isinstance(dur, (int, float)) or isinstance(dur, bool) or dur <= 0:
                errs.append(f"audio: {key}[{lang}]: duration_hint_s must be a positive number")
            if e.get("status") not in ("unrecorded", "recorded", "reviewed"):
                errs.append(f"audio: {key}[{lang}]: invalid status {e.get('status')!r}")
    for key in sorted(set(prompts) - set(guard_keys)):
        errs.append(f"audio: {key}: prompt for unknown guard key")
    return errs


def check_icons(root: Path, cats: dict[str, dict[str, str]]) -> list[str]:
    errs: list[str] = []
    doc = _load_yaml(root / "icons.yaml", errs)
    icons = doc.get("icons") or {}
    for key in sorted(k for k in cats[SOURCE] if k.startswith("guard.")):
        if not icons.get(key):
            errs.append(f"icons: {key}: no icon mapped")
    for k in sorted(set(icons) - set(cats[SOURCE])):
        errs.append(f"icons: {k}: unknown key")
    allow, deny = icons.get("guard.decision.allow"), icons.get("guard.decision.deny")
    if allow and allow == deny:
        errs.append("icons: allow and deny share an icon; must differ by shape (UX-02)")
    return errs


def check_review(root: Path, cats: dict[str, dict[str, str]]) -> tuple[list[str], list[str]]:
    errs: list[str] = []
    report: list[str] = []
    path = root / "review_status.json"
    try:
        rs = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return [f"review_status.json: cannot read: {e}"], report
    if "COM-02" not in str(rs.get("policy", "")):
        errs.append("review_status.json: policy must reference COM-02 human review")
    required = set(rs.get("human_review_required") or [])
    namespaces = {k.split(".", 1)[0] for k in cats[SOURCE]}
    locales = rs.get("locales") or {}
    for lang in LANGS:
        for n in sorted(namespaces):
            entry = (locales.get(lang) or {}).get(n)
            if not isinstance(entry, dict) or not isinstance(entry.get("machine_drafted"), bool):
                errs.append(f"review_status.json: {lang}/{n}: missing machine_drafted flag")
                continue
            if lang == SOURCE and entry["machine_drafted"]:
                errs.append(
                    f"review_status.json: {lang}/{n}: source must have machine_drafted=false"
                )
            if lang != SOURCE and not entry["machine_drafted"] and not entry.get("human_reviewed"):
                errs.append(
                    f"review_status.json: {lang}/{n}: not machine_drafted yet not human_reviewed"
                )
            if entry.get("human_reviewed") and not entry.get("reviewer"):
                errs.append(f"review_status.json: {lang}/{n}: human_reviewed requires a reviewer")
            if not entry.get("human_reviewed"):
                count = sum(1 for k in cats[lang] if k.split(".", 1)[0] == n)
                tag = " [LEGAL/SAFETY: human review required]" if n in required else ""
                state = "machine-drafted, " if entry["machine_drafted"] else ""
                report.append(f"{lang}/{n}: {count} strings {state}unreviewed{tag}")
    return errs, report


def run(root: Path) -> tuple[list[str], list[str]]:
    cats, errs = load_catalogs(root)
    if errs or not cats.get(SOURCE):
        return errs or ["no English catalog"], []
    errs += check_catalogs(cats)
    errs += check_audio(root, cats)
    errs += check_icons(root, cats)
    e, report = check_review(root, cats)
    return errs + e, report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    errs, report = run(args.root)
    if args.json:
        print(json.dumps({"errors": errs, "unreviewed": report}, ensure_ascii=False, indent=2))
    else:
        for e in errs:
            print(f"ERROR {e}")
        print(f"-- unreviewed string report ({len(report)} sets) --")
        for r in report:
            print(f"WARN  {r}")
        print(f"i18n_check: {len(errs)} error(s)")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
