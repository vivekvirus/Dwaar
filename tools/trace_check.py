#!/usr/bin/env python3
"""Requirement traceability checker for Dwaar (PRD sections 4.3, 19.2 rule 5, 19.6).

Reads the requirement register in ``docs/traceability`` and scans the repository for annotations that tie code,
tests and docs to requirement IDs, then writes ``TRACEABILITY.md`` and ``TRACEABILITY.json`` for a milestone.

Annotation forms (all deterministic, no imports of project code):

* Comment form, in any scanned file: the keyword ``REQ`` (or ``REQS``) followed by a colon and one or more IDs,
  for example ``# REQ`` + ``: GATE-03, GATE-04``.  Other keywords: ``AT`` (links a test to an acceptance test),
  ``ADAPTER`` and ``SIMULATOR`` (``SIM``) which also count as implemented-in and mark the file's role.
* Python tests: ``@pytest.mark.req("GATE-03")`` and ``@pytest.mark.at("AT-04")`` (also ``mark.req``, bare ``req``
  and ``at``, ``pytestmark`` at module level, and marks inside ``pytest.param``), found through the AST.
* Markdown only counts HTML-comment annotations and bare ``KEYWORD: IDs`` lines outside code fences.
* A file whose first ten lines contain ``trace-check: ignore-file`` is skipped (fixtures that quote annotations).

Status per requirement (see ``compute_status``): ``done`` | ``partial`` | ``not-started`` | ``blocked-external``.
Decisions and open questions are reference items: listed, never statused.

``done`` is an ANNOTATION status, not a verification: it means "implemented and tested by at least one collected,
function-level test, with every acceptance gate tagged". Whether those tests PASS comes from a run report
(``docs/evidence/_run.json``, written by ``make acceptance`` / ``pytest --run-json``): when one is present each
requirement gets a ``verification`` block, a failing test downgrades ``done`` to ``partial``, and without a run
report the ``verification`` of every requirement is ``null`` (unknown), never "passing".

Only test files that a runner actually COLLECTS are test evidence (``test_*.py``, ``*_test.py``, ``*.test.ts``,
``*Test.kt``, ``__tests__/``). A file in a test directory that no runner collects (``verify_*.py``, helpers,
fixtures) is "support": its annotations are never counted as tested-by or implemented-in.

Exit codes: 0 success, 1 check failure (orphans with --fail-on-orphans, registry errors with --check-registry),
2 usage or I/O error.
"""

from __future__ import annotations

import argparse
import ast
import difflib
import hashlib
import json
import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:  # PyYAML is the only third-party dependency.
    import yaml
except ImportError:  # pragma: no cover - exercised only on a broken environment
    yaml = None  # type: ignore[assignment]

SCHEMA_VERSION = 1
MILESTONES = ("M0", "M1", "M2", "M3", "M4")
MILESTONE_RANK = {m: i for i, m in enumerate(MILESTONES)}
REGISTRY_DIR = Path("docs") / "traceability"
REQUIREMENTS_FILE = "requirements.yaml"
ACCEPTANCE_FILE = "acceptance_matrix.yaml"
MODULE_MAP_FILE = "module_map.yaml"
PRD_DEFAULT = Path("docs") / "prd" / "Dwaar_Master_PRD_v2.0.txt"

KINDS = (
    "requirement",
    "invariant",
    "acceptance",
    "ai-feature",
    "nfr",
    "security",
    "decision",
    "guardrail",
    "db-invariant",
    "arch",
    "runbook",
    "open-question",
)
REFERENCE_KINDS = frozenset(
    {"decision", "open-question"}
)  # recorded, not implementable: never statused
PRIORITIES = ("P0", "P1", "P2")
LABELS = ("LEGAL", "CA", "VERIFY", "TBD")
STATUSES = ("not-started", "partial", "done", "blocked-external")
ITEM_KEYS = (
    "id",
    "kind",
    "area",
    "title",
    "priority",
    "release",
    "release_notes",
    "labels",
    "prd_section",
    "prd_page",
    "slice",
    "module",
    "status",
)
# External dependency kinds (module_map external_dependencies[].kind).
INTEGRATION_KINDS = frozenset(
    {"provider", "hardware", "partner"}
)  # need adapter + simulator evidence
APPROVAL_KINDS = frozenset(
    {"approval", "field", "data"}
)  # need implementation + tests; the approval is outside code
MAX_TITLE_WORDS = 14
MAX_FILE_BYTES = 1_500_000

# --------------------------------------------------------------------------------------------- id grammar
_ID = r"(?:AI-[A-Z]\d{2}|[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d{1,3}|[GQ]\d{1,2})"
_IDLIST = rf"{_ID}(?:\s*[,;/]\s*{_ID}|\s+{_ID})*"
_KEYS = r"REQS?|AT|ADAPTER|SIMULATOR|SIM"
ID_RE = re.compile(rf"(?<![A-Za-z0-9_-]){_ID}(?![A-Za-z0-9_])")
COMMENT_ANN_RE = re.compile(
    rf"(?:#|//|--|/\*|\*|<!--)\s*(?P<key>{_KEYS})\s*:\s*(?P<ids>{_IDLIST})(?![A-Za-z0-9_])"
)
LINESTART_ANN_RE = re.compile(
    rf"^\s*(?:[-*]\s+)?(?P<key>{_KEYS})\s*:\s*(?P<ids>{_IDLIST})(?![A-Za-z0-9_])"
)
HTML_ANN_RE = re.compile(rf"<!--\s*(?P<key>{_KEYS})\s*:\s*(?P<ids>{_IDLIST})(?![A-Za-z0-9_])")
KEY_KIND = {
    "REQ": "req",
    "REQS": "req",
    "AT": "at",
    "ADAPTER": "adapter",
    "SIMULATOR": "simulator",
    "SIM": "simulator",
}
IGNORE_FILE_MARKER = "trace-check: ignore-file"

SCAN_EXTENSIONS = frozenset(
    {
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".kt",
        ".kts",
        ".java",
        ".sql",
        ".yaml",
        ".yml",
        ".md",
        ".sh",
        ".toml",
    }
)
PRUNE_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".hypothesis",
        "build",
        "dist",
        ".next",
        ".expo",
        ".turbo",
        ".gradle",
        ".idea",
        "coverage",
        "htmlcov",
        ".local",
        "site-packages",
    }
)
# Repo-relative directories never scanned for annotations: the confidential PRD, our generated output and the
# evidence records (evidence is read separately by scan_evidence).
PRUNE_PATHS = frozenset({"docs/prd", "docs/traceability", "docs/evidence"})
TEST_DIR_NAMES = frozenset({"tests", "test", "__tests__", "androidTest", "e2e"})
_TEST_FILE_RE = re.compile(
    r"^(?:test_.*\.py|.*_test\.py|.*\.(?:test|spec)\.(?:ts|tsx|js|jsx|mjs)|.*Tests?\.kt|.*Tests?\.java)$"
)
EVIDENCE_DIR = Path("docs") / "evidence"
EVIDENCE_EXTENSIONS = frozenset({".md", ".json", ".yaml", ".yml", ".txt"})


# --------------------------------------------------------------------------------------------- data classes
@dataclass(frozen=True)
class Annotation:
    kind: str  # req | at | adapter | simulator
    ident: str
    path: str  # posix, repo-relative
    line: int
    category: str  # test (collected) | support (never evidence) | impl
    symbol: str | None = None  # pytest scope for AST marks

    def entry(self) -> str:
        """Stable human reference for tested-by lists."""
        return f"{self.path}::{self.symbol}" if self.symbol else f"{self.path}:{self.line}"


@dataclass
class Registry:
    items: list[dict[str, Any]]
    by_id: dict[str, dict[str, Any]]
    acceptance: list[dict[str, Any]]
    module_map: dict[str, Any]
    digest: str
    source: str = ""

    @property
    def assignments(self) -> dict[str, dict[str, Any]]:
        return self.module_map.get("assignments") or {}

    @property
    def milestone_of_slice(self) -> dict[int, str]:
        return {int(k): v for k, v in (self.module_map.get("milestone_of_slice") or {}).items()}

    @property
    def external_kinds(self) -> dict[str, str]:
        return {e["id"]: e["kind"] for e in (self.module_map.get("external_dependencies") or [])}

    def aliases(self) -> dict[str, str]:
        """Legacy alias -> unified ID, from ``alias=A,B`` tokens in release_notes."""
        out: dict[str, str] = {}
        for it in self.items:
            m = re.search(r"alias=([A-Za-z0-9,\-]+)", it.get("release_notes") or "")
            if m:
                for a in m.group(1).split(","):
                    out[a] = it["id"]
        return out


@dataclass
class ScanResult:
    annotations: list[Annotation] = field(default_factory=list)
    files_scanned: int = 0
    files_ignored: int = 0


# --------------------------------------------------------------------------------------------- registry
class RegistryError(Exception):
    """Raised when the registry files cannot be read at all."""


def _load_yaml(path: Path) -> Any:
    if yaml is None:
        raise RegistryError("PyYAML is required (uv add pyyaml, or install it in the repo venv)")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RegistryError(f"cannot read {path}: {exc}") from exc
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    try:
        return yaml.load(data, Loader=loader), data  # noqa: S506 - SafeLoader variants only
    except yaml.YAMLError as exc:
        raise RegistryError(f"invalid YAML in {path}: {exc}") from exc


def load_registry(root: Path, registry_dir: Path | None = None) -> Registry:
    base = registry_dir or (root / REGISTRY_DIR)
    req, req_bytes = _load_yaml(base / REQUIREMENTS_FILE)
    acc, acc_bytes = _load_yaml(base / ACCEPTANCE_FILE)
    mm, mm_bytes = _load_yaml(base / MODULE_MAP_FILE)
    if not isinstance(req, dict) or not isinstance(req.get("items"), list):
        raise RegistryError(f"{REQUIREMENTS_FILE}: expected a mapping with an items list")
    if not isinstance(acc, dict) or not isinstance(acc.get("items"), list):
        raise RegistryError(f"{ACCEPTANCE_FILE}: expected a mapping with an items list")
    if not isinstance(mm, dict):
        raise RegistryError(f"{MODULE_MAP_FILE}: expected a mapping")
    items = [i for i in req["items"] if isinstance(i, dict)]
    by_id: dict[str, dict[str, Any]] = {}
    for it in items:
        by_id.setdefault(str(it.get("id")), it)
    digest = hashlib.sha256(req_bytes + b"\0" + acc_bytes + b"\0" + mm_bytes).hexdigest()
    return Registry(
        items,
        by_id,
        [a for a in acc["items"] if isinstance(a, dict)],
        mm,
        digest,
        str(req.get("source") or ""),
    )


def validate_registry(reg: Registry) -> list[str]:
    """Structural checks over the three registry files. Returns human-readable errors (empty = valid)."""
    errors: list[str] = []
    mm = reg.module_map
    modules = {m.get("path"): m for m in mm.get("modules") or []}
    if len(modules) != len(mm.get("modules") or []):
        errors.append("module_map: duplicate module paths")
    ext_ids = {e.get("id") for e in mm.get("external_dependencies") or []}
    for e in mm.get("external_dependencies") or []:
        if e.get("kind") not in INTEGRATION_KINDS | APPROVAL_KINDS:
            errors.append(f"module_map: external {e.get('id')} has unknown kind {e.get('kind')!r}")
        if not str(e.get("id", "")).startswith(f"{e.get('kind')}:"):
            errors.append(f"module_map: external id {e.get('id')!r} must start with its kind")
    slice_ids = {s.get("id") for s in mm.get("slices") or []}
    if slice_ids != set(range(1, 10)):
        errors.append(f"module_map: slices must be 1..9, got {sorted(slice_ids, key=str)}")
    ms = reg.milestone_of_slice
    for s in mm.get("slices") or []:
        if ms.get(s.get("id")) != s.get("milestone"):
            errors.append(
                f"module_map: slice {s.get('id')} milestone disagrees with milestone_of_slice"
            )
    seen: set[str] = set()
    ids = [str(i.get("id")) for i in reg.items]
    for i in reg.items:
        rid = str(i.get("id"))
        if rid in seen:
            errors.append(f"requirements: duplicate id {rid}")
        seen.add(rid)
        if tuple(i.keys()) != ITEM_KEYS and set(i.keys()) != set(ITEM_KEYS):
            errors.append(f"{rid}: keys {sorted(i.keys())} differ from the schema")
            continue
        if not isinstance(rid, str) or not ID_RE.fullmatch(rid):
            errors.append(f"{rid!r}: not a valid requirement ID")
        if i["kind"] not in KINDS:
            errors.append(f"{rid}: unknown kind {i['kind']!r}")
        if i["priority"] not in (*PRIORITIES, None):
            errors.append(f"{rid}: bad priority {i['priority']!r}")
        if i["release"] not in (*MILESTONES, None):
            errors.append(f"{rid}: bad release {i['release']!r}")
        if not isinstance(i["labels"], list) or any(x not in LABELS for x in i["labels"]):
            errors.append(f"{rid}: bad labels {i['labels']!r}")
        if i["slice"] is not None and (not isinstance(i["slice"], int) or not 1 <= i["slice"] <= 9):
            errors.append(f"{rid}: slice must be 1..9 or null, got {i['slice']!r}")
        title = i["title"]
        if not isinstance(title, str) or not title.strip() or len(title.split()) > MAX_TITLE_WORDS:
            errors.append(f"{rid}: title must be 1..{MAX_TITLE_WORDS} words")
        if i["status"] not in STATUSES:
            errors.append(f"{rid}: bad status {i['status']!r}")
        if not isinstance(i["prd_page"], int) or i["prd_page"] < 1:
            errors.append(f"{rid}: prd_page must be a positive integer")
        if not isinstance(i["prd_section"], str) or not i["prd_section"]:
            errors.append(f"{rid}: prd_section must be a non-empty string")
        if i["module"] not in modules:
            errors.append(f"{rid}: module {i['module']!r} is not in module_map.yaml")
        if i["kind"] == "ai-feature" and not re.match(r"class=", str(i.get("release_notes") or "")):
            errors.append(f"{rid}: AI features must start release_notes with class=")
    assign = reg.assignments
    for rid in ids:
        if rid not in assign:
            errors.append(f"module_map: no assignment for {rid}")
    for rid, a in assign.items():
        if rid not in reg.by_id:
            errors.append(f"module_map: assignment for unknown id {rid}")
            continue
        for s in a.get("surfaces") or []:
            if s not in modules:
                errors.append(f"module_map: {rid} surface {s!r} is not a module")
        for g in a.get("gates") or []:
            if g not in reg.by_id or reg.by_id[g].get("kind") != "acceptance":
                errors.append(f"module_map: {rid} gate {g!r} is not an acceptance test")
        for e in a.get("external") or []:
            if e not in ext_ids:
                errors.append(f"module_map: {rid} external {e!r} is not in the catalogue")
    # acceptance matrix <-> register
    at_ids = [a.get("id") for a in reg.acceptance]
    expected = [f"AT-{n:02d}" for n in range(1, len(at_ids) + 1)]
    if at_ids != expected:
        errors.append("acceptance_matrix: IDs must be contiguous AT-01..AT-nn in order")
    for a in reg.acceptance:
        if set(a.keys()) != {"id", "milestone", "scenario", "expected", "prd_page"}:
            errors.append(f"acceptance_matrix: {a.get('id')} keys differ from the schema")
        if a.get("milestone") not in MILESTONES:
            errors.append(f"acceptance_matrix: {a.get('id')} bad milestone {a.get('milestone')!r}")
        reg_item = reg.by_id.get(str(a.get("id")))
        if not reg_item or reg_item.get("kind") != "acceptance":
            errors.append(
                f"acceptance_matrix: {a.get('id')} missing from requirements.yaml as kind acceptance"
            )
        elif reg_item.get("release") != a.get("milestone") or reg_item.get("prd_page") != a.get(
            "prd_page"
        ):
            errors.append(
                f"acceptance_matrix: {a.get('id')} disagrees with requirements.yaml on milestone or page"
            )
    reg_at = sorted(str(i["id"]) for i in reg.items if i.get("kind") == "acceptance")
    if reg_at != sorted(str(x) for x in at_ids):
        errors.append("requirements.yaml acceptance items differ from acceptance_matrix.yaml")
    # every acceptance test must gate at least one requirement (links come from the AT scenarios)
    linked = {g for a in assign.values() for g in a.get("gates") or []}
    for at_id in at_ids:
        if at_id not in linked:
            errors.append(f"module_map: {at_id} gates no requirement")
    return errors


# --------------------------------------------------------------------------------------------- PRD checks
# ID-looking tokens in the PRD that are not requirement IDs (document refs, models, units, releases, priorities).
PRD_NON_REQUIREMENT_TOKENS = frozenset(
    {
        "A1",
        "A2",
        "B1",
        "B2",  # source document references
        "BG100",
        "IN865",
        "IP65",
        "RP002-1",
        "RS-485",
        "SHA-256",
        "FY25",  # model, band, rating, spec, cipher, FY labels
        "M0",
        "M1",
        "M2",
        "M3",
        "M4",
        "M7",
        "P0",
        "P1",
        "P2",
        "R1",
        "R3",
        "R4",  # milestones, priorities, Draft A releases
    }
)
PRD_ID_RE = re.compile(
    r"(?<![A-Za-z0-9_/.\-])"
    r"(?:AI-[A-Z]\d{2}|[A-Z]{2,}(?:-[A-Z]+)*-\d{1,3}|D-\d{2}|[GQ]\d{1,2}|[A-Z]{1,3}\d+(?:-\d+)?)"
    r"(?![A-Za-z0-9_\-])"
)


def extract_prd_ids(text: str) -> set[str]:
    """Every ID-looking token in the PRD text (generic regex; the caller decides what is ignorable)."""
    return set(PRD_ID_RE.findall(text))


def check_prd_completeness(reg: Registry, prd_text: str) -> list[str]:
    """Both directions: every PRD token is registered (or a documented alias/non-requirement) and vice versa."""
    errors: list[str] = []
    tokens = extract_prd_ids(prd_text)
    aliases = reg.aliases()
    for tok in sorted(tokens):
        if tok in reg.by_id or tok in aliases or tok in PRD_NON_REQUIREMENT_TOKENS:
            continue
        errors.append(f"PRD token {tok} is not in the register")
    for rid in sorted(reg.by_id):
        if rid not in tokens:
            errors.append(f"register ID {rid} does not occur in the PRD text")
    return errors


# --------------------------------------------------------------------------------------------- scanning
def is_test_path(rel: str) -> bool:
    """Test CODE of any kind: inside a test directory or named like a test file (collected or not)."""
    parts = rel.split("/")
    return any(p in TEST_DIR_NAMES for p in parts[:-1]) or bool(_TEST_FILE_RE.match(parts[-1]))


def is_collected_test(rel: str) -> bool:
    """A file a test runner actually collects (pytest, jest/vitest/playwright, JUnit): the only test EVIDENCE.

    ``tests/security/verify_w1_x.py`` or ``tests/_harness/helpers.py`` are test code but are never collected.
    """
    parts = rel.split("/")
    name = parts[-1]
    if _TEST_FILE_RE.match(name):
        return True
    return name.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs")) and "__tests__" in parts[:-1]


def file_category(rel: str) -> str:
    """``test`` (collected), ``support`` (test code nobody collects: never evidence) or ``impl``."""
    if is_collected_test(rel):
        return "test"
    return "support" if is_test_path(rel) else "impl"


def path_role(rel: str) -> str | None:
    """'simulator' or 'adapter' from the path of an implementation file (simulator wins)."""
    parts = [p.lower() for p in rel.split("/")]
    name = parts[-1]
    stem = name.rsplit(".", 1)[0]
    if (
        any(p in ("simulator", "simulators", "sim", "sims") for p in parts[:-1])
        or "simulator" in stem
        or stem.startswith("sim_")
        or stem.endswith("_sim")
    ):
        return "simulator"
    if any(p in ("adapter", "adapters") for p in parts[:-1]) or "adapter" in stem:
        return "adapter"
    return None


def _scan_lines(rel: str, text: str, category: str, markdown: bool) -> list[Annotation]:
    out: list[Annotation] = []
    in_fence = False
    for no, line in enumerate(text.splitlines(), start=1):
        if markdown:
            stripped = line.lstrip()
            if stripped.startswith("```") or stripped.startswith("~~~"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            matches = list(HTML_ANN_RE.finditer(line))
            if not matches:
                m = LINESTART_ANN_RE.match(line)
                matches = [m] if m else []
        else:
            matches = list(COMMENT_ANN_RE.finditer(line))
            if not matches:
                m = LINESTART_ANN_RE.match(line)
                matches = [m] if m else []
        for m in matches:
            kind = KEY_KIND[m.group("key")]
            for ident in ID_RE.findall(m.group("ids")):
                out.append(Annotation(kind, ident, rel, no, category))
    return out


class _MarkVisitor(ast.NodeVisitor):
    """Collects pytest-style ``req`` and ``at`` marks with the nearest enclosing def or class as scope."""

    def __init__(self, rel: str) -> None:
        self.rel = rel
        self.stack: list[str] = []
        self.found: list[Annotation] = []

    @staticmethod
    def _mark_kind(func: ast.expr) -> str | None:
        if isinstance(func, ast.Name) and func.id in ("req", "at"):
            return func.id
        if isinstance(func, ast.Attribute) and func.attr in ("req", "at"):
            base = func.value
            if isinstance(base, ast.Attribute) and base.attr == "mark":
                return func.attr
            if isinstance(base, ast.Name) and base.id == "mark":
                return func.attr
        return None

    def _scoped(self, node: ast.AST, name: str) -> None:
        self.stack.append(name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._scoped(node, node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._scoped(node, node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self._scoped(node, node.name)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        kind = self._mark_kind(node.func)
        if kind:
            symbol = ".".join(self.stack) or "<module>"
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    self.found.append(
                        Annotation(kind, arg.value.strip(), self.rel, node.lineno, "test", symbol)
                    )
        self.generic_visit(node)


def _scan_python_marks(rel: str, text: str) -> list[Annotation]:
    if "req(" not in text and "at(" not in text:
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    visitor = _MarkVisitor(rel)
    visitor.visit(tree)
    return visitor.found


def is_ignored_file(text: str) -> bool:
    """True when the ignore marker appears in the first ten lines."""
    return IGNORE_FILE_MARKER in "\n".join(text.splitlines()[:10])


def scan_file(rel: str, text: str) -> list[Annotation]:
    """Annotations in one file (pure function: path + content in, annotations out)."""
    if is_ignored_file(text):
        return []
    category = file_category(rel)
    markdown = rel.endswith(".md")
    out: list[Annotation] = []
    if any(k in text for k in ("REQ", "AT:", "ADAPTER", "SIMULATOR", "SIM:")):
        out.extend(_scan_lines(rel, text, category, markdown))
    if rel.endswith(".py") and category == "test":
        out.extend(_scan_python_marks(rel, text))
    return out


def iter_repo_files(root: Path) -> Iterable[tuple[str, Path]]:
    """Yield (posix relative path, absolute path) for scannable files in sorted order."""
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in PRUNE_DIRS
            and not d.endswith(".egg-info")
            and (f"{rel_dir}/{d}" if rel_dir else d) not in PRUNE_PATHS
        )
        for name in sorted(filenames):
            if os.path.splitext(name)[1] not in SCAN_EXTENSIONS:
                continue
            rel = f"{rel_dir}/{name}" if rel_dir else name
            yield rel, Path(dirpath) / name


def scan_repo(root: Path) -> ScanResult:
    result = ScanResult()
    for rel, abspath in iter_repo_files(root):
        try:
            if abspath.stat().st_size > MAX_FILE_BYTES:
                continue
            text = abspath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if is_ignored_file(text):
            result.files_ignored += 1
            continue
        result.files_scanned += 1
        result.annotations.extend(scan_file(rel, text))
    result.annotations.sort(key=lambda a: (a.path, a.line, a.kind, a.ident, a.symbol or ""))
    return result


def scan_evidence(root: Path) -> dict[str, dict[str, Any]]:
    """AT id -> {files: [...], failed: bool} from docs/evidence (file names carry the AT id)."""
    out: dict[str, dict[str, Any]] = {}
    base = root / EVIDENCE_DIR
    if not base.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(dirnames)
        for name in sorted(filenames):
            ext = os.path.splitext(name)[1].lower()
            if ext not in EVIDENCE_EXTENSIONS:
                continue
            rel_path = Path(dirpath, name)
            rel = rel_path.relative_to(root).as_posix()
            ats = sorted(
                set(re.findall(r"AT-\d{2}", rel_path.relative_to(base).as_posix().upper()))
            )
            if not ats:
                continue
            failed = _evidence_failed(rel_path, ext)
            for at in ats:
                rec = out.setdefault(at, {"files": [], "failed": False})
                rec["files"].append(rel)
                rec["failed"] = rec["failed"] or failed
    return out


def _evidence_failed(path: Path, ext: str) -> bool:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if ext in (".json", ".yaml", ".yml") and yaml is not None:
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            return False
        if isinstance(data, dict):
            for key in ("result", "outcome", "status"):
                val = data.get(key)
                if isinstance(val, str) and val.strip().lower() in ("fail", "failed", "error"):
                    return True
        return False
    return bool(re.search(r"\bFAIL(?:ED)?\b", raw[:2000]))


# --------------------------------------------------------------------------------------------- model
def effective_milestone(item: dict[str, Any], reg: Registry) -> str | None:
    """Printed release, else the milestone of the item's build slice, else None (cross-cutting)."""
    if item.get("release"):
        return str(item["release"])
    if item.get("slice"):
        return reg.milestone_of_slice.get(item["slice"])
    return None


def in_scope(item: dict[str, Any], reg: Registry, target: str, exact: bool) -> bool:
    eff = effective_milestone(item, reg)
    if eff is None:
        return not exact  # cross-cutting items apply to every cumulative milestone
    if exact:
        return eff == target
    return MILESTONE_RANK[eff] <= MILESTONE_RANK[target]


def _short(paths: list[str], limit: int = 3) -> str:
    if not paths:
        return "-"
    shown = ", ".join(f"`{p}`" for p in paths[:limit])
    return shown + (f" (+{len(paths) - limit})" if len(paths) > limit else "")


def _roles_by_id(anns: list[Annotation]) -> dict[str, dict[str, set[str]]]:
    """Per ID: files that implement it (impl category), with adapter/simulator roles and test entries."""
    out: dict[str, dict[str, set[str]]] = {}

    def slot(ident: str) -> dict[str, set[str]]:
        return out.setdefault(
            ident,
            {
                "impl": set(),
                "adapter": set(),
                "simulator": set(),
                "tests": set(),
                "at_tests": set(),
            },
        )

    for a in anns:
        if a.category == "support":
            continue  # test code that no runner collects (verify_*, helpers): never evidence
        s = slot(a.ident)
        if a.category == "impl":
            if a.kind in ("req", "adapter", "simulator"):
                s["impl"].add(a.path)
                role = {"adapter": "adapter", "simulator": "simulator"}.get(a.kind) or path_role(
                    a.path
                )
                if role:
                    s[role].add(a.path)
        else:  # test category
            if a.kind == "req":
                s["tests"].add(a.entry())
            elif a.kind == "at":
                s["at_tests"].add(a.entry())
    return out


def compute_status(
    ev: dict[str, set[str]] | None,
    gates: list[str],
    gate_tests: dict[str, set[str]],
    labels: list[str],
    externals: list[str],
    external_kinds: dict[str, str],
) -> tuple[str, list[str], list[str]]:
    """Return (status, blocked_by, gaps).

    * not-started: no implemented-in file and no test mention the ID.
    * blocked-external: the item has an external dependency (label LEGAL/CA/VERIFY/TBD or a catalogued provider,
      hardware, partner, approval, field or data dependency) and its software side exists: for provider, hardware
      and partner dependencies an adapter and a simulator must both exist; for approval-type dependencies an
      implementation and at least one test.
    * done: no external dependency, implemented, tested by at least one function-level test of a COLLECTED test
      file, and every acceptance gate in scope has a tagged test. ``done`` is not "verified": see
      :func:`verification_by_requirement` for what a run report adds.
    * partial: anything else with evidence.
    """
    ev = ev or {
        "impl": set(),
        "adapter": set(),
        "simulator": set(),
        "tests": set(),
        "at_tests": set(),
    }
    has_impl, has_test = bool(ev["impl"]), bool(ev["tests"])
    # A module-level ``pytestmark`` says a file's tests evidence the ID but does not say a test exists FOR it:
    # only a mark on a function (or a class, or a comment in a collected test file) counts as a tested claim.
    has_fn_test = any(not t.endswith("::<module>") for t in ev["tests"])
    blocked_by = sorted(set(labels) | set(externals))
    integration = [e for e in externals if external_kinds.get(e) in INTEGRATION_KINDS]
    gaps: list[str] = []
    if not has_impl:
        gaps.append("no-implementation")
    if not has_test:
        gaps.append("no-tests")
    elif not has_fn_test:
        gaps.append("module-level-marks-only")
    missing_gates = [g for g in gates if not gate_tests.get(g)]
    gaps.extend(f"acceptance-untested:{g}" for g in missing_gates)
    if not has_impl and not has_test:
        return "not-started", blocked_by, gaps
    if blocked_by:
        if integration:
            if not ev["adapter"]:
                gaps.append("no-adapter")
            if not ev["simulator"]:
                gaps.append("no-simulator")
            ok = has_impl and bool(ev["adapter"]) and bool(ev["simulator"])
        else:
            ok = has_impl and has_fn_test
        return ("blocked-external" if ok else "partial"), blocked_by, sorted(set(gaps))
    if has_impl and has_fn_test and not missing_gates:
        return "done", blocked_by, []
    return "partial", blocked_by, gaps


def build_report(
    root: Path,
    reg: Registry,
    scan: ScanResult,
    target: str,
    exact: bool = False,
    run: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if target not in MILESTONE_RANK:
        raise ValueError(f"unknown milestone {target!r}")
    anns = scan.annotations
    per_id = _roles_by_id(anns)
    ext_kinds = reg.external_kinds
    at_tests = {i: sorted(v["at_tests"]) for i, v in per_id.items() if v["at_tests"]}
    evidence = scan_evidence(root)
    verification = verification_by_requirement(run)

    requirements: list[dict[str, Any]] = []
    acceptance: list[dict[str, Any]] = []
    reference = {"decision": 0, "open-question": 0}
    for it in reg.items:
        if not in_scope(it, reg, target, exact):
            continue
        rid = it["id"]
        assign = reg.assignments.get(rid, {})
        if it["kind"] in REFERENCE_KINDS:
            reference[it["kind"]] += 1
            continue
        if it["kind"] == "acceptance":
            tests = sorted(
                per_id.get(rid, {}).get("at_tests", set()) | per_id.get(rid, {}).get("tests", set())
            )
            ev = evidence.get(rid)
            if not tests:
                status = "not-started" if not ev else "partial"
            elif ev and not ev["failed"]:
                status = "done"
            else:
                status = "partial"
            at_meta = next((a for a in reg.acceptance if a.get("id") == rid), {})
            acceptance.append(
                {
                    "id": rid,
                    "milestone": it["release"],
                    "slice": it["slice"],
                    "status": status,
                    "tests": tests,
                    "evidence": sorted(ev["files"]) if ev else [],
                    "evidence_failed": bool(ev and ev["failed"]),
                    "scenario": at_meta.get("scenario"),
                }
            )
            continue
        gates_all = list(assign.get("gates") or [])
        gates = [
            g
            for g in gates_all
            if MILESTONE_RANK[reg.by_id[g]["release"]] <= MILESTONE_RANK[target]
        ]
        ev_rec = per_id.get(rid)
        status, blocked_by, gaps = compute_status(
            ev_rec,
            gates,
            at_tests_as_sets(at_tests),
            list(it.get("labels") or []),
            list(assign.get("external") or []),
            ext_kinds,
        )
        proof = verification.get(rid)
        if proof is not None and proof["failed"] and status == "done":
            status = "partial"
            gaps = [*gaps, f"failing-tests:{proof['failed']}"]
        requirements.append(
            {
                "id": rid,
                "kind": it["kind"],
                "area": it["area"],
                "title": it["title"],
                "priority": it["priority"],
                "release": it["release"],
                "effective_milestone": effective_milestone(it, reg),
                "slice": it["slice"],
                "module": it["module"],
                "labels": list(it.get("labels") or []),
                "status": status,
                "blocked_by": blocked_by,
                "implemented_in": sorted(ev_rec["impl"]) if ev_rec else [],
                "adapter_files": sorted(ev_rec["adapter"]) if ev_rec else [],
                "simulator_files": sorted(ev_rec["simulator"]) if ev_rec else [],
                "tested_by": sorted(ev_rec["tests"]) if ev_rec else [],
                "acceptance_gates": gates,
                "gaps": gaps,
                # None = unknown (no run report, or the run did not execute a test tagged with this ID)
                "verification": proof,
                "verified": None
                if proof is None
                else bool(proof["passed"] and not proof["failed"]),
            }
        )

    known = set(reg.by_id)
    aliases = reg.aliases()
    orphans: list[dict[str, Any]] = []
    for a in anns:
        if a.ident in known:
            continue
        hint = None
        if a.ident in aliases:
            hint = f"legacy Draft B alias of {aliases[a.ident]}"
        else:
            m = re.fullmatch(r"([A-Z][A-Z0-9-]*?)-(\d+)", a.ident)
            if m:
                padded = f"{m.group(1)}-{int(m.group(2)):02d}"
                if padded in known:
                    hint = f"did you mean {padded}"
            if hint is None:
                close = difflib.get_close_matches(a.ident, sorted(known), n=1, cutoff=0.85)
                if close:
                    hint = f"did you mean {close[0]}"
        orphans.append(
            {
                "id": a.ident,
                "annotation": a.kind,
                "path": a.path,
                "line": a.line,
                "scope": a.symbol,
                "hint": hint,
            }
        )

    by_status = dict.fromkeys(("done", "partial", "blocked-external", "not-started"), 0)
    by_priority: dict[str, dict[str, int]] = {}
    for r in requirements:
        by_status[r["status"]] += 1
        row = by_priority.setdefault(r["priority"] or "none", dict.fromkeys(by_status, 0))
        row[r["status"]] += 1
    at_status = dict.fromkeys(("done", "partial", "not-started"), 0)
    for acc in acceptance:
        at_status[acc["status"]] += 1
    return {
        "tool": "tools/trace_check.py",
        "schema_version": SCHEMA_VERSION,
        "milestone": target,
        "scope": "exact" if exact else "cumulative",
        "registry": {
            "source": reg.source,
            "items": len(reg.items),
            "digest": f"sha256:{reg.digest}",
        },
        "test_run": None
        if run is None
        else {
            "commit": run.get("commit"),
            "results": len(run.get("results") or []),
            "milestone_filter": run.get("milestone_filter"),
        },
        "scan": {
            "files_scanned": scan.files_scanned,
            "files_ignored": scan.files_ignored,
            "annotations": len(anns),
        },
        "summary": {
            "requirements_in_scope": len(requirements),
            "by_status": by_status,
            "verified": {
                "verified": sum(1 for r in requirements if r["verified"] is True),
                "failing": sum(1 for r in requirements if r["verified"] is False),
                "unknown": sum(1 for r in requirements if r["verified"] is None),
            },
            "by_priority": {k: by_priority[k] for k in sorted(by_priority)},
            "acceptance_in_scope": len(acceptance),
            "acceptance_by_status": at_status,
            "reference_items": reference,
            "orphans": len(orphans),
        },
        "requirements": requirements,
        "acceptance": acceptance,
        "orphans": orphans,
    }


RUN_REPORT = Path("docs") / "evidence" / "_run.json"


def load_run_report(path: Path) -> dict[str, Any] | None:
    """The pytest run report written by the harness (``--run-json`` / ``--evidence``), or None if unusable."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return None
    return data


def verification_by_requirement(run: dict[str, Any] | None) -> dict[str, dict[str, int]]:
    """Requirement ID -> counts of passed / failed / skipped tests that carry its ``req`` mark in the run report.

    ``xfailed`` and ``skipped`` are never counted as passing; ``error`` counts as failed.
    """
    out: dict[str, dict[str, int]] = {}
    for result in (run or {}).get("results") or []:
        if not isinstance(result, dict):
            continue
        outcome = str(result.get("outcome"))
        bucket = (
            "passed"
            if outcome in ("passed", "xpassed")
            else "failed"
            if outcome in ("failed", "error")
            else "skipped"
        )
        for rid in result.get("reqs") or []:
            row = out.setdefault(str(rid), {"passed": 0, "failed": 0, "skipped": 0})
            row[bucket] += 1
    return out


def at_tests_as_sets(at_tests: dict[str, list[str]]) -> dict[str, set[str]]:
    return {k: set(v) for k, v in at_tests.items()}


# --------------------------------------------------------------------------------------------- rendering
def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    if report["scope"] == "exact":
        scope = f"exactly {report['milestone']}"
    elif report["milestone"] == "M0":
        scope = "M0 only"
    else:
        scope = f"cumulative M0 to {report['milestone']}"
    lines = [
        f"# Requirement traceability: {report['milestone']} ({scope})",
        "",
        "Generated by `tools/trace_check.py` from `docs/traceability/*.yaml` and repository annotations. "
        "Deterministic: no timestamps; the same tree and registry give the same file. Do not edit by hand.",
        "",
        f"Registry digest `{report['registry']['digest'][:19]}`; {report['scan']['files_scanned']} files scanned, "
        f"{report['scan']['annotations']} annotations, {s['orphans']} orphan annotations.",
        "",
        "## Summary",
        "",
        "| Status | Requirements |",
        "|---|---|",
    ]
    for st in ("done", "partial", "blocked-external", "not-started"):
        lines.append(f"| {st} | {s['by_status'][st]} |")
    lines.append(f"| **in scope** | **{s['requirements_in_scope']}** |")
    v = s["verified"]
    lines += [
        "",
        "**Status is not verification.** `done` means annotated, implemented and covered by a function-level test "
        "of a collected test file; it does not say the tests pass. "
        + (
            f"Run report ({report['test_run']['results']} tests at commit `{report['test_run']['commit']}`): "
            f"{v['verified']} requirements verified (every tagged test passed), {v['failing']} failing, "
            f"{v['unknown']} not executed by that run."
            if report["test_run"]
            else "No run report was supplied (`docs/evidence/_run.json`), so every requirement is unverified."
        ),
    ]
    lines += [
        "",
        "| Priority | done | partial | blocked-external | not-started |",
        "|---|---|---|---|---|",
    ]
    for pr, row in s["by_priority"].items():
        lines.append(
            f"| {pr} | {row['done']} | {row['partial']} | {row['blocked-external']} | {row['not-started']} |"
        )
    ats = s["acceptance_by_status"]
    lines += [
        "",
        f"Acceptance tests in scope: {s['acceptance_in_scope']} (done {ats['done']}, partial {ats['partial']}, "
        f"not-started {ats['not-started']}). Reference items not statused: "
        f"{s['reference_items']['decision']} decisions, {s['reference_items']['open-question']} open questions "
        "(see `BLOCKING_DECISIONS.md`).",
        "",
    ]
    lines += ["## Requirements", ""]
    areas: dict[str, list[dict[str, Any]]] = {}
    for r in report["requirements"]:
        areas.setdefault(r["area"], []).append(r)
    for area, rows in areas.items():
        lines += [
            f"### {area}",
            "",
            "| ID | Pri | Rel | Title | Status | Implemented in | Tested by | AT gates | Blocked by |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for r in rows:
            lines.append(
                "| "
                + " | ".join(
                    [
                        r["id"],
                        r["priority"] or "-",
                        r["release"] or "-",
                        _cell(r["title"]),
                        r["status"],
                        _cell(_short(r["implemented_in"])),
                        _cell(_short(r["tested_by"])),
                        ", ".join(r["acceptance_gates"]) or "-",
                        ", ".join(r["blocked_by"]) or "-",
                    ]
                )
                + " |"
            )
        lines.append("")
    lines += ["## Acceptance tests", ""]
    if report["acceptance"]:
        lines += [
            "| Test | Milestone | Slice | Status | Tests | Evidence | Scenario |",
            "|---|---|---|---|---|---|---|",
        ]
        for a in report["acceptance"]:
            ev = "FAILED: " if a["evidence_failed"] else ""
            lines.append(
                f"| {a['id']} | {a['milestone']} | {a['slice'] or '-'} | {a['status']} | {_cell(_short(a['tests']))} "
                f"| {_cell(ev + _short(a['evidence']))} | {_cell(a['scenario'] or '')} |"
            )
    else:
        lines.append("None in scope.")
    lines += ["", "## Orphan annotations", ""]
    if report["orphans"]:
        lines += ["| ID | Annotation | Location | Hint |", "|---|---|---|---|"]
        for o in report["orphans"]:
            where = f"`{o['path']}:{o['line']}`" + (f" ({o['scope']})" if o["scope"] else "")
            lines.append(
                f"| {_cell(o['id'])} | {o['annotation']} | {_cell(where)} | {_cell(o['hint'] or '-')} |"
            )
    else:
        lines.append("None.")
    lines += [
        "",
        "## How status is computed",
        "",
        "- **not-started**: no implementation file and no test mention the ID.",
        "- **done**: no external dependency; at least one implementation file and one FUNCTION-LEVEL test in a "
        "collected test file (a module-level `pytestmark` alone, or a file no runner collects, does not count); every "
        "acceptance test that gates the requirement (up to this milestone) has a test tagged for it. `done` is an "
        "annotation status, NOT a verification: with a run report a failing tagged test downgrades it to partial, "
        "and `verified` in `TRACEABILITY.json` is true only when a tagged test actually passed in that run.",
        "- **blocked-external**: the requirement carries a LEGAL, CA, VERIFY or TBD label or needs a provider, "
        "hardware, partner, approval, field measurement or baseline data, and its software side exists: for "
        "provider, hardware and partner dependencies an adapter and a simulator both exist; otherwise "
        "implementation and tests exist. It is never reported as done.",
        "- **partial**: some evidence, not enough for the rules above. Gaps are listed in `TRACEABILITY.json`.",
        "- Acceptance tests are **done** only with a tagged test and a passing evidence file under `docs/evidence/`.",
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trace_check.py",
        description="Compute requirement traceability for a milestone and write TRACEABILITY.md/.json.",
    )
    p.add_argument(
        "--milestone", choices=MILESTONES, default="M1", help="target milestone (default M1)"
    )
    p.add_argument(
        "--exact",
        action="store_true",
        help="only items whose milestone equals --milestone (default is cumulative M0..milestone)",
    )
    p.add_argument(
        "--format",
        choices=("md", "json", "both", "none"),
        default="both",
        help="files to write into --out-dir (default both; none = check only)",
    )
    p.add_argument(
        "--stdout",
        action="store_true",
        help="print the chosen format to stdout instead of writing files (both prints JSON)",
    )
    p.add_argument(
        "--root", type=Path, default=None, help="repository root (default: parent of tools/)"
    )
    p.add_argument(
        "--out-dir", type=Path, default=None, help="output directory (default docs/traceability)"
    )
    p.add_argument(
        "--fail-on-orphans",
        action="store_true",
        help="exit 1 if any annotation points at an ID that is not in the register",
    )
    p.add_argument(
        "--check-registry",
        action="store_true",
        help="validate the registry files (and PRD completeness when the PRD text exists); exit 1 on errors",
    )
    p.add_argument(
        "--prd",
        type=Path,
        default=None,
        help="PRD text path (default docs/prd/Dwaar_Master_PRD_v2.0.txt)",
    )
    p.add_argument(
        "--run-json",
        type=Path,
        default=None,
        help="pytest run report (default docs/evidence/_run.json when present): adds per-requirement verification",
    )
    p.add_argument(
        "--no-run-json",
        action="store_true",
        help="ignore any run report (deterministic output that depends on the tree and registry only)",
    )
    p.add_argument("--quiet", action="store_true", help="suppress the summary line")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = (args.root or Path(__file__).resolve().parent.parent).resolve()
    try:
        reg = load_registry(root)
    except RegistryError as exc:
        print(f"trace_check: {exc}", file=sys.stderr)
        return 2

    failed = False
    if args.check_registry:
        errors = validate_registry(reg)
        prd_path = args.prd or (root / PRD_DEFAULT)
        if prd_path.is_file():
            errors += check_prd_completeness(reg, prd_path.read_text(encoding="utf-8"))
        elif args.prd is not None:
            print(f"trace_check: PRD text not found: {prd_path}", file=sys.stderr)
            return 2
        elif not args.quiet:
            print(
                "trace_check: PRD text not present; completeness check against the PRD skipped",
                file=sys.stderr,
            )
        for e in errors:
            print(f"registry: {e}", file=sys.stderr)
        if errors:
            failed = True
        elif not args.quiet:
            print(
                f"trace_check: registry OK ({len(reg.items)} items, {len(reg.acceptance)} acceptance tests)"
            )

    if args.format == "none" and not args.stdout and not args.fail_on_orphans:
        return 1 if failed else 0

    scan = scan_repo(root)
    run_path = args.run_json or (root / RUN_REPORT)
    run = None if args.no_run_json or not run_path.is_file() else load_run_report(run_path)
    if args.run_json is not None and not args.no_run_json and run is None:
        print(f"trace_check: run report not readable: {run_path}", file=sys.stderr)
        return 2
    report = build_report(root, reg, scan, args.milestone, args.exact, run)
    if args.stdout:
        sys.stdout.write(render_markdown(report) if args.format == "md" else render_json(report))
    elif args.format != "none":
        out_dir = (args.out_dir or (root / REGISTRY_DIR)).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        if args.format in ("md", "both"):
            (out_dir / "TRACEABILITY.md").write_text(render_markdown(report), encoding="utf-8")
        if args.format in ("json", "both"):
            (out_dir / "TRACEABILITY.json").write_text(render_json(report), encoding="utf-8")
    if not args.quiet:
        s = report["summary"]
        b = s["by_status"]
        print(
            f"trace_check: {report['milestone']} ({report['scope']}): {s['requirements_in_scope']} requirements, "
            f"done {b['done']}, partial {b['partial']}, blocked-external {b['blocked-external']}, "
            f"not-started {b['not-started']}; acceptance {s['acceptance_by_status']}; orphans {s['orphans']}",
            file=sys.stderr if args.stdout else sys.stdout,
        )
    if args.fail_on_orphans and report["orphans"]:
        for o in report["orphans"]:
            print(
                f"orphan: {o['id']} at {o['path']}:{o['line']}"
                + (f" ({o['hint']})" if o["hint"] else ""),
                file=sys.stderr,
            )
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
