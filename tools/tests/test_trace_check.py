"""Tests for tools/trace_check.py and the requirement register in docs/traceability.

Two groups:

* Register tests. PRD-independent ones pin family counts, schema, milestone/slice consistency and the module map,
  so CI (where the confidential PRD text is absent) still guards the register. PRD-backed ones re-derive every ID,
  priority, release, page and section from ``docs/prd/*.txt`` and skip when that file is missing.
* Tool tests that build small fixture trees in ``tmp_path``. Fixture annotations are produced with ``ann()`` so this
  file never contains the literal annotation syntax the scanner looks for (it would otherwise annotate itself).
"""

from __future__ import annotations

import json
import re
import shutil
import time
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

from tools import trace_check as tc

REPO = Path(__file__).resolve().parents[2]
TRACE_DIR = REPO / "docs" / "traceability"
PRD = REPO / "docs" / "prd" / "Dwaar_Master_PRD_v2.0.txt"
needs_prd = pytest.mark.skipif(
    not PRD.is_file(), reason="PRD text is local-only (git-ignored); not present"
)

EXPECTED_FAMILY_COUNTS = {
    "INV": 12, "D": 28, "IAM": 14, "UX": 10, "ARCH": 5, "DB": 8, "SOC": 9, "GATE": 14, "EDGE": 10, "NOTIF": 9,
    "CALL": 2, "PAR": 8, "STAFF": 7, "SHIFT": 2, "OPS": 11, "COM": 6, "AMEN": 3, "GOV": 10, "FIN": 12, "PAY": 11,
    "ERP": 7, "TAX": 5, "EXP": 3, "HW": 7, "VEH": 5, "IOT": 3, "WATER": 3, "FUEL": 2, "EV": 3, "SUS": 1,
    "PRIV": 15, "RIGHTS": 3, "RPT": 7, "PLAT": 5, "AI-SYS": 9, "G": 12, "AI-G": 10, "AI-R": 11, "AI-C": 12,
    "AI-A": 7, "AI-F": 8, "AI-I": 7, "AI-S": 3, "AI-D": 2, "AI-P": 6, "OBS": 3, "RUN": 3, "NFR": 15, "SEC": 10,
    "MIG": 4, "Q": 14, "AT": 48,
}  # fmt: skip
AT_MILESTONES = {
    "M0": [f"AT-{n:02d}" for n in (1, 2, 3, 4)],
    "M1": [f"AT-{n:02d}" for n in (5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 17, 18, 22, 23, 24, 25, 26, 29, 32, 33, 34,
                                   35, 36, 37, 39, 40, 44, 45, 46, 47, 48)],
    "M2": [f"AT-{n:02d}" for n in (9, 10, 19, 20, 21, 27, 28, 38, 42, 43)],
    "M3": [f"AT-{n:02d}" for n in (30, 31, 41)],
}  # fmt: skip
SLICE_GATES = {
    1: ["AT-01", "AT-02"], 2: ["AT-03", "AT-04"], 3: ["AT-05", "AT-06", "AT-07", "AT-08"],
    4: ["AT-11", "AT-12", "AT-13", "AT-40"], 5: ["AT-14", "AT-15", "AT-16", "AT-17", "AT-18"],
    6: ["AT-23", "AT-24", "AT-33", "AT-34"], 7: [], 8: ["AT-09", "AT-10"], 9: [],
}  # fmt: skip
M1_AI_FEATURES = {"AI-R02", "AI-R07", "AI-F01", "AI-R06", "AI-C01", "AI-C05", "AI-C12", "AI-G08"}
# Printed release differs from the milestone of the build slice only here (see release_notes in the register).
RELEASE_SLICE_EXCEPTIONS = {"PRIV-10"}
# Labels not printed on the item's own row: inherited from a section heading or a cited decision (documented).
INHERITED_LABELS = {f"PRIV-{n:02d}" for n in range(1, 16)} | {
    f"RIGHTS-{n:02d}" for n in range(1, 4)
}
INHERITED_LABELS |= {"AMEN-02", "OPS-11", "AI-D01"}


def family(rid: str) -> str:
    if rid.startswith("AI-SYS-"):
        return "AI-SYS"
    if re.fullmatch(r"AI-[A-Z]\d{2}", rid):
        return rid[:4]
    if re.fullmatch(r"D-\d\d", rid):
        return "D"
    if re.fullmatch(r"G\d+", rid):
        return "G"
    if re.fullmatch(r"Q\d+", rid):
        return "Q"
    return rid.split("-")[0]


def ann(key: str, *ids: str) -> str:
    """Annotation text built at runtime so this source never contains the literal syntax."""
    return f"{key}: {', '.join(ids)}"


# ------------------------------------------------------------------------------------------- real register
@pytest.fixture(scope="module")
def reg() -> tc.Registry:
    return tc.load_registry(REPO)


def test_registry_files_exist() -> None:
    for name in ("requirements.yaml", "acceptance_matrix.yaml", "module_map.yaml"):
        assert (TRACE_DIR / name).is_file(), name


def test_registry_is_structurally_valid(reg: tc.Registry) -> None:
    assert tc.validate_registry(reg) == []


def test_register_family_counts(reg: tc.Registry) -> None:
    counts = Counter(family(i["id"]) for i in reg.items)
    assert dict(counts) == EXPECTED_FAMILY_COUNTS
    assert len(reg.items) == sum(EXPECTED_FAMILY_COUNTS.values()) == 444
    assert len({i["id"] for i in reg.items}) == len(reg.items)


def test_ai_catalogue_has_65_features_with_class_and_release(reg: tc.Registry) -> None:
    feats = [i for i in reg.items if i["kind"] == "ai-feature"]
    assert len(feats) == 65
    for f in feats:
        assert re.match(r"class=(A|B|C|A/B|B/C|n/a)\b", f["release_notes"]), f["id"]
        assert f["release"] in ("M1", "M2", "M3", "M4"), f["id"]
        assert f["priority"] is None  # the PRD catalogue prints no priority
    # PRD 4.1: the M1 scope names exactly these AI features
    assert {f["id"] for f in feats if f["release"] == "M1"} == M1_AI_FEATURES
    assert "alias=AI-01" in next(f for f in feats if f["id"] == "AI-R02")["release_notes"]


def test_pay04_hw06_veh04_releases_keep_the_extra_text(reg: tc.Registry) -> None:
    pay04 = reg.by_id["PAY-04"]
    assert (pay04["priority"], pay04["release"]) == ("P0", "M1")
    assert "M2: AutoPay and BBPS" in pay04["release_notes"]
    hw06 = reg.by_id["HW-06"]
    assert hw06["release"] == "M1"
    assert "M2" in hw06["release_notes"]
    veh04 = reg.by_id["VEH-04"]
    assert veh04["release"] == "M2"
    assert "M3" in veh04["release_notes"]
    s01 = reg.by_id["AI-S01"]
    assert s01["release"] == "M3"
    assert "M3+" in s01["release_notes"]


def test_known_labels(reg: tc.Registry) -> None:
    expect = {
        "PAY-05": ["VERIFY"], "TAX-02": ["CA"], "TAX-04": ["CA"], "WATER-03": ["LEGAL"],
        "EV-03": ["LEGAL", "CA"], "D-16": ["LEGAL"], "D-21": ["TBD"], "D-24": ["LEGAL"], "D-25": ["LEGAL"],
        "D-28": ["VERIFY"], "Q4": ["LEGAL"], "Q5": ["VERIFY"], "Q8": ["CA"], "Q9": ["VERIFY"], "Q12": ["TBD"],
        "Q14": ["TBD"], "PRIV-08": ["LEGAL"], "RIGHTS-01": ["LEGAL"], "GATE-01": [],
    }  # fmt: skip
    for rid, labels in expect.items():
        assert reg.by_id[rid]["labels"] == labels, rid


def test_acceptance_matrix_count_and_milestone_coverage(reg: tc.Registry) -> None:
    ats = reg.acceptance
    assert [a["id"] for a in ats] == [f"AT-{n:02d}" for n in range(1, 49)]
    by_ms: dict[str, list[str]] = {}
    for a in ats:
        by_ms.setdefault(a["milestone"], []).append(a["id"])
    assert by_ms == AT_MILESTONES
    assert by_ms["M0"] == ["AT-01", "AT-02", "AT-03", "AT-04"]
    assert sum(len(v) for v in by_ms.values()) == 48
    for a in ats:
        assert set(a) == {"id", "milestone", "scenario", "expected", "prd_page"}
        assert a["scenario"].strip()
        assert a["expected"].strip()
        assert a["prd_page"] in (46, 47)
        assert reg.by_id[a["id"]]["release"] == a["milestone"]
        assert reg.by_id[a["id"]]["kind"] == "acceptance"


def test_release_and_slice_are_consistent(reg: tc.Registry) -> None:
    ms = reg.milestone_of_slice
    for i in reg.items:
        if i["kind"] == "decision" or i["id"] in RELEASE_SLICE_EXCEPTIONS:
            continue
        if i["release"] == "M4":
            assert i["slice"] is None, i["id"]
        elif i["release"] and i["slice"]:
            assert ms[i["slice"]] == i["release"], (
                f"{i['id']}: {i['release']} vs slice {i['slice']}"
            )
    prd10 = reg.by_id["PRIV-10"]
    assert prd10["release"] == "M2"
    assert prd10["slice"] == 6
    assert "AT-23" in prd10["release_notes"]


def test_slice_gates_match_prd_build_slices(reg: tc.Registry) -> None:
    slices = {s["id"]: s for s in reg.module_map["slices"]}
    assert {k: v["gate_ats"] for k, v in slices.items()} == SLICE_GATES
    for sid, gates in SLICE_GATES.items():
        for at in gates:
            assert reg.by_id[at]["slice"] == sid, at
    assert reg.milestone_of_slice == {
        1: "M0",
        2: "M0",
        3: "M1",
        4: "M1",
        5: "M1",
        6: "M1",
        7: "M2",
        8: "M2",
        9: "M3",
    }


def test_module_map_covers_every_requirement(reg: tc.Registry) -> None:
    assert set(reg.assignments) == set(reg.by_id)
    paths = {m["path"] for m in reg.module_map["modules"]}
    used = {i["module"] for i in reg.items} | {
        s for a in reg.assignments.values() for s in a["surfaces"]
    }
    assert paths <= used, f"unused modules: {sorted(paths - used)}"
    for m in reg.module_map["modules"]:
        if m["path"].startswith("services/api/modules/"):
            assert m["physical_path"] == m["path"].replace(
                "services/api/modules/", "services/api/dwaar_api/modules/"
            )
    # every AT gates something; AT-01..04 (M0) gate their M0 requirements
    gated = {g for a in reg.assignments.values() for g in a["gates"]}
    assert gated == {a["id"] for a in reg.acceptance}
    assert "AT-04" in reg.assignments["GATE-03"]["gates"]
    assert "AT-01" in reg.assignments["INV-01"]["gates"]


def test_external_dependencies_are_catalogued_and_spot_checked(reg: tc.Registry) -> None:
    ext = reg.assignments
    assert "provider:payment-aggregator" in ext["PAY-03"]["external"]
    assert "hardware:barrier-controller" in ext["HW-06"]["external"]
    assert "provider:telephony-ivr" in ext["NOTIF-03"]["external"]
    assert "partner:delivery-partner" in ext["PAR-07"]["external"]
    assert ext["GATE-02"]["external"] == []
    kinds = reg.external_kinds
    assert {
        kinds[e] for a in ext.values() for e in a["external"]
    } <= tc.INTEGRATION_KINDS | tc.APPROVAL_KINDS


def test_m0_scope_is_small_and_p0(reg: tc.Registry) -> None:
    m0 = [i for i in reg.items if i["release"] == "M0" and i["kind"] == "requirement"]
    assert {i["id"] for i in m0} == {
        "IAM-01", "IAM-02", "IAM-03", "IAM-04", "IAM-06", "IAM-08", "IAM-13", "IAM-14", "SOC-01", "SOC-02",
        "GATE-01", "GATE-02", "GATE-03", "EDGE-02", "EDGE-03", "EDGE-07", "NOTIF-01",
    }  # fmt: skip
    assert all(i["priority"] == "P0" and i["slice"] in (1, 2) for i in m0)


def test_cli_check_registry_passes_on_real_registry(capsys: pytest.CaptureFixture[str]) -> None:
    code = tc.main(["--check-registry", "--format", "none", "--quiet", "--root", str(REPO)])
    assert code == 0, capsys.readouterr().err


def test_tool_and_its_tests_do_not_annotate_themselves() -> None:
    for path in (REPO / "tools" / "trace_check.py", Path(__file__)):
        rel = path.relative_to(REPO).as_posix()
        assert tc.scan_file(rel, path.read_text(encoding="utf-8")) == [], rel


# ------------------------------------------------------------------------------------------- PRD-backed
class Prd:
    """Minimal PRD text indexer: footers give pages, headings give sections, row starts give lines."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.lines = text.split("\n")
        self.footers = [
            (i, int(m.group(1)))
            for i, line in enumerate(self.lines)
            if (m := re.search(r"Page (\d+) of 61", line))
        ]
        self.heads: list[tuple[int, str]] = []
        for i, line in enumerate(self.lines):
            if i < 158:
                continue
            m = re.match(r"^  (\d+(?:\.\d+)?)\.?\s+[A-Z]", line)
            if m:
                self.heads.append((i, m.group(1)))
            m2 = re.match(r"^  (Appendix [A-F]):", line)
            if m2:
                self.heads.append((i, m2.group(1)))

    def page_of(self, i: int) -> int:
        return next(pn for fi, pn in self.footers if fi >= i)

    def section_of(self, i: int) -> str | None:
        cur = None
        for hi, num in self.heads:
            if hi <= i:
                cur = num
            else:
                break
        return cur

    def row_line(self, rid: str) -> int:
        esc = re.escape(rid)
        for pat in (rf"^\s{{3}}{esc}\s", rf"^\s{{5,}}{esc}:"):
            for i, line in enumerate(self.lines):
                if i >= 158 and re.match(pat, line):
                    return i
        for i, line in enumerate(self.lines):
            if i >= 158 and re.search(rf"(?<![A-Za-z0-9-]){esc}(?![A-Za-z0-9-])", line):
                return i
        raise AssertionError(f"{rid} not found in PRD")

    def row_text(self, i: int) -> str:
        out = [self.lines[i]]
        for line in self.lines[i + 1 :]:
            if not line.strip() or re.match(r"^\s{0,3}\S", line):
                break
            out.append(line)
        return "\n".join(out)


@pytest.fixture(scope="module")
def prd() -> Prd:
    return Prd(PRD.read_text(encoding="utf-8"))


@needs_prd
def test_every_prd_id_token_is_in_the_register(reg: tc.Registry, prd: Prd) -> None:
    tokens = tc.extract_prd_ids(prd.text)
    aliases = reg.aliases()
    unregistered = sorted(
        t
        for t in tokens
        if t not in reg.by_id and t not in aliases and t not in tc.PRD_NON_REQUIREMENT_TOKENS
    )
    assert unregistered == []
    assert tc.check_prd_completeness(reg, prd.text) == []
    # no invented IDs: every register ID occurs in the PRD
    assert sorted(set(reg.by_id) - tokens) == []
    # the ignore list is exactly the non-requirement tokens that occur (no stale entries)
    assert tokens >= tc.PRD_NON_REQUIREMENT_TOKENS


@needs_prd
def test_draft_b_aliases_match_section_11_6(reg: tc.Registry, prd: Prd) -> None:
    start = [i for i, line in enumerate(prd.lines) if line.strip().startswith("11.6 Mapping")][-1]
    pairs = {}
    for line in prd.lines[start + 1 : start + 30]:
        for old, new in re.findall(r"(AI-\d\d)\s+(AI-[A-Z]\d\d)", line):
            pairs[old] = new
    assert len(pairs) == 30
    assert reg.aliases() == pairs
    for new in pairs.values():
        assert new in reg.by_id


@needs_prd
def test_priority_release_page_and_section_match_the_prd(reg: tc.Registry, prd: Prd) -> None:
    table_row = re.compile(r"\s(P[012])\s+(M[0-4])\b")
    cat_row = re.compile(r"\s(A/B|B/C|A|B|C|n/a(?: \(feeds)?)\s+(M[0-4])(\+?)\s")
    checked = Counter[str]()
    for it in reg.items:
        i = prd.row_line(it["id"])
        first = prd.lines[i]
        assert it["prd_page"] == prd.page_of(i), f"{it['id']} page"
        assert it["prd_section"] == prd.section_of(i), f"{it['id']} section"
        if it["kind"] == "ai-feature":
            m = cat_row.search(first)
            assert m, it["id"]
            assert it["release"] == m.group(2), it["id"]
            cls = "n/a" if m.group(1).startswith("n/a") else m.group(1)
            assert it["release_notes"].startswith(f"class={cls}"), it["id"]
            assert it["priority"] is None
            checked["ai"] += 1
        elif it["kind"] == "acceptance":
            m2 = re.match(r"^\s{3}AT-\d\d\s+(M[0-4])\s", first)
            assert m2, it["id"]
            assert it["release"] == m2.group(1), it["id"]
            checked["at"] += 1
        elif (m3 := table_row.search(first)) and it["kind"] == "requirement":
            assert (it["priority"], it["release"]) == (m3.group(1), m3.group(2)), it["id"]
            checked["req"] += 1
        else:
            assert it["priority"] is None, it["id"]
            if it["kind"] == "requirement":  # OBS rows print neither priority nor release
                assert it["release"] is None, it["id"]
    assert checked["ai"] == 65
    assert checked["at"] == 48
    assert checked["req"] == sum(
        1 for i in reg.items if i["kind"] == "requirement" and i["priority"]
    )


@needs_prd
def test_labels_match_the_prd_rows(reg: tc.Registry, prd: Prd) -> None:
    for it in reg.items:
        text = prd.row_text(prd.row_line(it["id"]))
        printed = sorted(set(re.findall(r"\[(LEGAL|CA|VERIFY|TBD)", text)))
        if it["id"] in INHERITED_LABELS:
            assert not printed or sorted(it["labels"]) == printed, it["id"]
            assert it["labels"], it["id"]
        else:
            assert sorted(it["labels"]) == printed, (
                f"{it['id']}: register {it['labels']} vs PRD {printed}"
            )


@needs_prd
def test_titles_are_paraphrases_not_prd_copies(reg: tc.Registry, prd: Prd) -> None:
    words = re.sub(r"[^a-z0-9% ]+", " ", prd.text.lower()).split()
    grams: dict[int, set[tuple[str, ...]]] = {}

    def has(g: tuple[str, ...]) -> bool:
        grams.setdefault(
            len(g), {tuple(words[i : i + len(g)]) for i in range(len(words) - len(g) + 1)}
        )
        return g in grams[len(g)]

    worst = 0.0
    for it in reg.items:
        tw = re.sub(r"[^a-z0-9% ]+", " ", it["title"].lower()).split()
        assert 1 <= len(tw) <= tc.MAX_TITLE_WORDS + 2, it["id"]
        assert len(it["title"].split()) <= tc.MAX_TITLE_WORDS, it["id"]
        best = 0
        for s in range(len(tw)):
            n = best + 1
            while s + n <= len(tw) and has(tuple(tw[s : s + n])):
                best = n
                n += 1
        ratio = best / len(tw)
        worst = max(worst, ratio)
        assert ratio <= 0.65, f"{it['id']} copies the PRD too closely ({ratio:.2f}): {it['title']}"
        assert " ".join(tw) not in " ".join(words), it["id"]
    assert worst > 0  # sanity: the measure sees overlap at all


@needs_prd
def test_acceptance_matrix_matches_prd_rows(reg: tc.Registry, prd: Prd) -> None:
    rows = {}
    for i, line in enumerate(prd.lines):
        m = re.match(r"^\s{3}(AT-\d\d)\s+(M[0-4])\s", line)
        if m:
            rows[m.group(1)] = (m.group(2), prd.page_of(i))
    assert len(rows) == 48
    assert {a["id"]: (a["milestone"], a["prd_page"]) for a in reg.acceptance} == rows


# ------------------------------------------------------------------------------------------- fixture helpers
def write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def item(
    rid: str,
    kind: str = "requirement",
    *,
    pri: str | None = "P0",
    rel: str | None = "M1",
    slc: int | None = 4,
    labels: tuple[str, ...] = (),
    notes: str | None = None,
    area: str = "area-a",
) -> dict[str, Any]:
    return {
        "id": rid, "kind": kind, "area": area, "title": f"Title of {rid}", "priority": pri, "release": rel,
        "release_notes": notes, "labels": list(labels), "prd_section": "9.2", "prd_page": 22, "slice": slc,
        "module": "services/api/modules/visits", "status": "not-started",
    }  # fmt: skip


def mini_items() -> list[dict[str, Any]]:
    return [
        item("GATE-01", rel="M0", slc=2),
        item("GATE-02", rel="M1", slc=3),
        item("PAY-04", rel="M1", slc=5, area="area-b"),
        item("PRIV-08", rel="M1", slc=6, labels=("LEGAL",), area="area-b"),
        item("HW-01", rel="M2", slc=8),
        item("INV-01", "invariant", pri=None, rel=None, slc=1),
        item("DB-05", "db-invariant", pri=None, rel=None, slc=4),
        item(
            "AI-R02",
            "ai-feature",
            pri=None,
            rel="M1",
            slc=4,
            notes="class=B; alias=AI-01; target: x",
        ),
        item("AI-F04", "ai-feature", pri=None, rel="M4", slc=None, notes="class=B; target: x"),
        item("D-14", "decision", pri=None, rel=None, slc=2),
        item("Q4", "open-question", pri=None, rel=None, slc=None),
        item("AT-03", "acceptance", pri=None, rel="M0", slc=2),
        item("AT-12", "acceptance", pri=None, rel="M1", slc=4),
    ]


MINI_ASSIGN: dict[str, dict[str, Any]] = {
    "GATE-01": {"surfaces": [], "gates": ["AT-03", "AT-12"], "external": []},
    "PAY-04": {"surfaces": [], "gates": [], "external": ["provider:payment-aggregator"]},
    "PRIV-08": {"surfaces": [], "gates": [], "external": []},
    "HW-01": {"surfaces": [], "gates": [], "external": ["hardware:barrier-controller"]},
}
MINI_EXTERNALS = [
    {"id": "provider:payment-aggregator", "kind": "provider"},
    {"id": "hardware:barrier-controller", "kind": "hardware"},
    {"id": "approval:counsel", "kind": "approval"},
]


def make_repo(
    root: Path,
    files: dict[str, str] | None = None,
    *,
    items: list[dict[str, Any]] | None = None,
    assign: dict[str, dict[str, Any]] | None = None,
) -> Path:
    items = items if items is not None else mini_items()
    assign = assign if assign is not None else MINI_ASSIGN
    full = {
        i["id"]: assign.get(i["id"], {"surfaces": [], "gates": [], "external": []}) for i in items
    }
    ats = [
        {
            "id": i["id"],
            "milestone": i["release"],
            "scenario": f"scenario {i['id']}",
            "expected": "x",
            "prd_page": 46,
        }
        for i in items
        if i["kind"] == "acceptance"
    ]
    mm = {
        "version": 1,
        "milestone_of_slice": {
            1: "M0",
            2: "M0",
            3: "M1",
            4: "M1",
            5: "M1",
            6: "M1",
            7: "M2",
            8: "M2",
            9: "M3",
        },
        "external_dependencies": MINI_EXTERNALS,
        "assignments": full,
    }
    d = root / "docs" / "traceability"
    d.mkdir(parents=True, exist_ok=True)
    (d / "requirements.yaml").write_text(
        yaml.safe_dump({"version": 1, "source": "fixture", "items": items}, sort_keys=False),
        encoding="utf-8",
    )
    (d / "acceptance_matrix.yaml").write_text(
        yaml.safe_dump({"version": 1, "items": ats}), encoding="utf-8"
    )
    (d / "module_map.yaml").write_text(yaml.safe_dump(mm), encoding="utf-8")
    for rel, text in (files or {}).items():
        write(root, rel, text)
    return root


def report(root: Path, milestone: str = "M1", exact: bool = False) -> dict[str, Any]:
    return tc.build_report(root, tc.load_registry(root), tc.scan_repo(root), milestone, exact)


def row(rep: dict[str, Any], rid: str) -> dict[str, Any]:
    return next(r for r in rep["requirements"] if r["id"] == rid)


def triples(anns: list[tc.Annotation]) -> list[tuple[str, str, str]]:
    return [(a.kind, a.ident, a.category) for a in anns]


# ------------------------------------------------------------------------------------------- annotation scanning
def test_comment_annotations_in_every_language() -> None:
    sources = {
        "services/api/x.py": f"def f():  # {ann('REQ', 'GATE-03')}\n    pass\n",
        "apps/web/x.ts": f"// {ann('REQ', 'GATE-03')}\nexport const a = 1;\n",
        "apps/web/x.tsx": f"const a = <div>{{/* {ann('REQ', 'GATE-03')} */}}</div>;\n",
        "apps/guard/X.kt": f"/**\n * {ann('REQ', 'GATE-03')}\n */\nclass X\n",
        "migrations/0001.sql": f"-- {ann('REQ', 'GATE-03')}\nselect 1;\n",
        "packs/p.yaml": f"# {ann('REQ', 'GATE-03')}\nkey: value\n",
        "docs/guide.md": f"<!-- {ann('REQ', 'GATE-03')} -->\ntext\n",
    }
    for rel, text in sources.items():
        got = tc.scan_file(rel, text)
        assert triples(got) == [("req", "GATE-03", "impl")], rel


def test_python_docstring_line_and_multiple_ids_and_id_forms() -> None:
    text = (
        f'"""Module.\n\n{ann("REQ", "GATE-03", "AI-SYS-04", "AI-R02", "G7", "Q4", "D-14")}\n"""\n'
    )
    got = tc.scan_file("services/api/x.py", text)
    assert [a.ident for a in got] == ["GATE-03", "AI-SYS-04", "AI-R02", "G7", "Q4", "D-14"]
    assert {a.line for a in got} == {3}
    text2 = f"# {ann('REQS', 'GATE-03 GATE-04; IAM-01 / IAM-02 and not-an-id')}\nx = 1\n"
    assert [a.ident for a in tc.scan_file("a.py", text2)] == [
        "GATE-03",
        "GATE-04",
        "IAM-01",
        "IAM-02",
    ]


def test_keywords_map_to_kinds() -> None:
    pairs = (
        ("REQ", "GATE-01"),
        ("AT", "AT-03"),
        ("ADAPTER", "HW-06"),
        ("SIMULATOR", "HW-06"),
        ("SIM", "HW-07"),
    )
    text = "\n".join(f"# {ann(k, i)}" for k, i in pairs)
    got = tc.scan_file("services/edge/x.py", text)
    assert [(a.kind, a.ident) for a in got] == [
        ("req", "GATE-01"), ("at", "AT-03"), ("adapter", "HW-06"), ("simulator", "HW-06"), ("simulator", "HW-07"),
    ]  # fmt: skip


def test_non_annotations_are_ignored() -> None:
    text = "\n".join([
        f"# {ann('REQ', 'not an id')}",  # no ID after the keyword
        "# req: GATE-03",  # lower case
        "x = 'REQ GATE-03'",  # no colon
        f"url = 'http://example.test/{ann('REQ', 'GATE-03')}'",  # not behind a comment introducer
        "# see GATE-03 for details",
    ])  # fmt: skip
    assert tc.scan_file("a.py", text) == []


def test_markdown_ignores_fences_headings_and_prose_but_keeps_bare_lines() -> None:
    text = "\n".join([
        f"# {ann('REQ', 'GATE-01')}",  # heading
        "Reference requirement IDs in code (`" + f"# {ann('REQ', 'GATE-02')}" + "`), as text.",
        "```",
        f"# {ann('REQ', 'GATE-03')}",
        f"{ann('REQ', 'GATE-03')}",
        "```",
        f"{ann('REQ', 'IAM-01')}",
        f"- {ann('REQ', 'IAM-02')}",
        f"<!-- {ann('REQ', 'IAM-03')} -->",
    ])  # fmt: skip
    got = tc.scan_file("docs/runbooks/r.md", text)
    assert [a.ident for a in got] == ["IAM-01", "IAM-02", "IAM-03"]


def test_ignore_file_marker_skips_the_file() -> None:
    text = f"# trace-check: ignore-file\n# {ann('REQ', 'GATE-03')}\n"
    assert tc.scan_file("tests/fixtures/x.py", text) == []
    assert tc.scan_file(
        "tests/fixtures/x.py",
        f"# {ann('REQ', 'GATE-03')}\n" + "\n" * 12 + f"# {tc.IGNORE_FILE_MARKER}\n",
    )


@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        ("tests/integration/visits/test_a.py", True),
        ("services/api/tests/unit/test_b.py", True),
        ("services/api/dwaar_api/modules/visits/service.py", False),
        ("services/api/dwaar_api/modules/visits/foo_test.py", True),
        ("apps/admin-web/src/a.test.tsx", True),
        ("apps/admin-web/src/a.spec.ts", True),
        ("apps/admin-web/src/__tests__/a.ts", True),
        ("apps/guard-android/core/src/test/kotlin/DecisionTest.kt", True),
        ("apps/guard-android/core/src/main/kotlin/Decision.kt", False),
        ("docs/runbooks/breach.md", False),
        ("packages/legal-packs/maharashtra.yaml", False),
        ("tests/acceptance/at_04.py", True),
        ("contest.py", False),
    ],
)
def test_is_test_path(rel: str, expected: bool) -> None:
    assert tc.is_test_path(rel) is expected


@pytest.mark.parametrize(
    ("rel", "role"),
    [
        ("services/edge/adapters/barrier.py", "adapter"),
        ("services/edge/dwaar_edge/adapters/dry_contact/driver.py", "adapter"),
        ("services/api/dwaar_api/modules/payments/razorpay_adapter.py", "adapter"),
        ("services/edge/simulators/barrier.py", "simulator"),
        ("services/edge/adapters/simulator.py", "simulator"),
        ("services/api/dwaar_api/modules/payments/sim_aggregator.py", "simulator"),
        ("services/api/dwaar_api/modules/payments/aggregator_sim.py", "simulator"),
        ("services/api/dwaar_api/modules/payments/service.py", None),
    ],
)
def test_path_role(rel: str, role: str | None) -> None:
    assert tc.path_role(rel) == role


# ------------------------------------------------------------------------------------------- pytest marks (AST)
MARK_SOURCE = """
import pytest
from pytest import mark

pytestmark = [pytest.mark.req("IAM-01"), pytest.mark.at("AT-01")]


@pytest.mark.req("GATE-03", "GATE-04")
@pytest.mark.at("AT-04")
def test_one() -> None:
    pass


class TestGroup:
    @mark.req("PAR-02")
    def test_method(self) -> None:
        def inner() -> None:
            helper = pytest.mark.req("PAR-03")
            assert helper
        inner()


@pytest.mark.req("FIN-03")
class TestWholeClass:
    def test_x(self) -> None:
        pass


@pytest.mark.parametrize("a", [pytest.param(1, marks=pytest.mark.req("PAY-02"))])
def test_param(a: int) -> None:
    pass


@req("EXP-01")
@at("AT-33")
def test_bare() -> None:
    pass


@pytest.mark.req(dynamic_value)
@pytest.mark.req()
def test_nonliteral() -> None:
    other.at("AT-99")
"""


def test_python_marks_are_found_with_their_scope() -> None:
    got = tc.scan_file("tests/integration/x/test_marks.py", MARK_SOURCE)
    pairs = sorted((a.kind, a.ident, a.symbol) for a in got)
    assert pairs == sorted([
        ("req", "IAM-01", "<module>"), ("at", "AT-01", "<module>"),
        ("req", "GATE-03", "test_one"), ("req", "GATE-04", "test_one"), ("at", "AT-04", "test_one"),
        ("req", "PAR-02", "TestGroup.test_method"),
        ("req", "PAR-03", "TestGroup.test_method.inner"),
        ("req", "FIN-03", "TestWholeClass"),
        ("req", "PAY-02", "test_param"),
        ("req", "EXP-01", "test_bare"), ("at", "AT-33", "test_bare"),
    ])  # fmt: skip
    assert all(a.category == "test" for a in got)
    assert {a.entry() for a in got if a.ident == "GATE-03"} == {
        "tests/integration/x/test_marks.py::test_one"
    }


def test_python_marks_in_implementation_files_and_syntax_errors_are_ignored() -> None:
    assert tc.scan_file("services/api/x.py", MARK_SOURCE) == []
    assert (
        tc.scan_file("tests/test_broken.py", 'def test_x(:\n    @pytest.mark.req("GATE-03")\n')
        == []
    )


# ------------------------------------------------------------------------------------------- repo scan
def test_scan_repo_walks_sorted_prunes_and_counts(tmp_path: Path) -> None:
    line = f"# {ann('REQ', 'GATE-01')}\n"
    make_repo(
        tmp_path,
        {
            "services/api/a.py": line,
            "services/api/b.py": "x = 1\n",
            "node_modules/pkg/x.ts": f"// {ann('REQ', 'GATE-01')}\n",
            ".venv/lib/x.py": line,
            "services/api/__pycache__/x.py": line,
            "docs/prd/p.md": f"{ann('REQ', 'GATE-01')}\n",
            "docs/evidence/AT-03.md": f"{ann('REQ', 'GATE-01')}\n",
            "pkg/x.egg-info/y.py": line,
            "web/data.json": f"// {ann('REQ', 'GATE-01')}\n",
            "tests/fixtures/f.py": f"# {tc.IGNORE_FILE_MARKER}\n{line}",
        },
    )
    scan = tc.scan_repo(tmp_path)
    assert [a.path for a in scan.annotations] == ["services/api/a.py"]
    assert scan.files_ignored == 1


def test_scan_repo_is_fast_on_a_large_tree(tmp_path: Path) -> None:
    make_repo(tmp_path)
    for n in range(1500):
        body = f"def f{n}():\n    return {n}\n"
        if n % 10 == 0:
            body = f"# {ann('REQ', 'GATE-01')}\n" + body
        write(tmp_path, f"services/api/mod{n % 30}/f{n}.py", body)
    started = time.perf_counter()
    scan = tc.scan_repo(tmp_path)
    elapsed = time.perf_counter() - started
    assert len([a for a in scan.annotations if a.ident == "GATE-01"]) == 150
    assert elapsed < 10, f"scan took {elapsed:.2f}s"


# ------------------------------------------------------------------------------------------- status logic
def test_nothing_annotated_is_not_started(tmp_path: Path) -> None:
    rep = report(make_repo(tmp_path))
    assert {r["status"] for r in rep["requirements"]} == {"not-started"}
    assert row(rep, "GATE-02")["gaps"] == ["no-implementation", "no-tests"]
    assert rep["summary"]["by_status"] == {
        "done": 0,
        "partial": 0,
        "blocked-external": 0,
        "not-started": 7,
    }


def test_implementation_only_or_tests_only_is_partial(tmp_path: Path) -> None:
    rep = report(
        make_repo(
            tmp_path,
            {
                "services/api/visits.py": f"# {ann('REQ', 'GATE-02')}\n",
                "tests/integration/test_gate.py": f"# {ann('REQ', 'GATE-01')}\n",
            },
        )
    )
    assert row(rep, "GATE-02")["status"] == "partial"
    assert row(rep, "GATE-02")["gaps"] == ["no-tests"]
    assert row(rep, "GATE-01")["status"] == "partial"
    assert row(rep, "GATE-01")["tested_by"] == ["tests/integration/test_gate.py:1"]


def test_done_needs_implementation_tests_and_acceptance_gates(tmp_path: Path) -> None:
    files = {
        "services/api/visits.py": f"# {ann('REQ', 'GATE-01', 'GATE-02')}\n",
        "tests/integration/test_gate.py": f"# {ann('REQ', 'GATE-01', 'GATE-02')}\n",
    }
    rep = report(make_repo(tmp_path, files), "M1")
    assert row(rep, "GATE-02")["status"] == "done"  # no gates
    g1 = row(rep, "GATE-01")  # gates AT-03 (M0) and AT-12 (M1), neither tagged yet
    assert g1["status"] == "partial"
    assert g1["gaps"] == ["acceptance-untested:AT-03", "acceptance-untested:AT-12"]
    write(
        tmp_path,
        "tests/acceptance/test_at.py",
        'import pytest\n\n@pytest.mark.at("AT-03")\ndef test_a(): pass\n',
    )
    assert row(report(tmp_path, "M1"), "GATE-01")["gaps"] == ["acceptance-untested:AT-12"]
    write(tmp_path, "tests/acceptance/test_at12.py", f"# {ann('AT', 'AT-12')}\n")
    assert row(report(tmp_path, "M1"), "GATE-01")["status"] == "done"


def test_gates_beyond_the_target_milestone_are_not_required(tmp_path: Path) -> None:
    files = {
        "services/api/visits.py": f"# {ann('REQ', 'GATE-01')}\n",
        "tests/integration/test_gate.py": f"# {ann('REQ', 'GATE-01')}\n",
        "tests/acceptance/test_at.py": 'import pytest\n\n@pytest.mark.at("AT-03")\ndef test_a(): pass\n',
    }
    root = make_repo(tmp_path, files)
    assert row(report(root, "M0"), "GATE-01")["status"] == "done"
    assert row(report(root, "M0"), "GATE-01")["acceptance_gates"] == ["AT-03"]
    assert row(report(root, "M1"), "GATE-01")["status"] == "partial"


def test_label_makes_a_complete_requirement_blocked_external(tmp_path: Path) -> None:
    root = make_repo(tmp_path, {"services/api/privacy.py": f"# {ann('REQ', 'PRIV-08')}\n"})
    assert row(report(root), "PRIV-08")["status"] == "partial"  # implementation but no test yet
    write(root, "tests/integration/test_p.py", f"# {ann('REQ', 'PRIV-08')}\n")
    r = row(report(root), "PRIV-08")
    assert r["status"] == "blocked-external"
    assert r["blocked_by"] == ["LEGAL"]


def test_external_item_with_no_evidence_stays_not_started(tmp_path: Path) -> None:
    r = row(report(make_repo(tmp_path)), "PAY-04")
    assert r["status"] == "not-started"
    assert r["blocked_by"] == ["provider:payment-aggregator"]


def test_provider_dependency_needs_adapter_and_simulator(tmp_path: Path) -> None:
    root = make_repo(
        tmp_path,
        {
            "services/api/payments/service.py": f"# {ann('REQ', 'PAY-04')}\n",
            "tests/integration/test_pay.py": f"# {ann('REQ', 'PAY-04')}\n",
        },
    )
    r = row(report(root), "PAY-04")
    assert r["status"] == "partial"
    assert r["gaps"] == ["no-adapter", "no-simulator"]
    write(root, "services/api/payments/adapters/aggregator.py", f"# {ann('REQ', 'PAY-04')}\n")
    r = row(report(root), "PAY-04")
    assert r["status"] == "partial"
    assert r["gaps"] == ["no-simulator"]
    write(root, "services/api/payments/simulators/aggregator.py", f"# {ann('REQ', 'PAY-04')}\n")
    r = row(report(root), "PAY-04")
    assert r["status"] == "blocked-external"
    assert r["adapter_files"] == ["services/api/payments/adapters/aggregator.py"]
    assert r["simulator_files"] == ["services/api/payments/simulators/aggregator.py"]


def test_explicit_adapter_and_simulator_annotations_count(tmp_path: Path) -> None:
    root = make_repo(
        tmp_path,
        {
            "services/edge/barrier.py": f"# {ann('ADAPTER', 'HW-01')}\n# {ann('SIMULATOR', 'HW-01')}\n",
        },
    )
    r = row(report(root, "M2"), "HW-01")
    assert r["status"] == "blocked-external"  # adapter+simulator exist even without a test yet
    assert r["implemented_in"] == ["services/edge/barrier.py"]
    assert "no-tests" in r["gaps"]  # but the gap is reported honestly


def test_simulator_path_inside_a_test_tree_is_not_a_simulator(tmp_path: Path) -> None:
    root = make_repo(
        tmp_path,
        {
            "services/edge/adapters/barrier.py": f"# {ann('REQ', 'HW-01')}\n",
            "tests/simulators/fake_barrier.py": f"# {ann('REQ', 'HW-01')}\n",
        },
    )
    r = row(report(root, "M2"), "HW-01")
    assert r["status"] == "partial"
    assert "no-simulator" in r["gaps"]
    assert r["tested_by"] == ["tests/simulators/fake_barrier.py:1"]


# ------------------------------------------------------------------------------------------- milestones
def ids(rep: dict[str, Any]) -> set[str]:
    return {r["id"] for r in rep["requirements"]}


def test_milestone_scope_is_cumulative_and_uses_slice_for_unreleased_items(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    m0, m1, m2, m4 = (report(root, m) for m in ("M0", "M1", "M2", "M4"))
    assert ids(m0) == {"GATE-01", "INV-01"}  # INV-01: no release, slice 1 -> M0
    assert ids(m1) == {"GATE-01", "GATE-02", "PAY-04", "PRIV-08", "INV-01", "DB-05", "AI-R02"}
    assert "HW-01" in ids(m2)
    assert "AI-F04" not in ids(m2)
    assert "AI-F04" in ids(m4)
    assert [a["id"] for a in m0["acceptance"]] == ["AT-03"]
    assert [a["id"] for a in m1["acceptance"]] == ["AT-03", "AT-12"]


def test_exact_scope_and_reference_items(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    ex = report(root, "M1", exact=True)
    assert ids(ex) == {"GATE-02", "PAY-04", "PRIV-08", "DB-05", "AI-R02"}
    assert ex["scope"] == "exact"
    cum = report(root, "M1")
    assert cum["summary"]["reference_items"] == {
        "decision": 1,
        "open-question": 1,
    }  # D-14 (slice 2) and Q4
    assert "D-14" not in ids(cum)
    assert "Q4" not in ids(cum)


def test_unknown_milestone_is_rejected(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    with pytest.raises(ValueError, match="unknown milestone"):
        report(root, "M9")


# ------------------------------------------------------------------------------------------- acceptance tests
def test_acceptance_status_needs_a_test_and_passing_evidence(tmp_path: Path) -> None:
    root = make_repo(tmp_path)

    def at(rep: dict[str, Any]) -> dict[str, Any]:
        return next(a for a in rep["acceptance"] if a["id"] == "AT-03")

    assert at(report(root, "M0"))["status"] == "not-started"
    write(
        root,
        "tests/acceptance/test_at03.py",
        'import pytest\n\n@pytest.mark.at("AT-03")\ndef test_a(): pass\n',
    )
    a = at(report(root, "M0"))
    assert a["status"] == "partial"
    assert a["evidence"] == []
    assert a["tests"] == ["tests/acceptance/test_at03.py::test_a"]
    write(root, "docs/evidence/M0/AT-03.json", json.dumps({"result": "pass"}))
    a = at(report(root, "M0"))
    assert a["status"] == "done"
    assert a["evidence"] == ["docs/evidence/M0/AT-03.json"]
    write(root, "docs/evidence/M0/AT-03.json", json.dumps({"result": "fail"}))
    a = at(report(root, "M0"))
    assert a["status"] == "partial"
    assert a["evidence_failed"] is True
    # evidence without a test is not done either; markdown evidence mentioning FAIL is read as failed
    (root / "tests" / "acceptance" / "test_at03.py").unlink()
    write(root, "docs/evidence/AT-03-notes.md", "Result: PASS\n")
    write(root, "docs/evidence/M0/AT-03.json", json.dumps({"result": "pass"}))
    assert at(report(root, "M0"))["status"] == "partial"


# ------------------------------------------------------------------------------------------- orphans
def test_orphans_carry_hints_and_locations(tmp_path: Path) -> None:
    root = make_repo(
        tmp_path,
        {
            "services/api/a.py": f"# {ann('REQ', 'AI-01')}\n# {ann('REQ', 'GATE-1')}\n# {ann('REQ', 'GATE-99')}\n",
            "tests/test_o.py": 'import pytest\n\n@pytest.mark.req("NOPE-01")\ndef test_x() -> None:\n    pass\n',
        },
    )
    orphans = report(root)["orphans"]
    by_id = {o["id"]: o for o in orphans}
    assert set(by_id) == {"AI-01", "GATE-1", "GATE-99", "NOPE-01"}
    assert by_id["AI-01"]["hint"] == "legacy Draft B alias of AI-R02"
    assert by_id["GATE-1"]["hint"] == "did you mean GATE-01"
    assert by_id["GATE-99"]["hint"] is None
    assert by_id["NOPE-01"]["scope"] == "test_x"
    assert by_id["NOPE-01"]["path"] == "tests/test_o.py"
    assert report(root)["summary"]["orphans"] == 4


# ------------------------------------------------------------------------------------------- output
def test_output_is_deterministic_and_independent_of_creation_order(tmp_path: Path) -> None:
    files = {
        "services/api/a.py": f"# {ann('REQ', 'GATE-01', 'GATE-02')}\n",
        "services/api/b.py": f"# {ann('REQ', 'GATE-01')}\n",
        "tests/integration/test_a.py": f"# {ann('REQ', 'GATE-01')}\n",
        "apps/web/x.ts": f"// {ann('REQ', 'PAY-04')}\n",
        "docs/runbooks/r.md": f"<!-- {ann('REQ', 'PRIV-08')} -->\n",
    }
    one = make_repo(tmp_path / "one", files)
    two = make_repo(tmp_path / "two", dict(reversed(list(files.items()))))
    a, b = report(one), report(two)
    assert tc.render_json(a) == tc.render_json(b)
    assert tc.render_markdown(a) == tc.render_markdown(b)
    assert tc.render_json(report(one)) == tc.render_json(a)  # second run, same bytes
    assert row(a, "GATE-01")["implemented_in"] == ["services/api/a.py", "services/api/b.py"]
    assert "T" not in a["registry"]["digest"][:7]  # digest is a plain hash, no timestamps anywhere
    assert not re.search(r"\d{4}-\d{2}-\d{2}T", tc.render_json(a))


def test_markdown_has_sections_and_escapes_cells(tmp_path: Path) -> None:
    items = mini_items()
    items[0]["title"] = "Pipes | in | titles"
    root = make_repo(tmp_path, {"services/api/a.py": f"# {ann('REQ', 'GATE-01')}\n"}, items=items)
    md = tc.render_markdown(report(root))
    for heading in ("# Requirement traceability: M1", "## Summary", "## Requirements", "## Acceptance tests",
                    "## Orphan annotations", "## How status is computed", "### area-a", "### area-b"):  # fmt: skip
        assert heading in md, heading
    assert "Pipes \\| in \\| titles" in md
    assert "`services/api/a.py`" in md
    assert "None." in md  # no orphans
    assert tc.render_markdown(report(root, "M0")).startswith(
        "# Requirement traceability: M0 (M0 only)"
    )


def test_json_report_shape(tmp_path: Path) -> None:
    rep = json.loads(tc.render_json(report(make_repo(tmp_path))))
    assert set(rep) == {"tool", "schema_version", "milestone", "scope", "registry", "scan", "summary",
                        "requirements", "acceptance", "orphans"}  # fmt: skip
    assert rep["schema_version"] == 1
    assert rep["milestone"] == "M1"
    assert rep["scope"] == "cumulative"
    assert set(rep["requirements"][0]) == {
        "id", "kind", "area", "title", "priority", "release", "effective_milestone", "slice", "module", "labels",
        "status", "blocked_by", "implemented_in", "adapter_files", "simulator_files", "tested_by",
        "acceptance_gates", "gaps",
    }  # fmt: skip
    assert rep["registry"]["digest"].startswith("sha256:")


# ------------------------------------------------------------------------------------------- CLI
def test_cli_writes_requested_formats(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = make_repo(tmp_path)
    out = root / "docs" / "traceability"
    assert tc.main(["--root", str(root), "--format", "md"]) == 0
    assert (out / "TRACEABILITY.md").is_file()
    assert not (out / "TRACEABILITY.json").exists()
    assert "7 requirements" in capsys.readouterr().out
    assert tc.main(["--root", str(root), "--format", "json", "--milestone", "M0", "--quiet"]) == 0
    assert json.loads((out / "TRACEABILITY.json").read_text())["milestone"] == "M0"
    (out / "TRACEABILITY.md").unlink()
    assert tc.main(["--root", str(root), "--quiet"]) == 0  # default both
    assert (out / "TRACEABILITY.md").is_file()
    elsewhere = tmp_path / "elsewhere"
    assert tc.main(["--root", str(root), "--out-dir", str(elsewhere), "--quiet"]) == 0
    assert (elsewhere / "TRACEABILITY.json").is_file()


def test_cli_format_none_and_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = make_repo(tmp_path)
    out = root / "docs" / "traceability"
    assert tc.main(["--root", str(root), "--format", "none", "--quiet"]) == 0
    assert not (out / "TRACEABILITY.md").exists()
    assert tc.main(["--root", str(root), "--stdout", "--format", "md", "--quiet"]) == 0
    assert capsys.readouterr().out.startswith("# Requirement traceability")
    assert tc.main(["--root", str(root), "--stdout", "--quiet"]) == 0
    assert json.loads(capsys.readouterr().out)["milestone"] == "M1"
    assert not (out / "TRACEABILITY.md").exists()


def test_cli_fail_on_orphans(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = make_repo(tmp_path, {"services/api/a.py": f"# {ann('REQ', 'GATE-1')}\n"})
    assert tc.main(["--root", str(root), "--quiet"]) == 0  # reported, not fatal
    assert tc.main(["--root", str(root), "--quiet", "--fail-on-orphans"]) == 1
    err = capsys.readouterr().err
    assert "orphan: GATE-1 at services/api/a.py:1 (did you mean GATE-01)" in err
    assert tc.main(["--root", str(root), "--quiet", "--format", "none", "--fail-on-orphans"]) == 1
    (root / "services" / "api" / "a.py").write_text("x = 1\n")
    assert tc.main(["--root", str(root), "--quiet", "--fail-on-orphans"]) == 0


def test_cli_exit_2_when_registry_is_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert tc.main(["--root", str(tmp_path)]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_cli_exit_2_when_explicit_prd_is_missing(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code = tc.main(
        [
            "--root",
            str(REPO),
            "--check-registry",
            "--format",
            "none",
            "--prd",
            str(tmp_path / "nope.txt"),
        ]
    )
    assert code == 2
    assert "PRD text not found" in capsys.readouterr().err


@pytest.fixture
def broken_repo(tmp_path: Path) -> Path:
    shutil.copytree(
        TRACE_DIR,
        tmp_path / "docs" / "traceability",
        ignore=shutil.ignore_patterns("TRACEABILITY.*"),
    )
    return tmp_path


def mutate(root: Path, name: str, fn: Any) -> None:
    path = root / "docs" / "traceability" / name
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    fn(doc)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


@pytest.mark.parametrize(
    ("file", "mutation", "needle"),
    [
        (
            "requirements.yaml",
            lambda d: d["items"].append(dict(d["items"][0])),
            "duplicate id INV-01",
        ),
        ("requirements.yaml", lambda d: d["items"][0].update(kind="bogus"), "unknown kind"),
        ("requirements.yaml", lambda d: d["items"][0].update(slice=12), "slice must be 1..9"),
        ("requirements.yaml", lambda d: d["items"][0].update(title="one " * 15), "title must be"),
        (
            "requirements.yaml",
            lambda d: d["items"][0].update(module="services/nowhere"),
            "not in module_map",
        ),
        ("requirements.yaml", lambda d: d["items"][0].update(labels=["MAYBE"]), "bad labels"),
        ("requirements.yaml", lambda d: d["items"][0].pop("area"), "differ from the schema"),
        ("module_map.yaml", lambda d: d["assignments"].pop("GATE-01"), "no assignment for GATE-01"),
        (
            "module_map.yaml",
            lambda d: d["assignments"]["GATE-01"]["gates"].append("GATE-02"),
            "is not an acceptance",
        ),
        (
            "module_map.yaml",
            lambda d: d["assignments"]["GATE-01"]["external"].append("x:y"),
            "not in the catalogue",
        ),
        (
            "module_map.yaml",
            lambda d: d["assignments"]["GATE-01"]["surfaces"].append("zzz"),
            "is not a module",
        ),
        ("module_map.yaml", lambda d: d["slices"].pop(), "slices must be 1..9"),
        ("acceptance_matrix.yaml", lambda d: d["items"].pop(5), "contiguous"),
        (
            "acceptance_matrix.yaml",
            lambda d: d["items"][0].update(milestone="M1"),
            "disagrees with requirements.yaml",
        ),
    ],
)
def test_check_registry_detects_corruption(
    broken_repo: Path, capsys: pytest.CaptureFixture[str], file: str, mutation: Any, needle: str
) -> None:
    assert (
        tc.main(["--root", str(broken_repo), "--check-registry", "--format", "none", "--quiet"])
        == 0
    )
    capsys.readouterr()
    mutate(broken_repo, file, mutation)
    assert (
        tc.main(["--root", str(broken_repo), "--check-registry", "--format", "none", "--quiet"])
        == 1
    )
    assert needle in capsys.readouterr().err


@needs_prd
def test_check_registry_detects_prd_drift(
    broken_repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mutate(
        broken_repo, "requirements.yaml", lambda d: d["items"].pop(5)
    )  # drop an item the PRD still names
    code = tc.main(
        [
            "--root",
            str(broken_repo),
            "--check-registry",
            "--format",
            "none",
            "--prd",
            str(PRD),
            "--quiet",
        ]
    )
    err = capsys.readouterr().err
    assert code == 1
    assert "is not in the register" in err
    mutate(broken_repo, "requirements.yaml", lambda d: d["items"][0].update(id="ZZZ-77"))
    tc.main(
        [
            "--root",
            str(broken_repo),
            "--check-registry",
            "--format",
            "none",
            "--prd",
            str(PRD),
            "--quiet",
        ]
    )
    assert "does not occur in the PRD" in capsys.readouterr().err
