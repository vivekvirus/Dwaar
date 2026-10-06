"""PII redaction evaluation on the frozen golden set (PRD 11.3 'PII redaction: 500 samples, recall >= 99%', AI-SYS-05).

Recall: an identifier counts as PROTECTED only if EVERY non-space character of its span lies inside a detected span (a partial cover
leaks a fragment). False-positive rate: share of decoys (amounts, dates, unit labels, invoice numbers, UTR/reference numbers, PIN codes ...)
touched by ANY detection; spurious detections on plain text are reported too. The set is pinned by sha256 and must not be edited to fit
the redactor (see packages/prompts/evals/pii/build_golden.py).
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import pii
from ..paths import evals_root
from . import banner

TARGET_RECALL = 0.99


@dataclass
class PiiReport:
    set_name: str
    samples: int
    identifiers: int
    recalled: int
    decoys: int
    false_positives: int
    spurious: int
    by_type: dict[str, tuple[int, int]] = field(default_factory=dict)
    by_lang: dict[str, tuple[int, int]] = field(default_factory=dict)
    by_digits: dict[str, tuple[int, int]] = field(default_factory=dict)
    misses: list[dict[str, str]] = field(default_factory=list)
    sha_ok: bool | None = None

    @property
    def recall(self) -> float:
        return self.recalled / self.identifiers if self.identifiers else 0.0

    @property
    def fpr(self) -> float:
        return self.false_positives / self.decoys if self.decoys else 0.0

    def render(self) -> str:
        def pct(a: int, b: int) -> str:
            return f"{(100 * a / b):.1f}% ({a}/{b})" if b else "n/a"

        lines = [
            f"PII REDACTION ({self.set_name})", banner(),
            f"samples={self.samples} identifiers={self.identifiers} decoys={self.decoys} (set hash verified: {self.sha_ok})",
            f"MEASURED recall: {pct(self.recalled, self.identifiers)}   [release gate >= {TARGET_RECALL:.0%}: {'met' if self.recall >= TARGET_RECALL else 'NOT MET'}]",
            f"MEASURED false-positive rate on decoys: {pct(self.false_positives, self.decoys)}   spurious detections on plain text: {self.spurious}",
            "by type: " + ", ".join(f"{k} {pct(*v)}" for k, v in sorted(self.by_type.items())),
            "by language: " + ", ".join(f"{k} {pct(*v)}" for k, v in sorted(self.by_lang.items())),
            "by digit script: " + ", ".join(f"{k} {pct(*v)}" for k, v in sorted(self.by_digits.items())),
        ]  # fmt: skip
        for m in self.misses[:10]:
            lines.append(f"  MISS {m['id']} {m['type']}")
        return "\n".join(lines)


def load(path: Path | None = None) -> list[dict[str, Any]]:
    p = path or (evals_root() / "pii" / "golden.jsonl")
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def manifest_hash_ok(path: Path | None = None) -> bool:
    p = path or (evals_root() / "pii" / "golden.jsonl")
    m = (
        p.with_name("MANIFEST.json")
        if p.name == "golden.jsonl"
        else p.with_name(p.stem + ".manifest.json")
    )
    want = json.loads(m.read_text(encoding="utf-8"))["sha256"]
    return bool(hashlib.sha256(p.read_bytes()).hexdigest() == want)


def evaluate(rows: list[dict[str, Any]], name: str = "pii-golden-v1") -> PiiReport:
    r = PiiReport(name, len(rows), 0, 0, 0, 0, 0)
    t: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    lg: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    dg: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for row in rows:
        text = row["text"]
        dets = pii.detect(text)
        covered = [False] * len(text)
        for d in dets:
            for i in range(d.start, d.end):
                covered[i] = True
        for sp in row["spans"]:
            r.identifiers += 1
            ok = all(covered[i] for i in range(sp["start"], sp["end"]) if not text[i].isspace())
            r.recalled += int(ok)
            digits = "devanagari" if row.get("devanagari_digits") else "ascii"
            for bucket, key in ((t, sp["type"]), (lg, row["lang"]), (dg, digits)):
                bucket[key][1] += 1
                bucket[key][0] += int(ok)
            if not ok:
                r.misses.append({"id": row["id"], "type": sp["type"]})
        for dc in row["decoys"]:
            r.decoys += 1
            r.false_positives += int(any(d.start < dc["end"] and dc["start"] < d.end for d in dets))
        for d in dets:
            if not any(
                d.start < s["end"] and s["start"] < d.end for s in (*row["spans"], *row["decoys"])
            ):
                r.spurious += 1
    r.by_type, r.by_lang, r.by_digits = (
        {k: (v[0], v[1]) for k, v in b.items()} for b in (t, lg, dg)
    )
    return r


def run(path: Path | None = None) -> PiiReport:
    rows = load(path)
    rep = evaluate(rows, (path or Path("golden.jsonl")).name)
    rep.sha_ok = manifest_hash_ok(path)
    return rep


def main() -> int:
    rep = run()
    print(rep.render())
    return 0 if rep.recall >= TARGET_RECALL and rep.sha_ok else 1


if __name__ == "__main__":
    sys.exit(main())
