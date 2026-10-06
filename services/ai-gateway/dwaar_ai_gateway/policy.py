"""Policy enforcement BEFORE and AFTER the model (PRD 10.1, AI-SYS-02).

REQ: AI-SYS-02 (retrieval applies server-derived society, role, unit and document visibility BEFORE similarity search and AGAIN
before response; deleted, superseded and archived content is excluded), INV-01, G6.

The retrieval layer (database queries under RLS in the API module) proposes candidate documents; THIS module re-checks every one,
so a buggy or hostile retrieval (cross-society rows, another unit's ticket, a committee-only document asked for by a resident)
still cannot put unauthorised text in front of a model. Excluded documents are fingerprinted so an echo of their text in a model
output is detected (``validation``).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from .types import Caller, SourceDoc

_WORD = re.compile(r"\w+", re.UNICODE)
SHINGLE = 4


class PolicyDenied(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def shingles(text: str, n: int = SHINGLE) -> frozenset[str]:
    words = [w.lower() for w in _WORD.findall(text)]
    if len(words) < n + 2:
        return frozenset()
    return frozenset(
        hashlib.sha256(" ".join(words[i : i + n]).encode()).hexdigest()[:16]
        for i in range(len(words) - n + 1)
    )


@dataclass
class SourceDecision:
    allowed: list[SourceDoc] = field(default_factory=list)
    excluded: list[dict[str, str]] = field(
        default_factory=list
    )  # {"ref": sha256(source_id)[:12], "reason": code}
    fingerprints: frozenset[str] = frozenset()

    @property
    def critical(self) -> bool:
        return any(e["reason"] == "other_society" for e in self.excluded)


def authorise_sources(caller: Caller, docs: Sequence[SourceDoc]) -> SourceDecision:
    decision = SourceDecision()
    prints: set[str] = set()
    for d in docs:
        reason: str | None = None
        if d.society_id != caller.society_id:
            reason = "other_society"
        elif d.status != "published":
            reason = "not_published"
        elif d.visible_to_roles is not None and caller.role not in d.visible_to_roles:
            reason = "role_not_visible"
        elif d.unit_id is not None and not caller.covers_unit(d.unit_id):
            reason = "unit_not_covered"
        if reason is None:
            decision.allowed.append(d)
        else:
            decision.excluded.append(
                {"ref": hashlib.sha256(d.source_id.encode()).hexdigest()[:12], "reason": reason}
            )
            prints |= shingles(d.text)
    decision.fingerprints = frozenset(prints)
    return decision


def check_role(feature_roles: frozenset[str], caller: Caller) -> None:
    if caller.role not in feature_roles:
        raise PolicyDenied("role_not_allowed_for_feature")
