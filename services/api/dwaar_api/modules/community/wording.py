"""Neutral-wording check hook for opinion polls (COM-06; AI-C12 is built later).

REQ: COM-06 (neutral wording check), INV-06 (a model proposes, a person decides: flags never block by themselves; a person opens
a flagged poll with a recorded reason), AI-C12 (bias flags and a neutral rewrite, built later by the ai-gateway work).

``NeutralWordingChecker.check`` returns flag codes only (no rewritten text). The default ``RuleBasedChecker`` is deterministic
and deliberately small: it catches leading questions, loaded words, shouting and one-sided option sets; it does NOT claim to
detect bias in general. ``register_checker`` is the seam for the AI-C12 implementation; every registered checker runs and the
flags are the union.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final, Protocol

_LEADING: Final = (
    "don't you agree", "do you not agree", "isn't it obvious", "surely", "obviously", "everyone knows", "no sensible person",
    "isn't it time", "shouldn't we finally", "wouldn't you say",
)  # fmt: skip
_LOADED: Final = (
    "disgraceful",
    "shameful",
    "useless",
    "corrupt",
    "scam",
    "idiotic",
    "unacceptable",
    "outrageous",
)
_SHOUT: Final = re.compile(r"\b[A-Z]{5,}\b")


class NeutralWordingChecker(Protocol):
    name: str

    def check(self, question: str, description: str, options: Sequence[str]) -> list[str]: ...


class RuleBasedChecker:
    name = "rule-based-v1"

    def check(self, question: str, description: str, options: Sequence[str]) -> list[str]:
        flags: list[str] = []
        low = f"{question} {description}".lower()
        if any(p in low for p in _LEADING):
            flags.append("leading_question")
        if any(re.search(rf"\b{re.escape(w)}\b", low) for w in _LOADED):
            flags.append("loaded_wording")
        if _SHOUT.search(f"{question} {description}") or "!" in question:
            flags.append("emphatic_style")
        if (
            len(options) == 2
            and {o.strip().lower() for o in options} <= {"yes", "no"}
            and low.count("?") != 1
        ):
            flags.append("unclear_yes_no_question")
        if (
            len(options) >= 3
            and not any(
                re.search(
                    r"\b(no opinion|undecided|abstain|none|neutral|not sure|other)\b", o.lower()
                )
                for o in options
            )
            and any(re.search(r"\b(strongly|definitely|absolutely)\b", o.lower()) for o in options)
        ):
            flags.append("one_sided_options")
        return flags


_CHECKERS: list[NeutralWordingChecker] = [RuleBasedChecker()]


def register_checker(checker: NeutralWordingChecker) -> None:
    if all(c.name != checker.name for c in _CHECKERS):
        _CHECKERS.append(checker)


def run_checks(question: str, description: str, options: Sequence[str]) -> dict[str, object]:
    flags: list[str] = []
    for checker in _CHECKERS:
        flags.extend(f for f in checker.check(question, description, options) if f not in flags)
    return {"checkers": [c.name for c in _CHECKERS], "flags": flags}
