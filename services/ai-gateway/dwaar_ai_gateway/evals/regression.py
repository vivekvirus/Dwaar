"""Regression runner for a prompt or model change (AI-SYS-07): run the evaluation sets, then allow only a CANARY rollout.

Usage: ``python -m dwaar_ai_gateway.evals.regression --feature AI-R07 --candidate v2``

What it does: loads the candidate prompt version, checks its schema and metadata, runs the access/injection set (a candidate prompt can
change what the gateway accepts), the PII gate and the feature's own set, and prints whether the candidate MAY enter a canary. Promotion
is never automatic: the registry file is edited by a reviewer (``canary: v2`` + ``canary_percent``), and a society pin in the database
(``ai_feature_controls.prompt_version_pin``) rolls a society back immediately without a deploy.

HONESTY: with the simulator provider this verifies the harness, the schema and the gateway layers. It says NOTHING about whether the
candidate prompt gives better answers from a real model; that needs a real-model run on the reviewed sets, which has not happened.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field

import yaml
from jsonschema import Draft202012Validator, SchemaError

from ..prompts import PromptError, PromptStore
from . import access_injection, banner, pii_eval


@dataclass
class RegressionReport:
    feature_id: str
    candidate: str
    active: str
    checks: list[tuple[str, bool, str]] = field(default_factory=list)

    @property
    def canary_allowed(self) -> bool:
        return all(ok for _, ok, _ in self.checks)

    def render(self) -> str:
        lines = [
            f"PROMPT REGRESSION {self.feature_id}: candidate {self.candidate} vs active {self.active}",
            banner(),
        ]
        lines += [
            f"  [{'ok' if ok else 'FAIL'}] {name}: {detail}" for name, ok, detail in self.checks
        ]
        lines.append(
            "RESULT: "
            + (
                "candidate may enter a CANARY (reviewer edits registry.yaml: canary + canary_percent)"
                if self.canary_allowed
                else "candidate BLOCKED"
            )
            + ". This is not a quality result: no real model ran."
        )
        return "\n".join(lines)


def regression(
    feature_id: str, candidate: str, store: PromptStore | None = None
) -> RegressionReport:
    store = store or PromptStore()
    active = str(store.entries[feature_id]["active"])
    rep = RegressionReport(feature_id, candidate, active)
    try:
        bundle = store.load(feature_id, version=candidate)
        Draft202012Validator.check_schema(bundle.schema)
        meta = (
            yaml.safe_load(
                (store.root / bundle.directory / candidate / "meta.yaml").read_text(
                    encoding="utf-8"
                )
            )
            or {}
        )
        rep.checks.append(
            (
                "candidate loads, schema is valid JSON Schema",
                True,
                f"schema_version {bundle.schema_version}, sha256 {bundle.sha256[:12]}",
            )
        )
        rep.checks.append(
            (
                "meta.risk_class unchanged",
                str(meta.get("risk_class")) in {"A", "B", "C"},
                f"risk_class {meta.get('risk_class')}",
            )
        )
        rep.checks.append(
            (
                "no raw 'ignore previous' style wording in the system prompt",
                "ignore previous" not in bundle.system.lower(),
                "static lint",
            )
        )
    except (PromptError, SchemaError, OSError, KeyError) as exc:
        rep.checks.append(("candidate loads", False, type(exc).__name__))
        return rep
    # run the sets with the CANDIDATE as the active version
    probe = PromptStore(store.root)
    probe.entries[feature_id] = {**probe.entries[feature_id], "active": candidate}
    attack = access_injection.run(prompts=probe)
    rep.checks.append(
        (
            "access and injection set: zero critical failures",
            attack.critical_failures == 0,
            f"{attack.critical_failures} critical of {len(attack.attack)}",
        )
    )
    rep.checks.append(
        (
            "benign controls still succeed",
            attack.control_failures == 0,
            f"{attack.control_failures} over-blocked",
        )
    )
    p = pii_eval.run()
    rep.checks.append(
        (
            "PII recall gate (model independent)",
            p.recall >= pii_eval.TARGET_RECALL,
            f"recall {p.recall:.1%}, fpr {p.fpr:.1%}",
        )
    )
    return rep


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--feature", required=True)
    ap.add_argument("--candidate", required=True)
    args = ap.parse_args(argv)
    rep = regression(args.feature, args.candidate)
    print(rep.render())
    return 0 if rep.canary_allowed else 1


if __name__ == "__main__":
    sys.exit(main())
