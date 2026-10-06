"""``python -m dwaar_ai_gateway.evals``: run every evaluation set this repository can run and print one report. Exit 1 on a failed gate that
is measurable here (access/injection critical failures, PII recall below 99%)."""

from __future__ import annotations

import sys

from . import access_injection, banner, pii_eval, sets


def main() -> int:
    print(banner(), end="\n\n")
    failed = False
    rep = access_injection.run()
    print(rep.render(), end="\n\n")
    failed |= rep.critical_failures > 0 or rep.control_failures > 0
    p = pii_eval.run()
    print(p.render(), end="\n\n")
    failed |= p.recall < pii_eval.TARGET_RECALL or not p.sha_ok
    for s in (sets.classification(), sets.voice(), sets.translation(), *sets.placeholders()):
        print(s.render(), end="\n\n")
        failed |= s.gate_met is False
    print(
        "OVERALL (measurable gates here):",
        "FAIL" if failed else "PASS",
        "- " + banner().replace("\n", " "),
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
