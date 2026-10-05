"""CLI: ``python -m dwaar_packs validate [paths...]`` (exit 0 if every pack is valid, 1 otherwise) and
``python -m dwaar_packs pin <file>`` (the approval-registry entry for that exact content)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .approvals import approval_pin
from .errors import PackValidationError
from .loader import discover_pack_files, load_pack


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m dwaar_packs")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="validate pack files against JSON Schema and models")
    v.add_argument("paths", nargs="*", type=Path, help="pack files (default: all shipped packs)")
    pin = sub.add_parser(
        "pin",
        help="print the DWAAR_PACK_APPROVALS entry that records approval of this exact content",
    )
    pin.add_argument("path", type=Path)
    args = ap.parse_args(argv)
    if args.cmd == "pin":
        try:
            print(approval_pin(load_pack(args.path)))
        except PackValidationError as exc:
            print(f"FAIL {args.path}: {exc}")
            return 1
        return 0
    paths = args.paths or list(discover_pack_files())
    failed = 0
    for p in paths:
        try:
            pack = load_pack(p)
        except PackValidationError as exc:
            failed += 1
            print(f"FAIL {p}")
            for problem in exc.problems:
                print(f"  - {problem}")
            continue
        print(
            f"OK   {p} [{pack.pack_id} {pack.version} status={pack.status} enabled={pack.enabled}]"
        )
    print(f"{len(paths) - failed}/{len(paths)} packs valid")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
