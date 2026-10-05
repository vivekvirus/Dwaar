"""``python -m dwaar_api.seed [seed | demo-logins | totp <phone>]`` (local only)."""

from __future__ import annotations

import os
import sys

from . import SeedRefused, run
from .demo import print_demo_logins, print_totp
from .runtime import out


def main(argv: list[str]) -> int:
    command = argv[0] if argv else "seed"
    try:
        if command == "seed":
            result = run(os.environ)
            out(
                f"seed done in {result.seconds:.1f}s: "
                + ", ".join(f"{k}={v}" for k, v in sorted(result.counts.items()))
            )
            out("demo logins: python -m dwaar_api.seed demo-logins   (README: Local demo)")
            return 0
        if command == "demo-logins":
            print_demo_logins(os.environ)
            return 0
        if command == "totp" and len(argv) == 2:
            print_totp(os.environ, argv[1])
            return 0
    except SeedRefused as exc:
        sys.stderr.write(f"seed: {exc}\n")
        return 2
    sys.stderr.write("usage: python -m dwaar_api.seed [seed | demo-logins | totp <phone>]\n")
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
