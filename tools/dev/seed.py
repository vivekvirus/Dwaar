#!/usr/bin/env python3
"""`make seed`: run dwaar_api.seed (synthetic demo data, DWAAR_ENV=local only) if it exists."""

from __future__ import annotations

import importlib.util
import os
import runpy
import sys

from tools.dev.devenv import load_env


def seed_available() -> bool:
    try:
        return importlib.util.find_spec("dwaar_api.seed") is not None
    except ModuleNotFoundError:
        return False


def main() -> int:
    if not seed_available():
        print(
            "make seed: not implemented yet - dwaar_api.seed does not exist "
            "(it is added with the identity/organisation seed step). Nothing was changed."
        )
        return 0
    os.environ.update(load_env())
    runpy.run_module("dwaar_api.seed", run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main())
