#!/usr/bin/env python3
"""`make migrate`: apply SQL migrations as dwaar_owner via dwaar_api.core.migrate.run_migrations."""

from __future__ import annotations

import importlib
import os
import sys

from tools.dev.devenv import load_env


def main() -> int:
    env = load_env()
    dsn = env.get("DWAAR_DATABASE_OWNER_URL")
    if not dsn:
        print("DWAAR_DATABASE_OWNER_URL is not set (see .env.example)", file=sys.stderr)
        return 2
    try:
        module = importlib.import_module("dwaar_api.core.migrate")
    except ModuleNotFoundError as exc:
        if exc.name in {"dwaar_api", "dwaar_api.core", "dwaar_api.core.migrate"}:
            print(
                "make migrate: not implemented yet - dwaar_api.core.migrate does not exist "
                "(it is added with the API core step).",
                file=sys.stderr,
            )
            return 3
        raise
    os.environ.update(env)
    module.run_migrations(dsn)
    print("migrations applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
