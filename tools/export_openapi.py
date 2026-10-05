#!/usr/bin/env python3
"""Export the API contract deterministically: OpenAPI 3 plus JSON Schemas for the shared event envelopes.

    python tools/export_openapi.py             write packages/contracts/{openapi,jsonschema}/...
    python tools/export_openapi.py --check     exit 1 if the committed files differ from a fresh export
    python tools/export_openapi.py --out DIR   write somewhere else (tests)

REQ: PRD 12 (APIs are versioned under /v1 and described in OpenAPI with JSON Schema), PRD 12.3 / 12.4
(EdgeEvent and DomainEvent contracts). The export builds the real application (every discovered module
included) with throw-away settings; it never connects to a database. Output is byte-for-byte stable:
sorted keys, fixed indentation, trailing newline, no timestamps.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "packages" / "contracts"

# Not real credentials: the engine is created lazily and never connects during an export.
_EXPORT_SETTINGS: dict[str, Any] = {
    "env": "test",
    "database_url": "postgresql://dwaar_app:export-only@127.0.0.1:1/export",
    "cursor_signing_key": "export-only-not-a-secret",
}


def dumps(document: Any) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def build_documents() -> dict[str, str]:
    """Relative output path -> file text."""
    config = importlib.import_module("dwaar_api.core.config")
    main = importlib.import_module("dwaar_api.main")
    errors = importlib.import_module("dwaar_api.core.errors")
    events = importlib.import_module("dwaar_common.events")
    app = main.create_app(config.Settings.model_validate(_EXPORT_SETTINGS))
    try:
        openapi = app.openapi()
    finally:
        app.state.db.dispose()
    return {
        "openapi/dwaar.v1.json": dumps(openapi),
        "jsonschema/DomainEvent.schema.json": dumps(events.DomainEvent.model_json_schema()),
        "jsonschema/EdgeEvent.schema.json": dumps(events.EdgeEvent.model_json_schema()),
        "jsonschema/ErrorBody.schema.json": dumps(errors.ErrorBody.model_json_schema()),
    }


def write(out: Path) -> list[Path]:
    written: list[Path] = []
    for relative, text in build_documents().items():
        target = out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        written.append(target)
    return written


def check(out: Path) -> list[str]:
    """Names of committed files that are missing or stale."""
    stale: list[str] = []
    for relative, text in build_documents().items():
        target = out / relative
        if not target.is_file() or target.read_text(encoding="utf-8") != text:
            stale.append(relative)
    return stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0] if __doc__ else None)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true", help="fail if the exported files are stale")
    args = parser.parse_args(argv)
    if args.check:
        stale = check(args.out)
        if stale:
            sys.stderr.write(
                "stale contract files (run tools/export_openapi.py): " + ", ".join(stale) + "\n"
            )
            return 1
        sys.stdout.write("contracts are up to date\n")
        return 0
    for path in write(args.out):
        sys.stdout.write(f"wrote {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
