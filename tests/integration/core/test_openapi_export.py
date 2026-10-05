"""tools/export_openapi.py: deterministic, database-free export of the OpenAPI and JSON Schema contracts."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
TOOL = REPO / "tools" / "export_openapi.py"

pytestmark = pytest.mark.req("ARCH-03")


def run_tool(*args: str) -> subprocess.CompletedProcess[str]:
    # minimal environment: no DWAAR_* variables, no database anywhere
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=120,
        env={"PATH": "/usr/bin:/bin"},
        cwd=REPO,
        check=False,
    )


def test_export_is_deterministic_and_complete(tmp_path: Path) -> None:
    first, second = tmp_path / "one", tmp_path / "two"
    assert run_tool("--out", str(first)).returncode == 0
    assert run_tool("--out", str(second)).returncode == 0
    files = sorted(p.relative_to(first) for p in first.rglob("*.json"))
    assert [str(f) for f in files] == [
        "jsonschema/DomainEvent.schema.json",
        "jsonschema/EdgeEvent.schema.json",
        "jsonschema/ErrorBody.schema.json",
        "openapi/dwaar.v1.json",
    ]
    for relative in files:
        a = (first / relative).read_bytes()
        assert a == (second / relative).read_bytes(), f"{relative} differs between runs"
        assert a.endswith(b"\n")
        json.loads(a)  # valid JSON
    spec = json.loads((first / "openapi/dwaar.v1.json").read_text())
    assert spec["openapi"].startswith("3.")
    assert spec["info"]["title"] == "Dwaar API"
    assert {"/healthz", "/readyz", "/v1/meta"} <= set(spec["paths"])
    assert "ErrorBody" in spec["components"]["schemas"]
    assert list(spec["paths"]) == sorted(spec["paths"])  # the encoder sorts keys: stable diffs
    text = (first / "openapi/dwaar.v1.json").read_text()
    assert "export-only" not in text  # throw-away settings never leak into the contract
    assert "127.0.0.1" not in text


def test_event_schemas_describe_the_prd_contracts(tmp_path: Path) -> None:
    assert run_tool("--out", str(tmp_path)).returncode == 0
    domain = json.loads((tmp_path / "jsonschema/DomainEvent.schema.json").read_text())
    edge = json.loads((tmp_path / "jsonschema/EdgeEvent.schema.json").read_text())
    assert {"event_id", "schema_version", "society_id", "aggregate_type", "aggregate_id", "aggregate_version", "event_type",
            "occurred_at", "actor_ref", "correlation_id"} <= set(domain["required"])  # fmt: skip
    assert "causation_id" not in domain["required"]
    assert {"event_id", "society_id", "device_id", "seq", "entity_id", "entity_version", "type", "policy_version",
            "occurred_at", "clock_uncertainty_ms", "payload_hash", "payload"} <= set(edge["required"])  # fmt: skip
    assert domain["additionalProperties"] is False


def test_check_mode_detects_stale_and_missing_files(tmp_path: Path) -> None:
    assert run_tool("--check", "--out", str(tmp_path)).returncode == 1  # nothing exported yet
    assert run_tool("--out", str(tmp_path)).returncode == 0
    ok = run_tool("--check", "--out", str(tmp_path))
    assert ok.returncode == 0
    assert "up to date" in ok.stdout
    victim = tmp_path / "openapi" / "dwaar.v1.json"
    victim.write_text(victim.read_text() + " ")
    stale = run_tool("--check", "--out", str(tmp_path))
    assert stale.returncode == 1
    assert "openapi/dwaar.v1.json" in stale.stderr
