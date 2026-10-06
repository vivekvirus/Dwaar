from __future__ import annotations

import base64
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

from tests._harness.pgcluster import PgClusterError, find_pg_bin, free_port
from tools.dev import devenv, seed
from tools.dev.devenv import (
    GENERATE_KEY,
    generate_key,
    init_env,
    load_env,
    parse_env_text,
    render_env_from_example,
)

ROOT = Path(__file__).resolve().parents[2]


def test_parse_env_text() -> None:
    text = """
    # comment
    A=1
    export B = two words   # trailing comment
    C="quoted # not a comment"
    D='single'
    E=
    bad line
    F=postgresql://u:p@h:5/db
    """
    assert parse_env_text(text) == {
        "A": "1",
        "B": "two words",
        "C": "quoted # not a comment",
        "D": "single",
        "E": "",
        "F": "postgresql://u:p@h:5/db",
    }


def test_load_env_precedence(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text(f"A=example\nB=example\nC=example\nK={GENERATE_KEY}\n")
    (tmp_path / ".env").write_text("B=dotenv\nC=dotenv\n")
    env = load_env(tmp_path, {"C": "process"})
    assert env["A"] == "example"
    assert env["B"] == "dotenv"
    assert env["C"] == "process"
    assert "K" not in env  # unresolved placeholders are never exported


def test_render_replaces_each_placeholder_with_distinct_valid_keys() -> None:
    text = render_env_from_example(
        "DWAAR_ENV=local\nA=__GENERATE_KEY__\nB=__GENERATE_ED25519__\nC=x=__GENERATE_KEY__\n"
    )
    values = parse_env_text(text)
    assert values["DWAAR_ENV"] == "local"
    a, b, c = values["A"], values["B"], values["C"].removeprefix("x=")
    assert len({a, b, c}) == 3
    for item in (a, b, c):
        assert len(base64.urlsafe_b64decode(item + "=" * (-len(item) % 4))) == 32
    assert "__GENERATE" not in text


def test_init_env_creates_private_file_once(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("K=__GENERATE_KEY__\nPLAIN=1\n")
    created = init_env(tmp_path)
    assert created == tmp_path / ".env"
    assert stat.S_IMODE(created.stat().st_mode) == 0o600
    first = created.read_text()
    assert "__GENERATE" not in first
    assert init_env(tmp_path) is None  # never overwrites
    assert created.read_text() == first


def test_repo_env_example_is_complete_and_secret_free() -> None:
    values = parse_env_text((ROOT / ".env.example").read_text())
    assert values["DWAAR_ENV"] == "local"
    for required in (
        "DWAAR_DATABASE_OWNER_URL", "DWAAR_DATABASE_URL", "DWAAR_DATABASE_WORKER_URL",
        "DWAAR_PII_KEYS", "DWAAR_PII_ACTIVE_KEY_ID", "DWAAR_PHONE_HASH_KEY", "DWAAR_REDIS_URL",
        "DWAAR_TEST_PG_ADMIN_URL", "DWAAR_OIDC_ISSUER_URL", "DWAAR_AI_PROVIDER",
    ):  # fmt: skip
        assert required in values, required
    # key material is generated, never shipped
    assert GENERATE_KEY in values["DWAAR_PHONE_HASH_KEY"]
    assert values["ANTHROPIC_API_KEY"] == ""
    # the three role URLs use the three distinct roles
    assert "dwaar_owner:" in values["DWAAR_DATABASE_OWNER_URL"]
    assert "dwaar_app:" in values["DWAAR_DATABASE_URL"]
    assert "dwaar_worker:" in values["DWAAR_DATABASE_WORKER_URL"]


def test_shell_output_only_exports_dwaar_variables(tmp_path: Path) -> None:
    result = subprocess.run(
        ["python3", str(ROOT / "tools/dev/devenv.py"), "shell"],
        capture_output=True, text=True, check=True,
        env={**os.environ, "ANTHROPIC_API_KEY": "must-not-leak", "DWAAR_PG_PORT": "61234"},
    )  # fmt: skip
    assert "export DWAAR_PG_PORT=61234" in result.stdout
    assert "must-not-leak" not in result.stdout
    assert all(line.startswith("export DWAAR_") for line in result.stdout.splitlines())


def test_print_masks_secrets() -> None:
    result = subprocess.run(
        ["python3", str(ROOT / "tools/dev/devenv.py"), "print"],
        capture_output=True, text=True, check=True,
        env={**os.environ, "DWAAR_PHONE_HASH_KEY": "super-secret-value"},
    )  # fmt: skip
    assert "super-secret-value" not in result.stdout
    assert "DWAAR_PHONE_HASH_KEY=***" in result.stdout


def test_seed_reports_not_implemented_when_module_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(seed, "seed_available", lambda: False)
    assert seed.main() == 0
    assert "not implemented yet" in capsys.readouterr().out


def test_make_targets_exist() -> None:
    text = (ROOT / "Makefile").read_text()
    for target in (
        "setup", "db-up", "db-down", "db-reset", "migrate", "seed", "api", "lint",
        "typecheck", "test", "acceptance", "trace",
    ):  # fmt: skip
        assert f"\n{target}:" in text, target
    assert "flock $(UV_LOCK) uv sync" in text


def test_make_acceptance_requires_milestone() -> None:
    result = subprocess.run(
        ["make", "-C", str(ROOT), "acceptance"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 2
    assert "MILESTONE=M0|M1" in result.stderr


def test_devenv_module_exposes_root() -> None:
    assert devenv.ROOT == ROOT


@pytest.mark.slow
def test_pg_sh_lifecycle_on_private_root() -> None:
    """tools/dev/pg.sh up -> query -> reset -> down -> destroy, leaving nothing running."""
    try:
        find_pg_bin()
    except PgClusterError:
        pytest.skip("PostgreSQL binaries not available")
    root = Path(tempfile.mkdtemp(prefix="dwaar-devpg-", dir="/tmp"))
    os.chmod(root, 0o755)
    env = {
        **os.environ,
        "DWAAR_PG_ROOT": str(root / "pg"),
        "DWAAR_PG_PORT": str(free_port()),
        "DWAAR_DB_NAME": "dwaar_scripttest",
    }

    def pg(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(ROOT / "tools/dev/pg.sh"), *args], capture_output=True, text=True, env=env,
            check=False, timeout=120,
        )  # fmt: skip

    try:
        up = pg("up")
        assert up.returncode == 0, up.stderr
        assert pg("status").returncode == 0
        again = pg("up")  # idempotent
        assert again.returncode == 0, again.stderr
        info = pg(
            "psql",
            "-Atc",
            "SELECT current_database(), pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()",
        )
        assert info.stdout.strip() == "dwaar_scripttest|dwaar_owner", info.stderr
        roles = pg(
            "psql",
            "-d",
            "postgres",
            "-Atc",
            "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'dwaar\\_%' AND NOT rolsuper AND NOT rolbypassrls",
        )
        assert roles.stdout.strip() == "3"
        pg("psql", "-Atc", "CREATE TABLE gone_after_reset (i int)")
        assert pg("reset").returncode == 0
        assert (
            pg("psql", "-Atc", "SELECT to_regclass('gone_after_reset') IS NULL").stdout.strip()
            == "t"
        )
        assert pg("url", "app").stdout.strip().startswith("postgresql://dwaar_app:")
    finally:
        pg("down")
        pg("destroy")
        shutil.rmtree(root, ignore_errors=True)
    assert pg("status").returncode == 3


# --------------------------------------------------------------------------- slice 3: edge and worker variables
def _edge_vars_read_by_code() -> set[str]:
    import re

    used: set[str] = set()
    for pattern in (
        "services/edge/dwaar_edge/*.py",
        "services/api/dwaar_api/modules/edge/*.py",
        "services/api/dwaar_api/seed/steps/s450_edge.py",
        "services/worker/dwaar_worker/*.py",
    ):
        for path in ROOT.glob(pattern):
            used |= set(
                re.findall(
                    r"\b(DWAAR_(?:EDGE|WORKER|SEED_EDGE)[A-Z0-9_]*)\b",
                    path.read_text(encoding="utf-8"),
                )
            )
    return used - {"DWAAR" + "_EDGE_"}  # a prefix literal in the code, not a variable


def test_every_edge_and_worker_variable_the_code_reads_is_documented_in_env_example() -> None:
    import re

    documented = set(
        re.findall(r"^#?\s*(DWAAR_[A-Z0-9_]+)=", (ROOT / ".env.example").read_text(), re.M)
    )
    assert sorted(_edge_vars_read_by_code() - documented) == []
    for name in (
        "DWAAR_EDGE_POLICY_SIGNING_KEY", "DWAAR_EDGE_POLICY_KEY_ID", "DWAAR_EDGE_RETIRED_KEYS", "DWAAR_EDGE_REF_KEY",
        "DWAAR_EDGE_ISSUER_KEYS", "DWAAR_EDGE_PASS_KEYS", "DWAAR_EDGE_DEVICE_KEY", "DWAAR_EDGE_TOKEN_KEY", "DWAAR_EDGE_PII_KEYS",
    ):  # fmt: skip
        assert name in documented, name


def test_make_setup_generates_distinct_local_edge_keys_and_the_apps_accept_them() -> None:
    """``make setup`` renders .env.example: every edge key placeholder becomes its own 32-byte key, and the cloud edge config and the
    gateway config really load from the result (no empty or malformed key)."""
    from dwaar_api.core.config import load_settings
    from dwaar_api.modules.edge.config import EdgeConfig as CloudEdgeConfig
    from dwaar_api.modules.visits.config import VisitsConfig
    from dwaar_edge.config import EdgeConfig as GatewayEdgeConfig

    values = parse_env_text(render_env_from_example((ROOT / ".env.example").read_text()))
    keys = [
        values[n]
        for n in (
            "DWAAR_EDGE_POLICY_SIGNING_KEY", "DWAAR_EDGE_REF_KEY", "DWAAR_EDGE_DEVICE_KEY", "DWAAR_EDGE_TOKEN_KEY",
            "DWAAR_PASS_SIGNING_KEY", "DWAAR_VISITOR_HMAC_KEY",
        )
    ]  # fmt: skip
    assert len(set(keys)) == len(keys)
    assert all(len(base64.urlsafe_b64decode(k + "=" * (-len(k) % 4))) == 32 for k in keys)
    env = {**values, "DWAAR_ENV": "staging", "DWAAR_DATABASE_URL": "postgresql://dwaar_app:x@127.0.0.1:5/d", "DWAAR_CURSOR_SIGNING_KEY": generate_key(),
           "DWAAR_OIDC_ISSUER_URL": "https://idp.example", "DWAAR_OIDC_JWKS_URL": "https://idp.example/jwks"}  # fmt: skip
    settings = load_settings(env)
    cloud = CloudEdgeConfig.from_environment(
        settings, env
    )  # a non-local environment: the keys MUST come from the generated values
    assert cloud.signer.public_key_b64
    assert len(cloud.ref_key) == 32
    assert VisitsConfig.from_environment(settings, env).key_id
    import uuid

    gw_env = {**env, "DWAAR_EDGE_SOCIETY_ID": str(uuid.uuid4()), "DWAAR_EDGE_DEVICE_ID": str(uuid.uuid4()),
              "DWAAR_EDGE_ISSUER_KEYS": f"policy-1={cloud.signer.public_key_b64}"}  # fmt: skip
    gateway = GatewayEdgeConfig.from_env(gw_env)
    assert set(gateway.issuer_keys) == {"policy-1"}
    assert gateway.device_key_id == "edge-local-1"


# --------------------------------------------------------------------------- every variable is documented (slice 4)
_VAR = re.compile(r"""["'](DWAAR_[A-Z0-9]+(?:_[A-Z0-9]+)+)["']""")


def _documented_names() -> set[str]:
    return {
        m.group(1)
        for line in (ROOT / ".env.example").read_text().splitlines()
        if (m := re.match(r"^#?\s*(DWAAR_[A-Z0-9_]+)=", line))
    }


def test_every_settings_field_is_documented_in_env_example() -> None:
    """A deployer must find each core Settings variable in .env.example (the file `make setup` copies)."""
    from dwaar_api.core.config import Settings

    documented = _documented_names()
    missing = sorted(
        f"DWAAR_{name.upper()}"
        for name in Settings.model_fields
        if f"DWAAR_{name.upper()}" not in documented
    )
    # DWAAR_ENV is documented; the three URLs are documented under their own names.
    assert not missing, f"undocumented Settings fields: {missing}"


def test_every_environment_variable_read_by_product_code_is_documented() -> None:
    """Module configs (notifications, community, ai gateway, worker, ...) read os.environ directly: each name
    quoted in product source (not tests) must be in .env.example, so a new variable cannot ship undocumented."""
    found: dict[str, str] = {}
    for base in ("services", "packages"):
        for path in (ROOT / base).rglob("*.py"):
            parts = path.relative_to(ROOT).parts
            if (
                "tests" in parts
                or ".venv" in parts
                or "node_modules" in parts
                or path.name.startswith("test_")
            ):
                continue
            for name in _VAR.findall(path.read_text(encoding="utf-8")):
                found.setdefault(name, str(path.relative_to(ROOT)))
    missing = {n: where for n, where in sorted(found.items()) if n not in _documented_names()}
    assert not missing, f"variables read by code but missing from .env.example: {missing}"


def test_new_secrets_are_generated_by_make_setup_not_shipped() -> None:
    values = parse_env_text((ROOT / ".env.example").read_text())
    assert GENERATE_KEY in values["DWAAR_COMMUNITY_DOWNLOAD_KEY"]
    assert (
        values["DWAAR_AI_ANTHROPIC_API_KEY"] == ""
    )  # a provider key is never generated or shipped
    rendered = render_env_from_example((ROOT / ".env.example").read_text())
    assert "__GENERATE" not in rendered
    assert parse_env_text(rendered)["DWAAR_COMMUNITY_DOWNLOAD_KEY"] != GENERATE_KEY
