#!/usr/bin/env python3
"""Local development environment helper (standard library only, except `init` key generation).

Layers, lowest to highest precedence:  .env.example (without generate-placeholders)
< .env < real process environment.

  devenv.py shell            print `export KEY='value'` lines (used by tools/dev/pg.sh)
  devenv.py exec -- CMD ...  run CMD with the merged environment (used by `make api`)
  devenv.py init             create .env from .env.example with freshly generated local keys
                             (never overwrites an existing .env)
  devenv.py print            print the merged environment as KEY=value (secrets masked)
"""

from __future__ import annotations

import base64
import os
import re
import secrets
import shlex
import sys
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATE_KEY = "__GENERATE_KEY__"
GENERATE_ED25519 = "__GENERATE_ED25519__"
_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_SECRET_NAME = re.compile(r"(KEY|SECRET|PASSWORD|TOKEN)", re.IGNORECASE)


def parse_env_text(text: str) -> dict[str, str]:
    """Minimal dotenv: KEY=value, optional quotes, `#` comments, no interpolation."""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        match = _LINE.match(raw)
        if not match:
            continue
        name, value = match.groups()
        if value[:1] in {'"', "'"} and value[-1:] == value[:1] and len(value) >= 2:
            value = value[1:-1]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        values[name] = value
    return values


def parse_env_file(path: Path) -> dict[str, str]:
    try:
        return parse_env_text(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


def load_env(root: Path = ROOT, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    merged = {
        k: v
        for k, v in parse_env_file(root / ".env.example").items()
        if GENERATE_KEY not in v and GENERATE_ED25519 not in v
    }
    merged.update(parse_env_file(root / ".env"))
    merged.update(os.environ if environ is None else environ)
    return merged


def generate_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def generate_ed25519_seed() -> str:
    # An Ed25519 private key is a 32-byte seed: no third-party library needed to mint one.
    return generate_key()


def render_env_from_example(example_text: str) -> str:
    """Replace each generate-placeholder with its own freshly generated value."""
    out: list[str] = []
    for original in example_text.splitlines():
        line = original
        while GENERATE_KEY in line:
            line = line.replace(GENERATE_KEY, generate_key(), 1)
        while GENERATE_ED25519 in line:
            line = line.replace(GENERATE_ED25519, generate_ed25519_seed(), 1)
        out.append(line)
    return "\n".join(out) + "\n"


def init_env(root: Path = ROOT) -> Path | None:
    """Create .env (mode 0600) from .env.example. Returns the path, or None if it existed."""
    target = root / ".env"
    if target.exists():
        return None
    example = (root / ".env.example").read_text(encoding="utf-8")
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(render_env_from_example(example))
    return target


def main(argv: list[str]) -> int:
    command = argv[0] if argv else "print"
    if command == "init":
        created = init_env()
        print(f"created {created}" if created else ".env already exists; left untouched")
        return 0
    env = load_env()
    if command == "shell":
        for name, value in sorted(env.items()):
            if name.startswith("DWAAR_") and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                print(f"export {name}={shlex.quote(value)}")
        return 0
    if command == "print":
        for name, value in sorted(env.items()):
            if name.startswith("DWAAR_"):
                print(f"{name}={'***' if _SECRET_NAME.search(name) and value else value}")
        return 0
    if command == "exec":
        rest = argv[1:]
        if rest[:1] == ["--"]:
            rest = rest[1:]
        if not rest:
            print("usage: devenv.py exec -- COMMAND [ARGS...]", file=sys.stderr)
            return 2
        os.execvpe(rest[0], rest, env)  # noqa: S606 - replaces this process by design
    print(f"unknown command {command!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
