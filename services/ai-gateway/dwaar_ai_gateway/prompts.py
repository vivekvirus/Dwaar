"""Versioned prompt files, JSON-schema outputs and the canary / rollback rollout (AI-SYS-07).

REQ: AI-SYS-07 (model or prompt changes run the regression set and a canary rollout; prompts are versioned files in the
repository), AI-SYS-06 (per-feature rollback without an app update: a version pin passed in from the database wins over the file).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .paths import prompts_root
from .types import Tier


class PromptError(Exception):
    pass


@dataclass(frozen=True)
class PromptBundle:
    feature_id: str
    directory: str
    version: str
    system: str
    schema: dict[str, Any]
    schema_version: str
    tier: Tier
    sha256: str
    canary: bool = False

    @property
    def label(self) -> str:
        return f"{self.directory}/{self.version}"


def society_bucket(society_id: uuid.UUID) -> int:
    """Stable 0..99 bucket of a society for canary rollouts."""
    return int(hashlib.sha256(str(society_id).encode()).hexdigest()[:8], 16) % 100


class PromptStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or prompts_root()
        try:
            data = yaml.safe_load((self.root / "registry.yaml").read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PromptError(f"prompt registry unreadable: {type(exc).__name__}") from None
        self.entries: dict[str, dict[str, Any]] = dict((data or {}).get("features") or {})

    def features(self) -> list[str]:
        return sorted(self.entries)

    def versions(self, feature_id: str) -> list[str]:
        entry = self._entry(feature_id)
        base = self.root / str(entry["dir"])
        return sorted(p.name for p in base.iterdir() if p.is_dir() and (p / "prompt.md").exists())

    def _entry(self, feature_id: str) -> dict[str, Any]:
        entry = self.entries.get(feature_id)
        if entry is None:
            raise PromptError(f"no prompt registered for {feature_id}")
        return entry

    def choose_version(
        self, feature_id: str, society_id: uuid.UUID | None = None, pin: str | None = None
    ) -> tuple[str, bool]:
        """(version, is_canary). A pin (database rollback) wins; then the canary bucket; then the active version."""
        entry = self._entry(feature_id)
        if pin:
            return pin, False
        canary = entry.get("canary")
        percent = int(entry.get("canary_percent") or 0)
        if canary and society_id is not None and society_bucket(society_id) < percent:
            return str(canary), True
        return str(entry["active"]), False

    def load(
        self,
        feature_id: str,
        society_id: uuid.UUID | None = None,
        pin: str | None = None,
        *,
        version: str | None = None,
    ) -> PromptBundle:
        entry = self._entry(feature_id)
        canary = False
        if version is None:
            version, canary = self.choose_version(feature_id, society_id, pin)
        base = self.root / str(entry["dir"]) / version
        if not (base / "prompt.md").is_file():
            raise PromptError(f"prompt {entry['dir']}/{version} not found")
        system = (base / "prompt.md").read_text(encoding="utf-8")
        schema_text = (base / "output.schema.json").read_text(encoding="utf-8")
        meta = yaml.safe_load((base / "meta.yaml").read_text(encoding="utf-8")) or {}
        if meta.get("feature_id") != feature_id:
            raise PromptError(f"{base}: meta.feature_id does not match the registry")
        digest = hashlib.sha256((system + "\n" + schema_text).encode("utf-8")).hexdigest()
        return PromptBundle(
            feature_id=feature_id,
            directory=str(entry["dir"]),
            version=version,
            system=system,
            schema=json.loads(schema_text),
            schema_version=str(meta.get("schema_version", "1")),
            tier=Tier(str(meta.get("tier", "extract"))),
            sha256=digest,
            canary=canary,
        )
