"""Approval EVIDENCE for packs (GOV-01): approval is not something a pack file can claim about itself.

REQ: GOV-01, INV-10.

A pack carries ``status: approved`` / ``approved_by`` / ``approved_at``, but those are just data: anyone who
can edit a YAML file can type an approver's name. A pack is therefore *binding* only if, in addition, an
approval registry holds a pin for exactly this ``pack_id@version`` and exactly this content
(``pack_content_hash``). The registry is deliberately NOT part of the pack tree:

* ``EnvApprovalRegistry`` (default) reads ``DWAAR_PACK_APPROVALS`` from the deployment configuration:
  ``id@version=sha256:<hex>`` entries separated by ``;`` or newlines. Approval is recorded after counsel/CA
  sign-off by whoever controls deployment secrets, with the hash taken from ``python -m dwaar_packs pin``.
* ``MappingApprovalRegistry`` is for tests and for a future DB-backed approvals table (PRD 8.2).

Any change to the pack's content (a rule value, a date, a source) changes the hash and silently revokes the
evidence until the new content is approved again. Operational toggles (``enabled``) and the claim fields
themselves are not part of the hash.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Protocol

from .models import PackHeader

APPROVALS_ENV: Final = "DWAAR_PACK_APPROVALS"
_EXCLUDED_FROM_HASH: Final = frozenset(
    {"status", "approved_by", "approved_at", "enabled", "disabled_reason"}
)
_PIN: Final = re.compile(
    r"^(?P<ref>[A-Za-z0-9._-]+@[A-Za-z0-9._+-]+)=(?P<hash>sha256:[0-9a-f]{64})$"
)


def pack_content_hash(pack: PackHeader) -> str:
    """``sha256:<hex>`` over the canonical JSON of everything counsel approves (not the approval claim)."""
    body = pack.model_dump(mode="json", exclude=set(_EXCLUDED_FROM_HASH))
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def pack_ref(pack: PackHeader) -> str:
    return f"{pack.pack_id}@{pack.version}"


def approval_pin(pack: PackHeader) -> str:
    """The registry entry that records approval of this exact pack content."""
    return f"{pack_ref(pack)}={pack_content_hash(pack)}"


class ApprovalRegistry(Protocol):
    def has_evidence(self, pack: PackHeader) -> bool: ...


@dataclass(frozen=True)
class MappingApprovalRegistry:
    """Pins held in memory: ``{"pack_id@version": "sha256:<hex>"}``."""

    pins: Mapping[str, str] = field(default_factory=dict)

    def has_evidence(self, pack: PackHeader) -> bool:
        return self.pins.get(pack_ref(pack)) == pack_content_hash(pack)


class EnvApprovalRegistry:
    """Pins from ``DWAAR_PACK_APPROVALS``, parsed on every call (so a rotated value takes effect at once)."""

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = environ

    def pins(self) -> dict[str, str]:
        env = os.environ if self._environ is None else self._environ
        out: dict[str, str] = {}
        for raw in re.split(r"[;\n]", env.get(APPROVALS_ENV, "")):
            entry = raw.strip()
            if not entry:
                continue
            match = _PIN.match(entry)
            if match:  # malformed entries are ignored: evidence is never guessed
                out[match.group("ref")] = match.group("hash")
        return out

    def has_evidence(self, pack: PackHeader) -> bool:
        return self.pins().get(pack_ref(pack)) == pack_content_hash(pack)


def default_registry() -> ApprovalRegistry:
    return EnvApprovalRegistry()
