"""Locating the pack directories (``packages/legal-packs`` and ``packages/tax-packs``)."""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger("dwaar_packs")
_OVERRIDE_ENVIRONMENTS = frozenset({"local", "test"})


def packages_root() -> Path:
    """Directory that contains ``legal-packs`` and ``tax-packs``.

    ``DWAAR_PACKS_ROOT`` overrides discovery ONLY when ``DWAAR_ENV`` is ``local`` or ``test`` (development
    and test fixtures). Anywhere else (including an unset ``DWAAR_ENV``) it is ignored with a warning, so a
    stray environment variable can never swap the law the platform runs on (GOV-01, INV-10).
    """
    env = os.environ.get("DWAAR_PACKS_ROOT")
    if env:
        if os.environ.get("DWAAR_ENV", "").strip().lower() in _OVERRIDE_ENVIRONMENTS:
            return Path(env)
        log.warning("DWAAR_PACKS_ROOT ignored: it is honoured only when DWAAR_ENV is local or test")
    for parent in Path(__file__).resolve().parents:
        if (parent / "legal-packs").is_dir() and (parent / "tax-packs").is_dir():
            return parent
        if (parent / "packages" / "legal-packs").is_dir():
            return parent / "packages"
    raise FileNotFoundError("cannot locate packages/legal-packs; set DWAAR_PACKS_ROOT")


def legal_packs_dir() -> Path:
    return packages_root() / "legal-packs"


def tax_packs_dir() -> Path:
    return packages_root() / "tax-packs"
