"""Where the versioned prompt files and evaluation sets live (``packages/prompts``).

REQ: AI-SYS-07 (prompts are versioned files in the repository). ``DWAAR_PROMPTS_DIR`` overrides the location for deployments
that ship the files elsewhere; otherwise the repository layout is used.
"""

from __future__ import annotations

import os
from pathlib import Path


def prompts_root() -> Path:
    override = os.environ.get("DWAAR_PROMPTS_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "packages" / "prompts"


def evals_root() -> Path:
    return prompts_root() / "evals"
