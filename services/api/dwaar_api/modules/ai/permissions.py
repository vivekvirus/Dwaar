"""Permission declarations of the AI module (module-local; PRD 5.2 has no AI row).

REQ: INV-01, IAM-08, AI-SYS-04 (the role is re-derived NOW on every proposal and confirmation), PRD 10.2.

The matrix has no 'AI assistance' row, so these are declared HERE (listed in the slice-4 report as a request to fold into the matrix):
* ``ai.use``: residents and committee roles may ASK for AI help; WHICH feature a role may use is decided by the feature registry in the
  gateway (``FeatureSpec.roles``), so the registry cannot drift from the route table. UNIT scope: a resident's grant covers their own unit.
* ``ai.status.read`` / ``ai.audit.read`` / ``ai.controls.manage`` / ``ai.providers.read``: society administration of AI. The controls and the
  provider table are SENSITIVE (fresh grant lookup) and secretary-only; the provider table names missing dependencies, so it is for
  authorised admins only (BUILD_BRIEF section 6).
"""

from __future__ import annotations

from typing import Final

from ...core.authz import Permission, ScopeKind
from ..identity import matrix

RESIDENT_ROLES: Final = frozenset({matrix.OWNER_OCC, matrix.OWNER_NR, matrix.TENANT, matrix.FAMILY})
ADMIN_ROLES: Final = frozenset(
    {matrix.SECRETARY, matrix.COMMITTEE, matrix.ESTATE_MGR, matrix.TREASURER, matrix.GUARD_SUP}
)

permissions: Final = (
    Permission(
        "ai.use",
        RESIDENT_ROLES | ADMIN_ROLES,
        scope=ScopeKind.UNIT,
        description="Ask for AI assistance, read and confirm own proposals, send feedback, list own drafts. Which feature a role may use is "
        "decided by the gateway feature registry. Declining AI never reduces service.",
    ),
    Permission(
        "ai.status.read",
        frozenset({matrix.SECRETARY, matrix.COMMITTEE, matrix.ESTATE_MGR, matrix.AUDITOR}),
        description="Read AI usage, budget, kill-switch state and measured latency for the society",
    ),
    Permission(
        "ai.audit.read",
        frozenset({matrix.SECRETARY, matrix.AUDITOR}),
        description="Read the ai_runs audit list (no prompts, no payloads)",
    ),
    Permission(
        "ai.controls.manage",
        frozenset({matrix.SECRETARY}),
        description="Per-society AI kill switch; per-feature disable, prompt rollback pin and daily limit",
        sensitive=True,
    ),
    Permission(
        "ai.providers.read",
        frozenset({matrix.SECRETARY, matrix.ORG_ADMIN}),
        description="Provider adapter table including 'not configured: <missing dependency>' and the disclosed sub-processors (admins only)",
        sensitive=True,
    ),
)
