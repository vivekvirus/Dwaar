"""dwaar_packs: law is configuration (INV-10). See docs/adr/0007."""

from .approvals import (
    ApprovalRegistry,
    EnvApprovalRegistry,
    MappingApprovalRegistry,
    approval_pin,
    pack_content_hash,
)
from .binding import (
    binding_blockers,
    binding_status,
    is_binding_allowed,
    is_binding_ready,
    resolve_rule,
    rule_value,
    unconfigured_rule_keys,
    with_secretary_overrides,
)
from .cascade import CascadeConfig, cascade_config
from .errors import (
    ConfigBoundsError,
    PackError,
    PackValidationError,
    RuleNotConfigured,
    RuleNotEffective,
    RuleNotFound,
)
from .interest import InterestCapResult, InterestViolation, check_interest_cap
from .loader import build_pack, discover_pack_files, load_pack
from .models import LegalPack, RetentionRule
from .quorum import (
    QuorumResult,
    ResolutionResult,
    developer_selection_met,
    evaluate_quorum,
    evaluate_resolution,
    quorum_required,
    resolution_passes,
)
from .repository import FilePackRepository, InMemoryPackRepository, PackRepository
from .retention import retention_rule
from .rounding import RoundingMode
from .tax import assess_gst_rwa, compute_tds, einvoice_reporting_deadline
from .upi import upi_mdr_paise, upi_mdr_quote

__all__ = [
    "ApprovalRegistry",
    "CascadeConfig",
    "ConfigBoundsError",
    "EnvApprovalRegistry",
    "FilePackRepository",
    "InMemoryPackRepository",
    "InterestCapResult",
    "InterestViolation",
    "LegalPack",
    "MappingApprovalRegistry",
    "PackError",
    "PackRepository",
    "PackValidationError",
    "QuorumResult",
    "ResolutionResult",
    "RetentionRule",
    "RoundingMode",
    "RuleNotConfigured",
    "RuleNotEffective",
    "RuleNotFound",
    "approval_pin",
    "assess_gst_rwa",
    "binding_blockers",
    "binding_status",
    "build_pack",
    "cascade_config",
    "check_interest_cap",
    "compute_tds",
    "developer_selection_met",
    "discover_pack_files",
    "einvoice_reporting_deadline",
    "evaluate_quorum",
    "evaluate_resolution",
    "is_binding_allowed",
    "is_binding_ready",
    "load_pack",
    "pack_content_hash",
    "quorum_required",
    "resolution_passes",
    "resolve_rule",
    "retention_rule",
    "rule_value",
    "unconfigured_rule_keys",
    "upi_mdr_paise",
    "upi_mdr_quote",
    "with_secretary_overrides",
]
