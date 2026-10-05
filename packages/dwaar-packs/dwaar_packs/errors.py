"""Pack errors. Every error carries a stable ``code`` so callers can map it to the PRD 12.2 envelope."""

from __future__ import annotations


class PackError(Exception):
    code = "pack_error"


class PackValidationError(PackError):
    """A pack file failed JSON-Schema or model validation (INV-10: malformed law is rejected)."""

    code = "pack_invalid"

    def __init__(self, source: str, problems: list[str]) -> None:
        self.source = source
        self.problems = problems
        super().__init__(f"{source}: " + "; ".join(problems))


class RuleNotFound(PackError):
    code = "rule_not_found"


class RuleNotConfigured(PackError):
    """The rule exists but its value is null: configure it with a legal reference (GOV-01, TAX-05)."""

    code = "rule_not_configured"


class RuleNotEffective(PackError):
    """The requested date is outside the pack's effective range."""

    code = "rule_not_effective"


class ConfigBoundsError(PackError):
    """A per-society override violates approved bounds (D-13, D-15)."""

    code = "config_out_of_bounds"

    def __init__(self, violations: list[str]) -> None:
        self.violations = violations
        super().__init__("; ".join(violations))
