"""Edge error types. Messages never contain credentials, nonces or personal data."""

from __future__ import annotations


class EdgeError(Exception):
    """Base class. ``code`` is a stable machine-readable string."""

    code = "edge_error"

    def __init__(self, message: str = "", *, code: str | None = None) -> None:
        super().__init__(message or self.code)
        if code is not None:
            self.code = code


class StoreLockedError(EdgeError):
    """Another process owns the SQLite file (EDGE-01: exactly one writer process)."""

    code = "store_locked"


class StoreCorruptError(EdgeError):
    """Startup integrity check failed; the gateway refuses to run on a damaged store."""

    code = "store_corrupt"


class MigrationError(EdgeError):
    code = "migration_error"


class PolicyRejected(EdgeError):
    """A policy snapshot was not applied. ``code`` says why (bad_signature, rollback, expired, ...)."""

    code = "policy_rejected"


class NotAuthorisedError(EdgeError):
    code = "not_authorised"


class ConflictError(EdgeError):
    code = "conflict"


class InvalidRequest(EdgeError):
    code = "invalid_request"


class TombstonesRequired(EdgeError):
    """EDGE-10: a stale terminal must process tombstones before uploading cached personal records."""

    code = "tombstones_required"


class SimulationOnly(EdgeError):
    """HW-06 / HW-03: nothing in this slice may reach real hardware."""

    code = "simulation_only"
