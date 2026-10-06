"""Feature catalogue (M1 subset of PRD 11.1)."""

from .handlers import build_handlers, diagnose_notifications, resolve_location
from .spec import (
    FeatureHandler,
    FeatureOutput,
    FeatureSpec,
    InvalidInput,
    LocationDirectory,
    LocationRef,
    Prepared,
)

__all__ = [
    "FeatureHandler", "FeatureOutput", "FeatureSpec", "InvalidInput", "LocationDirectory", "LocationRef", "Prepared",
    "build_handlers", "diagnose_notifications", "resolve_location",
]  # fmt: skip
