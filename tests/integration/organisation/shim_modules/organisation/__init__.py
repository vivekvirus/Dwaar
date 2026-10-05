"""Re-export of the real organisation module under a test-only package (ADR-0006: ``create_app(modules_package=...)``)."""

from dwaar_api.modules.organisation import permissions, router

__all__ = ["permissions", "router"]
