"""Re-export of the real organisation module under a test-only package."""

from dwaar_api.modules.organisation import permissions, router

__all__ = ["permissions", "router"]
