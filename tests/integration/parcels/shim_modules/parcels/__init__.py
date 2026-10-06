"""Re-export of the real parcels module under a test-only package."""

from dwaar_api.modules.parcels import permissions, router

__all__ = ["permissions", "router"]
