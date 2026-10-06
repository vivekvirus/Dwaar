"""Re-export of the real staff module under a test-only package."""

from dwaar_api.modules.staff import permissions, router

__all__ = ["permissions", "router"]
