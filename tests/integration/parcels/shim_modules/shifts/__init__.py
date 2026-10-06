"""Re-export of the real shifts module under a test-only package."""

from dwaar_api.modules.shifts import permissions, router

__all__ = ["permissions", "router"]
