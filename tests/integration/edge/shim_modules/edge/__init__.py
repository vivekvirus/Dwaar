"""Re-export of the real edge module under a test-only package."""

from dwaar_api.modules.edge import permissions, register, router

__all__ = ["permissions", "register", "router"]
