"""Re-export of the real notifications module under a test-only package."""

from dwaar_api.modules.notifications import permissions, register, router

__all__ = ["permissions", "register", "router"]
