"""Re-export of the real visits module under a test-only package."""

from dwaar_api.modules.visits import permissions, register, router

__all__ = ["permissions", "register", "router"]
