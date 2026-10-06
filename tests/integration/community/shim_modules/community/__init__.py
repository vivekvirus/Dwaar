"""Re-export of the real community module under a test-only package."""

from dwaar_api.modules.community import permissions, register, router

__all__ = ["permissions", "register", "router"]
