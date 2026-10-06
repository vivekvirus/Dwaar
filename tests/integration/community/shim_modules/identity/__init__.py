"""Re-export of the real identity module under a test-only package."""

from dwaar_api.modules.identity import permissions, register, router

__all__ = ["permissions", "register", "router"]
