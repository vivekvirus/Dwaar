"""Re-export of the real AI module under a test-only package."""

from dwaar_api.modules.ai import permissions, register, router

__all__ = ["permissions", "register", "router"]
