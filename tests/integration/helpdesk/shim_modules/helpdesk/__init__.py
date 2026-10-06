"""Re-export of the real helpdesk module under a test-only package."""

from dwaar_api.modules.helpdesk import permissions, router

__all__ = ["permissions", "router"]
