"""Provider registry: which adapters exist, which are usable, and why not (shown to authorised admins ONLY).

REQ: AI-SYS-01, BUILD_BRIEF section 6 (``blocked-external``: adapter + simulator, disabled by default, missing dependency shown to
authorised admins only), PRIV-14/G11 (sub-processors disclosed).
"""

from __future__ import annotations

from typing import Any

from ..config import SUBPROCESSORS, GatewayConfig
from .anthropic_adapter import AnthropicProvider, missing_dependency
from .base import Provider
from .simulator import SimulatorProvider


class ProviderUnavailable(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ProviderRegistry:
    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self._extra: dict[str, Provider] = {}  # test doubles, only in local/test
        self._anthropic: AnthropicProvider | None = None

    def register_test_double(self, provider: Provider) -> None:
        if not self.config.simulators_allowed:
            raise ProviderUnavailable("test doubles are refused outside local/test")
        self._extra[provider.name] = provider

    def _anthropic_state(self) -> tuple[bool, str | None]:
        if not self.config.anthropic_api_key:
            return False, "not configured: DWAAR_AI_ANTHROPIC_API_KEY is not set"
        dep = missing_dependency()
        if dep:
            return False, f"not configured: {dep}"
        return True, None

    def status(self) -> list[dict[str, Any]]:
        """Full adapter table. Callers MUST be authorised admins: it names missing dependencies."""
        ok, why = self._anthropic_state()
        sim_ok = self.config.simulators_allowed
        return [
            {
                "name": "simulator", "simulation": True, "enabled": sim_ok,
                "state": "enabled" if sim_ok else "disabled",
                "reason": None if sim_ok else "simulators are refused outside local/test",
                "selected": self.config.provider == "simulator",
            },
            {
                "name": "anthropic", "simulation": False, "enabled": ok,
                "state": "enabled" if ok else "not_configured", "reason": why,
                "selected": self.config.provider == "anthropic",
            },
        ]  # fmt: skip

    def subprocessors(self) -> list[dict[str, Any]]:
        return [dict(s) for s in SUBPROCESSORS]

    def get(self, name: str | None = None) -> Provider:
        wanted = name or self.config.provider
        if wanted in self._extra:
            return self._extra[wanted]
        if wanted == "simulator":
            if not self.config.simulators_allowed:
                raise ProviderUnavailable("simulator_not_allowed_in_this_environment")
            return SimulatorProvider()
        if wanted == "anthropic":
            ok, why = self._anthropic_state()
            if not ok:
                raise ProviderUnavailable(why or "not configured")
            if self._anthropic is None:
                assert self.config.anthropic_api_key
                self._anthropic = AnthropicProvider(
                    self.config.anthropic_api_key,
                    timeout_seconds=self.config.timeout_seconds,
                    usd_inr=self.config.usd_inr,
                )
            return self._anthropic
        raise ProviderUnavailable(f"unknown provider {wanted!r}")
