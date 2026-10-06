"""Provider adapter interface (D-18 'provider-neutral adapter')."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..types import ProviderRequest, ProviderResponse


class ProviderError(Exception):
    """The provider could not answer. ``kind``: timeout | outage | rate_limited | refused | error. Never carries model text."""

    def __init__(self, kind: str, detail: str = "") -> None:
        super().__init__(kind)
        self.kind = kind
        self.detail = detail


@runtime_checkable
class Provider(Protocol):
    name: str
    simulation: bool

    def complete(self, request: ProviderRequest) -> ProviderResponse: ...
