"""Fixtures for the gateway unit tests: no database, no network, no API key."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from dwaar_ai_gateway.config import GatewayConfig
from dwaar_ai_gateway.features import LocationDirectory, LocationRef
from dwaar_ai_gateway.pipeline import Availability, Gateway, GatewayRequest
from dwaar_ai_gateway.testing import PERSON, SOC, UNIT_A, UNIT_B
from dwaar_ai_gateway.types import Caller, GatewayResult


@pytest.fixture
def config() -> GatewayConfig:
    return GatewayConfig(environment="test", provider="simulator", timeout_seconds=1.0)


@pytest.fixture
def gateway(config: GatewayConfig) -> Gateway:
    return Gateway(config)


@pytest.fixture
def resident() -> Caller:
    return Caller(SOC, PERSON, "owner_occ", unit_ids=frozenset({UNIT_A}), language="en")


@pytest.fixture
def secretary() -> Caller:
    return Caller(SOC, PERSON, "secretary", society_wide=True, language="en")


@pytest.fixture
def directory() -> LocationDirectory:
    return LocationDirectory(
        units=[LocationRef(UNIT_A, "B", "B-402", 3), LocationRef(UNIT_B, "A", "A-101", 5)]
    )


@pytest.fixture
def run(gateway: Gateway) -> Callable[..., GatewayResult]:
    def go(feature: str, caller: Caller, inputs: dict, **kw: object) -> GatewayResult:
        return gateway.run(
            GatewayRequest(
                feature,
                caller,
                inputs,
                kw.pop("availability", Availability()),
                kw.pop("sources", ()),
                kw.pop("locations", None),
            )
        )  # type: ignore[arg-type]

    return go
