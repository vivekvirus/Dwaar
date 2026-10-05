"""W1 fix round 2: regression tests for Idempotency-Key semantics (INV-02, PRD 7.4 / 12).

These started life as failing repros in ``verify_w1_idempotency.py`` (open findings of verification round 1) and were moved
here when their root causes were fixed; each asserts the SECURE behaviour. Tests that already passed in the
repro file (attacks that were tried and did not work) are kept as regression evidence.
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from dwaar_api.core.authz import Grant
from dwaar_api.core.idempotency import request_hash
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import (
    COMMITTEE_A,
    SOCIETY_A,
    SOCIETY_B,
    CoreHarness,
    core_harness,
)

pytestmark = pytest.mark.req("INV-02", "INV-01")

OTHER_COMMITTEE = uuid.UUID("0192f300-0000-7000-8000-0000000000c9")
BOTH = uuid.UUID("0192f300-0000-7000-8000-0000000000d1")
KEY = "verify-key-000001"


@pytest.fixture
def core(db: DbHandle) -> Iterator[CoreHarness]:
    with core_harness(db) as harness:
        harness.resolver.add(OTHER_COMMITTEE, Grant("committee", SOCIETY_A))
        harness.resolver.add(BOTH, Grant("committee", SOCIETY_A))
        harness.resolver.add(BOTH, Grant("committee", SOCIETY_B))
        yield harness


def _post(
    core: CoreHarness,
    person: uuid.UUID,
    society: uuid.UUID,
    name: str,
    key: str = KEY,
    path: str = "things",
) -> Any:
    return core.client().post(
        f"/v1/probe/{society}/{path}",
        headers={**core.auth(person), "Idempotency-Key": key},
        json={"name": name},
    )


def _things(core: CoreHarness, society: uuid.UUID = SOCIETY_A) -> int:
    with core.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(society),))
        row = conn.execute("SELECT count(*) FROM probe_things").fetchone()
    assert row
    return int(row[0])


# ------------------------------------------------------------------------------------------------
# concurrency, scoping
# ------------------------------------------------------------------------------------------------


# ------------------------------------------------------------------------------------------------
# huge / hostile payloads
# ------------------------------------------------------------------------------------------------


def test_repeated_query_parameters_in_different_order_do_not_share_a_hash() -> None:
    """Starlette hands a scalar parameter the LAST value, so ?x=1&x=2 and ?x=2&x=1 are different requests,
    but request_hash sorts the pairs and gives them the same hash: a replay can answer the wrong one."""
    first = request_hash("POST", "/p", "amount=100&amount=200", b"")
    second = request_hash("POST", "/p", "amount=200&amount=100", b"")
    assert first != second


# ------------------------------------------------------------------------------------------------
# expiry, clock skew, partial failure
# ------------------------------------------------------------------------------------------------
def _expire_in(core: CoreHarness, seconds: int) -> None:
    with core.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_A),))
        conn.execute(
            "UPDATE idempotency_keys SET expires_at = now() + make_interval(secs => %s)", (seconds,)
        )


def test_replayed_body_carries_the_original_request_id_but_header_has_the_new_one(
    core: CoreHarness,
) -> None:
    """Informational: a replay returns the stored body (first request's request_id inside) with a fresh
    X-Request-ID header, so support tracing by the body field points at the wrong request."""
    first = _post(core, COMMITTEE_A, SOCIETY_A, "trace")
    second = _post(core, COMMITTEE_A, SOCIETY_A, "trace")
    assert second.headers["idempotent-replayed"] == "true"
    assert second.json()["request_id"] == second.headers["x-request-id"], (
        first.json()["request_id"],
        second.headers["x-request-id"],
    )
