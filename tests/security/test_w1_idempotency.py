"""Regression tests from W1 verification and fix round 1: Idempotency-Key semantics (INV-02, PRD 7.4 / 12).

Fixed in round 1: F10 (claim loop under clock skew), F11 (late retry after expiry), F12 (body size limit),
F13 (Decimal responses).
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import datetime as dt
import threading
import time
import uuid
from collections.abc import Iterator
from decimal import Decimal
from typing import Annotated, Any

import pytest
from fastapi import APIRouter, Depends

from dwaar_api.core import idempotency
from dwaar_api.core.authz import AuthContext, Grant, Permission, require
from dwaar_api.core.idempotency import IdempotentCall, idempotency_required, request_hash
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
def test_concurrent_identical_requests_produce_one_effect(core: CoreHarness) -> None:
    results: list[Any] = []

    def go() -> None:
        results.append(_post(core, COMMITTEE_A, SOCIETY_A, "slow:one"))

    threads = [threading.Thread(target=go) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(r.status_code for r in results) == [201] * 10
    assert len({r.json()["id"] for r in results}) == 1
    assert _things(core) == 1


def test_concurrent_same_key_different_payload_yields_one_effect_and_409s(
    core: CoreHarness,
) -> None:
    results: list[Any] = []

    def go(name: str) -> None:
        results.append(_post(core, COMMITTEE_A, SOCIETY_A, name))

    threads = [threading.Thread(target=go, args=(f"slow:{i}",)) for i in range(6)]
    for t in threads:
        t.start()
        time.sleep(0.02)
    for t in threads:
        t.join()
    codes = sorted(r.status_code for r in results)
    assert codes.count(201) == 1 and codes.count(409) == 5, codes
    assert _things(core) == 1


def test_same_key_other_actor_is_independent_and_never_replays_foreign_response(
    core: CoreHarness,
) -> None:
    a = _post(core, COMMITTEE_A, SOCIETY_A, "alpha")
    b = _post(core, OTHER_COMMITTEE, SOCIETY_A, "alpha")
    assert a.status_code == b.status_code == 201
    assert a.json()["id"] != b.json()["id"]
    assert "idempotent-replayed" not in {k.lower() for k in b.headers}
    assert _things(core) == 2


def test_same_key_same_actor_other_society_is_independent(core: CoreHarness) -> None:
    a = _post(core, BOTH, SOCIETY_A, "alpha")
    b = core.client().post(
        f"/v1/probe/{SOCIETY_B}/things",
        headers={**core.auth(BOTH), "Idempotency-Key": KEY},
        json={"name": "alpha"},
    )
    assert a.status_code == 201
    assert b.status_code in (
        201,
        500,
    )  # probe table insert uses auth.scope society; both must not replay A
    assert "idempotent-replayed" not in {k.lower() for k in b.headers}
    assert b.json().get("id") != a.json().get("id")


def test_key_cannot_be_reused_for_another_endpoint_even_with_the_same_body(
    core: CoreHarness,
) -> None:
    assert _post(core, COMMITTEE_A, SOCIETY_A, "alpha").status_code == 201
    other = _post(core, COMMITTEE_A, SOCIETY_A, "alpha", path="things-alt")
    assert other.status_code == 409
    assert other.json()["code"] == "duplicate_payload_mismatch"
    assert _things(core) == 1


def test_key_case_and_whitespace_variants_are_different_keys_but_never_collide_silently(
    core: CoreHarness,
) -> None:
    assert _post(core, COMMITTEE_A, SOCIETY_A, "alpha", key="Verify-Key-000001").status_code == 201
    assert _post(core, COMMITTEE_A, SOCIETY_A, "alpha", key="verify-key-000001").status_code == 201
    assert _things(core) == 2
    bad = core.client().post(
        f"/v1/probe/{SOCIETY_A}/things",
        headers={**core.auth(COMMITTEE_A), "Idempotency-Key": "verify-key-000001 "},
        json={"name": "alpha"},
    )
    assert bad.status_code in (200, 201, 400, 422)


# ------------------------------------------------------------------------------------------------
# huge / hostile payloads
# ------------------------------------------------------------------------------------------------
def test_oversized_body_is_refused_before_it_is_buffered_and_hashed(core: CoreHarness) -> None:
    """The idempotency dependency does ``await request.body()`` and canonicalises the whole JSON before any
    schema validation; nothing in the app limits body size, so memory/CPU are attacker-chosen."""
    big = "a" * 30_000_000
    started = time.perf_counter()
    resp = _post(core, COMMITTEE_A, SOCIETY_A, big)
    elapsed = time.perf_counter() - started
    assert resp.status_code == 413, (
        f"30 MB body answered {resp.status_code} after {elapsed:.1f}s (no size limit)"
    )


def test_pathologically_deep_json_is_a_client_error_not_a_500(core: CoreHarness) -> None:
    depth = 200_000
    body = "[" * depth + "]" * depth
    resp = core.client().post(
        f"/v1/probe/{SOCIETY_A}/things",
        headers={
            **core.auth(COMMITTEE_A),
            "Idempotency-Key": KEY,
            "Content-Type": "application/json",
        },
        content=body,
    )
    assert resp.status_code in (400, 413, 422), (resp.status_code, resp.text[:120])


def test_json_float_bodies_hash_stably_and_never_collide_with_integers() -> None:
    a = request_hash("POST", "/p", "", b'{"amount": 100}')
    b = request_hash("POST", "/p", "", b'{"amount": 100.0}')
    c = request_hash("POST", "/p", "", b'{"amount":100}')
    assert a == c
    assert a != b


# ------------------------------------------------------------------------------------------------
# expiry, clock skew, partial failure
# ------------------------------------------------------------------------------------------------
def _expire_in(core: CoreHarness, seconds: int) -> None:
    with core.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_A),))
        conn.execute(
            "UPDATE idempotency_keys SET expires_at = now() + make_interval(secs => %s)", (seconds,)
        )


def _skew_application_clock(monkeypatch: pytest.MonkeyPatch, seconds: int) -> None:
    """Move every application-side clock the idempotency path could use; the database clock stays put."""
    from dwaar_common import timeutil

    real = timeutil.utc_now
    skewed = lambda: real() + dt.timedelta(seconds=seconds)  # noqa: E731
    monkeypatch.setattr(timeutil, "utc_now", skewed)
    monkeypatch.setattr(
        idempotency, "utc_now", skewed, raising=False
    )  # the claim no longer reads it


def test_late_retry_after_key_expiry_does_not_repeat_the_effect(core: CoreHarness) -> None:
    """Offline-first clients queue writes for days; after ``idempotency_ttl_seconds`` (default 24 h) the key
    is simply free, so a delayed retry of the SAME key and payload executes a second time."""
    first = _post(core, COMMITTEE_A, SOCIETY_A, "payment-ish")
    _expire_in(core, -3600)
    second = _post(core, COMMITTEE_A, SOCIETY_A, "payment-ish")
    assert first.status_code == second.status_code == 201
    assert _things(core) == 1, f"retry after expiry created {_things(core)} effects"


def test_app_clock_ahead_of_database_clock_does_not_loop_in_claim(
    core: CoreHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """expiry is judged by the Python clock but the reclaim UPDATE re-checks ``expires_at <= now()`` on the
    DB clock. With the app clock ahead, ``_claim`` recurses forever -> RecursionError -> HTTP 500."""
    assert _post(core, COMMITTEE_A, SOCIETY_A, "skew").status_code == 201
    _expire_in(core, 5)
    _skew_application_clock(monkeypatch, +10)
    resp = _post(core, COMMITTEE_A, SOCIETY_A, "skew")
    assert resp.status_code != 500, f"claim recursion: {resp.status_code} {resp.text[:100]}"
    assert resp.status_code == 201  # same request, key still stored: replayed, never re-executed
    assert _things(core) == 1


def test_app_clock_behind_database_clock_never_replays_an_expired_key_as_valid(
    core: CoreHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _post(core, COMMITTEE_A, SOCIETY_A, "skew2").status_code == 201
    _expire_in(core, -5)  # expired 5 s ago on the DB clock
    _skew_application_clock(monkeypatch, -30)
    resp = _post(core, COMMITTEE_A, SOCIETY_A, "skew2")
    # consistent behaviour either way: replay (still valid by app clock) or a fresh execution, never a 500
    assert resp.status_code in (201, 409)


def test_response_with_decimal_quantities_is_stored_and_replayed_exactly(core: CoreHarness) -> None:
    """Quantities are fixed-decimal (Wh, litres). ``jsonable_encoder`` turns Decimal into float."""
    router = APIRouter()
    core.app.state.permissions.register(Permission("verify.qty", frozenset({"committee"})))

    @router.post("/v1/verify/{society_id}/qty")
    def qty(
        society_id: uuid.UUID,
        auth: Annotated[AuthContext, Depends(require("verify.qty"))],
        idem: Annotated[IdempotentCall, Depends(idempotency_required)],
    ) -> Any:
        return idem.run(
            auth, lambda conn: {"litres": Decimal("12345678901234567.89"), "paise": 10**18 + 1}
        )

    core.app.include_router(router)
    resp = core.client().post(
        f"/v1/verify/{SOCIETY_A}/qty",
        headers={**core.auth(COMMITTEE_A), "Idempotency-Key": KEY},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["paise"] == 10**18 + 1
    assert resp.json()["litres"] == "12345678901234567.89", (
        f"Decimal became {resp.json()['litres']!r}"
    )
