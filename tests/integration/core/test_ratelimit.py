"""Python wrapper over the Postgres token bucket: 429 with retry information (IAM-06, PRD 12.2)."""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest

from dwaar_api.core.db import Database
from dwaar_api.core.ratelimit import enforce, take
from dwaar_common.errors import RateLimited
from tests._harness.pgfixtures import DbHandle

pytestmark = pytest.mark.req("IAM-06", "ARCH-05")


@pytest.fixture
def database(db: DbHandle) -> Iterator[Database]:
    database = Database(db.app_dsn)
    try:
        yield database
    finally:
        database.dispose()


def test_enforce_raises_429_with_retry_after_once_the_bucket_is_empty(database: Database) -> None:
    for _ in range(3):
        enforce(database, "otp:phone:hash-abc", capacity=3, refill_per_second=0.2)
    with pytest.raises(RateLimited) as exc:
        enforce(database, "otp:phone:hash-abc", capacity=3, refill_per_second=0.2)
    assert exc.value.status == 429
    assert exc.value.code == "rate_limited"
    assert exc.value.retry_after >= 1  # about 5 s at 0.2 tokens/s
    assert exc.value.headers == {"Retry-After": str(exc.value.retry_after)}
    assert exc.value.details["retry_after_seconds"] == exc.value.retry_after


def test_a_denied_attempt_is_persisted_even_though_the_request_fails(
    database: Database, db: DbHandle
) -> None:
    take(database, "k", capacity=1, refill_per_second=0.001)
    denied = take(database, "k", capacity=1, refill_per_second=0.001)
    assert denied.allowed is False
    assert denied.retry_after_seconds >= 1
    with db.admin_conn() as conn:
        assert conn.execute(
            "SELECT count(*) FROM rate_limit_buckets WHERE key = 'k'"
        ).fetchone() == (1,)


def test_bucket_refills(database: Database) -> None:
    assert take(database, "fast", capacity=1, refill_per_second=50.0).allowed
    assert not take(database, "fast", capacity=1, refill_per_second=50.0).allowed
    time.sleep(0.1)
    assert take(database, "fast", capacity=1, refill_per_second=50.0).allowed
