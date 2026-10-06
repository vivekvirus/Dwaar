"""Worker configuration: environment only, validated, no values in error messages."""

from __future__ import annotations

import pytest

from dwaar_worker.config import WorkerConfig, WorkerConfigError


def test_defaults_without_any_environment() -> None:
    cfg = WorkerConfig.from_env({})
    assert cfg.queue == "dwaar"
    assert (cfg.policy_interval_s, cfg.sweep_interval_s) == (60, 60)
    assert cfg.redis_url.startswith("redis://")


def test_values_come_from_the_environment() -> None:
    cfg = WorkerConfig.from_env(
        {
            "DWAAR_REDIS_URL": "rediss://cache.internal:6380/2",
            "DWAAR_WORKER_QUEUE": "edge-jobs",
            "DWAAR_WORKER_POLICY_INTERVAL_S": "30",
            "DWAAR_WORKER_SWEEP_INTERVAL_S": "120",
        }
    )
    assert (cfg.redis_url, cfg.queue, cfg.policy_interval_s, cfg.sweep_interval_s) == (
        "rediss://cache.internal:6380/2",
        "edge-jobs",
        30,
        120,
    )


@pytest.mark.parametrize(
    "env",
    [
        {"DWAAR_WORKER_QUEUE": "Bad Queue!"},
        {"DWAAR_REDIS_URL": "http://not-redis"},
        {"DWAAR_WORKER_POLICY_INTERVAL_S": "1"},
        {"DWAAR_WORKER_SWEEP_INTERVAL_S": "never"},
        {"DWAAR_WORKER_SWEEP_INTERVAL_S": "999999"},
    ],
)
def test_invalid_values_are_refused_by_variable_name_only(env: dict[str, str]) -> None:
    with pytest.raises(WorkerConfigError) as exc:
        WorkerConfig.from_env(env)
    assert all(v not in str(exc.value) for v in env.values())


def test_a_redis_broker_is_built_without_connecting() -> None:
    from dwaar_worker.broker import make_redis_broker

    broker = make_redis_broker(
        WorkerConfig(redis_url="redis://127.0.0.1:1/0")
    )  # nothing listens there: construction must not connect
    assert type(broker).__name__ == "RedisBroker"
