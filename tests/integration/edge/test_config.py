"""Edge configuration: simulated KMS issuer, rotation lists, keys only from the environment outside local/test.

REQ: EDGE-04 (issuer key ids, rotation), ARCH-02/ARCH-04 (keys come from the environment; placeholders only where simulators are allowed),
BUILD_BRIEF 7 (simulators are labelled).
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from dwaar_api.core.config import ConfigError
from dwaar_api.modules.edge import localdev, localkeys
from dwaar_api.modules.edge.config import EdgeConfig, SimulatedKmsSigner
from dwaar_common.crypto import key_to_b64
from dwaar_common.signing import (
    generate_private_key,
    key_id_for,
    private_key_to_b64,
    public_key_to_b64,
    verify_bytes,
)

pytestmark = [pytest.mark.req("EDGE-04")]


@dataclass
class FakeSettings:
    simulation: bool


def seed_b64() -> str:
    return private_key_to_b64(generate_private_key())


def test_local_defaults_are_labelled_simulation_and_derived_from_public_labels() -> None:
    cfg = EdgeConfig.from_environment(FakeSettings(True), {})  # type: ignore[arg-type]
    assert cfg.simulation is True and cfg.signer.simulation is True
    assert cfg.ref_key == localkeys.ref_key()
    keys = cfg.key_list()
    assert keys == [
        {
            "key_id": cfg.signer.key_id,
            "public_key": cfg.signer.public_key_b64,
            "status": "active",
            "simulation": True,
        }
    ]
    info = localdev.describe()
    assert (
        info["policy_issuer_key_id"] == cfg.signer.key_id
        and info["policy_issuer_public_key"] == cfg.signer.public_key_b64
    )


def test_outside_local_the_keys_are_required_and_never_defaulted() -> None:
    with pytest.raises(ConfigError, match="DWAAR_EDGE_POLICY_SIGNING_KEY"):
        EdgeConfig.from_environment(FakeSettings(False), {})  # type: ignore[arg-type]
    with pytest.raises(ConfigError, match="DWAAR_EDGE_REF_KEY"):
        EdgeConfig.from_environment(
            FakeSettings(False), {"DWAAR_EDGE_POLICY_SIGNING_KEY": seed_b64()}
        )  # type: ignore[arg-type]


def test_environment_keys_are_used_and_not_labelled_simulation_when_simulators_are_not_allowed() -> (
    None
):
    seed = seed_b64()
    ref = key_to_b64(b"r" * 32)
    cfg = EdgeConfig.from_environment(
        FakeSettings(False),  # type: ignore[arg-type]
        {
            "DWAAR_EDGE_POLICY_SIGNING_KEY": seed,
            "DWAAR_EDGE_REF_KEY": ref,
            "DWAAR_EDGE_POLICY_KEY_ID": "prod-2026-10",
        },
    )
    assert (
        cfg.signer.key_id == "prod-2026-10"
        and cfg.signer.simulation is False
        and cfg.simulation is False
    )
    signature = cfg.signer.sign(b"payload")
    from dwaar_common.signing import public_key_from_b64

    assert verify_bytes(public_key_from_b64(cfg.signer.public_key_b64), b"payload", signature)


def test_retired_keys_are_listed_after_the_active_one() -> None:
    old = generate_private_key()
    env = {
        "DWAAR_EDGE_POLICY_SIGNING_KEY": seed_b64(), "DWAAR_EDGE_REF_KEY": key_to_b64(b"r" * 32),
        "DWAAR_EDGE_RETIRED_KEYS": f"older:{public_key_to_b64(generate_private_key().public_key())}, {key_id_for(old.public_key())}:{public_key_to_b64(old.public_key())}",
    }  # fmt: skip
    cfg = EdgeConfig.from_environment(FakeSettings(False), env)  # type: ignore[arg-type]
    listed = cfg.key_list()
    assert listed[0]["status"] == "active" and [k["status"] for k in listed[1:]] == [
        "retired",
        "retired",
    ]
    assert [k["key_id"] for k in listed[1:]] == sorted(k["key_id"] for k in listed[1:])  # type: ignore[type-var]


@pytest.mark.parametrize(
    "env",
    [
        {"DWAAR_EDGE_POLICY_SIGNING_KEY": "short"},
        {"DWAAR_EDGE_POLICY_SIGNING_KEY": "not base64 !!"},
        {"DWAAR_EDGE_POLICY_KEY_ID": "bad id with spaces"},
        {"DWAAR_EDGE_REF_KEY": "AAAA"},
        {"DWAAR_EDGE_RETIRED_KEYS": "nopublickey"},
        {"DWAAR_EDGE_RETIRED_KEYS": "k:AAAA"},
        {"DWAAR_EDGE_RATE_CAPACITY": "lots"},
        {"DWAAR_EDGE_RATE_CAPACITY": "0"},
    ],
)
def test_bad_configuration_is_a_config_error_not_a_crash(env: dict[str, str]) -> None:
    base = {
        "DWAAR_EDGE_POLICY_SIGNING_KEY": seed_b64(),
        "DWAAR_EDGE_REF_KEY": key_to_b64(b"r" * 32),
    }
    with pytest.raises(ConfigError):
        EdgeConfig.from_environment(FakeSettings(True), {**base, **env})  # type: ignore[arg-type]


def test_a_signer_never_shows_its_private_key() -> None:
    signer = SimulatedKmsSigner.from_seed_b64(seed_b64())
    assert "Ed25519PrivateKey" not in repr(signer) and signer.key_id.startswith("ed-")


def test_localdev_refuses_outside_local(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DWAAR_ENV", "staging")
    assert localdev.main() == 2
    monkeypatch.setenv("DWAAR_ENV", "local")
    assert localdev.main() == 0
    out = capsys.readouterr().out
    assert '"simulation": true' in out and "device_seed_b64url" in out
