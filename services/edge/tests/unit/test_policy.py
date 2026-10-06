"""Signed policy snapshots: verification, atomic apply, rollback, data minimisation (EDGE-04, EDGE-05)."""

from __future__ import annotations

import uuid
from datetime import timedelta
from pathlib import Path

import pytest

from dwaar_common.signing import Signer
from dwaar_edge.errors import PolicyRejected
from dwaar_edge.policy import verify_snapshot
from dwaar_edge.policy_model import minimisation_violations
from tests.integration.edge_gateway.support import (
    START,
    World,
    standard_world_with_policy,
)

pytestmark = pytest.mark.req("EDGE-04")

W = World()
KEYS = {W.issuer.key_id: W.issuer.public_key}


def verify(raw: dict, *, now=START + timedelta(minutes=1), cur: int = 0):  # type: ignore[no-untyped-def]
    return verify_snapshot(raw, issuer_keys=KEYS, society_id=W.society_id, now=now, current_seq=cur)


def snap(**kw):  # type: ignore[no-untyped-def]
    return W.snapshot(
        seq=kw.pop("seq", 5),
        issued_at=kw.pop("issued_at", START),
        manifest=kw.pop("manifest", W.manifest(residents=[W.resident()])),
        **kw,
    )


def code(raw: dict, **kw) -> str:  # type: ignore[no-untyped-def]
    with pytest.raises(PolicyRejected) as exc:
        verify(raw, **kw)
    return exc.value.code


def test_good_snapshot_verifies() -> None:
    s = verify(snap())
    assert s.seq == 5 and s.society_id == W.society_id


def test_tampered_snapshot_rejected() -> None:
    raw = snap()
    raw["manifest"]["residents"][0]["status"] = "active"
    raw["manifest"]["timing"]["guest_offline_max_s"] = 99
    assert code(raw) == "bad_signature"
    raw2 = snap()
    raw2["seq"] = 6
    assert code(raw2) == "bad_signature"


def test_signature_from_unprovisioned_or_wrong_key_rejected() -> None:
    assert code(snap(signer=W.other_issuer)) == "unknown_issuer"  # key id not provisioned
    forged = snap()
    forged["issuer_key_id"] = W.issuer.key_id
    forged["signature"] = snap(signer=Signer(W.issuer.key_id, W.other_issuer.private_key))[
        "signature"
    ]
    assert code(forged) == "bad_signature"  # claims the provisioned id but signed by another key


def test_issuer_key_is_never_taken_from_the_snapshot() -> None:
    raw = snap()
    raw["issuer_public_key"] = "AAAA"  # a snapshot cannot introduce a key
    assert code(raw) == "bad_signature"


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"society_id": uuid.uuid4()}, "wrong_society"),
        ({"schema_version": 2}, "unsupported_schema"),
    ],
)
def test_wrong_society_or_schema_rejected(kw: dict, expected: str) -> None:
    assert code(snap(**kw)) == expected


def test_rollback_and_duplicate_rejected() -> None:
    assert code(snap(seq=4), cur=5) == "rollback"
    assert code(snap(seq=5), cur=5) == "duplicate"
    assert verify(snap(seq=6), cur=5).seq == 6


def test_expired_and_future_snapshots_rejected() -> None:
    assert code(snap(valid_for=timedelta(minutes=1)), now=START + timedelta(hours=1)) == "expired"
    assert code(snap(issued_at=START + timedelta(days=2)), now=START) == "issued_in_future"


def test_unknown_field_is_rejected_as_data_minimisation() -> None:
    m = W.manifest(residents=[{**W.resident(), "phone": "+91 99999 00101"}])
    assert code(snap(manifest=m)) == "schema_invalid"
    m2 = W.manifest(residents=[W.resident()])
    m2["residents"][0]["full_name"] = "Invented Person"
    assert code(snap(manifest=m2)) == "schema_invalid"


def test_personal_data_in_free_form_members_rejected() -> None:
    rule = {
        "unit_id": str(W.unit_1),
        "rule_kind": "allow_window",
        "params": {"category": "x", "contact_phone": "9999900101", "phone": "x"},
        "effective_from": None,
        "effective_to": None,
    }
    assert code(snap(manifest=W.manifest(rules=[rule]))) == "minimisation_violation"
    inv = W.invitation(
        uuid.uuid4(),
        gate=None,
        start=START,
        end=START + timedelta(hours=1),
        visitor_alias="call +91 99999 00102",
    )
    assert code(snap(manifest=W.manifest(invitations=[inv]))) == "minimisation_violation"


def test_minimisation_helper_flags_keys_and_values() -> None:
    assert minimisation_violations({"a": {"Email": "x"}}) == ["$.a.Email"]
    assert minimisation_violations(["write to someone@example.invalid"]) == ["$[0]"]
    assert minimisation_violations({"category": "milk_vendor", "start_local": "06:00"}) == []


def test_malformed_inputs_never_raise_anything_but_policy_rejected() -> None:
    for bad in (
        {},
        {"issuer_key_id": 5, "signature": 1},
        {"issuer_key_id": "issuer-1", "signature": "nope"},
    ):
        assert code(bad) in {"malformed", "bad_signature"}


# ---- applying (gateway level) ---------------------------------------------------------------------------------
def test_apply_keeps_last_good_policy_on_rejection(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        assert gw.policy and gw.policy.seq == 1
        good = w.snapshot(
            seq=2, issued_at=t.wall_now, manifest=w.manifest(residents=[w.resident("cred-new")])
        )
        assert gw.apply_policy(good)["applied_seq"] == 2
        for bad in (
            w.snapshot(seq=1, issued_at=t.wall_now, manifest=w.manifest()),  # rollback
            {**good, "seq": 99},  # tampered
            w.snapshot(
                seq=3, issued_at=t.wall_now, manifest=w.manifest(), valid_for=timedelta(seconds=1)
            ),  # expired once time passes
        ):
            t.advance(5)
            with pytest.raises(PolicyRejected):
                gw.apply_policy(bad)
        assert gw.policy and gw.policy.seq == 2 and "cred-new" in gw.policy.residents
        rejected = [r["action"] for r in gw.store.all("SELECT action FROM audit_log")]
        assert rejected.count("policy_rejected") == 3
    finally:
        gw.stop()


def test_apply_is_atomic_when_the_process_dies_mid_apply(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)

    class Boom(Exception):
        pass

    def hook(label: str) -> None:
        if label == "after_policy_insert":
            raise Boom

    gw.store.crash_hook = hook
    with pytest.raises(Boom):
        gw.apply_policy(
            w.snapshot(
                seq=2,
                issued_at=t.wall_now,
                manifest=w.manifest(revocations=[{"ref": "cred-r1", "version": 1}]),
            )
        )
    assert (
        gw.store.one("SELECT COUNT(*) AS n FROM policy_snapshots WHERE seq=2")["n"] == 0
    )  # rolled back
    assert gw.store.one("SELECT COUNT(*) AS n FROM known_revocations")["n"] == 0
    assert gw.policy and gw.policy.seq == 1 and gw.policy_seq() == 1
    gw.store.crash_hook = None
    gw.apply_policy(w.snapshot(seq=2, issued_at=t.wall_now, manifest=w.manifest()))
    gw.stop()


def test_policy_survives_restart_and_stays_verified(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    gw.stop()
    gw2 = w.gateway(tmp_path / "edge", t)
    try:
        assert gw2.policy and gw2.policy.seq == 1
        assert gw2.policy.confirmed_at is not None  # confirmation persisted
    finally:
        gw2.stop()


def test_newest_known_deny_is_kept_across_snapshots(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    try:
        gw.apply_policy(
            w.snapshot(
                seq=2,
                issued_at=t.wall_now,
                manifest=w.manifest(
                    residents=[w.resident()], revocations=[{"ref": "cred-r1", "version": 3}]
                ),
            )
        )
        gw.apply_policy(
            w.snapshot(seq=3, issued_at=t.wall_now, manifest=w.manifest(residents=[w.resident()]))
        )  # omits the revocation
        assert gw.policy and gw.policy.revocations["cred-r1"] == 3
    finally:
        gw.stop()


def test_data_minimisation_at_rest_no_plaintext_personal_fields(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    inv = w.invitation(
        uuid.uuid4(),
        gate=w.gate_a,
        start=t.wall_now,
        end=t.wall_now + timedelta(hours=1),
        visitor_alias="DeliveryAlias",
        nonce="secret-nonce-123",
    )
    gw.apply_policy(
        w.snapshot(
            seq=2,
            issued_at=t.wall_now,
            manifest=w.manifest(residents=[w.resident("cred-secret-ref")], invitations=[inv]),
        )
    )
    gw.stop()
    blob = b"".join(p.read_bytes() for p in (tmp_path / "edge").glob("edge.sqlite3*"))
    for needle in (b"cred-secret-ref", b"secret-nonce-123", b"DeliveryAlias", b"p-cred-r1"):
        assert needle not in blob, needle  # sealed with the envelope cipher, not stored in clear


def test_random_ids_that_look_like_phone_numbers_are_not_personal_data() -> None:
    """Regression: a UUID with a long digit run (e.g. 99999000-...) must not make a legitimate snapshot fail."""
    unit = uuid.UUID("99999012-3456-7890-8123-456789012345")
    rule = {
        "unit_id": str(unit),
        "rule_kind": "allow_window",
        "params": {"category": "x", "start_local": "06:00", "end_local": "07:00"},
        "effective_from": None,
        "effective_to": None,
    }
    res = W.resident("cred-9999901234", unit_id=str(unit))
    assert verify(snap(manifest=W.manifest(rules=[rule], residents=[res]))).seq == 5
    # the same digits in a FREE-FORM member are still caught
    bad = {**rule, "params": {"category": "x", "note": "99999 01234"}}
    assert code(snap(manifest=W.manifest(rules=[bad]))) == "minimisation_violation"
    assert minimisation_violations("99999012-3456-7890-8123-456789012345") == []
