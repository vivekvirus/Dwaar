"""Pickup: single-use token, supervised alternate proof, delegated family pickup, denied attempts recorded (PAR-03, PAR-08, AT-13).

REQ: PAR-03, PAR-08, INV-07.
"""

from __future__ import annotations

import pytest

from tests.integration.parcels._support import PW

pytestmark = [pytest.mark.req("PAR-03", "PAR-08", "INV-07")]


def _collect(pw: PW, who, parcel_id, body, **kw):  # type: ignore[no-untyped-def]
    return pw.call(who, "POST", f"/v1/parcels/{parcel_id}/collect", json=body, **kw)


def _ready(pw: PW):  # type: ignore[no-untyped-def]
    h = pw.household("A-101", tenant=True)
    stored = pw.stored_parcel(h.unit)
    ready, token = pw.issue_token(h.owner, stored)
    return h, ready, token


# REQ: PAR-03
def test_the_pickup_token_is_shown_once_and_only_its_hash_is_stored(pw: PW) -> None:
    h, ready, token = _ready(pw)
    assert len(token) >= 30
    again = pw.call(h.owner, "GET", f"/v1/parcels/{ready['id']}").json()
    assert "pickup_token" not in again and "pickup_token_hash" not in again
    dump = pw.rows("SELECT pickup_token_hash FROM parcels WHERE id = %s", (ready["id"],))[0][0]
    assert dump != token and len(dump) == 64
    assert token not in str(pw.rows("SELECT payload::text FROM outbox")) and token not in str(
        pw.rows("SELECT diff_masked::text FROM audit_log")
    )


def test_the_token_is_single_use_and_the_second_attempt_is_denied_with_history_intact(
    pw: PW,
) -> None:
    """AT-13 at the module level."""
    h, ready, token = _ready(pw)
    first = _collect(pw, pw.guard, ready["id"], pw.collect_body(token))
    assert first.status_code == 200
    chain_before = pw.rows(
        "SELECT seq, from_party, to_party, at FROM custody_transfers WHERE parcel_id = %s ORDER BY seq",
        (ready["id"],),
    )
    second = _collect(pw, pw.guard, ready["id"], pw.collect_body(token))
    assert second.status_code == 409 and second.json()["code"] == "already_decided"
    assert second.json()["details"]["reason"] == "already_collected"
    assert (
        pw.rows(
            "SELECT seq, from_party, to_party, at FROM custody_transfers WHERE parcel_id = %s ORDER BY seq",
            (ready["id"],),
        )
        == chain_before
    )
    attempts = pw.rows(
        "SELECT outcome, reason, method FROM parcel_pickup_attempts WHERE parcel_id = %s ORDER BY at, id",
        (ready["id"],),
    )
    assert attempts == [("granted", "collected", "token"), ("denied", "already_collected", "token")]
    state = pw.rows(
        "SELECT state, custodian, collected_by_kind FROM parcels WHERE id = %s", (ready["id"],)
    )[0]
    assert state[0] == "collected" and state[1].startswith("resident")


def test_a_wrong_token_is_denied_and_recorded_and_does_not_burn_the_real_one(pw: PW) -> None:
    h, ready, token = _ready(pw)
    wrong = _collect(pw, pw.guard, ready["id"], pw.collect_body("x" * 32))
    assert wrong.status_code == 422 and wrong.json()["details"]["reason"] == "invalid_token"
    assert pw.rows(
        "SELECT outcome, reason FROM parcel_pickup_attempts WHERE parcel_id = %s", (ready["id"],)
    ) == [("denied", "invalid_token")]
    assert _collect(pw, pw.guard, ready["id"], pw.collect_body(token)).status_code == 200


def test_an_expired_token_is_refused(pw: PW) -> None:
    h, ready, token = _ready(pw)
    pw.sql(
        "UPDATE parcels SET pickup_token_expires_at = clock_timestamp() - interval '1 minute' WHERE id = %s",
        (ready["id"],),
    )
    late = _collect(pw, pw.guard, ready["id"], pw.collect_body(token))
    assert late.status_code == 422 and late.json()["details"]["reason"] == "token_expired"


def test_a_new_token_replaces_the_old_one(pw: PW) -> None:
    h, ready, old = _ready(pw)
    current = pw.call(h.owner, "GET", f"/v1/parcels/{ready['id']}").json()
    _, new = pw.issue_token(h.owner, current)
    assert new != old
    assert _collect(pw, pw.guard, ready["id"], pw.collect_body(old)).status_code == 422
    assert _collect(pw, pw.guard, ready["id"], pw.collect_body(new)).status_code == 200


def test_token_and_alternate_method_bodies_must_match_their_method(pw: PW) -> None:
    h, ready, token = _ready(pw)
    assert (
        _collect(
            pw, pw.guard, ready["id"], {"method": "token", "collector": {"kind": "recipient"}}
        ).status_code
        == 400
    )
    mixed = {
        "method": "alternate_proof",
        "token": token,
        "collector": {"kind": "recipient"},
        "alternate_proof": {"kind": "photo_id_checked", "note": "checked the id card"},
    }
    assert _collect(pw, pw.guard_sup, ready["id"], mixed).status_code == 400


# REQ: PAR-03
def test_alternate_proof_needs_the_supervisor_not_the_guard(pw: PW) -> None:
    h = pw.household("A-101")
    stored = pw.stored_parcel(h.unit)
    body = {
        "method": "alternate_proof",
        "collector": {"kind": "recipient"},
        "alternate_proof": {"kind": "photo_id_checked", "note": "Aadhaar shown, last four match"},
    }
    by_guard = _collect(pw, pw.guard, stored["id"], body)
    assert (
        by_guard.status_code == 403
        and by_guard.json()["details"]["reason"] == "supervision_required"
    )
    assert pw.rows(
        "SELECT outcome, reason, method FROM parcel_pickup_attempts WHERE parcel_id = %s",
        (stored["id"],),
    ) == [("denied", "supervision_required", "alternate_proof")]
    by_sup = _collect(pw, pw.guard_sup, stored["id"], body)
    assert by_sup.status_code == 200 and by_sup.json()["collected"] == {
        "at": by_sup.json()["collected"]["at"],
        "by_kind": "supervised_alternate",
        "via": "alternate_proof",
    }
    chain = pw.rows(
        "SELECT reason, evidence_ref FROM custody_transfers WHERE parcel_id = %s ORDER BY seq",
        (stored["id"],),
    )
    assert chain[-1] == ("collected", "alternate_proof:photo_id_checked")


# REQ: PAR-08
@pytest.mark.parametrize(
    "kind", ["order_screenshot", "screenshot", "Order_Page_Screenshot", "image_of_order"]
)
def test_a_screenshot_is_never_proof_of_entitlement_at_the_gate(pw: PW, kind: str) -> None:
    h = pw.household("A-101")
    stored = pw.stored_parcel(h.unit)
    body = {
        "method": "alternate_proof",
        "collector": {"kind": "recipient"},
        "alternate_proof": {"kind": kind, "note": "the rider shows an order page"},
    }
    for who in (pw.guard, pw.guard_sup):
        r = _collect(pw, who, stored["id"], body)
        assert (
            r.status_code == 422 and r.json()["details"]["reason"] == "screenshot_not_accepted"
        ), who
    assert pw.rows("SELECT state FROM parcels WHERE id = %s", (stored["id"],)) == [("stored",)]
    unknown = {**body, "alternate_proof": {"kind": "a_selfie", "note": "face of the collector"}}
    assert _collect(pw, pw.guard_sup, stored["id"], unknown).status_code == 400


# REQ: PAR-03
def test_family_pickup_requires_delegated_authority(pw: PW) -> None:
    undelegated = pw.household("A-101", family=False)
    plain_family = pw.resident(undelegated.unit, "family")
    stored = pw.stored_parcel(undelegated.unit)
    refused = pw.call(
        plain_family,
        "POST",
        f"/v1/parcels/{stored['id']}/pickup-token",
        json={"expected_version": stored["version"]},
    )
    assert (
        refused.status_code == 422 and refused.json()["details"]["reason"] == "delegation_required"
    )
    delegated = pw.household("A-102")  # owner + a DELEGATED family member
    stored2 = pw.stored_parcel(delegated.unit)
    ok, token = pw.issue_token(delegated.family, stored2)
    assert ok["state"] == "pickup_pending"
    # at the gate: a family collector must be a delegated member
    impostor = _collect(pw, pw.guard, stored2["id"], pw.collect_body(token, "family", plain_family))
    assert (
        impostor.status_code == 422
        and impostor.json()["details"]["reason"] == "delegation_required"
    )
    unnamed = _collect(pw, pw.guard, stored2["id"], pw.collect_body(token, "family"))
    assert (
        unnamed.status_code == 422 and unnamed.json()["details"]["reason"] == "delegation_required"
    )
    done = _collect(pw, pw.guard, stored2["id"], pw.collect_body(token, "family", delegated.family))
    assert done.status_code == 200 and done.json()["collected"]["by_kind"] == "delegate"
    last = pw.rows(
        "SELECT to_party FROM custody_transfers WHERE parcel_id = %s ORDER BY seq DESC LIMIT 1",
        (stored2["id"],),
    )[0][0]
    assert last == f"delegate:{delegated.family.id}"


def test_a_non_resident_owner_or_a_stranger_cannot_issue_the_token(pw: PW) -> None:
    h = pw.household("A-101", nr_owner=True)
    stored = pw.stored_parcel(h.unit)
    nr = pw.call(
        h.nr_owner,
        "POST",
        f"/v1/parcels/{stored['id']}/pickup-token",
        json={"expected_version": stored["version"]},
    )
    assert nr.status_code in (403, 404, 422), nr.text
    assert nr.status_code != 200
    stranger = pw.household("A-102")
    assert (
        pw.call(
            stranger.owner,
            "POST",
            f"/v1/parcels/{stored['id']}/pickup-token",
            json={"expected_version": stored["version"]},
        ).status_code
        == 404
    )


def test_a_token_cannot_be_issued_before_the_parcel_is_stored(pw: PW) -> None:
    h = pw.household("A-101")
    received = pw.receive(h.unit)
    r = pw.call(
        h.owner,
        "POST",
        f"/v1/parcels/{received['id']}/pickup-token",
        json={"expected_version": received["version"]},
    )
    assert r.status_code == 422 and r.json()["details"]["reason"] == "not_ready_for_pickup"


def test_replaying_the_same_idempotency_key_is_not_a_second_attempt(pw: PW) -> None:
    h, ready, token = _ready(pw)
    a = _collect(pw, pw.guard, ready["id"], pw.collect_body(token), key="collect-key-0001")
    b = _collect(pw, pw.guard, ready["id"], pw.collect_body(token), key="collect-key-0001")
    assert a.status_code == b.status_code == 200 and b.headers["Idempotent-Replayed"] == "true"
    assert pw.rows(
        "SELECT count(*) FROM parcel_pickup_attempts WHERE parcel_id = %s", (ready["id"],)
    ) == [(1,)]


def test_collecting_a_parcel_of_another_society_is_a_404(pw: PW) -> None:
    h, ready, token = _ready(pw)
    r = pw.call_b(
        pw.other.guard, "POST", f"/v1/parcels/{ready['id']}/collect", json=pw.collect_body(token)
    )
    assert r.status_code == 404
    assert pw.rows("SELECT state FROM parcels WHERE id = %s", (ready["id"],)) == [
        ("pickup_pending",)
    ]
