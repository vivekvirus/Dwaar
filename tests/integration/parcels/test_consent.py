"""Leave-at-gate consent: explicit, revocable BEFORE custody (PAR-03), and no screenshot as proof (PAR-08, PAR-01).

REQ: PAR-03, PAR-08, PAR-01.
"""

from __future__ import annotations

import pytest

from tests.integration.parcels._support import PW

pytestmark = [pytest.mark.req("PAR-03", "PAR-08", "PAR-01")]


def _put(pw: PW, who, parcel, granted: bool):  # type: ignore[no-untyped-def]
    return pw.call(
        who,
        "PUT",
        f"/v1/parcels/{parcel['id']}/leave-at-gate-consent",
        json={"granted": granted, "expected_version": parcel["version"]},
    )


# REQ: PAR-03
def test_leave_at_gate_is_refused_without_the_residents_explicit_consent(pw: PW) -> None:
    h = pw.household("A-101")
    unexpected = pw.vw.call(
        pw.guard,
        "POST",
        "/v1/parcels",
        json={
            "unit_id": str(h.unit),
            "gate_id": str(pw.gate_id),
            "brand": "X",
            "leave_at_gate": True,
        },
    )
    assert (
        unexpected.status_code == 422
        and unexpected.json()["details"]["reason"] == "leave_at_gate_consent_required"
    )
    pw.expect(h.owner, h.unit, "Zomart")  # a pre-approval WITHOUT consent
    still = pw.vw.call(
        pw.guard,
        "POST",
        "/v1/parcels",
        json={
            "unit_id": str(h.unit),
            "gate_id": str(pw.gate_id),
            "brand": "Zomart",
            "leave_at_gate": True,
        },
    )
    assert (
        still.status_code == 422
        and still.json()["details"]["reason"] == "leave_at_gate_consent_required"
    )
    assert pw.rows("SELECT count(*) FROM custody_transfers")[0][0] == 0, (
        "nothing was taken into custody"
    )


def test_with_consent_the_guard_may_take_the_parcel_unattended(pw: PW) -> None:
    h = pw.household("A-101")
    exp = pw.expect(h.owner, h.unit, "Zomart", leave_at_gate_consent=True)
    assert exp["leave_at_gate"]["consent_active"] is True
    got = pw.receive(h.unit, "Zomart", leave_at_gate=True)
    assert got["state"] == "received_at_gate" and got["leave_at_gate"]["left_at_gate"] is True


def test_consent_can_be_granted_and_revoked_before_custody(pw: PW) -> None:
    h = pw.household("A-101")
    exp = pw.expect(h.owner, h.unit, "Zomart")
    granted = _put(pw, h.owner, exp, True)
    assert granted.status_code == 200 and granted.json()["leave_at_gate"]["consent_active"] is True
    revoked = _put(pw, h.owner, granted.json(), False)
    assert revoked.status_code == 200 and revoked.json()["leave_at_gate"]["consent_active"] is False
    assert revoked.json()["leave_at_gate"]["revoked_at"] is not None
    refused = pw.vw.call(
        pw.guard,
        "POST",
        "/v1/parcels",
        json={
            "unit_id": str(h.unit),
            "gate_id": str(pw.gate_id),
            "brand": "Zomart",
            "leave_at_gate": True,
        },
    )
    assert refused.status_code == 422, "a revoked consent is no consent"
    regranted = _put(pw, h.owner, revoked.json(), True)
    assert regranted.json()["leave_at_gate"]["consent_active"] is True
    assert pw.outbox("LeaveAtGateConsentRevoked") and pw.audit("parcel.leave_at_gate_consent")


def test_consent_cannot_be_revoked_once_the_guard_has_custody(pw: PW) -> None:
    h = pw.household("A-101")
    exp = pw.expect(h.owner, h.unit, "Zomart", leave_at_gate_consent=True)
    received = pw.receive(h.unit, "Zomart", leave_at_gate=True)
    late = _put(pw, h.owner, {**exp, "version": received["version"]}, False)
    assert late.status_code == 422 and late.json()["details"]["reason"] == "custody_already_taken"


def test_revoking_a_consent_that_was_never_given_is_refused_and_a_stranger_gets_404(pw: PW) -> None:
    h = pw.household("A-101")
    exp = pw.expect(h.owner, h.unit)
    nothing = _put(pw, h.owner, exp, False)
    assert (
        nothing.status_code == 422 and nothing.json()["details"]["reason"] == "no_consent_to_revoke"
    )
    stranger = pw.household("A-102")
    assert _put(pw, stranger.owner, exp, True).status_code == 404


def test_a_pre_approval_can_be_withdrawn_until_custody(pw: PW) -> None:
    h = pw.household("A-101")
    exp = pw.expect(h.owner, h.unit)
    gone = pw.call(h.owner, "DELETE", f"/v1/parcel-expectations/{exp['id']}")
    assert gone.status_code == 200 and gone.json()["state"] == "cancelled"
    assert (
        pw.call(h.owner, "DELETE", f"/v1/parcel-expectations/{exp['id']}").json()["state"]
        == "cancelled"
    )
    nothing = pw.receive(h.unit, "Zomart")
    assert nothing["expectation"]["matched"] is False and nothing["id"] != exp["id"]
    taken = pw.expect(h.owner, h.unit, "Bluecart")
    pw.receive(h.unit, "Bluecart")
    assert pw.call(h.owner, "DELETE", f"/v1/parcel-expectations/{taken['id']}").status_code == 422


# REQ: PAR-08, PAR-01
def test_an_order_screenshot_is_never_accepted_as_a_pre_approval_source_or_proof(pw: PW) -> None:
    h = pw.household("A-101")
    body = {
        "unit_id": str(h.unit),
        "brand": "Zomart",
        "expected_from": "2026-10-06T10:00:00+00:00",
        "expected_until": "2026-10-06T12:00:00+00:00",
    }
    as_source = pw.call(
        h.owner, "POST", "/v1/parcel-expectations", json={**body, "source": "order_screenshot"}
    )
    assert (
        as_source.status_code == 422
        and as_source.json()["details"]["reason"] == "order_screenshot_not_available"
    )
    for smuggled in ("screenshot", "screenshot_ref", "order_image", "photo_proof"):
        r = pw.call(h.owner, "POST", "/v1/parcel-expectations", json={**body, smuggled: "x"})
        assert r.status_code == 400, smuggled  # unknown fields are rejected, not ignored
    assert pw.rows("SELECT count(*) FROM parcels")[0][0] == 0
