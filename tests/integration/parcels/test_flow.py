"""Parcels: pre-approval, receipt, storage, custody chain and the state machine (PAR-01, PAR-02, INV-07).

REQ: PAR-01 (brand + window; matched at the gate), PAR-02 (states, carrier reference, receiving guard, bin code, time, optional photo reference),
INV-07 (received / stored / collected are distinct), PRD 12.2 errors.
"""

from __future__ import annotations

import itertools
import uuid
from datetime import timedelta

import pytest

from tests.integration.parcels._support import PW, iso, now

pytestmark = [pytest.mark.req("PAR-01", "PAR-02", "INV-07")]


# REQ: PAR-01
def test_preapproval_is_tagged_by_brand_and_matched_at_the_gate_by_brand_and_window(pw: PW) -> None:
    h = pw.household("A-101")
    expected = pw.expect(h.owner, h.unit, "Zomart")
    assert expected["state"] == "expected" and expected["brand"] == "Zomart"
    assert expected["expectation"]["matched"] is False
    received = pw.receive(
        h.unit, "ZOMART", carrier_ref="AWB-1"
    )  # brand compared case-insensitively
    assert received["id"] == expected["id"], (
        "the open pre-approval of the same unit and brand is the parcel"
    )
    assert received["state"] == "received_at_gate" and received["expectation"]["matched"] is True


def test_a_different_brand_or_a_window_that_is_over_does_not_match(pw: PW) -> None:
    h = pw.household("A-101")
    pw.expect(h.owner, h.unit, "Zomart")
    other = pw.receive(h.unit, "Bluecart")
    assert other["expectation"]["matched"] is False
    past = pw.vw.call(
        h.owner, "POST", "/v1/parcel-expectations",
        json={"unit_id": str(h.unit), "brand": "Old", "expected_from": iso(now() - timedelta(days=3)), "expected_until": iso(now() - timedelta(days=2))},
    )  # fmt: skip
    assert past.status_code == 400 and past.json()["code"] == "invalid_schema"


def test_an_unexpected_parcel_is_recorded_with_who_when_and_the_carrier_reference(pw: PW) -> None:
    h = pw.household("A-102")
    p = pw.receive(h.unit, "Bluecart", carrier_ref="AWB-9", photo_ref="photo://minimal/1")
    assert p["state"] == "received_at_gate" and p["expectation"]["matched"] is False
    assert (
        p["carrier"] == "Bluefleet"
        and p["carrier_ref"] == "AWB-9"
        and p["photo_ref"] == "photo://minimal/1"
    )
    row = pw.rows(
        "SELECT received_by, received_at IS NOT NULL, custodian, custody_seq FROM parcels WHERE id = %s",
        (p["id"],),
    )[0]
    assert row == (pw.guard.id, True, f"guard:{pw.guard.id}", 1)


# REQ: PAR-02
def test_the_full_happy_path_states_and_the_custody_chain(pw: PW) -> None:
    h = pw.household("A-101")
    p = pw.receive(h.unit)
    stored = pw.store(p, "B-07")
    assert (
        stored["state"] == "stored"
        and stored["bin_code"] == "B-07"
        and stored["custodian"] == "storage:B-07"
    )
    ready, token = pw.issue_token(h.owner, stored)
    assert ready["state"] == "pickup_pending" and ready["pickup"]["token_live"] is True
    done = pw.call(pw.guard, "POST", f"/v1/parcels/{p['id']}/collect", json=pw.collect_body(token))
    assert done.status_code == 200, done.text
    body = done.json()
    assert (
        body["state"] == "collected"
        and body["collected"]["via"] == "token"
        and body["in_society_custody"] is False
    )
    chain = pw.rows(
        "SELECT seq, prev_seq, from_party, to_party, reason FROM custody_transfers WHERE parcel_id = %s ORDER BY seq",
        (p["id"],),
    )
    assert [c[0] for c in chain] == [1, 2, 3] and [c[1] for c in chain] == [None, 1, 2]
    assert [c[4] for c in chain] == ["received", "stored", "collected"]
    for earlier, later in itertools.pairwise(chain):
        assert earlier[3] == later[2], "each hand-over starts from the previous custodian"
    assert chain[0][2] == "courier" and chain[-1][3].startswith("resident")


def test_every_step_writes_an_audit_row_and_an_outbox_event(pw: PW) -> None:
    h = pw.household("A-101")
    p = pw.store(pw.receive(h.unit))
    for op in ("parcel.receive", "parcel.store"):
        assert pw.audit(op), op
    assert [e["version"] for e in pw.outbox("ParcelReceivedAtGate", p["id"])] == [1]
    assert pw.outbox("ParcelStored", p["id"])[0]["payload"]["state"] == "stored"


def test_store_needs_the_right_state_and_version(pw: PW) -> None:
    h = pw.household("A-101")
    p = pw.receive(h.unit)
    stale = pw.call(
        pw.guard,
        "POST",
        f"/v1/parcels/{p['id']}/store",
        json={"bin_code": "B-1", "expected_version": 99},
    )
    assert stale.status_code == 409 and stale.json()["code"] == "stale_version"
    stored = pw.store(p)
    again = pw.call(
        pw.guard,
        "POST",
        f"/v1/parcels/{p['id']}/store",
        json={"bin_code": "B-2", "expected_version": stored["version"]},
    )
    assert again.status_code == 422 and again.json()["code"] == "policy_violation"
    bad_bin = pw.call(
        pw.guard,
        "POST",
        f"/v1/parcels/{p['id']}/store",
        json={"bin_code": "../x", "expected_version": 1},
    )
    assert bad_bin.status_code == 400


def test_exactly_one_current_custodian_per_parcel_in_every_state(pw: PW) -> None:
    h = pw.household("A-101")
    parcels = [pw.receive(h.unit, f"Brand{i}") for i in range(3)]
    pw.store(parcels[1])
    for p in parcels:
        r = pw.rows(
            "SELECT p.custodian, (SELECT to_party FROM custody_transfers t WHERE t.parcel_id = p.id ORDER BY seq DESC LIMIT 1),"
            " (SELECT count(*) FROM custody_transfers t WHERE t.parcel_id = p.id AND NOT EXISTS (SELECT 1 FROM custody_transfers n"
            "  WHERE n.parcel_id = t.parcel_id AND n.prev_seq = t.seq)) FROM parcels p WHERE p.id = %s", (p["id"],),
        )[0]  # fmt: skip
        assert r[0] == r[1], "the parcel row names the head of the chain"
        assert r[2] == 1, "exactly one link has no successor: one current custodian"


# REQ: PAR-02
def test_refusal_return_and_loss_branches(pw: PW) -> None:
    h = pw.household("A-101")
    refused = pw.stored_parcel(h.unit)
    r = pw.call(
        pw.guard,
        "POST",
        f"/v1/parcels/{refused['id']}/resolve",
        json={
            "outcome": "refused",
            "note": "Recipient refused it",
            "expected_version": refused["version"],
        },
    )
    assert (
        r.status_code == 200
        and r.json()["state"] == "refused"
        and r.json()["in_society_custody"] is True
    )
    returned = pw.call(
        pw.guard,
        "POST",
        f"/v1/parcels/{refused['id']}/resolve",
        json={
            "outcome": "returned",
            "note": "Handed to the carrier",
            "expected_version": r.json()["version"],
        },
    )
    assert returned.status_code == 200 and returned.json()["state"] == "returned"
    assert (
        returned.json()["custodian"].startswith("carrier:")
        and returned.json()["in_society_custody"] is False
    )
    lost = pw.stored_parcel(h.unit, "Lostbrand")
    body = {
        "outcome": "lost_exception",
        "note": "Not on the shelf at the count",
        "expected_version": lost["version"],
    }
    by_guard = pw.call(pw.guard, "POST", f"/v1/parcels/{lost['id']}/resolve", json=body)
    assert by_guard.status_code == 403, "a guard cannot declare a parcel lost"
    by_sup = pw.call(pw.guard_sup, "POST", f"/v1/parcels/{lost['id']}/resolve", json=body)
    assert (
        by_sup.status_code == 200
        and by_sup.json()["state"] == "lost_exception"
        and by_sup.json()["custodian"] == "lost"
    )


def test_terminal_states_take_no_further_transition(pw: PW) -> None:
    h = pw.household("A-101")
    p = pw.stored_parcel(h.unit)
    _, token = pw.issue_token(h.owner, p)
    assert (
        pw.call(
            pw.guard, "POST", f"/v1/parcels/{p['id']}/collect", json=pw.collect_body(token)
        ).status_code
        == 200
    )
    r = pw.call(
        pw.guard,
        "POST",
        f"/v1/parcels/{p['id']}/resolve",
        json={"outcome": "returned", "note": "too late for that", "expected_version": 99},
    )
    assert r.status_code in (409, 422)
    v = pw.call(pw.guard, "GET", f"/v1/parcels/{p['id']}").json()["version"]
    r = pw.call(
        pw.guard,
        "POST",
        f"/v1/parcels/{p['id']}/resolve",
        json={"outcome": "returned", "note": "too late for that", "expected_version": v},
    )
    assert r.status_code == 422 and r.json()["details"]["reason"] == "transition_not_allowed"


def test_a_parcel_for_a_unit_in_another_society_or_a_made_up_unit_is_a_404(pw: PW) -> None:
    r = pw.call(
        pw.guard,
        "POST",
        "/v1/parcels",
        json={"unit_id": str(pw.other.unit), "gate_id": str(pw.gate_id), "brand": "X"},
    )
    assert r.status_code == 404 and r.json()["code"] == "not_found"
    r = pw.call(
        pw.guard,
        "POST",
        "/v1/parcels",
        json={"unit_id": str(uuid.uuid4()), "gate_id": str(pw.gate_id), "brand": "X"},
    )
    assert r.status_code == 404
    r = pw.call(
        pw.guard,
        "POST",
        "/v1/parcels",
        json={
            "unit_id": str(pw.household("A-101").unit),
            "gate_id": str(uuid.uuid4()),
            "brand": "X",
        },
    )
    assert r.status_code == 400


def test_receive_is_idempotent_on_the_idempotency_key(pw: PW) -> None:
    h = pw.household("A-101")
    body = {"unit_id": str(h.unit), "gate_id": str(pw.gate_id), "brand": "Zomart"}
    first = pw.call(pw.guard, "POST", "/v1/parcels", json=body, key="receive-key-0001")
    second = pw.call(pw.guard, "POST", "/v1/parcels", json=body, key="receive-key-0001")
    assert (
        first.status_code == second.status_code == 201
        and second.headers["Idempotent-Replayed"] == "true"
    )
    assert first.json()["id"] == second.json()["id"]
    assert pw.rows("SELECT count(*) FROM parcels WHERE unit_id = %s", (h.unit,))[0][0] == 1
    other = pw.call(
        pw.guard, "POST", "/v1/parcels", json={**body, "brand": "Different"}, key="receive-key-0001"
    )
    assert other.status_code == 409 and other.json()["code"] == "duplicate_payload_mismatch"
    missing = pw.vw.client.post(
        "/v1/parcels", headers={**pw.guard.headers, "X-Society-Id": str(pw.soc.id)}, json=body
    )
    assert missing.status_code == 400


def test_pagination_and_audience_views(pw: PW) -> None:
    h = pw.household("A-101")
    for i in range(5):
        pw.receive(h.unit, f"Brand{i}")
    page = pw.call(pw.guard, "GET", "/v1/parcels", params={"limit": 2}).json()
    assert len(page["items"]) == 2 and page["next_cursor"]
    seen = {i["id"] for i in page["items"]}
    nxt = pw.call(
        pw.guard, "GET", "/v1/parcels", params={"limit": 10, "cursor": page["next_cursor"]}
    ).json()
    assert len(nxt["items"]) == 3 and not seen & {i["id"] for i in nxt["items"]}
    too_big = pw.call(pw.guard, "GET", "/v1/parcels", params={"limit": 101})
    assert too_big.status_code == 400
    mine = pw.call(h.owner, "GET", "/v1/parcels").json()["items"]
    assert len(mine) == 5 and "pickup_attempts" in mine[0] and "received_by" in mine[0]
    guard_view = pw.call(pw.guard, "GET", f"/v1/parcels/{mine[0]['id']}").json()
    assert "pickup_attempts" not in guard_view and "received_by" not in guard_view
    stranger = pw.household("A-102")
    assert pw.call(stranger.owner, "GET", "/v1/parcels").json()["items"] == []
    assert pw.call(stranger.owner, "GET", f"/v1/parcels/{mine[0]['id']}").status_code == 404
    assert (
        pw.call(stranger.owner, "GET", "/v1/parcels", params={"unit_id": str(h.unit)}).status_code
        == 404
    )


def test_a_resident_cannot_receive_store_or_collect(pw: PW) -> None:
    h = pw.household("A-101")
    p = pw.receive(h.unit)
    for path, body in (
        ("/v1/parcels", {"unit_id": str(h.unit), "gate_id": str(pw.gate_id), "brand": "X"}),
        (f"/v1/parcels/{p['id']}/store", {"bin_code": "B-1", "expected_version": 1}),
        (
            f"/v1/parcels/{p['id']}/collect",
            {"method": "alternate_proof", "collector": {"kind": "recipient"}},
        ),
    ):
        assert pw.call(h.owner, "POST", path, json=body).status_code == 403, path


def test_the_partner_token_contract_and_label_ocr_are_not_built_pr_par_06_par_07(pw: PW) -> None:
    """PAR-07 (partner token contract, M3, disabled until a partner contract exists) and PAR-06 (label OCR, M2) have no surface at all."""
    assert not [p for p in pw.route_paths() if "partner" in p or "ocr" in p or "label" in p], (
        pw.route_paths()
    )
    cols = pw.rows(
        "SELECT column_name FROM information_schema.columns WHERE table_name IN ('parcels', 'custody_transfers')"
    )
    assert not [
        c
        for c in cols
        if any(w in c[0] for w in ("partner", "rider_ref", "jti", "assignment_version", "ocr"))
    ]
