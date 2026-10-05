"""No raw phone number anywhere: not in a response, a table, an audit row, an outbox payload or a log line (GATE-13);
guards never see a resident's number or identity.

REQ: GATE-13, GATE-08, INV-05, PRD 7.4, OBS-01.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import uuid
from typing import Any

import pytest

from tests.integration.visits._support import VW

pytestmark = [pytest.mark.req("GATE-13")]

VISITOR_PHONE = "+919999900777"
NATIONAL = "9999900777"


def _everything(vw: VW) -> str:
    """Every row of every table in schema public, as text (the oracle: a number stored anywhere shows up here)."""
    names = [
        r[0]
        for r in vw.rows("SELECT tablename FROM pg_tables WHERE schemaname IN ('public', 'iam')")
    ]
    chunks: list[str] = []
    for schema_table in vw.rows(
        "SELECT schemaname, tablename FROM pg_tables WHERE schemaname IN ('public', 'iam')"
    ):
        chunks.append(
            json.dumps(
                vw.rows(f'SELECT t::text FROM "{schema_table[0]}"."{schema_table[1]}" t'),
                default=str,
            )  # noqa: S608
        )
    assert names
    return "\n".join(chunks)


def test_a_visitor_number_is_never_stored_returned_audited_evented_or_logged(
    vw: VW, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    vw.setup_gate()
    h = vw.household("A-101")
    responses: list[Any] = []
    window = {
        "start": (dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5)).isoformat(),
        "end": (dt.datetime.now(dt.UTC) + dt.timedelta(hours=2)).isoformat(),
    }
    inv = vw.call(
        h.owner,
        "POST",
        vw.s("invitations"),
        json={
            "unit_id": str(h.unit),
            "purpose": "Delivery",
            "visitor_phone": VISITOR_PHONE,
            "windows": [window],
        },
    )
    responses.append(inv)
    req = vw.call(
        vw.guard,
        "POST",
        "/v1/approval-requests",
        json=vw.request_body(h.unit, visitor_phone=VISITOR_PHONE),
    )
    responses.append(req)
    responses.append(vw.decide(h.owner, req.json()))
    responses.append(
        vw.call(
            vw.guard,
            "POST",
            vw.s("invitations/redeem"),
            json={"gate_id": str(vw.gate_id), "qr": inv.json()["qr"]},
        )
    )
    visit_id = req.json()["visit_id"]
    responses.append(vw.observe(visit_id, "entry"))
    responses.append(vw.call(h.owner, "GET", vw.s(f"units/{h.unit}/visits")))
    responses.append(vw.call(vw.guard, "GET", vw.s("visits"), params={"gate_id": str(vw.gate_id)}))
    responses.append(
        vw.call(vw.secretary, "GET", vw.s("visits"), params={"purpose": "PII review of visits"})
    )
    responses.append(vw.call(h.owner, "GET", vw.s("invitations")))
    assert all(r.status_code in (200, 201) for r in responses), [
        r.text for r in responses if r.status_code not in (200, 201)
    ]
    for r in responses:
        assert (
            VISITOR_PHONE not in r.text and NATIONAL not in r.text and "99999 00777" not in r.text
        )
    # the keyed token is stored (so a blocklist by contact token is possible later), the number is not
    stored = _everything(vw)
    assert NATIONAL not in stored and VISITOR_PHONE not in stored
    tokens = vw.rows(
        "SELECT visitor_contact_token FROM visits WHERE visitor_contact_token IS NOT NULL"
    )
    assert tokens and all(len(t[0]) == 64 for t in tokens)
    # the same number gives the same token inside a society (so it can be matched), and differs from a plain hash
    assert len({t[0] for t in tokens}) == 1
    import hashlib

    assert tokens[0][0] != hashlib.sha256(VISITOR_PHONE.encode()).hexdigest()
    logs = "\n".join(
        rec.getMessage() + json.dumps(getattr(rec, "__dict__", {}), default=str)
        for rec in caplog.records
    )
    assert NATIONAL not in logs and VISITOR_PHONE not in logs


def test_guards_never_see_a_resident_number_or_identity(vw: VW) -> None:
    vw.setup_gate()
    h = vw.household("A-101", tenant=True)
    vw.sql("UPDATE iam.persons SET display_name = 'Rekha Pawar' WHERE id = %s", (h.owner.id,))
    secrets_ = [
        h.owner.phone,
        h.tenant.phone,
        h.family.phone,
        h.owner.phone[3:],
        str(h.owner.id),
        str(h.tenant.id),
        "Rekha",
        "Pawar",
    ]  # type: ignore[union-attr]
    req = vw.raise_request(h.unit)
    vw.decide(h.owner, req)
    gate_params = {"gate_id": str(vw.gate_id)}
    guard_views = [
        vw.call(vw.guard, "GET", vw.s(f"units/{h.unit}/destination-hint")),
        vw.call(vw.guard, "GET", vw.s(f"units/{h.unit}/visits"), params=gate_params),
        vw.call(vw.guard, "GET", vw.s("visits"), params=gate_params),
        vw.call(
            vw.guard, "GET", vw.s("approval-requests"), params={**gate_params, "state": "approved"}
        ),
        vw.call(vw.guard, "GET", f"/v1/approval-requests/{req['id']}", params=gate_params),
        vw.call(vw.guard, "GET", f"/v1/visits/{req['visit_id']}", params=gate_params),
        vw.call(vw.guard, "GET", vw.s(f"gates/{vw.gate_id}/recent-destinations")),
        vw.observe(req["visit_id"], "entry"),
    ]
    for r in guard_views:
        assert r.status_code in (200, 201), r.text
        for secret in secrets_:
            assert secret not in r.text, (secret, r.request.url)
    # the guard cannot reach the member register or phone directory through the visits module either
    assert vw.call(
        vw.guard, "GET", vw.s("memberships"), params={"purpose": "looking up a resident number"}
    ).status_code in (200, 403)
    reg = vw.call(
        vw.guard, "GET", vw.s("memberships"), params={"purpose": "looking up a resident number"}
    )
    if reg.status_code == 200:
        for secret in (h.owner.phone, h.owner.phone[3:], "Rekha Pawar"):
            assert secret not in reg.text


def test_errors_and_audit_never_echo_submitted_visitor_data(vw: VW) -> None:
    vw.setup_gate()
    h = vw.household("A-101")
    bad = vw.request_body(
        h.unit, visitor_phone="not-a-number-+919999900777", visitor_alias="Mr Visitor"
    )
    r = vw.call(vw.guard, "POST", "/v1/approval-requests", json=bad)
    assert r.status_code == 400 and "9999900777" not in r.text and "not-a-number" not in r.text
    ok = vw.raise_request(h.unit, visitor_phone=VISITOR_PHONE, vehicle_plate="MH 12 AB 1234")
    audit_blob = json.dumps(
        [list(row) for row in vw.rows("SELECT diff_masked, reason FROM audit_log")], default=str
    )
    outbox_blob = json.dumps(
        [list(row) for row in vw.rows("SELECT payload FROM outbox")], default=str
    )
    for blob in (audit_blob, outbox_blob):
        assert NATIONAL not in blob and "MH 12 AB 1234" not in blob and "MH12AB1234" not in blob
    assert ok["status"] == "pending" and uuid.UUID(ok["id"])
