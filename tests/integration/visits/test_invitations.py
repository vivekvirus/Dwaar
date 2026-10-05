"""Invitations (GATE-01, GATE-08): signed QR without personal data, explicit windows, max uses, rate-limited codes,
versioned revocation, single-use under concurrency.

REQ: GATE-01, GATE-08, GATE-13, INV-07.
"""

from __future__ import annotations

import datetime as dt
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient

from dwaar_api.modules.visits import tokens
from dwaar_common.signing import b64url_decode, generate_private_key, public_key_to_b64, sign_bytes
from tests.integration.visits._support import UA, VW

pytestmark = [pytest.mark.req("GATE-01")]

PHONE = "+919999900888"


@pytest.fixture
def gate(vw: VW) -> VW:
    vw.setup_gate()
    return vw


def _iso(delta: dt.timedelta) -> str:
    return (dt.datetime.now(dt.UTC) + delta).isoformat()


def window(
    start: dt.timedelta = -dt.timedelta(minutes=5), end: dt.timedelta = dt.timedelta(hours=3)
) -> dict[str, str]:
    return {"start": _iso(start), "end": _iso(end)}


def create(vw: VW, who: Any, unit: uuid.UUID, **extra: Any) -> Any:
    body: dict[str, Any] = {
        "unit_id": str(unit), "purpose": "Dinner", "visitor_alias": "Aunt Sunita", "people_count": 2,
        "windows": [window()], "max_uses": 1,
    }  # fmt: skip
    body.update(extra)
    return vw.call(who, "POST", vw.s("invitations"), json=body)


def redeem(vw: VW, who: Any = None, **body: Any) -> Any:
    return vw.call(
        who or vw.guard,
        "POST",
        vw.s("invitations/redeem"),
        json={"gate_id": str(vw.gate_id), **body},
    )


def test_create_returns_a_signed_qr_with_no_personal_data_and_a_code_shown_once(gate: VW) -> None:
    h = gate.household("A-101")
    r = create(gate, h.owner, h.unit, vehicle_plate="MH 12 AB 1234")
    assert r.status_code == 201, r.text
    inv = r.json()
    assert (
        inv["state"] == "active"
        and inv["uses"] == 0
        and inv["max_uses"] == 1
        and inv["host_is_me"] is True
    )
    assert len(inv["code"]) == 6 and inv["code"].isdigit()
    # the QR carries opaque ids, an expiry and a nonce - nothing about a person, a number or an address
    body_part, signature = inv["qr"].split(".")
    payload = json.loads(b64url_decode(body_part))
    assert set(payload) == {"v", "typ", "iid", "sid", "n", "nbf", "exp", "kid"}
    assert (
        payload["iid"] == inv["id"]
        and payload["sid"] == str(gate.soc.id)
        and payload["typ"] == "dwaar.pass"
    )
    blob = json.dumps(payload)
    for secret in ("Sunita", "Dinner", "A-101", "MH 12", "AB 1234", str(h.owner.id), PHONE):
        assert secret not in blob and secret not in inv["qr"]
    assert signature.startswith("ed25519:")
    # the DB keeps the HASH of the code, never the code
    stored = gate.rows("SELECT code_hash, token_nonce FROM invitations")[0]
    assert stored[0] and inv["code"] not in stored[0] and stored[1] == payload["n"]
    again = gate.call(h.owner, "GET", gate.s(f"invitations/{inv['id']}")).json()
    assert again["has_code"] is True and "code" not in again and again["qr"] == inv["qr"]
    assert (
        len(gate.outbox("InvitationCreated", inv["id"])) == 1
        and len(gate.audit("invitation.create")) == 1
    )
    audit_text = json.dumps([list(row) for row in gate.audit("invitation.create")], default=str)
    assert "MH 12" not in audit_text and inv["code"] not in audit_text


def test_who_may_create_a_pass(gate: VW) -> None:
    h = gate.household("A-101", tenant=True, nr_owner=True)
    other = gate.household("A-102")
    for who in (h.owner, h.tenant, h.family):
        assert create(gate, who, h.unit).status_code == 201
    assert (
        create(gate, h.nr_owner, h.unit).status_code == 403
    )  # PRD 5.2: OWNER_NR has no visitor passes
    assert create(gate, gate.guard, h.unit).status_code == 403
    assert create(gate, gate.secretary, h.unit).status_code == 403
    assert (
        create(gate, other.owner, h.unit).status_code == 404
    )  # a unit that is not theirs looks unknown
    assert create(gate, h.owner, uuid.uuid4()).status_code == 404
    assert create(gate, gate.person(), h.unit).status_code == 404
    assert create(gate, h.owner, h.unit, society_id=str(gate.soc.id)).status_code == 400


def test_windows_are_explicit_and_bounded(gate: VW) -> None:
    h = gate.household("A-101")
    day = dt.timedelta(days=1)
    bad: list[dict[str, Any]] = [
        {"windows": []},
        {"windows": [window(-dt.timedelta(hours=2), -dt.timedelta(hours=1))]},  # already over
        {
            "windows": [window(dt.timedelta(0), dt.timedelta(days=9))]
        },  # one window longer than 7 days
        {
            "windows": [
                window(dt.timedelta(0), dt.timedelta(hours=30)),
                window(dt.timedelta(days=3), dt.timedelta(days=3, hours=2)),
            ]
        },
        {
            "windows": [
                window(dt.timedelta(0), dt.timedelta(hours=3)),
                window(dt.timedelta(hours=2), dt.timedelta(hours=5)),
            ]
        },
        {
            "windows": [{"start": "2026-10-10T10:00:00", "end": "2026-10-10T11:00:00"}]
        },  # no time zone
        {
            "windows": [
                window(dt.timedelta(0), dt.timedelta(hours=1)),
                window(dt.timedelta(days=400), dt.timedelta(days=400, hours=1)),
            ]
        },
        {"windows": [window()], "max_uses": 0},
        {"windows": [window()], "max_uses": 500},
        {"windows": [window()], "vehicle_plate": "<script>"},
        {"windows": [window() for _ in range(70)]},
    ]
    for extra in bad:
        r = create(gate, h.owner, h.unit, **extra)
        assert r.status_code == 400, (extra, r.text)
    assert gate.rows("SELECT count(*) FROM invitations")[0][0] == 0
    # a RECURRING pass is a list of short explicit windows (a milk vendor every morning for a week)
    weekly = [
        window(day * i + dt.timedelta(hours=6), day * i + dt.timedelta(hours=7)) for i in range(7)
    ]
    r = create(gate, h.owner, h.unit, windows=weekly, max_uses=7, kind="vendor", with_code=False)
    assert r.status_code == 201, r.text
    assert (
        len(r.json()["windows"]) == 7 and r.json()["code"] is None and r.json()["has_code"] is False
    )
    assert gate.rows("SELECT count(*) FROM invitation_windows")[0][0] == 7


def test_a_phone_free_pass_and_a_pass_with_a_phone_both_store_no_number(gate: VW) -> None:
    h = gate.household("A-101")
    free = create(gate, h.owner, h.unit)  # GATE-08: alias only, host-issued
    assert free.status_code == 201
    with_phone = create(gate, h.owner, h.unit, visitor_phone=PHONE, visitor_alias="Courier")
    assert with_phone.status_code == 201
    tokens_ = [
        r[0] for r in gate.rows("SELECT visitor_contact_token FROM invitations ORDER BY created_at")
    ]
    assert (
        tokens_[0] is None and tokens_[1] and PHONE[3:] not in tokens_[1] and len(tokens_[1]) == 64
    )
    assert create(gate, h.owner, h.unit, visitor_phone="12345").status_code == 400
    everything = json.dumps(
        [gate.rows(f"SELECT * FROM {t}") for t in ("invitations", "audit_log", "outbox")],
        default=str,  # noqa: S608
    )
    assert PHONE not in everything and PHONE[3:] not in everything
    for resp in (free, with_phone):
        assert PHONE not in resp.text


def test_redeem_a_qr_authorises_a_visit_and_a_single_use_pass_is_then_consumed(gate: VW) -> None:
    h = gate.household("A-101")
    inv = create(gate, h.owner, h.unit).json()
    r = redeem(gate, qr=inv["qr"])
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["entry_observed"] is False  # authorisation is not evidence of entry (INV-07)
    visit = body["visit"]
    assert (
        visit["state"] == "authorised"
        and visit["authorisation_source"] == "invitation"
        and visit["entry_observed"] is False
    )
    assert visit["stops"][0]["authorised"] is True and visit["stops"][0]["unit_label"] == "A-101"
    assert body["invitation"]["uses"] == 1 and body["invitation"]["state"] == "consumed"
    assert (
        "invitation_id" not in visit and "consent_recorded" not in visit
    )  # the guard view is masked
    again = redeem(gate, qr=inv["qr"])
    assert again.status_code == 422 and again.json()["details"]["reason"] == "consumed"
    assert gate.rows("SELECT state, uses FROM invitations") == [("consumed", 1)]
    assert gate.rows("SELECT count(*) FROM visits")[0][0] == 1
    assert len(gate.outbox("VisitAuthorised")) == 1
    # entering is a SEPARATE fact
    entry = gate.observe(visit["id"], "entry")
    assert entry.status_code == 201 and entry.json()["visit"]["state"] == "inside"


def test_max_uses_bounds_a_multi_use_pass(gate: VW) -> None:
    h = gate.household("A-101")
    inv = create(gate, h.owner, h.unit, max_uses=3).json()
    for n in (1, 2, 3):
        r = redeem(gate, qr=inv["qr"])
        assert r.status_code == 201 and r.json()["invitation"]["uses"] == n
    assert redeem(gate, qr=inv["qr"]).json()["details"]["reason"] == "consumed"
    assert gate.rows("SELECT uses, state FROM invitations") == [(3, "consumed")]


def test_a_forged_or_foreign_or_edited_qr_is_refused(gate: VW) -> None:
    h = gate.household("A-101")
    inv = create(gate, h.owner, h.unit).json()
    body, sig = inv["qr"].split(".")
    cfg = gate.idh.app.state.visits_config
    forged_key = generate_private_key()
    payload = json.loads(b64url_decode(body))
    forged_body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    other_signer = tokens.b64url_encode(forged_body) + "." + sign_bytes(forged_key, forged_body)
    other_society = tokens.build_qr(
        cfg, invitation_id=uuid.UUID(inv["id"]), society_id=uuid.uuid4(), nonce=payload["n"],
        not_before=dt.datetime.now(dt.UTC), expires=dt.datetime.now(dt.UTC) + dt.timedelta(hours=1), gate_id=None,
    )  # fmt: skip
    wrong_nonce = tokens.build_qr(
        cfg, invitation_id=uuid.UUID(inv["id"]), society_id=gate.soc.id, nonce="not-the-nonce-1234",
        not_before=dt.datetime.now(dt.UTC), expires=dt.datetime.now(dt.UTC) + dt.timedelta(hours=1), gate_id=None,
    )  # fmt: skip
    unknown_pass = tokens.build_qr(
        cfg, invitation_id=uuid.uuid4(), society_id=gate.soc.id, nonce=payload["n"],
        not_before=dt.datetime.now(dt.UTC), expires=dt.datetime.now(dt.UTC) + dt.timedelta(hours=1), gate_id=None,
    )  # fmt: skip
    tampered = tokens.b64url_encode(body.encode()) + "." + sig
    for bad in (
        other_signer,
        other_society,
        wrong_nonce,
        unknown_pass,
        tampered,
        "garbage",
        "a.b",
        inv["qr"][:-3] + "AAA",
        body,
    ):
        r = redeem(gate, qr=bad if len(bad) >= 20 else bad + "x" * 20)
        assert r.status_code == 422 and r.json()["details"]["reason"] == "invalid_pass", bad
    assert gate.rows("SELECT uses FROM invitations") == [(0,)]
    assert gate.rows("SELECT count(*) FROM visits")[0][0] == 0
    assert public_key_to_b64(
        forged_key.public_key()
    )  # (the forged signer is a real, different Ed25519 key)


def test_a_gate_bound_pass_is_refused_at_another_gate(gate: VW) -> None:
    h = gate.household("A-101")
    back = gate.make_gate("Back gate", "pedestrian")
    inv = create(gate, h.owner, h.unit, gate_id=str(back)).json()
    wrong = redeem(gate, qr=inv["qr"])
    assert wrong.status_code == 422 and wrong.json()["details"]["reason"] == "wrong_gate"
    ok = gate.call(
        gate.guard,
        "POST",
        gate.s("invitations/redeem"),
        json={"gate_id": str(back), "qr": inv["qr"]},
    )
    assert ok.status_code == 201


def test_a_pass_outside_its_window_is_refused(gate: VW) -> None:
    h = gate.household("A-101")
    later = create(
        gate, h.owner, h.unit, windows=[window(dt.timedelta(hours=2), dt.timedelta(hours=4))]
    ).json()
    r = redeem(gate, qr=later["qr"])
    assert r.status_code == 422 and r.json()["details"]["reason"] == "not_yet_valid"
    gap = create(
        gate,
        h.owner,
        h.unit,
        windows=[
            window(-dt.timedelta(hours=3), -dt.timedelta(hours=2)),
            window(dt.timedelta(hours=5), dt.timedelta(hours=6)),
        ],
    )
    assert gap.status_code == 201
    in_gap = redeem(gate, qr=gap.json()["qr"])
    assert in_gap.status_code == 422 and in_gap.json()["details"]["reason"] == "not_yet_valid"
    expired = create(gate, h.owner, h.unit).json()
    gate.sql(
        "UPDATE invitation_windows SET window_end = now() - interval '1 minute', window_start = now() - interval '2 hours'"
    )
    gate.sql(
        "UPDATE invitations SET window_end = now() - interval '1 minute', window_start = now() - interval '2 hours'"
    )
    r = redeem(gate, qr=expired["qr"])
    assert r.status_code == 422 and r.json()["details"]["reason"] == "expired"
    listing = gate.call(h.owner, "GET", gate.s("invitations"), params={"state": "expired"}).json()[
        "items"
    ]
    assert any(i["id"] == expired["id"] and i["state"] == "expired" for i in listing)
    assert len(gate.outbox("InvitationExpired")) >= 1  # persisted by the lazy sweep on read


def test_redeem_with_a_six_digit_code_needs_the_unit_and_is_rate_limited(gate: VW) -> None:
    h = gate.household("A-101")
    other = gate.household("A-102")
    inv = create(gate, h.owner, h.unit).json()
    code = inv["code"]
    assert (
        redeem(gate, code=code).status_code == 400
    )  # a code alone is not enough: the destination unit is needed
    assert (
        redeem(gate, code=code, unit_id=str(other.unit)).json()["details"]["reason"]
        == "invalid_pass"
    )  # wrong unit
    wrong = "000000" if code != "000000" else "111111"
    assert (
        redeem(gate, code=wrong, unit_id=str(h.unit)).json()["details"]["reason"] == "invalid_pass"
    )
    ok = redeem(gate, code=code, unit_id=str(h.unit))
    assert ok.status_code == 201 and ok.json()["visit"]["authorisation_source"] == "invitation"
    assert redeem(gate, code=code, unit_id=str(h.unit)).json()["details"]["reason"] == "consumed"
    # guessing: the per-unit bucket (10 attempts) runs dry, then 429 with Retry-After, before anything is looked up
    codes = [f"{n:06d}" for n in range(10)]
    seen: list[int] = []
    for guess in codes:
        r = redeem(gate, code=guess, unit_id=str(h.unit))
        seen.append(r.status_code)
        if r.status_code == 429:
            assert r.headers["Retry-After"] and r.json()["code"] == "rate_limited"
            break
    assert 429 in seen


def test_a_code_cannot_be_used_after_the_pass_is_revoked_or_for_another_units_pass(
    gate: VW,
) -> None:
    h = gate.household("A-101")
    inv = create(gate, h.owner, h.unit).json()
    rev = gate.call(h.owner, "DELETE", f"/v1/invitations/{inv['id']}")
    assert rev.status_code == 200
    assert (
        redeem(gate, code=inv["code"], unit_id=str(h.unit)).json()["details"]["reason"] == "revoked"
    )
    assert redeem(gate, qr=inv["qr"]).json()["details"]["reason"] == "revoked"


# ------------------------------------------------------------------------------------------ revocation
def test_revocation_is_versioned_monotonic_and_idempotent(gate: VW) -> None:
    h = gate.household("A-101")
    a = create(gate, h.owner, h.unit).json()
    b = create(gate, h.owner, h.unit).json()
    first = gate.call(h.owner, "DELETE", f"/v1/invitations/{a['id']}")
    assert first.status_code == 200
    assert (
        first.json()["state"] == "revoked"
        and first.json()["revoked_version"] == 1
        and first.json()["already_revoked"] is False
    )
    second = gate.call(
        h.family, "DELETE", f"/v1/invitations/{b['id']}"
    )  # any household member with pass rights
    assert second.json()["revoked_version"] == 2
    repeat = gate.call(h.owner, "DELETE", f"/v1/invitations/{a['id']}")
    assert (
        repeat.status_code == 200
        and repeat.json()["revoked_version"] == 1
        and repeat.json()["already_revoked"] is True
    )
    assert gate.rows("SELECT revocation_version FROM gate_policies")[0][0] == 2
    ev = gate.outbox("InvitationRevoked", a["id"])
    assert len(ev) == 1 and ev[0]["payload"]["revoked_version"] == 1
    assert gate.audit("invitation.revoke") and len(gate.audit("invitation.revoke")) == 2
    shown = gate.call(h.owner, "GET", gate.s(f"invitations/{a['id']}")).json()
    assert shown["state"] == "revoked" and shown["revoked_version"] == 1 and "qr" not in shown


def test_revocation_withdraws_authorised_visits_that_have_not_entered(gate: VW) -> None:
    h = gate.household("A-101")
    inv = create(gate, h.owner, h.unit, max_uses=3).json()
    waiting = redeem(gate, qr=inv["qr"]).json()["visit"]
    inside = redeem(gate, qr=inv["qr"]).json()["visit"]
    assert gate.observe(inside["id"], "entry").status_code == 201
    r = gate.call(h.owner, "DELETE", f"/v1/invitations/{inv['id']}")
    assert r.json()["cancelled_visits"] == 1
    states = dict(gate.rows("SELECT id::text, state FROM visits"))
    assert states[waiting["id"]] == "cancelled" and states[inside["id"]] == "inside"
    assert gate.rows("SELECT closed_reason FROM visits WHERE id = %s", (waiting["id"],)) == [
        ("invitation_revoked",)
    ]


def test_only_the_household_revokes_and_other_states_are_not_revocable(gate: VW) -> None:
    h = gate.household("A-101", nr_owner=True)
    other = gate.household("A-102")
    inv = create(gate, h.owner, h.unit).json()
    for who in (other.owner, gate.person()):
        assert gate.call(who, "DELETE", f"/v1/invitations/{inv['id']}").status_code == 404
    for who in (gate.guard, gate.secretary, h.nr_owner):
        assert gate.call(who, "DELETE", f"/v1/invitations/{inv['id']}").status_code == 403
    assert gate.call(h.owner, "DELETE", f"/v1/invitations/{uuid.uuid4()}").status_code == 404
    assert (
        gate.call(
            h.owner, "DELETE", f"/v1/invitations/{inv['id']}", society=uuid.uuid4()
        ).status_code
        == 404
    )
    done = create(gate, h.owner, h.unit).json()
    redeem(gate, qr=done["qr"])  # single use: consumed
    r = gate.call(h.owner, "DELETE", f"/v1/invitations/{done['id']}")
    assert r.status_code == 422 and r.json()["details"]["reason"] == "not_revocable"
    assert gate.rows("SELECT revocation_version FROM gate_policies") == []  # nothing was revoked


def test_the_household_lists_only_its_own_passes(gate: VW) -> None:
    a, b = gate.household("A-101"), gate.household("A-102")
    mine = create(gate, a.owner, a.unit).json()
    theirs = create(gate, b.owner, b.unit).json()
    listing = gate.call(a.family, "GET", gate.s("invitations")).json()["items"]  # type: ignore[arg-type]
    assert [i["id"] for i in listing] == [mine["id"]] and listing[0]["host_is_me"] is False
    assert (
        gate.call(
            a.owner, "GET", gate.s("invitations"), params={"unit_id": str(b.unit)}
        ).status_code
        == 404
    )
    assert gate.call(a.owner, "GET", gate.s(f"invitations/{theirs['id']}")).status_code == 404
    assert gate.call(gate.guard, "GET", gate.s("invitations")).status_code == 403


def test_a_single_use_pass_presented_at_two_desks_at_once_is_consumed_once(gate: VW) -> None:
    h = gate.household("A-101")
    other_guard = gate.person()
    gate.idh.seed_grant(gate.soc.id, other_guard.id, "guard")
    inv = create(gate, h.owner, h.unit).json()
    barrier = threading.Barrier(8)

    def present(who: Any) -> Any:
        client = TestClient(gate.idh.app, raise_server_exceptions=False, headers=UA)
        barrier.wait()
        return client.post(
            gate.s("invitations/redeem"),
            json={"gate_id": str(gate.gate_id), "qr": inv["qr"]},
            headers={**who.headers, "Idempotency-Key": f"desk-{uuid.uuid4()}"},
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = [
            f.result()
            for f in [pool.submit(present, gate.guard if i % 2 else other_guard) for i in range(8)]
        ]
    assert sorted(r.status_code for r in results) == [201] + [422] * 7
    assert gate.rows("SELECT uses, state FROM invitations") == [(1, "consumed")]
    assert gate.rows("SELECT count(*) FROM visits")[0][0] == 1


def test_redeem_is_idempotent_under_one_key_and_needs_a_gate_guard(gate: VW) -> None:
    h = gate.household("A-101")
    inv = create(gate, h.owner, h.unit).json()
    body = {"gate_id": str(gate.gate_id), "qr": inv["qr"]}
    first = gate.call(
        gate.guard, "POST", gate.s("invitations/redeem"), json=body, key="redeem-key-0001"
    )
    replay = gate.call(
        gate.guard, "POST", gate.s("invitations/redeem"), json=body, key="redeem-key-0001"
    )
    assert (
        first.status_code == replay.status_code == 201
        and replay.headers["Idempotent-Replayed"] == "true"
    )
    assert first.json()["visit"]["id"] == replay.json()["visit"]["id"]
    assert gate.rows("SELECT uses FROM invitations") == [(1,)]
    for who in (h.owner, gate.secretary):
        assert gate.call(who, "POST", gate.s("invitations/redeem"), json=body).status_code == 403
    assert (
        gate.call(
            gate.guard,
            "POST",
            gate.s("invitations/redeem"),
            json={"gate_id": str(uuid.uuid4()), "qr": inv["qr"]},
        ).status_code
        == 400
    )
