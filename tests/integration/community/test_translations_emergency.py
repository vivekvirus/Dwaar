"""COM-02 translations show the original and legal/safety ones need recorded human review; COM-05 emergency broadcast."""

from __future__ import annotations

import psycopg
import pytest

from dwaar_api.modules.community import notices
from tests.integration.community._flow import crew, draft, post, reader_view

HI = {"language": "hi", "title": "पानी की आपूर्ति बंद रहेगी", "body": "शनिवार को टंकी की सफाई होगी।"}
MR = {"language": "mr", "title": "पाणीपुरवठा बंद राहील", "body": "शनिवारी टाकी स्वच्छ केली जाईल."}


def approved_legal(cw, c, **kw):
    n = draft(
        cw,
        c.committee,
        kind=kw.pop("kind", "legal"),
        title="Notice of special general meeting",
        body="A special general meeting will be held on the stated date for the stated agenda.",
        **kw,
    )
    post(cw, c.secretary, n["id"], "approve")
    return n


# ------------------------------------------------------------------------------------------------ COM-02
@pytest.mark.req("COM-02")
@pytest.mark.parametrize("kind", ["legal", "safety"])
def test_unreviewed_legal_or_safety_translation_blocks_publication(cw, kind) -> None:
    c = crew(cw)
    n = approved_legal(cw, c, kind=kind, target_languages=["hi"])
    nid = n["id"]
    r = cw.call(c.secretary, "POST", f"/v1/notices/{nid}/publish", json={})
    assert r.status_code == 422 and r.json()["code"] == "policy_violation"
    assert r.json()["details"] == {
        "reason": "translation_review_required",
        "unreviewed": [],
        "missing_or_unreviewed_targets": ["hi"],
    }
    # a human translation exists but nobody reviewed it: still blocked
    t = cw.call(c.committee, "POST", f"/v1/notices/{nid}/translations", json=HI)
    assert t.status_code == 201
    tr = t.json()["notice"]["translations"][0]
    assert (
        tr["review_state"] == "unreviewed"
        and tr["human_reviewed"] is False
        and tr["machine_drafted"] is False
    )
    r = cw.call(c.secretary, "POST", f"/v1/notices/{nid}/publish", json={})
    assert r.status_code == 422 and r.json()["details"]["unreviewed"] == ["hi"]
    # the translator may not review their own legal/safety translation
    reviewed = cw.call(
        c.secretary,
        "POST",
        f"/v1/notices/{nid}/translations/hi/review",
        json={"decision": "approve", "note": "checked against the English original"},
    )
    assert (
        reviewed.status_code == 200
        and reviewed.json()["notice"]["translations"][0]["human_reviewed"] is True
    )
    assert cw.rows("SELECT review_state, reviewed_by FROM notice_translations")[0] == (
        "reviewed",
        c.secretary.id,
    )
    assert cw.call(c.secretary, "POST", f"/v1/notices/{nid}/publish", json={}).status_code == 200


@pytest.mark.req("COM-02")
def test_a_machine_draft_needs_a_human_and_is_never_shown_unreviewed_for_legal_notices(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    n = approved_legal(cw, c, target_languages=["hi", "mr"])
    nid = n["id"]
    with cw.svc(None, "system") as (
        conn,
        ctx,
        _a,
    ):  # the ai-gateway integration point: a machine draft, flagged as such
        notices.add_translation(
            conn,
            ctx,
            __import__("uuid").UUID(nid),
            "hi",
            HI["title"],
            HI["body"],
            origin="machine_draft",
            ai_run_ref="run-77",
        )
    row = cw.rows(
        "SELECT origin, drafted_by_ai, translated_by, review_state, ai_run_ref FROM notice_translations"
    )[0]
    assert row == ("machine_draft", True, None, "unreviewed", "run-77")
    cw.call(c.committee, "POST", f"/v1/notices/{nid}/translations", json=MR)
    assert cw.call(c.secretary, "POST", f"/v1/notices/{nid}/publish", json={}).status_code == 422
    # rejecting is a recorded decision; a rejected translation is not "reviewed", so it still blocks a legal notice
    cw.call(
        c.secretary,
        "POST",
        f"/v1/notices/{nid}/translations/mr/review",
        json={"decision": "reject", "note": "wrong date format in the text"},
    )
    cw.call(
        c.secretary,
        "POST",
        f"/v1/notices/{nid}/translations/hi/review",
        json={"decision": "approve"},
    )
    blocked = cw.call(c.secretary, "POST", f"/v1/notices/{nid}/publish", json={})
    assert blocked.status_code == 422 and blocked.json()["details"][
        "missing_or_unreviewed_targets"
    ] == ["mr"]
    fixed = cw.call(
        c.committee,
        "POST",
        f"/v1/notices/{nid}/translations",
        json={**MR, "body": "शनिवारी सभा होईल."},
    )
    assert (
        fixed.status_code == 201
    )  # a rejected translation can be replaced; it restarts as unreviewed
    cw.call(
        c.estate, "POST", f"/v1/notices/{nid}/translations/mr/review", json={"decision": "approve"}
    )  # estate manager: no matrix manage right
    cw.call(
        c.secretary,
        "POST",
        f"/v1/notices/{nid}/translations/mr/review",
        json={"decision": "approve"},
    )
    assert cw.call(c.secretary, "POST", f"/v1/notices/{nid}/publish", json={}).status_code == 200
    seen = reader_view(cw, owner, nid)
    assert seen["original"]["language"] == "en" and seen["original"]["title"].startswith(
        "Notice of special"
    )  # the original is ALWAYS there
    assert {t["language"]: t["human_reviewed"] for t in seen["translations"]} == {
        "hi": True,
        "mr": True,
    }
    hi = next(t for t in seen["translations"] if t["language"] == "hi")
    assert hi["machine_drafted"] is True and hi["body"] == HI["body"]


@pytest.mark.req("COM-02")
def test_a_routine_notice_shows_unreviewed_translations_but_labels_them(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    n = draft(cw, c.committee)
    nid = n["id"]
    cw.call(c.committee, "POST", f"/v1/notices/{nid}/translations", json=HI)
    post(cw, c.secretary, nid, "approve")
    post(cw, c.secretary, nid, "publish")  # routine notices do not need review to publish
    seen = reader_view(cw, owner, nid)
    assert seen["original"]["language"] == "en" and len(seen["translations"]) == 1
    t = seen["translations"][0]
    assert (
        t["human_reviewed"] is False
        and t["review_state"] == "unreviewed"
        and t["body"] == HI["body"]
    )


@pytest.mark.req("COM-02")
def test_legal_translations_are_hidden_from_readers_until_reviewed_and_a_reviewed_text_is_immutable(
    cw,
) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    n = approved_legal(cw, c)  # no declared target language: publishing is allowed
    nid = n["id"]
    post(cw, c.secretary, nid, "publish")
    # a translation added AFTER publication attaches to the latest revision (the published one)
    cw.call(c.committee, "POST", f"/v1/notices/{nid}/translations", json=HI)
    assert (
        reader_view(cw, owner, nid)["translations"] == []
    )  # unreviewed legal translation: not shown
    cw.call(
        c.secretary,
        "POST",
        f"/v1/notices/{nid}/translations/hi/review",
        json={"decision": "approve"},
    )
    assert [t["language"] for t in reader_view(cw, owner, nid)["translations"]] == ["hi"]
    again = cw.call(
        c.committee, "POST", f"/v1/notices/{nid}/translations", json={**HI, "body": "बदला हुआ पाठ"}
    )
    assert again.status_code == 409 and again.json()["details"]["reason"] == "translation_reviewed"
    with (
        cw.idh.db.app_conn(cw.soc.id, c.secretary.id, "secretary") as conn,
        pytest.raises(psycopg.errors.DatabaseError),
    ):
        conn.execute(
            "UPDATE notice_translations SET body = 'tampered' WHERE review_state = 'reviewed'"
        )  # type: ignore[call-overload]
    # the review itself is final too
    assert (
        cw.call(
            c.secretary,
            "POST",
            f"/v1/notices/{nid}/translations/hi/review",
            json={"decision": "reject"},
        ).status_code
        == 409
    )


@pytest.mark.req("COM-02")
def test_translation_input_rules(cw) -> None:
    c = crew(cw)
    n = draft(cw, c.committee)
    nid = n["id"]
    same = cw.call(
        c.committee,
        "POST",
        f"/v1/notices/{nid}/translations",
        json={"language": "en", "title": "Same language", "body": "Original language again"},
    )
    assert same.status_code == 400
    assert (
        cw.call(
            c.committee,
            "POST",
            f"/v1/notices/{nid}/translations",
            json={**HI, "origin": "machine_draft"},
        ).status_code
        == 400
    )  # the HTTP route is human only
    assert (
        cw.call(
            c.committee, "POST", f"/v1/notices/{nid}/translations", json={**HI, "language": "xx"}
        ).status_code
        == 400
    )
    assert (
        cw.call(
            c.secretary,
            "POST",
            f"/v1/notices/{nid}/translations/zz/review",
            json={"decision": "approve"},
        ).status_code
        == 404
    )
    assert (
        cw.call(
            c.secretary,
            "POST",
            f"/v1/notices/{nid}/translations/kn/review",
            json={"decision": "approve"},
        ).status_code
        == 404
    )
    owner = cw.resident(cw.unit("A-101"), "owner")
    assert cw.call(owner, "POST", f"/v1/notices/{nid}/translations", json=HI).status_code == 403


@pytest.mark.req("COM-02")
def test_a_legal_human_translation_needs_another_reviewer_than_its_translator(cw) -> None:
    c = crew(cw)
    n = approved_legal(cw, c)
    nid = n["id"]
    cw.call(
        c.secretary, "POST", f"/v1/notices/{nid}/translations", json=HI
    )  # the secretary translates it herself
    r = cw.call(
        c.secretary,
        "POST",
        f"/v1/notices/{nid}/translations/hi/review",
        json={"decision": "approve"},
    )
    assert r.status_code == 422 and r.json()["details"]["reason"] == "reviewer_must_differ"


# ------------------------------------------------------------------------------------------------ COM-05
@pytest.mark.req("COM-05")
@pytest.mark.parametrize("role", ["secretary", "estate_mgr", "guard_sup"])
def test_privileged_roles_can_issue_an_emergency_broadcast(cw, role) -> None:
    who = cw.staff(role)
    owner = cw.resident(cw.unit("A-101"), "owner")
    r = cw.call(
        who,
        "POST",
        "/v1/emergency-broadcasts",
        json={
            "title": "Fire in tower B",
            "message": "Please leave tower B by the stairs now and assemble at the main gate.",
            "hazard": "fire",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    n = body["notice"]
    assert body["channel"] == "emergency" and body["carries_ads"] is False
    assert (
        n["kind"] == "emergency"
        and n["state"] == "published"
        and n["channel"] == "emergency"
        and n["significant"] is True
    )
    ev = cw.outbox("EmergencyBroadcastIssued", n["id"])
    assert (
        len(ev) == 1
        and ev[0]["payload"]["channel"] == "emergency"
        and ev[0]["payload"]["carries_ads"] is False
        and ev[0]["payload"]["hazard"] == "fire"
    )
    assert "assemble" not in str(
        ev[0]["payload"]
    )  # the text travels in the notice, not in the event
    audit = cw.audit("notice.emergency_broadcast")[0]
    assert audit[2] == role and audit[6] == who.id  # who issued it, recorded as the authority
    seen = reader_view(cw, owner, n["id"])
    assert seen["channel"] == "emergency" and seen["original"]["body"].startswith("Please leave")
    assert (
        cw.call(owner, "GET", "/v1/notices", params={"kind": "emergency"}).json()["items"][0]["id"]
        == n["id"]
    )


@pytest.mark.req("COM-05")
@pytest.mark.parametrize("role", ["committee", "treasurer", "auditor", "guard"])
def test_other_staff_and_residents_cannot_broadcast(cw, role) -> None:
    who = cw.staff(role)
    for person in (who, cw.resident(cw.unit("A-102"), "tenant")):
        r = cw.call(
            person,
            "POST",
            "/v1/emergency-broadcasts",
            json={"message": "Anything at all about an emergency"},
        )
        assert r.status_code == 403
    assert cw.rows("SELECT count(*) FROM notices")[0][0] == 0


@pytest.mark.req("COM-05")
def test_emergency_broadcasts_are_rate_limited_per_person_and_per_society(cw) -> None:
    sec = cw.staff("secretary")
    mgr = cw.staff("estate_mgr")
    sup = cw.staff("guard_sup")
    body = {"message": "Test of the emergency channel: please stay calm"}
    codes = [
        cw.call(sec, "POST", "/v1/emergency-broadcasts", json=body).status_code for _ in range(4)
    ]
    assert codes == [201, 201, 201, 429]  # 3 per hour per person
    limited = cw.call(sec, "POST", "/v1/emergency-broadcasts", json=body)
    assert (
        limited.status_code == 429
        and limited.json()["code"] == "rate_limited"
        and int(limited.headers["Retry-After"]) >= 1
    )
    assert (
        cw.call(mgr, "POST", "/v1/emergency-broadcasts", json=body).status_code == 201
    )  # another person: own allowance
    assert cw.call(mgr, "POST", "/v1/emergency-broadcasts", json=body).status_code == 201
    assert cw.call(mgr, "POST", "/v1/emergency-broadcasts", json=body).status_code == 201
    third = cw.call(
        sup, "POST", "/v1/emergency-broadcasts", json=body
    )  # 6 per society per hour in total are used up
    assert third.status_code == 429
    assert cw.rows("SELECT count(*) FROM notices WHERE kind = 'emergency'")[0][0] == 6


@pytest.mark.req("COM-05")
def test_a_replayed_emergency_request_does_not_spend_the_allowance_twice(cw) -> None:
    sec = cw.staff("secretary")
    body = {"message": "Replay safe emergency test message"}
    first = cw.call(sec, "POST", "/v1/emergency-broadcasts", json=body, key="emergency-key-1")
    for _ in range(5):
        again = cw.call(sec, "POST", "/v1/emergency-broadcasts", json=body, key="emergency-key-1")
        assert (
            again.status_code == 201
            and again.json()["notice"]["id"] == first.json()["notice"]["id"]
        )
    assert cw.rows("SELECT count(*) FROM notices")[0][0] == 1
    assert (
        cw.call(sec, "POST", "/v1/emergency-broadcasts", json=body).status_code == 201
    )  # tokens left


@pytest.mark.req("COM-05", "INV-05")
def test_the_emergency_channel_never_carries_ads_or_links_or_ai_text(cw) -> None:
    sec = cw.staff("secretary")
    for msg in (
        "Visit https://offers.example.com for a discount now",
        "Call www.shop.example now",
        "Open example.com/sale today",
    ):
        r = cw.call(sec, "POST", "/v1/emergency-broadcasts", json={"message": msg})
        assert r.status_code == 422 and r.json()["details"]["reason"] == "no_links_in_emergency", (
            msg
        )
    for extra in (
        {"url": "https://x.example"},
        {"sponsor": "Acme"},
        {"attachments": ["a"]},
        {"drafted_by_ai": True},
        {"image": "x"},
        {"society_id": "x"},
        {"kind": "general"},
    ):
        assert (
            cw.call(
                sec,
                "POST",
                "/v1/emergency-broadcasts",
                json={"message": "Plain emergency message text", **extra},
            ).status_code
            == 400
        ), extra
    assert cw.rows("SELECT count(*) FROM notices")[0][0] == 0
    # defence in depth: the database refuses links and AI drafts on an emergency notice too
    ok = cw.call(
        sec, "POST", "/v1/emergency-broadcasts", json={"message": "Water main burst near gate two"}
    ).json()["notice"]
    with cw.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(cw.soc.id),))
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO notice_versions (society_id, notice_id, revision, language, title, body, content_hash, created_by)"
                " SELECT society_id, id, 2, 'en', 'Sale today', 'Buy now at http://shop.example', repeat('a', 64), created_by FROM notices WHERE id = %s",
                (ok["id"],),
            )
    with cw.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(cw.soc.id),))
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "INSERT INTO notice_versions (society_id, notice_id, revision, language, title, body, content_hash, created_by, drafted_by_ai)"
                " SELECT society_id, id, 2, 'en', 'Plain alert', 'Plain text message', repeat('a', 64), created_by, true FROM notices WHERE id = %s",
                (ok["id"],),
            )
    # an emergency cannot go through the ordinary publish path either
    assert cw.call(sec, "POST", f"/v1/notices/{ok['id']}/publish", json={}).status_code == 409
