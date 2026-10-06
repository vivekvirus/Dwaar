"""COM-01 notice lifecycle, versions, immutability, audience, receipts; COM-03 AI-draft approval gate."""

from __future__ import annotations

import psycopg
import pytest

from tests.integration.community._flow import crew, draft, post, published, reader_view
from tests.integration.helpdesk._support import text_of

pytestmark = pytest.mark.req("COM-01")


def test_lifecycle_draft_approved_published_with_audit_and_events(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    n = draft(cw, c.committee)
    assert n["state"] == "draft" and n["latest_state"] == "draft" and n["channel"] == "notices"
    nid = n["id"]
    # a draft exists for staff only: residents and the treasurer get the same 404 as for an unknown id
    for who in (owner, c.treasurer):
        assert cw.call(who, "GET", f"/v1/notices/{nid}").status_code == 404
        assert cw.call(who, "GET", "/v1/notices").json()["items"] == []
    # approval is a separate, recorded step done by the secretary; publishing needs it
    post(cw, c.secretary, nid, "publish", expect=409)
    a = post(cw, c.secretary, nid, "approve")["notice"]
    assert a["state"] == "approved" and a["approved_by"] is not None
    assert (
        cw.call(owner, "GET", f"/v1/notices/{nid}").status_code == 404
    )  # approved is still not public
    p = post(cw, c.secretary, nid, "publish")["notice"]
    assert p["state"] == "published" and p["original"]["title"].startswith("Water supply")
    seen = reader_view(cw, owner, nid)
    assert (
        seen["state"] == "published"
        and seen["original"]["language"] == "en"
        and seen["read"] is False
    )
    assert nid in {i["id"] for i in cw.call(owner, "GET", "/v1/notices").json()["items"]}
    for event in ("NoticeDrafted", "NoticeApproved", "NoticePublished"):
        assert len(cw.outbox(event, nid)) == 1, event
    versions = [
        e["version"]
        for e in cw.outbox("NoticeDrafted", nid)
        + cw.outbox("NoticeApproved", nid)
        + cw.outbox("NoticePublished", nid)
    ]
    assert versions == [1, 2, 3]
    assert cw.audit("notice.approve")[0][2] == "secretary" and cw.audit("notice.publish")
    blob = str(cw.rows("SELECT payload FROM outbox WHERE aggregate_id = %s", (nid,))) + str(
        cw.rows("SELECT diff_masked FROM audit_log WHERE object_id = %s", (nid,))
    )
    assert "overhead tank" not in blob  # notice text is never copied into events or audit rows
    assert cw.outbox("NoticePublished", nid)[0]["payload"]["audience"] == {
        "scope": "society",
        "block_ids": [],
        "unit_ids": [],
        "roles": [],
    }


def test_a_published_revision_is_immutable_and_a_change_is_a_new_revision(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    n = published(cw, c)
    nid = n["id"]
    r = cw.call(
        c.committee, "PATCH", f"/v1/notices/{nid}", json={"body": "Sneaky change after publication"}
    )
    assert r.status_code == 409 and r.json()["details"]["reason"] == "revision_not_draft"
    # the database refuses it too, even for the application role and for the owner
    for sql in (
        "UPDATE notice_versions SET body = 'tampered' WHERE state = 'published'",
        "UPDATE notice_versions SET state = 'draft' WHERE state = 'published'",
        "UPDATE notice_versions SET published_at = now() WHERE state = 'published'",
    ):
        with (
            cw.idh.db.app_conn(cw.soc.id, c.committee.id, "committee") as conn,
            pytest.raises(psycopg.errors.DatabaseError),
        ):
            conn.execute(sql)  # type: ignore[call-overload]
    with (
        cw.idh.db.app_conn(cw.soc.id, c.committee.id, "committee") as conn,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        conn.execute("DELETE FROM notice_versions")  # type: ignore[call-overload]
    with cw.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(cw.soc.id),))
        with pytest.raises(psycopg.Error):
            conn.execute(
                "UPDATE notice_versions SET title = 'tampered title' WHERE state = 'published'"
            )
    # a correction is a NEW revision; the published one is untouched until the new one goes live
    rev = cw.call(
        c.committee,
        "POST",
        f"/v1/notices/{nid}/revisions",
        json={
            "title": "Water supply interruption moved",
            "body": "The cleaning moved to Sunday between 10:00 and 14:00.",
        },
    )
    assert rev.status_code == 201 and rev.json()["notice"]["latest_revision"] == 2
    assert (
        reader_view(cw, owner, nid)["original"]["title"] == "Water supply interruption on Saturday"
    )
    assert (
        cw.call(
            c.committee,
            "POST",
            f"/v1/notices/{nid}/revisions",
            json={"title": "Another one", "body": "A second pending draft"},
        ).status_code
        == 409
    )
    post(cw, c.secretary, nid, "approve")
    post(cw, c.secretary, nid, "publish")
    now = reader_view(cw, owner, nid)
    assert now["revision"] == 2 and now["original"]["title"] == "Water supply interruption moved"
    states = cw.rows(
        "SELECT revision, state FROM notice_versions WHERE notice_id = %s ORDER BY revision", (nid,)
    )
    assert states == [(1, "superseded"), (2, "published")]
    staff = reader_view(cw, c.secretary, nid)
    assert [v["state"] for v in staff["versions"]] == ["superseded", "published"]


def test_a_draft_can_be_edited_only_by_its_author_or_the_secretary(cw) -> None:
    c = crew(cw)
    n = draft(cw, c.committee)
    nid = n["id"]
    assert (
        cw.call(
            c.estate, "PATCH", f"/v1/notices/{nid}", json={"title": "Edited by someone else"}
        ).status_code
        == 404
    )
    ok = cw.call(
        c.committee,
        "PATCH",
        f"/v1/notices/{nid}",
        json={"title": "Water tank cleaning on Saturday", "expected_version": n["version"]},
    )
    assert (
        ok.status_code == 200
        and ok.json()["notice"]["latest"]["title"] == "Water tank cleaning on Saturday"
    )
    assert (
        cw.call(
            c.committee,
            "PATCH",
            f"/v1/notices/{nid}",
            json={"title": "Stale edit here", "expected_version": n["version"]},
        ).status_code
        == 409
    )
    assert (
        cw.call(
            c.secretary,
            "PATCH",
            f"/v1/notices/{nid}",
            json={"body": "Secretary edits the body text now"},
        ).status_code
        == 200
    )
    h = cw.rows("SELECT content_hash FROM notice_versions WHERE notice_id = %s", (nid,))[0][0]
    assert len(h) == 64


def test_every_state_change_is_one_way(cw) -> None:
    c = crew(cw)
    n = published(cw, c)
    nid = n["id"]
    post(cw, c.secretary, nid, "approve", expect=409)  # nothing left to approve
    post(cw, c.secretary, nid, "publish", expect=409)  # already published
    post(cw, c.secretary, nid, "archive", {"reason": "event is over"})
    post(cw, c.secretary, nid, "archive", {"reason": "again"}, expect=409)
    assert (
        cw.call(
            c.committee,
            "POST",
            f"/v1/notices/{nid}/revisions",
            json={"title": "Too late now", "body": "Archived notices are closed"},
        ).status_code
        == 409
    )
    owner = cw.resident(cw.unit("A-101"), "owner")
    assert (
        cw.call(owner, "GET", "/v1/notices").json()["items"] == []
    )  # archived is history, not the default list
    hist = cw.call(owner, "GET", "/v1/notices", params={"state": "archived"}).json()["items"]
    assert [i["id"] for i in hist] == [nid]
    assert cw.call(owner, "GET", "/v1/notices", params={"state": "draft"}).json()["items"] == []


def test_a_notice_can_supersede_another(cw) -> None:
    c = crew(cw)
    old = published(
        cw, c, title="Old parking rules for visitors", body="Visitors park in the basement only."
    )
    new = draft(
        cw,
        c.committee,
        title="New parking rules for visitors",
        body="Visitors park in the stilt area only.",
    )
    post(cw, c.secretary, new["id"], "approve")
    post(cw, c.secretary, new["id"], "publish", {"supersedes_notice_id": old["id"]})
    assert reader_view(cw, c.secretary, old["id"])["state"] == "superseded"
    assert reader_view(cw, c.secretary, old["id"])["superseded_by"] == new["id"]
    post(cw, c.secretary, new["id"], "publish", {"supersedes_notice_id": new["id"]}, expect=409)


def test_recipient_scope_society_block_unit_role(cw) -> None:
    c = crew(cw)
    block_b, units_b = cw.add_block("B", ("B-1",))
    in_a = cw.resident(cw.unit("A-101"), "owner")
    other_a = cw.resident(cw.unit("A-102"), "tenant")
    in_b = cw.resident(units_b["B-1"], "owner")
    block_notice = published(
        cw,
        c,
        title="Block B lift service on Monday",
        audience={"scope": "block", "block_ids": [str(block_b)]},
    )
    unit_notice = published(
        cw,
        c,
        title="Water meter reading for A-101",
        audience={"scope": "unit", "unit_ids": [str(cw.unit("A-101"))]},
    )
    role_notice = published(
        cw,
        c,
        title="Tenants: registration reminder",
        audience={"scope": "role", "roles": ["tenant"]},
    )
    society_notice = published(
        cw, c, title="Society-wide annual notice", audience={"scope": "society"}
    )

    def ids(who):
        return {i["id"] for i in cw.call(who, "GET", "/v1/notices").json()["items"]}

    assert ids(in_a) == {unit_notice["id"], society_notice["id"]}
    assert ids(other_a) == {role_notice["id"], society_notice["id"]}
    assert ids(in_b) == {block_notice["id"], society_notice["id"]}
    assert ids(c.treasurer) == {
        block_notice["id"],
        unit_notice["id"],
        role_notice["id"],
        society_notice["id"],
    }
    for who, hidden in (
        (in_a, block_notice),
        (other_a, unit_notice),
        (in_b, role_notice),
        (in_b, unit_notice),
    ):
        assert cw.call(who, "GET", f"/v1/notices/{hidden['id']}").status_code == 404
        assert (
            cw.call(
                who, "POST", f"/v1/notices/{hidden['id']}/receipts", json={"kind": "read"}
            ).status_code
            == 404
        )
    bad = (
        {"scope": "block", "block_ids": []}, {"scope": "unit", "unit_ids": [str(cw.unit("A-101"))], "roles": ["tenant"]},
        {"scope": "role", "roles": ["wizard"]}, {"scope": "society", "roles": ["tenant"]},
        {"scope": "block", "block_ids": ["00000000-0000-0000-0000-000000000001"]},
    )  # fmt: skip
    for aud in bad:
        r = cw.call(
            c.committee,
            "POST",
            "/v1/notices",
            json={
                "title": "Bad audience here",
                "body": "Should be refused outright",
                "audience": aud,
            },
        )
        assert r.status_code == 400, (aud, r.text)


def test_scheduled_publication_waits_for_its_time_and_rechecks_the_gate(cw) -> None:
    import datetime as dt

    from dwaar_api.modules.community import notices

    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    n = draft(
        cw,
        c.committee,
        title="Holi celebration in the clubhouse",
        body="Join us on the terrace lawn at 5 pm.",
    )
    post(cw, c.secretary, n["id"], "approve")
    when = dt.datetime.now(dt.UTC) + dt.timedelta(hours=3)
    s = post(cw, c.secretary, n["id"], "publish", {"publish_at": when.isoformat()})["notice"]
    assert s["state"] == "scheduled" and s["latest_state"] == "scheduled"
    assert cw.call(owner, "GET", f"/v1/notices/{n['id']}").status_code == 404
    with cw.svc(None, "system") as (conn, ctx, _a):
        assert notices.publish_due(conn, ctx, now=when - dt.timedelta(minutes=1)) == 0
    with cw.svc(None, "system") as (conn, ctx, _a):
        assert notices.publish_due(conn, ctx, now=when + dt.timedelta(minutes=1)) == 1
    assert reader_view(cw, owner, n["id"])["state"] == "published"
    assert cw.outbox("NoticeScheduled", n["id"]) and cw.outbox("NoticePublished", n["id"])
    with cw.svc(None, "system") as (conn, ctx, _a):
        assert notices.publish_due(conn, ctx, now=when + dt.timedelta(hours=1)) == 0  # idempotent
    naive = cw.call(
        c.secretary,
        "POST",
        f"/v1/notices/{n['id']}/publish",
        json={"publish_at": "2030-01-01T10:00:00"},
    )
    assert naive.status_code in (400, 409)


# ------------------------------------------------------------------------------------------------ COM-03
@pytest.mark.req("COM-03")
def test_an_ai_drafted_notice_cannot_be_published_without_human_approval(cw) -> None:
    c = crew(cw)
    n = draft(
        cw,
        c.committee,
        drafted_by_ai=True,
        ai_run_ref="run-0001",
        title="Lift maintenance schedule",
        body="Draft produced by the assistant about the lift.",
    )
    nid = n["id"]
    assert n["drafted_by_ai"] is True and n["gates"]["ai_draft_requires_confirmation"] is True
    post(cw, c.secretary, nid, "publish", expect=409)  # no approval, no publication
    r = cw.call(c.secretary, "POST", f"/v1/notices/{nid}/approve", json={})
    assert r.status_code == 422 and r.json()["details"]["reason"] == "ai_draft_needs_human_review"
    assert (
        cw.call(
            c.committee, "POST", f"/v1/notices/{nid}/approve", json={"confirm_ai_review": True}
        ).status_code
        == 403
    )  # only the secretary approves
    ok = post(cw, c.secretary, nid, "approve", {"confirm_ai_review": True})["notice"]
    assert ok["approved_by"] is not None and ok["drafted_by_ai"] is True
    assert post(cw, c.secretary, nid, "publish")["notice"]["state"] == "published"
    assert cw.rows(
        "SELECT drafted_by_ai, approved_by IS NOT NULL FROM notice_versions WHERE notice_id = %s",
        (nid,),
    ) == [(True, True)]
    assert cw.outbox("NoticeApproved", nid)[0]["payload"]["drafted_by_ai"] is True


@pytest.mark.req("COM-03")
def test_the_database_itself_refuses_an_unapproved_ai_publication(cw) -> None:
    c = crew(cw)
    n = draft(
        cw,
        c.committee,
        drafted_by_ai=True,
        title="AI drafted circular",
        body="Draft produced by the assistant.",
    )
    with cw.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(cw.soc.id),))
        with pytest.raises(psycopg.Error):  # draft -> published skips the approval step
            conn.execute(
                "UPDATE notice_versions SET state = 'published', published_at = now() WHERE notice_id = %s",
                (n["id"],),
            )
    with cw.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(cw.soc.id),))
        with pytest.raises(psycopg.errors.CheckViolation):  # approved without an approver
            conn.execute(
                "UPDATE notice_versions SET state = 'approved' WHERE notice_id = %s", (n["id"],)
            )
    ai_flag = cw.call(
        c.committee,
        "POST",
        "/v1/notices",
        json={"title": "Not AI really", "body": "A human wrote this text", "ai_run_ref": "run-9"},
    )
    assert ai_flag.status_code == 400


# ------------------------------------------------------------------------------------------------ receipts and deliveries
def test_read_and_acknowledgement_receipts_and_delivery_records(cw) -> None:
    from dwaar_api.modules.community import notices

    c = crew(cw)
    a = cw.resident(cw.unit("A-101"), "owner")
    b = cw.resident(cw.unit("A-102"), "tenant")
    n = published(cw, c)
    nid = n["id"]
    r1 = cw.call(a, "POST", f"/v1/notices/{nid}/receipts", json={"kind": "read"})
    r2 = cw.call(a, "POST", f"/v1/notices/{nid}/receipts", json={"kind": "read"})
    assert (
        r1.status_code == r2.status_code == 201
        and r1.json()["recorded"] is True
        and r2.json()["recorded"] is False
    )
    assert r1.json()["at"] == r2.json()["at"]
    assert (
        cw.call(a, "POST", f"/v1/notices/{nid}/receipts", json={"kind": "acknowledged"}).json()[
            "recorded"
        ]
        is True
    )
    cw.call(b, "POST", f"/v1/notices/{nid}/receipts", json={"kind": "read"})
    assert (
        reader_view(cw, a, nid)["acknowledged"] is True
        and reader_view(cw, b, nid)["acknowledged"] is False
    )
    assert (
        cw.call(a, "POST", f"/v1/notices/{nid}/receipts", json={"kind": "seen"}).status_code == 400
    )
    summary = cw.call(c.committee, "GET", f"/v1/notices/{nid}/receipts").json()
    assert (
        summary["read"] == 2 and summary["acknowledged"] == 1 and "acknowledgements" not in summary
    )
    detail = cw.call(
        c.secretary, "GET", f"/v1/notices/{nid}/receipts", params={"detail": "true"}
    ).json()
    assert [x["person_id"] for x in detail["acknowledgements"]] == [str(a.id)]
    assert cw.call(a, "GET", f"/v1/notices/{nid}/receipts").status_code == 403
    assert cw.audit("notice.acknowledged")
    # delivery ATTEMPTS are records written by the notifications module through the service contract
    version = cw.rows("SELECT current_version_id FROM notices WHERE id = %s", (nid,))[0][0]
    with cw.svc(None, "system") as (conn, ctx, _a):
        notices.record_delivery_attempt(
            conn,
            ctx,
            version,
            a.id,
            "sms",
            "failed",
            attempt=1,
            detail="provider timeout",
            simulation=True,
        )
        notices.record_delivery_attempt(
            conn, ctx, version, a.id, "sms", "delivered", attempt=2, simulation=True
        )
        notices.record_delivery_attempt(
            conn, ctx, version, b.id, "app_push", "delivered", simulation=True
        )
    items = cw.call(c.committee, "GET", f"/v1/notices/{nid}/deliveries").json()["items"]
    assert {(i["channel"], i["status"], i["attempt"]) for i in items} == {
        ("sms", "failed", 1),
        ("sms", "delivered", 2),
        ("app_push", "delivered", 1),
    }
    assert {
        s["status"]
        for s in cw.call(c.committee, "GET", f"/v1/notices/{nid}/receipts").json()[
            "delivery_summary"
        ]
    } == {"failed", "delivered"}
    with cw.idh.db.app_conn(cw.soc.id, None, "system") as conn:
        for sql in (
            "UPDATE notice_deliveries SET status = 'delivered'",
            "DELETE FROM notice_deliveries",
            "UPDATE notice_receipts SET kind = 'read'",
            "DELETE FROM notice_receipts",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(sql)  # type: ignore[call-overload]
            conn.rollback()


def test_receipts_only_for_the_current_published_revision(cw) -> None:
    c = crew(cw)
    a = cw.resident(cw.unit("A-101"), "owner")
    n = draft(cw, c.committee)
    assert (
        cw.call(a, "POST", f"/v1/notices/{n['id']}/receipts", json={"kind": "read"}).status_code
        == 404
    )
    post(cw, c.secretary, n["id"], "approve")
    post(cw, c.secretary, n["id"], "publish")
    cw.call(a, "POST", f"/v1/notices/{n['id']}/receipts", json={"kind": "read"})
    cw.call(
        c.committee,
        "POST",
        f"/v1/notices/{n['id']}/revisions",
        json={"title": "Second revision of it", "body": "Corrected text for the notice."},
    )
    post(cw, c.secretary, n["id"], "approve")
    post(cw, c.secretary, n["id"], "publish")
    assert reader_view(cw, a, n["id"])["read"] is False  # a receipt belongs to one revision
    assert cw.rows("SELECT count(*) FROM notice_receipts")[0][0] == 1


def test_idempotent_replay_and_validation(cw) -> None:
    c = crew(cw)
    body = {"title": "Replay safe notice", "body": "Same key, same payload, same notice."}
    one = cw.call(c.committee, "POST", "/v1/notices", json=body, key="notice-key-0001")
    two = cw.call(c.committee, "POST", "/v1/notices", json=body, key="notice-key-0001")
    assert (
        one.json()["notice"]["id"] == two.json()["notice"]["id"]
        and two.headers["Idempotent-Replayed"] == "true"
    )
    assert cw.rows("SELECT count(*) FROM notices")[0][0] == 1
    assert (
        cw.call(
            c.committee,
            "POST",
            "/v1/notices",
            json={**body, "title": "Different payload"},
            key="notice-key-0001",
        ).status_code
        == 409
    )
    for bad in (
        {**body, "title": "x"},
        {**body, "kind": "emergency"},
        {**body, "society_id": "abc"},
        {**body, "language": "fr"},
        {**body, "body": "ab"},
    ):
        assert cw.call(c.committee, "POST", "/v1/notices", json=bad).status_code == 400, bad
    assert (
        text_of(one)
        and cw.call(c.committee, "GET", "/v1/notices", params={"colour": "red"}).status_code == 400
    )
