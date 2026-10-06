"""COM-06 opinion polls: non-binding, owners-only, result visibility, neutral-wording hook; binding votes do not exist."""

from __future__ import annotations

import datetime as dt
import re

import psycopg
import pytest

from dwaar_api.modules.community import polls, wording
from tests.integration.community._flow import crew
from tests.integration.helpdesk._support import text_of

pytestmark = pytest.mark.req("COM-06")

BODY = {
    "question": "Should the clubhouse stay open until 10 pm on weekdays?",
    "description": "An opinion poll before the next meeting.",
    "options": ["Yes", "No", "No opinion"],
}


def make(cw, c, **kw):
    r = cw.call(c.committee, "POST", "/v1/polls", json={**BODY, **kw})
    assert r.status_code == 201, r.text
    return r.json()["poll"]


def open_it(cw, c, poll, **kw):
    r = cw.call(c.secretary, "POST", f"/v1/polls/{poll['id']}/open", json=kw)
    assert r.status_code == 200, r.text
    return r.json()["poll"]


def answer(cw, who, poll, option, expect=201):
    r = cw.call(who, "POST", f"/v1/polls/{poll['id']}/responses", json={"option_id": option})
    assert r.status_code == expect, (r.status_code, r.text)
    return r


def test_every_view_says_the_poll_is_non_binding(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    p = make(cw, c)
    assert (
        p["non_binding"] is True
        and p["label_key"] == "community.poll.non_binding"
        and p["state"] == "draft"
    )
    assert p["neutrality"]["status"] == "clean" and [o["label"] for o in p["options"]] == [
        "Yes",
        "No",
        "No opinion",
    ]
    o = open_it(cw, c, p)
    for view in (
        o,
        cw.call(owner, "GET", f"/v1/polls/{p['id']}").json()["poll"],
        cw.call(owner, "GET", "/v1/polls").json()["items"][0],
    ):
        assert (
            view["non_binding"] is True
            and view["label_key"] == "community.poll.non_binding"
            and view["state"] == "open"
        )
    assert cw.call(owner, "GET", f"/v1/polls/{p['id']}/results").json()["non_binding"] is True
    assert (
        "neutrality" not in cw.call(owner, "GET", f"/v1/polls/{p['id']}").json()["poll"]
    )  # residents see no wording internals


def test_a_draft_is_invisible_to_residents_and_the_lifecycle_is_one_way(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    p = make(cw, c)
    assert cw.call(owner, "GET", f"/v1/polls/{p['id']}").status_code == 404
    assert cw.call(owner, "GET", "/v1/polls").json()["items"] == []
    assert cw.call(owner, "GET", f"/v1/polls/{p['id']}/results").status_code == 404
    answer(cw, owner, p, p["options"][0]["id"], expect=404)
    open_it(cw, c, p)
    assert cw.call(c.secretary, "POST", f"/v1/polls/{p['id']}/open", json={}).status_code == 409
    cw.call(c.secretary, "POST", f"/v1/polls/{p['id']}/close", json={})
    assert cw.call(c.secretary, "POST", f"/v1/polls/{p['id']}/close", json={}).status_code == 409
    assert [i["state"] for i in cw.call(owner, "GET", "/v1/polls").json()["items"]] == ["closed"]
    assert (
        cw.outbox("PollDrafted", p["id"])
        and cw.outbox("PollOpened", p["id"])
        and cw.outbox("PollClosed", p["id"])
    )


def test_one_answer_per_person_and_nothing_after_close(cw) -> None:
    c = crew(cw)
    a = cw.resident(cw.unit("A-101"), "owner")
    b = cw.resident(cw.unit("A-102"), "tenant")
    p = open_it(cw, c, make(cw, c))
    yes, no = p["options"][0]["id"], p["options"][1]["id"]
    answer(cw, a, p, yes)
    again = answer(cw, a, p, no, expect=409)
    assert again.json()["code"] == "already_decided"
    answer(cw, b, p, no)
    assert cw.rows("SELECT count(*) FROM poll_responses")[0][0] == 2
    mine = cw.call(a, "GET", f"/v1/polls/{p['id']}").json()["poll"]
    assert mine["my_response"] == yes and mine["eligible"] is True
    bogus = cw.call(
        a,
        "POST",
        f"/v1/polls/{p['id']}/responses",
        json={"option_id": "00000000-0000-0000-0000-000000000001"},
    )
    assert bogus.status_code == 400
    cw.call(c.secretary, "POST", f"/v1/polls/{p['id']}/close", json={})
    c2 = cw.resident(cw.unit("A-103"), "owner")
    assert answer(cw, c2, p, yes, expect=409).json()["details"]["reason"] == "poll_closed"
    with (
        cw.idh.db.app_conn(cw.soc.id, a.id, "owner_occ") as conn,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        conn.execute("UPDATE poll_responses SET option_id = option_id")  # type: ignore[call-overload]


def test_owners_only_polls(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    nr_owner = cw.resident(cw.unit("A-102"), "owner", lives=False)
    tenant = cw.resident(cw.unit("A-103"), "tenant")
    family = cw.resident(cw.unit("A-101"), "family")
    p = open_it(cw, c, make(cw, c, eligibility="owners_only"))
    opt = p["options"][0]["id"]
    for who in (tenant, family):
        r = answer(cw, who, p, opt, expect=422)
        assert r.json()["details"]["reason"] == "owners_only"
        assert (
            cw.call(who, "GET", f"/v1/polls/{p['id']}").json()["poll"]["eligible"] is False
        )  # visible, not answerable
    answer(cw, owner, p, opt)
    answer(cw, nr_owner, p, opt)
    # staff are not household voters: an opinion poll is for residents
    answer(cw, c.secretary, p, opt, expect=403)
    assert cw.rows("SELECT count(*) FROM poll_responses")[0][0] == 2


@pytest.mark.parametrize(
    ("visibility", "while_open", "after_close", "staff_open"),
    [
        ("live", True, True, True),
        ("after_close", False, True, True),
        ("managers_only", False, False, True),
    ],
)
def test_result_visibility_rules(cw, visibility, while_open, after_close, staff_open) -> None:
    c = crew(cw)
    a = cw.resident(cw.unit("A-101"), "owner")
    b = cw.resident(cw.unit("A-102"), "tenant")
    p = open_it(cw, c, make(cw, c, result_visibility=visibility))
    yes = p["options"][0]["id"]
    answer(cw, a, p, yes)
    answer(cw, b, p, p["options"][1]["id"])
    res = cw.call(b, "GET", f"/v1/polls/{p['id']}/results").json()
    assert res["visible"] is while_open
    if while_open:
        assert res["total_responses"] == 2 and {o["label"]: o["count"] for o in res["options"]} == {
            "Yes": 1,
            "No": 1,
            "No opinion": 0,
        }
    else:
        assert "options" not in res and res["reason"] == visibility
    staff = cw.call(c.committee, "GET", f"/v1/polls/{p['id']}/results").json()
    assert staff["visible"] is staff_open and staff["total_responses"] == 2
    cw.call(c.secretary, "POST", f"/v1/polls/{p['id']}/close", json={})
    assert cw.call(b, "GET", f"/v1/polls/{p['id']}/results").json()["visible"] is after_close
    # whoever looks: counts only, never who answered what
    for who in (a, b, c.secretary, c.committee):
        blob = text_of(cw.call(who, "GET", f"/v1/polls/{p['id']}/results"))
        assert str(a.id) not in blob and str(b.id) not in blob
    assert res["non_binding"] is True


def test_the_neutral_wording_hook_flags_and_a_person_decides(cw) -> None:
    c = crew(cw)
    p = make(
        cw,
        c,
        question="Don't you agree the useless committee should obviously fix the gate IMMEDIATELY?",
        options=["Yes", "No"],
    )
    assert p["neutrality"]["status"] == "flagged" and {
        "leading_question",
        "loaded_wording",
        "emphatic_style",
    } <= set(p["neutrality"]["flags"])
    refused = cw.call(c.secretary, "POST", f"/v1/polls/{p['id']}/open", json={})
    assert (
        refused.status_code == 422 and refused.json()["details"]["reason"] == "neutrality_flagged"
    )
    assert "leading_question" in refused.json()["details"]["flags"]
    assert (
        cw.call(
            c.secretary, "POST", f"/v1/polls/{p['id']}/open", json={"override_reason": "short"}
        ).status_code
        == 400
    )
    opened = open_it(
        cw,
        c,
        p,
        override_reason="The committee reviewed the wording and keeps it as the members' own phrasing",
    )
    assert opened["neutrality"]["status"] == "overridden"
    assert cw.audit("poll.open")[0][5].startswith("The committee reviewed")
    clean = make(cw, c)
    assert clean["neutrality"] == {"status": "clean", "checkers": ["rule-based-v1"], "flags": []}


def test_a_registered_checker_extends_the_hook(cw) -> None:
    class Ai:
        name = "ai-c12-test-double"

        def check(self, question, description, options):
            return ["model_says_biased"] if "tax" in question.lower() else []

    wording.register_checker(Ai())
    try:
        c = crew(cw)
        p = make(cw, c, question="Should the maintenance tax be raised for next year?")
        assert (
            p["neutrality"]["status"] == "flagged"
            and "model_says_biased" in p["neutrality"]["flags"]
        )
        assert "ai-c12-test-double" in p["neutrality"]["checkers"]
    finally:
        wording._CHECKERS[:] = [x for x in wording._CHECKERS if x.name != "ai-c12-test-double"]


def test_polls_close_by_themselves_at_their_closing_time(cw) -> None:
    c = crew(cw)
    p = make(cw, c)
    when = dt.datetime.now(dt.UTC) + dt.timedelta(days=2)
    open_it(cw, c, p, closes_at=when.isoformat())
    assert (
        cw.call(
            c.secretary,
            "POST",
            f"/v1/polls/{make(cw, c)['id']}/open",
            json={"closes_at": "2020-01-01T00:00:00+00:00"},
        ).status_code
        == 400
    )
    with cw.svc(None, "system") as (conn, ctx, _a):
        assert polls.close_due(conn, ctx, now=when - dt.timedelta(minutes=1)) == 0
        assert polls.close_due(conn, ctx, now=when + dt.timedelta(minutes=1)) == 1
        assert polls.close_due(conn, ctx, now=when + dt.timedelta(minutes=2)) == 0
    assert cw.call(c.secretary, "GET", f"/v1/polls/{p['id']}").json()["poll"]["state"] == "closed"


# ------------------------------------------------------------------------------------------------ no binding votes
@pytest.mark.req("COM-06", "GOV-01")
def test_no_binding_vote_route_exists_and_the_database_cannot_represent_one(cw) -> None:
    from dwaar_api.core.authz import iter_api_routes

    paths = sorted(
        {
            (m, r.path)
            for r in iter_api_routes(cw.app)
            for m in (r.methods or ())
            if m not in {"HEAD", "OPTIONS"}
        }
    )
    forbidden = re.compile(
        r"ballot|binding|resolution|quorum|meeting|proxy|vote|tally|agm", re.IGNORECASE
    )
    assert [p for p in paths if forbidden.search(p[1])] == []
    poll_routes = [p for p in paths if p[1].startswith("/v1/polls")]
    assert poll_routes == sorted([
        ("GET", "/v1/polls"), ("POST", "/v1/polls"), ("GET", "/v1/polls/{poll_id}"), ("POST", "/v1/polls/{poll_id}/open"),
        ("POST", "/v1/polls/{poll_id}/close"), ("POST", "/v1/polls/{poll_id}/responses"), ("GET", "/v1/polls/{poll_id}/results"),
    ])  # fmt: skip
    c = crew(cw)
    p = make(cw, c)
    for body in ({"is_binding": True}, {"binding": True}, {"quorum": 10}, {"type": "binding"}):
        assert cw.call(c.committee, "POST", "/v1/polls", json={**BODY, **body}).status_code == 400
    with cw.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(cw.soc.id),))
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute("UPDATE polls SET is_binding = true WHERE id = %s", (p["id"],))
    with cw.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(cw.soc.id),))
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "UPDATE polls SET label_key = 'community.poll.binding' WHERE id = %s", (p["id"],)
            )
    cols = {
        r[0]
        for r in cw.rows(
            "SELECT column_name FROM information_schema.columns WHERE table_name IN ('polls', 'poll_options', 'poll_responses')"
        )
    }
    assert not {c for c in cols if forbidden.search(c) and c != "is_binding"}
    assert cw.rows(
        "SELECT to_regclass('ballots'), to_regclass('resolutions'), to_regclass('meetings')"
    )[0] == (None, None, None)


def test_permissions_and_validation(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    assert cw.call(owner, "POST", "/v1/polls", json=BODY).status_code == 403
    assert cw.call(c.treasurer, "POST", "/v1/polls", json=BODY).status_code == 403
    assert cw.call(c.guard, "GET", "/v1/polls").status_code == 403
    assert cw.call(c.auditor, "GET", "/v1/polls").status_code == 403
    p = make(cw, c)
    assert (
        cw.call(c.committee, "POST", f"/v1/polls/{p['id']}/open", json={}).status_code == 403
    )  # committee drafts, secretary opens
    assert cw.call(c.estate, "POST", f"/v1/polls/{p['id']}/close", json={}).status_code == 403
    for bad in (
        {**BODY, "options": ["Only one"]},
        {**BODY, "options": ["Same", "same"]},
        {**BODY, "options": ["a"] * 13},
        {**BODY, "question": "Hey"},
        {**BODY, "eligibility": "tenants_only"},
        {**BODY, "result_visibility": "never"},
        {**BODY, "society_id": "x"},
        {**BODY, "options": ["Yes", ""]},
    ):
        assert cw.call(c.committee, "POST", "/v1/polls", json=bad).status_code == 400, bad
    assert (
        cw.call(c.committee, "GET", "/v1/polls", params={"state": "draft"}).json()["items"][0]["id"]
        == p["id"]
    )
    assert cw.call(c.committee, "GET", "/v1/polls", params={"bogus": "1"}).status_code == 400
