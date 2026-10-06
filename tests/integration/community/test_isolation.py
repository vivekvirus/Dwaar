"""INV-01 / AT-01 for every community route: another society's id answers EXACTLY like a random id (404 not_found, same body),
nothing of the foreign society leaks, nothing in it changes."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import pytest

from dwaar_api.modules.community import files
from tests.integration.community._flow import crew, draft, post
from tests.integration.community.test_documents import PDF, add_version, make_doc, publish, upload
from tests.integration.helpdesk._support import World

pytestmark = pytest.mark.req("COM-01", "COM-04", "COM-06", "INV-01")


@dataclass
class Case:
    actor: str
    method: str
    path: str
    body: dict[str, Any] | None = None


X = "{x}"
POLL_BODY = {"question": "Should the lawn be redone this year?", "options": ["Yes", "No"]}


def notice_cases(own_notice: str) -> list[Case]:
    n = f"/v1/notices/{X}"
    return [
        Case("sec", "GET", n), Case("res", "GET", n), Case("com", "PATCH", n, {"title": "Isolation probe"}),
        Case("com", "POST", f"{n}/revisions", {"title": "Isolation probe", "body": "Isolation probe body"}),
        Case("sec", "POST", f"{n}/approve", {}), Case("sec", "POST", f"{n}/publish", {}),
        Case("sec", "POST", f"{n}/archive", {"reason": "isolation probe"}),
        Case("com", "POST", f"{n}/translations", {"language": "hi", "title": "शीर्षक यहाँ", "body": "पाठ यहाँ है"}),
        Case("sec", "POST", f"{n}/translations/hi/review", {"decision": "approve"}),
        Case("res", "POST", f"{n}/receipts", {"kind": "read"}), Case("com", "GET", f"{n}/receipts"), Case("com", "GET", f"{n}/deliveries"),
        Case("sec", "POST", f"/v1/notices/{own_notice}/publish", {"supersedes_notice_id": X}),
    ]  # fmt: skip


def document_cases(own_doc: str) -> list[Case]:
    d, v = f"/v1/documents/{X}", f"/v1/documents/{X}/versions/{X}"
    return [
        Case("sec", "GET", d), Case("res", "GET", d), Case("com", "POST", f"{d}/versions", {"effective_from": "2026-04-01"}),
        Case("com", "PUT", f"{v}/content", None), Case("com", "POST", f"{v}/scan", {}), Case("sec", "POST", f"{v}/publish", {}),
        Case("sec", "POST", f"{v}/withdraw", {"reason": "isolation probe"}), Case("res", "POST", f"{v}/download-url", {}),
        Case("res", "POST", f"/v1/documents/{own_doc}/versions/{X}/download-url", {}),
        Case("sec", "POST", f"/v1/documents/{own_doc}/versions/{X}/publish", {}),
    ]  # fmt: skip


def poll_cases() -> list[Case]:
    p = f"/v1/polls/{X}"
    return [
        Case("sec", "GET", p), Case("res", "GET", p), Case("sec", "POST", f"{p}/open", {}), Case("sec", "POST", f"{p}/close", {}),
        Case("res", "POST", f"{p}/responses", {"option_id": X}), Case("res", "GET", f"{p}/results"), Case("com", "GET", f"{p}/results"),
    ]  # fmt: skip


def scope_cases() -> list[Case]:
    """Ids of another society used as AUDIENCE targets or option ids."""
    aud = {"title": "Isolation probe", "body": "Isolation probe body text"}
    return [
        Case("com", "POST", "/v1/notices", {**aud, "audience": {"scope": "block", "block_ids": [X]}}),
        Case("com", "POST", "/v1/notices", {**aud, "audience": {"scope": "unit", "unit_ids": [X]}}),
        Case("sec", "POST", "/v1/emergency-broadcasts", {"message": "Isolation probe", "audience": {"scope": "block", "block_ids": [X]}}),
        Case("sec", "POST", "/v1/emergency-broadcasts", {"message": "Isolation probe", "audience": {"scope": "unit", "unit_ids": [X]}}),
    ]  # fmt: skip


def run(cw: World, who, case: Case, x: str, extra: dict[str, str] | None = None) -> Any:
    path = case.path.replace(X, x)
    for key, value in (extra or {}).items():
        path = path.replace(key, value)

    def sub(v: Any) -> Any:
        if v == X:
            return x
        if isinstance(v, dict):
            return {k: sub(i) for k, i in v.items()}
        if isinstance(v, list):
            return [sub(i) for i in v]
        return v

    if case.method == "PUT":
        return cw.call(who, "PUT", path, content=PDF, headers={"Content-Type": "application/pdf"})
    return cw.call(who, case.method, path, json=None if case.body is None else sub(case.body))


def normal(r: Any) -> tuple[int, Any]:
    body = r.json()
    return r.status_code, {k: v for k, v in body.items() if k != "request_id"} if isinstance(
        body, dict
    ) else body


def test_every_route_answers_a_foreign_id_like_a_random_one(cw) -> None:
    foreign = cw.second_society()
    sec_b, com_b = cw.staff("secretary", soc=foreign), cw.staff("committee", soc=foreign)
    res_b = cw.resident(foreign.units["Z-101"], "owner", soc=foreign)
    block_b = cw.rows("SELECT id FROM blocks WHERE society_id = %s", (foreign.id,))[0][0]
    # foreign objects (created through the API in society B)
    nb = cw.call(
        com_b,
        "POST",
        "/v1/notices",
        society=foreign.id,
        json={"title": "Foreign secret notice", "body": "Foreign private body 55555"},
    ).json()["notice"]["id"]
    db_ = cw.call(
        com_b,
        "POST",
        "/v1/documents",
        society=foreign.id,
        json={"doc_type": "minutes", "title": "Foreign minutes", "authority": "Foreign committee"},
    ).json()["document"]
    vb = cw.call(
        com_b,
        "POST",
        f"/v1/documents/{db_['id']}/versions",
        society=foreign.id,
        json={"effective_from": "2026-04-01"},
    ).json()["version"]["id"]
    cw.call(
        com_b,
        "PUT",
        f"/v1/documents/{db_['id']}/versions/{vb}/content",
        society=foreign.id,
        content=PDF,
        headers={"Content-Type": "application/pdf"},
    )
    pb = cw.call(com_b, "POST", "/v1/polls", society=foreign.id, json=POLL_BODY).json()["poll"]
    opt_b = pb["options"][0]["id"]
    snapshot = lambda: (  # noqa: E731
        cw.rows(
            "SELECT id, version, state FROM notices WHERE society_id = %s ORDER BY id",
            (foreign.id,),
        ),
        cw.rows(
            "SELECT id, state, sha256 FROM document_versions WHERE society_id = %s ORDER BY id",
            (foreign.id,),
        ),
        cw.rows(
            "SELECT id, state, version FROM polls WHERE society_id = %s ORDER BY id", (foreign.id,)
        ),
        cw.rows("SELECT count(*) FROM poll_responses WHERE society_id = %s", (foreign.id,)),
    )
    before = snapshot()

    people = {
        "sec": cw.staff("secretary"),
        "com": cw.staff("committee"),
        "res": cw.resident(cw.unit("A-101"), "owner"),
    }
    c = crew(cw)
    own_notice = draft(cw, c.committee)["id"]
    post(cw, c.secretary, own_notice, "approve")
    own_doc = make_doc(cw, c)["id"]
    own_version = add_version(cw, c.committee, own_doc)["id"]
    upload(cw, c.committee, own_doc, own_version)
    publish(cw, c.secretary, own_doc, own_version)
    own_poll = cw.call(c.committee, "POST", "/v1/polls", json=POLL_BODY).json()["poll"]
    cw.call(c.secretary, "POST", f"/v1/polls/{own_poll['id']}/open", json={})

    probes: list[tuple[Case, str, dict[str, str]]] = []
    for case in notice_cases(own_notice):
        probes.append((case, nb, {}))
    for case in document_cases(own_doc):
        probes.append((case, db_["id"], {}))
    # a foreign VERSION id under our own document: also identical to a random id
    probes.append(
        (
            Case(
                "sec",
                "POST",
                f"/v1/documents/{own_doc}/versions/{X}/withdraw",
                {"reason": "isolation probe"},
            ),
            vb,
            {},
        )
    )
    for case in poll_cases():
        probes.append((case, pb["id"], {}))
    probes.append(
        (Case("res", "POST", f"/v1/polls/{own_poll['id']}/responses", {"option_id": X}), opt_b, {})
    )
    for case in scope_cases():
        probes.append(
            (case, str(block_b if "block" in str(case.body) else foreign.units["Z-102"]), {})
        )
    seen = 0
    for case, foreign_id, extra in probes:
        who = people[case.actor]
        for _ in range(2):
            f = run(cw, who, case, foreign_id, extra)
            rnd = run(cw, who, case, str(uuid.uuid4()), extra)
            assert normal(f) == normal(rnd), (
                case,
                f.status_code,
                f.text,
                rnd.status_code,
                rnd.text,
            )
            assert f.status_code in (400, 403, 404, 405), (case, f.status_code, f.text)
            for leak in (
                nb,
                db_["id"],
                vb,
                pb["id"],
                opt_b,
                "Foreign",
                "55555",
                str(foreign.id),
                str(block_b),
                str(foreign.units["Z-102"]),
            ):
                assert leak not in f.text, (case, leak)
        seen += 1
    assert seen >= 35
    assert snapshot() == before  # nothing in the other society moved
    # and the foreign staff cannot reach OUR objects
    for path in (
        f"/v1/notices/{own_notice}",
        f"/v1/documents/{own_doc}",
        f"/v1/polls/{own_poll['id']}",
        f"/v1/polls/{own_poll['id']}/results",
    ):
        assert cw.call(sec_b, "GET", path, society=foreign.id).status_code == 404, path
    assert (
        cw.call(
            sec_b, "POST", f"/v1/notices/{own_notice}/publish", json={}, society=foreign.id
        ).status_code
        == 404
    )
    assert (
        cw.call(
            res_b,
            "POST",
            f"/v1/documents/{own_doc}/versions/{own_version}/download-url",
            json={},
            society=foreign.id,
        ).status_code
        == 404
    )


def test_a_download_token_cannot_cross_societies(cw) -> None:
    c = crew(cw)
    foreign = cw.second_society()
    com_b = cw.staff("committee", soc=foreign)
    sec_b = cw.staff("secretary", soc=foreign)
    doc = cw.call(
        com_b,
        "POST",
        "/v1/documents",
        society=foreign.id,
        json={
            "doc_type": "circular",
            "title": "Foreign circular",
            "authority": "Foreign committee",
        },
    ).json()["document"]
    v = cw.call(
        com_b,
        "POST",
        f"/v1/documents/{doc['id']}/versions",
        society=foreign.id,
        json={"effective_from": "2026-04-01"},
    ).json()["version"]["id"]
    cw.call(
        com_b,
        "PUT",
        f"/v1/documents/{doc['id']}/versions/{v}/content",
        society=foreign.id,
        content=PDF,
        headers={"Content-Type": "application/pdf"},
    )
    cw.call(
        sec_b,
        "POST",
        f"/v1/documents/{doc['id']}/versions/{v}/publish",
        society=foreign.id,
        json={},
    )
    res_b = cw.resident(foreign.units["Z-101"], "owner", soc=foreign)
    url = cw.call(
        res_b,
        "POST",
        f"/v1/documents/{doc['id']}/versions/{v}/download-url",
        society=foreign.id,
        json={},
    ).json()["url"]
    assert cw.call(None, "GET", url, society=False).status_code == 200  # the rightful holder
    key = cw.app.state.community_config.download_key
    mine = cw.resident(cw.unit("A-101"), "owner")  # society A person: no standing in B
    version_uuid = uuid.UUID(v)
    for claim in (
        files.DownloadClaim(
            foreign.id, version_uuid, mine.id, mine.session_id, 2**31
        ),  # our person, their society
        files.DownloadClaim(
            cw.soc.id, version_uuid, mine.id, mine.session_id, 2**31
        ),  # our society, their version
        files.DownloadClaim(
            foreign.id, version_uuid, c.secretary.id, c.secretary.session_id, 2**31
        ),
    ):
        r = cw.call(None, "GET", f"/v1/downloads/{files.issue_token(key, claim)}", society=False)
        assert (
            r.status_code == 404 and r.json()["code"] == "not_found" and PDF[:20] not in r.content
        )
