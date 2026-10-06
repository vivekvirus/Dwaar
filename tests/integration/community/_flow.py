"""Scenario helpers shared by the community tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tests.integration.helpdesk._support import World
from tests.integration.identity._support import Person


@dataclass
class Crew:
    secretary: Person
    committee: Person
    estate: Person
    treasurer: Person
    auditor: Person
    guard: Person
    guard_sup: Person


def crew(w: World) -> Crew:
    return Crew(
        w.staff("secretary"), w.staff("committee"), w.staff("estate_mgr"), w.staff("treasurer"), w.staff("auditor"),
        w.staff("guard"), w.staff("guard_sup"),
    )  # fmt: skip


def draft(w: World, who: Person, **kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "kind": "general", "title": "Water supply interruption on Saturday",
        "body": "The overhead tank will be cleaned on Saturday between 10:00 and 14:00. Please store water.",
    }  # fmt: skip
    body.update(kw)
    r = w.call(who, "POST", "/v1/notices", json=body)
    assert r.status_code == 201, r.text
    out: dict[str, Any] = r.json()["notice"]
    return out


def post(
    w: World,
    who: Person,
    nid: str,
    verb: str,
    body: dict[str, Any] | None = None,
    *,
    expect: int = 200,
) -> Any:
    r = w.call(who, "POST", f"/v1/notices/{nid}/{verb}", json=body or {})
    assert r.status_code == expect, (verb, r.status_code, r.text)
    return r.json()


def published(w: World, c: Crew, **kw: Any) -> dict[str, Any]:
    n = draft(w, c.committee, **kw)
    post(w, c.secretary, n["id"], "approve")
    return post(w, c.secretary, n["id"], "publish")["notice"]  # type: ignore[no-any-return]


def reader_view(w: World, who: Person, nid: str) -> dict[str, Any]:
    r = w.call(who, "GET", f"/v1/notices/{nid}")
    assert r.status_code == 200, r.text
    out: dict[str, Any] = r.json()["notice"]
    return out
