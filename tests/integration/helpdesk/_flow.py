"""Small scenario helpers shared by the helpdesk tests."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from tests.integration.helpdesk._support import World
from tests.integration.identity._support import Person


@dataclass
class Crew:
    secretary: Person
    estate: Person
    committee: Person
    treasurer: Person
    auditor: Person
    guard: Person


def crew(w: World) -> Crew:
    return Crew(
        w.staff("secretary"), w.staff("estate_mgr"), w.staff("committee"), w.staff("treasurer"),
        w.staff("auditor"), w.staff("guard"),
    )  # fmt: skip


def raise_ticket(w: World, who: Person, **kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "scope": "society", "category": "common_area", "title": "Corridor light flickers",
        "description": "The light near the stairs keeps flickering at night",
    }  # fmt: skip
    body.update(kw)
    r = w.call(who, "POST", "/v1/tickets", json=body)
    assert r.status_code == 201, r.text
    out: dict[str, Any] = r.json()
    return out


def tid(created: dict[str, Any]) -> str:
    return str(created["ticket"]["id"] if "ticket" in created else created["id"])


def act(
    w: World,
    who: Person,
    ticket: str,
    verb: str,
    body: dict[str, Any] | None = None,
    *,
    expect: int = 200,
) -> dict[str, Any]:
    r = w.call(who, "POST", f"/v1/tickets/{ticket}/{verb}", json=body or {})
    assert r.status_code == expect, (verb, r.status_code, r.text)
    out: dict[str, Any] = r.json()
    return out


def get(w: World, who: Person, ticket: str) -> dict[str, Any]:
    r = w.call(who, "GET", f"/v1/tickets/{ticket}")
    assert r.status_code == 200, r.text
    out: dict[str, Any] = r.json()
    return out


def household(w: World, label: str) -> tuple[uuid.UUID, Person]:
    unit = w.unit(label)
    return unit, w.resident(unit, "owner")
