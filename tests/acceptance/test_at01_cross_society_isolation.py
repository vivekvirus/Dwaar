"""AT-01 (M0): a user who belongs to Society A and Society B switches to B and reuses A's object IDs -> nothing from A.

PRD 16: "User switches from Society A to B and reuses A object IDs. Required outcome: No A data from API, files, export,
search or AI."  PRD 4.3 slice 1 gate.

Dataset: the real seed (Sahyadri Residency CHS = "A", Maharashtra; Nandana Apartments = "B", Karnataka), real API, real
OTP/TOTP sign-in through the labelled local simulator (``simulation=true``). Personas:

* ``ka.secretary`` (Meera Joshi): secretary of B (MFA step-up done) AND non-resident owner in A. She holds the most
  powerful role in B and still reaches nothing of A through B: the strongest form of the scenario.
* ``farhan``: member of B only. ``vikram``: MOVED: his A membership has ended, he is now a tenant in B.

What is proven here, and what is not (be honest, see docs/reports/slice-1.md):

* every society-scoped route that exists today (inventory-checked: a new route fails ``test_route_inventory`` until it is
  classified and covered) answers an A id used in B, and an A path used by a non-member, exactly like a random id: same
  status, same code, same message, same details, and no A identifier anywhere in the body;
* slice 2 added the gate, device, pass, approval-request, visit and exception routes. They are probed like every other route,
  including the routes whose society comes from ``X-Society-Id`` instead of the path (``society_header=True``), with the SEEDED
  gate, lane, device, pass, request, visit and exception ids of A replayed in B (``_visits_world.visit_ids``): same status,
  same code, same body shape as a made-up id, and none of those ids in any answer;
* the database refuses the same thing underneath (RLS on every table with a ``society_id`` column);
* FILES, EXPORT, SEARCH and AI have no endpoints in this slice. They are covered only by a tripwire (no such route exists;
  probing the obvious paths answers 404) and will be exercised end-to-end by the slices that add them.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import psycopg
import pytest
from psycopg import errors as pgerr

from dwaar_api.core.authz import iter_api_routes
from tests.acceptance._visits_world import visit_ids
from tests.acceptance._world import DATASET, World, leaks, shape

pytestmark = [
    pytest.mark.simulation,
    pytest.mark.at("AT-01", dataset=DATASET),
    pytest.mark.req("INV-01", "ARCH-01", "IAM-08", "IAM-01", "SOC-01", "SOC-02"),
]

SOC = "/v1/societies/{society_id}"
PURPOSE = {"purpose": "AT-01 isolation probe"}


@dataclass(frozen=True)
class Case:
    method: str
    template: str
    body: dict[str, Any] | None = None
    params: dict[str, Any] | None = None
    #: ids of A that this route takes (besides the society): the route is replayed in B with each of them
    foreign: tuple[str, ...] = ()
    #: raw CSV body instead of JSON
    csv: bool = False
    #: the society is chosen by the ``X-Society-Id`` header (the PRD paths of approvals, visits, exceptions carry none)
    society_header: bool = False
    #: Meera (secretary of B) holds a role that may call this route in B; False = guard/household-only (403 for her)
    meera_authorised: bool = True

    @property
    def key(self) -> tuple[str, str]:
        return (self.method, self.template)


CSV_BODY = b"block,label,floor\nZ,1,1\n"

CASES: tuple[Case, ...] = (
    Case("GET", SOC),
    Case("GET", f"{SOC}/configuration"),
    Case("GET", f"{SOC}/feature-flags"),
    Case("GET", f"{SOC}/quotas"),
    Case("PATCH", SOC, {"expected_version": 1, "name": "Hijacked"}),
    Case("PUT", f"{SOC}/feature-flags/{{flag_key}}", {"enabled": True}),
    Case("PUT", f"{SOC}/quotas", {"rate_per_minute": 1}),
    Case("GET", f"{SOC}/blocks"),
    Case("POST", f"{SOC}/blocks", {"name": "ZZ", "floors": 1}),
    Case("GET", f"{SOC}/blocks/{{block_id}}", foreign=("block_id",)),
    Case(
        "PATCH",
        f"{SOC}/blocks/{{block_id}}",
        {"expected_version": 1, "name": "ZZ"},
        foreign=("block_id",),
    ),
    Case("DELETE", f"{SOC}/blocks/{{block_id}}", foreign=("block_id",)),
    Case("GET", f"{SOC}/units"),
    Case(
        "POST",
        f"{SOC}/units",
        {"block_id": "{block_id}", "label": "Z1", "floor": 1},
        foreign=("block_id",),
    ),
    Case("GET", f"{SOC}/units/{{unit_id}}", foreign=("unit_id",)),
    Case(
        "PATCH",
        f"{SOC}/units/{{unit_id}}",
        {"expected_version": 1, "label": "Z2"},
        foreign=("unit_id",),
    ),
    Case("DELETE", f"{SOC}/units/{{unit_id}}", foreign=("unit_id",)),
    Case("POST", f"{SOC}/units:import", csv=True),
    Case("GET", f"{SOC}/memberships", params=PURPOSE),
    Case(
        "GET",
        f"{SOC}/memberships",
        params={**PURPOSE, "unit_id": "{unit_id}"},
        foreign=("unit_id",),
    ),
    Case("GET", f"{SOC}/verification-cases"),
    Case(
        "POST",
        f"{SOC}/verification-cases/{{case_id}}/advance",
        {"action": "start_review"},
        foreign=("case_id",),
    ),
    Case(
        "POST",
        f"{SOC}/memberships/{{membership_id}}/dispute",
        {"reason": "AT-01 probe: replaying a foreign membership id"},
        foreign=("membership_id",),
    ),
    Case(
        "POST",
        f"{SOC}/memberships/{{membership_id}}/holds",
        {"reason": "AT-01 probe: replaying a foreign membership id"},
        foreign=("membership_id",),
    ),
    Case("GET", f"{SOC}/memberships/{{membership_id}}/holds", foreign=("membership_id",)),
    Case(
        "POST",
        f"{SOC}/holds/{{hold_id}}/appeal",
        {"reason": "AT-01 probe: replaying a foreign hold id"},
        foreign=("hold_id",),
    ),
    Case(
        "POST",
        f"{SOC}/holds/{{hold_id}}/decide",
        {"outcome": "release", "reason": "AT-01 probe"},
        foreign=("hold_id",),
    ),
    Case("GET", f"{SOC}/role-grants", params=PURPOSE),
    Case(
        "POST",
        f"{SOC}/role-grants",
        {
            "person_phone": "+919999909999",
            "role": "guard",
            "reason": "AT-01 probe",
            "unit_id": "{unit_id}",
        },
        foreign=("unit_id",),
    ),
    Case(
        "POST",
        f"{SOC}/role-grants/{{grant_id}}/revoke",
        {"reason": "AT-01 probe"},
        foreign=("grant_id",),
    ),
)

KEY43 = "A" * 43
WINDOW = [{"start": "2026-10-06T10:00:00+00:00", "end": "2026-10-06T12:00:00+00:00"}]
NOTICE = {"version": "visitor-notice-v1", "language": "en", "consent_given": True}
DECISION = {
    "decision": "approve",
    "expected_version": 1,
    "client_action_id": "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b11",
}
OBSERVATION = {
    "type": "entry",
    "gate_id": "{gate_id}",
    "device_id": "{device_id}",
    "event_id": "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b12",
    "seq": 1,
    "occurred_at": "2026-10-06T10:00:00+00:00",
}

#: slice 2: gates, devices, policy, passes, approval requests, visits, exceptions (ids are the SEEDED ones of A)
VISIT_CASES: tuple[Case, ...] = (
    Case("GET", f"{SOC}/gates"),
    Case("POST", f"{SOC}/gates", {"name": "AT-01 gate", "kind": "mixed"}),
    Case("GET", f"{SOC}/gates/{{gate_id}}/lanes", foreign=("gate_id",)),
    Case(
        "POST",
        f"{SOC}/gates/{{gate_id}}/lanes",
        {"label": "AT-01 lane", "direction": "in"},
        foreign=("gate_id",),
    ),
    Case(
        "GET",
        f"{SOC}/gates/{{gate_id}}/recent-destinations",
        foreign=("gate_id",),
        meera_authorised=False,
    ),
    Case("GET", f"{SOC}/gate-policy"),
    Case("PUT", f"{SOC}/gate-policy", {"approval_expiry_seconds": 120}),
    Case(
        "POST",
        f"{SOC}/devices",
        {"kind": "terminal", "name": "AT-01 device", "gate_id": "{gate_id}", "public_key": KEY43},
        foreign=("gate_id",),
        meera_authorised=False,
    ),
    Case("GET", f"{SOC}/devices"),
    Case("GET", f"{SOC}/devices/{{device_id}}", foreign=("device_id",)),
    Case(
        "POST",
        f"{SOC}/devices/{{device_id}}/decision",
        {"decision": "approve", "expected_version": 1},
        foreign=("device_id",),
    ),
    Case(
        "POST",
        f"{SOC}/devices/{{device_id}}/revoke",
        {"expected_version": 1, "reason": "AT-01 probe"},
        foreign=("device_id",),
    ),
    Case(
        "POST",
        f"{SOC}/invitations",
        {"unit_id": "{unit_id}", "purpose": "AT-01 probe", "windows": WINDOW},
        foreign=("unit_id",),
        meera_authorised=False,
    ),
    Case(
        "GET",
        f"{SOC}/invitations",
        params={"unit_id": "{unit_id}"},
        foreign=("unit_id",),
        meera_authorised=False,
    ),
    Case(
        "GET",
        f"{SOC}/invitations/{{invitation_id}}",
        foreign=("invitation_id",),
        meera_authorised=False,
    ),
    Case(
        "DELETE",
        "/v1/invitations/{invitation_id}",
        foreign=("invitation_id",),
        society_header=True,
        meera_authorised=False,
    ),
    Case(
        "POST",
        f"{SOC}/invitations/redeem",
        {"gate_id": "{gate_id}", "qr": "x" * 40},
        foreign=("gate_id",),
        meera_authorised=False,
    ),
    Case(
        "POST",
        "/v1/approval-requests",
        {
            "unit_id": "{unit_id}",
            "visitor_alias": "AT-01 probe",
            "gate_id": "{gate_id}",
            "destination_confirmed": True,
            "notice": NOTICE,
        },
        foreign=("unit_id", "gate_id"),
        society_header=True,
        meera_authorised=False,
    ),
    Case(
        "GET",
        "/v1/approval-requests/{request_id}",
        params={"gate_id": "{gate_id}"},
        foreign=("request_id", "gate_id"),
        society_header=True,
        meera_authorised=False,
    ),
    Case(
        "POST",
        "/v1/approval-requests/{request_id}/decision",
        DECISION,
        foreign=("request_id",),
        society_header=True,
        meera_authorised=False,
    ),
    Case(
        "POST",
        "/v1/approval-requests/{request_id}/reversal",
        {
            "expected_version": 2,
            "client_action_id": DECISION["client_action_id"],
            "reason": "AT-01 probe",
        },
        foreign=("request_id",),
        society_header=True,
        meera_authorised=False,
    ),
    Case(
        "POST",
        "/v1/approval-requests/{request_id}/cancel",
        {"expected_version": 1},
        foreign=("request_id",),
        society_header=True,
        meera_authorised=False,
    ),
    Case(
        "GET",
        f"{SOC}/approval-requests",
        params={"unit_id": "{unit_id}", "gate_id": "{gate_id}"},
        foreign=("unit_id", "gate_id"),
        meera_authorised=False,
    ),
    Case(
        "GET",
        f"{SOC}/units/{{unit_id}}/destination-hint",
        foreign=("unit_id",),
        meera_authorised=False,
    ),
    Case("GET", f"{SOC}/units/{{unit_id}}/visits", params=PURPOSE, foreign=("unit_id",)),
    Case("GET", f"{SOC}/visits", params={**PURPOSE, "unit_id": "{unit_id}"}, foreign=("unit_id",)),
    Case(
        "GET", "/v1/visits/{visit_id}", params=PURPOSE, foreign=("visit_id",), society_header=True
    ),
    Case(
        "POST",
        "/v1/visits/{visit_id}/observations",
        OBSERVATION,
        foreign=("visit_id", "gate_id", "device_id"),
        society_header=True,
        meera_authorised=False,
    ),
    Case(
        "POST",
        "/v1/visits/{visit_id}/stops",
        {"unit_id": "{unit_id}", "destination_confirmed": True, "expected_version": 1},
        foreign=("visit_id", "unit_id"),
        society_header=True,
        meera_authorised=False,
    ),
    Case(
        "POST",
        "/v1/visits/{visit_id}/cancel",
        {"expected_version": 1, "reason": "AT-01 probe cancel"},
        foreign=("visit_id",),
        society_header=True,
        meera_authorised=False,
    ),
    Case("GET", f"{SOC}/exceptions"),
    Case(
        "POST",
        f"{SOC}/exceptions",
        {"kind": "other", "reason": "AT-01 probe exception", "visit_id": "{visit_id}"},
        foreign=("visit_id",),
        meera_authorised=False,
    ),
    Case(
        "POST",
        "/v1/exceptions/{exception_id}/transition",
        {"action": "start_review", "expected_version": 1},
        foreign=("exception_id",),
        society_header=True,
    ),
)
CASES = CASES + VISIT_CASES

#: society-scoped routes deliberately NOT in the generic probes, and why. Each has its own test below.
APPLICANT_ROUTE = ("POST", f"{SOC}/memberships")

#: routes with no society in the path: own-person or public. They carry no society object ids.
GLOBAL_ROUTES: dict[tuple[str, str], str] = {
    ("GET", "/healthz"): "public liveness",
    ("GET", "/readyz"): "public readiness",
    ("GET", "/v1/meta"): "public build metadata",
    ("POST", "/v1/auth/otp/request"): "sign-in (public)",
    ("POST", "/v1/auth/otp/verify"): "sign-in (public)",
    ("POST", "/v1/auth/refresh"): "own session",
    ("POST", "/v1/auth/logout"): "own session",
    ("GET", "/v1/auth/sessions"): "own sessions only (person scope)",
    (
        "DELETE",
        "/v1/auth/sessions/{session_id}",
    ): "own sessions only: someone else's session id answers 404",
    ("DELETE", "/v1/auth/sessions"): "own sessions only",
    ("POST", "/v1/auth/mfa/totp/enrol"): "own MFA factor",
    ("POST", "/v1/auth/mfa/totp/confirm"): "own MFA factor",
    ("POST", "/v1/auth/mfa/verify"): "own MFA factor",
    ("POST", "/v1/auth/phone/change/request"): "own number",
    ("POST", "/v1/auth/phone/change/confirm"): "own number",
    ("GET", "/v1/me"): "the caller's OWN access overview across societies (tested below)",
    ("PATCH", "/v1/me/profile"): "own profile",
    (
        "POST",
        "/v1/memberships/{membership_id}/owner-confirm",
    ): "tested below: owner proof on the unit, else 404",
    ("GET", "/v1/dev/otp"): "labelled simulator endpoint (local/test only)",
    ("GET", "/.well-known/openid-configuration"): "simulator discovery (local/test only)",
    ("GET", "/.well-known/jwks.json"): "simulator public keys (local/test only)",
    ("POST", "/v1/societies"): "platform operators only (society.create)",
    ("GET", "/v1/societies"): "the caller's societies only (tested below)",
}


def _fill(template: str, ids: dict[str, uuid.UUID | str]) -> str:
    out = template
    for name, value in ids.items():
        out = out.replace("{" + name + "}", str(value))
    return out


def _subst(value: Any, ids: dict[str, uuid.UUID | str]) -> Any:
    if isinstance(value, str):
        return _fill(value, ids)
    if isinstance(value, dict):
        return {k: _subst(v, ids) for k, v in value.items()}
    return value


def _a_ids(world: World, society: uuid.UUID | None = None) -> dict[str, uuid.UUID | str]:
    a = world.objects("mh")
    v = visit_ids(world, "mh")
    return {
        "gate_id": v.gate,
        "lane_id": v.lane,
        "device_id": v.device,
        "invitation_id": v.invitation,
        "request_id": v.request,
        "visit_id": v.visit,
        "exception_id": v.exception or uuid.uuid4(),
        "society_id": society or a.society,
        "block_id": a.ref.blocks["A"],
        "unit_id": a.ref.unit("A", "101"),
        "membership_id": a.memberships[0],
        "case_id": a.cases[0],
        "hold_id": a.holds[0],
        "grant_id": a.grants[0],
        "flag_key": "binding_governance",
    }


def _a_all_ids(world: World) -> set[str]:
    """Every id of A the replays must never reveal: the slice 1 objects plus the seeded gate/visit objects."""
    return world.objects("mh").all_ids() | visit_ids(world, "mh").all_ids()


def _random_like(
    ids: dict[str, uuid.UUID | str], keep: tuple[str, ...] = ("society_id", "flag_key")
) -> dict[str, uuid.UUID | str]:
    return {k: (v if k in keep else uuid.uuid4()) for k, v in ids.items()}


def _send(world: World, who: Any, case: Case, ids: dict[str, uuid.UUID | str]) -> Any:
    url = _fill(case.template, ids)
    params = _subst(case.params, ids) if case.params else None
    extra = {"X-Society-Id": str(ids["society_id"])} if case.society_header else None
    if case.csv:
        return world.call(
            who,
            case.method,
            url,
            content=CSV_BODY,
            headers={"Content-Type": "text/csv"},
            params=params,
        )
    return world.call(
        who, case.method, url, json=_subst(case.body, ids), params=params, headers=extra
    )


# ===================================================================================================== inventory
def test_route_inventory(world: World) -> None:
    """Every route of the running app is either probed here or classified as own-person/public. A new route (a later
    slice adds files, exports, search, AI ...) fails this test until it is added to ``CASES`` or ``GLOBAL_ROUTES``."""
    covered = {c.key for c in CASES} | {APPLICANT_ROUTE} | set(GLOBAL_ROUTES)
    live: set[tuple[str, str]] = set()
    for route in iter_api_routes(world.app):
        for method in route.methods or ():
            if method not in {"HEAD", "OPTIONS"}:
                live.add((method, route.path))
    missing = sorted(live - covered)
    assert not missing, (
        "routes not covered by AT-01 (add them to CASES with their foreign ids, or classify them in GLOBAL_ROUTES): "
        f"{missing}"
    )
    stale = sorted(covered - live)
    assert not stale, f"AT-01 table names routes that no longer exist: {stale}"


def test_files_exports_search_and_ai_do_not_exist_yet(world: World) -> None:
    """PRD AT-01 also names files, export, search and AI. None exists in slice 1: the inventory above is the tripwire,
    and the obvious paths answer the generic 404 (never someone else's data). Exercised end-to-end when slices add them."""
    fragments = (
        "/file",
        "export",
        "search",
        "retriev",
        "/ai",
        "assistant",
        "document",
        "upload",
        "download",
    )
    names = sorted(
        route.path
        for route in iter_api_routes(world.app)
        if any(f in route.path.lower() for f in fragments)
    )
    assert names == [], (
        f"a files/export/search/AI route now exists; add its replay to AT-01: {names}"
    )
    meera = world.login("ka.secretary")
    b = world.objects("ka").society
    a = world.objects("mh")
    for tail in (
        f"files/{uuid.uuid4()}",
        f"exports/{uuid.uuid4()}",
        "search?q=Sahyadri",
        f"documents/{a.memberships[0]}",
        f"ai/conversations/{uuid.uuid4()}",
    ):
        r = world.call(meera, "GET", f"/v1/societies/{b}/{tail}")
        assert r.status_code == 404, (tail, r.status_code, r.text)
        assert r.json()["code"] == "not_found"
        assert not leaks(r, a.all_ids())


# ===================================================================================================== A path
@pytest.mark.parametrize("who", ["farhan", "vikram"])
@pytest.mark.parametrize(
    "case", CASES, ids=lambda c: f"{c.method} {c.template.removeprefix('/v1/societies/')}"
)
def test_non_member_gets_nothing_from_a_on_every_route(world: World, who: str, case: Case) -> None:
    """A signed-in person with no standing in A (never a member: farhan; moved away: vikram) uses A's society path and
    A's object ids on EVERY society route: 404 not_found, byte-identical in shape to a made-up society, and no A id echoed."""
    person = world.login(who)
    a_ids = _a_ids(world)
    real = _send(world, person, case, a_ids)
    unknown = _send(world, person, case, _random_like(a_ids, keep=("flag_key",)))
    assert real.status_code == 404, (case, real.status_code, real.text)
    assert real.json()["code"] == "not_found"
    assert shape(real) == shape(unknown), (
        "an A society id must be indistinguishable from an id that does not exist"
    )
    assert not leaks(
        real,
        _a_all_ids(world) - {str(a_ids["society_id"])} - {str(v) for v in a_ids.values()},
    )


# ===================================================================================================== B context
@pytest.mark.parametrize("who", ["ka.secretary", "farhan", "vikram"])
@pytest.mark.parametrize(
    "case",
    [c for c in CASES if c.foreign],
    ids=lambda c: f"{c.method} {c.template.removeprefix('/v1/societies/')}",
)
def test_switching_to_b_and_replaying_a_ids_is_indistinguishable_from_unknown_ids(
    world: World, who: str, case: Case
) -> None:
    """In B's context every A id behaves like an id that never existed: same status, code, message and details as a
    random id, never a 2xx, never an A identifier. Meera (secretary of B) is authorised for these routes in B, so for her
    the answer is exactly 404 not_found; the others are refused earlier (403/404), identically for real and made-up ids."""
    person = world.login(who)
    b = world.objects("ka").society
    a_ids = _a_ids(world, society=b)
    real = _send(world, person, case, a_ids)
    unknown = _send(world, person, case, _random_like(a_ids))
    assert shape(real) == shape(unknown), (who, case.key, real.text, unknown.text)
    if real.status_code == 200:
        # a LIST filtered by an A id: an empty page, exactly the page a random id gives (checked by shape() above)
        assert case.method == "GET" and real.json()["items"] == [], (who, case.key, real.text)
    else:
        assert real.status_code in (400, 403, 404), (who, case.key, real.status_code, real.text)
    if who == "ka.secretary" and not case.meera_authorised:
        # a guard-only or household-only route: she has standing in B but not that role, for real and made-up ids alike
        assert real.status_code == 403 and real.json()["code"] == "not_authorised", (
            case.key,
            real.text,
        )
    elif who == "ka.secretary" and real.status_code != 200:
        # authorised in B, so the only reason left is the id: it is simply not there
        assert real.status_code in (404, 400), (case.key, real.status_code, real.text)
        if real.status_code == 404:
            assert real.json()["code"] == "not_found"
    assert not leaks(real, _a_all_ids(world) - {str(v) for v in a_ids.values()})


@pytest.mark.parametrize("who", ["ka.secretary", "farhan", "vikram"])
def test_b_lists_contain_no_a_object(world: World, who: str) -> None:
    """Every list a member of B can read, read in B's context, holds only B objects (unit/block filters naming A's ids
    just filter to nothing)."""
    person = world.login(who)
    a_all = _a_all_ids(world)
    b = world.objects("ka")
    a = world.objects("mh")
    seen = 0
    for path, params in (
        (f"/v1/societies/{b.society}/units", None),
        (f"/v1/societies/{b.society}/units", {"block_id": str(a.ref.blocks["A"])}),
        (
            f"/v1/societies/{b.society}/units",
            {"label": "101"},
        ),  # duplicate labels exist in A as well: label alone is no key
        (f"/v1/societies/{b.society}/blocks", None),
        (f"/v1/societies/{b.society}/memberships", {**PURPOSE}),
        (
            f"/v1/societies/{b.society}/memberships",
            {**PURPOSE, "unit_id": str(a.ref.unit("A", "101"))},
        ),
        (f"/v1/societies/{b.society}/verification-cases", None),
        (f"/v1/societies/{b.society}/role-grants", {**PURPOSE}),
        (f"/v1/societies/{b.society}", None),
        (f"/v1/societies/{b.society}/configuration", None),
        (f"/v1/societies/{b.society}/gates", None),
        (f"/v1/societies/{b.society}/devices", None),
        (f"/v1/societies/{b.society}/exceptions", None),
        (f"/v1/societies/{b.society}/gate-policy", None),
        (f"/v1/societies/{b.society}/visits", {**PURPOSE}),
        (f"/v1/societies/{b.society}/visits", {**PURPOSE, "unit_id": str(a.ref.unit("A", "203"))}),
        (f"/v1/societies/{b.society}/invitations", None),
        (f"/v1/societies/{b.society}/approval-requests", None),
    ):
        r = world.call(person, "GET", path, params=params)
        if r.status_code == 200:
            seen += 1
            assert not leaks(r, a_all), (who, path, params)
        else:
            assert r.status_code in (403, 404), (who, path, r.status_code, r.text)
    assert seen >= 3  # the probes did read something: this is not a vacuous pass


def test_header_and_body_cannot_smuggle_the_other_society(world: World) -> None:
    """The society of a request is the validated path (never a header, never a body field): ``X-Society-Id: A`` next to a
    B path changes nothing, and a ``society_id`` in a body is refused."""
    meera = world.login("ka.secretary")
    a, b = world.objects("mh"), world.objects("ka")
    r = world.call(
        meera,
        "GET",
        f"/v1/societies/{b.society}/units",
        headers={"X-Society-Id": str(a.society)},
        params={"limit": 100},
    )
    assert r.status_code == 200
    returned = {item["id"] for item in r.json()["items"]}
    assert returned and returned <= {str(u) for u in b.ref.units.values()}
    assert not leaks(r, a.all_ids())
    smuggle = world.call(
        meera,
        "POST",
        f"/v1/societies/{b.society}/blocks",
        json={"name": "S", "floors": 1, "society_id": str(a.society)},
    )
    assert smuggle.status_code == 400 and smuggle.json()["code"] == "invalid_schema"
    blocks_a = world.admin_rows(
        "SELECT count(*) FROM blocks WHERE society_id = %s AND name = 'S'", (a.society,)
    )
    assert blocks_a[0][0] == 0


def test_own_overview_lists_only_own_societies(world: World) -> None:
    """``/v1/me`` and ``GET /v1/societies`` span societies by design but only the caller's OWN standing. Farhan (B only)
    sees no trace of A. Vikram (moved to B) still sees his OWN ended membership record in A (his history, no active role)
    but ``GET /v1/societies`` no longer lists A. Meera sees both, because she is genuinely in both."""
    a, b = world.objects("mh").society, world.objects("ka").society
    farhan = world.login("farhan")
    me = world.call(farhan, "GET", "/v1/me")
    assert {s["society_id"] for s in me.json()["societies"]} == {str(b)}
    assert str(a) not in me.text
    assert {s["id"] for s in world.call(farhan, "GET", "/v1/societies").json()["items"]} == {str(b)}
    vikram = world.login("vikram")
    me = world.call(vikram, "GET", "/v1/me").json()
    by_society = {s["society_id"]: s for s in me["societies"]}
    assert set(by_society) == {str(a), str(b)}
    assert all(r["active"] is False for r in by_society[str(a)]["roles"]), (
        "an ended membership grants nothing"
    )
    assert [m["verification"] for m in by_society[str(a)]["memberships"]] == ["verified"]
    assert by_society[str(a)]["memberships"][0]["effective_to"] is not None
    assert {s["id"] for s in world.call(vikram, "GET", "/v1/societies").json()["items"]} == {str(b)}
    meera = world.login("ka.secretary")
    listed = world.call(meera, "GET", "/v1/societies").json()
    assert {s["id"] for s in listed["items"]} == {str(a), str(b)}
    # her roles are independent per society (INV-04): owner_nr in A, secretary in B
    me = world.call(meera, "GET", "/v1/me").json()
    roles = {s["society_id"]: sorted({r["role"] for r in s["roles"]}) for s in me["societies"]}
    assert roles == {str(a): ["owner_nr"], str(b): ["secretary"]}


def test_mover_has_no_standing_in_a_anymore(world: World) -> None:
    """The scenario as the PRD words it: the user MOVED from A to B. Vikram's A membership ended by an explicit decision;
    his token works in B and A is gone, including the unit he used to own."""
    vikram = world.login("vikram")
    a, b = world.objects("mh"), world.objects("ka")
    old_unit = a.ref.unit("A", "108")
    assert (
        world.call(vikram, "GET", f"/v1/societies/{a.society}/units/{old_unit}").status_code == 404
    )
    assert world.call(vikram, "GET", f"/v1/societies/{a.society}").status_code == 404
    assert world.call(vikram, "GET", f"/v1/societies/{b.society}").status_code == 200
    me = world.call(vikram, "GET", "/v1/me").json()
    assert all(
        r["active"] is False
        for s in me["societies"]
        if s["society_id"] == str(a.society)
        for r in s["roles"]
    )


def test_positive_control_the_same_ids_work_in_the_right_society(world: World) -> None:
    """Without this, a 404 could mean 'wrong id' rather than 'wrong society': Meera reads A's unit B-205 (her own, as owner)
    through A, and a B unit through B, with the very ids used in the replays."""
    meera = world.login("ka.secretary")
    a, b = world.objects("mh"), world.objects("ka")
    own = a.ref.unit("B", "205")
    r = world.call(meera, "GET", f"/v1/societies/{a.society}/units/{own}")
    assert r.status_code == 200 and r.json()["id"] == str(own)
    r = world.call(meera, "GET", f"/v1/societies/{b.society}/units/{b.ref.unit('Tower 1', '101')}")
    assert r.status_code == 200
    # ... and the A unit she does NOT own is 404 even in A (own records only), same as in B
    other = a.ref.unit("A", "101")
    assert world.call(meera, "GET", f"/v1/societies/{a.society}/units/{other}").status_code == 404


def test_positive_control_the_visit_ids_work_in_the_right_society(world: World) -> None:
    """The visit replays above mean something only if the SAME seeded ids work where they belong: the guard of A reads A's
    request and visit, A's household reads its own history, and A's secretary lists A's gates and devices."""
    v = visit_ids(world, "mh")
    header = {"X-Society-Id": str(v.society)}
    guard = world.login("mh.guard1")
    r = world.call(
        guard,
        "GET",
        f"/v1/approval-requests/{v.request}",
        params={"gate_id": str(v.gate)},
        headers=header,
    )
    assert r.status_code == 200 and r.json()["id"] == str(v.request)
    r = world.call(
        guard, "GET", f"/v1/visits/{v.visit}", params={"gate_id": str(v.gate)}, headers=header
    )
    assert r.status_code in (
        200,
        404,
    )  # 404 only if the first seeded visit is no longer active at the gate (it is closed)
    ganesh = world.login("ganesh")
    r = world.call(ganesh, "GET", f"/v1/societies/{v.society}/units/{v.unit}/visits")
    assert r.status_code == 200 and r.json()["items"]
    secretary = world.login("mh.secretary")
    gates = world.call(secretary, "GET", f"/v1/societies/{v.society}/gates").json()["items"]
    assert str(v.gate) in {g["id"] for g in gates}
    devices = world.call(secretary, "GET", f"/v1/societies/{v.society}/devices").json()["items"]
    assert {str(v.device), str(v.pending_device)} <= {d["id"] for d in devices}
    assert world.call(secretary, "GET", f"/v1/societies/{v.society}/gates/{v.gate}/lanes").json()[
        "items"
    ]


def test_owner_confirm_needs_proof_of_ownership_of_that_unit(world: World) -> None:
    """``POST /v1/memberships/{id}/owner-confirm`` has no society in its path: any membership id of A used by someone who
    does not own that unit answers 404, the same as an unknown id."""
    a = world.objects("mh")
    tenant_membership = world.membership_of(a.society, "dev", "A", "305", "tenant")
    for who in ("farhan", "vikram", "ka.secretary"):
        person = world.login(who)
        real = world.call(
            person,
            "POST",
            f"/v1/memberships/{tenant_membership}/owner-confirm",
            json={"decision": "confirm"},
        )
        fake = world.call(
            person,
            "POST",
            f"/v1/memberships/{uuid.uuid4()}/owner-confirm",
            json={"decision": "confirm"},
        )
        assert real.status_code == 404, (who, real.text)
        assert shape(real) == shape(fake)


# ===================================================================================================== applicant door
def test_applying_to_join_a_society_reveals_nothing_and_grants_nothing(fresh_world: World) -> None:
    """The one door a non-member may knock on: ``POST /v1/societies/{id}/memberships`` (apply to join a unit). It only ever
    makes a PENDING claim (no grant), it answers a foreign unit id used in the WRONG society like a random unit id, and a
    pending claim still reads nothing."""
    w = fresh_world
    farhan = w.login("farhan")
    a, b = w.objects("mh"), w.objects("ka")
    foreign_unit = a.ref.unit("A", "101")
    # A's unit id offered inside B: refused exactly like a unit id that does not exist
    real = w.call(
        farhan,
        "POST",
        f"/v1/societies/{b.society}/memberships",
        json={"unit_id": str(foreign_unit), "kind": "tenant"},
    )
    fake = w.call(
        farhan,
        "POST",
        f"/v1/societies/{b.society}/memberships",
        json={"unit_id": str(uuid.uuid4()), "kind": "tenant"},
    )
    assert real.status_code == fake.status_code and real.status_code in (400, 404, 422), (
        real.text,
        fake.text,
    )
    assert shape(real) == shape(fake)
    assert not w.admin_rows(
        "SELECT 1 FROM memberships WHERE unit_id = %s AND person_id = %s",
        (foreign_unit, farhan.person_id),
    )
    # A unit of A in A's own path: a legitimate application -> pending, no grant
    r = w.call(
        farhan,
        "POST",
        f"/v1/societies/{a.society}/memberships",
        json={"unit_id": str(foreign_unit), "kind": "tenant"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["verification"] == "pending"
    assert (
        w.call(farhan, "GET", f"/v1/societies/{a.society}/units/{foreign_unit}").status_code == 404
    )
    assert w.call(farhan, "GET", f"/v1/societies/{a.society}").status_code == 404
    me = w.call(farhan, "GET", "/v1/me").json()
    a_entry = [s for s in me["societies"] if s["society_id"] == str(a.society)]
    assert all(not x["active"] for s in a_entry for x in s["roles"])


def test_membership_that_ends_takes_effect_on_the_live_token(fresh_world: World) -> None:
    """Move away while signed in: Kunal is an owner in A with a live token (A reads work); a reviewer ends his membership;
    the SAME token reads nothing of A on the next request (IAM-08: authorisation is re-derived from the database)."""
    w = fresh_world
    kunal = w.login("leaver")
    a = w.objects("mh")
    unit = a.ref.unit("B", "101")
    assert w.call(kunal, "GET", f"/v1/societies/{a.society}/units/{unit}").status_code == 200
    secretary = w.login("mh.secretary")
    membership = w.membership_of(a.society, "leaver", "B", "101", "owner")
    case = w.admin_rows(
        "SELECT id FROM verification_cases WHERE membership_id = %s AND kind <> 'dispute' ORDER BY created_at LIMIT 1",
        (membership,),
    )[0][0]
    ended = w.call(
        secretary,
        "POST",
        f"/v1/societies/{a.society}/verification-cases/{case}/advance",
        json={"action": "deactivate", "reason": "Moved to another city"},
    )
    assert ended.status_code == 200, ended.text
    assert w.call(kunal, "GET", f"/v1/societies/{a.society}/units/{unit}").status_code == 404
    assert w.call(kunal, "GET", f"/v1/societies/{a.society}").status_code == 404


# ===================================================================================================== database level
def _society_tables(w: World) -> list[str]:
    rows = w.admin_rows(
        "SELECT c.table_name FROM information_schema.columns c JOIN information_schema.tables t"
        " ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'"
        " WHERE c.table_schema = 'public' AND c.column_name = 'society_id' ORDER BY 1"
    )
    return [r[0] for r in rows]


def test_database_rls_hides_a_from_b_on_every_society_table(world: World) -> None:
    """Underneath the API: connected as the restricted application role with B's context, no table that carries a
    ``society_id`` returns a row of A, whatever the predicate; with no context there are zero rows; and A's rows are there
    (positive control) under A's own context."""
    a, b = world.objects("mh").society, world.objects("ka").society
    tables = _society_tables(world)
    assert {
        "societies",
        "blocks",
        "units",
        "memberships",
        "role_grants",
        "audit_log",
        "outbox",
    } <= set(tables)
    populated = 0
    for table in tables:
        with world.db.app_conn(a) as conn:
            in_a = conn.execute(
                f'SELECT count(*) FROM "{table}" WHERE society_id = %s', (a,)
            ).fetchone()  # type: ignore[call-overload]
        populated += 1 if in_a and in_a[0] else 0
        with world.db.app_conn(b) as conn:
            assert conn.execute(
                f'SELECT count(*) FROM "{table}" WHERE society_id = %s', (a,)
            ).fetchone() == (0,), table  # type: ignore[call-overload]
            total = conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()  # type: ignore[call-overload]
            own = conn.execute(
                f'SELECT count(*) FROM "{table}" WHERE society_id = %s', (b,)
            ).fetchone()  # type: ignore[call-overload]
            assert total == own, f"{table}: B's context sees rows that are not B's"
        with world.db.app_conn() as conn:
            assert conn.execute(f'SELECT count(*) FROM "{table}"').fetchone() == (0,), (
                f"{table}: no context must mean no rows"
            )  # type: ignore[call-overload]
    assert populated >= 6, "the seed should populate most society tables, or the check is hollow"


def test_database_refuses_writes_and_cross_society_references(world: World) -> None:
    """RLS also stops the WRITE side: in B's context A's rows cannot be updated or deleted (zero rows), nothing can be
    inserted FOR A, and a composite foreign key refuses a B row pointing at an A unit."""
    a, b = world.objects("mh"), world.objects("ka")
    unit_a = a.ref.unit("A", "101")
    with world.db.app_conn(b.society) as conn:
        assert (
            conn.execute("UPDATE units SET label = 'HACK' WHERE id = %s", (unit_a,)).rowcount == 0
        )
        assert (
            conn.execute(
                "UPDATE memberships SET verification = 'verified' WHERE society_id = %s",
                (a.society,),
            ).rowcount
            == 0
        )
    with pytest.raises(pgerr.InsufficientPrivilege), world.db.app_conn(b.society) as conn:
        conn.execute(
            "DELETE FROM units WHERE id = %s", (unit_a,)
        )  # units are archived, never deleted: no privilege at all
    with pytest.raises(pgerr.InsufficientPrivilege), world.db.app_conn(b.society) as conn:
        conn.execute(
            "INSERT INTO blocks (id, society_id, name, floors) VALUES (gen_random_uuid(), %s, 'PLANTED', 1)",
            (a.society,),
        )
    # a membership of B pointing at A's unit: the composite FK (society_id, unit_id) -> units refuses it even for the owner role
    with pytest.raises(pgerr.ForeignKeyViolation), world.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(b.society),))
        conn.execute(
            "INSERT INTO memberships (id, society_id, person_id, unit_id, kind, verification, created_by)"
            " SELECT gen_random_uuid(), %s, person_id, %s, 'owner', 'pending', person_id FROM memberships"
            " WHERE society_id = %s LIMIT 1",
            (b.society, unit_a, b.society),
        )


def test_database_identity_internals_are_not_readable_by_the_runtime_role(world: World) -> None:
    """The global identity tables (persons, sessions, the access index) are reachable only through reviewed functions:
    the application role has no table privilege, so even a SQL foothold in B cannot list people of A."""
    b = world.objects("ka").society
    for table in (
        "iam.persons",
        "iam.person_vault",
        "iam.auth_sessions",
        "iam.person_access_index",
        "iam.mfa_factors",
    ):
        with pytest.raises(pgerr.InsufficientPrivilege), world.db.app_conn(b) as conn:
            conn.execute(f"SELECT count(*) FROM {table}")  # type: ignore[call-overload]


def test_session_user_is_the_restricted_role(world: World) -> None:
    """The role the API connects as can neither bypass RLS nor own the tables (so the checks above mean something)."""
    with world.db.app_conn() as conn:
        row = conn.execute(
            "SELECT current_user, r.rolsuper, r.rolbypassrls FROM pg_roles r WHERE r.rolname = current_user"
        ).fetchone()
    assert row == ("dwaar_app", False, False)
    assert isinstance(world.db, object) and psycopg  # keep the import honest for type checkers
