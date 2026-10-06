"""Cross-society isolation for EVERY notifications route (INV-01, AT-01): a foreign id used inside another society answers exactly like a random id.

REQ: INV-01, ARCH-01, NOTIF-05 (a notification of another society is not reachable), CALL-01 (a proxy call of another society is not reachable),
NOTIF-07 (metrics and device health never mix societies), D-21.

Society A holds the data (a household, devices, a request with its cascade and notifications, a proxy call, templates, counters). A person of society B
with the RIGHT role for each route (resident, guard, supervisor, secretary) replays A's ids in B's society path, and a person who is not in A at all uses
A's path. Every answer must equal the answer for a made-up id: same status, same code, same message, same details, and no A identifier in the body.

ROUTES (method, path, scope, auth) covered below, all under ``/v1/societies/{society_id}`` and authenticated by a bearer token:
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import pytest

from dwaar_api.core.authz import iter_api_routes
from tests.integration.identity._support import Person
from tests.integration.notifications._support import NW, secs

pytestmark = [pytest.mark.req("INV-01", "ARCH-01", "NOTIF-05", "CALL-01")]

P = "/v1/societies/{s}"
TOKEN = "device-token-0123456789abcdef"


@dataclass(frozen=True)
class Probe:
    method: str
    path: str  # with {s} (society) and {x} (the foreign id)
    role: str  # which B persona calls it: resident | guard | sup | secretary
    body: Any = None
    params: Any = None
    foreign: str | None = (
        None  # the key of the A id replayed as {x}; None = the route has no foreign id (society path only)
    )


def _body_with(x: str | None) -> Any:
    return None


PROBES: tuple[Probe, ...] = (
    Probe("POST", f"{P}/push-tokens", "resident", {"platform": "fcm", "token": TOKEN}),
    Probe("GET", f"{P}/push-tokens", "resident"),
    Probe("DELETE", f"{P}/push-tokens/{{x}}", "resident", foreign="token"),
    Probe("GET", f"{P}/device-diagnostics/guidance", "resident"),
    Probe("POST", f"{P}/device-diagnostics", "resident", {"manufacturer": "Oppo", "notification_permission": "granted", "token_id": "{x}"}, foreign="token"),
    Probe("GET", f"{P}/notification-preferences/me", "resident"),
    Probe("PUT", f"{P}/notification-preferences/me", "resident", {"show_identity_on_lockscreen": False, "whatsapp_opt_in": False, "sms_opt_in": False, "language": "en"}),
    Probe("GET", f"{P}/units/{{x}}/notification-settings", "resident", foreign="unit"),
    Probe("GET", f"{P}/units/{{x}}/notification-settings", "secretary", foreign="unit"),
    Probe("PUT", f"{P}/units/{{x}}/notification-settings", "resident", {"fallback_mode": "intercom"}, foreign="unit"),
    Probe("GET", f"{P}/notifications", "resident"),
    Probe("GET", f"{P}/notifications/{{x}}", "resident", foreign="notification"),
    Probe("POST", f"{P}/notifications/{{x}}/receipt", "resident", {"event": "app_received"}, foreign="notification"),
    Probe("POST", f"{P}/notifications/{{x}}/action", "resident", {"action": "approve", "client_action_id": "{u}"}, foreign="notification"),
    Probe("GET", f"{P}/approval-requests/{{x}}/notification-status", "guard", params={"gate_id": "{g}"}, foreign="request"),
    Probe("GET", f"{P}/approval-requests/{{x}}/notification-status", "secretary", foreign="request"),
    Probe("POST", f"{P}/approval-requests/{{x}}/cascade-attempts", "sup", {"reason": "owner unreachable"}, foreign="request"),
    Probe("POST", f"{P}/approval-requests/{{x}}/proxy-calls", "guard", {"target": "primary", "gate_id": "{g}"}, foreign="request"),
    Probe("GET", f"{P}/proxy-calls/{{x}}", "secretary", foreign="call"),
    Probe("GET", f"{P}/proxy-calls/{{x}}", "guard", params={"gate_id": "{g}"}, foreign="call"),
    Probe("GET", f"{P}/notification-providers", "secretary"),
    Probe("GET", f"{P}/notification-metrics", "secretary"),
    Probe("GET", f"{P}/device-health", "secretary"),
    Probe("GET", f"{P}/notification-budget", "secretary"),
    Probe("PUT", f"{P}/notification-budget", "secretary", {"monthly_notification_cap": 5, "monthly_call_cap": 5, "monthly_sms_cap": 5}),
    Probe("GET", f"{P}/notification-templates", "secretary"),
    Probe("PUT", f"{P}/notification-templates/{{x}}/dlt", "secretary", {"dlt_header": "DWAARX", "dlt_template_id": "1107160000000000001"}, foreign="template"),
    Probe("POST", f"{P}/notification-templates", "secretary", {"template_key": "a.b", "category": "finance", "channel": "push", "language": "en", "body_key": "finance.notice.body"}),
)  # fmt: skip

ROUTES = sorted(
    {(p.method, p.path.replace("{s}", "{society_id}").replace("{x}", "{x}")) for p in PROBES}
)


class World:
    """Society A (data) and society B (the intruder's own society)."""

    def __init__(self, nw: NW) -> None:
        self.nw = nw
        owner, family = nw.household2("A-101")
        self.a_owner = owner
        nw.register_device(owner, "a-phone")
        nw.sim_device("a-phone").force_stopped = True
        nw.sims.ivr.script(f"person:{owner.id}", outcome="answered", dtmf=None)
        self.request = nw.raise_request(nw.unit("A-101"))
        t0 = nw.created_at(self.request["id"])
        for at in (0, 10, 20):
            nw.tick(t0 + secs(at))
        r = nw.call(
            nw.guard_sup,
            "POST",
            nw.s(f"approval-requests/{self.request['id']}/cascade-attempts"),
            json={"reason": "isolation fixture"},
        )
        assert r.status_code == 201, r.text
        nw.call(
            nw.secretary,
            "POST",
            nw.s("notification-templates"),
            json={
                "template_key": "a.only",
                "category": "finance",
                "channel": "push",
                "language": "en",
                "body_key": "finance.notice.body",
            },
        )
        nw.call(
            nw.secretary,
            "PUT",
            nw.s("notification-budget"),
            json={"monthly_notification_cap": 77, "monthly_call_cap": 7, "monthly_sms_cap": 7},
        )
        nw.call(
            owner,
            "PUT",
            nw.s("notification-preferences/me"),
            json={
                "show_identity_on_lockscreen": True,
                "whatsapp_opt_in": True,
                "sms_opt_in": True,
                "language": "hi",
            },
        )
        self.ids = {
            "token": str(nw.rows("SELECT id FROM device_push_tokens")[0][0]),
            "notification": str(
                nw.rows("SELECT id FROM notifications ORDER BY created_at LIMIT 1")[0][0]
            ),
            "request": self.request["id"],
            "unit": str(nw.unit("A-101")),
            "call": str(nw.rows("SELECT id FROM proxy_call_sessions LIMIT 1")[0][0]),
            "template": str(nw.rows("SELECT id FROM notification_templates LIMIT 1")[0][0]),
        }
        # society B and its people
        idh = nw.idh
        self.b = idh.society("Intruder Court", units=("B-1", "B-2"))
        self.people: dict[str, Person] = {}
        for role, n in (("resident", 970), ("guard", 971), ("sup", 972), ("secretary", 973)):
            who = idh.login(n, client=nw.client)
            self.people[role] = who
        idh.seed_membership(
            self.b.id,
            self.people["resident"].id,
            self.b.units["B-1"],
            "owner",
            lives=True,
            verification="verified",
        )
        idh.seed_grant(self.b.id, self.people["guard"].id, "guard")
        idh.seed_grant(self.b.id, self.people["sup"].id, "guard_sup")
        idh.seed_grant(self.b.id, self.people["secretary"].id, "secretary")
        idh.elevate_session(self.people["sup"])
        idh.elevate_session(self.people["secretary"])
        self.outsider = idh.login(980, client=nw.client)  # in no society at all
        self.gate_b = uuid.uuid4()

    def fill(self, value: Any, x: str) -> Any:
        if isinstance(value, dict):
            return {k: self.fill(v, x) for k, v in value.items()}
        if value == "{x}":
            return x
        if value == "{u}":
            return str(uuid.uuid4())
        if value == "{g}":
            return str(self.gate_b)
        return value

    def call(self, probe: Probe, who: Person, society: uuid.UUID, x: str) -> Any:
        path = probe.path.replace("{s}", str(society)).replace("{x}", x)
        return self.nw.call(
            who,
            probe.method,
            path,
            json=self.fill(probe.body, x),
            params=self.fill(probe.params, x),
        )


def shape(response: Any) -> tuple[Any, ...]:
    body = response.json()
    return (
        response.status_code,
        body.get("code"),
        body.get("message"),
        body.get("message_key"),
        body.get("details"),
    )


@pytest.fixture
def world(nw: NW) -> World:
    return World(nw)


@pytest.mark.parametrize(
    "probe",
    [p for p in PROBES if p.foreign],
    ids=lambda p: f"{p.method} {p.path.split('{s}')[1]} as {p.role}",
)
def test_a_foreign_id_in_my_society_answers_exactly_like_a_random_id(
    world: World, probe: Probe
) -> None:
    who = world.people[probe.role]
    foreign = world.ids[probe.foreign or ""]
    got = world.call(probe, who, world.b.id, foreign)
    random = world.call(probe, who, world.b.id, str(uuid.uuid4()))
    assert shape(got) == shape(random), (got.text, random.text)
    assert got.status_code in (404, 403, 400)  # never 2xx
    assert all(v not in got.text for v in world.ids.values()), got.text  # no A identifier is echoed
    assert str(world.a_owner.id) not in got.text


@pytest.mark.parametrize(
    "probe", PROBES, ids=lambda p: f"{p.method} {p.path.split('{s}')[1]} as {p.role}"
)
def test_a_person_of_another_society_gets_the_same_not_found_on_my_society_path(
    world: World, probe: Probe
) -> None:
    """The intruder is a member of B only: A's path is the same ``not_found`` as for a society that does not exist."""
    who = world.people[probe.role]
    foreign = world.ids.get(probe.foreign or "", str(uuid.uuid4()))
    got = world.call(probe, who, world.nw.soc.id, foreign)
    nothing = world.call(probe, who, uuid.uuid4(), foreign)
    assert got.status_code == 404 and shape(got) == shape(nothing), got.text
    assert all(v not in got.text for v in world.ids.values())
    outsider = world.call(probe, world.outsider, world.nw.soc.id, foreign)
    assert outsider.status_code == 404 and shape(outsider) == shape(nothing)


def test_nothing_of_a_leaks_into_bs_lists_and_numbers(world: World) -> None:
    nw = world.nw
    sec, res, guard = world.people["secretary"], world.people["resident"], world.people["guard"]
    b = world.b.id
    assert nw.call(sec, "GET", f"/v1/societies/{b}/notification-templates").json()["items"] == []
    budget = nw.call(sec, "GET", f"/v1/societies/{b}/notification-budget").json()
    assert budget["caps"] == {"notification": 30000, "call": 3000, "sms": 3000} and budget[
        "used"
    ] == {"notification": 0, "call": 0, "sms": 0}
    metrics = nw.call(sec, "GET", f"/v1/societies/{b}/notification-metrics").json()
    assert (
        metrics["arrivals"] == 0
        and metrics["notifications"]["total"] == 0
        and metrics["calls"]["total"] == 0
        and metrics["requests_with_cascade"] == 0
    )
    assert nw.call(sec, "GET", f"/v1/societies/{b}/device-health").json()["groups"] == []
    assert nw.call(res, "GET", f"/v1/societies/{b}/notifications").json()["items"] == []
    assert nw.call(res, "GET", f"/v1/societies/{b}/push-tokens").json()["items"] == []
    prefs = nw.call(res, "GET", f"/v1/societies/{b}/notification-preferences/me").json()
    assert (
        prefs["show_identity_on_lockscreen"] is False and prefs["language"] == "en"
    )  # A's preferences are not B's
    settings = nw.call(
        res, "GET", f"/v1/societies/{b}/units/{world.b.units['B-1']}/notification-settings"
    ).json()
    assert settings["version"] == 0
    # and A still has all of it
    assert (
        nw.call(nw.secretary, "GET", nw.s("notification-budget")).json()["caps"]["notification"]
        == 77
    )
    assert len(nw.call(nw.secretary, "GET", nw.s("notification-templates")).json()["items"]) == 1
    assert guard is not None


def test_a_cursor_issued_in_one_society_cannot_be_replayed_in_another(world: World) -> None:
    nw = world.nw
    nw.call(
        nw.secretary,
        "POST",
        nw.s("notification-templates"),
        json={
            "template_key": "a.two",
            "category": "finance",
            "channel": "push",
            "language": "en",
            "body_key": "finance.notice.body",
        },
    )
    first = nw.call(nw.secretary, "GET", nw.s("notification-templates"), params={"limit": 1}).json()
    assert first["next_cursor"]
    replay = nw.call(
        world.people["secretary"],
        "GET",
        f"/v1/societies/{world.b.id}/notification-templates",
        params={"limit": 1, "cursor": first["next_cursor"]},
    )
    assert replay.status_code == 400 and replay.json()["code"] == "invalid_schema"


def test_a_society_id_in_a_body_is_rejected_not_obeyed(world: World) -> None:
    nw = world.nw
    r = nw.call(world.people["secretary"], "PUT", f"/v1/societies/{world.b.id}/notification-budget",
                json={"monthly_notification_cap": 1, "monthly_call_cap": 1, "monthly_sms_cap": 1, "society_id": str(nw.soc.id)})  # fmt: skip
    assert r.status_code == 400
    assert (
        nw.call(nw.secretary, "GET", nw.s("notification-budget")).json()["caps"]["notification"]
        == 77
    )


def test_every_notifications_route_is_covered_by_a_probe(nw: NW) -> None:
    """A new route without an isolation probe fails here (the AT-01 inventory test fails first, by design)."""
    live = {
        (m, r.path)
        for r, m in (
            (route, method)
            for route in iter_api_routes(nw.app)
            for method in sorted(route.methods or ())
        )
        if r.path.startswith("/v1/societies/{society_id}/")
        and any(
            seg in r.path
            for seg in (
                "push-tokens",
                "device-diagnostics",
                "notification-",
                "notifications",
                "proxy-calls",
                "device-health",
                "cascade-attempts",
            )
        )
        and m not in ("HEAD", "OPTIONS")
    }
    live = {
        (
            m,
            p.replace("{unit_id}", "{x}")
            .replace("{token_id}", "{x}")
            .replace("{notification_id}", "{x}")
            .replace("{request_id}", "{x}")
            .replace("{call_id}", "{x}")
            .replace("{template_id}", "{x}"),
        )
        for m, p in live
    }
    covered = set(ROUTES)
    assert live == covered, (sorted(live - covered), sorted(covered - live))


def probed_routes() -> list[tuple[str, str]]:
    """(method, path template) of every route this file REALLY probes with a foreign id (the ``PROBES`` the parametrized test iterates over). The
    AT-01 route inventory resolves these against the live app: a route that is not here fails it."""
    return [(p.method, p.path.replace("{s}", "{society_id}")) for p in PROBES]
