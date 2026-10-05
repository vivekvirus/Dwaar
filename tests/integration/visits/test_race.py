"""Real concurrent transactions: the household race (AT-03 core), a stress run of hundreds of racing decisions, the
expiry-versus-decision boundary (AT-04 core) and the double tap with one Idempotency-Key.

Every thread uses its OWN client and so its own database transaction on its own pooled connection: no mocks, no
serialisation in the test. The invariants are read back from the database as the oracle.

REQ: GATE-03, INV-03, INV-07, AT-03, AT-04.
"""

from __future__ import annotations

import threading
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.integration.identity._support import Person
from tests.integration.visits._support import UA, VW

pytestmark = [pytest.mark.req("GATE-03", "INV-03")]


@pytest.fixture
def gate(vw: VW) -> VW:
    vw.setup_gate()
    return vw


def _post(
    app: Any,
    who: Person,
    society: uuid.UUID,
    request_id: str,
    body: dict[str, Any],
    key: str | None = None,
) -> Any:
    client = TestClient(app, raise_server_exceptions=False, headers=UA)
    return client.post(
        f"/v1/approval-requests/{request_id}/decision",
        json=body,
        headers={
            **who.headers,
            "X-Society-Id": str(society),
            "Idempotency-Key": key or f"race-{uuid.uuid4()}",
        },
    )


def _body(decision: str, version: int = 1) -> dict[str, Any]:
    return {
        "decision": decision,
        "expected_version": version,
        "client_action_id": str(uuid.uuid4()),
    }


def _assert_consistent(vw: VW, request_id: str) -> tuple[str, int]:
    """The database invariants of ONE request after any race. Returns (final state, valid decision count)."""
    state, version, perm = vw.rows(
        "SELECT state, version, permission_expires_at FROM approval_requests WHERE id = %s",
        (request_id,),
    )[0]
    valid = vw.rows(
        "SELECT decision FROM approval_decisions WHERE request_id = %s AND valid", (request_id,)
    )
    visit_state = vw.rows(
        "SELECT v.state FROM visits v JOIN approval_requests r ON r.visit_id = v.id WHERE r.id = %s",
        (request_id,),
    )[0][0]
    if state == "approved":
        assert (
            [r[0] for r in valid] == ["approve"]
            and perm is not None
            and visit_state == "authorised"
        )
    elif state == "denied":
        assert [r[0] for r in valid] == ["deny"] and perm is None and visit_state == "cancelled"
    else:  # expired / cancelled: no decision, no permission, no authorisation
        assert state == "expired" and valid == [] and perm is None and visit_state == "expired"
    assert version == 2
    events = vw.outbox("ApprovalDecided", request_id) + vw.outbox("ApprovalEscalated", request_id)
    assert (
        len(events) == 1
    )  # exactly one outcome event: the notification worker stops alerting once
    return str(state), len(valid)


@pytest.mark.at("AT-03")
def test_two_family_decisions_race_exactly_one_wins(gate: VW) -> None:
    h = gate.household("A-101", tenant=True)
    approver_a, approver_b = h.owner, h.family
    outcomes: Counter[tuple[int, str]] = Counter()
    for _ in range(12):
        req = gate.raise_request(h.unit)
        barrier = threading.Barrier(2)

        def attempt(
            who: Person,
            decision: str,
            req: dict[str, Any] = req,
            barrier: threading.Barrier = barrier,
        ) -> Any:
            barrier.wait()
            return _post(gate.idh.app, who, gate.soc.id, req["id"], _body(decision, req["version"]))

        with ThreadPoolExecutor(max_workers=2) as pool:
            fa = pool.submit(attempt, approver_a, "approve")
            fb = pool.submit(attempt, approver_b, "deny")  # type: ignore[arg-type]
            ra, rb = fa.result(), fb.result()
        statuses = sorted([ra.status_code, rb.status_code])
        assert statuses == [200, 409], (ra.text, rb.text)
        winner, loser = (ra, rb) if ra.status_code == 200 else (rb, ra)
        assert loser.json()["code"] == "already_decided"
        # the losing device receives the winner's canonical result in the very same answer
        assert loser.json()["details"]["canonical"] == winner.json()
        state, _ = _assert_consistent(gate, req["id"])
        assert state == winner.json()["status"]
        outcomes[(winner.status_code, winner.json()["status"])] += 1
    assert sum(outcomes.values()) == 12


@pytest.mark.req("GATE-03", "INV-07")
def test_hundreds_of_racing_decisions_one_winner_per_request(gate: VW) -> None:
    h = gate.household("A-101", tenant=True)
    people: list[Person] = [h.owner, h.tenant, h.family]  # type: ignore[list-item]
    requests = [gate.raise_request(h.unit, visitor_alias=f"V{i}") for i in range(10)]
    jobs: list[tuple[dict[str, Any], Person, str]] = []
    for req in requests:
        for i in range(30):  # 300 decisions in total
            jobs.append((req, people[i % 3], "approve" if i % 2 else "deny"))
    results: list[tuple[str, Any]] = []
    lock = threading.Lock()
    start = threading.Event()

    def work(job: tuple[dict[str, Any], Person, str]) -> None:
        req, who, decision = job
        start.wait()
        r = _post(gate.idh.app, who, gate.soc.id, req["id"], _body(decision, req["version"]))
        with lock:
            results.append((req["id"], r))

    with ThreadPoolExecutor(max_workers=24) as pool:
        futures = [pool.submit(work, job) for job in jobs]
        start.set()
        for f in futures:
            f.result()
    assert len(results) == 300
    for req in requests:
        mine = [r for rid, r in results if rid == req["id"]]
        codes = Counter(r.status_code for r in mine)
        assert codes == {200: 1, 409: 29}, (
            req["id"],
            codes,
            [r.text for r in mine if r.status_code not in (200, 409)],
        )
        winner = next(r for r in mine if r.status_code == 200).json()
        for loser in (r for r in mine if r.status_code == 409):
            assert (
                loser.json()["code"] == "already_decided"
                and loser.json()["details"]["canonical"] == winner
            )
        state, valid = _assert_consistent(gate, req["id"])
        assert valid == 1 and state == winner["status"]
    assert gate.rows("SELECT count(*) FROM approval_decisions WHERE valid")[0][0] == 10
    assert (
        gate.rows("SELECT count(*) FROM audit_log WHERE operation = 'approval.decide'")[0][0] == 10
    )
    assert gate.rows("SELECT count(*) FROM outbox WHERE event_type = 'ApprovalDecided'")[0][0] == 10


@pytest.mark.at("AT-04")
@pytest.mark.req("GATE-03", "INV-03")
def test_decisions_racing_the_expiry_never_leave_a_permission_behind(gate: VW) -> None:
    """Decide at the expiry boundary 24 times. Whatever wins, the invariants hold: an approved request was decided before
    its expiry; an expired one has no decision and no permission window; never both."""
    h = gate.household("A-101")
    outcomes: Counter[str] = Counter()
    for i in range(24):
        req = gate.raise_request(h.unit, visitor_alias=f"Edge{i}")
        gate.sql(
            "UPDATE approval_requests SET expires_at = clock_timestamp() + (%s * interval '1 millisecond') WHERE id = %s",
            (40 + (i % 6) * 25, req["id"]),
        )
        r = _post(gate.idh.app, h.owner, gate.soc.id, req["id"], _body("approve", req["version"]))
        assert r.status_code in (200, 409), r.text
        if r.status_code == 409:
            assert r.json()["code"] == "request_expired"
        state, _ = _assert_consistent(gate, req["id"])
        outcomes[state] += 1
        if state == "approved":
            decided_at, expires_at = gate.rows(
                "SELECT d.decided_at, r.expires_at FROM approval_decisions d JOIN approval_requests r ON r.id = d.request_id"
                " WHERE d.request_id = %s AND d.valid",
                (req["id"],),
            )[0]
            assert decided_at <= expires_at
    assert sum(outcomes.values()) == 24


@pytest.mark.req("GATE-03")
def test_double_tap_with_one_idempotency_key_decides_once(gate: VW) -> None:
    h = gate.household("A-101")
    req = gate.raise_request(h.unit)
    body = _body("approve", req["version"])
    barrier = threading.Barrier(2)

    def tap() -> Any:
        barrier.wait()
        return _post(gate.idh.app, h.owner, gate.soc.id, req["id"], body, key="double-tap-key-1")

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(tap), pool.submit(tap)
        ra, rb = a.result(), b.result()
    assert ra.status_code == rb.status_code == 200, (ra.text, rb.text)
    assert ra.json() == rb.json() and ra.json()["request_id"] == req["id"]
    assert {ra.headers.get("Idempotent-Replayed"), rb.headers.get("Idempotent-Replayed")} == {
        None,
        "true",
    }
    assert gate.rows("SELECT count(*) FROM approval_decisions")[0][0] == 1
    assert len(gate.outbox("ApprovalDecided", req["id"])) == 1
