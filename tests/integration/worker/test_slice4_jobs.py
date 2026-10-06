"""Slice 4 worker jobs run for real as ``dwaar_worker`` (narrow grants, per-society RLS context, idempotent) and as Dramatiq actors on a StubBroker.

REQ: OPS-01, OPS-04 (helpdesk sweep), COM-01, COM-06 (scheduled notices, poll closing), PAR-05 (parcel reminders), SHIFT-01 (handover escalation, override
expiry), PRD 12.4 (a job's mutation commits with its audit and outbox row), PRD 13 (Dramatiq + Redis adapter, plain job functions, StubBroker in tests),
INV-01 (one society per transaction), INV-03/INV-08 (no sweep can allow or lock anything). Redis is never started.

The module tests drive the same service functions as the API role; this file proves they also work with the WORKER role's grants, which is the role a
real deployment uses.
"""
# ruff: noqa: PT018, PT012, PT011, F811, RUF015, PT022

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from contextlib import contextmanager

import dramatiq
import psycopg
import pytest
from psycopg import errors as pg

from dwaar_worker import jobs
from dwaar_worker.actors import Actors, Runtime, build_actors
from dwaar_worker.broker import make_stub_broker
from dwaar_worker.config import WorkerConfig
from dwaar_worker.scheduler import run_scheduler
from tests.integration.community._flow import crew as community_crew
from tests.integration.community._flow import draft as draft_notice
from tests.integration.community._flow import post as post_notice
from tests.integration.community.conftest import cw  # noqa: F401
from tests.integration.helpdesk._flow import crew, raise_ticket, tid
from tests.integration.helpdesk._support import World, hw  # noqa: F401
from tests.integration.helpdesk.test_closure_reopen_settings import household, resolved_ticket
from tests.integration.parcels._support import PW, now, pw  # noqa: F401

pytestmark = [
    pytest.mark.req("OPS-01", "OPS-04", "COM-01", "COM-06", "PAR-05", "SHIFT-01", "INV-01")
]

CONFIG = WorkerConfig(queue="dwaar-slice4-test", policy_interval_s=5, sweep_interval_s=10)


def _breaches(w: World, ticket: str) -> list[tuple[str, str]]:
    return [
        (r[0], r[1])
        for r in w.rows(
            "SELECT clock, basis FROM ticket_sla_breaches WHERE ticket_id = %s ORDER BY clock",
            (ticket,),
        )
    ]


# ------------------------------------------------------------------------------------------------------------ helpdesk
def test_the_helpdesk_sweep_runs_as_the_worker_role_records_breaches_once_and_closes_stale_resolutions(
    hw: World,
) -> None:
    c = crew(hw)
    unit, owner = household(hw, "A-101")
    late = tid(raise_ticket(hw, c.secretary, title="Lift button broken", category="common_area"))
    hw.sql("UPDATE tickets SET sla_ack_by = now() - interval '2 hours' WHERE id = %s", (late,))
    done = resolved_ticket(hw, c, owner, unit)
    hw.sql(
        "UPDATE tickets SET feedback_due_at = now() - interval '1 minute' WHERE id = %s", (done,)
    )

    first = jobs.sweep_helpdesk(hw.database, societies=[hw.soc.id])
    assert first.failed == {} and first.societies == 1 and first.changed == 1, first
    assert first.detail == {"closed": 1, "breached": 1}
    assert _breaches(hw, late) == [("acknowledgement", "sweep")]
    row = hw.rows("SELECT state, closed_basis FROM tickets WHERE id = %s", (done,))[0]
    assert row == ("closed", "feedback_window_elapsed")
    # the system, not a person, is the actor; audit and outbox rows were written in the same transaction by the worker role
    assert hw.audit("ticket.close")[-1][1] is None
    assert hw.outbox("TicketClosed", done) and hw.outbox("TicketSlaBreached", late)

    audit_rows = hw.rows("SELECT count(*) FROM audit_log")[0][0]
    outbox_rows = hw.rows("SELECT count(*) FROM outbox")[0][0]
    second = jobs.sweep_helpdesk(hw.database, societies=[hw.soc.id])
    third = jobs.sweep_helpdesk(hw.database, societies=[hw.soc.id])
    assert second.failed == third.failed == {} and second.changed == third.changed == 0, (
        second,
        third,
    )
    assert hw.rows("SELECT count(*) FROM audit_log")[0][0] == audit_rows
    assert hw.rows("SELECT count(*) FROM outbox")[0][0] == outbox_rows
    assert _breaches(hw, late) == [("acknowledgement", "sweep")]  # exactly one row, ever


def test_a_sweep_of_one_society_touches_nothing_of_another(hw: World) -> None:
    foreign = hw.second_society()
    res_b = hw.resident(foreign.units["Z-101"], "owner", soc=foreign)
    r = hw.call(
        res_b,
        "POST",
        "/v1/tickets",
        society=foreign.id,
        json={"scope": "society", "category": "common_area", "title": "Foreign lift fault"},
    )
    assert r.status_code == 201, r.text
    foreign_ticket = r.json()["ticket"]["id"]
    mine = tid(raise_ticket(hw, crew(hw).secretary, title="Our own lift fault"))
    hw.sql("UPDATE tickets SET sla_ack_by = now() - interval '2 hours'")  # both are overdue
    out = jobs.sweep_helpdesk(hw.database, societies=[hw.soc.id])
    assert out.failed == {} and out.detail.get("breached") == 1
    assert _breaches(hw, mine) == [("acknowledgement", "sweep")]
    assert (
        _breaches(hw, foreign_ticket) == []
    )  # society B was not in this run: its context never existed
    both = jobs.sweep_helpdesk(hw.database)  # every active society, each in its own transaction
    assert both.societies >= 2 and both.failed == {}
    assert _breaches(hw, foreign_ticket) == [("acknowledgement", "sweep")]


def test_a_failure_in_one_society_is_recorded_by_class_name_and_does_not_stop_the_others(
    hw: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    foreign = hw.second_society()
    from dwaar_api.modules.helpdesk import service

    real = service.sweep_society

    def flaky(conn, ctx, now=None):  # type: ignore[no-untyped-def]
        if ctx.society_id == foreign.id:
            raise RuntimeError("boom: carries a name that must not be logged")
        return real(conn, ctx, now)

    monkeypatch.setattr(service, "sweep_society", flaky)
    out = jobs.sweep_helpdesk(hw.database, societies=[foreign.id, hw.soc.id])
    assert out.societies == 2 and out.failed == {foreign.id: "RuntimeError"}


# ------------------------------------------------------------------------------------------------------------ community
def test_scheduled_notices_go_live_through_the_worker_once(cw: World) -> None:
    c = community_crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    n = draft_notice(
        cw, c.committee, title="Terrace lawn reopening", body="The lawn reopens on Sunday morning."
    )
    post_notice(cw, c.secretary, n["id"], "approve")
    when = dt.datetime.now(dt.UTC) + dt.timedelta(hours=3)
    post_notice(cw, c.secretary, n["id"], "publish", {"publish_at": when.isoformat()})
    assert cw.call(owner, "GET", f"/v1/notices/{n['id']}").status_code == 404
    early = jobs.publish_due_notices(
        cw.database, now=when - dt.timedelta(minutes=1), societies=[cw.soc.id]
    )
    assert early.failed == {} and early.changed == 0
    live = jobs.publish_due_notices(
        cw.database, now=when + dt.timedelta(minutes=1), societies=[cw.soc.id]
    )
    assert live.failed == {} and live.detail == {"notices_published": 1}
    assert cw.call(owner, "GET", f"/v1/notices/{n['id']}").json()["notice"]["state"] == "published"
    events = len(cw.outbox("NoticePublished", n["id"]))
    again = jobs.publish_due_notices(
        cw.database, now=when + dt.timedelta(hours=1), societies=[cw.soc.id]
    )
    assert again.changed == 0 and len(cw.outbox("NoticePublished", n["id"])) == events == 1


def test_polls_close_through_the_worker_once_and_stay_non_binding(cw: World) -> None:
    c = community_crew(cw)
    made = cw.call(
        c.committee,
        "POST",
        "/v1/polls",
        json={"question": "Should the lawn be redone this year?", "options": ["Yes", "No"]},
    )
    assert made.status_code == 201, made.text
    poll = made.json()["poll"]
    when = dt.datetime.now(dt.UTC) + dt.timedelta(days=2)
    opened = cw.call(
        c.secretary, "POST", f"/v1/polls/{poll['id']}/open", json={"closes_at": when.isoformat()}
    )
    assert opened.status_code == 200, opened.text
    early = jobs.close_due_polls(
        cw.database, now=when - dt.timedelta(minutes=1), societies=[cw.soc.id]
    )
    assert early.failed == {} and early.changed == 0
    closed = jobs.close_due_polls(
        cw.database, now=when + dt.timedelta(minutes=1), societies=[cw.soc.id]
    )
    assert closed.failed == {} and closed.detail == {"polls_closed": 1}
    got = cw.call(c.secretary, "GET", f"/v1/polls/{poll['id']}").json()["poll"]
    assert got["state"] == "closed"
    assert cw.rows("SELECT is_binding FROM polls WHERE id = %s", (poll["id"],)) == [(False,)]
    again = jobs.close_due_polls(
        cw.database, now=when + dt.timedelta(minutes=5), societies=[cw.soc.id]
    )
    assert again.changed == 0 and len(cw.outbox("PollClosed", poll["id"])) == 1


# ------------------------------------------------------------------------------------------------------------ parcels and shifts
def test_parcel_reminders_run_through_the_worker_wrapper_once_per_age(pw: PW) -> None:
    h = pw.household("A-101")
    old = pw.stored_parcel(h.unit, "Old")
    pw.sql(
        "UPDATE parcels SET received_at = clock_timestamp() - interval '49 hours' WHERE id = %s",
        (old["id"],),
    )
    first = jobs.send_parcel_reminders(pw.idh.database, now=now(), societies=[pw.soc.id])
    assert first.failed == {} and first.detail == {"reminders_h24": 1, "reminders_h48": 1}
    again = jobs.send_parcel_reminders(pw.idh.database, now=now(), societies=[pw.soc.id])
    assert again.changed == 0 and again.detail == {}
    assert len(pw.outbox("ParcelReminderDue")) == 2
    # the custody report is a guard's physical count, never a timer's: the job writes none
    assert pw.rows("SELECT count(*) FROM parcel_custody_reports") == [(0,)]


def test_the_shift_sweep_runs_through_the_worker_wrapper(pw: PW) -> None:
    shift = pw.schedule(pw.guard)
    started = pw.call(pw.guard, "POST", f"/v1/shifts/{shift['id']}/start", json={"checklist": {}})
    assert started.status_code == 200, started.text
    ended = pw.call(pw.guard, "POST", f"/v1/shifts/{shift['id']}/end", json=pw.end_body())
    assert ended.status_code == 200, ended.text
    handover = ended.json()["handover"]
    early = jobs.sweep_shifts(
        pw.idh.database, now=now() + dt.timedelta(minutes=5), societies=[pw.soc.id]
    )
    assert early.failed == {} and early.detail["handovers_escalated"] == 0
    late = jobs.sweep_shifts(
        pw.idh.database, now=now() + dt.timedelta(minutes=30), societies=[pw.soc.id]
    )
    assert late.failed == {} and late.detail["handovers_escalated"] == 1
    again = jobs.sweep_shifts(
        pw.idh.database, now=now() + dt.timedelta(minutes=60), societies=[pw.soc.id]
    )
    assert again.changed == 0
    assert pw.rows("SELECT state FROM shift_handovers WHERE id = %s", (handover["id"],)) == [
        ("escalated",)
    ]


# ------------------------------------------------------------------------------------------------------------ actors
@contextmanager
def running(runtime: Runtime) -> Iterator[tuple[object, Actors, dramatiq.Worker]]:
    broker = make_stub_broker()
    actors = build_actors(broker, runtime, CONFIG)
    worker = dramatiq.Worker(broker, worker_timeout=100)
    worker.start()
    try:
        yield broker, actors, worker
    finally:
        worker.stop()
        broker.close()


def test_every_slice4_job_is_a_registered_dramatiq_actor_and_duplicate_messages_are_harmless(
    hw: World,
) -> None:
    c = crew(hw)
    late = tid(raise_ticket(hw, c.secretary, title="Gate light out", category="common_area"))
    hw.sql("UPDATE tickets SET sla_ack_by = now() - interval '2 hours' WHERE id = %s", (late,))
    runtime = Runtime(hw.database, None)  # type: ignore[arg-type]
    with running(runtime) as (broker, actors, worker):
        names = {
            getattr(actors, f).actor_name
            for f in (
                "helpdesk_sweep",
                "notices_publish_due",
                "polls_close_due",
                "parcels_reminders",
                "shifts_sweep",
            )
        }
        assert names == {
            "helpdesk_sweep",
            "notices_publish_due",
            "polls_close_due",
            "parcels_reminders",
            "shifts_sweep",
        }
        assert all(
            getattr(actors, f).queue_name == CONFIG.queue
            for f in ("helpdesk_sweep", "notices_publish_due", "polls_close_due")
        )
        for _ in range(3):  # a replayed trigger is harmless
            actors.helpdesk_sweep.send()
            actors.notices_publish_due.send()
            actors.polls_close_due.send()
            actors.parcels_reminders.send()
            actors.shifts_sweep.send()
        broker.join(CONFIG.queue)  # type: ignore[attr-defined]
        worker.join()
    assert runtime.last is not None
    assert all(runtime.last[n].failed == {} for n in names), runtime.last
    assert _breaches(hw, late) == [("acknowledgement", "sweep")]  # three messages, one breach row


def test_the_scheduler_sends_every_slice4_sweep_on_the_sweep_cadence() -> None:
    sent: list[str] = []

    class Spy:
        def __init__(self, name: str) -> None:
            self.name = name

        def send(self) -> None:
            sent.append(self.name)

    now_ = {"t": 0.0}
    rounds = {"n": 0}

    def should_stop() -> bool:
        rounds["n"] += 1
        return rounds["n"] > 21  # t = 0 .. 20 s

    def sleep(_s: float) -> None:
        now_["t"] += 1.0

    actors = Actors(
        Spy("publish"),
        Spy("sweep"),
        None,
        helpdesk_sweep=Spy("helpdesk"),
        notices_publish_due=Spy("notices"),
        polls_close_due=Spy("polls"),
        parcels_reminders=Spy("parcels"),
        shifts_sweep=Spy("shifts"),
    )
    run_scheduler(actors, CONFIG, should_stop=should_stop, sleep=sleep, clock=lambda: now_["t"])
    for name in ("helpdesk", "notices", "polls", "parcels", "shifts", "sweep"):
        assert sent.count(name) == 3, (name, sent.count(name))  # t = 0, 10, 20


# ------------------------------------------------------------------------------------------------------------ grants
#: what dwaar_worker may do to the slice 4 society tables after migration 0540 (and 0400/0460/0500): nothing wider than the jobs above need
EXPECTED_WORKER_WRITES = {
    "tickets": {"UPDATE"},
    "ticket_events": {"INSERT"},
    "ticket_priority_history": {"INSERT"},
    "ticket_sla_log": {"INSERT"},
    "ticket_sla_breaches": {"INSERT"},
    "notices": {"UPDATE"},
    "notice_versions": {"UPDATE"},
    "polls": {"UPDATE"},
    "parcel_reminders": {"INSERT"},
    "shift_handovers": {"UPDATE"},
    "shift_overrides": {"UPDATE"},
}


def test_the_worker_role_has_exactly_the_narrow_writes_the_slice4_jobs_need(hw: World) -> None:
    rows = hw.rows(
        "SELECT c.relname, has_table_privilege('dwaar_worker', c.oid, 'INSERT'),"
        " has_table_privilege('dwaar_worker', c.oid, 'UPDATE'),"
        " has_table_privilege('dwaar_worker', c.oid, 'DELETE'),"
        " has_table_privilege('dwaar_worker', c.oid, 'TRUNCATE'),"
        " has_any_column_privilege('dwaar_worker', c.oid, 'UPDATE')"
        " FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r'"
        " AND c.relname = ANY(%s)",
        (sorted(EXPECTED_WORKER_WRITES),),
    )
    assert len(rows) == len(EXPECTED_WORKER_WRITES)
    for table, ins, _upd, dele, trunc, col_upd in rows:
        assert not dele and not trunc, table  # never delete or truncate history
        assert ins == ("INSERT" in EXPECTED_WORKER_WRITES[table]), table
        assert col_upd == ("UPDATE" in EXPECTED_WORKER_WRITES[table]), table
        # column-scoped UPDATE only: no table-wide UPDATE on any of them
        assert not _upd, f"{table}: the worker must not hold table-wide UPDATE"


def test_the_worker_cannot_rewrite_what_a_resident_wrote(hw: World) -> None:
    c = crew(hw)
    unit, owner = household(hw, "A-101")
    t = tid(
        raise_ticket(
            hw, owner, scope="private", unit_id=str(unit), category="plumbing", title="Tap leaks"
        )
    )
    with psycopg.connect(hw.idh.db.worker_dsn, autocommit=False) as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(hw.soc.id),))
        for statement in (
            "UPDATE tickets SET title = 'tampered' WHERE id = %s",
            "UPDATE tickets SET description = 'tampered' WHERE id = %s",
            "UPDATE tickets SET raised_by = raised_by WHERE id = %s",
            "DELETE FROM tickets WHERE id = %s",
            "UPDATE ticket_events SET kind = 'x' WHERE ticket_id = %s",
        ):
            with pytest.raises((pg.InsufficientPrivilege, pg.RaiseException)):
                conn.execute(statement, (t,))  # type: ignore[call-overload]
            conn.rollback()
            conn.execute("SELECT set_config('app.society_id', %s, true)", (str(hw.soc.id),))
    assert c is not None
