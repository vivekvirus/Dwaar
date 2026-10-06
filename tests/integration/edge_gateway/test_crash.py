"""kill -9 recovery: no acknowledged event is lost and no torn state remains (EDGE-01, EDGE-02, NFR-09).

Real subprocesses, real SIGKILL, real SQLite files on disk with ``synchronous=FULL``. Caveat stated plainly: a
process kill does not exercise power loss or a lying disk cache; those need the actual gateway hardware (EDGE-01).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from datetime import timedelta
from pathlib import Path

import pytest

from tests.integration.edge_gateway.support import RealTime, World

pytestmark = [pytest.mark.req("EDGE-01", "EDGE-02", "NFR-09")]

WORKER = str(Path(__file__).with_name("crash_worker.py"))
ROOT = Path(__file__).resolve().parents[3]


def prepare(tmp_path: Path) -> tuple[World, Path, Path]:
    w = World()
    t = RealTime()
    data = tmp_path / "edge"
    gw = w.gateway(data, t)
    gw.apply_policy(
        w.snapshot(
            seq=1,
            issued_at=t.wall_now,
            manifest=w.manifest(residents=[w.resident()]),
            valid_for=timedelta(hours=96),
        )
    )
    gw.stop()
    wf = tmp_path / "world.json"
    wf.write_text(json.dumps(w.to_json()))
    return w, wf, data


def spawn(args: list[str]) -> subprocess.Popen[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONUNBUFFERED": "1"}
    return subprocess.Popen(
        [sys.executable, WORKER, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=ROOT,
    )  # noqa: S603


def check_consistent(w: World, data: Path, acked: list[tuple[int, str, str]]) -> int:
    t = RealTime()
    gw = w.gateway(data, t)  # startup runs the full integrity check and the torn-write invariant
    try:
        outbox = {
            int(r["seq"]): r["event_id"] for r in gw.store.all("SELECT seq, event_id FROM outbox")
        }
        moves = {r["entity_id"] for r in gw.store.all("SELECT entity_id FROM movements")}
        entities = {
            r["entity_id"]
            for r in gw.store.all("SELECT entity_id FROM outbox WHERE type='EntryObserved'")
        }
        n = len(outbox)
        assert sorted(outbox) == list(range(1, n + 1)), "sequence must be contiguous"
        assert gw.store.get_meta("last_seq") == str(n), (
            "device counter equals the outbox head (no torn state)"
        )
        assert moves == entities, "projection and outbox agree exactly"
        for seq, event_id, movement_id in acked:  # EVERY acknowledged event survived
            assert outbox.get(seq) == event_id
            assert movement_id in moves
        assert (
            len(acked) <= n <= len(acked) + 1
        )  # at most the one in flight, committed but not yet printed
        return n
    finally:
        gw.stop()


def parse_acks(text: str) -> list[tuple[int, str, str]]:
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[0] == "ACK":
            out.append((int(parts[1]), parts[2], parts[3]))
    return out


@pytest.mark.parametrize("round_no", range(3))
def test_sigkill_while_writing_loses_no_acknowledged_event(tmp_path: Path, round_no: int) -> None:
    w, wf, data = prepare(tmp_path)
    total_acked: list[tuple[int, str, str]] = []
    for _ in range(3):  # three crashes in a row on the same store
        p = spawn([str(wf), str(data), "loop"])
        assert p.stdout is not None
        lines: list[str] = []
        deadline = time.monotonic() + 60
        target = 15 + round_no * 7
        while len(lines) < target and time.monotonic() < deadline:
            line = p.stdout.readline()
            if not line:
                break
            lines.append(line)
        os.kill(p.pid, signal.SIGKILL)  # no warning, no cleanup, possibly mid-transaction
        p.wait(timeout=10)
        rest = p.stdout.read()  # whatever was printed before the kill
        err = p.stderr.read() if p.stderr else ""
        assert p.returncode == -signal.SIGKILL, err
        acked = parse_acks("".join(lines) + rest)
        assert len(acked) >= 5, err
        total_acked = [*total_acked, *acked]
        n = check_consistent(w, data, total_acked)
        assert n >= len(total_acked)
    assert [a[0] for a in total_acked] == sorted(
        {a[0] for a in total_acked}
    )  # no seq acknowledged twice


@pytest.mark.parametrize("label", ["after_projection", "after_outbox_insert", "after_event"])
def test_sigkill_in_the_middle_of_the_transaction_leaves_no_torn_state(
    tmp_path: Path, label: str
) -> None:
    w, wf, data = prepare(tmp_path)
    p = spawn([str(wf), str(data), "die_at", label, "2"])
    out, err = p.communicate(timeout=60)
    assert p.returncode == -signal.SIGKILL, err
    acked = parse_acks(out)
    assert len(acked) == 2  # the third entry died inside its transaction: it was never acknowledged
    n = check_consistent(w, data, acked)
    assert (
        n == 2
    )  # and left nothing behind: no event without projection, no projection without event
    gw = w.gateway(data, RealTime())
    try:
        actor = w.actor(gw, w.term_a)
        ev = gw.evaluate(
            actor,
            gate_id=w.gate_a,
            lane_id=w.lane_a_in,
            credential={"kind": "resident", "credential_ref": "cred-r1", "revocation_version": 1},
        )
        r = gw.record_entry(
            actor, gate_id=w.gate_a, lane_id=w.lane_a_in, evaluation_id=ev["evaluation_id"]
        )
        assert r["seq"] == 3  # no gap, no reuse
    finally:
        gw.stop()


def test_sigkill_during_policy_apply_keeps_the_last_good_policy(tmp_path: Path) -> None:
    w, wf, data = prepare(tmp_path)
    t = RealTime()
    code = f"""
import json, os, signal, sys
from pathlib import Path
from datetime import timedelta
from tests.integration.edge_gateway.support import RealTime, World
w = World.from_json(json.loads(Path({str(wf)!r}).read_text()))
t = RealTime()
gw = w.gateway(Path({str(data)!r}), t)
def hook(label):
    if label == 'after_policy_insert':
        os.kill(os.getpid(), signal.SIGKILL)
gw.store.crash_hook = hook
gw.apply_policy(w.snapshot(seq=2, issued_at=t.wall_now, manifest=w.manifest(revocations=[{{'ref': 'cred-r1', 'version': 9}}])))
"""
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    p = subprocess.run(
        [sys.executable, "-c", code], env=env, cwd=ROOT, capture_output=True, text=True, timeout=60
    )  # noqa: S603
    assert p.returncode == -signal.SIGKILL, p.stderr
    gw = w.gateway(data, t)
    try:
        assert gw.policy is not None and gw.policy.seq == 1 and gw.policy_seq() == 1
        assert gw.policy.revocations == {}  # the half-applied revocation did not leak in
        assert gw.store.one("SELECT COUNT(*) AS n FROM policy_snapshots")["n"] == 1
    finally:
        gw.stop()


def test_second_process_cannot_open_a_live_store(tmp_path: Path) -> None:
    w, wf, data = prepare(tmp_path)
    gw = w.gateway(data, RealTime())
    try:
        p = spawn([str(wf), str(data), "loop"])
        out, err = p.communicate(timeout=60)
        assert p.returncode != 0 and "StoreLockedError" in err and not parse_acks(out)
    finally:
        gw.stop()
