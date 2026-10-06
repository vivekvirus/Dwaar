"""Child process for the kill -9 tests. Prints ``ACK <seq> <event_id> <movement_id>`` ONLY after the gateway call
returned, i.e. after the transaction committed: an ACK line is what a terminal would have shown as success.

Usage: crash_worker.py <world.json> <data_dir> loop
       crash_worker.py <world.json> <data_dir> die_at <label> <after_n_entries>
"""

from __future__ import annotations

import json
import os
import signal
import sys
from pathlib import Path

from tests.integration.edge_gateway.support import RealTime, World

RES = {"kind": "resident", "credential_ref": "cred-r1", "revocation_version": 1}


def main() -> None:
    world = World.from_json(json.loads(Path(sys.argv[1]).read_text()))
    data_dir = Path(sys.argv[2])
    mode = sys.argv[3]
    t = RealTime()
    gw = world.gateway(data_dir, t)  # real clock, trusted sample at start
    actor = world.actor(gw, world.term_a)
    if mode == "die_at":
        label, after = sys.argv[4], int(sys.argv[5])
        state = {"n": 0}

        def hook(point: str) -> None:
            if point == label and state["n"] >= after:
                os.kill(
                    os.getpid(), signal.SIGKILL
                )  # real SIGKILL in the middle of the transaction

        gw.store.crash_hook = hook
    n = 0
    while True:
        ev = gw.evaluate(actor, gate_id=world.gate_a, lane_id=world.lane_a_in, credential=RES)
        r = gw.record_entry(
            actor, gate_id=world.gate_a, lane_id=world.lane_a_in, evaluation_id=ev["evaluation_id"]
        )
        n += 1
        if mode == "die_at":
            state["n"] = n  # type: ignore[possibly-undefined]
        print(f"ACK {r['seq']} {r['event_id']} {r['movement_id']}", flush=True)  # noqa: T201
        if mode == "die_at" and n > after + 5:  # type: ignore[possibly-undefined]
            raise SystemExit("hook never fired")


if __name__ == "__main__":
    main()
