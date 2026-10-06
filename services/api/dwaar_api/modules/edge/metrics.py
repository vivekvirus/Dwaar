"""Edge metrics for the later observability slice (OBS-02): in-process counters plus gauges computed from the database.

REQ: OBS-02 (metrics per society and device: sync age, policy age, outbox size), OBS-03 (alerts: edge silent over 5 minutes, policy
refresh failure), INV-12 (every SLO is instrumented). Nothing here claims a measured SLO: it exposes numbers for the future exporter.
Labels are opaque ids (a society or device UUID), never a phone, a name or a payload.
"""

from __future__ import annotations

import threading
import uuid
from collections import Counter
from collections.abc import Mapping
from typing import Any

from sqlalchemy import Connection, text

from dwaar_common.timeutil import utc_now


class EdgeMetrics:
    """Thread-safe monotonic counters. ``snapshot()`` is what an exporter would scrape."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Counter[tuple[str, tuple[tuple[str, str], ...]]] = Counter()

    def inc(self, name: str, **labels: str) -> None:
        self.inc_labels(name, labels)

    def inc_labels(self, name: str, labels: Mapping[str, str], amount: int = 1) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[key] += amount

    def get(self, name: str, **labels: str) -> int:
        with self._lock:
            return self._counters[(name, tuple(sorted(labels.items())))]

    def total(self, name: str) -> int:
        with self._lock:
            return sum(v for (n, _), v in self._counters.items() if n == name)

    def snapshot(self) -> dict[str, list[dict[str, Any]]]:
        with self._lock:
            items = sorted(self._counters.items())
        out: dict[str, list[dict[str, Any]]] = {}
        for (name, labels), value in items:
            out.setdefault(name, []).append({"labels": dict(labels), "value": value})
        return out

    def render_text(self) -> str:
        """Prometheus text exposition of the counters (no HTTP route is mounted for it yet)."""
        lines: list[str] = []
        for name, series in self.snapshot().items():
            lines.append(f"# TYPE dwaar_edge_{name} counter")
            for s in series:
                labels = ",".join(f'{k}="{v}"' for k, v in s["labels"].items())
                lines.append(f"dwaar_edge_{name}{{{labels}}} {s['value']}")
        return "\n".join(lines) + ("\n" if lines else "")


def collect_gauges(conn: Connection, society_id: uuid.UUID) -> dict[str, Any]:
    """Per-device sync age and policy age, edge backlog estimate and the cloud-side outbox backlog of ONE society (RLS context set)."""
    now = utc_now()
    latest = conn.execute(
        text("SELECT seq, issued_at, valid_until FROM policy_snapshots ORDER BY seq DESC LIMIT 1")
    ).first()
    rows = conn.execute(
        text(
            "SELECT d.id, d.name, d.state, d.last_seen_at, s.last_sync_at, s.highest_contiguous_seq, s.max_seq_seen,"
            " s.policy_seq_applied, s.last_policy_poll_at, s.quarantined_total,"
            " (SELECT p.issued_at FROM policy_snapshots p WHERE p.seq = s.policy_seq_applied) AS applied_issued_at"
            " FROM devices d LEFT JOIN edge_device_state s ON s.society_id = d.society_id AND s.device_id = d.id"
            " WHERE d.kind IN ('gateway', 'terminal') AND d.state IN ('active', 'revoked') ORDER BY d.name, d.id"
        )
    ).mappings()
    devices: list[dict[str, Any]] = []
    for r in rows:
        devices.append(
            {
                "device_id": r["id"],
                "name": r["name"],
                "state": r["state"],
                "sync_age_s": _age(now, r["last_sync_at"]),
                "seen_age_s": _age(now, r["last_seen_at"]),
                # the age of the policy the device says it applies; None when it never fetched one
                "policy_age_s": _age(now, r["applied_issued_at"]),
                "policy_seq_applied": r["policy_seq_applied"],
                "highest_contiguous_seq": r["highest_contiguous_seq"],
                # events the cloud knows exist above the contiguous cursor: the edge's unacknowledged backlog, as far as it is visible
                "edge_backlog_estimate": max(
                    0, int(r["max_seq_seen"] or 0) - int(r["highest_contiguous_seq"] or 0)
                ),
                "quarantined_total": r["quarantined_total"] or 0,
            }
        )
    outbox = conn.execute(
        text(
            "SELECT count(*) FROM outbox WHERE published_at IS NULL AND society_id = current_setting('app.society_id')::uuid"
        )
    ).scalar_one()
    return {
        "society_id": society_id,
        "latest_policy_seq": latest[0] if latest else None,
        "latest_policy_age_s": _age(now, latest[1]) if latest else None,
        "latest_policy_expires_in_s": None
        if latest is None
        else int((latest[2] - now).total_seconds()),
        "outbox_backlog": int(outbox),
        "devices": devices,
    }


def _age(now: Any, then: Any) -> int | None:
    return None if then is None else max(0, int((now - then).total_seconds()))
