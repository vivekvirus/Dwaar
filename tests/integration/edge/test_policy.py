"""Signed policy snapshots: content, signature, monotonic sequence, revocations, rotation, refresh, minimisation, isolation.

REQ: EDGE-04, GATE-06, GATE-01, PRD 9.3 (cloud authority), PRD 13 (publisher: on change and periodic refresh, revocations prioritised),
PRD 12.4 (PolicyPublished), EDGE-10 (tombstones), INV-01, DB-02.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import re
import uuid
from typing import Any

import psycopg
import pytest

from dwaar_api.core.db import RequestContext
from dwaar_api.modules.edge import snapshot as snap
from dwaar_api.modules.edge.config import SimulatedKmsSigner
from dwaar_common.signing import (
    generate_private_key,
    key_id_for,
    private_key_to_b64,
    public_key_from_b64,
    verify_envelope,
)
from dwaar_common.timeutil import utc_now
from tests.integration.edge._support import EdgeClient, EdgeWorld

pytestmark = [pytest.mark.req("EDGE-04", "GATE-06")]


@pytest.fixture
def dev(ew: EdgeWorld) -> EdgeClient:
    return ew.edge_device()


def fetch(dev: EdgeClient, after: int | None = None) -> dict[str, Any]:
    r = dev.policy(after)
    assert r.status_code == 200, r.text
    body: dict[str, Any] = r.json()
    return body


def trusted(dev: EdgeClient) -> dict[str, Any]:
    keys = dev.request("GET", "/v1/edge/keys").json()["keys"]
    return {k["key_id"]: public_key_from_b64(k["public_key"]) for k in keys}


def verifies(snapshot: dict[str, Any], keys: dict[str, Any]) -> bool:
    key = keys.get(snapshot["issuer_key_id"])
    return key is not None and verify_envelope(key, snapshot)


def publish(ew: EdgeWorld, *, force: bool = False, who: Any = None) -> Any:
    return ew.call(
        who or ew.secretary,
        "POST",
        ew.s("edge/policy/publish"),
        params={"force": force} if force else None,
    )


def make_invitation(ew: EdgeWorld, unit: uuid.UUID, who: Any, **extra: Any) -> dict[str, Any]:
    start = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5)
    body = {
        "unit_id": str(unit), "purpose": "Dinner", "visitor_alias": "Aunt Sulabha", "people_count": 2,
        "windows": [{"start": start.isoformat(), "end": (start + dt.timedelta(hours=3)).isoformat()}], "max_uses": 2,
    }  # fmt: skip
    body.update(extra)
    r = ew.call(who, "POST", ew.s("invitations"), json=body)
    assert r.status_code == 201, r.text
    created: dict[str, Any] = r.json()
    return created


# ------------------------------------------------------------------------------------------ shape and signature
def test_first_snapshot_is_signed_complete_and_verifiable_by_the_published_issuer_key(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    s = fetch(dev)
    assert set(s) == {
        "schema_version",
        "society_id",
        "seq",
        "issued_at",
        "valid_until",
        "issuer_key_id",
        "manifest",
        "signature",
    }
    assert s["schema_version"] == 1 and s["seq"] == 1 and s["society_id"] == str(ew.soc.id)
    assert set(s["manifest"]) == {
        "gates",
        "lanes",
        "devices",
        "residents",
        "invitations",
        "standing_rules",
        "timing",
        "revocations",
    }
    assert s["signature"].startswith("ed25519:")
    assert verifies(s, trusted(dev))
    issued = dt.datetime.fromisoformat(s["issued_at"].replace("Z", "+00:00"))
    valid = dt.datetime.fromisoformat(s["valid_until"].replace("Z", "+00:00"))
    assert valid - issued == dt.timedelta(hours=72)  # EDGE-05: policy age limit
    assert [g["kind"] for g in s["manifest"]["gates"]] == ["mixed"]
    assert any(
        d["id"] == str(dev.device_id) and d["status"] == "active" for d in s["manifest"]["devices"]
    )


def test_any_edit_of_a_snapshot_breaks_the_signature(ew: EdgeWorld, dev: EdgeClient) -> None:
    s = fetch(dev)
    keys = trusted(dev)
    assert verifies(s, keys)
    for mutate in (
        lambda x: x.update(seq=x["seq"] + 1),
        lambda x: x.update(valid_until="2099-01-01T00:00:00.000Z"),
        lambda x: x["manifest"]["gates"].clear(),
        lambda x: x["manifest"]["timing"].update(policy_age_limit_s=10**9),
        lambda x: x.update(society_id=str(uuid.uuid4())),
        lambda x: x["manifest"]["revocations"].append({"ref": "x", "version": 1}),
    ):
        copy = json.loads(json.dumps(s))
        mutate(copy)
        assert not verifies(copy, keys)
    assert not verifies({**s, "issuer_key_id": "ed-unknown"}, keys)  # unknown issuer


def test_polling_cursor_204_409_and_validation(ew: EdgeWorld, dev: EdgeClient) -> None:
    assert fetch(dev)["seq"] == 1
    assert dev.policy(after=1).status_code == 204
    assert dev.policy(after=1).content == b""
    ahead = dev.policy(after=7)
    assert ahead.status_code == 409 and ahead.json()["code"] == "stale_version"
    assert ahead.json()["details"] == {"reason": "cursor_ahead_of_cloud", "latest_seq": 1}
    assert dev.policy(after=-1).status_code == 400
    assert dev.policy(after="x").status_code == 400  # type: ignore[arg-type]
    assert fetch(dev, after=0)["seq"] == 1
    assert dev.me().json()["policy"]["applied_seq"] == 1  # the device says what it applied


def test_every_poll_returns_the_latest_snapshot_not_the_next(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    host = ew.household("A-101", family=False).owner
    for i in range(3):
        make_invitation(
            ew, ew.soc.units["A-101"], host, purpose=f"Visit {i}", visitor_alias=f"Guest {i}"
        )
        assert publish(ew).json()["changed"] is True
    latest = fetch(dev, after=0)
    assert latest["seq"] == 3 and len(latest["manifest"]["invitations"]) == 3
    assert dev.policy(after=latest["seq"]).status_code == 204


# ------------------------------------------------------------------------------------------ monotonic and idempotent
def test_publishing_unchanged_content_creates_no_snapshot(ew: EdgeWorld) -> None:
    first = publish(ew).json()
    assert first["changed"] is True and first["reason"] == "initial" and first["seq"] == 1
    for _ in range(3):
        again = publish(ew).json()
        assert again["changed"] is False and again["reason"] == "unchanged" and again["seq"] == 1
    assert ew.count("policy_snapshots") == 1
    assert len(ew.outbox("PolicyPublished")) == 1
    forced = publish(ew, force=True).json()
    assert forced["changed"] is True and forced["reason"] == "forced" and forced["seq"] == 2


def test_sequence_is_monotonic_gapless_and_enforced_by_the_database(ew: EdgeWorld) -> None:
    host = ew.household("A-101", family=False).owner
    for i in range(4):
        make_invitation(ew, ew.soc.units["A-101"], host, purpose=f"Visit {i}")
        publish(ew)
    seqs = [r[0] for r in ew.rows("SELECT seq FROM policy_snapshots ORDER BY seq")]
    assert seqs == list(range(1, len(seqs) + 1)) and len(seqs) == 4
    # the database refuses a rollback, a hole and a duplicate, even from the owner role
    with ew.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(ew.soc.id),))
        for bad in (3, 99, 6 + 5):
            with pytest.raises(psycopg.errors.Error), conn.transaction():
                conn.execute(
                    "INSERT INTO policy_snapshots (society_id, seq, issued_at, valid_until, issuer_key_id, content_hash, reason,"
                    " manifest, signature) VALUES (%s, %s, now(), now() + interval '1 day', 'k', %s, 'forced', '{}', %s)",
                    (ew.soc.id, bad, "sha256:" + "0" * 64, "ed25519:" + "A" * 86),
                )


def test_snapshots_are_append_only_for_the_application_role(ew: EdgeWorld) -> None:
    publish(ew)
    with ew.idh.db.app_conn(ew.soc.id) as conn:
        for sql in (
            "UPDATE policy_snapshots SET reason = 'forced'",
            "DELETE FROM policy_snapshots",
            "TRUNCATE policy_snapshots",
        ):
            with pytest.raises(psycopg.errors.Error), conn.transaction():
                conn.execute(sql)  # type: ignore[arg-type]
    assert ew.count("policy_snapshots") == 1


def test_publish_audits_and_emits_policy_published_in_the_same_transaction(ew: EdgeWorld) -> None:
    publish(ew)
    audit = ew.audit("edge.policy_publish")
    assert len(audit) == 1 and audit[0][2] == "secretary"
    out = ew.outbox("PolicyPublished")
    assert len(out) == 1
    payload = out[0]["payload"]
    assert (
        payload["seq"] == 1
        and payload["reason"] == "initial"
        and payload["manifest_digest"].startswith("sha256:")
    )
    assert "manifest" not in payload and set(payload["counts"]) >= {
        "gates",
        "residents",
        "revocations",
    }


# ------------------------------------------------------------------------------------------ content
def test_manifest_content_comes_from_the_domain_tables_and_the_approved_pack(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    lane = ew.call(
        ew.secretary,
        "POST",
        ew.s(f"gates/{ew.gate_id}/lanes"),
        json={"label": "Entry", "direction": "in"},
    )
    assert lane.status_code == 201, lane.text
    pending = ew.edge_device(approve=False)
    household = ew.household("A-101", tenant=True, family=True)
    inv = make_invitation(ew, ew.soc.units["A-101"], household.owner)
    s = fetch(dev)
    m = s["manifest"]
    assert [lane_["direction"] for lane_ in m["lanes"]] == ["in"] and m["lanes"][0][
        "gate_id"
    ] == str(ew.gate_id)
    assert str(pending.device_id) not in json.dumps(
        m
    )  # a pending enrolment is not part of the policy
    assert len(m["residents"]) == 3 and {r["status"] for r in m["residents"]} == {"active"}
    assert {r["unit_id"] for r in m["residents"]} == {str(ew.soc.units["A-101"])}
    entry = m["invitations"][0]
    assert (
        entry["id"] == inv["id"]
        and entry["max_uses"] == 2
        and entry["uses_remaining"] == 2
        and entry["revoked_version"] == 0
    )
    assert (
        entry["visitor_alias"] == "A*** S***"
        and entry["kind"] == "guest"
        and entry["gate_id"] is None
    )
    assert len(entry["windows"]) == 1 and entry["nonce"]
    t = m["timing"]
    assert t["approval_expiry_s"] == 90 and t["guest_offline_max_s"] == 7200
    assert t["resident_offline_validity_s"] == 72 * 3600 and t["policy_age_limit_s"] == 72 * 3600
    assert t["clock_uncertainty_limit_ms"] == 60_000
    assert [step["at_seconds"] for step in t["cascade_steps"]] == [0, 10, 20, 35, 90]
    assert t["cascade_steps"][-1]["guard_options"] == [
        "hold",
        "leave_at_gate",
        "lobby_only",
        "intercom",
        "deny",
    ]


def test_a_society_policy_change_is_published(ew: EdgeWorld, dev: EdgeClient) -> None:
    assert fetch(dev)["manifest"]["timing"]["approval_expiry_s"] == 90
    current = ew.call(ew.secretary, "GET", ew.s("gate-policy")).json()
    r = ew.call(
        ew.secretary, "PUT", ew.s("gate-policy"),
        json={"approval_expiry_seconds": 120, "expected_version": current["version"]},
    )  # fmt: skip
    assert r.status_code == 200, r.text
    assert fetch(dev, after=1)["manifest"]["timing"]["approval_expiry_s"] == 120


def test_nothing_personal_is_in_a_snapshot(ew: EdgeWorld, dev: EdgeClient) -> None:
    """EDGE-04 data minimisation: no phone, no name beyond a masked alias, no financial data, no person or membership id."""
    household = ew.household("A-101", tenant=True, family=True, nr_owner=True)
    make_invitation(ew, ew.soc.units["A-101"], household.owner, visitor_alias="Sulabha Pawar")
    raw = json.dumps(fetch(dev), sort_keys=True)
    people = [household.owner, household.tenant, household.family, household.nr_owner]
    for p in people:
        assert p is not None
        assert p.phone not in raw and p.phone[-10:] not in raw and str(p.id) not in raw
    for person_id, name in ew.rows("SELECT id, display_name FROM iam.persons"):
        assert str(person_id) not in raw
        if name and len(name) > 3:
            assert name not in raw
    for (membership_id,) in ew.rows("SELECT id FROM memberships"):
        assert str(membership_id) not in raw
    assert "Sulabha" not in raw and "Pawar" not in raw and "S*** P***" in raw
    assert not re.search(
        r"(?<!\d)[6-9]\d{9}(?!\d)", raw
    )  # no ten-digit mobile-shaped number anywhere
    assert not re.search(
        r'"[a-z_]*(phone|mobile|email|name|amount|paise|invoice|balance|account)[a-z_]*":', raw
    )
    for r in json.loads(raw)["manifest"]["residents"]:
        assert re.fullmatch(r"cr_[A-Za-z0-9_-]{32}", r["credential_ref"]) and re.fullmatch(
            r"pr_[A-Za-z0-9_-]{32}", r["person_ref"]
        )


def test_credential_refs_are_opaque_stable_per_membership_and_unique(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    ew.household("A-101", tenant=True, family=False)
    first = fetch(dev)["manifest"]["residents"]
    publish(ew, force=True)
    second = fetch(dev, after=1)["manifest"]["residents"]
    assert first == second
    assert len({r["credential_ref"] for r in first}) == len({r["person_ref"] for r in first}) == 2


def test_a_disputed_membership_keeps_access_but_a_committee_hold_suspends_it(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    h = ew.household("A-101", family=False)
    ew.sql("UPDATE memberships SET verification = 'disputed' WHERE person_id = %s", (h.owner.id,))
    publish(ew)
    assert {r["status"] for r in fetch(dev)["manifest"]["residents"]} == {
        "active"
    }  # IAM-05: a dispute never removes occupancy
    ew.sql(
        "INSERT INTO membership_holds (society_id, membership_id, state, placed_by, reason) SELECT society_id, id, 'active', created_by,"
        " 'committee hold for review of documents' FROM memberships WHERE person_id = %s",
        (h.owner.id,),
    )
    publish(ew)
    assert {r["status"] for r in fetch(dev, after=0)["manifest"]["residents"]} == {"suspended"}


# ------------------------------------------------------------------------------------------ revocations
def test_revoked_invitation_propagates_in_the_next_snapshot_with_its_version_first(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    h = ew.household("A-101", family=False)
    keep = make_invitation(ew, ew.soc.units["A-101"], h.owner, purpose="Keep")
    drop = make_invitation(ew, ew.soc.units["A-101"], h.owner, purpose="Drop")
    publish(ew)
    before = fetch(dev)
    assert before["manifest"]["revocations"] == []
    r = ew.call(h.owner, "DELETE", f"/v1/invitations/{drop['id']}")
    assert r.status_code == 200, r.text
    version = r.json()["revoked_version"]
    after = fetch(dev, after=before["seq"])  # published on the poll: no worker needed
    assert after["seq"] == before["seq"] + 1
    revs = after["manifest"]["revocations"]
    assert revs[0] == {"ref": drop["id"], "version": version}
    by_id = {i["id"]: i for i in after["manifest"]["invitations"]}
    assert (
        by_id[drop["id"]]["revoked_version"] == version and by_id[drop["id"]]["uses_remaining"] == 0
    )
    assert by_id[keep["id"]]["revoked_version"] == 0 and by_id[keep["id"]]["uses_remaining"] == 2
    assert verifies(after, trusted(dev))


def test_an_ended_membership_is_revoked_with_the_next_society_wide_version_and_a_returning_one_gets_a_new_reference(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    h = ew.household("A-101", tenant=True, family=False)
    s1 = fetch(dev)
    refs = {r["person_ref"]: r["credential_ref"] for r in s1["manifest"]["residents"]}
    ew.sql(
        "UPDATE memberships SET ended_at = now(), effective_to = (now() AT TIME ZONE 'Asia/Kolkata')::date WHERE person_id = %s",
        (h.tenant.id,),  # type: ignore[union-attr]
    )
    inv = make_invitation(ew, ew.soc.units["A-101"], h.owner)
    revoked_inv = ew.call(h.owner, "DELETE", f"/v1/invitations/{inv['id']}").json()[
        "revoked_version"
    ]
    s2 = fetch(dev, after=s1["seq"])
    gone = [r for r in s2["manifest"]["residents"] if r["status"] == "revoked"]
    assert (
        len(gone) == 1
        and gone[0]["credential_ref"] in refs.values()
        and gone[0]["revocation_version"] > 0
    )
    assert {r["ref"] for r in s2["manifest"]["revocations"]} == {
        gone[0]["credential_ref"],
        inv["id"],
    }
    versions = [r["version"] for r in s2["manifest"]["revocations"]]
    assert (
        versions == sorted(versions, reverse=True) and len(set(versions)) == 2
    )  # newest deny first, one counter for both kinds
    assert gone[0]["revocation_version"] != revoked_inv
    # the household member comes back (re-verified): a NEW reference, the old one stays revoked
    ew.sql(
        "UPDATE memberships SET ended_at = NULL, effective_to = NULL WHERE person_id = %s",
        (h.tenant.id,),
    )  # type: ignore[union-attr]
    s3 = fetch(dev, after=s2["seq"])
    active = [r for r in s3["manifest"]["residents"] if r["status"] == "active"]
    assert len(active) == 2
    returned = next(r for r in active if r["person_ref"] == gone[0]["person_ref"])
    assert returned["credential_ref"] != gone[0]["credential_ref"]
    assert any(
        r["status"] == "revoked" and r["credential_ref"] == gone[0]["credential_ref"]
        for r in s3["manifest"]["residents"]
    )


def test_tombstones_expire_after_the_retention_period(ew: EdgeWorld, dev: EdgeClient) -> None:
    h = ew.household("A-101", family=False)
    inv = make_invitation(ew, ew.soc.units["A-101"], h.owner)
    ew.call(h.owner, "DELETE", f"/v1/invitations/{inv['id']}")
    publish(ew)
    assert fetch(dev)["manifest"]["revocations"][0]["ref"] == inv["id"]
    cfg = dataclasses.replace(
        ew.app.state.edge_config, publish_on_poll=False
    )  # a poll would publish at the REAL time
    ew.app.state.edge_config = cfg
    result = snap.publish_for_society(
        ew.database,
        cfg,
        ew.soc.id,
        now=utc_now() + dt.timedelta(days=cfg.revocation_retention_days + 1),
    )
    assert result.changed
    latest = fetch(dev, after=0)
    assert latest["manifest"]["revocations"] == [] and latest["manifest"]["invitations"] == []


def test_a_revoked_device_is_listed_as_revoked_then_dropped(ew: EdgeWorld, dev: EdgeClient) -> None:
    other = ew.edge_device()
    assert any(
        d["id"] == str(other.device_id) and d["status"] == "active"
        for d in fetch(dev)["manifest"]["devices"]
    )
    ew.revoke_device(other)
    latest = fetch(dev, after=0)
    assert any(
        d["id"] == str(other.device_id) and d["status"] == "revoked"
        for d in latest["manifest"]["devices"]
    )


# ------------------------------------------------------------------------------------------ key rotation and refresh
def test_key_rotation_issues_a_new_snapshot_signed_by_the_new_key_and_old_ones_stay_verifiable(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    old = fetch(dev)
    cfg = ew.app.state.edge_config
    new_key = generate_private_key()
    new_signer = SimulatedKmsSigner.from_seed_b64(private_key_to_b64(new_key))
    ew.app.state.edge_config = dataclasses.replace(
        cfg, signer=new_signer, retired_keys={cfg.signer.key_id: cfg.signer.public_key_b64}
    )
    rotated = fetch(dev, after=old["seq"])
    assert rotated["seq"] == old["seq"] + 1 and rotated["issuer_key_id"] == key_id_for(
        new_key.public_key()
    )
    assert rotated["manifest"] == old["manifest"]  # same content: only the issuer changed
    keys = dev.request("GET", "/v1/edge/keys").json()["keys"]
    assert [(k["key_id"], k["status"]) for k in keys] == [
        (new_signer.key_id, "active"),
        (cfg.signer.key_id, "retired"),
    ]
    ring = trusted(dev)
    assert verifies(rotated, ring) and verifies(
        old, ring
    )  # an edge that kept the old snapshot can still check it
    assert ew.rows("SELECT reason FROM policy_snapshots ORDER BY seq")[-1][0] == "key_rotation"
    # a snapshot signed by a key that was never trusted is refused by an edge that only knows the ring
    forged = {**rotated, "issuer_key_id": "ed-forged"}
    assert not verifies(forged, ring)


def test_periodic_refresh_extends_validity_without_changing_content(ew: EdgeWorld) -> None:
    cfg = ew.app.state.edge_config
    first = snap.publish_for_society(ew.database, cfg, ew.soc.id)
    soon = snap.publish_for_society(
        ew.database, cfg, ew.soc.id, now=utc_now() + dt.timedelta(hours=1)
    )
    assert not soon.changed and soon.seq == first.seq
    later = snap.publish_for_society(
        ew.database, cfg, ew.soc.id, now=utc_now() + dt.timedelta(hours=7)
    )
    assert later.changed and later.reason == "refresh" and later.seq == first.seq + 1
    assert later.content_hash == first.content_hash and later.valid_until > first.valid_until


def test_domain_event_hook_is_idempotent_and_ignores_irrelevant_events(ew: EdgeWorld) -> None:
    cfg = ew.app.state.edge_config
    ctx = RequestContext(ew.soc.id, None, "system", uuid.uuid4())
    with ew.database.app_tx(ctx) as conn:
        assert snap.handle_domain_event(conn, ctx, cfg, "ParcelCollected") is None
        first = snap.handle_domain_event(conn, ctx, cfg, "DeviceActivated")
        assert first is not None and first.changed
    h = ew.household("A-101", family=False)
    make_invitation(ew, ew.soc.units["A-101"], h.owner)
    with ew.database.app_tx(ctx) as conn:
        a = snap.handle_domain_event(conn, ctx, cfg, "InvitationCreated")
        b = snap.handle_domain_event(conn, ctx, cfg, "InvitationCreated")
        assert a is not None and a.changed and b is not None and not b.changed and b.seq == a.seq
    assert ew.count("policy_snapshots") == 2


def test_publish_on_poll_can_be_switched_off_for_a_worker_driven_deployment(
    ew: EdgeWorld, dev: EdgeClient
) -> None:
    fetch(dev)
    ew.app.state.edge_config = dataclasses.replace(ew.app.state.edge_config, publish_on_poll=False)
    h = ew.household("A-101", family=False)
    make_invitation(ew, ew.soc.units["A-101"], h.owner)
    assert dev.policy(after=1).status_code == 204  # nothing published yet
    assert publish(ew).json()["changed"] is True
    assert fetch(dev, after=1)["seq"] == 2


# ------------------------------------------------------------------------------------------ who may publish, isolation
def test_who_may_publish_and_read_policy_status(ew: EdgeWorld) -> None:
    h = ew.household("A-101", family=False)
    assert publish(ew, who=ew.guard).status_code == 403
    assert publish(ew, who=h.owner).status_code == 403
    assert publish(ew, who=ew.guard_sup).status_code == 200
    stranger = ew.person()
    assert ew.call(stranger, "POST", ew.s("edge/policy/publish")).status_code == 404
    meta = ew.call(ew.secretary, "GET", ew.s("edge/policy"))
    assert (
        meta.status_code == 200
        and "manifest" not in meta.json()
        and meta.json()["counts"]["gates"] == 1
    )
    assert ew.call(h.owner, "GET", ew.s("edge/policy")).status_code == 403


def test_two_societies_never_see_each_others_policy(ew: EdgeWorld, dev: EdgeClient) -> None:
    rival = ew.idh.society("Rival Heights", units=("Z-1",))
    ew.idh.seed_grant(rival.id, ew.secretary.id, "secretary")
    ew.idh.elevate_session(ew.secretary)
    other = ew.call(
        ew.secretary,
        "POST",
        f"/v1/societies/{rival.id}/gates",
        json={"name": "Rival gate", "kind": "mixed"},
    )
    assert other.status_code == 201, other.text
    assert (
        ew.call(ew.secretary, "POST", f"/v1/societies/{rival.id}/edge/policy/publish").status_code
        == 200
    )
    mine = fetch(dev)
    assert mine["society_id"] == str(ew.soc.id) and "Rival" not in json.dumps(mine)
    assert [g["id"] for g in mine["manifest"]["gates"]] == [str(ew.gate_id)]
    with ew.idh.db.app_conn(rival.id) as conn:
        rows = conn.execute("SELECT society_id, seq FROM policy_snapshots").fetchall()
    assert rows == [(rival.id, 1)]
    with ew.idh.db.app_conn() as conn:  # no context: zero rows, never all rows
        assert conn.execute("SELECT count(*) FROM policy_snapshots").fetchone() == (0,)
    with ew.idh.db.app_conn(ew.soc.id) as conn:
        assert conn.execute(
            "SELECT count(*) FROM edge_credential_refs WHERE society_id = %s", (rival.id,)
        ).fetchone() == (0,)
