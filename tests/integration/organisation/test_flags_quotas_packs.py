"""ARCH-05 flags and budgets, INV-10 pack loading, migration guards for this module's tables."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text

from dwaar_api.modules.organisation.packs import PackLoadError, load_packs
from tests._harness.pgfixtures import DbHandle
from tests.integration.organisation._support import (
    AUDITOR,
    COMMITTEE,
    GUARD,
    SECRETARY,
    TREASURER,
    OrgHarness,
)


@pytest.fixture
def soc(org: OrgHarness) -> uuid.UUID:
    sid = uuid.UUID(org.create_society()["id"])
    org.seed_staff(sid)
    return sid


@pytest.mark.req("ARCH-05")
def test_feature_flags_are_per_society_and_versioned(org: OrgHarness, soc: uuid.UUID) -> None:
    other = uuid.UUID(org.create_society("Other")["id"])
    path = f"/v1/societies/{soc}/feature-flags/ai_assistant"
    on = org.call("PUT", path, SECRETARY, json={"enabled": True})
    assert on.status_code == 200 and on.json() == {
        **on.json(),
        "flag_key": "ai_assistant",
        "enabled": True,
        "version": 1,
    }
    off = org.call("PUT", path, SECRETARY, json={"enabled": False, "expected_version": 1})
    assert off.status_code == 200 and off.json()["version"] == 2 and off.json()["enabled"] is False
    stale = org.call("PUT", path, SECRETARY, json={"enabled": True, "expected_version": 1})
    assert stale.status_code == 409 and stale.json()["code"] == "stale_version"
    flags = org.call("GET", f"/v1/societies/{soc}/feature-flags", AUDITOR).json()["items"]
    assert {f["flag_key"] for f in flags} == {"ai_assistant", "binding_governance"}
    assert org.rows(other, "SELECT flag_key FROM society_feature_flags") == [
        ("binding_governance",)
    ]
    for bad in ("Bad-Key", "1abc", "x"):
        assert org.call(
            "PUT", f"/v1/societies/{soc}/feature-flags/{bad}", SECRETARY, json={"enabled": True}
        ).status_code in (400, 404)
    for person in (TREASURER, COMMITTEE, GUARD, AUDITOR):
        assert org.call("PUT", path, person, json={"enabled": True}).status_code == 403
    events = org.rows(
        soc,
        "SELECT aggregate_version FROM outbox WHERE event_type = 'FeatureFlagChanged' ORDER BY 1",
    )
    assert events == [(1,), (2,)]


@pytest.mark.req("ARCH-05")
def test_quotas_per_society(org: OrgHarness, soc: uuid.UUID) -> None:
    default = org.call("GET", f"/v1/societies/{soc}/quotas", COMMITTEE).json()
    assert (default["rate_per_minute"], default["rate_burst"], default["ai_requests_per_day"]) == (
        600,
        120,
        0,
    )
    ok = org.call(
        "PUT",
        f"/v1/societies/{soc}/quotas",
        SECRETARY,
        json={"rate_per_minute": 300, "ai_requests_per_day": 50},
    )
    assert (
        ok.status_code == 200 and ok.json()["rate_per_minute"] == 300 and ok.json()["version"] == 2
    )
    stale = org.call(
        "PUT",
        f"/v1/societies/{soc}/quotas",
        SECRETARY,
        json={"expected_version": 1, "queue_quota": 5},
    )
    assert stale.status_code == 409
    bad = org.call("PUT", f"/v1/societies/{soc}/quotas", SECRETARY, json={"rate_per_minute": 0})
    assert bad.status_code == 400
    burst = org.call("PUT", f"/v1/societies/{soc}/quotas", SECRETARY, json={"rate_burst": 5000})
    assert burst.status_code == 422
    assert (
        org.call(
            "PUT", f"/v1/societies/{soc}/quotas", TREASURER, json={"queue_quota": 1}
        ).status_code
        == 403
    )
    assert org.call("GET", f"/v1/societies/{soc}/quotas", GUARD).status_code == 403
    ai = org.call(
        "PATCH",
        f"/v1/societies/{soc}",
        SECRETARY,
        json={"expected_version": 1, "ai_budget_paise": 500000},
    )
    assert ai.status_code == 200 and ai.json()["ai_budget_paise"] == 500000
    neg = org.call(
        "PATCH",
        f"/v1/societies/{soc}",
        SECRETARY,
        json={"expected_version": 2, "ai_budget_paise": -1},
    )
    assert neg.status_code == 400


def _engine(db: DbHandle):  # type: ignore[no-untyped-def]
    return create_engine(db.owner_dsn.replace("postgresql://", "postgresql+psycopg://", 1))


@pytest.mark.req("INV-10", "GOV-01", "SOC-01")
def test_shipped_packs_load_from_files_unapproved_and_reload_is_a_noop(org: OrgHarness) -> None:
    engine = _engine(org.db)
    try:
        with engine.begin() as conn:
            report = load_packs(conn)
            assert (
                report.legal_inserted == 0
                and report.legal_updated == 0
                and report.legal_unchanged >= 5
            )
            assert report.tax_inserted == 0 and report.tax_unchanged >= 3
            rows = conn.execute(
                text(
                    "SELECT pack_key, pack_status, approved_by FROM legal_packs WHERE pack_key <> 'test-approved-chs'"
                )
            ).all()
            keys = {r[0] for r in rows}
            assert {
                "maharashtra-chs",
                "generic",
                "karnataka-aoa-1972",
                "haryana-group-housing",
            } <= keys
            assert all(r[1] != "approved" and r[2] is None for r in rows)  # nothing ships approved
            assert (
                conn.execute(
                    text("SELECT count(*) FROM legal_packs WHERE pack_key = 'maharashtra-chs'")
                ).scalar_one()
                == 1
            )
            rules = conn.execute(
                text("SELECT rules FROM legal_packs WHERE pack_key = 'maharashtra-chs'")
            ).scalar_one()
            assert rules  # values come from the file, not from SQL
    finally:
        engine.dispose()


@pytest.mark.req("INV-10", "GOV-01")
def test_approved_pack_content_is_immutable_and_changed_draft_updates(org: OrgHarness) -> None:
    engine = _engine(org.db)
    try:
        with engine.begin() as conn:
            conn.execute(
                text("UPDATE legal_packs SET content_hash = :h WHERE pack_key = 'generic'"),
                {"h": "sha256:" + "1" * 64},
            )
            report = load_packs(
                conn
            )  # the stored unapproved draft differs from the file: refreshed in place
            assert report.legal_updated == 1
            assert (
                conn.execute(
                    text("SELECT version_no FROM legal_packs WHERE pack_key = 'generic'")
                ).scalar_one()
                == 2
            )
        with pytest.raises(PackLoadError), engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE legal_packs SET pack_status = 'approved', approved_by = 'Counsel (fixture)', approved_at = now(),"
                    " content_hash = :h WHERE pack_key = 'generic'"
                ),
                {"h": "sha256:" + "2" * 64},
            )
            load_packs(conn)
    finally:
        engine.dispose()


@pytest.mark.req("GOV-01")
def test_database_refuses_approval_without_evidence(org: OrgHarness) -> None:
    from psycopg import errors

    with pytest.raises(errors.CheckViolation), org.db.owner_conn() as conn:
        conn.execute(
            "UPDATE legal_packs SET pack_status = 'approved' WHERE pack_key = 'maharashtra-chs'"
        )  # type: ignore[call-overload]
    with pytest.raises(errors.CheckViolation), org.db.owner_conn() as conn:
        conn.execute(
            "UPDATE legal_packs SET approved_by = 'Someone' WHERE pack_key = 'maharashtra-chs'"
        )  # type: ignore[call-overload]


@pytest.mark.req("ARCH-01", "ARCH-03", "DB-02")
def test_every_organisation_table_is_rls_forced_with_society_policy(org: OrgHarness) -> None:
    society_tables = {
        "societies",
        "legal_entities",
        "blocks",
        "units",
        "society_feature_flags",
        "society_quotas",
    }
    with org.db.admin_conn() as conn:
        rows = conn.execute(  # type: ignore[call-overload]
            "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,"
            " (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid"
            "   AND pg_get_expr(p.polqual, p.polrelid) LIKE '%%app.society_id%%')"
            " FROM pg_class c WHERE c.relname = ANY(%s) AND c.relkind = 'r'",
            (sorted(society_tables),),
        ).fetchall()
        assert {r[0] for r in rows} == society_tables
        assert all(r[1] and r[2] and r[3] >= 1 for r in rows), rows
        # global tables: no privileges for the runtime roles at all
        for table in ("orgs", "legal_packs", "tax_packs"):
            privs = conn.execute(  # type: ignore[call-overload]
                "SELECT has_table_privilege('dwaar_app', %s, 'SELECT, INSERT, UPDATE, DELETE'),"
                " has_table_privilege('dwaar_worker', %s, 'SELECT, INSERT, UPDATE, DELETE')",
                (table, table),
            ).fetchone()
            assert privs == (False, False)
        # the composite cross-society guards exist
        names = {
            r[0]
            for r in conn.execute(
                "SELECT conname FROM pg_constraint WHERE contype = 'f'"
            ).fetchall()  # type: ignore[call-overload]
        }
        assert {"units_block_fk", "societies_legal_entity_fk"} <= names
