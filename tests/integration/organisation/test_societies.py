"""SOC-01: society creation, masking of identifiers, pack selection, binding-governance gate, listing."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from dwaar_common.crypto import build_aad
from tests.integration.organisation._support import (
    AUDITOR,
    COMMITTEE,
    ESTATE_MGR,
    FAMILY,
    GUARD,
    ORG_ADMIN,
    OUTSIDER,
    OWNER_NR,
    OWNER_OCC,
    PLATFORM,
    SECRETARY,
    SECRETARY_B,
    TENANT,
    TREASURER,
    OrgHarness,
)

PAN, TAN, GSTIN = "ABCDE1234F", "PUNE12345A", "27ABCDE1234F1Z5"


@pytest.mark.req("SOC-01")
def test_create_society_returns_masked_identifiers_and_stores_ciphertext(org: OrgHarness) -> None:
    soc = org.create_society()
    entity = soc["legal_entity"]
    assert entity["pan_masked"] == "******234F"
    assert entity["tan_masked"] == "******345A"
    assert entity["gstin_masked"] == "***********F1Z5"
    assert entity["gst_registered"] is True
    text = str(soc)
    for secret in (PAN, TAN, GSTIN):
        assert secret not in text
    sid = uuid.UUID(soc["id"])
    row = org.rows(sid, "SELECT id, pan_enc, tan_enc, gstin_enc FROM legal_entities")[0]
    assert all(row[i] and PAN not in row[i] and TAN not in row[i] for i in (1, 2))
    # envelope encryption round-trips with the society/entity-bound AAD, and refuses another society's AAD
    aad = build_aad(sid, "legal_entities", "pan", row[0])
    assert org.cipher.decrypt(row[1], aad) == PAN
    with pytest.raises(Exception):  # noqa: B017, PT011 - any DecryptionError subclass
        org.cipher.decrypt(row[1], build_aad(uuid.uuid4(), "legal_entities", "pan", row[0]))


@pytest.mark.req("SOC-01")
def test_identifiers_never_in_audit_outbox_or_idempotency_rows(org: OrgHarness) -> None:
    soc = org.create_society()
    sid = uuid.UUID(soc["id"])
    audit = org.rows(sid, "SELECT diff_masked::text FROM audit_log WHERE society_id = %s", (sid,))
    outbox = org.rows(sid, "SELECT payload::text FROM outbox WHERE society_id = %s", (sid,))
    blob = " ".join(r[0] for r in audit + outbox)
    assert audit and outbox
    for secret in (PAN, TAN, GSTIN):
        assert secret not in blob


@pytest.mark.req("SOC-01", "ARCH-01")
def test_create_writes_audit_and_outbox_in_same_transaction(org: OrgHarness) -> None:
    soc = org.create_society()
    sid = uuid.UUID(soc["id"])
    audit = org.rows(
        sid,
        "SELECT operation, object_type, object_id, object_version, effective_role, actor_id"
        " FROM audit_log WHERE society_id = %s",
        (sid,),
    )
    assert audit == [("society.create", "society", sid, 1, "platform_admin", PLATFORM)]
    events = org.rows(
        sid,
        "SELECT event_type, aggregate_id, aggregate_version FROM outbox WHERE society_id = %s",
        (sid,),
    )
    assert events == [("SocietyCreated", sid, 1)]
    # defaults (ARCH-05): binding flag exists and is off; quotas row exists
    flags = org.rows(sid, "SELECT flag_key, enabled FROM society_feature_flags")
    assert flags == [("binding_governance", False)]
    assert org.rows(sid, "SELECT count(*) FROM society_quotas") == [(1,)]


@pytest.mark.req("SOC-01", "IAM-13")
def test_only_platform_or_org_admin_can_create(org: OrgHarness) -> None:
    soc = org.create_society()
    sid = uuid.UUID(soc["id"])
    org.seed_staff(sid)
    body = org.society_payload("Beta")
    for person in (SECRETARY, TREASURER, COMMITTEE, GUARD, OUTSIDER):
        resp = org.call("POST", "/v1/societies", person, json=body)
        assert resp.status_code == 403, (person, resp.text)
        assert resp.json()["code"] == "not_authorised"
    assert org.call("POST", "/v1/societies", None, json=body).status_code == 401


@pytest.mark.req("SOC-01")
def test_org_admin_is_limited_to_own_org(org: OrgHarness) -> None:
    with org.db.owner_conn() as conn:
        org1 = conn.execute(
            "INSERT INTO orgs (name, kind) VALUES ('Org One', 'fm') RETURNING id"
        ).fetchone()[0]  # type: ignore[call-overload,index]
        org2 = conn.execute(
            "INSERT INTO orgs (name, kind) VALUES ('Org Two', 'builder') RETURNING id"
        ).fetchone()[0]  # type: ignore[call-overload,index]
    first = org.create_society("Org One Society", org_id=str(org1))
    org.seeder.grant(ORG_ADMIN, "org_admin", uuid.UUID(first["id"]))
    admin = ORG_ADMIN
    ok = org.call(
        "POST", "/v1/societies", admin, json=org.society_payload("Second", org_id=str(org1))
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["org_id"] == str(org1)
    other = org.call(
        "POST", "/v1/societies", admin, json=org.society_payload("Third", org_id=str(org2))
    )
    assert other.status_code == 403
    no_org = org.call("POST", "/v1/societies", admin, json=org.society_payload("Fourth"))
    assert no_org.status_code == 403
    # platform admin may name any existing org, and an unknown org is a validation error
    assert (
        org.call(
            "POST", "/v1/societies", PLATFORM, json=org.society_payload("Fifth", org_id=str(org2))
        ).status_code
        == 201
    )
    unknown = org.call(
        "POST",
        "/v1/societies",
        PLATFORM,
        json=org.society_payload("Sixth", org_id=str(uuid.uuid4())),
    )
    assert unknown.status_code == 400


@pytest.mark.req("SOC-01")
@pytest.mark.parametrize(
    ("patch", "field"),
    [
        ({"pan": "BAD"}, "legal_entity.pan"),
        ({"tan": "12345"}, "legal_entity.tan"),
        ({"gstin": "27ABCDE1234F1Z"}, "legal_entity.gstin"),
        ({"gstin": GSTIN, "gst_registered": False}, "legal_entity"),
    ],
)
def test_invalid_identifier_formats_are_rejected(
    org: OrgHarness, patch: dict[str, object], field: str
) -> None:
    org.make_platform_admin()
    body = org.society_payload()
    body["legal_entity"].update(patch)
    resp = org.call("POST", "/v1/societies", PLATFORM, json=body)
    assert resp.status_code == 400
    assert resp.json()["code"] == "invalid_schema"
    assert (
        PAN not in resp.text and GSTIN not in resp.text
    )  # validation errors never echo the submitted value


@pytest.mark.req("SOC-01")
def test_identifiers_are_optional_and_body_cannot_name_a_society(org: OrgHarness) -> None:
    org.make_platform_admin()
    body = org.society_payload()
    body["legal_entity"] = {"name": "X Society", "entity_type": "chs", "registration_no": "R-1"}
    del body["tax_pack_id"]
    soc = org.call("POST", "/v1/societies", PLATFORM, json=body).json()
    assert soc["legal_entity"]["pan_masked"] is None
    assert soc["tax_configured"] is False
    smuggled = org.society_payload("Y")
    smuggled["society_id"] = str(uuid.uuid4())
    assert org.call("POST", "/v1/societies", PLATFORM, json=smuggled).status_code == 400


@pytest.mark.req("SOC-01", "GOV-01")
def test_unapproved_legal_pack_leaves_binding_governance_disabled(org: OrgHarness) -> None:
    soc = org.create_society()
    sid = uuid.UUID(soc["id"])
    org.seed_staff(sid)
    assert soc["legal_pack"]["approved"] is False
    assert soc["legal_pack"]["pack_status"] == "unapproved"
    assert soc["binding_governance"] == {
        "enabled": False,
        "blockers": ["legal_pack_not_approved", "feature_flag_disabled"],
    }
    resp = org.call(
        "PUT",
        f"/v1/societies/{sid}/feature-flags/binding_governance",
        SECRETARY,
        json={"enabled": True},
    )
    assert resp.status_code == 422
    assert resp.json()["code"] == "legal_pack_not_approved"
    assert org.rows(
        sid, "SELECT enabled FROM society_feature_flags WHERE flag_key = 'binding_governance'"
    ) == [(False,)]


@pytest.mark.req("SOC-01", "GOV-01")
def test_approved_pack_allows_binding_flag(org: OrgHarness) -> None:
    soc = org.create_society("Approved Society", legal_pack_id=str(org.approved_pack_id))
    sid = uuid.UUID(soc["id"])
    org.seed_staff(sid)
    assert soc["legal_pack"]["approved"] is True
    assert soc["binding_governance"]["blockers"] == ["feature_flag_disabled"]
    resp = org.call(
        "PUT",
        f"/v1/societies/{sid}/feature-flags/binding_governance",
        SECRETARY,
        json={"enabled": True},
    )
    assert resp.status_code == 200, resp.text
    config = org.call("GET", f"/v1/societies/{sid}/configuration", SECRETARY).json()
    assert config["binding_governance"] == {"enabled": True, "blockers": []}


@pytest.mark.req("SOC-01", "INV-10")
def test_pack_selection_rules(org: OrgHarness) -> None:
    org.make_platform_admin()
    with org.db.owner_conn() as conn:
        retired = conn.execute(  # type: ignore[call-overload]
            "INSERT INTO legal_packs (pack_key, jurisdiction, entity_type, version, pack_status, rules, content_hash,"
            " effective_from) VALUES ('old', 'IN-MH', 'chs', '1', 'retired', '{}', %s, DATE '2020-01-01') RETURNING id",
            ("sha256:" + "0" * 64,),
        ).fetchone()[0]
        karnataka = conn.execute(  # type: ignore[call-overload]
            "SELECT id FROM legal_packs WHERE pack_key = 'karnataka-bill-2026-variant'"
        ).fetchone()[0]
    cases = {
        "unknown": (str(uuid.uuid4()), 400),
        "retired": (str(retired), 422),
        "disabled": (str(karnataka), 422),
    }
    for label, (pack_id, status) in cases.items():
        resp = org.call(
            "POST",
            "/v1/societies",
            PLATFORM,
            json=org.society_payload(label, legal_pack_id=pack_id),
        )
        assert resp.status_code == status, (label, resp.text)
    wrong_type = org.society_payload("Wrong")
    wrong_type["legal_entity"]["entity_type"] = "company"
    resp = org.call("POST", "/v1/societies", PLATFORM, json=wrong_type)
    assert resp.status_code == 422
    assert resp.json()["details"]["reason"] == "pack_entity_type_mismatch"
    resp = org.call(
        "POST",
        "/v1/societies",
        PLATFORM,
        json=org.society_payload("TaxBad", tax_pack_id=str(uuid.uuid4())),
    )
    assert resp.status_code == 400


@pytest.mark.req("SOC-01")
def test_get_society_roles_and_non_member_gets_404_identical_to_missing(org: OrgHarness) -> None:
    a = org.create_society("A Society")
    b = org.create_society("B Society")
    sa, sb = uuid.UUID(a["id"]), uuid.UUID(b["id"])
    org.seed_staff(sa)
    org.seeder.grant(SECRETARY_B, "secretary", sb)
    org.seed_residents(sa, uuid.uuid4())
    for person in (
        SECRETARY,
        TREASURER,
        COMMITTEE,
        ESTATE_MGR,
        GUARD,
        AUDITOR,
        OWNER_OCC,
        OWNER_NR,
        TENANT,
        FAMILY,
    ):
        resp = org.call("GET", f"/v1/societies/{sa}", person)
        assert resp.status_code == 200, (person, resp.text)
        assert set(resp.json()) == {
            "request_id",
            "id",
            "name",
            "city",
            "state",
            "timezone",
            "status",
            "version",
        }
    other = org.call("GET", f"/v1/societies/{sb}", SECRETARY)
    missing = org.call("GET", f"/v1/societies/{uuid.uuid4()}", SECRETARY)
    assert other.status_code == missing.status_code == 404
    assert {k: v for k, v in other.json().items() if k != "request_id"} == {
        k: v for k, v in missing.json().items() if k != "request_id"
    }


@pytest.mark.req("SOC-01")
def test_configuration_read_follows_permission_matrix(org: OrgHarness) -> None:
    soc = org.create_society()
    sid = uuid.UUID(soc["id"])
    org.seed_staff(sid)
    org.seed_residents(sid, uuid.uuid4())
    allowed = (SECRETARY, TREASURER, COMMITTEE, ESTATE_MGR, AUDITOR)
    denied = (GUARD, OWNER_OCC, OWNER_NR, TENANT, FAMILY)
    for person in allowed:
        resp = org.call("GET", f"/v1/societies/{sid}/configuration", person)
        assert resp.status_code == 200, (person, resp.text)
        assert resp.json()["legal_entity"]["pan_masked"] == "******234F"
    for person in denied:
        resp = org.call("GET", f"/v1/societies/{sid}/configuration", person)
        assert resp.status_code == 403, (person, resp.text)


@pytest.mark.req("SOC-01", "IAM-08")
def test_configure_is_secretary_only_and_uses_optimistic_versions(org: OrgHarness) -> None:
    soc = org.create_society()
    sid = uuid.UUID(soc["id"])
    org.seed_staff(sid)
    for person in (TREASURER, COMMITTEE, ESTATE_MGR, GUARD, AUDITOR):
        resp = org.call(
            "PATCH", f"/v1/societies/{sid}", person, json={"expected_version": 1, "city": "Mumbai"}
        )
        assert resp.status_code == 403, person
    ok = org.call(
        "PATCH",
        f"/v1/societies/{sid}",
        SECRETARY,
        json={"expected_version": 1, "city": "Mumbai", "settings": {"visitor_photo": False}},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["city"] == "Mumbai" and ok.json()["version"] == 2
    stale = org.call(
        "PATCH", f"/v1/societies/{sid}", SECRETARY, json={"expected_version": 1, "city": "Nagpur"}
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "stale_version"
    bad_tz = org.call(
        "PATCH",
        f"/v1/societies/{sid}",
        SECRETARY,
        json={"expected_version": 2, "timezone": "Mars/Base"},
    )
    assert bad_tz.status_code == 400
    floats = org.call(
        "PATCH",
        f"/v1/societies/{sid}",
        SECRETARY,
        json={"expected_version": 2, "settings": {"x": 1.5}},
    )
    assert floats.status_code == 400
    audit = org.rows(
        sid, "SELECT operation, object_version FROM audit_log WHERE operation = 'society.update'"
    )
    assert audit == [("society.update", 2)]


@pytest.mark.req("SOC-01", "INV-01")
def test_list_societies_shows_only_current_grants_and_paginates(org: OrgHarness) -> None:
    ids = [uuid.UUID(org.create_society(f"Society {i}")["id"]) for i in range(3)]
    person = uuid.UUID("0192f300-0000-7000-8000-0000000000cc")
    for sid in ids[:2]:
        org.seeder.grant(person, "committee", sid)
    org.seeder.grant(person, "secretary", ids[2], expires_at=dt.datetime(2020, 1, 1, tzinfo=dt.UTC))
    full = org.call("GET", "/v1/societies", person).json()
    assert {i["id"] for i in full["items"]} == {str(s) for s in ids[:2]}
    first = org.call("GET", "/v1/societies", person, params={"limit": 1}).json()
    assert len(first["items"]) == 1 and first["next_cursor"]
    second = org.call(
        "GET", "/v1/societies", person, params={"limit": 1, "cursor": first["next_cursor"]}
    ).json()
    assert len(second["items"]) == 1 and second["next_cursor"] is None
    assert {first["items"][0]["id"], second["items"][0]["id"]} == {str(s) for s in ids[:2]}
    assert org.call("GET", "/v1/societies", OUTSIDER).json()["items"] == []
    assert org.call("GET", "/v1/societies", person, params={"limit": 101}).status_code == 400
    # a cursor issued to one person is useless to another
    assert (
        org.call(
            "GET", "/v1/societies", OUTSIDER, params={"cursor": first["next_cursor"]}
        ).status_code
        == 400
    )
