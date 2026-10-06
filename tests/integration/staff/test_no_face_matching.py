"""STAFF-05: check-in by code or card ONLY. Face matching is excluded from M1 to M3: there is no such field, column, route or credential kind.

REQ: STAFF-05, PRIV-04, PRIV-05, PRD 11.5.

This is a tripwire: it fails the day someone adds a face, selfie, embedding or biometric surface to the staff, attendance or parcels API, in the
schema, in a request model, in the OpenAPI document or in a route. Reconsidering face matching needs legal review first (PRD 11.5).
"""

from __future__ import annotations

import pytest

from dwaar_api.modules.staff import schemas
from tests.integration.parcels._support import PW

pytestmark = [pytest.mark.req("STAFF-05", "PRIV-04")]
FORBIDDEN = (
    "face",
    "facial",
    "biometric",
    "embedding",
    "faceprint",
    "selfie",
    "liveness",
    "template_vector",
    "match_score",
    "fingerprint",
    "iris",
)


def test_no_table_or_column_of_the_staff_attendance_or_parcels_schema_mentions_a_face_or_biometric(
    pw: PW,
) -> None:
    tables = (
        "staff",
        "staff_consents",
        "staff_engagements",
        "attendance_events",
        "attendance_corrections",
        "payroll_adjustments",
        "parcels",
        "custody_transfers",
    )
    cols = pw.rows(
        "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = ANY(%s)",
        (list(tables),),
    )
    assert cols
    assert not [c for c in cols if any(w in c[1].lower() for w in FORBIDDEN)], cols
    names = pw.rows(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
    )
    assert not [n for n in names if any(w in n[0].lower() for w in FORBIDDEN)]


def _names(node: object, out: set[str]) -> set[str]:
    """Property names and enum values of an OpenAPI document (descriptions are prose and may legitimately say 'no face matching')."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                out.update(str(k).lower() for k in value)
            if key == "enum" and isinstance(value, list):
                out.update(str(v).lower() for v in value)
            _names(value, out)
    elif isinstance(node, list):
        for item in node:
            _names(item, out)
    return out


def test_no_route_or_openapi_property_offers_face_matching(pw: PW) -> None:
    assert not [
        p for p in pw.route_paths() if any(w in p.lower() for w in (*FORBIDDEN, "match"))
    ], pw.route_paths()
    spec = pw.vw.client.get("/openapi.json").json()
    names = _names(spec, set()) | {p.lower() for p in spec["paths"]}
    assert "attendance_events" not in names and len(names) > 50
    assert not [n for n in names if any(w in n for w in FORBIDDEN)], sorted(
        n for n in names if any(w in n for w in FORBIDDEN)
    )


def test_no_request_model_has_a_face_biometric_or_selfie_field() -> None:
    for name in dir(schemas):
        model = getattr(schemas, name)
        fields = getattr(model, "model_fields", None)
        if not fields:
            continue
        assert not [f for f in fields if any(w in f.lower() for w in FORBIDDEN)], (
            name,
            list(fields),
        )


def test_the_api_rejects_face_credentials_and_face_fields(pw: PW) -> None:
    c = pw.consent()
    staff = pw.register_staff(consent=c)
    for kind in ("face", "biometric", "selfie", "fingerprint"):
        r = pw.call(
            pw.secretary,
            "POST",
            f"/v1/staff/{staff['id']}/credentials",
            json={"kind": kind, "expected_version": staff["version"]},
        )
        assert r.status_code == 400, kind
    for field in ("face_template", "face_embedding", "selfie_ref", "biometric_hash"):
        r = pw.call(
            pw.secretary,
            "PATCH",
            f"/v1/staff/{staff['id']}",
            json={"expected_version": staff["version"], field: "x"},
        )
        assert r.status_code == 400, field
        r = pw.call(
            pw.secretary,
            "POST",
            "/v1/staff",
            json={
                "consent_id": c["id"],
                "display_name": "X",
                "phone": "+919999980777",
                "staff_type": "cook",
                field: "x",
            },
        )
        assert r.status_code == 400, field
    for kind in ("face", "biometric"):
        r = pw.call(
            pw.guard,
            "POST",
            "/v1/attendance",
            json={
                "credential": {"kind": kind, "value": "abcd1234"},
                "direction": "in",
                "client_event_id": "00000000-0000-4000-8000-000000000001",
            },
        )
        assert r.status_code == 400, kind
    r = pw.call(
        pw.guard,
        "POST",
        "/v1/attendance",
        json={
            "credential": {"kind": "code", "value": "abcd1234"},
            "direction": "in",
            "client_event_id": "00000000-0000-4000-8000-000000000002",
            "face_image": "x",
        },
    )
    assert r.status_code == 400


def test_the_only_check_in_credentials_are_code_and_card(pw: PW) -> None:
    allowed = schemas.CredentialIssue.model_fields["kind"].annotation
    assert set(allowed.__args__) == {"code", "card"}  # type: ignore[union-attr]
    assert set(schemas.Credential.model_fields["kind"].annotation.__args__) == {"code", "card"}  # type: ignore[union-attr]
    constraint = pw.rows(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'attendance_events'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%%credential_kind%%'"
    )
    assert constraint and "manual_by_guard" in constraint[0][0] and "face" not in constraint[0][0]
