"""SOC-03 (units subset): strict CSV import, all-or-nothing, dry run, duplicate detection."""

from __future__ import annotations

import uuid

import pytest

from tests.integration.organisation._support import (
    COMMITTEE,
    ESTATE_MGR,
    SECRETARY,
    TREASURER,
    OrgHarness,
)

HEADER = "block,label,floor,carpet_area_sqft,builtup_area_sqft,undivided_interest_pct,construction_cost_paise\n"
CSV = {"Content-Type": "text/csv"}


@pytest.fixture
def soc(org: OrgHarness) -> uuid.UUID:
    sid = uuid.UUID(org.create_society()["id"])
    org.seed_staff(sid)
    org.create_block(sid, "A", floors=10)
    org.create_block(sid, "B", floors=10)
    return sid


def post(
    org: OrgHarness,
    soc: uuid.UUID,
    csv: str | bytes,
    key: str,
    person: uuid.UUID = SECRETARY,
    **params: object,
):  # noqa: ANN201
    body = csv if isinstance(csv, bytes) else csv.encode()
    return org.call(
        "POST",
        f"/v1/societies/{soc}/units:import",
        person,
        content=body,
        key=key,
        headers=CSV,
        params={k: str(v).lower() for k, v in params.items()} or None,
    )


def unit_count(org: OrgHarness, soc: uuid.UUID) -> int:
    return int(org.rows(soc, "SELECT count(*) FROM units")[0][0])


@pytest.mark.req("SOC-03", "SOC-02")
def test_valid_import_creates_all_units_with_one_audit_and_one_event(
    org: OrgHarness, soc: uuid.UUID
) -> None:
    csv = (
        HEADER
        + "A,101,1,650.50,780.25,0.125,450000000\nA,102,1,650.50,,0.125,\nB,101,1,700,800,0.2,\n"
    )
    resp = post(org, soc, csv, "import-ok-0001")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["valid"] is True and body["units_created"] == 3 and body["errors"] == []
    assert unit_count(org, soc) == 3  # same label 101 in blocks A and B is fine
    rows = org.rows(
        soc,
        "SELECT label, carpet_area_sqft::text, construction_cost_paise FROM units ORDER BY label, carpet_area_sqft",
    )
    assert ("101", "650.50", 450000000) in rows
    assert org.rows(soc, "SELECT count(*) FROM audit_log WHERE operation = 'unit.import'") == [(1,)]
    events = org.rows(
        soc,
        "SELECT event_type, payload->>'units_created' FROM outbox WHERE event_type = 'UnitsImported'",
    )
    assert events == [("UnitsImported", "3")]


@pytest.mark.req("SOC-03")
def test_dry_run_reports_without_writing(org: OrgHarness, soc: uuid.UUID) -> None:
    ok = post(org, soc, HEADER + "A,101,1,,,,\n", "import-dry-0001", dry_run=True)
    assert ok.status_code == 200 and ok.json()["dry_run"] is True and ok.json()["valid"] is True
    assert ok.json()["units_created"] == 0
    assert unit_count(org, soc) == 0
    assert org.rows(soc, "SELECT count(*) FROM audit_log WHERE operation = 'unit.import'") == [(0,)]
    bad = post(org, soc, HEADER + "A,101,1,,,,\nZ,102,1,,,,\n", "import-dry-0002", dry_run=True)
    assert bad.status_code == 200 and bad.json()["valid"] is False
    assert bad.json()["errors"] == [{"row": 3, "field": "block", "code": "unknown_block"}]


@pytest.mark.req("SOC-03")
def test_one_bad_row_creates_nothing(org: OrgHarness, soc: uuid.UUID) -> None:
    good_rows = "".join(f"A,{n},1,,,,\n" for n in range(100, 150))
    resp = post(org, soc, HEADER + good_rows + "A,999,notafloor,,,,\n", "import-atomic-01")
    assert resp.status_code == 422
    body = resp.json()
    assert (
        body["code"] == "policy_violation"
        and body["details"]["reason"] == "import_validation_failed"
    )
    report = body["details"]["report"]
    assert report["valid"] is False and report["units_created"] == 0
    assert report["errors"] == [{"row": 52, "field": "floor", "code": "invalid_integer"}]
    assert unit_count(org, soc) == 0  # NO partial rows
    assert org.rows(soc, "SELECT count(*) FROM audit_log WHERE operation = 'unit.import'") == [(0,)]
    assert org.rows(soc, "SELECT count(*) FROM outbox WHERE event_type = 'UnitsImported'") == [(0,)]


@pytest.mark.req("SOC-03")
def test_duplicate_detection_in_file_and_against_existing(org: OrgHarness, soc: uuid.UUID) -> None:
    org.create_unit(
        soc, org.rows(soc, "SELECT id FROM blocks WHERE name = 'A'")[0][0].__str__(), "101"
    )
    csv = HEADER + "A,101,1,,,,\nA,201,2,,,,\na, 201 ,2,,,,\nB,101,1,,,,\n"
    resp = post(org, soc, csv, "import-dups-0001", dry_run=True).json()
    errors = {(e["row"], e["code"]) for e in resp["errors"]}
    assert errors == {(2, "already_exists"), (4, "duplicate_in_file")}
    assert next(e for e in resp["errors"] if e["code"] == "duplicate_in_file")["first_row"] == 3
    assert unit_count(org, soc) == 1
    archived = org.rows(soc, "SELECT id FROM units")[0][0]
    org.call("DELETE", f"/v1/societies/{soc}/units/{archived}", SECRETARY)
    again = post(org, soc, HEADER + "A,101,1,,,,\n", "import-dups-0002", dry_run=True).json()
    assert [e["code"] for e in again["errors"]] == [
        "already_exists"
    ]  # archived units keep their label reserved


@pytest.mark.req("SOC-03", "SOC-02")
@pytest.mark.parametrize(
    ("row", "field", "code"),
    [
        ("A,101,1,abc,,,", "carpet_area_sqft", "invalid_number"),
        ("A,101,1,NaN,,,", "carpet_area_sqft", "invalid_number"),
        ("A,101,1,Infinity,,,", "carpet_area_sqft", "invalid_number"),
        ("A,101,1,-5,,,", "carpet_area_sqft", "out_of_range"),
        ("A,101,1,0,,,", "carpet_area_sqft", "out_of_range"),
        ("A,101,1,1.234,,,", "carpet_area_sqft", "too_many_decimals"),
        ("A,101,1,99999999999,,,", "carpet_area_sqft", "too_large"),
        ("A,101,1,900,800,,", "builtup_area_sqft", "builtup_area_below_carpet_area"),
        ("A,101,1,,,101,", "undivided_interest_pct", "out_of_range"),
        ("A,101,1,,,0.1234567,", "undivided_interest_pct", "too_many_decimals"),
        ("A,101,1,,,,1.5", "construction_cost_paise", "invalid_integer_paise"),
        ("A,101,1,,,,-1", "construction_cost_paise", "invalid_integer_paise"),
        ("A,101,11,,,,", "floor", "floor_exceeds_block_floors"),
        ("A,101,400,,,,", "floor", "out_of_range"),
        ("A,=cmd|' /C calc'!A0,1,,,,", "label", "unsafe_cell"),
        ("@SUM(1),101,1,,,,", "block", "unsafe_cell"),
        ("A,,1,,,,", "label", "required"),
        ("A," + "x" * 41 + ",1,,,,", "label", "too_long"),
        ("A,101,1,,,", "row", "column_count"),
    ],
)
def test_cell_validation(org: OrgHarness, soc: uuid.UUID, row: str, field: str, code: str) -> None:
    resp = post(org, soc, HEADER + row + "\n", "import-cell-0001", dry_run=True).json()
    assert resp["valid"] is False
    assert {"row": 2, "field": field, "code": code} in resp["errors"], resp["errors"]


@pytest.mark.req("SOC-03")
@pytest.mark.parametrize(
    ("csv", "expected"),
    [
        (
            "\n",
            [{"row": 1, "field": f, "code": "missing_column"} for f in ("block", "label", "floor")],
        ),
        ("block,label\nA,1\n", [{"row": 1, "field": "floor", "code": "missing_column"}]),
        (
            "block,label,floor,owner_phone\nA,1,1,x\n",
            [{"row": 1, "field": "owner_phone", "code": "unknown_column"}],
        ),
        (
            "block,label,floor,floor\nA,1,1,1\n",
            [{"row": 1, "field": "floor", "code": "duplicate_column"}],
        ),
    ],
)
def test_header_errors(
    org: OrgHarness, soc: uuid.UUID, csv: str, expected: list[dict[str, object]]
) -> None:
    resp = post(org, soc, csv, "import-head-0001", dry_run=True).json()
    assert resp["errors"] == expected


@pytest.mark.req("SOC-03")
def test_file_level_rejections(org: OrgHarness, soc: uuid.UUID) -> None:
    empty = post(org, soc, b"", "import-empty-0001", dry_run=True)
    assert empty.status_code == 400 and empty.json()["code"] == "invalid_schema"
    not_utf8 = post(
        org, soc, b"block,label,floor\n\xff\xfe,1,1\n", "import-enc-0001", dry_run=True
    ).json()
    assert not_utf8["errors"] == [{"row": 0, "field": "file", "code": "not_utf8"}]
    nul = post(org, soc, b"block,label,floor\nA,1\x00,1\n", "import-enc-0002", dry_run=True).json()
    assert nul["errors"] == [{"row": 0, "field": "file", "code": "nul_byte"}]
    many = HEADER.encode() + b"".join(b"A,%d,1,,,,\n" % n for n in range(5001))
    too_many = post(org, soc, many, "import-many-0001", dry_run=True).json()
    assert too_many["errors"] == [{"row": 0, "field": "file", "code": "too_many_rows"}]
    bom = post(
        org, soc, b"\xef\xbb\xbf" + (HEADER + "A,500,1,,,,\n").encode(), "import-bom-00001"
    ).json()
    assert bom["valid"] is True and bom["units_created"] == 1
    crlf = post(
        org, soc, "block,label,floor\r\nA,501,1\r\n\r\nA,502,2\r\n", "import-crlf-0001"
    ).json()
    assert crlf["units_created"] == 2


@pytest.mark.req("SOC-03")
def test_interest_total_must_not_exceed_100(org: OrgHarness, soc: uuid.UUID) -> None:
    csv = HEADER + "A,1,1,,,60,\nA,2,1,,,40.000001,\n"
    resp = post(org, soc, csv, "import-pct-00001", dry_run=True).json()
    assert resp["errors"] == [
        {
            "row": 0,
            "field": "undivided_interest_pct",
            "code": "undivided_interest_total_exceeds_100",
        }
    ]
    assert (
        post(org, soc, HEADER + "A,1,1,,,60,\nA,2,1,,,40,\n", "import-pct-00002").status_code == 200
    )
    assert (
        post(org, soc, HEADER + "A,3,1,,,0.5,\n", "import-pct-00003", dry_run=True).json()["valid"]
        is False
    )


@pytest.mark.req("SOC-03")
def test_create_missing_blocks_option(org: OrgHarness, soc: uuid.UUID) -> None:
    csv = HEADER + "Tower C,101,3,,,,\nTower C,102,7,,,,\nA,101,1,,,,\n"
    refused = post(org, soc, csv, "import-blk-00001", dry_run=True).json()
    assert refused["errors"] == [
        {"row": 2, "field": "block", "code": "unknown_block"},
        {"row": 3, "field": "block", "code": "unknown_block"},
    ]
    resp = post(org, soc, csv, "import-blk-00002", create_missing_blocks=True)
    assert resp.status_code == 200 and resp.json()["blocks_created"] == ["Tower C"]
    assert org.rows(soc, "SELECT name, floors FROM blocks WHERE name = 'Tower C'") == [
        ("Tower C", 7)
    ]
    assert unit_count(org, soc) == 3


@pytest.mark.req("SOC-03", "IAM-08")
def test_import_is_secretary_only(org: OrgHarness, soc: uuid.UUID) -> None:
    for person in (TREASURER, COMMITTEE, ESTATE_MGR):
        assert (
            post(
                org,
                soc,
                HEADER + "A,9,1,,,,\n",
                f"import-perm-{person.int % 1000:04d}",
                person=person,
            ).status_code
            == 403
        )
    assert unit_count(org, soc) == 0


@pytest.mark.req("SOC-03", "INV-02")
def test_import_replay_creates_nothing_twice(org: OrgHarness, soc: uuid.UUID) -> None:
    csv = HEADER + "A,1,1,,,,\nA,2,1,,,,\n"
    first = post(org, soc, csv, "import-idem-0001")
    again = post(org, soc, csv, "import-idem-0001")
    assert first.status_code == again.status_code == 200
    assert again.headers["Idempotent-Replayed"] == "true"
    assert unit_count(org, soc) == 2
    different = post(org, soc, csv + "A,3,1,,,,\n", "import-idem-0001")
    assert different.status_code == 409
    assert (
        post(org, soc, csv, "import-idem-0002").status_code == 422
    )  # a NEW key re-runs: now duplicates
    assert unit_count(org, soc) == 2
    assert post(org, soc, csv, "import-idem-0003").status_code == 422
    assert (
        org.call(
            "POST",
            f"/v1/societies/{soc}/units:import",
            SECRETARY,
            content=csv.encode(),
            headers=CSV,
        ).status_code
        == 400
    )
