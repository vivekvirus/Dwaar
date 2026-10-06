"""COM-04 document vault; SEC-03 upload validation and fail-closed malware scan; SEC-04 short-lived signed URLs."""

from __future__ import annotations

import dataclasses
import hashlib
import time
from pathlib import Path

import psycopg
import pytest

from dwaar_api.modules.community import files
from dwaar_api.modules.community.config import CommunityConfig
from dwaar_api.modules.community.scanner import EICAR, StubScanner, UnconfiguredScanner, scanner_for
from dwaar_api.modules.community.storage import LocalDiskStore, StorageError
from tests.integration.community._flow import Crew, crew

PDF = (
    b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
    + b"x" * 200
)
PDF2 = PDF + b"\n% second edition"


def make_doc(cw, c: Crew, **kw):
    body = {
        "doc_type": "bye_laws",
        "title": "Registered bye-laws of the society",
        "authority": "Registrar of Societies",
        "access_level": "all_residents",
    }
    body.update(kw)
    r = cw.call(c.committee, "POST", "/v1/documents", json=body)
    assert r.status_code == 201, r.text
    return r.json()["document"]


def add_version(cw, who, doc_id, **kw):
    body = {"effective_from": "2026-04-01", "change_note": "first filing"}
    body.update(kw)
    r = cw.call(who, "POST", f"/v1/documents/{doc_id}/versions", json=body)
    assert r.status_code == 201, r.text
    return r.json()["version"]


def upload(
    cw, who, doc_id, ver_id, data=PDF, ctype="application/pdf", name="bye-laws.pdf", expect=200
):
    r = cw.call(
        who,
        "PUT",
        f"/v1/documents/{doc_id}/versions/{ver_id}/content",
        content=data,
        headers={"Content-Type": ctype, "X-Filename": name},
    )
    assert r.status_code == expect, (r.status_code, r.text)
    return r


def publish(cw, who, doc_id, ver_id, expect=200):
    r = cw.call(who, "POST", f"/v1/documents/{doc_id}/versions/{ver_id}/publish", json={})
    assert r.status_code == expect, (r.status_code, r.text)
    return r


def ready(cw, c: Crew, data=PDF, **kw):
    doc = make_doc(cw, c, **kw)
    v = add_version(cw, c.committee, doc["id"])
    upload(cw, c.committee, doc["id"], v["id"], data)
    publish(cw, c.secretary, doc["id"], v["id"])
    return doc, v


# ------------------------------------------------------------------------------------------------ vault
@pytest.mark.req("COM-04")
def test_a_document_goes_from_draft_to_published_with_hash_dates_and_authority(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    doc = make_doc(cw, c)
    v = add_version(
        cw,
        c.committee,
        doc["id"],
        effective_from="2026-04-01",
        authority="Registrar of Societies, Pune",
        change_note="first filing",
    )
    assert (
        v["state"] == "draft"
        and v["effective_from"] == "2026-04-01"
        and v["authority"] == "Registrar of Societies, Pune"
        and v["sha256"] is None
    )
    # nothing but a draft: readers see no version, staff do
    assert cw.call(owner, "GET", f"/v1/documents/{doc['id']}").json()["versions"] == []
    up = upload(cw, c.committee, doc["id"], v["id"]).json()["version"]
    assert (
        up["sha256"] == hashlib.sha256(PDF).hexdigest()
        and up["size_bytes"] == len(PDF)
        and up["media_type"] == "application/pdf"
    )
    assert up["scan"] == {
        "state": "clean",
        "scanner": "stub-scanner-simulation",
        "simulation": True,
        "scanned_at": up["scan"]["scanned_at"],
    }
    assert up["storage_simulation"] is True and up["filename"] == "bye-laws.pdf"
    pub = publish(cw, c.secretary, doc["id"], v["id"]).json()["version"]
    assert pub["state"] == "published" and pub["published_at"]
    got = cw.call(owner, "GET", f"/v1/documents/{doc['id']}").json()
    assert got["document"]["current_version_id"] == v["id"] and [
        x["state"] for x in got["versions"]
    ] == ["published"]
    assert "object_key" not in str(got) and "object_key" not in str(up)
    assert doc["id"] in {d["id"] for d in cw.call(owner, "GET", "/v1/documents").json()["items"]}
    assert (
        cw.outbox("DocumentVersionPublished", doc["id"])
        and cw.audit("document.publish")[0][2] == "secretary"
    )
    key = cw.rows("SELECT object_key FROM document_versions")[0][0]
    assert (
        len(key) >= 43 and str(doc["id"]) not in key and "bye" not in key
    )  # unguessable, unrelated to anything


@pytest.mark.req("COM-04")
def test_a_new_version_supersedes_and_a_published_version_is_immutable(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    doc, v1 = ready(cw, c)
    # a published file cannot be replaced, edited or re-uploaded
    assert (
        upload(cw, c.committee, doc["id"], v1["id"], PDF2, expect=409).json()["details"]["reason"]
        == "version_not_draft"
    )
    for sql in (
        "UPDATE document_versions SET sha256 = repeat('a', 64) WHERE state = 'published'",
        "UPDATE document_versions SET effective_from = '2020-01-01' WHERE state = 'published'",
        "UPDATE document_versions SET object_key = repeat('b', 43) WHERE state = 'published'",
        "UPDATE document_versions SET state = 'draft' WHERE state = 'published'",
    ):
        with (
            cw.idh.db.app_conn(cw.soc.id, c.secretary.id, "secretary") as conn,
            pytest.raises(psycopg.errors.DatabaseError),
        ):
            conn.execute(sql)  # type: ignore[call-overload]
    with (
        cw.idh.db.app_conn(cw.soc.id, c.secretary.id, "secretary") as conn,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        conn.execute("DELETE FROM document_versions")  # type: ignore[call-overload]
    v2 = add_version(
        cw, c.committee, doc["id"], effective_from="2026-09-01", change_note="amended by the AGM"
    )
    assert v2["version_no"] == 2
    upload(cw, c.committee, doc["id"], v2["id"], PDF2)
    publish(cw, c.secretary, doc["id"], v2["id"])
    states = cw.rows("SELECT version_no, state FROM document_versions ORDER BY version_no")
    assert states == [(1, "superseded"), (2, "published")]
    got = cw.call(owner, "GET", f"/v1/documents/{doc['id']}").json()
    assert got["document"]["current_version_id"] == v2["id"] and [
        x["version_no"] for x in got["versions"]
    ] == [2, 1]
    publish(cw, c.secretary, doc["id"], v2["id"], expect=409)  # not a draft any more


@pytest.mark.req("COM-04")
def test_withdrawing_hides_a_version_but_keeps_the_record(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    doc, v = ready(cw, c)
    r = cw.call(
        c.secretary,
        "POST",
        f"/v1/documents/{doc['id']}/versions/{v['id']}/withdraw",
        json={"reason": "wrong file was filed"},
    )
    assert r.status_code == 200 and r.json()["version"]["state"] == "withdrawn"
    assert cw.call(owner, "GET", f"/v1/documents/{doc['id']}").json()["versions"] == []
    assert (
        cw.call(
            owner, "POST", f"/v1/documents/{doc['id']}/versions/{v['id']}/download-url", json={}
        ).status_code
        == 404
    )
    assert cw.rows("SELECT state, withdraw_reason FROM document_versions")[0] == (
        "withdrawn",
        "wrong file was filed",
    )
    assert [
        x["state"]
        for x in cw.call(c.committee, "GET", f"/v1/documents/{doc['id']}").json()["versions"]
    ] == ["withdrawn"]
    assert (
        cw.call(
            c.secretary,
            "POST",
            f"/v1/documents/{doc['id']}/versions/{v['id']}/withdraw",
            json={"reason": "again"},
        ).status_code
        == 409
    )


@pytest.mark.req("COM-04")
def test_access_levels_decide_who_sees_and_downloads_what(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    nr_owner = cw.resident(cw.unit("A-102"), "owner", lives=False)
    tenant = cw.resident(cw.unit("A-103"), "tenant")
    family = cw.resident(cw.unit("A-101"), "family")
    docs = {
        lvl: ready(cw, c, title=f"Document at level {lvl}", access_level=lvl)
        for lvl in ("all_residents", "owners", "committee", "managers")
    }
    allowed = [
        (owner, {"all_residents", "owners"}), (nr_owner, {"all_residents", "owners"}), (tenant, {"all_residents"}),
        (family, {"all_residents"}), (c.committee, {"all_residents", "owners", "committee"}),
        (c.treasurer, {"all_residents", "owners", "committee"}),
        (c.estate, {"all_residents", "owners", "committee", "managers"}),
        (c.secretary, {"all_residents", "owners", "committee", "managers"}),
    ]  # fmt: skip
    drafters = {c.committee.id, c.estate.id, c.secretary.id}
    for who, levels in allowed:
        listed = {d["access_level"] for d in cw.call(who, "GET", "/v1/documents").json()["items"]}
        # staff with draft rights (committee, estate manager, secretary) see every document to manage it
        if who.id in drafters:
            assert listed == set(docs)
        else:
            assert listed == levels, (who.id, listed)
        for lvl, (doc, v) in docs.items():
            r = cw.call(
                who, "POST", f"/v1/documents/{doc['id']}/versions/{v['id']}/download-url", json={}
            )
            expect = 200 if (lvl in levels or who.id in drafters) else 404
            assert r.status_code == expect, (lvl, r.status_code)
            if expect == 404:
                assert cw.call(who, "GET", f"/v1/documents/{doc['id']}").status_code == 404
    for who in (c.guard, c.auditor):  # the printed matrix gives them nothing in the vault
        assert cw.call(who, "GET", "/v1/documents").status_code == 403


# ------------------------------------------------------------------------------------------------ upload validation, scanner
@pytest.mark.req("SEC-03")
def test_uploads_are_validated_by_type_content_and_size(cw) -> None:
    c = crew(cw)
    doc = make_doc(cw, c)
    v = add_version(cw, c.committee, doc["id"])
    did, vid = doc["id"], v["id"]
    bad = (
        (b"MZ\x90\x00 this is a windows executable", "application/pdf"),  # claims PDF, is not
        (PDF, "image/png"),  # the bytes are a PDF
        (PDF, "application/zip"),  # type not allowed
        (PDF, "text/html"),
        (b"\x00\x01binary", "text/plain"),
        (b"\xff\xfe\xfa invalid utf8 \xc3", "text/plain"),
        (b"", "application/pdf"),
        (PDF, ""),
    )
    for data, ctype in bad:
        assert (
            upload(cw, c.committee, did, vid, data, ctype, expect=400).json()["code"]
            == "invalid_schema"
        ), ctype
    cfg = dataclasses.replace(cw.app.state.community_config, max_upload_bytes=1024)
    cw.app.state.community_config = cfg
    big = b"%PDF-1.4\n" + b"y" * 2048
    assert (
        upload(cw, c.committee, did, vid, big, expect=400).json()["details"]["reason"]
        == "payload_too_large"
    )
    assert cw.rows("SELECT sha256 FROM document_versions")[0][0] is None  # nothing was stored
    ok = upload(
        cw, c.committee, did, vid, b"a,b,c\n1,2,3\n", "text/csv; charset=utf-8", "../../etc/passwd"
    )
    assert (
        ok.json()["version"]["media_type"] == "text/csv"
        and ok.json()["version"]["filename"] == "passwd"
    )  # never a path
    png = upload(
        cw, c.committee, did, vid, b"\x89PNG\r\n\x1a\n" + b"0" * 64, "image/png", "scan <1>.png"
    )
    assert png.json()["version"]["filename"] == "scan _1_.png"


@pytest.mark.req("SEC-03")
def test_an_infected_file_is_never_kept_or_published(cw, tmp_path: Path) -> None:
    c = crew(cw)
    doc = make_doc(cw, c)
    v = add_version(cw, c.committee, doc["id"])
    good = upload(cw, c.committee, doc["id"], v["id"]).json()["version"]
    assert good["scan"]["state"] == "clean"
    old_key = cw.rows("SELECT object_key FROM document_versions")[0][0]
    store: LocalDiskStore = cw.app.state.community_store
    assert store.get(old_key) == PDF
    bad = upload(
        cw, c.committee, doc["id"], v["id"], b"%PDF-1.4\n" + EICAR, "application/pdf"
    ).json()["version"]
    assert bad["scan"]["state"] == "infected" and bad["sha256"] is None and bad["filename"] is None
    with pytest.raises(StorageError):
        store.get(
            old_key
        )  # the replaced clean object was removed, and the infected one was never stored
    assert not any(p.is_file() for p in (tmp_path / "objects").rglob("*"))
    r = publish(cw, c.secretary, doc["id"], v["id"], expect=422)
    assert r.json()["details"]["reason"] == "no_file"


@pytest.mark.req("SEC-03")
def test_without_a_configured_scanner_nothing_can_be_published_fail_closed(cw_noscan) -> None:
    cw = cw_noscan
    c = crew(cw)
    doc = make_doc(cw, c)
    v = add_version(cw, c.committee, doc["id"])
    up = upload(cw, c.committee, doc["id"], v["id"]).json()["version"]
    assert (
        up["scan"]["state"] == "unavailable"
        and up["scan"]["scanner"] == "none-configured"
        and up["scan"]["simulation"] is False
    )
    r = publish(cw, c.secretary, doc["id"], v["id"], expect=422)
    assert r.json()["details"] == {"reason": "scan_not_clean", "scan_state": "unavailable"}
    # a draft is not downloadable either: only a CLEAN file can ever be issued a URL
    assert (
        cw.call(
            c.committee,
            "POST",
            f"/v1/documents/{doc['id']}/versions/{v['id']}/download-url",
            json={},
        ).status_code
        == 404
    )
    # re-scanning with the same (absent) scanner stays closed; configuring the labelled stub opens it
    again = cw.call(
        c.committee, "POST", f"/v1/documents/{doc['id']}/versions/{v['id']}/scan", json={}
    )
    assert again.json()["version"]["scan"]["state"] == "unavailable"
    cw.app.state.community_scanner = StubScanner()
    clean = cw.call(
        c.committee, "POST", f"/v1/documents/{doc['id']}/versions/{v['id']}/scan", json={}
    ).json()["version"]
    assert clean["scan"]["state"] == "clean" and clean["scan"]["simulation"] is True
    publish(cw, c.secretary, doc["id"], v["id"])
    # and the database independently refuses a published row that is not clean
    cw.app.state.community_scanner = UnconfiguredScanner()
    d2 = add_version(cw, c.committee, doc["id"], effective_from="2026-10-01")
    upload(cw, c.committee, doc["id"], d2["id"], PDF2)
    with cw.idh.db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(cw.soc.id),))
        with pytest.raises(psycopg.Error):
            conn.execute(
                "UPDATE document_versions SET state = 'published', published_by = created_by, published_at = now() WHERE id = %s",
                (d2["id"],),
            )


@pytest.mark.req("SEC-03")
def test_scanner_and_storage_adapters_and_configuration(tmp_path: Path) -> None:
    assert UnconfiguredScanner().scan(b"anything", "a.pdf").state == "unavailable"  # never clean
    assert (
        scanner_for("").name == "none-configured"
        and scanner_for("unconfigured").simulation is False
    )
    stub = scanner_for("stub")
    assert (
        stub.simulation is True
        and stub.scan(b"hello", "a.txt").state == "clean"
        and stub.scan(EICAR, "a.txt").state == "infected"
    )
    store = LocalDiskStore(tmp_path)
    assert store.simulation is True and "simulation" in store.name
    key = store.put(b"data")
    assert store.get(key) == b"data" and len(key) >= 43 and key != store.put(b"data")
    store.delete(key)
    for bad in ("../../etc/passwd", "a/b", "short", "x" * 200, ""):
        with pytest.raises(StorageError):
            store.get(bad)
    with pytest.raises(StorageError):
        store.get(key)
    from dwaar_api.core.config import ConfigError, Settings

    base = {
        "cursor_signing_key": "test-cursor-Key-9fA3kQ7zLm2XpR8vT1bY",
        "database_url": "postgresql://x:y@localhost/z",
    }
    test = Settings.model_validate({**base, "env": "test"})
    cfg = CommunityConfig.from_environment(test, {"DWAAR_COMMUNITY_STORAGE_DIR": str(tmp_path)})
    assert (
        cfg.scanner_kind == "unconfigured"
        and cfg.download_ttl_seconds == 120
        and cfg.simulation is True
    )
    assert (
        CommunityConfig.from_environment(test, {"DWAAR_COMMUNITY_SCANNER": "stub"}).scanner_kind
        == "stub"
    )
    for env in (
        {"DWAAR_COMMUNITY_SCANNER": "clamav"},
        {"DWAAR_COMMUNITY_DOWNLOAD_TTL": "1"},
        {"DWAAR_COMMUNITY_DOWNLOAD_TTL": "9999"},
        {"DWAAR_COMMUNITY_DOWNLOAD_TTL": "x"},
    ):
        with pytest.raises(ConfigError):
            CommunityConfig.from_environment(test, env)


# ------------------------------------------------------------------------------------------------ SEC-04 signed URLs
@pytest.mark.req("SEC-04")
def test_a_signed_url_is_issued_after_an_access_check_and_serves_the_exact_bytes(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    doc, v = ready(cw, c)
    r = cw.call(
        owner, "POST", f"/v1/documents/{doc['id']}/versions/{v['id']}/download-url", json={}
    )
    assert r.status_code == 200
    body = r.json()
    url = body["url"]
    assert (
        url.startswith("/v1/downloads/")
        and body["ttl_seconds"] == 120
        and body["sha256"] == hashlib.sha256(PDF).hexdigest()
    )
    key = cw.rows("SELECT object_key FROM document_versions")[0][0]
    assert (
        key not in url and str(doc["id"]) not in url and str(v["id"]) not in url
    )  # no id, no storage key in the URL
    got = cw.call(
        None, "GET", url, society=False
    )  # no bearer token: the URL is the (short-lived) capability
    assert (
        got.status_code == 200
        and got.content == PDF
        and got.headers["content-type"] == "application/pdf"
    )
    assert got.headers["content-disposition"] == 'attachment; filename="bye-laws.pdf"'
    assert (
        got.headers["cache-control"] == "no-store"
        and got.headers["x-content-type-options"] == "nosniff"
    )
    assert got.headers["x-document-sha256"] == hashlib.sha256(PDF).hexdigest()
    assert [
        a[0]
        for a in cw.rows(
            "SELECT operation FROM audit_log WHERE operation LIKE %s ORDER BY at",
            ("document.download%",),
        )
    ] == ["document.download_url_issued", "document.downloaded"]
    assert cw.audit("document.downloaded")[0][1] == owner.id


@pytest.mark.req("SEC-04")
def test_the_url_expires_and_a_forged_one_is_the_same_404(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    doc, v = ready(cw, c)
    cw.app.state.community_config = dataclasses.replace(
        cw.app.state.community_config, download_ttl_seconds=1
    )
    url = cw.call(
        owner, "POST", f"/v1/documents/{doc['id']}/versions/{v['id']}/download-url", json={}
    ).json()["url"]
    assert cw.call(None, "GET", url, society=False).status_code == 200
    time.sleep(2.1)
    expired = cw.call(None, "GET", url, society=False)
    assert expired.status_code == 404 and expired.json()["code"] == "not_found"
    fresh = cw.call(
        owner, "POST", f"/v1/documents/{doc['id']}/versions/{v['id']}/download-url", json={}
    ).json()["url"]
    body, sig = fresh.rsplit("/", 1)[1].split(".")
    for forged in (f"{body}.{sig[:-2]}AA", f"{body}x.{sig}", "garbage", f"{sig}.{body}", "."):
        r = cw.call(None, "GET", f"/v1/downloads/{forged}", society=False)
        assert (
            r.status_code == 404
            and r.json()["code"] == "not_found"
            and r.content
            == expired.content.replace(
                expired.json()["request_id"].encode(), r.json()["request_id"].encode()
            )
        )
    # a token signed with another key is no token
    foreign = files.issue_token(
        b"k" * 32,
        files.read_token(cw.app.state.community_config.download_key, fresh.rsplit("/", 1)[1], 0)
        or files.DownloadClaim(cw.soc.id, v["id"], owner.id, None, 2**31),
    )
    assert cw.call(None, "GET", f"/v1/downloads/{foreign}", society=False).status_code == 404


@pytest.mark.req("SEC-04")
def test_possession_of_the_url_does_not_outlive_the_persons_access(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    tenant = cw.resident(cw.unit("A-102"), "tenant")
    doc, v = ready(cw, c)

    def issue(who):
        return cw.call(
            who, "POST", f"/v1/documents/{doc['id']}/versions/{v['id']}/download-url", json={}
        ).json()["url"]

    u_owner, u_tenant = issue(owner), issue(tenant)
    # the tenant's membership ends after the URL was issued: the URL dies with it
    cw.sql("UPDATE memberships SET verification = 'rejected' WHERE person_id = %s", (tenant.id,))
    assert cw.call(None, "GET", u_tenant, society=False).status_code == 404
    assert cw.call(None, "GET", u_owner, society=False).status_code == 200
    # a session that was revoked after issuing kills its URLs
    u2 = issue(owner)
    cw.sql("UPDATE iam.auth_sessions SET revoked_at = now() WHERE id = %s", (owner.session_id,))
    assert cw.call(None, "GET", u2, society=False).status_code == 404
    # tightening the document's access level after issue also kills outstanding URLs
    other = cw.resident(cw.unit("A-103"), "tenant")
    u3 = issue(other)
    cw.sql("UPDATE documents SET access_level = 'owners'")
    assert cw.call(None, "GET", u3, society=False).status_code == 404


@pytest.mark.req("SEC-04", "COM-04")
def test_withdrawing_a_version_or_changing_its_bytes_stops_the_download(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    doc, v = ready(cw, c)
    url = cw.call(
        owner, "POST", f"/v1/documents/{doc['id']}/versions/{v['id']}/download-url", json={}
    ).json()["url"]
    store: LocalDiskStore = cw.app.state.community_store
    key = cw.rows("SELECT object_key FROM document_versions")[0][0]
    path = next(Path(store.root).rglob(key))
    original = path.read_bytes()
    path.write_bytes(original + b"tampered")  # the stored bytes no longer match the recorded sha256
    r = cw.call(None, "GET", url, society=False)
    assert (
        r.status_code == 503
        and r.json()["code"] == "dependency_unavailable"
        and b"tampered" not in r.content
    )
    path.write_bytes(original)
    assert cw.call(None, "GET", url, society=False).status_code == 200
    cw.call(
        c.secretary,
        "POST",
        f"/v1/documents/{doc['id']}/versions/{v['id']}/withdraw",
        json={"reason": "retracted by the AGM"},
    )
    assert cw.call(None, "GET", url, society=False).status_code == 404


@pytest.mark.req("SEC-04")
def test_drafts_can_be_previewed_by_drafters_only_after_a_clean_scan(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    doc = make_doc(cw, c)
    v = add_version(cw, c.committee, doc["id"])
    upload(cw, c.committee, doc["id"], v["id"])
    assert (
        cw.call(
            c.committee,
            "POST",
            f"/v1/documents/{doc['id']}/versions/{v['id']}/download-url",
            json={},
        ).status_code
        == 200
    )
    assert (
        cw.call(
            owner, "POST", f"/v1/documents/{doc['id']}/versions/{v['id']}/download-url", json={}
        ).status_code
        == 404
    )
    assert cw.call(owner, "GET", f"/v1/documents/{doc['id']}/versions/{v['id']}").status_code in (
        404,
        405,
    )


@pytest.mark.req("COM-04")
def test_permissions_and_validation(cw) -> None:
    c = crew(cw)
    owner = cw.resident(cw.unit("A-101"), "owner")
    body = {
        "doc_type": "circular",
        "title": "Circular on waste segregation",
        "authority": "Managing Committee",
    }
    assert cw.call(owner, "POST", "/v1/documents", json=body).status_code == 403
    assert cw.call(c.treasurer, "POST", "/v1/documents", json=body).status_code == 403
    doc = make_doc(cw, c, **body)
    v = add_version(cw, c.committee, doc["id"])
    upload(cw, c.committee, doc["id"], v["id"])
    assert (
        cw.call(
            c.committee, "POST", f"/v1/documents/{doc['id']}/versions/{v['id']}/publish", json={}
        ).status_code
        == 403
    )  # only the secretary publishes
    assert (
        cw.call(
            c.estate,
            "POST",
            f"/v1/documents/{doc['id']}/versions/{v['id']}/withdraw",
            json={"reason": "no right"},
        ).status_code
        == 403
    )
    for bad in (
        {**body, "doc_type": "memo"},
        {**body, "access_level": "everyone"},
        {**body, "title": "x"},
        {**body, "object_key": "x"},
    ):
        assert cw.call(c.committee, "POST", "/v1/documents", json=bad).status_code == 400
    assert (
        cw.call(
            c.committee,
            "POST",
            f"/v1/documents/{doc['id']}/versions",
            json={"effective_from": "not-a-date"},
        ).status_code
        == 400
    )
    assert (
        cw.call(c.committee, "GET", "/v1/documents", params={"doc_type": "circular"}).json()[
            "items"
        ][0]["id"]
        == doc["id"]
    )
    assert cw.call(c.committee, "GET", "/v1/documents", params={"colour": "red"}).status_code == 400
    # the raised body limit applies to the document routes only: a 2 MiB body is refused 413 elsewhere
    big = cw.call(
        c.committee,
        "POST",
        "/v1/notices",
        content=b"{" + b" " * (2 * 1024 * 1024) + b"}",
        headers={"Content-Type": "application/json"},
    )
    assert big.status_code == 413
