"""Store: WAL + synchronous=FULL, one writer, encrypted fields, migrations, integrity, backup (EDGE-01)."""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest

from dwaar_common.crypto import DecryptionError, KeyRing, generate_key
from dwaar_edge.errors import MigrationError, StoreCorruptError, StoreLockedError
from dwaar_edge.store import EdgeStore, restore_backup
from tests.integration.edge_gateway.support import ManualTime, World, standard_world_with_policy

pytestmark = pytest.mark.req("EDGE-01")


def open_store(path: Path, ring: KeyRing | None = None, soc: uuid.UUID | None = None) -> EdgeStore:
    return EdgeStore(
        path / "edge.sqlite3",
        keyring=ring or KeyRing({"k": generate_key()}, "k"),
        society_id=soc or uuid.uuid4(),
        device_id=uuid.uuid4(),
    ).open()


def test_wal_and_synchronous_full_are_in_force(tmp_path: Path) -> None:
    s = open_store(tmp_path)
    try:
        p = s.pragmas()
        assert str(p["journal_mode"]).lower() == "wal"
        assert p["synchronous"] == 2  # FULL
        assert p["foreign_keys"] == 1
    finally:
        s.close()


def test_exactly_one_writer_process_owns_the_file(tmp_path: Path) -> None:
    ring, soc = KeyRing({"k": generate_key()}, "k"), uuid.uuid4()
    dev = uuid.uuid4()
    a = EdgeStore(tmp_path / "e.db", keyring=ring, society_id=soc, device_id=dev).open()
    try:
        with pytest.raises(StoreLockedError):
            EdgeStore(tmp_path / "e.db", keyring=ring, society_id=soc, device_id=dev).open()
    finally:
        a.close()
    EdgeStore(
        tmp_path / "e.db", keyring=ring, society_id=soc, device_id=dev
    ).open().close()  # lock released on close


def test_store_refuses_a_different_society_or_device(tmp_path: Path) -> None:
    ring, soc, dev = KeyRing({"k": generate_key()}, "k"), uuid.uuid4(), uuid.uuid4()
    EdgeStore(tmp_path / "e.db", keyring=ring, society_id=soc, device_id=dev).open().close()
    with pytest.raises(StoreCorruptError):
        EdgeStore(tmp_path / "e.db", keyring=ring, society_id=uuid.uuid4(), device_id=dev).open()


def test_migrations_are_checksummed(tmp_path: Path) -> None:
    ring, soc, dev = KeyRing({"k": generate_key()}, "k"), uuid.uuid4(), uuid.uuid4()
    EdgeStore(tmp_path / "e.db", keyring=ring, society_id=soc, device_id=dev).open().close()
    c = sqlite3.connect(tmp_path / "e.db")
    c.execute("UPDATE schema_migrations SET checksum='tampered'")
    c.commit()
    c.close()
    with pytest.raises(MigrationError):
        EdgeStore(tmp_path / "e.db", keyring=ring, society_id=soc, device_id=dev).open()


def test_integrity_check_detects_a_torn_outbox_counter(tmp_path: Path) -> None:
    ring, soc, dev = KeyRing({"k": generate_key()}, "k"), uuid.uuid4(), uuid.uuid4()
    s = EdgeStore(tmp_path / "e.db", keyring=ring, society_id=soc, device_id=dev).open()
    with s.transaction() as c:
        c.execute(
            "INSERT INTO outbox (seq, event_id, type, entity_id, entity_version, occurred_at, policy_version, wire_enc, size_bytes, state)"
            " VALUES (7, 'e', 'EntryObserved', 'x', 1, 't', 0, 'w', 1, 'pending')"
        )  # an outbox row WITHOUT the counter advancing: impossible in one transaction, so it signals damage
    s.close()
    with pytest.raises(StoreCorruptError, match="torn"):
        EdgeStore(tmp_path / "e.db", keyring=ring, society_id=soc, device_id=dev).open()


def test_corrupt_file_is_refused(tmp_path: Path) -> None:
    ring, soc, dev = KeyRing({"k": generate_key()}, "k"), uuid.uuid4(), uuid.uuid4()
    s = EdgeStore(tmp_path / "e.db", keyring=ring, society_id=soc, device_id=dev).open()
    with s.transaction() as c:
        for i in range(200):
            c.execute("INSERT INTO meta (key, value) VALUES (?, ?)", (f"k{i}", "v" * 200))
    s.close()
    data = bytearray((tmp_path / "e.db").read_bytes())
    for off in range(4096 * 2, min(len(data), 4096 * 6), 97):
        data[off] ^= 0xFF
    (tmp_path / "e.db").write_bytes(bytes(data))
    for suffix in ("-wal", "-shm"):
        (tmp_path / f"e.db{suffix}").unlink(missing_ok=True)
    with pytest.raises((StoreCorruptError, sqlite3.DatabaseError)):
        EdgeStore(tmp_path / "e.db", keyring=ring, society_id=soc, device_id=dev).open()


def test_field_encryption_is_bound_to_row_and_column(tmp_path: Path) -> None:
    s = open_store(tmp_path)
    try:
        tok = s.cipher.seal("pending_items", "detail_enc", "row-1", "secret")
        assert s.cipher.open("pending_items", "detail_enc", "row-1", tok) == "secret"
        with pytest.raises(DecryptionError):
            s.cipher.open("pending_items", "detail_enc", "row-2", tok)  # moved to another row
        with pytest.raises(DecryptionError):
            s.cipher.open("overrides", "detail_enc", "row-1", tok)  # moved to another table
    finally:
        s.close()


def test_audit_log_is_append_only(tmp_path: Path) -> None:
    s = open_store(tmp_path)
    try:
        with s.transaction():
            s.audit(
                "t", "x", None, {}, __import__("datetime").datetime.now(__import__("datetime").UTC)
            )
        with pytest.raises(sqlite3.DatabaseError, match="append-only"), s.transaction() as c:
            c.execute("UPDATE audit_log SET action='y'")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"), s.transaction() as c:
            c.execute("DELETE FROM audit_log")
    finally:
        s.close()


def test_transaction_rolls_back_on_error_and_is_reentrant(tmp_path: Path) -> None:
    s = open_store(tmp_path)
    try:
        with pytest.raises(RuntimeError), s.transaction() as c:
            c.execute("INSERT INTO meta (key, value) VALUES ('a', '1')")
            with s.transaction() as c2:  # nested: joins the outer transaction
                c2.execute("INSERT INTO meta (key, value) VALUES ('b', '2')")
            raise RuntimeError
        assert s.get_meta("a") is None and s.get_meta("b") is None
    finally:
        s.close()


def test_backup_is_consistent_encrypted_and_restorable(tmp_path: Path) -> None:
    w, t, gw = standard_world_with_policy(tmp_path)
    a = w.actor(gw, w.term_a)
    r = gw.evaluate(
        a,
        gate_id=w.gate_a,
        lane_id=w.lane_a_in,
        credential={"kind": "resident", "credential_ref": "cred-r1", "revocation_version": 1},
    )
    gw.record_entry(
        a,
        gate_id=w.gate_a,
        lane_id=w.lane_a_in,
        evaluation_id=r["evaluation_id"],
        alias="BackupAliasXYZ",
    )
    dest = gw.backup(tmp_path / "bk" / "edge-backup.sqlite3")
    assert b"BackupAliasXYZ" not in dest.read_bytes() and b"cred-r1" not in dest.read_bytes()
    gw.stop()
    restored = tmp_path / "restored" / "edge.sqlite3"
    restored.parent.mkdir()
    restore_backup(dest, restored)
    gw2 = w.gateway(tmp_path / "restored", t)
    try:
        assert gw2.outbox.stats()["pending"] == 1 and gw2.policy and gw2.policy.seq == 1
        assert gw2.list_inside()["count"] == 1
    finally:
        gw2.stop()


def test_fsync_probe_reports_latency(tmp_path: Path) -> None:
    s = open_store(tmp_path)
    try:
        p = s.fsync_probe(rounds=5)
        assert p["max_ms"] >= p["p50_ms"] >= 0
    finally:
        s.close()


def test_world_helpers_smoke(tmp_path: Path) -> None:
    assert ManualTime().wall() and World().society_id
