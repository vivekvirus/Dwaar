"""Schema/model validation of every shipped pack and of malformed packs (INV-10, GOV-01, PRIV-06)."""

from __future__ import annotations

import copy
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from dwaar_packs import PackValidationError, build_pack, discover_pack_files, load_pack
from dwaar_packs.loader import read_yaml
from dwaar_packs.paths import legal_packs_dir

pytestmark = pytest.mark.req("INV-10", "GOV-01")

FILES = list(discover_pack_files())


def test_all_expected_packs_ship() -> None:
    names = {p.name for p in FILES}
    assert {
        "maharashtra-chs.yaml",
        "karnataka-aoa-1972.yaml",
        "karnataka-bill-2026-variant.yaml",
        "haryana-group-housing.yaml",
        "generic.yaml",
        "retention-classes.yaml",
        "cascade-offline.yaml",
        "income-tax-tds.yaml",
        "gst-rwa.yaml",
        "gst-einvoice.yaml",
        "upi-mdr.yaml",
    } <= names


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_every_shipped_pack_validates_and_is_unapproved(path: Path) -> None:
    pack = load_pack(path)
    # Counsel/CA approval is an external step: nothing may ship approved.
    assert pack.approved_by is None and pack.approved_at is None
    assert pack.status in {"unapproved", "draft"}
    assert not pack.is_approved


def test_legal_packs_carry_labels_and_no_invented_urls() -> None:
    for path in FILES:
        pack = load_pack(path)
        assert pack.labels, path
        assert all(s.url is None for s in pack.legal_sources), f"{path}: url must not be invented"


def test_bill_variant_disabled() -> None:
    p = load_pack(legal_packs_dir() / "packs" / "karnataka-bill-2026-variant.yaml")
    assert p.enabled is False and p.disabled_reason


def test_cli_validate_all_ok() -> None:
    r = subprocess.run(
        [sys.executable, "-m", "dwaar_packs", "validate"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "11/11 packs valid" in r.stdout


def _mh_doc() -> dict[str, Any]:
    return copy.deepcopy(read_yaml(legal_packs_dir() / "packs" / "maharashtra-chs.yaml"))


def test_cli_fails_on_malformed_file(tmp_path: Path) -> None:
    doc = _mh_doc()
    del doc["rules"]
    bad = tmp_path / "bad.yaml"
    import yaml

    bad.write_text(yaml.safe_dump(doc))
    r = subprocess.run(
        [sys.executable, "-m", "dwaar_packs", "validate", str(bad)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 1 and "FAIL" in r.stdout and "rules" in r.stdout


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda d: d.pop("effective_from"), "effective_from"),
        (lambda d: d.update(entity_type="club"), "entity_type"),
        (lambda d: d.update(status="approved"), "approved"),  # approved without approver
        (lambda d: d.update(approved_by="Counsel X"), "approved_by"),  # approver but unapproved
        (lambda d: d.update(effective_from="05/10/2026"), "effective_from"),
        (lambda d: d.update(unexpected="x"), "unexpected"),
        (
            lambda d: d["rules"].update(
                {"BadKey": {"value": 1, "labels": [], "legal_source_ref": "x"}}
            ),
            "BadKey",
        ),
        (lambda d: d["rules"]["quorum.ordinary"].update(labels=["MAYBE"]), "MAYBE"),
        (lambda d: d.update(pack_type="nonsense"), "pack_type"),
    ],
)
def test_schema_rejects_malformed_pack(mutate: Any, needle: str) -> None:
    doc = _mh_doc()
    mutate(doc)
    with pytest.raises(PackValidationError) as ei:
        build_pack(doc)
    assert needle in str(ei.value)


def test_model_rejects_unknown_source_ref_and_date_order() -> None:
    doc = _mh_doc()
    doc["rules"]["interest.max_simple_pct_pa"]["legal_source_ref"] = "does-not-exist"
    with pytest.raises(PackValidationError, match="unknown legal_source_ref"):
        build_pack(doc)
    doc = _mh_doc()
    doc["effective_to"] = "2026-01-01"
    with pytest.raises(PackValidationError, match="effective_to"):
        build_pack(doc)


def test_null_rule_must_be_configurable() -> None:
    doc = _mh_doc()
    doc["rules"]["recovery.route"]["value"] = None
    with pytest.raises(PackValidationError, match="configurable"):
        build_pack(doc)


def test_malformed_tax_and_retention_packs_rejected() -> None:
    from dwaar_packs.paths import tax_packs_dir

    tds = read_yaml(tax_packs_dir() / "packs" / "income-tax-tds.yaml")
    tds["categories"]["contractor"]["payees"]["others"]["rate_bp"] = 20000  # > 100%
    with pytest.raises(PackValidationError):
        build_pack(tds)
    fee = read_yaml(tax_packs_dir() / "fee-schedules" / "upi-mdr.yaml")
    fee["pass_to_resident"] = True  # PAY-05: MDR is never passed to the resident
    with pytest.raises(PackValidationError):
        build_pack(fee)
    ret = read_yaml(legal_packs_dir() / "retention" / "retention-classes.yaml")
    del ret["classes"]["HOLD"]
    with pytest.raises(PackValidationError, match="HOLD"):
        build_pack(ret)
    cas = read_yaml(legal_packs_dir() / "defaults" / "cascade-offline.yaml")
    cas["cascade"]["auto_allow_on_timeout"] = True  # INV-03
    with pytest.raises(PackValidationError):
        build_pack(cas)


def test_db_row_shape(mh: Any) -> None:
    row = mh.to_db_row()
    assert set(row) == {
        "jurisdiction",
        "entity_type",
        "version",
        "rules",
        "legal_sources",
        "approved_by",
        "approved_at",
        "effective_from",
        "effective_to",
    }
    assert row["rules"]["interest.max_simple_pct_pa"]["value"] == 12
