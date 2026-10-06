"""Every message key and state the parcels, staff and shifts modules emit exists in all three catalogs (UX-08, INV-11, COM-02 flags).

REQ: UX-08, INV-11, COM-02.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dwaar_api.modules.shifts.schemas import SCENARIO_TYPES
from dwaar_api.modules.shifts.service import ITEM_ORDER

pytestmark = [pytest.mark.req("UX-08", "INV-11")]
ROOT = Path(__file__).resolve().parents[3] / "packages" / "i18n"
PARCEL_STATES = (
    "expected",
    "received_at_gate",
    "stored",
    "pickup_pending",
    "collected",
    "refused",
    "returned",
    "lost_exception",
    "cancelled",
)
POLICE = ("not_recorded", "requested", "verified", "not_verified", "expired")


def _catalog(lang: str, ns: str) -> dict[str, str]:
    return json.loads((ROOT / "locales" / lang / f"{ns}.json").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


@pytest.mark.parametrize("lang", ["en", "hi", "mr"])
def test_every_emitted_key_exists_in_every_language(lang: str) -> None:
    shifts, parcels, staff = (
        _catalog(lang, "shifts"),
        _catalog(lang, "parcels"),
        _catalog(lang, "staff"),
    )
    assert all(f"item.{k}" in shifts for k in ITEM_ORDER), (
        "the open-items message keys are shifts.item.<kind>"
    )
    assert all(f"training.scenario.{s}" in shifts for s in SCENARIO_TYPES)
    assert all(f"state.{s}" in parcels for s in PARCEL_STATES)
    assert all(f"police.{s}" in staff for s in POLICE)
    assert all(f"handover.state.{s}" in shifts for s in ("pending", "acknowledged", "escalated"))
    for catalog in (shifts, parcels, staff):
        assert catalog and all(v.strip() for v in catalog.values())


def test_the_catalogs_have_the_same_keys_and_the_machine_drafted_flags_are_honest() -> None:
    status = json.loads((ROOT / "review_status.json").read_text(encoding="utf-8"))
    for ns in ("parcels", "staff", "shifts"):
        assert set(_catalog("en", ns)) == set(_catalog("hi", ns)) == set(_catalog("mr", ns)), ns
        assert status["locales"]["en"][ns]["machine_drafted"] is False
        for lang in ("hi", "mr"):
            entry = status["locales"][lang][ns]
            assert entry == {"machine_drafted": True, "human_reviewed": False, "reviewer": None}, (
                lang,
                ns,
            )
    assert "staff" in status["human_review_required"], "the consent notice is legal text (COM-02)"


def test_the_consent_notice_says_that_no_face_is_used() -> None:
    en = _catalog("en", "staff")["consent.body"].lower()
    assert "face" in en and "do not use your face" in en
