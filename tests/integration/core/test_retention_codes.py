"""Retention class codes used by table defaults versus the retention pack (PRIV-06, Appendix B, PRD 8.2).

REQ: PRIV-06, PRIV-15, INV-10.

The slice 4 modules default some tables to class codes that the shipped retention pack does not define. That is a known, documented gap (slice 4 report,
migration 0710): the retention slice must map or add them. This test pins the set so that no FURTHER unmapped code can appear unnoticed, and fails when
the gap is closed so that the allow-list is removed rather than forgotten.
"""

from __future__ import annotations

import re

import pytest

from dwaar_packs.retention import default_retention_pack
from tests._harness.pgfixtures import DbHandle

pytestmark = pytest.mark.req("PRIV-06", "PRIV-15")

#: codes used as column defaults by slice 4 parents that are not in packages/legal-packs/retention (reviewed, to be mapped by the privacy slice)
KNOWN_UNMAPPED_CODES = {"CONSENT", "STAFF", "OPS", "COM", "DOC"}


def test_every_default_retention_class_is_in_the_pack_or_a_reviewed_gap(db: DbHandle) -> None:
    with db.admin_conn() as conn:
        rows = conn.execute(
            "SELECT table_name, column_default FROM information_schema.columns"
            " WHERE table_schema = 'public' AND column_name = 'retention_class'"
        ).fetchall()
    assert len(rows) > 60, "the common columns are expected on every domain table"
    used = {}
    for table, default in rows:
        match = re.match(r"^'([A-Z][A-Z0-9]{1,15})'::text$", str(default))
        assert match, f"{table}: retention_class default {default!r} is not a plain class code"
        used.setdefault(match.group(1), []).append(table)
    pack = set(default_retention_pack().classes)
    unmapped = set(used) - pack
    assert unmapped == KNOWN_UNMAPPED_CODES, (
        "retention class codes used but not in the retention pack differ from the reviewed gap: "
        f"{ {c: used[c][:3] for c in sorted(unmapped)} }"
    )
