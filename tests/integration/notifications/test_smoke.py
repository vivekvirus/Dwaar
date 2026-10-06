"""Smoke: the module loads, the migration applies, a request starts a cascade and the first push goes out (NOTIF-03 t = 0)."""

import pytest

pytestmark = [pytest.mark.req("NOTIF-03")]


def test_a_request_starts_a_cascade_and_pushes_to_the_primary(nw):  # type: ignore[no-untyped-def]
    owner, family = nw.household2("A-101")
    nw.register_device(owner, "owner-phone")
    request = nw.raise_and_start(nw.unit("A-101"))
    rows = nw.nrows(request["id"])
    assert [r["channel"] for r in rows] == ["push"]
    assert rows[0]["state"] == "provider_accepted"
