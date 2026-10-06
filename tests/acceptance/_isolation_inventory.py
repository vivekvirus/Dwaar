"""AT-01 route inventory support: which live routes are covered by a module's REAL foreign-id isolation probes (slice 4 integration).

Each slice 4 module keeps its own isolation tests (``tests/integration/<module>/test_isolation.py``) that replay society A's ids from society B against
every route. Instead of allow-listing those routes in AT-01, the inventory imports each module's ``probed_routes()`` (derived from the SAME case tables the
module's parametrized tests iterate over) and RESOLVES every probe against the live application with the framework's own route matching. A route is
covered only if some module probe lands on it, so:

* a new route with no probe fails ``test_route_inventory`` (and the module's own inventory test);
* a probe that no longer lands on a live route fails it too (a stale table cannot vouch for anything);
* literal path segments (``/v1/shifts/current``) and placeholders (``/v1/shifts/{shift_id}``) are told apart by the router, not by string tricks.
"""

from __future__ import annotations

import importlib
import re
import uuid
from collections.abc import Iterable

from fastapi import FastAPI
from starlette.routing import Match

from dwaar_api.core.authz import iter_api_routes

#: module name -> the test module that owns its real isolation probes
MODULE_PROBES: dict[str, str] = {
    "notifications": "tests.integration.notifications.test_isolation",
    "parcels": "tests.integration.parcels.test_isolation",
    "staff": "tests.integration.staff.test_isolation",
    "shifts": "tests.integration.shifts.test_isolation",
    "helpdesk": "tests.integration.helpdesk.test_isolation",
    "community": "tests.integration.community.test_isolation",
    "ai": "tests.integration.ai.test_isolation",
}

_PLACEHOLDER = re.compile(r"\{[^/}]*\}")


def resolve(
    app: FastAPI, probes: Iterable[tuple[str, str]]
) -> tuple[set[tuple[str, str]], list[tuple[str, str]]]:
    """(live routes the probes land on, probes that land on no live route). A probe path may carry ``{placeholders}`` and a query string."""
    routes = list(iter_api_routes(app))
    landed: set[tuple[str, str]] = set()
    stale: list[tuple[str, str]] = []
    for method, template in probes:
        concrete = _PLACEHOLDER.sub(lambda _m: str(uuid.uuid4()), template.split("?")[0])
        hit = None
        for route in routes:
            if method not in (route.methods or ()):
                continue
            match, _child = route.matches({"type": "http", "method": method, "path": concrete})
            if match is Match.FULL:
                hit = (method, route.path)
                break
        if hit is None:
            stale.append((method, template))
        else:
            landed.add(hit)
    return landed, stale


def module_coverage(
    app: FastAPI,
) -> tuple[dict[str, set[tuple[str, str]]], dict[str, list[tuple[str, str]]]]:
    """Per module: the live routes its real probes cover, and its stale probes."""
    covered: dict[str, set[tuple[str, str]]] = {}
    stale: dict[str, list[tuple[str, str]]] = {}
    for name, dotted in MODULE_PROBES.items():
        module = importlib.import_module(dotted)
        landed, bad = resolve(app, module.probed_routes())
        covered[name] = landed
        if bad:
            stale[name] = bad
    return covered, stale
