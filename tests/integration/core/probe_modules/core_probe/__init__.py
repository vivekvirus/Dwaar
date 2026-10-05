"""``core_probe``: a trivial feature module that exercises the API core end to end.

It exists only inside the tests (ADR-0006). It proves that a module needs no edit to any shared file:
router, permissions and a ``register`` hook are all discovered by ``dwaar_api.core.registry``.
"""

from __future__ import annotations

import time
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, Request
from pydantic import BaseModel, Field
from sqlalchemy import Connection, text

from dwaar_api.core.audit import MutationResult, mutation
from dwaar_api.core.authz import AuthContext, Permission, ScopeKind, require
from dwaar_api.core.idempotency import IdempotentCall, idempotency_required
from dwaar_api.core.pagination import (
    FilterDef,
    PageParams,
    Paginator,
    SortColumn,
    get_paginator,
    page_params,
    parse_filters,
)
from dwaar_common.errors import ERROR_BY_CODE, DependencyUnavailable, PolicyViolation, RateLimited

permissions = [
    Permission("probe.read", frozenset({"committee"}), description="read things"),
    Permission("probe.write", frozenset({"committee"}), description="create things"),
    Permission("probe.unit_read", frozenset({"committee", "resident"}), scope=ScopeKind.UNIT),
    Permission("probe.person_read", frozenset({"committee", "resident"}), scope=ScopeKind.PERSON),
    Permission("probe.sensitive", frozenset({"committee"}), sensitive=True),
]

router = APIRouter(prefix="/v1/probe", tags=["probe"])
registered: list[str] = []


def register(app: FastAPI) -> None:
    """The optional hook: runs once during assembly."""
    registered.append("core_probe")
    app.state.core_probe_registered = True


class ThingIn(BaseModel):
    name: str = Field(min_length=1, max_length=50)
    phone: str | None = Field(default=None, max_length=20)


def _create(auth: AuthContext, idem: IdempotentCall, body: ThingIn) -> Any:
    def work(conn: Connection) -> dict[str, Any]:
        def apply(c: Connection) -> MutationResult:
            row = (
                c.execute(
                    text(
                        "INSERT INTO probe_things (society_id, name, phone) VALUES (:s, :n, :p)"
                        " RETURNING id, name, version"
                    ),
                    {"s": auth.scope.society_id, "n": body.name, "p": body.phone},
                )
                .mappings()
                .one()
            )
            if body.name.startswith("slow:"):
                time.sleep(
                    0.4
                )  # keep the transaction open so concurrent identical requests overlap
            if body.name == "__policy__":
                raise PolicyViolation(
                    details={"rule": "demo"}
                )  # business rule fails AFTER the insert
            if body.name == "__crash__":
                raise RuntimeError("boom after insert")
            after = {"id": row["id"], "name": row["name"], "phone": body.phone}
            return MutationResult(
                object_id=row["id"],
                object_version=row["version"],
                after=after,
                event_payload={"name": row["name"]},
                value={"id": row["id"], "name": row["name"], "version": row["version"]},
            )

        outcome = mutation(
            conn,
            auth.ctx,
            operation="probe.thing.create",
            object_type="probe_thing",
            event_type="ThingCreated",
            apply=apply,
        )
        return {"request_id": str(auth.request_id), **outcome.result.value}

    return idem.run(auth, work, status_code=201)


@router.post("/{society_id}/things", status_code=201)
def create_thing(
    society_id: uuid.UUID,
    body: ThingIn,
    auth: Annotated[AuthContext, Depends(require("probe.write"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> Any:
    return _create(auth, idem, body)


@router.post("/{society_id}/things-alt", status_code=201)
def create_thing_alt(
    society_id: uuid.UUID,
    body: ThingIn,
    auth: Annotated[AuthContext, Depends(require("probe.write"))],
    idem: Annotated[IdempotentCall, Depends(idempotency_required)],
) -> Any:
    """A second idempotent endpoint: the same key must not be replayable across endpoints."""
    return _create(auth, idem, body)


@router.get("/{society_id}/things")
def list_things(
    society_id: uuid.UUID,
    request: Request,
    auth: Annotated[AuthContext, Depends(require("probe.read"))],
    page: Annotated[PageParams, Depends(page_params)],
    paginator: Annotated[Paginator, Depends(get_paginator)],
) -> dict[str, Any]:
    filters = parse_filters(
        dict(request.query_params),
        {"name": FilterDef("str", max_length=50), "kind": FilterDef("enum", frozenset({"a", "b"}))},
    )
    where: list[str] = []
    params: dict[str, Any] = {}
    if "name" in filters:
        where.append("name = :name")
        params["name"] = filters["name"]
    with auth.tx() as conn:
        result = paginator.fetch(
            conn,
            select_sql="SELECT id, name, created_at FROM probe_things",
            where=where,
            params=params,
            sort=[SortColumn("created_at", "timestamptz"), SortColumn("id", "uuid")],
            page=page,
            society_id=auth.scope.society_id,
            filters=filters,
        )
    return {"items": result.items, "next_cursor": result.next_cursor}


@router.get("/{society_id}/whoami")
def whoami(auth: Annotated[AuthContext, Depends(require("probe.read"))]) -> dict[str, Any]:
    scope = auth.scope
    return {
        "society_id": str(scope.society_id),
        "person_id": str(auth.principal.person_id),
        "role": scope.role,
        "society_wide": scope.society_wide,
    }


@router.post("/{society_id}/echo-society")
def echo_society(
    payload: dict[str, Any], auth: Annotated[AuthContext, Depends(require("probe.read"))]
) -> dict[str, Any]:
    """Body carries a (hostile) society_id; the server-derived scope must win."""
    with auth.tx() as conn:
        db_context = conn.execute(
            text("SELECT current_setting('app.society_id', true)")
        ).scalar_one()
    return {
        "scope_society_id": str(auth.scope.society_id),
        "db_context": db_context,
        "ignored": sorted(payload),
    }


@router.get("/{society_id}/units/{unit_id}")
def read_unit(
    unit_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("probe.unit_read", unit_param="unit_id"))],
) -> dict[str, Any]:
    return {"unit_id": str(unit_id), "role": auth.scope.role, "kind": auth.scope.kind.value}


@router.get("/{society_id}/people/{person_id}")
def read_person(
    person_id: uuid.UUID,
    auth: Annotated[AuthContext, Depends(require("probe.person_read", person_param="person_id"))],
) -> dict[str, Any]:
    return {"person_id": str(person_id), "role": auth.scope.role}


@router.get("/{society_id}/sensitive")
def sensitive(auth: Annotated[AuthContext, Depends(require("probe.sensitive"))]) -> dict[str, str]:
    return {"role": auth.scope.role}


@router.get("/errors/db-syntax")
def err_db_syntax(request: Request) -> None:
    with request.app.state.db.app_tx() as conn:
        conn.execute(text("SELECT * FROM table_that_does_not_exist_xyz"))


@router.get("/errors/db-unique")
def err_db_unique(request: Request) -> None:
    with request.app.state.db.app_tx() as conn:
        conn.execute(
            text(
                "INSERT INTO rate_limit_buckets (key, tokens, updated_at) VALUES ('dup-key', 1, now())"
            )
        )
        conn.execute(
            text(
                "INSERT INTO rate_limit_buckets (key, tokens, updated_at) VALUES ('dup-key', 1, now())"
            )
        )


@router.get("/errors/db-rls")
def err_db_rls(request: Request) -> None:
    with (
        request.app.state.db.app_tx() as conn
    ):  # no society context: an INSERT must be refused by RLS
        conn.execute(
            text("INSERT INTO probe_things (society_id, name) VALUES (gen_random_uuid(), 'x')")
        )


@router.get("/errors/db-param-leak")
def err_db_param_leak(request: Request) -> None:
    """A failing statement whose BOUND parameter is personal data: it must never reach logs or responses."""
    with request.app.state.db.app_tx() as conn:
        conn.execute(
            text("INSERT INTO table_that_does_not_exist_xyz (full_name) VALUES (:n)"),
            {"n": "Zorro-Secret-Resident-Name"},
        )


@router.get("/errors/code/{code}")
def err_code(code: str) -> None:
    """Raise any PRD 12.2 error by code (used to verify the whole error table)."""
    cls = ERROR_BY_CODE[code]
    if code == "rate_limited":
        raise RateLimited(retry_after=7)
    if code == "dependency_unavailable":
        raise DependencyUnavailable(retry_after=3)
    raise cls(details={"hint": "demo"})


@router.get("/context")
def header_scoped(
    auth: Annotated[AuthContext, Depends(require("probe.read", society_param="_unused_"))],
) -> dict[str, str]:
    """No society in the path: only the (untrusted, validated) X-Society-Id header can select one."""
    return {"society_id": str(auth.scope.society_id), "role": auth.scope.role}


@router.get("/errors/runtime")
def err_runtime() -> None:
    raise RuntimeError("secret internal detail: password=hunter2 select * from persons")


@router.get("/errors/policy")
def err_policy() -> None:
    raise PolicyViolation(details={"rule": "demo"})
