"""``Idempotency-Key`` for financial writes, approvals and command creation.

REQ: INV-02 (retries cannot duplicate), PRD 7.4 / 12 (key required; bound to actor, society, endpoint and
request hash; same key + different payload => 409 ``duplicate_payload_mismatch``; replay returns the stored
canonical response), EDGE-03 spirit (a retry never creates a second effect).

Usage::

    @router.post("/v1/societies/{society_id}/things", status_code=201)
    def create(body: In, auth: AuthContext = Depends(require("things.create")),
               idem: IdempotentCall = Depends(idempotency_required)) -> Response:
        return idem.run(auth, lambda conn: do_the_work(conn, auth, body))   # returns a JSON-able value

How it stays correct
--------------------
The key claim, the domain work (including ``mutation()`` audit/outbox rows) and the stored response are ONE
database transaction. Therefore:

* a crash or error before commit leaves no key behind: the client can retry the same key and the work runs;
* two concurrent requests with the same key serialise on the unique index: the second blocks until the first
  commits, then replays its stored response (no double effect, no polling, no stuck "in progress" state);
* a different payload (or endpoint) under the same (society, actor, key) is rejected with 409.

Failed requests (4xx/5xx raised by the work) roll back and are NOT stored; the client may retry.

Retention and late retries
--------------------------
A stored response is kept at least ``idempotency_ttl_seconds`` (default 7 days, longer than the 72 h offline
buffer of NFR-09) and until the worker's cleanup job deletes it. Expiry NEVER makes the same request run
twice: a retry with the same key AND the same endpoint/payload replays the stored response even after
``expires_at`` while the row still exists. Only a DIFFERENT payload may reclaim an expired key. All expiry
decisions use the database clock (``now()``) inside SQL, never the application clock, so clock skew between
API and database cannot change behaviour or loop. Once the cleanup job has deleted a row the key is gone, so
money-moving endpoints must ALSO carry a business-level unique key (for example ``client_action_id`` per
aggregate); the HTTP key alone cannot cover arbitrarily old retries.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Annotated, Any, Final
from urllib.parse import urlencode

from fastapi import Header, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlalchemy import Connection, text

from dwaar_common.errors import DependencyUnavailable, DuplicatePayloadMismatch
from dwaar_common.events import canonical_json
from dwaar_common.ids import uuid7

from .authz import IDEMPOTENCY_ATTR, AuthContext

log = logging.getLogger("dwaar_api.idempotency")

IDEMPOTENCY_HEADER: Final = "Idempotency-Key"
REPLAY_HEADER: Final = "Idempotent-Replayed"
ORIGINAL_REQUEST_HEADER: Final = "Idempotent-Original-Request-Id"
_KEY_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")
Work = Callable[[Connection], Any]
_MAX_CLAIM_ATTEMPTS: Final = 3


def request_hash(method: str, path: str, query: str, body: bytes) -> str:
    """``sha256:<hex>`` over method, path, sorted query and the body.

    JSON bodies are canonicalised (key order and whitespace do not matter); other bodies hash raw bytes.
    """
    try:
        parsed = json.loads(body) if body else None
        body_part = hashlib.sha256(canonical_json(parsed)).hexdigest() if body else ""
    except (ValueError, TypeError):
        body_part = hashlib.sha256(body).hexdigest()
    # Sort by NAME only (stable): ``?a=1&b=2`` equals ``?b=2&a=1``, but ``?x=1&x=2`` differs from ``?x=2&x=1``
    # because the framework hands a scalar parameter the LAST value, so those are different requests.
    pairs = sorted(
        ((k, v) for k, _, v in (p.partition("=") for p in query.split("&") if p)),
        key=lambda pair: pair[0],
    )
    material = "\n".join([method.upper(), path, urlencode(pairs), body_part])
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _reject_floats(value: Any, path: str = "$") -> None:
    if isinstance(value, float):
        raise TypeError(f"float in idempotent response at {path}: use Decimal (as string) or int")
    if isinstance(value, dict):
        for k, v in value.items():
            _reject_floats(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _reject_floats(v, f"{path}[{i}]")


def encode_response(value: Any) -> Any:
    """JSON-able form of a response that is stored and replayed byte-for-byte equivalent.

    ``Decimal`` becomes a string (exact; quantities are fixed-decimal, INV-02) instead of the lossy float
    that ``jsonable_encoder`` would produce, and any float that remains is a programming error.
    """
    body = jsonable_encoder(value, custom_encoder={Decimal: str})
    _reject_floats(body)
    return body


@dataclass(frozen=True)
class IdempotentCall:
    """A validated Idempotency-Key bound to this request's endpoint and payload hash."""

    key: str
    endpoint: str
    request_hash: str
    ttl_seconds: int = 7 * 86_400

    def run(self, auth: AuthContext, work: Work, *, status_code: int = 200) -> JSONResponse:
        """Claim the key, run ``work(conn)``, store its JSON result and commit - or replay the stored one.

        ``work`` receives the connection of the transaction (RLS context already set) and must return a
        JSON-able value (dict, list or pydantic model). Domain, audit and outbox writes done on ``conn``
        commit together with the stored response.
        """
        with auth.tx() as conn:
            existing = self._claim(conn, auth)
            if existing is not None:
                return self._replay(existing, auth.request_id)
            value = work(conn)
            body = encode_response(value)
            conn.execute(
                text(
                    "UPDATE idempotency_keys SET state = 'completed', response_status = :status,"
                    " response_body = CAST(:body AS jsonb), completed_at = now()"
                    " WHERE society_id = :society AND actor_id = :actor AND key = :key"
                ),
                {
                    "status": status_code,
                    "body": json.dumps(body, separators=(",", ":"), sort_keys=True),
                    "society": auth.scope.society_id,
                    "actor": auth.principal.person_id,
                    "key": self.key,
                },
            )
        return JSONResponse(status_code=status_code, content=body)

    def _claim(self, conn: Connection, auth: AuthContext) -> dict[str, Any] | None:
        """Return None when this request owns the key now, or the stored row to replay.

        Bounded (no recursion) and entirely on the database clock.
        """
        params = {
            "id": uuid7(),
            "society": auth.scope.society_id,
            "actor": auth.principal.person_id,
            "key": self.key,
            "endpoint": self.endpoint,
            "hash": self.request_hash,
            "ttl": self.ttl_seconds,
        }
        for _ in range(_MAX_CLAIM_ATTEMPTS):
            # A concurrent transaction holding the same key blocks THIS statement on the unique index until
            # it commits (we then see its row) or rolls back (we then insert): the serialisation point.
            inserted = conn.execute(
                text(
                    "INSERT INTO idempotency_keys (id, society_id, actor_id, key, endpoint, request_hash,"
                    " expires_at) VALUES (:id, :society, :actor, :key, :endpoint, :hash,"
                    " now() + make_interval(secs => :ttl))"
                    " ON CONFLICT (society_id, actor_id, key) DO NOTHING RETURNING id"
                ),
                params,
            ).first()
            if inserted is not None:
                return None
            row = (
                conn.execute(
                    text(
                        "SELECT endpoint, request_hash, state, response_status, response_body,"
                        " expires_at <= now() AS expired FROM idempotency_keys"
                        " WHERE society_id = :society AND actor_id = :actor AND key = :key"
                    ),
                    params,
                )
                .mappings()
                .first()
            )
            if row is None:  # deleted by the cleanup job between the two statements: take the slot
                continue
            if row["endpoint"] == self.endpoint and row["request_hash"] == self.request_hash:
                if (
                    row["state"] != "completed"
                ):  # cannot be observed by design; refuse, do not guess
                    raise DependencyUnavailable(retry_after=1)
                return dict(row)  # same request: replay, even after expiry (never run twice)
            if not row["expired"]:
                raise DuplicatePayloadMismatch()
            reclaimed = conn.execute(
                text(
                    "UPDATE idempotency_keys SET endpoint = :endpoint, request_hash = :hash,"
                    " state = 'in_progress', response_status = NULL, response_body = NULL,"
                    " completed_at = NULL, created_at = now(),"
                    " expires_at = now() + make_interval(secs => :ttl)"
                    " WHERE society_id = :society AND actor_id = :actor AND key = :key"
                    " AND expires_at <= now() RETURNING id"
                ),
                params,
            ).first()
            if reclaimed is not None:
                return None
            # lost the race to another reclaimer: look again (bounded)
        raise DependencyUnavailable(retry_after=1)

    @staticmethod
    def _replay(row: dict[str, Any], request_id: uuid.UUID) -> JSONResponse:
        """The stored response, with its ``request_id`` member (if the body has one) pointing at THIS request.

        The stored body is the first request's answer, so a ``request_id`` inside it names the first request while
        the ``X-Request-ID`` header names the replay: support tracing by the body field would land on the wrong
        request. The original id is kept in ``Idempotent-Original-Request-Id``.
        """
        log.info("idempotent replay")
        body = row["response_body"]
        headers = {REPLAY_HEADER: "true"}
        if isinstance(body, dict) and "request_id" in body:
            original = body["request_id"]
            body = {**body, "request_id": str(request_id)}
            if isinstance(original, str):
                headers[ORIGINAL_REQUEST_HEADER] = original
        return JSONResponse(status_code=int(row["response_status"]), content=body, headers=headers)


async def idempotency_required(
    request: Request,
    idempotency_key: Annotated[
        str,
        Header(
            alias=IDEMPOTENCY_HEADER,
            pattern=_KEY_PATTERN.pattern,
            description="Client-chosen unique key (8-128 chars of A-Z a-z 0-9 _ . : -), e.g. a UUIDv7. "
            "A retry MUST reuse it; the same key with a different payload is rejected with 409.",
        ),
    ],
) -> IdempotentCall:
    """FastAPI dependency: ``Idempotency-Key`` is mandatory; 400 ``invalid_schema`` if absent or malformed."""
    body = await request.body()
    route = request.scope.get("route")
    template = getattr(route, "path", None) or request.url.path
    digest = request_hash(request.method, request.url.path, request.url.query, body)
    ttl = int(getattr(request.app.state.settings, "idempotency_ttl_seconds", 7 * 86_400))
    return IdempotentCall(idempotency_key, f"{request.method.upper()} {template}", digest, ttl)


setattr(
    idempotency_required, IDEMPOTENCY_ATTR, True
)  # lets check_requirements see mutating routes that are keyed
