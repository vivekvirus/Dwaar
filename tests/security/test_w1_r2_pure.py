"""W1 fix round 2 (lens INVARIANTS + SECURITY): library-level regression tests that need no database.

Covers R2-01 (money survives masking), R2-05 (route registration fails closed), R2-06 (scrubber and masker),
R2-07 (tax results carry the binding stamp), R2-08 (verification never raises), R2-09 (money parsing is bounded)
and the small hygiene findings fixed alongside them. Each test asserts the SECURE behaviour; it was a failing
repro (``verify_w1_r2_pure.py``) before the root cause was fixed.
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001, S105, S106, S112

from __future__ import annotations

import base64
import os
import time
import uuid
from datetime import date
from decimal import Decimal
from typing import Any

import pytest

from dwaar_api.core.audit import mask_payload
from dwaar_common import events, money, signing
from dwaar_common.logging import is_sensitive_key, scrub_text, scrub_value
from dwaar_packs import InMemoryPackRepository, load_pack
from dwaar_packs.paths import legal_packs_dir

pytestmark = pytest.mark.req("INV-01", "INV-02", "INV-10", "OBS-01")

_B64_SECRET = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
_HEX_SECRET = bytes(range(32)).hex()
_STRONG_CURSOR_KEY = "Zk3vQ9xL2mPd7RtYb1HnWs8Ue4JgAc6F"  # 32 distinct characters


# ------------------------------------------------------------------------------------------------
# (9) event verification must never raise on attacker-shaped payloads
# ------------------------------------------------------------------------------------------------
def _signed_wire() -> tuple[signing.Signer, dict[str, Any]]:
    signer = signing.Signer.generate()
    event = events.EdgeEvent.build(
        society_id=uuid.uuid4(),
        device_id=uuid.uuid4(),
        seq=1,
        entity_id=uuid.uuid4(),
        entity_version=1,
        type="Entry",
        policy_version=1,
        payload={"a": 1},
    )
    return signer, signer.sign_event(event).to_wire()


def _deep() -> dict[str, Any]:
    root: dict[str, Any] = {}
    cur = root
    for _ in range(5000):
        cur["a"] = {}
        cur = cur["a"]
    return root


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"x": 1.5}, id="float"),
        pytest.param({"x": float("nan")}, id="nan"),
        pytest.param({"x": "\ud800"}, id="lone-surrogate"),
        pytest.param({"x": 10**5000}, id="5000-digit-int"),
        pytest.param(_deep(), id="5000-deep"),
    ],
)
def test_verifying_a_hostile_event_returns_false_it_does_not_raise(payload: dict[str, Any]) -> None:
    """``signing`` promises "Verification never raises on bad input: it returns False". An edge batch is
    attacker-shaped JSON; one event with a float / surrogate / huge int / deep nesting in its payload makes
    ``verify_edge_event`` and ``VerifierRing.verify_event`` raise CanonicalJsonError / UnicodeEncodeError /
    ValueError / RecursionError, which the sync endpoint turns into a 500 for the WHOLE batch (poison batch:
    the device retries it forever and every legitimate event behind it is stuck)."""
    signer, wire = _signed_wire()
    wire = {**wire, "payload": payload}
    event = events.EdgeEvent.from_wire(wire)
    ring = signing.VerifierRing()
    ring.add("k1", signer.public_key)
    assert signing.verify_edge_event(signer.public_key, event) is False
    assert ring.verify_event("k1", event) is False


def test_verify_envelope_returns_false_on_a_float() -> None:
    signer = signing.Signer.generate()
    assert signing.verify_envelope(signer.public_key, {"a": 1.5}, "ed25519:" + "A" * 86) is False


# ------------------------------------------------------------------------------------------------
# (10) money: Decimal inputs must fail fast with a MoneyError
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("exponent", [500_000, 999_999])
@pytest.mark.parametrize("parser", ["parse_rupees", "percent_to_bp"])
def test_huge_decimal_exponent_is_refused_quickly_with_a_money_error(
    parser: str, exponent: int
) -> None:
    """``Decimal('1e500000')`` is a legal pydantic Decimal. ``_decimal_to_paise`` / ``percent_to_bp`` call
    ``int(scaled)`` BEFORE any range check: ~3 s of CPU at 1e500000, >15 s at 1e999990, and the result is a
    raw ``ValueError`` (digit-limit message) or ``decimal.Overflow``, never a ``MoneyError``. One request
    pins a worker thread; a handful stall the API."""
    func = getattr(money, parser)
    started = time.perf_counter()
    with pytest.raises(money.MoneyError):
        func(Decimal(f"1e{exponent}"))
    assert time.perf_counter() - started < 0.5, "huge Decimal burned CPU before being rejected"


# ------------------------------------------------------------------------------------------------
# (7) logging scrubber misses
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "key",
    [
        "master_key", "hmac_key", "signing_key", "encryption_key", "pii_keys", "pii_key",
        "pepper", "passphrase", "pw", "dsn", "database_url", "connection_string",
    ],
)  # fmt: skip
def test_key_material_and_credential_field_names_are_redacted(key: str) -> None:
    """B-009 says credentials are redacted deny-by-default, but the key-name list has no *_key, pepper, salt,
    passphrase, pw or DSN. A settings dump, an audit diff or an event payload carrying the master
    key / pepper / DSN password is stored in clear."""
    assert scrub_value({key: _B64_SECRET})[key] == "[REDACTED]", f"{key} is logged in clear"
    assert mask_payload({key: _B64_SECRET})[key] == "[REDACTED]", f"{key} is audited in clear"


@pytest.mark.parametrize(
    "text",
    [
        f"DWAAR_PII_KEYS=k1={_B64_SECRET}",
        f"DWAAR_PII_ACTIVE_KEY_ID=k1 DWAAR_MASTER_KEY={_B64_SECRET}",
        f"phone_hmac_key={_B64_SECRET}",
        f"pepper={_HEX_SECRET}",
        f"decrypt failed for key {_HEX_SECRET}",
        "postgresql://dwaar_app:s3cretpw9@127.0.0.1:5432/dwaar",
        "Could not parse SQLAlchemy URL from string 'postgresql://dwaar_owner:Tr0ub4dor@db.internal/dwaar'",
    ],
)
def test_secrets_in_free_text_are_scrubbed(text: str) -> None:
    """The env-var name of the real PII key ring (DWAAR_PII_KEYS), 32-byte hex keys (the scrubber keeps any
    32+ hex run readable because hashes look the same) and DSN passwords all survive scrub_text. A failing
    ``make_url`` raises an error whose message embeds the whole URL including the password."""
    scrubbed = scrub_text(text)
    for secret in (_B64_SECRET, _HEX_SECRET, "s3cretpw9", "Tr0ub4dor"):
        assert secret not in scrubbed, f"{secret!r} survived: {scrubbed!r}"


@pytest.mark.parametrize(
    "text",
    [
        "GET /verify?code=482913&phone=x",
        "GET /v?c=482913",
        "code: 482913",
        "your code is 482913",
        "Use 482913 to verify your Dwaar account",
        "login?user=a&pass=hunter2xyz",
        "pw=hunter2xyz",
        "auth=abcdef123456",
        "आपका ओटीपी 482913 है",
    ],
)
def test_otp_and_password_shaped_text_is_scrubbed(text: str) -> None:
    """OTP detection is a phrase list (otp, verification code, passcode ...). The plain query parameter
    ``code=``, an SMS body that does not use one of those phrases, the Hindi word for OTP, ``pass=``/``pw=``
    and ``auth=`` all pass through unredacted."""
    scrubbed = scrub_text(text)
    for secret in ("482913", "hunter2xyz", "abcdef123456"):
        assert secret not in scrubbed, f"{secret!r} survived: {scrubbed!r}"


@pytest.mark.parametrize("key", ["session_id", "sessionid", "sid", "sig", "signature", "refresh"])
def test_dict_key_and_text_key_classifiers_agree(key: str) -> None:
    """Two independent key classifiers exist (``is_sensitive_key`` for mappings, ``_is_secret_text_key`` for
    free text) and they disagree: ``session_id=abc`` in text is redacted, ``{"session_id": "abc"}`` is not."""
    in_text = scrub_text(f"{key}=abc123XYZ789") != f"{key}=abc123XYZ789"
    in_mapping = is_sensitive_key(key)
    assert in_text == in_mapping, f"{key}: text-redacted={in_text} mapping-redacted={in_mapping}"


@pytest.mark.parametrize(
    "number",
    [
        "1234,5678,9012",
        "1234/5678/9012",
        "1234_5678_9012",
        "1234​5678​9012",
        "99999/00123",
        "99999_00123",
        "99999​00123",
        "99999 - - 00123",
    ],
)
def test_identifier_digit_runs_are_scrubbed_whatever_the_separator(number: str) -> None:
    """Digit runs are only joined across ``[ \\t.-()]`` (max 3 separator characters). Comma, slash, underscore
    and zero-width separators split an Aadhaar or a phone number into runs below the 9-digit threshold."""
    digits = "".join(ch for ch in number if ch.isdigit())
    assert scrub_text(f"id {number} end") != f"id {number} end", digits


# ------------------------------------------------------------------------------------------------
# (8) crypto / input hygiene
# ------------------------------------------------------------------------------------------------
def _must_match(found: object) -> None:
    if found is None:
        raise ValueError("no match")


def test_trailing_newline_is_not_accepted_by_python_dollar_anchored_validators() -> None:
    """``re.match(r'^...$')`` accepts a trailing newline (Postgres ``~`` and pydantic's regex engine do not).
    Four validators use Python ``re`` that way."""
    from dwaar_api.core.authz import Permission
    from dwaar_api.core.db import RequestContext
    from dwaar_common import crypto

    accepted: list[str] = []
    for label, fn in {
        "signing.check_key_id": lambda: signing.check_key_id("k1\n"),
        "crypto.KeyRing id": lambda: crypto.KeyRing({"k1\n": crypto.generate_key()}, "k1\n"),
        "RequestContext.actor_role": lambda: RequestContext(actor_role="committee\n"),
        "Permission.action": lambda: Permission("a.b\n", frozenset({"x"})),
        "events.PAYLOAD_HASH_PATTERN (used with .match)": lambda: _must_match(
            events.PAYLOAD_HASH_PATTERN.match("sha256:" + "0" * 64 + "\n")
        ),
    }.items():
        try:
            fn()
        except Exception:
            continue
        accepted.append(label)
    assert accepted == [], f"newline-suffixed values accepted by: {accepted}"


def test_key_ring_refuses_duplicate_key_ids_in_the_environment_value() -> None:
    """``k1=<A>,k1=<B>`` silently keeps B: a copy/paste during rotation makes every value encrypted under A
    undecryptable (or, with the roles swapped, leaves the retired key active) with no error at boot."""
    from dwaar_common import crypto

    a, b = crypto.generate_key(), crypto.generate_key()
    with pytest.raises(crypto.CryptoError):
        crypto.KeyRing.from_env_value(f"k1={crypto.key_to_b64(a)},k1={crypto.key_to_b64(b)}", "k1")


def test_key_ring_with_key_cannot_replace_existing_key_material_under_the_same_id() -> None:
    from dwaar_common import crypto

    ring = crypto.KeyRing({"k1": crypto.generate_key()}, "k1")
    with pytest.raises(crypto.CryptoError):
        ring.with_key("k1", crypto.generate_key())


def test_aad_with_no_parts_does_not_equal_aad_with_one_empty_part() -> None:
    from dwaar_common import crypto

    assert crypto.build_aad() != crypto.build_aad("")
    assert crypto.build_aad(None) != crypto.build_aad("None")


# ------------------------------------------------------------------------------------------------
# (11) packs and tax: approval must travel with every computed result
# ------------------------------------------------------------------------------------------------
def test_tax_results_say_whether_the_pack_that_produced_them_may_bind() -> None:
    """Legal-pack evaluators stamp results with ``binding`` (GOV-01). The tax calculators do not: the shipped
    TDS pack is ``status: draft`` / labelled [CA][VERIFY] yet ``compute_tds`` returns a plain
    ``tds_paise`` with nothing that marks it as unapproved, and ``default_tds_pack()`` bypasses the
    approval-evidence downgrade used by ``FilePackRepository``. Anything that posts the number cannot tell
    a draft figure from an approved one."""
    from dwaar_packs.tax import compute_tds, default_tds_pack

    pack = default_tds_pack()
    assert not pack.is_approved
    result = compute_tds(
        pack,
        category="contractor",
        payee_category="others",
        amount_paise=5_000_000,
        trigger_date=date(2026, 5, 1),
    )
    assert result.tds_paise > 0
    assert getattr(result, "binding", None) is False, "TdsResult carries no binding/approval stamp"


def test_find_legal_pack_prefers_approved_binding_pack_over_a_later_draft() -> None:
    """``find_legal_pack`` picks the LATEST ``effective_from`` among enabled packs and never looks at status.
    Adding an enabled draft/retired pack with a later date silently supersedes the approved one: every
    caller then evaluates against a non-binding pack (governance disabled by an unreviewed file drop)."""
    base = load_pack(legal_packs_dir() / "packs" / "maharashtra-chs.yaml")
    older = base.model_copy(
        update={
            "version": "1.0.0",
            "status": "approved",
            "approved_by": "counsel",
            "approved_at": "2026-01-01T00:00:00Z",
            "effective_from": date(2026, 1, 1),
        }
    )
    newer_draft = base.model_copy(
        update={"version": "2.0.0-draft", "status": "draft", "effective_from": date(2026, 6, 1)}
    )
    repo = InMemoryPackRepository([older, newer_draft])
    chosen = repo.find_legal_pack(base.jurisdiction, base.entity_type, date(2026, 9, 1))
    assert chosen.version == "1.0.0", f"selected {chosen.version} ({chosen.status})"


# ------------------------------------------------------------------------------------------------
# config hardening
# ------------------------------------------------------------------------------------------------
def test_cursor_signing_key_must_have_real_entropy_outside_local() -> None:
    """Cursors are HMAC-signed with ``DWAAR_CURSOR_SIGNING_KEY``; any non-empty string is accepted in
    production, so ``DWAAR_CURSOR_SIGNING_KEY=a`` boots and cursors can be forged by brute force."""
    from pydantic import ValidationError

    from dwaar_api.core.config import Settings

    with pytest.raises((ValidationError, ValueError), match="CURSOR_SIGNING_KEY"):
        Settings.model_validate(
            {
                "env": "production",
                "database_url": "postgresql://dwaar_app:x@db/dwaar",
                "cursor_signing_key": "a",
                "oidc_issuer_url": "https://idp.example.invalid",
                "oidc_jwks_url": "https://idp.example.invalid/jwks",
                "cors_origins": "https://admin.example.invalid",
            }
        )


def test_date_range_extremes_are_a_400_not_an_unhandled_overflow() -> None:
    """``to=0001-01-02T00:00:00Z`` (no ``from``) computes ``end - 92 days``; ``to=9999-12-31T23:59:59-05:00``
    calls ``astimezone(UTC)``. Both raise OverflowError, an unhandled 500 on every list endpoint that uses
    ``date_range_params``."""
    import datetime as dt

    from dwaar_api.core.pagination import bounded_range
    from dwaar_common.errors import InvalidSchema

    for start, end in (
        (None, dt.datetime(1, 1, 2, tzinfo=dt.UTC)),
        (
            dt.datetime(9999, 12, 30, tzinfo=dt.UTC),
            dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=dt.timezone(dt.timedelta(hours=-5))),
        ),
    ):
        with pytest.raises(InvalidSchema):
            bounded_range(start, end, max_days=92)


def test_os_environment_is_not_modified_by_these_tests() -> None:
    assert "DWAAR_PII_KEYS" not in os.environ or os.environ["DWAAR_PII_KEYS"] != _B64_SECRET


# ------------------------------------------------------------------------------------------------
# (10) money: out-of-range ints must be a MoneyRangeError, not a raw ValueError from formatting
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("operation", ["ensure_paise", "parse_rupees_int", "mul_int", "sum_paise"])
def test_five_thousand_digit_integers_raise_money_range_error(operation: str) -> None:
    """``ensure_paise`` puts the offending number into its exception message, and Python refuses to render an
    int above 4300 digits (``ValueError: Exceeds the limit``). A client JSON amount of ``10**5000`` therefore
    escapes as a bare ValueError (not ``MoneyRangeError``/``MoneyError``) and handlers that catch the money
    exception hierarchy turn it into a 500."""
    big = 10**5000
    calls = {
        "ensure_paise": lambda: money.ensure_paise(big),
        "parse_rupees_int": lambda: money.parse_rupees(big),
        "mul_int": lambda: money.mul_int(5, big),
        "sum_paise": lambda: money.sum_paise([big]),
    }
    with pytest.raises(money.MoneyRangeError):
        calls[operation]()


# ------------------------------------------------------------------------------------------------
# (5) JWKS transport and (1) fail-open route registration
# ------------------------------------------------------------------------------------------------
def test_jwks_url_must_be_https_outside_local() -> None:
    """Settings require the ISSUER url to be https outside local/test but never look at ``oidc_jwks_url``:
    ``DWAAR_OIDC_JWKS_URL=http://...`` boots in production, so anyone on the path can swap the signing keys
    and mint tokens for any person id."""
    from pydantic import ValidationError

    from dwaar_api.core.config import Settings

    with pytest.raises((ValidationError, ValueError), match="JWKS"):
        Settings.model_validate(
            {
                "env": "production",
                "database_url": "postgresql://dwaar_app:x@db/dwaar",
                "cursor_signing_key": _STRONG_CURSOR_KEY,
                "oidc_issuer_url": "https://idp.example.invalid",
                "oidc_jwks_url": "http://idp.example.invalid/jwks",
                "cors_origins": "https://admin.example.invalid",
            }
        )


def test_a_module_route_without_any_permission_requirement_cannot_start(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:  # R2-05
    """``check_requirements`` only validates ``require(...)`` dependencies that ARE declared. A feature module
    whose router has a handler with no ``require`` at all (forgotten, or copy-pasted from /healthz) is mounted
    and answers anonymous callers: INV-01 fails OPEN on omission. Startup should refuse any route that has
    neither a requirement nor an explicit public allowlist entry."""
    from dwaar_api.core.config import Settings
    from dwaar_api.core.db import Database
    from dwaar_api.main import create_app

    pkg = tmp_path / "r2_unguarded_pkg"
    (pkg / "open_mod").mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "open_mod" / "__init__.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/v1/leak')\n"
        "@router.get('/everyone')\n"
        "def everyone():\n"
        "    return {'rows': ['every society']}\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    settings = Settings.model_validate(
        {
            "env": "test",
            "database_url": "postgresql://dwaar_app:x@127.0.0.1:1/x",
            "cursor_signing_key": "k" * 40,
        }
    )
    from dwaar_api.core.config import ConfigError

    with pytest.raises(ConfigError, match=r"GET /v1/leak/everyone"):
        create_app(
            settings,
            database=Database("postgresql://dwaar_app:x@127.0.0.1:1/x"),
            modules_package="r2_unguarded_pkg",
        )


# ------------------------------------------------------------------------------------------------
# (4) audit / outbox payload masking must not destroy money
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "key",
    [
        "credit", "debit", "net", "gross", "principal", "interest", "fee", "tds", "gst",
        "outstanding", "arrears", "settled", "corpus", "penalty", "mdr", "cr", "dr",
    ],
)  # fmt: skip
def test_masking_never_redacts_a_money_amount(key: str) -> None:
    """Integers (and decimal strings) of 9+ digits are treated as phone/bank numbers unless the KEY contains one
    of a short allow-list of quantity words (paise, amount, balance, total ...). 250_000_000 paise is Rs 25 lakh
    and 9 digits starts at Rs 10 lakh: a settlement, corpus-fund or annual-bill figure under any other key
    (credit, debit, net, principal, interest, fee, tds, gst, arrears ...) is silently replaced by [REDACTED]
    in the audit diff AND in the outbox payload (whose payload_hash is then computed over the masked
    payload, so the figure is unrecoverable). INV-02: money must survive the audit/event path."""
    assert mask_payload({key: 250_000_000})[key] == 250_000_000
    assert mask_payload({key: "2500000.00"})[key] == "2500000.00"


def test_audit_diff_keeps_large_money_changes() -> None:
    from dwaar_api.core.audit import masked_diff

    diff = masked_diff({"credit": 100_000_000}, {"credit": 250_000_000})
    assert diff["changed"]["credit"] == {"before": 100_000_000, "after": 250_000_000}


# ------------------------------------------------------------------------------------------------
# migration runner: transaction-control guard is only a line-anchored regex
# ------------------------------------------------------------------------------------------------
def test_migration_files_cannot_smuggle_transaction_control(tmp_path: Any) -> None:
    """Each migration runs inside one transaction together with its ledger row. ``_TX_CONTROL`` only matches a
    COMMIT/ROLLBACK at the START of a line, so ``...; COMMIT; ...`` on one line is accepted: the file then
    commits half-way and a later failing statement leaves a partially applied, ledger-less migration."""
    from dwaar_api.core.migrate import MigrationError, discover

    (tmp_path / "0001_half_commit.sql").write_text(
        "CREATE TABLE half_a (id int); COMMIT; CREATE TABLE half_b (id int);\n"
    )
    with pytest.raises(MigrationError):
        discover(tmp_path)


# ================================================================================================
# fix round 2: behaviour added around the repro cases (boundaries, false-positive guards, markers)
# ================================================================================================
def _guard_app(*, post: bool = False, **route_kwargs: Any) -> Any:
    from fastapi import FastAPI

    app = FastAPI()
    if post:
        app.post("/t", **route_kwargs)(lambda: {"ok": True})
    else:
        app.get("/t", **route_kwargs)(lambda: {"ok": True})
    return app


def _registry() -> Any:
    from dwaar_api.core.authz import Permission, PermissionRegistry

    return PermissionRegistry([Permission("t.read", frozenset({"committee"}))])


def test_route_guard_accepts_require_public_marker_and_authenticated_routes() -> None:
    from fastapi import Depends

    from dwaar_api.core.authn import current_principal
    from dwaar_api.core.authz import check_requirements, public_route, require

    reg = _registry()
    check_requirements(_guard_app(dependencies=[Depends(require("t.read"))]), reg)
    check_requirements(_guard_app(dependencies=[Depends(public_route("health probe"))]), reg)
    check_requirements(_guard_app(dependencies=[Depends(current_principal)]), reg)
    with pytest.raises(ValueError, match="reason"):
        public_route("   ")


def test_route_guard_refuses_a_bare_route_and_a_route_added_through_starlette() -> None:
    from fastapi import FastAPI
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    from dwaar_api.core.authz import check_requirements
    from dwaar_api.core.config import ConfigError

    with pytest.raises(ConfigError, match="GET /t"):
        check_requirements(_guard_app(), _registry())
    app = FastAPI()
    app.router.routes.append(Route("/sneaky", lambda request: PlainTextResponse("hi")))
    with pytest.raises(ConfigError, match="/sneaky"):
        check_requirements(app, _registry())


def test_route_guard_requires_an_idempotency_key_on_mutating_routes() -> None:
    from fastapi import Depends

    from dwaar_api.core.authz import check_requirements, idempotency_exempt, public_route, require
    from dwaar_api.core.config import ConfigError
    from dwaar_api.core.idempotency import idempotency_required

    reg = _registry()
    guarded = Depends(require("t.read"))
    with pytest.raises(ConfigError, match="idempotency"):
        check_requirements(_guard_app(post=True, dependencies=[guarded]), reg)
    check_requirements(
        _guard_app(post=True, dependencies=[guarded, Depends(idempotency_required)]), reg
    )
    check_requirements(
        _guard_app(post=True, dependencies=[guarded, Depends(idempotency_exempt("pure read"))]), reg
    )
    check_requirements(  # a public POST (sign-in, OTP request) is not a ledger write
        _guard_app(post=True, dependencies=[Depends(public_route("otp request"))]), reg
    )


def test_money_parsing_boundaries_and_no_silent_rounding() -> None:
    assert money.parse_rupees("92233720368547758.07") == money.MAX_PAISE
    assert money.parse_rupees("-92233720368547758.08") == money.MIN_PAISE
    for too_big in ("92233720368547758.08", "9" * 5000, "1" + "0" * 17):
        with pytest.raises(money.MoneyRangeError):
            money.parse_rupees(too_big)
    assert money.parse_rupees("0" * 5000 + "5") == 500  # leading zeros are not magnitude
    # context rounding used to turn a tiny non-zero fraction into exactly Rs 1.00
    with pytest.raises(money.MoneyError, match="decimal"):
        money.parse_rupees(Decimal("1." + "0" * 70 + "1"))
    assert money.parse_rupees(Decimal("1.5E+1")) == 1500
    assert money.parse_rupees(Decimal("0E+99999")) == 0
    assert money.percent_to_bp("12.5") == 1250
    assert money.percent_to_bp(Decimal("1.5E+1")) == 1500
    assert money.percent_to_bp(Decimal("1e-2")) == 1
    with pytest.raises(money.MoneyError):
        money.percent_to_bp(Decimal("1e-3"))
    with pytest.raises(money.MoneyError):
        money.parse_rupees(Decimal("NaN"))
    with pytest.raises(money.MoneyError):
        money.parse_rupees(Decimal("Infinity"))


def test_decimal_parsing_agrees_with_integer_arithmetic() -> None:
    from hypothesis import given
    from hypothesis import strategies as st

    @given(st.decimals(min_value=-(10**15), max_value=10**15, places=2, allow_nan=False))
    def check(value: Decimal) -> None:
        assert money.parse_rupees(value) == int(value * 100)
        assert money.percent_to_bp(value) == int(value * 100)

    check()


def test_canonical_json_bounds_and_astral_key_order() -> None:
    from dwaar_common.events import CanonicalJsonError, canonical_json

    ok: Any = 1
    for _ in range(events.MAX_CANONICAL_DEPTH - 1):  # the surrounding dict is level 0, "x" level 1
        ok = [ok]
    assert canonical_json({"x": ok})
    with pytest.raises(CanonicalJsonError):
        canonical_json({"x": [ok]})
    assert canonical_json({"n": 2**64 - 1})
    with pytest.raises(CanonicalJsonError):
        canonical_json({"n": 2**64})
    # RFC 8785: UTF-16 code unit order puts the astral key (surrogate pair D800..) BEFORE U+FFFF
    assert canonical_json({"￿": 1, "\U00010000": 2}) == '{"\U00010000":2,"￿":1}'.encode()
    with pytest.raises(CanonicalJsonError):
        canonical_json({"\ud800": 1})


def test_transaction_control_is_found_by_structure_not_by_line_start() -> None:
    from dwaar_api.core.migrate import has_transaction_control

    bad = [
        "CREATE TABLE a (id int); COMMIT; CREATE TABLE b (id int);",
        "BEGIN;",
        "SELECT 1;\nROLLBACK",
        "select 1; end",
        "START TRANSACTION ISOLATION LEVEL SERIALIZABLE;",
        "SELECT 1;\n  Commit Prepared 'x';",
    ]
    good = [
        "DO $$ BEGIN PERFORM 1; END $$;",
        "SELECT 'commit; rollback;'; -- COMMIT;\n/* ROLLBACK; /* nested */ END; */ SELECT 1",
        "CREATE FUNCTION f() RETURNS int AS $body$ BEGIN RETURN 1; END; $body$ LANGUAGE plpgsql;",
        "SELECT E'it\\'s; COMMIT;'",
        'SELECT "commit" FROM t',
        "COMMENT ON TABLE t IS 'begin; commit;'",
    ]
    for sql in bad:
        assert has_transaction_control(sql), sql
    for sql in good:
        assert not has_transaction_control(sql), sql


@pytest.mark.parametrize(
    "key",
    ["Authorization", "x-api-key", "apiKey", "master_key", "pii_keys", "session_id", "sessionId",
     "sid", "pw", "dsn", "pepper", "DATABASE_URL", "phones", "tokens", "refresh_token", "csrfToken"],
)  # fmt: skip
def test_secret_looking_keys_are_sensitive(key: str) -> None:
    assert is_sensitive_key(key)


@pytest.mark.parametrize(
    "key",
    ["pass_id", "pass_type", "auth_method", "key_id", "idempotency_key", "public_key", "pin_code",
     "society_token", "token_type", "request_id", "status", "amount_paise", "code", "version"],
)  # fmt: skip
def test_ordinary_keys_are_not_over_redacted(key: str) -> None:
    assert not is_sensitive_key(key)


def test_audit_masks_identifier_numbers_by_key_and_keeps_every_other_number() -> None:
    masked = mask_payload(
        {
            "contact": 9999900123,
            "mobile_no": 9999900123,
            "account_number": 123456789012,
            "payout": 7_500_000_000,  # a money field nobody listed: still data
            "units": 12,
            "tds": "250000000",  # digits-only string under a quantity key
            "ref_note": "call 99999 00123",
            "phones": [9999900123],
            "nested": {"tds": 250_000_000, "card": 4111111111111111},
        }
    )
    assert masked["contact"] == "[REDACTED]"
    assert masked["mobile_no"] == "[REDACTED]"
    assert masked["account_number"] == "[REDACTED]"
    assert masked["payout"] == 7_500_000_000
    assert masked["units"] == 12
    assert masked["tds"] == "250000000"
    assert "99999 00123" not in str(masked["ref_note"])
    assert masked["phones"] == "[REDACTED]"
    assert masked["nested"] == {"tds": 250_000_000, "card": "[REDACTED]"}


def test_scrubber_keeps_labelled_digests_ids_and_dates_but_not_bare_hex_keys() -> None:
    digest = "sha256:" + "ab" * 32
    safe = (
        f"payload_hash={digest} id 0192f300-0000-7000-8000-00000000000a on 2026-10-05 from 10.0.0.7"
    )
    assert scrub_text(safe) == safe
    bare = "ab" * 32
    assert bare not in scrub_text(f"loaded key {bare} ok")
    assert "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" not in scrub_text(
        f"decrypt failed for {_B64_SECRET}0"
    )
    assert scrub_text("sha256 of the file is fine") == "sha256 of the file is fine"


def test_scrubber_masks_url_passwords_and_zero_width_split_numbers() -> None:
    out = scrub_text("connect postgresql://app:p%40ss-w0rd@db.internal:5432/dwaar failed")
    assert "p%40ss-w0rd" not in out
    assert "postgresql://app:[REDACTED]@db.internal:5432/dwaar" in out
    assert "999990012345" not in scrub_text("aadhaar 9999​9001‍2345 here")
    assert (
        scrub_text("error code 5000 on page 3") == "error code 5000 on page 3"
    )  # no over-redaction
