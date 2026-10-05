"""W1 verification round 2 (lens INVARIANTS + SECURITY): library-level attacks that need no database.

Not collected by ``make test`` (the file name does not start with ``test_``). Run explicitly:

    uv run --no-sync pytest tests/security/verify_w1_r2_pure.py -p no:cacheprovider

A test that FAILS here is a confirmed defect: it asserts the SECURE behaviour. A test that passes is an
attack that was tried and did not succeed (regression evidence). Nothing here changes production code.
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

    with pytest.raises((ValidationError, ValueError)):
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

    with pytest.raises((ValidationError, ValueError)):
        Settings.model_validate(
            {
                "env": "production",
                "database_url": "postgresql://dwaar_app:x@db/dwaar",
                "cursor_signing_key": "k" * 40,
                "oidc_issuer_url": "https://idp.example.invalid",
                "oidc_jwks_url": "http://idp.example.invalid/jwks",
                "cors_origins": "https://admin.example.invalid",
            }
        )


def test_a_module_route_without_any_permission_requirement_cannot_start(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``check_requirements`` only validates ``require(...)`` dependencies that ARE declared. A feature module
    whose router has a handler with no ``require`` at all (forgotten, or copy-pasted from /healthz) is mounted
    and answers anonymous callers: INV-01 fails OPEN on omission. Startup should refuse any route that has
    neither a requirement nor an explicit public allowlist entry."""
    from fastapi.testclient import TestClient

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
    try:
        app = create_app(
            settings,
            database=Database("postgresql://dwaar_app:x@127.0.0.1:1/x"),
            modules_package="r2_unguarded_pkg",
        )
    except Exception:
        return  # refused at startup: secure
    answer = TestClient(app, raise_server_exceptions=False).get("/v1/leak/everyone")
    pytest.fail(f"unguarded module route started and answered {answer.status_code} without a token")


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
