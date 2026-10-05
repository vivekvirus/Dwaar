"""OPEN findings from W1 verification: crypto, phone normalisation, event signing/canonicalisation, money (INV-01, INV-02).

Not collected by ``make test``; run explicitly with
``uv run --no-sync pytest tests/security/verify_w1_crypto_events_money.py -p no:cacheprovider``.

A FAILING test asserts the secure behaviour and marks a defect that is NOT fixed yet (not part of fix round 1).
When one is fixed, move it to ``tests/security/test_w1_crypto_events_money.py``. Tests for fixed findings live in
``tests/security/test_w1_*.py``.
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import datetime as dt
import inspect
import uuid
from typing import Any

import pytest

from dwaar_common.crypto import (
    DecryptionError,
    EnvelopeCipher,
    KeyRing,
    generate_key,
    keyed_hash,
)
from dwaar_common.events import CanonicalJsonError, EdgeEvent, canonical_json

pytestmark = pytest.mark.req("INV-01", "INV-02")

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _ring(*ids: str, active: str | None = None) -> KeyRing:
    return KeyRing({i: generate_key() for i in ids}, active or ids[0])


# ------------------------------------------------------------------------------------------------
# (8) crypto
# ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    ["", "v1", "v1:k1", "v1:k1:AAAA", "v1:k1:A:AAAA", "v1:k1:AAAAAAAAAAAAAAAA:A", "v1:k1:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAAA",
     "v2:k1:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAAAA", "v1:k1:" + "A" * 10_000 + ":" + "A" * 10_000, "v1:k1:١٢:AA", "v1:../:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAAAA"],
)  # fmt: skip
def test_malformed_ciphertexts_raise_only_decryption_error(token: str) -> None:
    cipher = EnvelopeCipher(_ring("k1"))
    with pytest.raises(DecryptionError):
        cipher.decrypt(token)


def test_ciphertext_encoding_is_canonical_one_value_one_string() -> None:
    """Non-canonical base64url (spare trailing bits) decodes to the same bytes, so several distinct token
    strings authenticate for ONE ciphertext. Harmless for confidentiality, harmful for any dedupe or
    allow/deny list keyed on the stored string."""
    cipher = EnvelopeCipher(_ring("k1"))
    token = cipher.encrypt("a")  # 1 + 16 byte tag = 17 bytes -> spare bits in the last base64 char
    head, last = token[:-1], token[-1]
    accepted = []
    for ch in ALPHABET:
        try:
            cipher.decrypt(head + ch)
            accepted.append(ch)
        except DecryptionError:
            pass
    assert accepted == [last], f"{len(accepted)} different strings decrypt to the same ciphertext"


def test_keyed_hash_offers_domain_separation_between_uses_of_one_master_key() -> None:
    """phone_token, OTP hashes, rate-limit keys etc. all call keyed_hash(value, key). With a shared key and no
    purpose/context parameter, the SAME input yields the SAME token in every domain, so a token minted for
    one purpose (e.g. an rate-limit key or a log token) is a valid lookup token for another."""
    params = set(inspect.signature(keyed_hash).parameters)
    assert params & {"purpose", "context", "domain", "label", "info"}, (
        f"keyed_hash parameters: {sorted(params)}"
    )


# ------------------------------------------------------------------------------------------------
# phone normalisation
# ------------------------------------------------------------------------------------------------


# ------------------------------------------------------------------------------------------------
# (9) canonicalisation and signatures
# ------------------------------------------------------------------------------------------------
def _event(**overrides: Any) -> EdgeEvent:
    base: dict[str, Any] = {
        "society_id": uuid.uuid4(),
        "device_id": uuid.uuid4(),
        "seq": 7,
        "entity_id": uuid.uuid4(),
        "entity_version": 1,
        "type": "EntryObserved",
        "policy_version": 3,
        "payload": {"gate": "main", "n": 2},
        "occurred_at": dt.datetime(2026, 10, 5, 8, 0, 0, 123456, tzinfo=dt.UTC),
    }
    base.update(overrides)
    return EdgeEvent.build(**base)


def test_canonical_json_orders_keys_like_rfc8785_utf16_code_units() -> None:
    """RFC 8785 (JCS) sorts members by UTF-16 code units; Python sorts by code point. Signatures made over
    these bytes will not verify in the Kotlin/JS clients for keys outside the BMP."""
    ours = canonical_json({"￿": 1, "\U00010000": 2})
    assert ours == '{"\U00010000":2,"￿":1}'.encode()


def test_lone_surrogates_are_a_canonical_json_error_not_a_unicode_crash() -> None:
    with pytest.raises(CanonicalJsonError):
        canonical_json({"note": "\ud800"})


def test_pathologically_deep_payloads_are_a_canonical_json_error_not_a_recursion_crash() -> None:
    value: Any = []
    for _ in range(50_000):
        value = [value]
    with pytest.raises(CanonicalJsonError):
        canonical_json({"x": value})


# ------------------------------------------------------------------------------------------------
# (10) money
# ------------------------------------------------------------------------------------------------
