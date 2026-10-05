"""W1 adversarial verification: crypto, phone normalisation, event signing/canonicalisation, money (INV-01, INV-02).

Not collected by ``make test``; run explicitly:
    uv run --no-sync pytest tests/security/verify_w1_crypto_events_money.py -p no:cacheprovider

A FAILING test asserts the secure behaviour and therefore marks a confirmed defect.
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import datetime as dt
import inspect
import uuid
from decimal import Decimal
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dwaar_common import money
from dwaar_common.crypto import (
    DecryptionError,
    EnvelopeCipher,
    InvalidPhoneError,
    KeyRing,
    build_aad,
    generate_key,
    keyed_hash,
    normalize_phone_in,
)
from dwaar_common.events import CanonicalJsonError, EdgeEvent, canonical_json
from dwaar_common.signing import (
    VerifierRing,
    generate_private_key,
    sign_edge_event,
    verify_edge_event,
)

pytestmark = pytest.mark.req("INV-01", "INV-02")

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _ring(*ids: str, active: str | None = None) -> KeyRing:
    return KeyRing({i: generate_key() for i in ids}, active or ids[0])


# ------------------------------------------------------------------------------------------------
# (8) crypto
# ------------------------------------------------------------------------------------------------
def test_nonces_do_not_repeat_across_many_encryptions() -> None:
    cipher = EnvelopeCipher(_ring("k1"))
    nonces = {cipher.encrypt("x").split(":")[2] for _ in range(60_000)}
    assert len(nonces) == 60_000


def test_aad_binds_ciphertext_to_its_row_and_column() -> None:
    cipher = EnvelopeCipher(_ring("k1"))
    aad = build_aad(uuid.uuid4(), "person_vault", "phone", uuid.uuid4())
    token = cipher.encrypt("+919999900123", aad)
    assert cipher.decrypt(token, aad) == "+919999900123"
    for other in (
        b"",
        build_aad(uuid.uuid4(), "person_vault", "phone", uuid.uuid4()),
        aad + b"x",
        aad[:-1],
    ):
        with pytest.raises(DecryptionError):
            cipher.decrypt(token, other)


def test_aad_parts_cannot_be_shifted_across_field_boundaries() -> None:
    from dwaar_common.crypto import CryptoError

    with pytest.raises(CryptoError):
        build_aad("a|b", "c")
    assert build_aad("ab", "c") != build_aad("a", "bc")
    assert build_aad(None) != build_aad("")  # type: ignore[arg-type]


def test_swapping_the_key_id_inside_a_token_fails_authentication() -> None:
    ring = _ring("k1", "k2")
    cipher = EnvelopeCipher(ring)
    token = cipher.encrypt("secret")
    swapped = token.replace(":k1:", ":k2:", 1)
    with pytest.raises(DecryptionError):
        cipher.decrypt(swapped)


def test_key_rotation_keeps_old_values_decryptable_until_swept() -> None:
    k1 = generate_key()
    ring1 = KeyRing({"k1": k1}, "k1")
    old = EnvelopeCipher(ring1).encrypt("secret", b"aad")
    ring2 = ring1.with_key("k2", generate_key(), activate=True)
    c2 = EnvelopeCipher(ring2)
    assert c2.decrypt(old, b"aad") == "secret"
    assert c2.needs_rotation(old)
    rotated = c2.rotate(old, b"aad")
    assert c2.key_id_of(rotated) == "k2"
    with pytest.raises(DecryptionError):
        c2.rotate(old, b"wrong-aad")  # rotation must not launder a value under the wrong binding
    only_new = EnvelopeCipher(KeyRing({"k2": ring2.get("k2")}, "k2"))
    assert only_new.decrypt(rotated, b"aad") == "secret"
    with pytest.raises(
        DecryptionError
    ):  # decommissioned key: clean error, no plaintext, no other exception type
        only_new.decrypt(old, b"aad")


def test_keyed_hash_requires_a_full_length_key_and_is_deterministic() -> None:
    from dwaar_common.crypto import CryptoError

    with pytest.raises(CryptoError):
        keyed_hash("x", b"short")
    key = generate_key()
    assert keyed_hash("x", key) == keyed_hash(b"x", key) != keyed_hash("y", key)


# ------------------------------------------------------------------------------------------------
# phone normalisation
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw",
    ["+91 99999 00123", "+91-99999-00123", "919999900123", "09999900123", "0091 9999900123", "00 91 99999 00123", "(+91) 99999-00123", " 9999900123 ", "99999.00123", "+91 99999 00123"],
)  # fmt: skip
def test_phone_variants_normalise_to_one_e164_form(raw: str) -> None:
    assert normalize_phone_in(raw) == "+919999900123"


@pytest.mark.parametrize(
    "raw",
    [
        "+91" + "9" + "٩" * 9,  # Arabic-Indic digits after an ASCII lead digit
        "9" + "०" * 9,  # Devanagari digits
        "＋919999900123",  # fullwidth plus
        "９９９９９００１２３",  # fullwidth digits
        "9999900123\u0000",
        "+91 9999900123 ext 4",
        "0919999900123",
        "+91(0)9999900123",
        "+1 9999900123",
        "5999900123",
        "99999001234",
        "",
        "+91",
    ],
)
def test_phone_lookalikes_are_rejected_not_normalised(raw: str) -> None:
    with pytest.raises(InvalidPhoneError):
        normalize_phone_in(raw)


def test_unicode_digit_phone_cannot_mint_a_second_lookup_token_for_the_same_person() -> None:
    """Same SIM, different token: also lets an attacker rotate the rate-limit bucket key."""
    key = generate_key()
    canonical = keyed_hash(normalize_phone_in("9999900123"), key)
    try:
        lookalike = keyed_hash(normalize_phone_in("9" + "٩" * 9), key)
    except InvalidPhoneError:
        return
    assert lookalike == canonical, "a second phone_token for the same number was produced"


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


def test_every_signed_field_is_covered_by_the_signature() -> None:
    key = generate_private_key()
    signed = sign_edge_event(key, _event())
    assert verify_edge_event(key.public_key(), signed)
    mutations: dict[str, Any] = {
        "event_id": uuid.uuid4(),
        "society_id": uuid.uuid4(),
        "device_id": uuid.uuid4(),
        "seq": 8,
        "entity_id": uuid.uuid4(),
        "entity_version": 2,
        "type": "ExitObserved",
        "policy_version": 4,
        "occurred_at": signed.occurred_at + dt.timedelta(milliseconds=1),
        "clock_uncertainty_ms": 5,
        "payload": {"gate": "main", "n": 3},
    }
    for name, value in mutations.items():
        tampered = signed.model_copy(update={name: value})
        assert not verify_edge_event(key.public_key(), tampered), (
            f"tampering with {name} still verifies"
        )
    forged_payload = signed.model_copy(update={"payload": {"gate": "main", "n": 3}})
    from dwaar_common.events import payload_hash

    consistent = forged_payload.model_copy(
        update={"payload_hash": payload_hash(forged_payload.payload)}
    )
    assert not verify_edge_event(key.public_key(), consistent)


def test_sub_millisecond_timestamp_tampering_is_detected() -> None:
    """The signed wire form truncates occurred_at to milliseconds, but the database keeps microseconds. Two
    different stored timestamps therefore share one valid signature."""
    key = generate_private_key()
    signed = sign_edge_event(key, _event())
    later = signed.model_copy(
        update={"occurred_at": signed.occurred_at.replace(microsecond=123999)}
    )
    assert not verify_edge_event(key.public_key(), later)


def test_signature_string_encoding_is_canonical() -> None:
    key = generate_private_key()
    signed = sign_edge_event(key, _event())
    assert signed.signature is not None
    head, last = signed.signature[:-1], signed.signature[-1]
    accepted = [
        ch
        for ch in ALPHABET
        if verify_edge_event(key.public_key(), signed.with_signature(head + ch))
    ]
    assert accepted == [last], (
        f"{len(accepted)} distinct signature strings verify for one signature"
    )


def test_verifier_ring_binds_a_key_to_the_society_or_device_it_may_sign_for() -> None:
    """VerifierRing maps key_id -> public key only. A key registered for a device of society A verifies an
    event that CLAIMS society B (the envelope's society_id/device_id are signed content, not checked against
    the key's owner), so a compromised device key forges events for other tenants unless every caller adds
    its own check."""
    ring = VerifierRing()
    key = generate_private_key()
    ring.add("device-a-key", key.public_key())
    victim_event = sign_edge_event(key, _event())  # claims an arbitrary society / device
    bound = set(inspect.signature(VerifierRing.add).parameters) & {
        "society_id",
        "device_id",
        "scope",
        "owner",
    }
    assert bound or not ring.verify_event("device-a-key", victim_event), "no key-to-tenant binding"


def test_canonical_json_rejects_every_ambiguous_number_and_key() -> None:
    for bad in (
        {"a": 1.0},
        {"a": float("nan")},
        {"a": Decimal("1.0")},
        {1: "x"},
        {"a": {2: "x"}},
        {"a": [1.5]},
        {"a": {1, 2}},
        {"a": b"x"},
    ):
        with pytest.raises((CanonicalJsonError, TypeError)):
            canonical_json(bad)
    assert canonical_json({"a": True}) != canonical_json({"a": 1})
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})
    assert canonical_json({"a": "é"}) != canonical_json({"a": "é"})  # NFC vs NFD stay distinct


def test_event_type_pattern_does_not_admit_a_trailing_newline() -> None:
    with pytest.raises(ValueError):  # noqa: PT011
        _event(type="EntryObserved\n")


# ------------------------------------------------------------------------------------------------
# (10) money
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("text", ["١٢٣.٥٠", "१२३", "１２３", "১২"])
def test_rupee_text_accepts_only_ascii_digits(text: str) -> None:
    with pytest.raises(money.MoneyError):
        money.parse_rupees(text)


def test_percent_text_accepts_only_ascii_digits() -> None:
    with pytest.raises(money.MoneyError):
        money.percent_to_bp("١٢.٥")


@pytest.mark.parametrize("mode", ["banana", "HALF_UP", "", "round", "half-up", None, 0])
def test_unknown_rounding_mode_is_an_error_even_when_the_division_is_exact(mode: Any) -> None:
    """The mode is a configured policy (often straight from a pack). A typo must fail loudly, not silently
    behave as 'nearest' (or, for exact divisions, not even be looked at)."""
    for amount, bp in ((100, 100), (1, 1), (7, 5000)):
        with pytest.raises(money.MoneyError):
            money.apply_bp(amount, bp, mode)


def test_money_never_accepts_floats_or_bools_or_out_of_range_integers() -> None:
    for bad in (1.0, True, Decimal("1.5"), "1", None, 2**63, -(2**63) - 1):
        with pytest.raises(money.MoneyError):
            money.ensure_paise(bad)
    with pytest.raises(money.MoneyError):
        money.mul_int(5, 2.0)  # type: ignore[arg-type]
    with pytest.raises(money.MoneyError):
        money.apply_bp(100, 18.0, "floor")  # type: ignore[arg-type]
    with pytest.raises(money.MoneyRangeError):
        money.add(money.MAX_PAISE, 1)
    with pytest.raises(money.MoneyRangeError):
        money.neg(money.MIN_PAISE)
    with pytest.raises(money.MoneyRangeError):
        money.mul_int(money.MAX_PAISE, 2)
    with pytest.raises(money.MoneyRangeError):
        money.parse_rupees("92233720368547758.08")
    assert money.parse_rupees("92233720368547758.07") == money.MAX_PAISE
    assert money.format_inr(money.MIN_PAISE).startswith("-")
    assert money.paise_to_rupees_str(money.MIN_PAISE).startswith("-")


@settings(max_examples=300, deadline=None)
@given(
    total=st.integers(min_value=-(2**62), max_value=2**62),
    weights=st.lists(st.integers(min_value=0, max_value=10**12), min_size=1, max_size=12),
)
def test_allocate_always_sums_exactly_and_is_sign_symmetric(total: int, weights: list[int]) -> None:
    if sum(weights) == 0:
        with pytest.raises(money.MoneyError):
            money.allocate(total, weights)
        return
    shares = money.allocate(total, weights)
    assert sum(shares) == total
    assert all(s == 0 for s, w in zip(shares, weights, strict=True) if w == 0)
    assert all(s >= 0 for s in shares) if total >= 0 else all(s <= 0 for s in shares)
    assert money.allocate(-total, weights) == [-s for s in shares]


@settings(max_examples=300, deadline=None)
@given(
    amount=st.integers(min_value=0, max_value=2**50), bp=st.integers(min_value=0, max_value=10**6)
)
def test_rounding_modes_are_sign_symmetric_and_bracketed(amount: int, bp: int) -> None:
    exact_num, den = amount * bp, 10_000
    floor = money.apply_bp(amount, bp, "floor")
    ceil = money.apply_bp(amount, bp, "ceil")
    assert floor <= exact_num / den <= ceil or exact_num // den == floor
    assert ceil - floor in (0, 1)
    for mode in ("half_up", "half_even", "down"):
        pos = money.apply_bp(amount, bp, mode)  # type: ignore[arg-type]
        neg = money.apply_bp(-amount, bp, mode)  # type: ignore[arg-type]
        assert neg == -pos, mode
        assert floor <= pos <= ceil
    assert money.apply_bp(-amount, bp, "ceil") == -floor
