import pytest
from hypothesis import given
from hypothesis import strategies as st

from dwaar_common.crypto import (
    CryptoError,
    DecryptionError,
    EnvelopeCipher,
    InvalidPhoneError,
    KeyRing,
    UnknownKeyError,
    build_aad,
    generate_key,
    key_to_b64,
    keyed_hash,
    normalize_phone_in,
)


def ring(*ids: str, active: str | None = None) -> KeyRing:
    return KeyRing({i: generate_key() for i in ids}, active or ids[0])


def test_roundtrip_and_format() -> None:
    cipher = EnvelopeCipher(ring("k1"))
    token = cipher.encrypt("+919999900123", b"aad")
    parts = token.split(":")
    assert parts[0] == "v1"
    assert parts[1] == "k1"
    assert len(parts) == 4
    assert "9999900123" not in token
    assert cipher.decrypt(token, b"aad") == "+919999900123"


@given(st.text(max_size=200), st.binary(max_size=50))
def test_roundtrip_property(plaintext: str, aad: bytes) -> None:
    cipher = EnvelopeCipher(ring("k1"))
    assert cipher.decrypt(cipher.encrypt(plaintext, aad), aad) == plaintext


def test_nonce_is_random_per_encryption() -> None:
    cipher = EnvelopeCipher(ring("k1"))
    assert cipher.encrypt("same", b"a") != cipher.encrypt("same", b"a")


def test_aad_mismatch_fails() -> None:
    cipher = EnvelopeCipher(ring("k1"))
    token = cipher.encrypt("secret", build_aad("soc-1", "person_vault", "phone", "row-1"))
    with pytest.raises(DecryptionError):
        cipher.decrypt(token, build_aad("soc-2", "person_vault", "phone", "row-1"))
    with pytest.raises(DecryptionError):
        cipher.decrypt(token, b"")


def test_tamper_fails() -> None:
    cipher = EnvelopeCipher(ring("k1"))
    token = cipher.encrypt("secret")
    head, nonce, body = token.rsplit(":", 2)
    flipped = body[:-2] + ("AA" if not body.endswith("AA") else "BB")
    for bad in [
        f"{head}:{nonce}:{flipped}",
        f"{head}:{body}:{nonce}",
        "v1:k1:AAAA:AAAA",
        "garbage",
        "v2:k1:a:b",
        "",
    ]:
        with pytest.raises(DecryptionError):
            cipher.decrypt(bad)


def test_wrong_key_with_same_id_fails_and_unknown_key_reported() -> None:
    token = EnvelopeCipher(ring("k1")).encrypt("secret")
    with pytest.raises(DecryptionError):
        EnvelopeCipher(ring("k1")).decrypt(token)
    with pytest.raises(UnknownKeyError):
        EnvelopeCipher(ring("k2")).decrypt(token)


def test_rotation_workflow() -> None:
    k1, k2 = generate_key(), generate_key()
    ring1 = KeyRing({"k1": k1}, "k1")
    old = EnvelopeCipher(ring1).encrypt("value", b"aad")
    ring2 = ring1.with_key("k2", k2, activate=True)
    cipher = EnvelopeCipher(ring2)
    assert cipher.decrypt(old, b"aad") == "value"  # old key still decrypts
    assert cipher.needs_rotation(old)
    new = cipher.rotate(old, b"aad")
    assert new != old
    assert cipher.key_id_of(new) == "k2"
    assert not cipher.needs_rotation(new)
    assert cipher.rotate(new, b"aad") == new
    assert cipher.decrypt(new, b"aad") == "value"
    # once rotated, k1 can be dropped
    only_k2 = EnvelopeCipher(KeyRing({"k2": k2}, "k2"))
    assert only_k2.decrypt(new, b"aad") == "value"
    with pytest.raises(UnknownKeyError):
        only_k2.decrypt(old, b"aad")
    with pytest.raises(DecryptionError):
        cipher.rotate(old, b"wrong-aad")


def test_keyring_validation_and_repr() -> None:
    with pytest.raises(CryptoError):
        KeyRing({}, "k1")
    with pytest.raises(CryptoError):
        KeyRing({"k1": b"short"}, "k1")
    with pytest.raises(CryptoError):
        KeyRing({"bad id": generate_key()}, "bad id")
    with pytest.raises(CryptoError):
        KeyRing({"k1": generate_key()}, "k2")
    key = generate_key()
    text = repr(KeyRing({"k1": key}, "k1"))
    assert key_to_b64(key) not in text
    assert "k1" in text


def test_keyring_from_env_value(monkeypatch: pytest.MonkeyPatch) -> None:
    a, b = generate_key(), generate_key()
    value = f"k1={key_to_b64(a)},k2={key_to_b64(b)}"
    parsed = KeyRing.from_env_value(value, "k2")
    assert parsed.key_ids == ["k1", "k2"]
    assert parsed.active_key_id == "k2"
    monkeypatch.setenv("DWAAR_PII_KEYS", value)
    monkeypatch.setenv("DWAAR_PII_ACTIVE_KEY_ID", "k1")
    assert KeyRing.from_env().active_key_id == "k1"
    with pytest.raises(CryptoError):
        KeyRing.from_env_value("k1", "k1")
    monkeypatch.delenv("DWAAR_PII_KEYS")
    with pytest.raises(CryptoError):
        KeyRing.from_env()


def test_build_aad() -> None:
    assert build_aad("a", 1, "c") == b"dwaar-aad|a|1|c"
    with pytest.raises(CryptoError):
        build_aad("a|b")


def test_keyed_hash_is_deterministic_keyed_and_hex() -> None:
    k1, k2 = generate_key(), generate_key()
    h = keyed_hash("+919999900123", k1, purpose="phone_token")
    assert h == keyed_hash("+919999900123", k1, purpose="phone_token")
    assert h != keyed_hash("+919999900123", k2, purpose="phone_token")
    assert h != keyed_hash("+919999900124", k1, purpose="phone_token")
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)
    assert keyed_hash("x", k1, purpose="p") == keyed_hash(b"x", k1, purpose="p")
    with pytest.raises(CryptoError):
        keyed_hash("x", b"short", purpose="p")


def test_keyed_hash_is_domain_separated_by_purpose() -> None:
    key = generate_key()
    assert keyed_hash("x", key, purpose="phone_token") != keyed_hash("x", key, purpose="otp_hash")
    for bad in ("", "Phone", "a b", "x\n", "1abc", "a" * 65):
        with pytest.raises(CryptoError):
            keyed_hash("x", key, purpose=bad)


def test_keyed_hash_known_vector() -> None:
    """Known answer: HMAC(HMAC(key, b'dwaar-keyed-hash/v1|' + purpose), data), computed independently."""
    import hashlib
    import hmac

    key = bytes(range(32))
    subkey = hmac.new(key, b"dwaar-keyed-hash/v1|phone_token", hashlib.sha256).digest()
    expected = hmac.new(subkey, b"data", hashlib.sha256).hexdigest()
    assert keyed_hash("data", key, purpose="phone_token") == expected


@pytest.mark.parametrize(
    "raw",
    [
        "+91 99999 00123", "+91-99999-00123", "919999900123", "09999900123", "9999900123",
        "0091 9999900123", "(+91) 99999 00123", " 99999 00123 ", "+919999900123",
    ],
)  # fmt: skip
def test_normalize_phone_valid(raw: str) -> None:
    assert normalize_phone_in(raw) == "+919999900123"


@pytest.mark.parametrize(
    "raw",
    ["", "12345", "5999900123", "+1 202 555 0100", "+9199999001", "99999001234", "abcdefghij",
     "+91 5999900123", "00999900123"],
)  # fmt: skip
def test_normalize_phone_invalid(raw: str) -> None:
    with pytest.raises(InvalidPhoneError):
        normalize_phone_in(raw)


def test_normalize_phone_rejects_non_str() -> None:
    with pytest.raises(InvalidPhoneError):
        normalize_phone_in(9999900123)  # type: ignore[arg-type]


# ------------------------------------------------------------------ fix round 1 (F22)


def test_unicode_digits_never_normalise_to_a_phone_number() -> None:
    from dwaar_common.crypto import InvalidPhoneError, normalize_phone_in

    for lookalike in (
        "9" + "\u0669" * 9,
        "9" + "\u0966" * 9,
        "+91" + "9" + "\u0669" * 9,
        "\uff19\uff19\uff19\uff19\uff19\uff10\uff10\uff11\uff12\uff13",
    ):
        with pytest.raises(InvalidPhoneError):
            normalize_phone_in(lookalike)
    assert normalize_phone_in("99999 00123") == "+919999900123"
