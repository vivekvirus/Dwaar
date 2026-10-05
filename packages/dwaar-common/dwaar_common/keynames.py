"""Field-name classification shared by the log scrubber, the audit masker and event payload hygiene.

REQ: OBS-01 (secrets, OTPs and identifiers never reach logs), PRD 12.4 (masked audit diffs), INV-02
(money must survive the audit and event path).

One classifier, three answers, so a field cannot be redacted in free text but kept as a mapping key (or the
other way round):

* :func:`is_sensitive_key`   the VALUE is a secret or a personal identifier: redact it whatever its type.
* :func:`is_quantity_key`    the value is a money amount or a measured quantity: never content-scrubbed.
* :func:`is_identifier_key`  a number under this name is an identifier (phone, account, card ...): redact
  long digit strings, because an int phone number is indistinguishable from an amount by its digits alone.

Matching is by WORD (snake, kebab or camel case; plurals fold to the singular), never by digit count.
"""

from __future__ import annotations

import re
from typing import Final

_CAMEL: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT: Final = re.compile(r"[^a-z0-9]+")

#: keys that are metadata about a token, not the token itself
ALLOWED_KEYS: Final = frozenset({"society_token", "correlation_id", "request_id", "token_type"})

# Whole words that mark a secret or a personal identifier.
_SENSITIVE_WORDS: Final = frozenset(
    {
        "authorization", "authorisation", "secret", "token", "password", "passwd", "pwd",
        "otp", "cookie", "credential", "passcode", "passphrase", "aadhaar", "aadhar", "phone",
        "mobile", "msisdn", "apikey", "privatekey", "jwt", "bearer", "cvv", "pepper", "salt",
        "dsn", "hmac",
    }
)  # fmt: skip
# Short names that are only secrets when they are the WHOLE key (``pass`` alone, but not ``pass_id``,
# which is a gate pass; ``auth`` alone, but not ``auth_method``).
_SENSITIVE_WHOLE: Final = frozenset(
    {"pin", "pass", "pw", "auth", "sid", "sig", "iban", "ifsc_account"}
)
_SENSITIVE_WHOLE_SQUASHED: Final = frozenset({"accountno", "acctno"})
# Words that make a neighbouring ``key``/``keys`` word key MATERIAL (master_key, pii_keys, signing_key ...).
_KEY_QUALIFIERS: Final = frozenset(
    {
        "master", "hmac", "signing", "sign", "encryption", "encrypt", "decryption", "crypto",
        "secret", "private", "priv", "pii", "api", "access", "auth", "session", "cursor", "jwt",
        "phone", "shared", "symmetric", "wrapping", "kek", "dek", "aes", "pepper", "salt",
        "password", "passphrase", "hs256", "service", "refresh", "csrf", "xsrf", "otp",
    }
)  # fmt: skip
# Substrings of the squashed key (no separators) that are secret on their own.
_SENSITIVE_COMPOUNDS: Final = (
    "apikey", "privatekey", "accountnumber", "bankaccount", "passsecret", "verificationcode",
    "verifycode", "authcode", "otpcode", "smscode", "resetcode", "logincode", "confirmcode",
    "confirmationcode", "securitycode", "accesscode", "mfacode", "2facode", "sessionid",
    "authheader", "masterkey", "hmackey", "signingkey", "encryptionkey", "decryptionkey",
    "secretkey", "piikey", "cursorkey", "databaseurl", "connectionstring", "connstring",
    "dburl", "refreshtoken", "accesstoken", "idtoken", "csrftoken", "xsrftoken",
)  # fmt: skip

# Money and measured quantities: ints, floats and decimal strings under these words are data, not ids.
_QUANTITY_WORDS: Final = frozenset(
    {
        "paise", "amount", "bp", "ms", "seconds", "count", "wh", "litres", "liters", "version",
        "seq", "balance", "total", "size", "bytes", "epoch", "latency", "attempts", "limit",
        "offset", "page", "status", "ttl", "pct", "bps", "quantity", "qty",
        # money vocabulary (ledger, billing, settlement)
        "credit", "debit", "net", "gross", "principal", "interest", "fee", "tds", "gst", "cgst",
        "sgst", "igst", "cess", "tax", "outstanding", "arrears", "settled", "corpus", "penalty",
        "mdr", "cr", "dr", "due", "charge", "rent", "price", "cost", "rate", "paid", "refund",
        "deposit", "subtotal", "discount", "surcharge", "levy", "waiver", "advance", "payable",
        "receivable", "payout", "settlement", "collection", "emi", "premium", "rupee", "rupees",
        "inr", "dues", "opening", "closing",
    }
)  # fmt: skip
# A number stored under one of these names is an identifier, so long digit strings are redacted.
_IDENTIFIER_WORDS: Final = frozenset(
    {
        "contact", "number", "num", "no", "nr", "ref", "reference", "account", "acct", "card",
        "tel", "telephone", "whatsapp", "uid", "ssn", "voter", "licence", "license", "passport",
        "utr", "rrn",
    }
)  # fmt: skip


def key_words(key: str) -> list[str]:
    """Lower-case words of a key: ``masterKey``, ``master_key`` and ``Master-Key`` all give master, key."""
    return [w for w in _SPLIT.split(_CAMEL.sub("_", key).lower()) if w]


def _singular(word: str) -> str:
    return word[:-1] if len(word) > 3 and word.endswith("s") and not word.endswith("ss") else word


def _folded(key: str) -> tuple[list[str], str]:
    """Words of the key with every plural also present in its singular form, and the squashed key."""
    raw = key_words(key)
    words = raw + [_singular(w) for w in raw if _singular(w) != w]
    return words, "".join(raw)


def is_sensitive_key(key: str) -> bool:
    """True if a mapping key, log extra name or ``name=value`` text key denotes a secret or identifier."""
    lowered = key.lower()
    if lowered in ALLOWED_KEYS:
        return False
    words, squashed = _folded(key)
    if not words:
        return False
    if squashed in _SENSITIVE_WHOLE or squashed in _SENSITIVE_WHOLE_SQUASHED:
        return True
    if any(w in _SENSITIVE_WORDS for w in words):
        return True
    if "key" in words and any(w in _KEY_QUALIFIERS for w in words):
        return True
    return any(c in squashed for c in _SENSITIVE_COMPOUNDS)


def is_quantity_key(key: str | None) -> bool:
    """True if the key names a money amount or a measured quantity (never content-scrubbed by digits)."""
    if key is None:
        return False
    words, _ = _folded(key)
    return any(w in _QUANTITY_WORDS for w in words)


def is_identifier_key(key: str | None) -> bool:
    """True if a number under this key is an identifier (phone, account, card, contact ...)."""
    if key is None:
        return False
    words, _ = _folded(key)
    return any(w in _IDENTIFIER_WORDS for w in words)
