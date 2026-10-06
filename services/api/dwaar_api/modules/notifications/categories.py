"""Notification categories, the content-class validator for the security and emergency channels, URL whitelist, lock-screen copy.

REQ: NOTIF-01 (five categories; security approval and emergency NEVER carry ads, launches or unrelated content), NOTIF-09 (lock-screen text omits
the full visitor identity and the unit unless the resident opted in), CALL-02 (SMS and its links: DLT header + template, whitelisted URLs
only), INV-05 (no commercial push), PRD 9.4 / 17.1 ("Commercial notifications: zero").

Three layers keep the clean channels clean, none of which relies on a caller behaving:

1. the **database**: ``notification_templates`` and ``notifications`` carry a CHECK that a security or emergency row is ``transactional``;
2. this **validator**: a template for those categories must be ``transactional``, its body key must live in the category's own copy family,
   its copy (every language) must contain no promotional marker and no URL beyond the whitelist;
3. the **sender**: ``assert_sendable`` re-checks the final text just before it is handed to a provider.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Mapping
from functools import lru_cache
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

from dwaar_common.errors import PolicyViolation

SECURITY: Final = "security_approval"
EMERGENCY: Final = "emergency"
FINANCE: Final = "finance"
SERVICE_TICKET: Final = "service_ticket"
DIGEST: Final = "community_digest"
CATEGORIES: Final = (SECURITY, EMERGENCY, FINANCE, SERVICE_TICKET, DIGEST)
#: categories whose channel can NEVER carry anything but its own transactional content (NOTIF-01)
CLEAN_CATEGORIES: Final = frozenset({SECURITY, EMERGENCY})
CONTENT_CLASSES: Final = ("transactional", "service", "promotional")
CHANNELS: Final = ("push", "ivr_call", "sms", "whatsapp")
LANGUAGES: Final = ("en", "hi", "mr")

#: the copy family (key prefix in the ``notifications`` namespace) each clean category may use: nothing unrelated can be attached
ALLOWED_BODY_PREFIX: Final[dict[str, tuple[str, ...]]] = {
    SECURITY: ("approval.",),
    EMERGENCY: ("emergency.", "channel.emergency."),
}

_PROMO: Final = re.compile(
    r"(?i)\b(offers?|discounts?|sale|deals?|cashback|coupons?|promo(?:tion|tional)?|advert(?:s|isement|ising)?|sponsor(?:ed)?|"
    r"launch(?:es|ed|ing)?|new\s+product|limited[\s-]time|buy\s+now|subscribe|upgrade|free\s+trial|win\s+a|lucky\s+draw|"
    r"click\s+here|shop\s+now|download\s+now|referral)\b"
    r"|\d\s?%\s?off|ऑफर|छूट|डिस्काउंट|सेल\b|विज्ञापन|लॉन्च|कैशबैक|कूपन|सवलत|जाहिरात|लाँच|ऑफर्स"
)
_URL: Final = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+|\bwww\.[^\s\"'<>]+")
_PHONE: Final = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")


class ContentRejected(PolicyViolation):
    """A template or message was refused by the content rules (HTTP 422 ``policy_violation`` with a stable reason)."""

    def __init__(self, reason: str, **extra: object) -> None:
        super().__init__(details={"reason": reason, **extra})


# ------------------------------------------------------------------------------------------------------------ URLs (CALL-02)
def link_hosts(environ: Mapping[str, str] | None = None) -> frozenset[str]:
    """The only hosts an SMS / WhatsApp link may point at (configuration; placeholder default on a reserved name)."""
    env = os.environ if environ is None else environ
    raw = env.get("DWAAR_NOTIFICATION_LINK_HOSTS", "").strip() or "links.dwaar.example"
    return frozenset(h.strip().lower() for h in raw.split(",") if h.strip())


def check_url(url: str, hosts: Iterable[str]) -> str:
    """The URL if it is https, on a whitelisted host, without credentials, port, query or fragment; else ``ContentRejected``."""
    allowed = {h.lower() for h in hosts}
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise ContentRejected("url_not_whitelisted") from None
    host = (parts.hostname or "").lower()
    ok = (
        parts.scheme == "https"
        and host in allowed
        and parts.username is None
        and parts.password is None
        and port is None
        and not parts.query
        and not parts.fragment
    )
    if not ok:
        raise ContentRejected("url_not_whitelisted")
    return url


def check_text_urls(text: str, hosts: Iterable[str]) -> None:
    for match in _URL.findall(text):
        check_url(match.rstrip(".,;)"), hosts)


# ------------------------------------------------------------------------------------------------------------ copy
@lru_cache(maxsize=1)
def _catalog_dir() -> Path | None:
    env = os.environ.get("DWAAR_I18N_DIR", "").strip()
    candidates = [Path(env)] if env else []
    here = Path(__file__).resolve()
    candidates += [p / "packages" / "i18n" / "locales" for p in here.parents]
    for c in candidates:
        if (c / "en" / "notifications.json").is_file():
            return c
    return None


@lru_cache(maxsize=8)
def catalog(language: str) -> dict[str, str]:
    """The ``notifications`` namespace of one language (English when missing). ``{}`` when no catalogue is installed."""
    root = _catalog_dir()
    if root is None:
        return {}
    for lang in (language, "en"):
        path = root / lang / "notifications.json"
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            return {str(k): str(v) for k, v in data.items()}
    return {}


def copy(key: str, language: str = "en", **params: object) -> str:
    """The text of ``key`` in ``language`` (falling back to English, then to the key itself) with ``{placeholders}`` filled."""
    text = catalog(language).get(key) or catalog("en").get(key) or key
    for name, value in params.items():
        text = text.replace("{" + name + "}", str(value))
    return text


# ------------------------------------------------------------------------------------------------------------ the validator
def promotional_marker(text: str) -> str | None:
    match = _PROMO.search(text)
    return match.group(0).lower() if match else None


def validate_template(
    *,
    category: str,
    channel: str,
    language: str,
    content_class: str,
    body_key: str,
    whitelisted_url: str | None = None,
    hosts: Iterable[str] | None = None,
) -> None:
    """Raise ``ContentRejected`` unless the template may exist. The rules of NOTIF-01 and CALL-02, in code."""
    if category not in CATEGORIES:
        raise ContentRejected("unknown_category")
    if channel not in CHANNELS or language not in LANGUAGES or content_class not in CONTENT_CLASSES:
        raise ContentRejected("unknown_channel_language_or_class")
    allowed_hosts = frozenset(hosts) if hosts is not None else link_hosts()
    if whitelisted_url is not None:
        check_url(whitelisted_url, allowed_hosts)
    if category in CLEAN_CATEGORIES:
        if content_class != "transactional":
            raise ContentRejected("promotional_content_on_clean_channel", category=category)
        prefixes = ALLOWED_BODY_PREFIX[category]
        if not body_key.startswith(prefixes):
            raise ContentRejected("unrelated_content_on_clean_channel", category=category)
    elif content_class == "promotional" and category in (FINANCE, SERVICE_TICKET):
        raise ContentRejected("promotional_content_on_transactional_category", category=category)
    # the copy itself, in every language, is judged too: a key that merely LOOKS related cannot smuggle an advert in
    for lang in LANGUAGES:
        text = catalog(lang).get(body_key)
        if text is None:
            continue
        if category in CLEAN_CATEGORIES:
            marker = promotional_marker(text)
            if marker is not None:
                raise ContentRejected("promotional_content_on_clean_channel", category=category)
            check_text_urls(text, allowed_hosts)


def assert_sendable(
    *,
    category: str,
    content_class: str,
    text: str,
    title: str | None = None,
    hosts: Iterable[str] | None = None,
) -> None:
    """The last check before a provider sees the message: clean categories carry no promotional marker, only whitelisted links."""
    if category in CLEAN_CATEGORIES:
        if content_class != "transactional":
            raise ContentRejected("promotional_content_on_clean_channel", category=category)
        for part in (title or "", text):
            if promotional_marker(part) is not None:
                raise ContentRejected("promotional_content_on_clean_channel", category=category)
    check_text_urls(
        f"{title or ''} {text}", frozenset(hosts) if hosts is not None else link_hosts()
    )


# ------------------------------------------------------------------------------------------------------------ lock screen
def lockscreen_copy(
    *, language: str, identity_opt_in: bool, visitor: str | None, unit: str | None
) -> tuple[str, str, bool]:
    """``(title, body, carries_identity)`` of the push the OS may show on a locked phone (NOTIF-09).

    Without the resident's opt-in neither the visitor's name nor the unit is in the text. With it, both are. The result says which it was, so
    the notification row records it truthfully.
    """
    if identity_opt_in and visitor and unit:
        return (
            copy("approval.request.title", language),
            copy("approval.request.body", language, visitor=visitor, unit=unit),
            True,
        )
    return (
        copy("approval.request.lockscreen.title", language),
        copy("approval.request.lockscreen.body", language),
        False,
    )


def mask_phone_like(text: str) -> str:
    """Defence in depth for logs and views: anything shaped like an Indian mobile number is replaced."""
    return _PHONE.sub("[phone]", text)


def contains_phone_like(text: str) -> bool:
    return _PHONE.search(text) is not None
