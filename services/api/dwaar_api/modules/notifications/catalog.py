"""Default template catalog and the per-manufacturer diagnostic guidance served for the on-device onboarding diagnostic.

REQ: NOTIF-01 (templates per category), NOTIF-06 (on-device diagnostic at onboarding; manufacturer-specific guidance for Xiaomi/HyperOS,
Oppo/ColorOS, Vivo/Funtouch, Samsung and iOS Focus; NO claim that a battery exemption guarantees delivery; NO fake incoming-call UI to bypass
platform rules), CALL-02 (DLT header and template id are PLACEHOLDERS until the society registers them), AI-R06.

The catalog holds KEYS of the ``notifications`` i18n namespace, never prose: clients render in the resident's language. The guidance is data,
versioned by ``GUIDANCE_VERSION``; steps name the setting, they do not promise an outcome. The wording of every step is machine-drafted in hi/mr
and awaits human review (packages/i18n/review_status.json).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from . import categories as cat

GUIDANCE_VERSION: Final = "2026.1"
GUARD_RULES_KEY: Final = "diag.disclaimer.no_guarantee"
#: constants the API states in every guidance answer so no client can present them otherwise
GUIDANCE_RULES: Final[dict[str, Any]] = {
    "battery_exemption_guarantees_delivery": False,
    "fake_incoming_call_ui": False,
    "disclaimer_key": "diag.disclaimer.no_guarantee",
}


@dataclass(frozen=True)
class DefaultTemplate:
    template_key: str
    category: str
    channel: str
    content_class: str
    body_key: str
    uses_link: bool = False


DEFAULT_TEMPLATES: Final[tuple[DefaultTemplate, ...]] = (
    DefaultTemplate(
        "approval.request", cat.SECURITY, "push", "transactional", "approval.request.body"
    ),
    DefaultTemplate(
        "approval.ivr", cat.SECURITY, "ivr_call", "transactional", "approval.ivr.prompt"
    ),
    DefaultTemplate(
        "approval.link", cat.SECURITY, "sms", "transactional", "approval.link.sms", uses_link=True
    ),
    DefaultTemplate(
        "approval.link",
        cat.SECURITY,
        "whatsapp",
        "transactional",
        "approval.link.whatsapp",
        uses_link=True,
    ),
    DefaultTemplate(
        "emergency.alert", cat.EMERGENCY, "push", "transactional", "emergency.alert.body"
    ),
    DefaultTemplate("finance.notice", cat.FINANCE, "push", "transactional", "finance.notice.body"),
    DefaultTemplate("ticket.update", cat.SERVICE_TICKET, "push", "service", "ticket.update.body"),
    DefaultTemplate("digest.weekly", cat.DIGEST, "push", "service", "digest.weekly.body"),
)

LINK_PATH: Final = "/r"

# ------------------------------------------------------------------------------------------------------------ guidance (NOTIF-06)
#: manufacturer code -> (operating-system family label for the title, ordered steps (id, i18n key))
_STEPS: Final[dict[str, tuple[str, tuple[tuple[str, str], ...]]]] = {
    "xiaomi": (
        "HyperOS / MIUI",
        (
            ("notification_permission", "diag.common.permission"),
            ("autostart", "diag.xiaomi.autostart"),
            ("battery_saver", "diag.xiaomi.battery"),
            ("lock_in_recents", "diag.xiaomi.lock_recents"),
            ("test_push", "diag.common.test_push"),
        ),
    ),
    "oppo": (
        "ColorOS",
        (
            ("notification_permission", "diag.common.permission"),
            ("app_launch", "diag.oppo.app_launch"),
            ("battery", "diag.oppo.battery"),
            ("test_push", "diag.common.test_push"),
        ),
    ),
    "vivo": (
        "Funtouch OS",
        (
            ("notification_permission", "diag.common.permission"),
            ("autostart", "diag.vivo.autostart"),
            ("background_power", "diag.vivo.background_power"),
            ("test_push", "diag.common.test_push"),
        ),
    ),
    "samsung": (
        "One UI",
        (
            ("notification_permission", "diag.common.permission"),
            ("sleeping_apps", "diag.samsung.sleeping_apps"),
            ("battery", "diag.samsung.battery"),
            ("test_push", "diag.common.test_push"),
        ),
    ),
    "apple": (
        "iOS",
        (
            ("notification_permission", "diag.common.permission"),
            ("focus", "diag.apple.focus_allow"),
            ("time_sensitive", "diag.apple.time_sensitive"),
            ("test_push", "diag.common.test_push"),
        ),
    ),
    "other": (
        "Android",
        (
            ("notification_permission", "diag.common.permission"),
            ("battery", "diag.common.battery"),
            ("test_push", "diag.common.test_push"),
        ),
    ),
}
MANUFACTURERS: Final = tuple(_STEPS)


def normalise_manufacturer(raw: str | None) -> str:
    """Map what a phone reports (``Xiaomi``, ``Redmi``, ``realme``, ``Apple`` ...) to a guidance family. Unknown -> ``other``."""
    value = (raw or "").strip().lower()
    table = {
        "xiaomi": "xiaomi", "redmi": "xiaomi", "poco": "xiaomi",
        "oppo": "oppo", "realme": "oppo", "oneplus": "oppo",
        "vivo": "vivo", "iqoo": "vivo",
        "samsung": "samsung",
        "apple": "apple", "iphone": "apple", "ios": "apple",
    }  # fmt: skip
    return table.get(value, "other")


def guidance_for(manufacturer: str) -> dict[str, Any]:
    family = normalise_manufacturer(manufacturer)
    label, steps = _STEPS[family]
    return {
        "version": GUIDANCE_VERSION,
        "manufacturer": family,
        "os_family": label,
        "steps": [
            {"id": sid, "text_key": key, "order": i + 1} for i, (sid, key) in enumerate(steps)
        ],
        "rules": dict(GUIDANCE_RULES),
    }


def all_guidance() -> list[dict[str, Any]]:
    return [guidance_for(m) for m in MANUFACTURERS]


def all_copy_keys() -> set[str]:
    """Every i18n key this module refers to (a test checks that all exist in en, hi and mr)."""
    keys = {t.body_key for t in DEFAULT_TEMPLATES} | {GUIDANCE_RULES["disclaimer_key"]}
    for _label, steps in _STEPS.values():
        keys |= {k for _sid, k in steps}
    return keys


# ------------------------------------------------------------------------------------------------------------ diagnostic verdict
def verdict(*, permission: str, battery: str, focus: str, test_push: str) -> tuple[str, list[str]]:
    """``(verdict, problem step ids)``. NEVER "delivery guaranteed": the best answer is ``no_problem_found`` for THIS test."""
    problems: list[str] = []
    if permission == "denied":
        problems.append("notification_permission")
    if battery == "optimised":
        problems.append("battery")
    if focus == "yes":
        problems.append("focus")
    if test_push == "not_received":
        problems.append("test_push")
    if problems:
        return "needs_attention", problems
    if permission == "granted" and test_push == "received":
        return "no_problem_found", []
    return "cannot_tell", []
