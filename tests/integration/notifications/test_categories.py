"""NOTIF-01 and CALL-02: five categories; security and emergency channels never carry ads, launches or unrelated content; DLT SMS, whitelisted URLs.

REQ: NOTIF-01, CALL-02, INV-05 (no commercial push), PRD 17.1 ("Commercial notifications: zero").
"""

from __future__ import annotations

import uuid

import psycopg
import pytest

from dwaar_api.modules.notifications import catalog
from dwaar_api.modules.notifications import categories as cat
from tests.integration.notifications._support import NW

pytestmark = [pytest.mark.req("NOTIF-01", "CALL-02", "INV-05")]
HOSTS = ["links.dwaar.example"]


def _template(**over: object) -> dict[str, object]:
    body: dict[str, object] = {
        "template_key": "approval.request.x", "category": "security_approval", "channel": "push", "language": "en",
        "body_key": "approval.request.body",
    }  # fmt: skip
    body.update(over)
    return body


def test_the_five_categories_exist() -> None:
    assert cat.CATEGORIES == (
        "security_approval",
        "emergency",
        "finance",
        "service_ticket",
        "community_digest",
    )
    assert {"security_approval", "emergency"} == cat.CLEAN_CATEGORIES


@pytest.mark.parametrize("category", ["security_approval", "emergency"])
def test_a_promotional_template_is_rejected_on_the_clean_channels(category: str) -> None:
    prefix = "approval." if category == "security_approval" else "emergency."
    with pytest.raises(cat.ContentRejected) as e:
        cat.validate_template(
            category=category,
            channel="push",
            language="en",
            content_class="promotional",
            body_key=prefix + "x",
        )
    assert e.value.details["reason"] == "promotional_content_on_clean_channel"


@pytest.mark.parametrize(
    "body_key",
    [
        "digest.weekly.body",
        "finance.notice.body",
        "ticket.update.body",
        "approval.link.sms.extra.launch",
    ],
)
def test_unrelated_copy_cannot_ride_the_security_channel(body_key: str) -> None:
    with pytest.raises(cat.ContentRejected) as e:
        cat.validate_template(
            category="emergency",
            channel="push",
            language="en",
            content_class="transactional",
            body_key=body_key,
        )
    assert e.value.details["reason"] == "unrelated_content_on_clean_channel"


def test_every_shipped_default_template_passes_its_own_validator() -> None:
    for t in catalog.DEFAULT_TEMPLATES:
        for lang in cat.LANGUAGES:
            cat.validate_template(
                category=t.category, channel=t.channel, language=lang, content_class=t.content_class, body_key=t.body_key,
                whitelisted_url="https://links.dwaar.example/r" if t.uses_link else None, hosts=HOSTS,
            )  # fmt: skip


def test_every_catalog_key_exists_in_all_three_languages() -> None:
    for lang in cat.LANGUAGES:
        known = cat.catalog(lang)
        missing = [k for k in catalog.all_copy_keys() if k not in known]
        assert missing == [], (lang, missing)


@pytest.mark.parametrize(
    "text",
    [
        "Big offer today",
        "Launch of our new product",
        "Get 20% off",
        "Subscribe now",
        "ऑफर",
        "जाहिरात",
    ],
)
def test_the_last_check_before_a_provider_rejects_promotional_text(text: str) -> None:
    with pytest.raises(cat.ContentRejected):
        cat.assert_sendable(
            category="security_approval", content_class="transactional", text=text, hosts=HOSTS
        )
    cat.assert_sendable(
        category="finance", content_class="service", text="Your bill is ready.", hosts=HOSTS
    )


@pytest.mark.parametrize("url", [
    "http://links.dwaar.example/r/1", "https://evil.example/r/1", "https://links.dwaar.example:8443/r/1", "https://user@links.dwaar.example/r",
    "https://links.dwaar.example/r?x=1", "https://links.dwaar.example/r#frag", "https://links.dwaar.example.evil.example/r", "javascript:alert(1)", "https:///r",
])  # fmt: skip
def test_only_whitelisted_urls_pass(url: str) -> None:
    with pytest.raises(cat.ContentRejected):
        cat.check_url(url, HOSTS)
    assert cat.check_url("https://links.dwaar.example/r/abc", HOSTS)


def test_a_message_with_a_foreign_link_is_refused_even_on_a_service_category() -> None:
    with pytest.raises(cat.ContentRejected):
        cat.assert_sendable(
            category="service_ticket",
            content_class="service",
            text="see https://phish.example/x",
            hosts=HOSTS,
        )


# ------------------------------------------------------------------------------------------------------------ the API and the database
def test_the_template_route_refuses_promotional_security_content(nw: NW) -> None:
    path = nw.s("notification-templates")
    r = nw.call(nw.secretary, "POST", path, json=_template(content_class="promotional"))
    assert (
        r.status_code == 422
        and r.json()["details"]["reason"] == "promotional_content_on_clean_channel"
    )
    r = nw.call(
        nw.secretary,
        "POST",
        path,
        json=_template(category="emergency", body_key="digest.weekly.body"),
    )
    assert (
        r.status_code == 422
        and r.json()["details"]["reason"] == "unrelated_content_on_clean_channel"
    )
    r = nw.call(
        nw.secretary,
        "POST",
        path,
        json=_template(channel="sms", whitelisted_url="https://evil.example/r"),
    )
    assert r.status_code == 422 and r.json()["details"]["reason"] == "url_not_whitelisted"
    r = nw.call(
        nw.secretary,
        "POST",
        path,
        json=_template(dlt_header="DWAARX", dlt_template_id="1107160000000000001"),
    )
    assert (
        r.status_code == 422 and r.json()["details"]["reason"] == "dlt_fields_only_for_sms"
    )  # DLT belongs to SMS only
    assert nw.rows("SELECT count(*) FROM notification_templates") == [(0,)]


def test_a_valid_template_is_created_audited_and_listed_and_duplicates_conflict(nw: NW) -> None:
    path = nw.s("notification-templates")
    r = nw.call(
        nw.secretary, "POST", path, json=_template(template_key="approval.request", language="hi")
    )
    assert r.status_code == 201, r.text
    assert r.json()["sendable"] is True and r.json()["content_class"] == "transactional"
    dup = nw.call(
        nw.secretary, "POST", path, json=_template(template_key="approval.request", language="hi")
    )
    assert dup.status_code == 422 and dup.json()["details"]["reason"] == "already_exists", (
        dup.text
    )  # the platform convention for a per-society name
    sms = nw.call(
        nw.secretary,
        "POST",
        path,
        json=_template(
            channel="sms",
            body_key="approval.link.sms",
            whitelisted_url="https://links.dwaar.example/r",
        ),
    )
    assert (
        sms.status_code == 201
        and sms.json()["dlt_placeholder"] is True
        and sms.json()["sendable"] is False
    )  # CALL-02: a placeholder
    listed = nw.call(nw.secretary, "GET", path).json()
    assert {t["channel"] for t in listed["items"]} == {"push", "sms"}
    assert nw.audit("notification.template.create")


def test_templates_are_secretary_only_to_write_and_not_for_residents_or_guards(nw: NW) -> None:
    owner, _ = nw.household2("A-101")
    path = nw.s("notification-templates")
    for who in (owner, nw.guard, nw.guard_sup):
        assert nw.call(who, "POST", path, json=_template()).status_code == 403
        assert nw.call(who, "GET", path).status_code == 403


def test_the_database_refuses_promotional_security_rows_whatever_the_code_does(nw: NW) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        nw.sql(
            "INSERT INTO notification_templates (society_id, template_key, category, channel, language, content_class, body_key)"
            " VALUES (%s, 'x.y', 'security_approval', 'push', 'en', 'promotional', 'approval.x')",
            (nw.soc.id,),
        )
    with pytest.raises(psycopg.errors.CheckViolation):
        nw.sql(
            "INSERT INTO notification_templates (society_id, template_key, category, channel, language, content_class, body_key)"
            " VALUES (%s, 'x.z', 'emergency', 'push', 'en', 'service', 'emergency.x')",
            (nw.soc.id,),
        )
    nw.sql(
        "INSERT INTO notification_templates (society_id, template_key, category, channel, language, content_class, body_key)"
        " VALUES (%s, 'x.ok', 'community_digest', 'push', 'en', 'promotional', 'digest.x')",
        (nw.soc.id,),
    )  # other categories may differ: only the clean ones are locked
    with pytest.raises(psycopg.errors.CheckViolation):
        nw.sql(
            "INSERT INTO notifications (society_id, category, channel, content_class, recipient_role, recipient_person_id, dedupe_key)"
            " VALUES (%s, 'security_approval', 'push', 'promotional', 'primary', %s, 'forged-promo-row')",
            (nw.soc.id, nw.guard.id),
        )


def test_no_promotional_marker_exists_in_any_security_or_emergency_copy_in_any_language() -> None:
    for lang in cat.LANGUAGES:
        for key, text in cat.catalog(lang).items():
            if key.startswith(("approval.", "emergency.")) and not key.startswith(
                "approval.guard_options"
            ):
                assert cat.promotional_marker(text) is None, (lang, key)


def test_a_dlt_placeholder_becomes_sendable_only_when_the_society_registers_its_ids(nw: NW) -> None:
    sms = nw.call(
        nw.secretary, "POST", nw.s("notification-templates"),
        json=_template(channel="sms", body_key="approval.link.sms", whitelisted_url="https://links.dwaar.example/r"),
    )  # fmt: skip
    assert (
        sms.status_code == 201
        and sms.json()["sendable"] is False
        and sms.json()["dlt_placeholder"] is True
    )
    tid, path = sms.json()["id"], nw.s(f"notification-templates/{sms.json()['id']}/dlt")
    ids = {"dlt_header": "DWAARX", "dlt_template_id": "1107160000000000001"}
    assert nw.call(nw.guard_sup, "PUT", path, json=ids).status_code == 403
    assert (
        nw.call(nw.secretary, "PUT", path, json={**ids, "dlt_header": "dwaar"}).status_code == 400
    )  # a sender header is six capital letters
    assert (
        nw.call(nw.secretary, "PUT", path, json={**ids, "dlt_template_id": "12"}).status_code == 400
    )
    assert (
        nw.call(nw.secretary, "PUT", path, json={**ids, "expected_version": 9}).status_code == 409
    )
    done = nw.call(nw.secretary, "PUT", path, json=ids)
    assert (
        done.status_code == 200
        and done.json()["sendable"] is True
        and done.json()["dlt_placeholder"] is False
        and done.json()["version"] == 2
    )
    assert nw.audit("notification.template.register_dlt")
    push = nw.call(
        nw.secretary,
        "POST",
        nw.s("notification-templates"),
        json=_template(template_key="approval.push2"),
    ).json()
    refused = nw.call(
        nw.secretary, "PUT", nw.s(f"notification-templates/{push['id']}/dlt"), json=ids
    )
    assert (
        refused.status_code == 422
        and refused.json()["details"]["reason"] == "dlt_fields_only_for_sms"
    )
    assert (
        nw.call(
            nw.secretary, "PUT", nw.s(f"notification-templates/{uuid.uuid4()}/dlt"), json=ids
        ).status_code
        == 404
    )
    assert tid
