"""PII redaction (AI-SYS-05, PRIV-14, G6): tokenise before the model, re-identify only for the authorised caller; golden-set gate."""

from __future__ import annotations

import pytest

from dwaar_ai_gateway import pii
from dwaar_ai_gateway.evals import pii_eval

pytestmark = pytest.mark.req("AI-SYS-05", "PRIV-14")


def test_golden_set_is_pinned_and_has_the_prd_size() -> None:
    rows = pii_eval.load()
    assert len(rows) == 500  # PRD 11.3: 500 samples with Indian identifiers
    assert pii_eval.manifest_hash_ok(), (
        "the frozen golden set was edited: publish a new version instead (build_golden.py)"
    )
    kinds = {sp["type"] for r in rows for sp in r["spans"]}
    assert kinds == {"phone", "aadhaar", "pan", "gstin", "account", "ifsc", "email", "plate"}
    assert {r["lang"] for r in rows} == {"en", "hi", "mr"}
    assert any(r["devanagari_digits"] for r in rows)


def test_measured_recall_and_false_positive_rate_on_the_golden_set() -> None:
    """The PRD target (recall >= 99%) is a RELEASE GATE. This asserts the MEASURED numbers, and prints them for the report."""
    rep = pii_eval.run()
    print(rep.render())  # noqa: T201
    assert rep.identifiers >= 500
    assert rep.recall >= pii_eval.TARGET_RECALL, rep.render()
    assert rep.fpr <= 0.02, (
        rep.render()
    )  # false positives on decoys (amounts, dates, unit labels, UTR ...)
    assert rep.spurious == 0
    assert "NOT achieved results" in rep.render() or "NOT" in rep.render()


def test_a_second_unseen_sample_does_not_fall_below_the_gate() -> None:
    """Same generator, another seed: the redactor was fixed against v1 misses, so v1 is no longer held-out. This set was generated and
    measured ONCE without any change to the redactor afterwards."""
    from dwaar_ai_gateway.paths import evals_root

    path = evals_root() / "pii" / "golden_unseen_seed20261107.jsonl"
    rep = pii_eval.run(path)
    assert rep.sha_ok
    assert rep.recall >= pii_eval.TARGET_RECALL, rep.render()


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("call +91 99999 00123 now", "phone"),
        ("call ९९९९९००१२३ now", "phone"),
        ("Aadhaar 2345 6789 0123", "aadhaar"),
        ("आधार २३४५-६७८९-०१२३", "aadhaar"),
        ("PAN ABCDE1234F", "pan"),
        ("GSTIN 27ABCDE1234F1Z5", "gstin"),
        ("A/c no 123456789012 IFSC HDFC0001234", "account"),
        ("mail asha.k@example.in", "email"),
        ("car MH 12 AB 1234", "plate"),
    ],
)
def test_each_identifier_kind_is_tokenised(text: str, kind: str) -> None:
    vault = pii.TokenVault()
    out = pii.redact(text, vault)
    assert out.detections, text
    assert (
        "99999" not in out.text
        and "ABCDE1234F" not in out.text
        and "27ABCDE" not in out.text
        and "asha.k" not in out.text
    )
    assert "⟦" in out.text
    assert sum(vault.counts.values()) >= 1


def test_plain_numbers_and_labels_are_left_alone() -> None:
    for text in (
        "Maintenance of A-101 is ₹8,000 due 05/10/2026",
        "Invoice INV-2026-000123 for FY 2026-27",
        "PIN 411014, OTP 482913, 12.5 kL",
        "UTR 398957137673",
    ):
        assert pii.detect(text) == [], text


def test_uuids_are_never_personal_data() -> None:
    assert pii.detect("id 0192f3a1-6b2d-7c00-8e4f-1a2b3c4d5e6f") == []


def test_reidentification_only_for_the_authorised_caller_and_only_own_tokens() -> None:
    v1, v2 = pii.TokenVault(), pii.TokenVault()
    red = pii.redact("phone 9999900123", v1)
    assert v1.reidentify(red.text, authorised=False) == red.text
    assert "9999900123" in v1.reidentify(red.text, authorised=True)
    assert (
        v2.reidentify(red.text, authorised=True) == red.text
    )  # another request's vault cannot open it
    assert (
        v1.reidentify("⟦PHONE:ffffff:1⟧", authorised=True) == "⟦PHONE:ffffff:1⟧"
    )  # forged token stays opaque
    assert not v1.has_token("⟦PHONE:ffffff:1⟧")


def test_the_same_value_gets_the_same_token_within_a_request() -> None:
    v = pii.TokenVault()
    a = pii.redact("call 9999900123 or +91 99999 00123", v)
    assert len(set(pii._TOKEN.findall(a.text))) == 1


def test_leaked_values_flags_identifiers_the_request_never_sent() -> None:
    v = pii.TokenVault()
    pii.redact("mine is 9999900123", v)
    assert pii.leaked_values("reach 99999 00123", v.values()) == []
    assert pii.leaked_values("neighbour 6666600456", v.values()) == ["phone"]
