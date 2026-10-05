"""Verification-case state machine (IAM-07) as pure data: testable without a database.

REQ: IAM-07 (requested -> evidence_pending -> society_review -> verified / rejected / appealed -> inactive; reasons
visible to the applicant; appeals reviewed by someone other than the original decision-maker), IAM-05 (a dispute is a
review state; only an explicit human decision ends occupancy), IAM-12.
"""

from __future__ import annotations

from typing import Final

from dwaar_common.errors import PolicyViolation

STATES: Final = (
    "requested", "evidence_pending", "society_review", "verified", "rejected", "appealed", "inactive",
)  # fmt: skip
APPLICANT_ACTIONS: Final = frozenset({"submit_evidence", "appeal", "leave"})
REVIEWER_ACTIONS: Final = frozenset(
    {"request_evidence", "start_review", "verify", "reject", "deactivate"}
)
REASON_REQUIRED: Final = frozenset({"request_evidence", "reject", "deactivate", "appeal"})

#: (state, action) -> next state. ``appeal`` opens a NEW case in state ``appealed`` (the rejected one stays rejected).
TRANSITIONS: Final[dict[tuple[str, str], str]] = {
    ("requested", "request_evidence"): "evidence_pending",
    ("requested", "start_review"): "society_review",
    ("requested", "reject"): "rejected",
    ("evidence_pending", "submit_evidence"): "society_review",
    ("evidence_pending", "reject"): "rejected",
    ("society_review", "request_evidence"): "evidence_pending",
    ("society_review", "verify"): "verified",
    ("society_review", "reject"): "rejected",
    ("rejected", "appeal"): "appealed",
    ("appealed", "verify"): "verified",
    ("appealed", "reject"): "rejected",
    ("verified", "deactivate"): "inactive",
    ("verified", "leave"): "inactive",
}
TERMINAL: Final = frozenset({"inactive"})
OPEN_STATES: Final = frozenset({"requested", "evidence_pending", "society_review", "appealed"})

#: case kind for each membership kind when someone applies
CASE_KIND: Final = {
    "owner": "ownership_claim",
    "joint_owner": "ownership_claim",
    "tenant": "tenant_onboarding",
    "family": "household_join",
    "staff": "staff_onboarding",
}
#: membership kinds whose claims only a society-wide reviewer (secretary) may decide
SOCIETY_ONLY_KINDS: Final = frozenset({"owner", "joint_owner", "staff"})
APPLICANT_KINDS: Final = (
    "owner",
    "joint_owner",
    "tenant",
    "family",
)  # staff are onboarded by the society


def next_state(state: str, action: str, *, case_kind: str = "household_join") -> str:
    """The state after ``action``, or ``PolicyViolation(invalid_transition)``.

    A dispute case (IAM-05) has its own small graph: start review, uphold the membership (verify) or END occupancy
    explicitly (deactivate, with a reason). It can never be 'rejected' or resolved by a bare timer.
    """
    if case_kind == "dispute":
        allowed = {
            ("requested", "start_review"): "society_review",
            ("society_review", "verify"): "verified",
            ("verified", "deactivate"): "inactive",
            ("society_review", "deactivate"): "inactive",
        }
        target = allowed.get((state, action))
    else:
        target = TRANSITIONS.get((state, action))
    if target is None:
        raise PolicyViolation(
            details={"reason": "invalid_transition", "state": state, "action": action}
        )
    return target
