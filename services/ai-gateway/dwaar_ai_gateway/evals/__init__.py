"""Evaluation harnesses (PRD 11.3). Every report states that targets are release gates, NOT achieved results, and that the simulator
provider measures no model quality."""

DISCLAIMER_GATES = "Targets are release gates, NOT achieved results."
DISCLAIMER_SIMULATOR = (
    "Simulator provider: no model quality is measured (rules and templates, not a language model)."
)


def banner() -> str:
    return f"{DISCLAIMER_GATES}\n{DISCLAIMER_SIMULATOR}"
