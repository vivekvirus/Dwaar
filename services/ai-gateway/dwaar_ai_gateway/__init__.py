"""Dwaar AI gateway: provider adapters, redaction, injection defence, validated proposals (PRD 10, 11).

REQ: AI-SYS-01..08, G1..G12. This library holds NO database handle and NO credentials other than the provider's own key inside
its adapter; the API module (``dwaar_api.modules.ai``) owns persistence (``ai_runs``, ``action_proposals``) and execution.

HONESTY: with no API key and no GPU in this environment every model path is a deterministic, labelled SIMULATOR
(``simulation=True``). Nothing here measures model quality; the PRD targets are release gates, not results.
"""

__version__ = "0.1.0"
SERVICE_NAME = "dwaar_ai_gateway"
