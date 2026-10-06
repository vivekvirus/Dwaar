"""Dwaar society edge gateway.

Encrypted SQLite store (WAL, synchronous=FULL), signed policy snapshots, deterministic local decision engine,
trusted-time clock model, durable outbox + sync client, authenticated local API for guard terminals.
No actuator code: see ``actuator.py`` (simulation-only stub). Decisions: docs/adr/0018-edge-gateway.md.
"""

__version__ = "0.1.0"
SERVICE_NAME = "dwaar_edge"
