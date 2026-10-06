"""Dwaar worker service: the edge policy publisher and the visits expiry/overstay sweep as plain job functions plus Dramatiq actors.

See ``jobs.py`` (the logic), ``actors.py`` (Dramatiq wiring), ``scheduler.py`` (periodic triggers), ``app.py`` (deployment entry point).
"""

__version__ = "0.1.0"
SERVICE_NAME = "dwaar_worker"
