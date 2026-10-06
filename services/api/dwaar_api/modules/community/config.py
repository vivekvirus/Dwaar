"""Community module configuration: object storage, malware scanner, download signing, emergency rate limits.

REQ: COM-04 / SEC-03 / SEC-04 (storage adapter, fail-closed scanner, short-lived signed URLs), COM-05 (rate-limited emergency
broadcast), ARCH-02 (keys from the environment; local and test get a labelled placeholder, other environments answer 503 on
the endpoints that need one), INV-10 (limits are configuration).

Environment variables (to be added to ``.env.example`` by the platform owner; see ADR-0022):

* ``DWAAR_COMMUNITY_STORAGE_DIR``     directory of the LOCAL-DISK object store (simulation=true, development only).
* ``DWAAR_COMMUNITY_DOWNLOAD_KEY``    base64url, 32 bytes: HMAC key of signed download URLs.
* ``DWAAR_COMMUNITY_SCANNER``         ``stub`` selects the LABELLED stub scanner (accepted only in local/test); unset means NO
                                      scanner is configured and every file stays unscanned (fail closed): nothing can be published.
* ``DWAAR_COMMUNITY_DOWNLOAD_TTL``    seconds a signed URL stays valid (default 120, at most 900).
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from dwaar_common.crypto import CryptoError, key_from_b64

from ...core.config import ConfigError, Settings

log = logging.getLogger("dwaar_api.community")

_LOCAL_LABEL: Final = b"dwaar-local-development-only-community-key"
MAX_DOWNLOAD_TTL: Final = 900


@dataclass(frozen=True)
class CommunityConfig:
    storage_dir: Path
    download_key: bytes
    scanner_kind: str  # 'unconfigured' | 'stub'
    simulation: bool
    download_ttl_seconds: int = 120
    max_upload_bytes: int = 10 * 1024 * 1024
    # COM-05: a broadcast is rare and loud. Per actor and per society, tokens per hour.
    emergency_actor_per_hour: int = 3
    emergency_society_per_hour: int = 6

    @classmethod
    def from_environment(
        cls, settings: Settings, environ: Mapping[str, str] | None = None
    ) -> CommunityConfig:
        env = os.environ if environ is None else environ
        simulation = settings.simulation
        try:
            raw = env.get("DWAAR_COMMUNITY_DOWNLOAD_KEY", "").strip()
            if raw:
                key = key_from_b64(raw)
            elif simulation:
                key = hashlib.sha256(_LOCAL_LABEL + b"|download").digest()
            else:
                raise ConfigError("DWAAR_COMMUNITY_DOWNLOAD_KEY is required")
        except CryptoError as exc:
            raise ConfigError(f"invalid community key configuration: {exc}") from None
        scanner = env.get("DWAAR_COMMUNITY_SCANNER", "").strip().lower() or "unconfigured"
        if scanner not in {"unconfigured", "stub"}:
            raise ConfigError("DWAAR_COMMUNITY_SCANNER must be 'stub' or unset")
        if scanner == "stub" and not simulation:
            raise ConfigError(
                "the stub malware scanner is accepted only in local and test environments"
            )
        storage = env.get("DWAAR_COMMUNITY_STORAGE_DIR", "").strip()
        if storage:
            storage_dir = Path(storage)
        elif simulation:
            storage_dir = Path(tempfile.gettempdir()) / "dwaar-community-objects"
        else:
            raise ConfigError(
                "DWAAR_COMMUNITY_STORAGE_DIR is required (no real object store adapter is built yet)"
            )
        try:
            ttl = int(env.get("DWAAR_COMMUNITY_DOWNLOAD_TTL", "120"))
        except ValueError:
            raise ConfigError("DWAAR_COMMUNITY_DOWNLOAD_TTL must be an integer") from None
        if not 5 <= ttl <= MAX_DOWNLOAD_TTL:
            raise ConfigError(
                f"DWAAR_COMMUNITY_DOWNLOAD_TTL must be between 5 and {MAX_DOWNLOAD_TTL} seconds"
            )
        return cls(storage_dir, key, scanner, simulation, download_ttl_seconds=ttl)
