"""Object storage adapter (COM-04, SEC-04).

REQ: SEC-04 (object storage via server policy; unguessable ids; no permanent access from a URL), SEC-03 (path traversal
protection), ARCH-02 (adapter so a managed store can drop in later), brief 1 (simulators are labelled ``simulation=true``).

``ObjectStore`` is the contract. ``LocalDiskStore`` is the development implementation and says so (``simulation = True``): it is
not a production store. Object keys are 32 random bytes (base64url): unguessable, and unrelated to the society, the document or
the file name; the database maps version -> key, so a key alone is never an access path (downloads need a signed URL issued
after a current access check, and the URL is re-checked when it is used).
"""

from __future__ import annotations

import base64
import os
import re
import secrets
import tempfile
from pathlib import Path
from typing import Final, Protocol

KEY_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]{32,128}\Z")


class StorageError(Exception):
    """The store could not complete the operation (the caller answers 503; no detail leaves the process)."""


class ObjectStore(Protocol):
    simulation: bool
    name: str

    def put(self, data: bytes) -> str:
        """Store bytes under a NEW unguessable key and return it."""
        ...

    def get(self, key: str) -> bytes: ...

    def delete(self, key: str) -> None: ...


def new_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


class LocalDiskStore:
    """Development object store on the local disk. ``simulation = True``: never a production store."""

    simulation = True
    name = "local-disk-simulation"

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def _path(self, key: str) -> Path:
        if not KEY_PATTERN.match(key):
            raise StorageError(
                "invalid object key"
            )  # also rules out '..', '/', and anything not base64url
        return self.root / key[:2] / key

    def put(self, data: bytes) -> str:
        key = new_key()
        path = self._path(key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
        except OSError as exc:
            raise StorageError("could not store the object") from exc
        return key

    def get(self, key: str) -> bytes:
        try:
            return self._path(key).read_bytes()
        except OSError as exc:
            raise StorageError("could not read the object") from exc

    def delete(self, key: str) -> None:
        try:
            self._path(key).unlink(missing_ok=True)
        except OSError as exc:
            raise StorageError("could not delete the object") from exc
