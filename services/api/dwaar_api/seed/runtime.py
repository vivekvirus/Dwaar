"""The seed runtime: the refusal rule, database access with the REAL role and RLS context, and the person registry.

REQ: BUILD_BRIEF 4 (no secrets, simulators only in local), BUILD_BRIEF 7 (demo logins only in synthetic development),
ADR-0004 (the API role and the society context are the only way to write society data), ADR-0005 (domain change + audit +
outbox in one transaction: the seed calls the SAME service functions the API routes call).

Roles used: ``dwaar_app`` (``DWAAR_DATABASE_URL``) for every domain write, with ``app.society_id`` / ``app.person_id`` /
``app.actor_role`` set per transaction exactly as a request would; ``dwaar_owner`` (``DWAAR_DATABASE_OWNER_URL``) ONLY to
load the shipped legal and tax packs into the global reference tables (the documented operations path, ADR-0010 #2/#6).
Nothing here bypasses row-level security, and nothing writes society data without its audit row.
"""

from __future__ import annotations

import logging
import sys
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field

from sqlalchemy import Connection, Engine, create_engine, text

from dwaar_common.crypto import EnvelopeCipher
from dwaar_common.errors import DwaarError
from dwaar_common.ids import uuid7

from ..core.config import ConfigError, Settings, load_settings
from ..core.db import Database, RequestContext, to_sqlalchemy_url
from ..modules.identity import crypto, store
from ..modules.identity.config import IdentityConfig
from .dataset import Person
from .ids import deterministic_ids, scoped_uuid
from .people import by_key

log = logging.getLogger("dwaar_api.seed")


def out(line: str = "") -> None:
    """Console output of the seed CLI (a tool, not the API: no log pipeline involved)."""
    sys.stdout.write(line + "\n")


class SeedRefused(Exception):
    """The seed will not run here."""


def require_local(environ: Mapping[str, str]) -> None:
    """Refuse unless ``DWAAR_ENV`` is exactly ``local`` (not test, staging or production, not unset)."""
    env = (environ.get("DWAAR_ENV") or "").strip().lower()
    if env != "local":
        raise SeedRefused(
            f"refusing to seed: DWAAR_ENV is {env or 'unset'!r}; the synthetic dataset and its demo logins exist only "
            "for DWAAR_ENV=local (never staging or production)"
        )


@dataclass
class SocietyRef:
    key: str
    id: uuid.UUID
    blocks: dict[str, uuid.UUID] = field(default_factory=dict)
    units: dict[tuple[str, str], uuid.UUID] = field(default_factory=dict)

    def unit(self, block: str, label: str) -> uuid.UUID:
        return self.units[(block, label)]


@dataclass
class SeedContext:
    db: Database
    settings: Settings
    config: IdentityConfig
    owner_url: str | None
    say: Callable[[str], None] = out
    counts: dict[str, int] = field(default_factory=dict)
    _people: dict[str, uuid.UUID] = field(default_factory=dict)
    _societies: dict[str, SocietyRef] = field(default_factory=dict)

    # ------------------------------------------------------------------------------------------ construction
    @classmethod
    def create(cls, environ: Mapping[str, str], *, say: Callable[[str], None] = out) -> SeedContext:
        require_local(environ)
        try:
            settings = load_settings(environ)
            config = IdentityConfig.from_environment(settings, environ)
        except ConfigError as exc:
            raise SeedRefused(f"configuration problem: {exc}") from None
        if not settings.simulation:  # defence in depth: local always allows simulators
            raise SeedRefused("simulators are not allowed in this environment")
        owner = environ.get("DWAAR_DATABASE_OWNER_URL") or None
        return cls(Database.from_settings(settings), settings, config, owner, say)

    def close(self) -> None:
        self.db.dispose()

    @property
    def cipher(self) -> EnvelopeCipher:
        return self.config.cipher

    # ------------------------------------------------------------------------------------------ bookkeeping
    def count(self, what: str, n: int = 1) -> None:
        self.counts[what] = self.counts.get(what, 0) + n

    def owner_engine(self) -> Engine:
        if not self.owner_url:
            raise SeedRefused("DWAAR_DATABASE_OWNER_URL is needed to load the legal and tax packs")
        return create_engine(to_sqlalchemy_url(self.owner_url))

    # ------------------------------------------------------------------------------------------ transactions
    @contextmanager
    def tx(
        self,
        scope: str,
        *,
        society: uuid.UUID | None = None,
        person: uuid.UUID | None = None,
        role: str | None = None,
    ) -> Iterator[tuple[Connection, RequestContext]]:
        """One transaction as ``dwaar_app`` with the RLS context of a request; ids minted inside are deterministic."""
        with deterministic_ids(scope):
            ctx = RequestContext(society, person, role, uuid7())
            with self.db.app_tx(ctx) as conn:
                yield conn, ctx

    # ------------------------------------------------------------------------------------------ people
    def person(self, key: str) -> uuid.UUID:
        """The person id for a seed person key, creating the person (stub, number NOT proven) on first use."""
        if key not in self._people:
            self._people[key] = self.ensure_person(by_key()[key])
        return self._people[key]

    def ensure_person(self, spec: Person) -> uuid.UUID:
        e164 = crypto.normalise_phone(spec.phone)
        token = crypto.phone_token(self.config, e164)
        new_id = scoped_uuid(f"person:{spec.key}")
        enc = self.cipher.encrypt(e164, crypto.vault_aad(new_id, "phone"))
        with self.db.app_tx(RequestContext(person_id=new_id)) as conn:
            known = store.person_profile(conn, new_id) is not None
        with self.db.app_tx(
            RequestContext(request_id=scoped_uuid(f"person-req:{spec.key}"))
        ) as conn:
            pid = store.ensure_person(
                conn, new_id=new_id, token=token, phone_enc=enc, display_name=spec.name
            )
        if not known and pid == new_id:
            self.count("persons_created")
            if spec.language != "en":
                with self.db.app_tx(RequestContext(person_id=pid)) as conn:
                    store.update_profile(conn, pid, spec.name, spec.language)
        else:
            self.count("persons_existing")
        return pid

    # ------------------------------------------------------------------------------------------ societies
    def society(self, key: str) -> SocietyRef:
        """The society as it is in the database now (loaded once per run, after the organisation step)."""
        if key not in self._societies:
            self._societies[key] = self.load_society(key)
        return self._societies[key]

    def society_id(self, key: str) -> uuid.UUID:
        return scoped_uuid(f"society:{key}")

    def load_society(self, key: str) -> SocietyRef:
        sid = self.society_id(key)
        ref = SocietyRef(key, sid)
        with self.db.app_tx(RequestContext(sid, actor_role="seed")) as conn:
            for row in conn.execute(text("SELECT id, name FROM blocks")):
                ref.blocks[str(row[1])] = row[0]
            names = {v: k for k, v in ref.blocks.items()}
            for row in conn.execute(text("SELECT id, block_id, label FROM units")):
                ref.units[(names[row[1]], str(row[2]))] = row[0]
        return ref

    def forget_societies(self) -> None:
        self._societies.clear()


def friendly(exc: BaseException) -> str:
    if isinstance(exc, DwaarError):
        return f"{type(exc).__name__}: {getattr(exc, 'details', '')}"
    return f"{type(exc).__name__}: {exc}"
