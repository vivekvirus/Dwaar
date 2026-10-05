"""The demo login table and TOTP helper (local simulator only).

REQ: IAM-06 (the OTP is exposed only through the labelled dev endpoint), BUILD_BRIEF 7.

Nothing here logs anyone in. A demo login is: ``POST /v1/auth/otp/request`` for the fictional number, read the code from the
labelled simulator endpoint ``GET /v1/dev/otp?phone=...`` (exists only when ``DWAAR_ENV`` is local or test),
``POST /v1/auth/otp/verify``; elevated roles then complete ``POST /v1/auth/mfa/verify`` with the code printed by
``python -m dwaar_api.seed totp <phone>``.
"""

from __future__ import annotations

from collections.abc import Mapping

from .dataset import ELEVATED, RESIDENTS, STAFF_GRANTS, Person
from .people import all_people, by_key, current_totp
from .runtime import SeedRefused, out, require_local


def _roles() -> dict[str, list[str]]:
    roles: dict[str, list[str]] = {}
    for g in STAFF_GRANTS:
        roles.setdefault(g.person, []).append(f"{g.role}@{g.society}")
    for r in RESIDENTS:
        role = {
            "owner": "owner_occ" if r.lives else "owner_nr",
            "joint_owner": "owner",
            "tenant": "tenant",
            "family": "family",
        }[r.kind]
        roles.setdefault(r.person, []).append(
            f"{role} {r.block}-{r.label}@{r.society} [{r.outcome}]"
        )
    return roles


def demo_rows() -> list[tuple[Person, str, bool]]:
    roles = _roles()
    rows: list[tuple[Person, str, bool]] = []
    for p in all_people():
        if p.key == "operator" or ".bulk" in p.key:
            continue
        r = roles.get(p.key, [])
        needs = any(g.role in ELEVATED for g in STAFF_GRANTS if g.person == p.key)
        rows.append((p, "; ".join(r) if r else "-", needs))
    return rows


def print_demo_logins(environ: Mapping[str, str]) -> None:
    require_local(environ)
    out("DEMO LOGINS (synthetic, local simulator only; phone numbers are fictional)")
    out(f"{'phone':<16} {'name':<20} {'MFA':<4} role / note")
    for p, roles, needs in demo_rows():
        out(f"{p.phone:<16} {p.name:<20} {'yes' if needs else 'no':<4} {roles}; {p.note}")
    out("generated owner-occupiers: +91 99999 02001.. (Sahyadri) and 03001.. (Nandana)")


def print_totp(environ: Mapping[str, str], phone: str) -> None:
    require_local(environ)
    digits = "".join(ch for ch in phone if ch.isdigit() or ch == "+")
    e164 = digits if digits.startswith("+") else "+91" + digits[-10:]
    if e164 not in {p.phone for p in all_people()}:
        raise SeedRefused("not a seeded number")
    out(current_totp(e164))


__all__ = ["by_key", "demo_rows", "print_demo_logins", "print_totp"]
