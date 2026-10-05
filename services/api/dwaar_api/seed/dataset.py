"""The seed dataset as PURE DATA (no database, no clock): PRD 8.3 "Seed dataset", slice 1 part.

REQ: PRD 8.3 (two societies: a Maharashtra CHS with 3 blocks and 240 units and a Karnataka association with 2 blocks and
180 units; duplicate unit labels across blocks; owners with multiple memberships; an active tenant with an absent owner;
a disputed move-out; family approvals), IAM-01..IAM-07, IAM-12, INV-04, INV-10.

NOT here yet (later slices add their own modules under ``dwaar_api/seed/steps``): guard shifts, visits, invoices,
receipts, bank lines, settlements.

Everything is INVENTED. Names are common regional names combined at random, none belongs to a real person. Phone
numbers are the reserved fictional range ``+91 99999 0nnnn`` (the harness uses ``99999 00nnn``); ``nnnn`` is fixed per
person below and must never be reused for someone else. New people are APPENDED with new numbers.

Unit labels repeat across blocks on purpose (``101`` exists in every block), so any query that matches a unit by label
alone is wrong; the key of a unit is (society, block, label).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Literal

DATASET_VERSION: Final = "1"
DATASET_NAME: Final = "dwaar-seed-v1 (PRD 8.3 slice 1: societies, units, people, roles)"

Lang = Literal["en", "hi", "mr", "kn"]
Pack = Literal["maharashtra-chs", "karnataka-aoa-1972"]


def phone_for(n: int) -> str:
    """Reserved fictional number: n=1001 -> +919999901001."""
    if not 1000 <= n <= 9999:
        raise ValueError("seed phone index must be 1000..9999")
    return f"+91999990{n:04d}"


@dataclass(frozen=True)
class BlockSpec:
    name: str
    floors: int
    has_lift: bool
    per_floor: int = 10

    def labels(self) -> list[tuple[int, str]]:
        """(floor, label) for every unit: floor 1 flat 1 is ``101``."""
        return [
            (f, f"{f}{k:02d}")
            for f in range(1, self.floors + 1)
            for k in range(1, self.per_floor + 1)
        ]


@dataclass(frozen=True)
class SocietySpec:
    key: str
    name: str
    legal_name: str
    entity_type: Literal["chs", "apartment_assoc"]
    registration_no: str
    legal_pack_key: Pack
    tax_pack_key: str
    city: str
    state: str
    blocks: tuple[BlockSpec, ...]
    interest_pct: str  # undivided interest per unit (decimal string); total must stay <= 100
    default_language: Lang

    @property
    def unit_count(self) -> int:
        return sum(len(b.labels()) for b in self.blocks)


MH: Final = SocietySpec(
    key="mh",
    name="Sahyadri Residency CHS (demo)",
    legal_name="Sahyadri Residency Co-operative Housing Society Ltd (synthetic)",
    entity_type="chs",
    registration_no="SYN/MH/PUN/0001",
    legal_pack_key="maharashtra-chs",
    tax_pack_key="gst-rwa",
    city="Pune",
    state="Maharashtra",
    blocks=(BlockSpec("A", 10, True), BlockSpec("B", 8, True), BlockSpec("C", 6, False)),
    interest_pct="0.400000",  # 240 x 0.4 = 96
    default_language="mr",
)
KA: Final = SocietySpec(
    key="ka",
    name="Nandana Apartments Owners Association (demo)",
    legal_name="Nandana Apartment Owners Association (synthetic)",
    entity_type="apartment_assoc",
    registration_no="SYN/KA/BLR/0001",
    legal_pack_key="karnataka-aoa-1972",
    tax_pack_key="gst-rwa",
    city="Bengaluru",
    state="Karnataka",
    blocks=(BlockSpec("Tower 1", 10, True), BlockSpec("Tower 2", 8, True)),
    interest_pct="0.500000",  # 180 x 0.5 = 90
    default_language="kn",
)
SOCIETIES: Final = (MH, KA)
assert MH.unit_count == 240  # noqa: S101 (PRD 8.3 numbers)
assert KA.unit_count == 180  # noqa: S101

#: Staff roles are role grants; PRD roles that need a fresh TOTP step-up are the elevated ones (IAM-03).
STAFF_ROLES: Final = (
    "secretary",
    "treasurer",
    "committee",
    "estate_mgr",
    "guard",
    "guard_sup",
    "auditor",
)
ELEVATED: Final = frozenset(
    {"secretary", "treasurer", "committee", "estate_mgr", "guard_sup", "auditor"}
)


@dataclass(frozen=True)
class Person:
    key: str
    name: str
    n: int  # phone index
    language: Lang = "en"
    note: str = ""

    @property
    def phone(self) -> str:
        return phone_for(self.n)


@dataclass(frozen=True)
class StaffGrant:
    society: str
    person: str
    role: str
    reason: str


@dataclass(frozen=True)
class Resident:
    """One membership claim, driven through the real verification flow."""

    society: str
    person: str
    block: str
    label: str
    kind: Literal["owner", "joint_owner", "tenant", "family"]
    lives: bool = True
    #: verified | pending (left in review) | rejected | disputed (tenant, owner contests) | ended (verified, then ended)
    #: | held (pending; the society's committee holds the onboarding with a logged reason, IAM-12)
    outcome: Literal["verified", "pending", "rejected", "disputed", "ended", "held"] = "verified"
    #: who decides: ``secretary`` or ``owner:<person key>`` (household joins are approved by the unit's owner)
    decided_by: str = "secretary"
    #: tenants: the owner who confirms (``None`` = no owner on the platform: reasoned waiver by the secretary)
    owner_confirms: str | None = None
    reason: str = ""


def _p(key: str, name: str, n: int, lang: Lang = "en", note: str = "") -> Person:
    return Person(key, name, n, lang, note)


#: Platform operator: issues the first secretary grant out of band (platform roles are never self-service, IAM-13).
OPERATOR: Final = _p(
    "operator",
    "Seed Operator (platform, synthetic)",
    1000,
    note="issues the first secretary grant; no login role",
)

# fmt: off
STAFF_PEOPLE: Final = (
    _p("mh.secretary", "Anita Kulkarni", 1001, "mr", "secretary, Sahyadri (MH)"),
    _p("mh.treasurer", "Rajesh Pawar", 1002, "mr", "treasurer, Sahyadri (MH)"),
    _p("mh.committee1", "Sunita Deshmukh", 1003, "mr", "committee, Sahyadri (MH)"),
    _p("mh.committee2", "Prakash Joshi", 1004, "mr", "committee, Sahyadri (MH)"),
    _p("mh.estate_mgr", "Vinod Gaikwad", 1005, "hi", "estate manager, Sahyadri (MH)"),
    _p("mh.guard1", "Ramesh Shinde", 1006, "mr", "guard, Sahyadri (MH); no MFA needed"),
    _p("mh.guard2", "Dattatray More", 1007, "mr", "guard, Sahyadri (MH); no MFA needed"),
    _p("mh.guard_sup", "Sachin Jadhav", 1008, "mr", "guard supervisor, Sahyadri (MH)"),
    _p("mh.auditor", "Kavita Bhosale", 1009, "en", "auditor (time-bound), Sahyadri (MH)"),
    _p("ka.secretary", "Meera Joshi", 1101, "en", "secretary, Nandana (KA); also non-resident owner in Sahyadri (MH)"),
    _p("ka.treasurer", "Suresh Gowda", 1102, "kn", "treasurer, Nandana (KA)"),
    _p("ka.committee1", "Deepa Rao", 1103, "kn", "committee, Nandana (KA)"),
    _p("ka.estate_mgr", "Manjunath Shetty", 1104, "kn", "estate manager, Nandana (KA)"),
    _p("ka.guard1", "Basavaraj Naik", 1105, "kn", "guard, Nandana (KA); no MFA needed"),
    _p("ka.guard_sup", "Kiran Poojary", 1106, "kn", "guard supervisor, Nandana (KA)"),
    _p("ka.auditor", "Shobha Iyer", 1107, "en", "auditor (time-bound), Nandana (KA)"),
)
# fmt: on

#: (society, person key, role, reason). The first secretary of each society is issued by the OPERATOR; everyone else by
#: that society's secretary. Auditors are time-bound (``AUDITOR_DAYS``).
AUDITOR_DAYS: Final = 180
# fmt: off
STAFF_GRANTS: Final = (
    StaffGrant("mh", "mh.secretary", "secretary", "Elected secretary (seed: operator onboarding)"),
    StaffGrant("mh", "mh.treasurer", "treasurer", "Elected treasurer of the managing committee"),
    StaffGrant("mh", "mh.committee1", "committee", "Elected committee member"),
    StaffGrant("mh", "mh.committee2", "committee", "Elected committee member"),
    StaffGrant("mh", "mh.estate_mgr", "estate_mgr", "Appointed estate manager"),
    StaffGrant("mh", "mh.guard1", "guard", "Gate guard, day shift"),
    StaffGrant("mh", "mh.guard2", "guard", "Gate guard, night shift"),
    StaffGrant("mh", "mh.guard_sup", "guard_sup", "Guard supervisor"),
    StaffGrant("mh", "mh.auditor", "auditor", "Statutory audit, time-bound access"),
    StaffGrant("ka", "ka.secretary", "secretary", "Elected secretary (seed: operator onboarding)"),
    StaffGrant("ka", "ka.treasurer", "treasurer", "Elected treasurer of the managing committee"),
    StaffGrant("ka", "ka.committee1", "committee", "Elected committee member"),
    StaffGrant("ka", "ka.estate_mgr", "estate_mgr", "Appointed estate manager"),
    StaffGrant("ka", "ka.guard1", "guard", "Gate guard, day shift"),
    StaffGrant("ka", "ka.guard_sup", "guard_sup", "Guard supervisor"),
    StaffGrant("ka", "ka.auditor", "auditor", "Statutory audit, time-bound access"),
)
# fmt: on

# ---------------------------------------------------------------------------------------------- named resident personas
# fmt: off
RESIDENT_PEOPLE: Final = (
    _p("neha", "Neha Patil", 1201, "mr", "owner-occupier A-101 (MH) only: plain single-society member"),
    _p("sanjay", "Sanjay Deshpande", 1202, "mr", "two memberships in MH: owner-occupier A-402, non-resident owner C-101"),
    _p("smita", "Smita Phadke", 1203, "mr", "non-resident owner of A-305 (MH) whose tenant is in a disputed move-out"),
    _p("dev", "Dev Rane", 1204, "mr", "tenant of A-305 (MH): move-out disputed by the owner; occupancy continues"),
    _p("imran", "Imran Qureshi", 1205, "hi", "active tenant of C-203 (MH) whose owner is absent from the platform"),
    _p("ganesh", "Ganesh Pawar", 1206, "mr", "owner-occupier A-203 (MH); approves his family"),
    _p("rekha", "Rekha Pawar", 1207, "mr", "family of Ganesh, approved"),
    _p("aarav", "Aarav Pawar", 1208, "mr", "family of Ganesh, approved (adult child, synthetic)"),
    _p("mohini", "Mohini Pawar", 1209, "mr", "household join to A-203 still waiting for the owner"),
    _p("unknown", "Rahul Verma", 1210, "hi", "household join to A-203 rejected with a reason"),
    _p("priya", "Priya Menon", 1211, "en", "tenant of B-205 (MH); her landlord is the non-resident owner Meera (AT-02)"),
    _p("vikram", "Vikram Nair", 1212, "en", "MOVED: owner of A-108 (MH) ended; now tenant of Tower 1 304 (KA) (AT-01 mover)"),
    _p("farhan", "Farhan Sheikh", 1213, "hi", "owner-occupier Tower 1 101 (KA) only: plain single-society member"),
    _p("gayathri", "Gayathri Murthy", 1214, "kn", "non-resident owner of Tower 1 304 (KA); confirms Vikram"),
    _p("kapoor", "Neelam Kapoor", 1215, "hi", "tenant applicant for B-110 (MH) whose onboarding has a committee hold (IAM-12)"),
    _p("leaver", "Kunal Sathe", 1216, "mr", "owner-occupier B-101 (MH): AT-01 ends this membership while his token is live"),
)
# fmt: on
#: Meera is the Karnataka secretary (STAFF_PEOPLE) and ALSO owns B-205 in Maharashtra without living there (INV-04).

# fmt: off
RESIDENTS: Final = (
    Resident("mh", "neha", "A", "101", "owner"),
    Resident("mh", "sanjay", "A", "402", "owner"),
    Resident("mh", "sanjay", "C", "101", "owner", lives=False),
    Resident("mh", "ganesh", "A", "203", "owner"),
    Resident("mh", "rekha", "A", "203", "family", decided_by="owner:ganesh"),
    Resident("mh", "aarav", "A", "203", "family", decided_by="owner:ganesh"),
    Resident("mh", "mohini", "A", "203", "family", outcome="pending"),
    Resident("mh", "unknown", "A", "203", "family", outcome="rejected", decided_by="owner:ganesh", reason="Not a member of the household; no relationship evidence supplied"),
    Resident("mh", "smita", "A", "305", "owner", lives=False),
    Resident("mh", "dev", "A", "305", "tenant", outcome="disputed", owner_confirms="smita", reason="Tenant says he vacated on 30 Sep; owner says the keys were not handed over"),
    Resident("mh", "imran", "C", "203", "tenant", owner_confirms=None, reason="Owner has not joined the platform and cannot be reached; tenancy agreement sighted"),
    Resident("mh", "ka.secretary", "B", "205", "owner", lives=False),
    Resident("mh", "priya", "B", "205", "tenant", owner_confirms="ka.secretary"),
    Resident("mh", "leaver", "B", "101", "owner"),
    Resident("mh", "kapoor", "B", "110", "tenant", outcome="held", reason="Dues of the previous tenancy are unresolved; held pending committee review"),
    Resident("mh", "vikram", "A", "108", "owner", outcome="ended", reason="Flat sold; resident moved to Bengaluru"),
    Resident("ka", "farhan", "Tower 1", "101", "owner"),
    Resident("ka", "gayathri", "Tower 1", "304", "owner", lives=False),
    Resident("ka", "vikram", "Tower 1", "304", "tenant", owner_confirms="gayathri"),
)
# fmt: on


#: Bulk owner-occupiers (plain, verified): the first ``count`` units of each society that are not used above get one
#: generated person each. Phones start at ``phone_base`` (MH 2000.., KA 3000..).
@dataclass(frozen=True)
class Bulk:
    society: str
    count: int
    phone_base: int
    lang: Lang


BULK: Final = (Bulk("mh", 36, 2000, "mr"), Bulk("ka", 28, 3000, "kn"))

FIRST: Final = {
    "mr": (
        "Aditi",
        "Swapnil",
        "Pooja",
        "Nilesh",
        "Madhuri",
        "Amol",
        "Shweta",
        "Yogesh",
        "Rutuja",
        "Omkar",
        "Snehal",
        "Tushar",
        "Vaishali",
        "Mangesh",
        "Archana",
        "Harshad",
    ),
    "kn": (
        "Chandana",
        "Harish",
        "Pavithra",
        "Ravi",
        "Spoorthi",
        "Naveen",
        "Roopa",
        "Girish",
        "Vidya",
        "Prashanth",
        "Anitha",
        "Sandeep",
        "Veena",
        "Mahesh",
        "Kavya",
        "Darshan",
    ),
}
LAST: Final = {
    "mr": (
        "Sawant",
        "Kadam",
        "Chavan",
        "Naik",
        "Salvi",
        "Kale",
        "Mane",
        "Gokhale",
        "Thakur",
        "Bhide",
        "Jagtap",
        "Ghare",
    ),
    "kn": (
        "Reddy",
        "Shetty",
        "Hegde",
        "Bhat",
        "Kamath",
        "Gowda",
        "Nayak",
        "Kulal",
        "Acharya",
        "Prabhu",
        "Rai",
        "Urs",
    ),
}


def bulk_people(spec: Bulk) -> list[Person]:
    """Deterministic generated people: pure function of the index."""
    firsts, lasts = FIRST[spec.lang], LAST[spec.lang]
    out: list[Person] = []
    for i in range(spec.count):
        name = f"{firsts[i % len(firsts)]} {lasts[(i * 5 + i // len(firsts)) % len(lasts)]}"
        out.append(
            Person(
                f"{spec.society}.bulk{i + 1:02d}",
                name,
                spec.phone_base + i + 1,
                spec.lang,
                "plain owner-occupier",
            )
        )
    return out


@dataclass(frozen=True)
class DemoLogin:
    key: str
    name: str
    phone: str
    roles: tuple[str, ...]
    needs_totp: bool
    note: str = ""
    societies: tuple[str, ...] = field(default=())
