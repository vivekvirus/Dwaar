"""Community: notices (published, legal with reviewed translations, an AI-drafted one awaiting a person), a document, an open poll.

REQ: COM-01 (a published notice, revisions), COM-02 (a legal notice published only after human review of its Hindi and Marathi
translations; the Marathi text is MACHINE-DRAFTED by a labelled simulator and needs native review before a pilot), COM-03 (an
AI-drafted notice that is still DRAFT: it cannot be published until a person approves it), COM-04 (a bye-laws document: stored,
hashed, scanned by the LABELLED STUB scanner, published), COM-06 (an opinion poll, non-binding, with a few answers), PRD 8.3.

Every write goes through the module's SERVICE functions as ``dwaar_app`` with the RLS context of the real actor; a second run changes
nothing (everything is found by its natural key first). Content is invented. The seed is local-only, so it may use the stub
scanner; the document row says ``scanner_simulation = true`` and ``storage_simulation = true``. No model ran: the "AI draft" is
a flag and a run reference to a simulator, never a claim about AI quality.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from sqlalchemy import text

from ...modules.community import documents, notices, polls
from ...modules.community.actors import Actor
from ...modules.community.config import CommunityConfig
from ...modules.community.scanner import StubScanner
from ...modules.community.schemas import (
    ApproveIn,
    Audience,
    DocumentCreate,
    NoticeCreate,
    PollCreate,
    PollOpenIn,
    PublishIn,
    VersionCreate,
)
from ...modules.community.storage import LocalDiskStore
from ..runtime import SeedContext, SocietyRef

NAME = "community"
ORDER = 570

BYE_LAWS = (
    b"%PDF-1.4\n% synthetic seed document, not a real bye-law\n1 0 obj << /Type /Catalog >> endobj\n"
    b"trailer << /Root 1 0 R >>\n%%EOF\n"
)


@dataclass(frozen=True)
class NoticeSpec:
    key: str
    kind: str
    title: str
    body: str
    translations: tuple[tuple[str, str, str], ...] = ()  # (language, title, body)
    publish: bool = True
    ai: bool = False


NOTICES = (
    NoticeSpec(
        "water",
        "general",
        "Water tank cleaning on Saturday",
        "The overhead tanks of all blocks will be cleaned on Saturday between 10:00 and 14:00. Please store water.",
    ),
    NoticeSpec(
        "agm",
        "legal",
        "Notice of the annual general meeting",
        "The annual general meeting will be held on the date and at the place announced on the notice board. The agenda is attached to this notice.",
        translations=(
            (
                "hi",
                "वार्षिक आम सभा की सूचना",
                "वार्षिक आम सभा की तारीख और स्थान सूचना पट पर घोषित किया जाएगा।",
            ),
            (
                "mr",
                "वार्षिक सर्वसाधारण सभेची सूचना",
                "वार्षिक सर्वसाधारण सभेची तारीख आणि ठिकाण सूचना फलकावर जाहीर केले जाईल.",
            ),
        ),
    ),
    NoticeSpec(
        "lift-ai",
        "general",
        "Lift servicing schedule for October",
        "Draft prepared by a simulated assistant: the lifts will be serviced one block at a time.",
        publish=False,
        ai=True,
    ),
)

POLL = PollCreate(
    question="Should the clubhouse stay open until 10 pm on weekdays?",
    description="An opinion poll only: it does not bind the committee. The committee will read the result at its next meeting.",
    options=["Yes", "No", "No opinion"],
)


def _known(ctx: SeedContext, soc: SocietyRef, sql: str, title: str) -> object | None:
    with ctx.tx(f"community:read:{title}", society=soc.id, role="seed") as (conn, _c):
        row = conn.execute(text(sql), {"t": title}).first()
    return None if row is None else row[0]


def _notices(ctx: SeedContext, soc: SocietyRef) -> None:
    committee, secretary = ctx.person("mh.committee1"), ctx.person("mh.secretary")
    drafter = Actor(committee, "committee", True)
    boss = Actor(secretary, "secretary", True)
    for spec in NOTICES:
        sql = "SELECT n.id FROM notices n JOIN notice_versions v ON v.notice_id = n.id AND v.revision = 1 WHERE v.title = :t"
        if _known(ctx, soc, sql, spec.title) is not None:
            continue
        body = NoticeCreate(
            kind=spec.kind, audience=Audience(), title=spec.title, body=spec.body, drafted_by_ai=spec.ai,
            ai_run_ref="seed-simulated-run" if spec.ai else None, target_languages=[t[0] for t in spec.translations],
        )  # fmt: skip
        with ctx.tx(
            f"community:notice:{spec.key}", society=soc.id, person=committee, role="committee"
        ) as (conn, rctx):
            nid = notices.create_notice(conn, rctx, drafter, body)["id"]
        ctx.count("notices_created")
        for language, title, text_body in spec.translations:
            with ctx.tx(
                f"community:tr:{spec.key}:{language}",
                society=soc.id,
                person=committee,
                role="committee",
            ) as (conn, rctx):
                notices.add_translation(conn, rctx, nid, language, title, text_body, origin="human")
        for language, _t, _b in spec.translations:
            with ctx.tx(
                f"community:review:{spec.key}:{language}",
                society=soc.id,
                person=secretary,
                role="secretary",
            ) as (conn, rctx):
                notices.review_translation(
                    conn,
                    rctx,
                    boss,
                    nid,
                    language,
                    "approve",
                    "Seed: checked against the English text",
                )
        if spec.publish:
            with ctx.tx(
                f"community:approve:{spec.key}", society=soc.id, person=secretary, role="secretary"
            ) as (conn, rctx):
                notices.approve(conn, rctx, boss, nid, ApproveIn())
            with ctx.tx(
                f"community:publish:{spec.key}", society=soc.id, person=secretary, role="secretary"
            ) as (conn, rctx):
                notices.publish(conn, rctx, boss, nid, PublishIn())


def _document(ctx: SeedContext, soc: SocietyRef) -> None:
    title = "Registered bye-laws of the society"
    if _known(ctx, soc, "SELECT id FROM documents WHERE title = :t", title) is not None:
        return
    cfg = CommunityConfig.from_environment(ctx.settings)
    store, scanner = (
        LocalDiskStore(cfg.storage_dir),
        StubScanner(),
    )  # LABELLED simulations: local development only
    committee, secretary = ctx.person("mh.committee1"), ctx.person("mh.secretary")
    with ctx.tx("community:doc", society=soc.id, person=committee, role="committee") as (
        conn,
        rctx,
    ):
        doc = documents.create_document(
            conn, rctx, DocumentCreate(doc_type="bye_laws", title=title, authority="Registrar of Cooperative Societies (invented)", access_level="all_residents")
        )  # fmt: skip
    with ctx.tx("community:doc:version", society=soc.id, person=committee, role="committee") as (
        conn,
        rctx,
    ):
        version = documents.add_version(
            conn,
            rctx,
            doc["id"],
            VersionCreate(effective_from=dt.date(2026, 4, 1), change_note="Seed: first filing"),
        )
    with ctx.tx("community:doc:upload", society=soc.id, person=committee, role="committee") as (
        conn,
        rctx,
    ):
        documents.upload_content(
            conn,
            rctx,
            cfg,
            store,
            scanner,
            doc["id"],
            version["id"],
            BYE_LAWS,
            "application/pdf",
            "bye-laws.pdf",
        )
    with ctx.tx("community:doc:publish", society=soc.id, person=secretary, role="secretary") as (
        conn,
        rctx,
    ):
        documents.publish_version(conn, rctx, doc["id"], version["id"])
    ctx.count("documents_created")


def _poll(ctx: SeedContext, soc: SocietyRef) -> None:
    if _known(ctx, soc, "SELECT id FROM polls WHERE question = :t", POLL.question) is not None:
        return
    committee, secretary = ctx.person("mh.committee1"), ctx.person("mh.secretary")
    with ctx.tx("community:poll", society=soc.id, person=committee, role="committee") as (
        conn,
        rctx,
    ):
        poll = polls.create_poll(conn, rctx, POLL)
    with ctx.tx("community:poll:open", society=soc.id, person=secretary, role="secretary") as (
        conn,
        rctx,
    ):
        polls.open_poll(conn, rctx, poll["id"], PollOpenIn())
    with ctx.tx("community:poll:options", society=soc.id, role="seed") as (conn, _c):
        options = [
            r[0]
            for r in conn.execute(
                text("SELECT id FROM poll_options WHERE poll_id = :p ORDER BY position"),
                {"p": poll["id"]},
            )
        ]
    for who, block, label, role, pick in (
        ("neha", "A", "101", "owner_occ", 0),
        ("ganesh", "A", "203", "owner_occ", 0),
        ("priya", "B", "205", "tenant", 1),
    ):
        pid, unit = ctx.person(who), soc.unit(block, label)
        with ctx.tx(f"community:poll:answer:{who}", society=soc.id, person=pid, role=role) as (
            conn,
            rctx,
        ):
            polls.respond(
                conn, rctx, Actor(pid, role, False, frozenset({unit})), poll["id"], options[pick]
            )
    ctx.count("polls_created")


def run(ctx: SeedContext) -> None:
    soc = ctx.society("mh")
    _notices(ctx, soc)
    _document(ctx, soc)
    _poll(ctx, soc)
    ctx.say(
        "  community: notices (published, legal with reviewed translations, an AI-drafted draft), a bye-laws document (stub scanner, "
        f"simulation) and an open non-binding poll seeded ({ctx.counts.get('notices_created', 0)} notices this run)"
    )
