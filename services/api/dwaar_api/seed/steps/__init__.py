"""Seed steps, discovered by file name (``sNNN_<name>.py``) and run in ``ORDER``.

HOW A LATER SLICE ADDS ITS PART (no shared file is edited): create ``steps/s<NNN>_<area>.py`` exposing

    NAME = "visits"          # shown in the run report
    ORDER = 500              # unique; lower runs first (see the bands below)
    def run(ctx: SeedContext) -> None: ...

``run`` must be IDEMPOTENT (look the natural key up first; a second run changes nothing), DETERMINISTIC (mint ids inside
``ctx.tx("<stable scope key>", ...)`` so they come from ``dwaar_api.seed.ids``), go through the module's SERVICE functions
or SQL under the proper RLS context (``ctx.tx`` sets it), and leave the audit and outbox rows the domain would write.
Invented identities and the reserved fictional numbers only (see ``dataset.py``).

Bands:  000-099 reference data · 100-199 organisation · 200-299 identity and access · 300-399 residents and units
        400-499 visits and gate (slice 2/3) · 500-599 staff, shifts, parcels (slice 4) · 600-699 finance (slice 5)
        700+ later. Steps in a higher band may rely on every lower band having run.

Not built yet on purpose (PRD 8.3 mentions them): six guard shifts, overdue/partial/overpaid invoices, one failed
settlement, six months of bills, receipts and bank lines. Their slices own them.
"""
