"""Platform core of the Dwaar API: configuration, database context, migrations, audit/outbox,
idempotency, errors, pagination, authn/authz framework and module registry.

Feature code lives in ``dwaar_api.modules.<name>``; nothing in this package knows about a
specific feature (see docs/adr/0006).
"""
