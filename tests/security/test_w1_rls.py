"""W1 adversarial verification, lens INVARIANTS+SECURITY: RLS, roles, catalog guard (INV-01, ARCH-01/03).

Not collected by ``make test`` (file name does not match ``test_*.py``); run explicitly:

    uv run --no-sync pytest tests/security/verify_w1_rls.py -p no:cacheprovider

A test that FAILS here is a confirmed defect: it asserts the SECURE behaviour. Tests that pass are
attacks that were tried and did not succeed (regression evidence).
"""

# ruff: noqa: PT018, PT011, PT012, S608, E501, SIM117, PLC0415, RUF001, RUF002, RUF003, S603, S607, S310, B017, BLE001

from __future__ import annotations

import uuid
from collections.abc import Iterator

import psycopg
import pytest
from psycopg import errors
from sqlalchemy import text

from dwaar_api.core.db import Database, RequestContext
from tests._harness.pgfixtures import DbHandle
from tests.integration.core._support import SOCIETY_A, SOCIETY_B, create_probe_table
from tests.security.test_core_rls_isolation import find_rls_violations

pytestmark = pytest.mark.req("INV-01", "ARCH-01", "ARCH-03", "DB-02")


def _seed(db: DbHandle, society: uuid.UUID, *names: str) -> None:
    with db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(society),))
        for name in names:
            conn.execute(
                "INSERT INTO probe_things (society_id, name) VALUES (%s, %s)", (society, name)
            )


@pytest.fixture
def two(db: DbHandle) -> DbHandle:
    create_probe_table(db)
    _seed(db, SOCIETY_A, "a-1", "a-2")
    _seed(db, SOCIETY_B, "b-1", "b-2", "b-3")
    return db


# ------------------------------------------------------------------------------------------------
# (1a) unset / blank / garbage app.society_id
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value", ["", " ", "\t", "NULL", "null", "0", "00000000-0000-0000-0000-000000000000"]
)
def test_blank_or_nonsense_society_never_returns_rows(two: DbHandle, value: str) -> None:
    try:
        with two.app_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (value,))
            count = conn.execute("SELECT count(*) FROM probe_things").fetchone()
    except (errors.InvalidTextRepresentation, errors.DataError):
        return  # fail closed by raising: acceptable
    assert count == (0,), f"society_id={value!r} returned rows"


def test_injection_shaped_society_value_is_inert(two: DbHandle) -> None:
    payload = "x'; DROP TABLE probe_things; --"
    with pytest.raises((errors.InvalidTextRepresentation, errors.DataError)):
        with two.app_conn() as conn:
            conn.execute("SELECT set_config('app.society_id', %s, true)", (payload,))
            conn.execute("SELECT count(*) FROM probe_things")
    with two.app_conn(society_id=SOCIETY_A) as conn:
        assert conn.execute("SELECT count(*) FROM probe_things").fetchone() == (2,)


def test_uuid_spelling_variants_are_normalised_before_set_config(two: DbHandle) -> None:
    """Header-supplied selectors only reach set_config as str(uuid.UUID(...)): attack the parser."""
    from dwaar_api.core.authz import _uuid_or_none  # noqa: PLC0415
    from dwaar_common.errors import NotFound  # noqa: PLC0415

    for evil in ("a'; select 1;--", "{" + str(SOCIETY_A) + "} ", "../../etc/passwd", "1" * 5000):
        try:
            parsed = _uuid_or_none(evil)
        except NotFound:
            continue
        assert parsed is None or isinstance(parsed, uuid.UUID)
    # a valid variant is normalised to the canonical lower-case form, never passed through verbatim
    variant = str(SOCIETY_A).upper().replace("-", "")
    assert str(_uuid_or_none(variant)) == str(SOCIETY_A)


# ------------------------------------------------------------------------------------------------
# (1b) session-level state leaking across pooled connections
# ------------------------------------------------------------------------------------------------
@pytest.fixture
def one_connection_database(two: DbHandle) -> Iterator[Database]:
    database = Database(two.app_dsn, pool_size=1, max_overflow=0)
    try:
        yield database
    finally:
        database.dispose()


def test_session_level_society_setting_does_not_leak_into_society_less_transactions(
    two: DbHandle, one_connection_database: Database
) -> None:
    """A stray non-local SET (bug or SQL injection) on a pooled connection must not widen a later,
    society-less request. ``RequestContext.settings`` only sets fields that are present, and the
    pool never resets session state, so society A stays active for the next borrower."""
    database = one_connection_database
    with database.app_engine.connect() as conn:
        conn.execute(text(f"SET app.society_id = '{SOCIETY_A}'"))  # session level, survives COMMIT
        conn.commit()
    ctx = RequestContext(person_id=uuid.uuid4())  # e.g. a sign-in style call: no society
    with database.app_tx(ctx) as conn:
        leaked = conn.execute(text("SELECT count(*) FROM probe_things")).scalar_one()
    assert leaked == 0, "society A rows visible to a transaction that named no society"
    with database.app_tx(None) as conn:
        assert conn.execute(text("SELECT count(*) FROM probe_things")).scalar_one() == 0


def test_set_config_false_on_the_app_connection_is_cleared_by_the_next_scoped_transaction(
    two: DbHandle, one_connection_database: Database
) -> None:
    database = one_connection_database
    with database.app_engine.connect() as conn:
        conn.execute(text("SELECT set_config('app.society_id', :s, false)"), {"s": str(SOCIETY_B)})
        conn.commit()
    with database.app_tx(RequestContext(society_id=SOCIETY_A, person_id=uuid.uuid4())) as conn:
        names = {r[0] for r in conn.execute(text("SELECT name FROM probe_things"))}
    assert names == {"a-1", "a-2"}  # the explicit scoped context wins (secure)


def test_role_level_guc_default_cannot_be_planted_by_the_app_role(two: DbHandle) -> None:
    """``ALTER ROLE dwaar_app SET app.society_id = ...`` is allowed for a role on itself in PostgreSQL.
    If the runtime role can do it, one injected statement permanently poisons every new connection
    of the API for society-less transactions."""
    planted = False
    try:
        with psycopg.connect(two.app_dsn, autocommit=True) as conn:
            try:
                conn.execute(f"ALTER ROLE dwaar_app SET app.society_id = '{SOCIETY_A}'")  # type: ignore[call-overload]
                planted = True
            except errors.InsufficientPrivilege:
                return
        with psycopg.connect(two.app_dsn) as conn:  # a brand new session, no context at all
            leaked = conn.execute("SELECT count(*) FROM probe_things").fetchone()
        assert leaked == (0,), "role-level default app.society_id applied to a context-less session"
    finally:
        if planted:
            with two.admin_conn() as admin:
                admin.execute("ALTER ROLE dwaar_app RESET app.society_id")


def test_role_level_custom_guc_default_cannot_be_planted_on_the_worker_either(
    two: DbHandle,
) -> None:
    planted = False
    try:
        with psycopg.connect(two.worker_dsn, autocommit=True) as conn:
            try:
                conn.execute(f"ALTER ROLE dwaar_worker SET app.society_id = '{SOCIETY_B}'")  # type: ignore[call-overload]
                planted = True
            except errors.InsufficientPrivilege:
                return
        pytest.fail("worker role can persist app.society_id")
    finally:
        if planted:
            with two.admin_conn() as admin:
                admin.execute("ALTER ROLE dwaar_worker RESET app.society_id")


# ------------------------------------------------------------------------------------------------
# (1c) SECURITY DEFINER functions / views / materialised views
# ------------------------------------------------------------------------------------------------
def test_every_security_definer_function_is_locked_down(db: DbHandle) -> None:
    with db.admin_conn() as conn:
        rows = conn.execute(
            """
            SELECT p.oid::regprocedure::text, p.proconfig,
                   has_function_privilege('dwaar_app', p.oid, 'EXECUTE'),
                   has_function_privilege('dwaar_worker', p.oid, 'EXECUTE'),
                   has_function_privilege('public'::name, p.oid, 'EXECUTE')
            FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = 'public'
            WHERE p.prosecdef
            """
        ).fetchall()
    assert rows, "expected dwaar_purge_append_only at least"
    for sig, config, app, worker, public in rows:
        assert not (app or worker or public), (
            f"{sig} is SECURITY DEFINER and executable by runtime roles"
        )
        assert config and any(c.startswith("search_path=") for c in config), (
            f"{sig}: no pinned search_path"
        )


def test_catalog_guard_catches_a_view_exposing_a_society_table(db: DbHandle) -> None:
    """Views run as their owner, and the owner is subject to FORCE RLS, so a plain view is safe.
    This test proves it (an attack that did not work)."""
    create_probe_table(db)
    _seed(db, SOCIETY_A, "a-1")
    _seed(db, SOCIETY_B, "b-1")
    with db.owner_conn() as conn:
        conn.execute("CREATE VIEW v_things AS SELECT * FROM probe_things")
        conn.execute("GRANT SELECT ON v_things TO dwaar_app")
    with db.app_conn(society_id=SOCIETY_A) as conn:
        assert [r[0] for r in conn.execute("SELECT name FROM v_things")] == ["a-1"]
    with db.app_conn() as conn:
        assert conn.execute("SELECT count(*) FROM v_things").fetchone() == (0,)


def test_catalog_guard_catches_a_materialized_view_that_caches_society_rows(db: DbHandle) -> None:
    """Row level security does NOT apply to materialised views: a snapshot of society rows granted to the API
    role is readable across tenants (physically demonstrated below). The database cannot stop that GRANT, so
    the CI catalog guard must: it is deny-by-default and flags any matview a runtime role can read."""
    create_probe_table(db)
    _seed(db, SOCIETY_A, "a-secret-1", "a-secret-2")
    with db.owner_conn() as conn:
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_A),))
        conn.execute(
            "CREATE MATERIALIZED VIEW mv_things AS SELECT society_id, name FROM probe_things"
        )
        conn.execute("GRANT SELECT ON mv_things TO dwaar_app")
    with db.app_conn(society_id=SOCIETY_B) as conn:
        leaked = [r[0] for r in conn.execute("SELECT name FROM mv_things")]
    with db.admin_conn() as conn:
        guard_problems = find_rls_violations(conn)
    assert leaked == [
        "a-secret-1",
        "a-secret-2",
    ]  # the leak is real; this is why the guard must object
    assert any("mv_things" in p for p in guard_problems), guard_problems


def test_catalog_guard_flags_matviews_with_a_society_column(db: DbHandle) -> None:
    create_probe_table(db)
    with db.owner_conn() as conn:
        conn.execute("CREATE MATERIALIZED VIEW mv_x AS SELECT society_id, name FROM probe_things")
        conn.execute("GRANT SELECT ON mv_x TO dwaar_app")
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
    assert any("mv_x" in p for p in problems), "guard ignores materialised views entirely"


def test_catalog_guard_flags_society_scoped_table_with_a_differently_named_column(
    db: DbHandle,
) -> None:
    """A table scoped by tenant_id / soc_id / org_id and granted to the API role with no RLS is fully readable
    across tenants (shown below); the guard is deny-by-default: any table a runtime role can touch must carry
    society_id + RLS or be on the explicit platform allowlist."""
    with db.owner_conn() as conn:
        conn.execute("CREATE TABLE tenant_docs (id int, tenant_id uuid NOT NULL, body text)")
        conn.execute("INSERT INTO tenant_docs VALUES (1, %s, 'A only')", (SOCIETY_A,))
        conn.execute("INSERT INTO tenant_docs VALUES (2, %s, 'B only')", (SOCIETY_B,))
        conn.execute("GRANT SELECT ON tenant_docs TO dwaar_app")
    with db.app_conn(society_id=SOCIETY_A) as conn:
        visible = {r[0] for r in conn.execute("SELECT body FROM tenant_docs")}
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
    assert visible == {"A only", "B only"}  # the leak is real; this is why the guard must object
    assert any("tenant_docs" in p for p in problems), "catalog guard blind to tenant_id tables"


def test_catalog_guard_flags_any_table_granted_to_runtime_roles_without_rls(db: DbHandle) -> None:
    """Deny-by-default view of the same gap: every table the runtime roles can touch must have RLS or be
    on an explicit allowlist."""
    with db.owner_conn() as conn:
        conn.execute("CREATE TABLE sneaky_ledger (id int, amount bigint)")
        conn.execute("GRANT SELECT, INSERT ON sneaky_ledger TO dwaar_app")
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
    assert any("sneaky_ledger" in p for p in problems)


def test_catalog_guard_accepts_vacuous_policies_that_merely_mention_the_setting(
    db: DbHandle,
) -> None:
    """A policy that is always true but mentions 'app.society_id' leaks across societies (shown below). The
    guard evaluates policy expressions semantically, so the substring is not enough to pass."""
    with db.owner_conn() as conn:
        conn.execute("CREATE TABLE vacuous (id int, society_id uuid NOT NULL)")
        conn.execute("ALTER TABLE vacuous ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE vacuous FORCE ROW LEVEL SECURITY")
        conn.execute(
            "CREATE POLICY p ON vacuous USING (true OR society_id = nullif(current_setting('app.society_id', true), '')::uuid)"
        )
        conn.execute("GRANT SELECT ON vacuous TO dwaar_app")
        conn.execute("SELECT set_config('app.society_id', %s, true)", (str(SOCIETY_A),))
        conn.execute("INSERT INTO vacuous VALUES (1, %s)", (SOCIETY_A,))
    with db.app_conn(society_id=SOCIETY_B) as conn:
        rows = conn.execute("SELECT count(*) FROM vacuous").fetchone()
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
    assert rows == (1,)  # the leak is real; this is why the guard must object
    assert any(p.startswith("vacuous") for p in problems), "guard accepted an always-true policy"


def test_catalog_guard_covers_partitioned_tables_and_their_partitions(db: DbHandle) -> None:
    """Partitions are ordinary tables with their own (absent) RLS: querying a partition directly bypasses
    the parent policy. The guard sees partitions because each carries society_id (attack that failed)."""
    with db.owner_conn() as conn:
        conn.execute(
            "CREATE TABLE part_parent (id int, society_id uuid NOT NULL, d date NOT NULL) PARTITION BY RANGE (d)"
        )
        conn.execute(
            "CREATE TABLE part_child PARTITION OF part_parent FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')"
        )
        conn.execute("ALTER TABLE part_parent ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE part_parent FORCE ROW LEVEL SECURITY")
        conn.execute(
            "CREATE POLICY p ON part_parent USING (society_id = nullif(current_setting('app.society_id', true), '')::uuid)"
        )
        conn.execute("GRANT SELECT ON part_parent, part_child TO dwaar_app")
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
    assert any(p.startswith("part_child") for p in problems)


def test_helper_cannot_protect_a_partitioned_table(db: DbHandle) -> None:
    """dwaar_enable_society_rls refuses relkind 'p', so the documented one-liner cannot be used for a
    partitioned society table and authors must hand-roll the policy on parent AND every partition."""
    with db.owner_conn() as conn:
        conn.execute(
            "CREATE TABLE part_p (id int, society_id uuid NOT NULL, d date NOT NULL) PARTITION BY RANGE (d)"
        )
    with pytest.raises(errors.RaiseException), db.owner_conn() as conn:
        conn.execute("SELECT dwaar_enable_society_rls('part_p')")


# ------------------------------------------------------------------------------------------------
# (1d) dwaar_app privilege probes
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "statement",
    [
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT pg_ls_dir('/')",
        "SELECT pg_stat_file('/etc/passwd')",
        "COPY (SELECT 1) TO PROGRAM 'id'",
        "COPY probe_things FROM PROGRAM 'id'",
        "COPY (SELECT 1) TO '/tmp/dwaar_verify_w1.out'",
        "SELECT lo_import('/etc/passwd')",
        "SELECT lo_export(1, '/tmp/dwaar_verify_w1.lo')",
        "CREATE TEMP TABLE t_leak (x int)",
        "CREATE SCHEMA evil",
        "CREATE FUNCTION public.evil() RETURNS int LANGUAGE sql AS 'SELECT 1'",
        "SELECT rolpassword FROM pg_authid",
        "SELECT passwd FROM pg_shadow",
        "SELECT pg_reload_conf()",
        "SELECT pg_switch_wal()",
        "CREATE ROLE evil LOGIN",
        "DROP ROLE dwaar_worker",
        "SET ROLE pg_read_server_files",
        "SET ROLE pg_execute_server_program",
        "CREATE EXTENSION plpython3u",
        "CREATE PUBLICATION p FOR ALL TABLES",
        "ALTER DATABASE postgres SET app.society_id = 'x'",
    ],
)
@pytest.mark.parametrize("role", ["app", "worker"])
def test_runtime_roles_have_no_file_program_or_ddl_reach(
    two: DbHandle, role: str, statement: str
) -> None:
    opener = two.app_conn if role == "app" else two.worker_conn
    with (
        pytest.raises(
            (errors.InsufficientPrivilege, errors.FeatureNotSupported, errors.UndefinedFile)
        ),
        opener(society_id=SOCIETY_A) as conn,
    ):
        conn.execute(statement)  # type: ignore[call-overload]


def test_runtime_role_membership_and_default_privileges_are_empty(db: DbHandle) -> None:
    with db.admin_conn() as conn:
        members = conn.execute(
            "SELECT r.rolname, g.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member"
            " JOIN pg_roles g ON g.oid = m.roleid WHERE r.rolname IN ('dwaar_app', 'dwaar_worker')"
        ).fetchall()
        defacl = conn.execute("SELECT count(*) FROM pg_default_acl").fetchone()
        db_privs = conn.execute(
            "SELECT has_database_privilege(r, current_database(), 'TEMPORARY'),"
            " has_database_privilege(r, current_database(), 'CREATE'),"
            " has_schema_privilege(r, 'public', 'CREATE')"
            " FROM unnest(ARRAY['dwaar_app', 'dwaar_worker']) AS r"
        ).fetchall()
    assert members == []
    assert defacl == (0,)
    assert db_privs == [(False, False, False), (False, False, False)]


# ------------------------------------------------------------------------------------------------
# (1e) worker over-grant
# ------------------------------------------------------------------------------------------------
def _live_key(db: DbHandle, society: uuid.UUID, key: str = "live-key-0001") -> None:
    with db.app_conn(society_id=society) as conn:
        conn.execute(
            "INSERT INTO idempotency_keys (society_id, actor_id, key, endpoint, request_hash, state,"
            " response_status, response_body, completed_at, expires_at)"
            " VALUES (%s, %s, %s, 'POST /x', %s, 'completed', 201, '{}'::jsonb, now(), now() + interval '1 day')",
            (society, uuid.uuid4(), key, "sha256:" + "a" * 64),
        )


def test_worker_with_a_society_context_cannot_delete_live_idempotency_keys(two: DbHandle) -> None:
    """The migration says the worker only cleans EXPIRED keys, but the generic society policy is
    FOR ALL and also applies to dwaar_worker, so with app.society_id set the worker may delete live keys
    of that society and re-open the duplicate-effect window (INV-02)."""
    _live_key(two, SOCIETY_A)
    try:
        with two.worker_conn(society_id=SOCIETY_A) as conn:
            deleted = conn.execute("DELETE FROM idempotency_keys WHERE expires_at > now()").rowcount
    except errors.InsufficientPrivilege:
        deleted = 0
    assert deleted == 0, "worker deleted an unexpired idempotency key"


def test_worker_cannot_read_other_societies_live_idempotency_responses(two: DbHandle) -> None:
    _live_key(two, SOCIETY_A)
    with two.worker_conn() as conn:  # no society context at all
        rows = conn.execute(
            "SELECT count(*) FROM idempotency_keys WHERE expires_at > now()"
        ).fetchone()
    assert rows == (0,)


def test_worker_cross_society_visibility_is_limited_to_outbox_delivery_and_expired_keys(
    two: DbHandle,
) -> None:
    with two.worker_conn() as conn:
        for table in ("probe_things", "audit_log"):
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,), table  # type: ignore[call-overload]


# ------------------------------------------------------------------------------------------------
# more (1): header-borne selectors over real HTTP, role-scoped policy exemption, worker INSERT rights
# ------------------------------------------------------------------------------------------------
def test_hostile_selector_and_request_id_headers_over_http(db: DbHandle) -> None:
    from tests.integration.core._support import COMMITTEE_A, core_harness

    with core_harness(db) as core:
        client = core.client()
        evil = [
            "x'; SELECT set_config('app.society_id', '', false); --",
            f"{SOCIETY_A}' OR '1'='1",
            f"{SOCIETY_A},{SOCIETY_B}",
            str(SOCIETY_B),  # a real society the caller does not belong to
            "",
            "null",
        ]
        for value in evil:
            resp = client.get(
                "/v1/probe/things-no-society-in-path-is-404",
                headers={**core.auth(COMMITTEE_A), "X-Society-Id": value},
            )
            assert resp.status_code == 404
            resp = client.get(
                f"/v1/probe/{SOCIETY_A}/things",
                headers={**core.auth(COMMITTEE_A), "X-Request-ID": value or "x"},
            )
            assert resp.status_code == 200
            if value != str(SOCIETY_B):  # a syntactically valid UUID is honoured by design
                assert resp.headers["x-request-id"] != value  # arbitrary text is never reflected
        resp = client.get(
            f"/v1/probe/{SOCIETY_A}/things",
            headers={**core.auth(COMMITTEE_A), "X-Society-Id": str(SOCIETY_B)},
        )
        assert resp.status_code == 200  # path param wins over the header
        assert core.database.app_engine.pool.checkedout() == 0


def test_role_scoped_cross_society_policies_are_reviewed_not_silently_accepted(
    db: DbHandle,
) -> None:
    """The guard exempts any policy scoped TO dwaar_worker/dwaar_owner from the society check, so a later
    migration can add ``TO dwaar_worker USING (true)`` to a table and give the background role every
    society's rows with no allowlist entry and no red test (outbox needs this; nothing else should)."""
    create_probe_table(db)
    with db.owner_conn() as conn:
        conn.execute(
            "CREATE POLICY quiet_cross_society ON probe_things TO dwaar_worker USING (true)"
        )
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
    assert any("quiet_cross_society" in p for p in problems)


def test_worker_cannot_forge_outbox_events(db: DbHandle) -> None:
    with db.admin_conn() as conn:
        # column-level INSERT grants (outbox and audit_log delivery/time columns are server-set) count too
        row = conn.execute(
            "SELECT has_any_column_privilege('dwaar_worker', 'outbox', 'INSERT'),"
            " has_any_column_privilege('dwaar_worker', 'audit_log', 'INSERT'),"
            " has_any_column_privilege('dwaar_app', 'outbox', 'INSERT')"
        ).fetchone()
    assert row == (False, True, True)


# ------------------------------------------------------------------------------------------------
# fix round 1: more attacks on the deny-by-default catalog guard (F05) and pooled-connection state (F06)
# ------------------------------------------------------------------------------------------------
def test_catalog_guard_flags_a_view_owned_by_a_role_that_bypasses_rls(db: DbHandle) -> None:
    """A view runs with its OWNER's rights: owned by a superuser it silently bypasses every policy."""
    create_probe_table(db)
    _seed(db, SOCIETY_A, "a-1")
    _seed(db, SOCIETY_B, "b-1")
    with db.admin_conn() as conn:
        conn.execute("CREATE VIEW v_super AS SELECT * FROM probe_things")
        conn.execute("GRANT SELECT ON v_super TO dwaar_app")
    with db.app_conn(society_id=SOCIETY_A) as conn:
        seen = sorted(r[0] for r in conn.execute("SELECT name FROM v_super"))
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
    assert seen == ["a-1", "b-1"]  # the leak is real
    assert any(p.startswith("v_super") and "bypasses RLS" in p for p in problems), problems


def test_catalog_guard_cross_society_allowlist_is_by_table_and_policy_name(db: DbHandle) -> None:
    """The reviewed outbox relay policies are accepted; the same shape on any other table is not, and a
    reviewed policy name on the wrong table does not borrow the exemption."""
    create_probe_table(db)
    with db.owner_conn() as conn:
        conn.execute(
            "CREATE POLICY outbox_relay_select ON probe_things FOR SELECT TO dwaar_worker USING (true)"
        )
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
    assert any(p.startswith("probe_things.outbox_relay_select") for p in problems), problems
    assert not any(p.startswith("outbox.") for p in problems), problems


def test_catalog_guard_flags_unprobeable_policies_for_the_api_role(db: DbHandle) -> None:
    """A policy the guard cannot evaluate (it depends on other columns) must be rewritten in the standard form."""
    with db.owner_conn() as conn:
        conn.execute("CREATE TABLE odd (id int, society_id uuid NOT NULL, owner_flag boolean)")
        conn.execute("ALTER TABLE odd ENABLE ROW LEVEL SECURITY")
        conn.execute("ALTER TABLE odd FORCE ROW LEVEL SECURITY")
        conn.execute(
            "CREATE POLICY p ON odd USING (owner_flag AND society_id = nullif(current_setting('app.society_id', true), '')::uuid)"
        )
        conn.execute("GRANT SELECT ON odd TO dwaar_app")
    with db.admin_conn() as conn:
        problems = find_rls_violations(conn)
    assert any(p.startswith("odd.p") and "cannot be probed" in p for p in problems), problems


def test_catalog_guard_is_green_on_the_shipped_schema(db: DbHandle) -> None:
    with db.admin_conn() as conn:
        assert find_rls_violations(conn) == []


def test_pool_session_state_is_not_inherited_even_without_a_transaction_context(
    two: DbHandle, one_connection_database: Database
) -> None:
    """Defence in depth for F06: even code that borrows a raw connection (no apply_context) after a poisoned
    session sees no society, because the pool resets the session on check-in."""
    database = one_connection_database
    with database.app_engine.connect() as conn:
        conn.execute(text(f"SET app.society_id = '{SOCIETY_A}'"))
        conn.commit()
    with database.app_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM probe_things")).scalar_one() == 0
        conn.rollback()
