-- 0003 platform core: the SQL helpers that EVERY later migration uses for tenant isolation and history protection.
--
-- REQ: ARCH-01 (society_id on every society-owned row), ARCH-03 (restricted role + transaction-scoped
--      context drives RLS), INV-01 (isolation), DB-02 (append-only tables reject UPDATE/DELETE for the
--      application role), PRD 12.4 (audit rows are history).
--
-- Usage in a later migration (call once, right after CREATE TABLE):
--     SELECT dwaar_enable_society_rls('my_table');                       -- app+worker get full CRUD
--     SELECT dwaar_enable_society_rls('my_table', 'SELECT, INSERT', 'SELECT');   -- narrower grants
--     SELECT dwaar_make_append_only('my_ledger_table');                  -- order vs. the call above does not matter
-- Extra grants (for example column-level UPDATE) go AFTER the helper call: the helper resets table grants.

-- ---------------------------------------------------------------------------------------------
-- dwaar_enable_society_rls
-- ---------------------------------------------------------------------------------------------
CREATE FUNCTION dwaar_enable_society_rls(
    tbl regclass,
    app_privileges text DEFAULT 'SELECT, INSERT, UPDATE, DELETE',
    worker_privileges text DEFAULT 'SELECT, INSERT, UPDATE, DELETE'
) RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    c_allowed constant text[] := ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE'];
    v_type oid;
    v_kind "char";
    v_app text[];
    v_worker text[];
    v_priv text;
    v_seq text;
    c_expr constant text :=
        $e$society_id = nullif(current_setting('app.society_id', true), '')::uuid$e$;
BEGIN
    SELECT c.relkind INTO v_kind FROM pg_class c WHERE c.oid = tbl;
    IF v_kind IS DISTINCT FROM 'r' THEN
        RAISE EXCEPTION 'dwaar_enable_society_rls: % is not an ordinary table', tbl;
    END IF;

    SELECT a.atttypid INTO v_type
    FROM pg_attribute a
    WHERE a.attrelid = tbl AND a.attname = 'society_id' AND NOT a.attisdropped;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'dwaar_enable_society_rls: % has no society_id column (ARCH-01)', tbl;
    END IF;
    IF v_type <> 'uuid'::regtype THEN
        RAISE EXCEPTION 'dwaar_enable_society_rls: %.society_id must be uuid', tbl;
    END IF;

    v_app := ARRAY(SELECT btrim(upper(x)) FROM unnest(string_to_array(app_privileges, ',')) AS x WHERE btrim(x) <> '');
    v_worker := ARRAY(SELECT btrim(upper(x)) FROM unnest(string_to_array(worker_privileges, ',')) AS x WHERE btrim(x) <> '');
    FOREACH v_priv IN ARRAY v_app || v_worker LOOP
        IF NOT (v_priv = ANY (c_allowed)) THEN
            RAISE EXCEPTION 'dwaar_enable_society_rls: privilege % is not allowed (use %)', v_priv, c_allowed;
        END IF;
    END LOOP;

    -- society_id is mandatory: a NULL society would be invisible to every tenant and unreachable for repair.
    EXECUTE format('ALTER TABLE %s ALTER COLUMN society_id SET NOT NULL', tbl);
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);

    -- Missing or empty context => nullif(...) is NULL => predicate is NULL => zero rows; writes fail WITH CHECK.
    EXECUTE format('DROP POLICY IF EXISTS dwaar_society_isolation ON %s', tbl);
    EXECUTE format(
        'CREATE POLICY dwaar_society_isolation ON %s AS PERMISSIVE FOR ALL USING (%s) WITH CHECK (%s)',
        tbl, c_expr, c_expr);

    EXECUTE format('REVOKE ALL ON TABLE %s FROM PUBLIC, dwaar_app, dwaar_worker', tbl);
    IF cardinality(v_app) > 0 THEN
        EXECUTE format('GRANT %s ON TABLE %s TO dwaar_app', array_to_string(v_app, ', '), tbl);
    END IF;
    IF cardinality(v_worker) > 0 THEN
        EXECUTE format('GRANT %s ON TABLE %s TO dwaar_worker', array_to_string(v_worker, ', '), tbl);
    END IF;

    -- Serial / identity columns: INSERT is useless without USAGE on the owned sequence.
    FOR v_seq IN
        SELECT pg_get_serial_sequence(tbl::text, a.attname)
        FROM pg_attribute a
        WHERE a.attrelid = tbl AND a.attnum > 0 AND NOT a.attisdropped
          AND pg_get_serial_sequence(tbl::text, a.attname) IS NOT NULL
    LOOP
        IF 'INSERT' = ANY (v_app) THEN
            EXECUTE format('GRANT USAGE ON SEQUENCE %s TO dwaar_app', v_seq);
        END IF;
        IF 'INSERT' = ANY (v_worker) THEN
            EXECUTE format('GRANT USAGE ON SEQUENCE %s TO dwaar_worker', v_seq);
        END IF;
    END LOOP;

    -- Append-only tables never regain UPDATE/DELETE, whatever the call order (DB-02).
    IF EXISTS (
        SELECT 1 FROM pg_trigger t
        WHERE t.tgrelid = tbl AND NOT t.tgisinternal
          AND t.tgname IN ('dwaar_append_only_row', 'dwaar_history_guard')
    ) THEN
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON TABLE %s FROM PUBLIC, dwaar_app, dwaar_worker', tbl);
    END IF;
END
$$;

COMMENT ON FUNCTION dwaar_enable_society_rls(regclass, text, text) IS
    'Enable+FORCE row level security with the standard society policy and grant table privileges to dwaar_app/dwaar_worker.';

-- ---------------------------------------------------------------------------------------------
-- Append-only protection
-- ---------------------------------------------------------------------------------------------
CREATE FUNCTION dwaar_reject_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    -- The ONLY way through is dwaar_purge_append_only(): it runs as the table owner (SECURITY DEFINER),
    -- flags the table for the current transaction and only ever deletes. A session that merely forges
    -- the flag still fails here unless it is the table owner, and the application role has no DELETE
    -- privilege at all.
    IF TG_OP = 'DELETE' AND TG_LEVEL = 'ROW'
       AND current_setting('dwaar.purge_table', true) = TG_RELID::text
       AND current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = TG_RELID)
    THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'append-only table "%": % is not allowed', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'DW001';
END
$$;

CREATE FUNCTION dwaar_make_append_only(tbl regclass) RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_kind "char";
BEGIN
    SELECT c.relkind INTO v_kind FROM pg_class c WHERE c.oid = tbl;
    IF v_kind IS DISTINCT FROM 'r' THEN
        RAISE EXCEPTION 'dwaar_make_append_only: % is not an ordinary table', tbl;
    END IF;
    EXECUTE format('DROP TRIGGER IF EXISTS dwaar_append_only_row ON %s', tbl);
    EXECUTE format(
        'CREATE TRIGGER dwaar_append_only_row BEFORE UPDATE OR DELETE ON %s '
        'FOR EACH ROW EXECUTE FUNCTION dwaar_reject_mutation()', tbl);
    EXECUTE format('DROP TRIGGER IF EXISTS dwaar_append_only_truncate ON %s', tbl);
    EXECUTE format(
        'CREATE TRIGGER dwaar_append_only_truncate BEFORE TRUNCATE ON %s '
        'FOR EACH STATEMENT EXECUTE FUNCTION dwaar_reject_mutation()', tbl);
    EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON TABLE %s FROM PUBLIC, dwaar_app, dwaar_worker', tbl);
END
$$;

COMMENT ON FUNCTION dwaar_make_append_only(regclass) IS
    'Reject UPDATE/DELETE/TRUNCATE for every role (privileged purge excepted) and revoke them from app/worker (DB-02).';

-- ---------------------------------------------------------------------------------------------
-- purge_log: evidence that history was purged (privacy engine, later migrations)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE purge_log (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid,
    table_name text NOT NULL,
    row_count bigint NOT NULL CHECK (row_count >= 0),
    reason text NOT NULL CHECK (char_length(btrim(reason)) >= 5),
    purged_by text NOT NULL DEFAULT session_user,
    at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX purge_log_society_idx ON purge_log (society_id, at);

ALTER TABLE purge_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE purge_log FORCE ROW LEVEL SECURITY;
CREATE POLICY purge_log_read ON purge_log FOR SELECT
    USING (society_id = nullif(current_setting('app.society_id', true), '')::uuid);
CREATE POLICY purge_log_insert_owner ON purge_log FOR INSERT TO dwaar_owner WITH CHECK (true);
GRANT SELECT ON purge_log TO dwaar_app;
SELECT dwaar_make_append_only('purge_log');

-- ---------------------------------------------------------------------------------------------
-- dwaar_purge_append_only: the explicit, owner-only, logged purge path (used by the privacy engine)
-- ---------------------------------------------------------------------------------------------
CREATE FUNCTION dwaar_purge_append_only(
    tbl regclass,
    ids uuid[],
    reason text,
    society uuid DEFAULT NULL,
    id_column name DEFAULT 'id'
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_prev_flag text;
    v_prev_society text;
    v_count bigint;
    v_type oid;
BEGIN
    IF reason IS NULL OR char_length(btrim(reason)) < 5 THEN
        RAISE EXCEPTION 'dwaar_purge_append_only: a reason of at least 5 characters is required';
    END IF;
    IF tbl::oid = coalesce(to_regclass('purge_log')::oid, 0::oid) THEN
        RAISE EXCEPTION 'dwaar_purge_append_only: purge_log can never be purged';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger t
        WHERE t.tgrelid = tbl AND NOT t.tgisinternal
          AND t.tgname IN ('dwaar_append_only_row', 'dwaar_history_guard')
    ) THEN
        RAISE EXCEPTION 'dwaar_purge_append_only: % is not a protected history table', tbl;
    END IF;
    SELECT a.atttypid INTO v_type
    FROM pg_attribute a WHERE a.attrelid = tbl AND a.attname = id_column AND NOT a.attisdropped;
    IF NOT FOUND OR v_type <> 'uuid'::regtype THEN
        RAISE EXCEPTION 'dwaar_purge_append_only: % has no uuid column %', tbl, id_column;
    END IF;

    v_prev_flag := current_setting('dwaar.purge_table', true);
    v_prev_society := current_setting('app.society_id', true);
    PERFORM set_config('dwaar.purge_table', tbl::oid::text, true);
    IF society IS NOT NULL THEN
        PERFORM set_config('app.society_id', society::text, true);
    END IF;

    EXECUTE format('DELETE FROM %s WHERE %I = ANY ($1)', tbl, id_column) USING ids;
    GET DIAGNOSTICS v_count = ROW_COUNT;

    PERFORM set_config('dwaar.purge_table', coalesce(v_prev_flag, ''), true);
    PERFORM set_config('app.society_id', coalesce(v_prev_society, ''), true);

    INSERT INTO purge_log (society_id, table_name, row_count, reason)
    VALUES (society, tbl::text, v_count, reason);
    RETURN v_count;
END
$$;

COMMENT ON FUNCTION dwaar_purge_append_only(regclass, uuid[], text, uuid, name) IS
    'Owner-only privileged DELETE of history rows by id; sets a transaction-local flag and writes purge_log.';

-- Helpers are DDL/maintenance tools: only the owner (and superusers) may run them.
REVOKE ALL ON FUNCTION dwaar_enable_society_rls(regclass, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION dwaar_make_append_only(regclass) FROM PUBLIC;
REVOKE ALL ON FUNCTION dwaar_purge_append_only(regclass, uuid[], text, uuid, name) FROM PUBLIC;
