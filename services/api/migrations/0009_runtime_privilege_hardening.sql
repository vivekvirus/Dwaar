-- 0009 platform core: runtime-privilege hardening found by W1 verification (fix round 2).
-- REQ: INV-01, INV-02, DB-02, ARCH-03, PRD 12.4.
--
-- * R2-10        worker had table-level SELECT on idempotency_keys: with no society context it could read the
--                stored response_body of other societies' expired keys. Cleanup needs only (id, expires_at).
-- * LOCK TABLE   PostgreSQL permits ANY lock mode to a role holding table-level UPDATE, DELETE or TRUNCATE
--                (column-level UPDATE does not count). dwaar_app held table-level UPDATE on idempotency_keys
--                and rate_limit_buckets, so one statement could take ACCESS EXCLUSIVE and stall every
--                idempotent write of every society. Now: column-level UPDATE on idempotency_keys; no table
--                privileges at all on rate_limit_buckets (SECURITY DEFINER function instead).
-- * rate limits  rate_limit_buckets was full CRUD for app AND worker (any SQL could wipe another phone's OTP
--                throttle). The token-bucket function is now SECURITY DEFINER; the worker may only read and
--                delete STALE buckets (housekeeping), enforced by row level security.
-- * purge        the purge flag is a plain GUC the table owner can forge; a forged purge left no purge_log row.
--                Every permitted DELETE on a protected history table now writes its own purge_log row from an
--                AFTER DELETE statement trigger, so a forged flag still leaves evidence (the owner credential
--                remains break-glass, but never silent). The owner can read purge_log across societies.
-- * outbox       one event per (society, aggregate type, aggregate, version): PRD 12.4 orders events only per
--                aggregate version, so two events sharing one cannot be ordered or deduplicated.

-- ---------------------------------------------------------------------------------------------
-- idempotency_keys: no table-level UPDATE for the API role; the worker reads only what cleanup needs
-- ---------------------------------------------------------------------------------------------
REVOKE UPDATE ON TABLE idempotency_keys FROM dwaar_app;
GRANT UPDATE (endpoint, request_hash, state, response_status, response_body, completed_at, created_at, expires_at)
    ON TABLE idempotency_keys TO dwaar_app;

REVOKE SELECT ON TABLE idempotency_keys FROM dwaar_worker;
GRANT SELECT (id, expires_at) ON TABLE idempotency_keys TO dwaar_worker;

-- ---------------------------------------------------------------------------------------------
-- rate_limit_buckets: only the SECURITY DEFINER function touches live buckets
-- ---------------------------------------------------------------------------------------------
REVOKE ALL ON TABLE rate_limit_buckets FROM PUBLIC, dwaar_app, dwaar_worker;
ALTER TABLE rate_limit_buckets ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limit_buckets FORCE ROW LEVEL SECURITY;
-- The function runs as its owner; the owner (and only the owner) may use buckets freely.
CREATE POLICY rate_limit_owner_all ON rate_limit_buckets FOR ALL TO dwaar_owner
    USING (true) WITH CHECK (true);
-- Housekeeping: the worker sees and deletes only buckets untouched for a day (a refilled bucket is
-- indistinguishable from a fresh one, so nothing live is lost).
GRANT SELECT (key, updated_at), DELETE ON TABLE rate_limit_buckets TO dwaar_worker;
CREATE POLICY rate_limit_stale_select ON rate_limit_buckets FOR SELECT TO dwaar_worker
    USING (updated_at < now() - interval '1 day');
CREATE POLICY rate_limit_stale_delete ON rate_limit_buckets FOR DELETE TO dwaar_worker
    USING (updated_at < now() - interval '1 day');

ALTER FUNCTION dwaar_rate_limit_take(text, integer, double precision, integer) SECURITY DEFINER;

-- ---------------------------------------------------------------------------------------------
-- purge evidence: a permitted DELETE on a history table always leaves a purge_log row
-- ---------------------------------------------------------------------------------------------
CREATE POLICY purge_log_owner_read ON purge_log FOR SELECT TO dwaar_owner USING (true);

CREATE FUNCTION dwaar_purge_evidence() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- Without the flag the row guard has already refused every delete; nothing to record.
    IF current_setting('dwaar.purge_table', true) IS DISTINCT FROM TG_RELID::text THEN
        RETURN NULL;
    END IF;
    INSERT INTO purge_log (society_id, table_name, row_count, reason)
    SELECT nullif(current_setting('dwaar.purge_society', true), '')::uuid,
           TG_TABLE_NAME::text,
           count(*),
           coalesce(
               nullif(btrim(current_setting('dwaar.purge_reason', true)), ''),
               'purge flag set outside dwaar_purge_append_only(): no reason recorded')
    FROM deleted;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION dwaar_purge_evidence() FROM PUBLIC;

CREATE TRIGGER dwaar_purge_evidence AFTER DELETE ON audit_log
    REFERENCING OLD TABLE AS deleted FOR EACH STATEMENT EXECUTE FUNCTION dwaar_purge_evidence();
CREATE TRIGGER dwaar_purge_evidence AFTER DELETE ON outbox
    REFERENCING OLD TABLE AS deleted FOR EACH STATEMENT EXECUTE FUNCTION dwaar_purge_evidence();

-- Future append-only tables get the evidence trigger from the helper (purge_log itself can never be purged).
CREATE OR REPLACE FUNCTION dwaar_make_append_only(tbl regclass) RETURNS void
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
    IF tbl::oid <> coalesce(to_regclass('purge_log')::oid, 0::oid) THEN
        EXECUTE format('DROP TRIGGER IF EXISTS dwaar_purge_evidence ON %s', tbl);
        EXECUTE format(
            'CREATE TRIGGER dwaar_purge_evidence AFTER DELETE ON %s '
            'REFERENCING OLD TABLE AS deleted FOR EACH STATEMENT EXECUTE FUNCTION dwaar_purge_evidence()', tbl);
    END IF;
    EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON TABLE %s FROM PUBLIC, dwaar_app, dwaar_worker', tbl);
END
$$;

-- The explicit purge path: same checks as before, plus the evidence trigger must exist; the trigger (not this
-- function) writes the purge_log row, so the forged-flag path and this path leave the same kind of evidence.
CREATE OR REPLACE FUNCTION dwaar_purge_append_only(
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
    v_prev_reason text;
    v_prev_purge_society text;
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
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger t
        WHERE t.tgrelid = tbl AND NOT t.tgisinternal AND t.tgname = 'dwaar_purge_evidence'
    ) THEN
        RAISE EXCEPTION 'dwaar_purge_append_only: % has no purge evidence trigger', tbl;
    END IF;
    SELECT a.atttypid INTO v_type
    FROM pg_attribute a WHERE a.attrelid = tbl AND a.attname = id_column AND NOT a.attisdropped;
    IF NOT FOUND OR v_type <> 'uuid'::regtype THEN
        RAISE EXCEPTION 'dwaar_purge_append_only: % has no uuid column %', tbl, id_column;
    END IF;

    v_prev_flag := current_setting('dwaar.purge_table', true);
    v_prev_society := current_setting('app.society_id', true);
    v_prev_reason := current_setting('dwaar.purge_reason', true);
    v_prev_purge_society := current_setting('dwaar.purge_society', true);
    PERFORM set_config('dwaar.purge_table', tbl::oid::text, true);
    PERFORM set_config('dwaar.purge_reason', reason, true);
    PERFORM set_config('dwaar.purge_society', coalesce(society::text, ''), true);
    IF society IS NOT NULL THEN
        PERFORM set_config('app.society_id', society::text, true);
    END IF;

    EXECUTE format('DELETE FROM %s WHERE %I = ANY ($1)', tbl, id_column) USING ids;
    GET DIAGNOSTICS v_count = ROW_COUNT;

    PERFORM set_config('dwaar.purge_table', coalesce(v_prev_flag, ''), true);
    PERFORM set_config('app.society_id', coalesce(v_prev_society, ''), true);
    PERFORM set_config('dwaar.purge_reason', coalesce(v_prev_reason, ''), true);
    PERFORM set_config('dwaar.purge_society', coalesce(v_prev_purge_society, ''), true);
    RETURN v_count;
END
$$;

-- ---------------------------------------------------------------------------------------------
-- outbox: one event per aggregate version
-- ---------------------------------------------------------------------------------------------
CREATE UNIQUE INDEX outbox_aggregate_version_uq
    ON outbox (society_id, aggregate_type, aggregate_id, aggregate_version);
DROP INDEX outbox_aggregate_idx;
