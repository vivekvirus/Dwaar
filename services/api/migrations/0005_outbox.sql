-- 0005 platform core: transactional outbox (PRD 12.4 event contract).
-- REQ: PRD 12.4 (domain mutation, audit row and outbox row in one transaction; workers publish at least
--      once; ordering only per aggregate version), INV-01, DB-02 (history is never updated or deleted by
--      the application role).
CREATE TABLE outbox (
    event_id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    schema_version integer NOT NULL CHECK (schema_version >= 1),
    society_id uuid NOT NULL,
    aggregate_type text NOT NULL CHECK (char_length(aggregate_type) BETWEEN 1 AND 100),
    aggregate_id uuid NOT NULL,
    aggregate_version integer NOT NULL CHECK (aggregate_version >= 0),
    event_type text NOT NULL CHECK (event_type ~ '^[A-Za-z][A-Za-z0-9_.]{0,99}$'),
    occurred_at timestamptz NOT NULL,
    actor_ref text NOT NULL CHECK (char_length(actor_ref) BETWEEN 1 AND 200),
    correlation_id uuid NOT NULL,
    causation_id uuid,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    payload_hash text NOT NULL CHECK (payload_hash ~ '^sha256:[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    -- delivery state: the ONLY columns the relay may change
    published_at timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text CHECK (last_error IS NULL OR char_length(last_error) <= 200)
);

-- Relay claim:  SELECT ... FROM outbox WHERE published_at IS NULL AND next_attempt_at <= now()
--               ORDER BY next_attempt_at, event_id FOR UPDATE SKIP LOCKED LIMIT n
CREATE INDEX outbox_claim_idx ON outbox (next_attempt_at, event_id) WHERE published_at IS NULL;
CREATE INDEX outbox_aggregate_idx ON outbox (society_id, aggregate_type, aggregate_id, aggregate_version);

-- App: write its own society's events (and read them back). Worker: read + delivery-field updates only.
SELECT dwaar_enable_society_rls('outbox', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (published_at, attempts, next_attempt_at, last_error) ON TABLE outbox TO dwaar_worker;

-- The relay is a platform job that must see pending events of ALL societies to claim them. These policies
-- are scoped TO dwaar_worker (the API role never gets them) and are limited by the column-level grant above.
CREATE POLICY outbox_relay_select ON outbox FOR SELECT TO dwaar_worker USING (true);
CREATE POLICY outbox_relay_update ON outbox FOR UPDATE TO dwaar_worker USING (true) WITH CHECK (true);
CREATE POLICY outbox_purge_select_owner ON outbox FOR SELECT TO dwaar_owner
    USING (current_setting('dwaar.purge_table', true) = 'outbox'::regclass::oid::text);
CREATE POLICY outbox_purge_owner ON outbox FOR DELETE TO dwaar_owner
    USING (current_setting('dwaar.purge_table', true) = 'outbox'::regclass::oid::text);

CREATE FUNCTION dwaar_outbox_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    c_delivery constant text[] := ARRAY['published_at', 'attempts', 'next_attempt_at', 'last_error'];
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF current_setting('dwaar.purge_table', true) = TG_RELID::text
           AND current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = TG_RELID)
        THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'outbox rows cannot be deleted' USING ERRCODE = 'DW001';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF (to_jsonb(NEW) - c_delivery) IS DISTINCT FROM (to_jsonb(OLD) - c_delivery) THEN
            RAISE EXCEPTION 'outbox event content is immutable; only delivery fields may change' USING ERRCODE = 'DW001';
        END IF;
        IF OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at THEN
            RAISE EXCEPTION 'outbox event is already published' USING ERRCODE = 'DW001';
        END IF;
        IF NEW.attempts < OLD.attempts THEN
            RAISE EXCEPTION 'outbox attempts cannot decrease' USING ERRCODE = 'DW001';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'outbox: % is not allowed', TG_OP USING ERRCODE = 'DW001';
END
$$;

CREATE TRIGGER dwaar_history_guard BEFORE UPDATE OR DELETE ON outbox
    FOR EACH ROW EXECUTE FUNCTION dwaar_outbox_guard();
CREATE TRIGGER dwaar_history_guard_truncate BEFORE TRUNCATE ON outbox
    FOR EACH STATEMENT EXECUTE FUNCTION dwaar_outbox_guard();

-- Keep the grants consistent with the guard (the helper re-checks this too).
REVOKE DELETE, TRUNCATE ON TABLE outbox FROM PUBLIC, dwaar_app, dwaar_worker;

COMMENT ON TABLE outbox IS 'Transactional outbox. Content is immutable; the relay updates delivery fields only.';
