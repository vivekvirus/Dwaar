-- 0008 platform core: integrity hardening found by W1 verification (fix round 1).
-- REQ: INV-01, INV-02, DB-02, PRD 8.2 (common columns), PRD 12.4 (audit + outbox history).
--
-- * F07  idempotency_keys: the generic society policy applied to dwaar_worker too, so a worker with a
--        society context could delete LIVE keys (reopening the duplicate-effect window). The society
--        policy now applies to dwaar_app and dwaar_owner only; the worker keeps ONLY its two
--        expired-rows-only policies.
-- * F08  outbox: dwaar_app could INSERT delivery columns (published_at, attempts, next_attempt_at,
--        last_error) and so create an event that is never relayed. INSERT is now column-scoped to the
--        content columns; delivery state always starts from its defaults.
-- * F09  audit_log: dwaar_app/dwaar_worker could INSERT `at` and backdate rows. `at` is now server-set only.
-- * Q-06 audit_log and outbox get retention_class and legal_hold_id (PRD 8.2 common columns).
--        retention_class is a class CODE from the retention pack (packages/legal-packs/retention); durations
--        stay in the pack (INV-10). legal_hold_id is set by privacy tooling, never by the runtime roles.
--        Placing a hold on an existing append-only row needs an owner-only guard exception that belongs
--        to the privacy engine migration (range 0700).

-- ---------------------------------------------------------------------------------------------
-- Q-06: common retention columns on the history tables
-- ---------------------------------------------------------------------------------------------
ALTER TABLE audit_log
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG'
        CONSTRAINT audit_log_retention_class_check CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
ALTER TABLE outbox
    ADD COLUMN retention_class text NOT NULL DEFAULT 'LOG'
        CONSTRAINT outbox_retention_class_check CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    ADD COLUMN legal_hold_id uuid;
COMMENT ON COLUMN audit_log.retention_class IS 'Retention class code from the retention pack (PRD Appendix B); default LOG.';
COMMENT ON COLUMN outbox.retention_class IS 'Retention class code from the retention pack (PRD Appendix B); default LOG.';
COMMENT ON COLUMN audit_log.legal_hold_id IS 'Set by privacy tooling when a legal hold applies; never by the runtime roles.';
COMMENT ON COLUMN outbox.legal_hold_id IS 'Set by privacy tooling when a legal hold applies; never by the runtime roles.';

-- ---------------------------------------------------------------------------------------------
-- F09: audit_log.at is server-set. Column-scoped INSERT: at, legal_hold_id are not grantable to runtime roles.
-- ---------------------------------------------------------------------------------------------
REVOKE INSERT ON TABLE audit_log FROM PUBLIC, dwaar_app, dwaar_worker;
GRANT INSERT (id, society_id, actor_id, effective_role, operation, object_type, object_id,
              object_version, diff_masked, reason, approver_id, request_id, retention_class)
    ON TABLE audit_log TO dwaar_app, dwaar_worker;

-- ---------------------------------------------------------------------------------------------
-- F08: outbox delivery state always starts at its defaults for the API role.
-- ---------------------------------------------------------------------------------------------
REVOKE INSERT ON TABLE outbox FROM PUBLIC, dwaar_app, dwaar_worker;
GRANT INSERT (event_id, schema_version, society_id, aggregate_type, aggregate_id, aggregate_version,
              event_type, occurred_at, actor_ref, correlation_id, causation_id, payload, payload_hash,
              retention_class)
    ON TABLE outbox TO dwaar_app;

-- ---------------------------------------------------------------------------------------------
-- F07: idempotency_keys society policy for the API role (and owner) only
-- ---------------------------------------------------------------------------------------------
DROP POLICY dwaar_society_isolation ON idempotency_keys;
CREATE POLICY dwaar_society_isolation ON idempotency_keys AS PERMISSIVE FOR ALL TO dwaar_app, dwaar_owner
    USING (society_id = nullif(current_setting('app.society_id', true), '')::uuid)
    WITH CHECK (society_id = nullif(current_setting('app.society_id', true), '')::uuid);
