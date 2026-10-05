-- 0004 platform core: audit_log (PRD 8.2 / 12.4). Append-only history (DB-02).
-- REQ: DB-02, INV-01, PRD 12.4 (actor and effective role, operation, object and version, masked
--      before/after diff, reason, approver, timestamp, request id), IAM-04 (privileged reads log purpose).
--
-- society_id is NULLABLE on purpose: platform-level events that happen before or outside any society
-- (sign-in failures, society creation) are audited too. Such rows can be INSERTED by the application
-- but are invisible to every society context; they are read through the database owner / privacy tooling.
-- So this table has hand-written policies instead of the standard helper.
CREATE TABLE audit_log (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid,
    actor_id uuid,
    effective_role text NOT NULL CHECK (char_length(effective_role) BETWEEN 1 AND 64),
    operation text NOT NULL CHECK (operation ~ '^[a-z][a-z0-9_.:-]{0,99}$'),
    object_type text NOT NULL CHECK (char_length(object_type) BETWEEN 1 AND 100),
    object_id uuid,
    object_version integer CHECK (object_version IS NULL OR object_version >= 0),
    diff_masked jsonb NOT NULL DEFAULT '{}'::jsonb,
    reason text,
    approver_id uuid,
    request_id uuid,
    at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_society_at_idx ON audit_log (society_id, at DESC, id);
CREATE INDEX audit_log_object_idx ON audit_log (object_type, object_id, at);
CREATE INDEX audit_log_request_idx ON audit_log (request_id) WHERE request_id IS NOT NULL;

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_log_read ON audit_log FOR SELECT
    USING (society_id = nullif(current_setting('app.society_id', true), '')::uuid);
CREATE POLICY audit_log_insert ON audit_log FOR INSERT
    WITH CHECK (society_id IS NULL OR society_id = nullif(current_setting('app.society_id', true), '')::uuid);
-- Privileged purge (privacy engine) only: owner role AND the transaction-local flag set by dwaar_purge_append_only().
-- (DELETE ... WHERE needs the rows to be visible through a SELECT policy as well.)
CREATE POLICY audit_log_purge_select_owner ON audit_log FOR SELECT TO dwaar_owner
    USING (current_setting('dwaar.purge_table', true) = 'audit_log'::regclass::oid::text);
CREATE POLICY audit_log_purge_owner ON audit_log FOR DELETE TO dwaar_owner
    USING (current_setting('dwaar.purge_table', true) = 'audit_log'::regclass::oid::text);

REVOKE ALL ON TABLE audit_log FROM PUBLIC, dwaar_app, dwaar_worker;
GRANT SELECT, INSERT ON TABLE audit_log TO dwaar_app, dwaar_worker;
SELECT dwaar_make_append_only('audit_log');

COMMENT ON TABLE audit_log IS 'Append-only audit history. diff_masked never contains raw PII (see dwaar_api.core.audit).';
