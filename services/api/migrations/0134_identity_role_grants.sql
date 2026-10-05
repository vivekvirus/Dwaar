-- 0134 identity: role grants (society-owned, RLS).
-- REQ: IAM-02 (grants carry action scope, issuer, expiry and reason; they expire automatically and expiry revokes the
--      open sessions that used the privilege), IAM-03 (elevated roles cannot be self-granted), IAM-13 (no sign-up
--      path can assign platform or committee roles: the ONLY writer is the role-grant API, which needs the
--      secretary permission), PRD 8.2 (role_grants), PRD 5.1 (roles).
CREATE TABLE role_grants (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL,
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    role text NOT NULL CHECK (role IN ('guard', 'guard_sup', 'estate_mgr', 'technician', 'vendor_tech', 'treasurer',
                                       'secretary', 'committee', 'auditor', 'org_admin', 'plat_support')),
    scope jsonb NOT NULL DEFAULT '{"kind": "society"}'::jsonb,
    issued_by uuid NOT NULL REFERENCES iam.persons (id),
    approved_by uuid REFERENCES iam.persons (id),
    reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 5 AND 500),
    issued_at timestamptz NOT NULL DEFAULT now(),
    not_before timestamptz,
    expires_at timestamptz,
    revoked_at timestamptz,
    revoked_by uuid REFERENCES iam.persons (id),
    revoke_reason text CHECK (revoke_reason IS NULL OR char_length(revoke_reason) <= 500),
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT role_grants_society_id_key UNIQUE (society_id, id),
    CONSTRAINT role_grants_no_self_grant CHECK (person_id <> issued_by),
    CONSTRAINT role_grants_window_check CHECK (expires_at IS NULL OR expires_at > coalesce(not_before, issued_at)),
    CONSTRAINT role_grants_time_bound CHECK (role NOT IN ('auditor', 'plat_support', 'vendor_tech') OR expires_at IS NOT NULL),
    CONSTRAINT role_grants_support_approval CHECK (role <> 'plat_support'
        OR (approved_by IS NOT NULL AND approved_by <> issued_by AND approved_by <> person_id)),
    CONSTRAINT role_grants_scope_check CHECK (
        jsonb_typeof(scope) = 'object' AND scope ->> 'kind' IN ('society', 'unit')
        AND (scope ->> 'kind' = 'society'
             OR scope ->> 'unit_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')),
    CONSTRAINT role_grants_revoked_check CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE INDEX role_grants_person_idx ON role_grants (society_id, person_id);
SELECT dwaar_enable_society_rls('role_grants', 'SELECT, INSERT, UPDATE', 'SELECT');

CREATE FUNCTION iam.index_role_grant() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
BEGIN
    INSERT INTO iam.person_access_index AS i (source_kind, source_id, person_id, society_ref, unit_ref, role,
        effective, not_before, expires_at, scope, updated_at)
    VALUES ('role_grant', NEW.id, NEW.person_id, NEW.society_id,
            CASE WHEN NEW.scope ->> 'kind' = 'unit' THEN (NEW.scope ->> 'unit_id')::uuid END,
            NEW.role, NEW.revoked_at IS NULL, coalesce(NEW.not_before, NEW.issued_at), NEW.expires_at, NEW.scope, now())
    ON CONFLICT (source_kind, source_id) DO UPDATE SET
        effective = EXCLUDED.effective, not_before = EXCLUDED.not_before, expires_at = EXCLUDED.expires_at,
        scope = EXCLUDED.scope, unit_ref = EXCLUDED.unit_ref, swept_at = NULL, updated_at = now();
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION iam.index_role_grant() FROM PUBLIC;
CREATE TRIGGER role_grants_index AFTER INSERT OR UPDATE ON role_grants
    FOR EACH ROW EXECUTE FUNCTION iam.index_role_grant();

-- Only the revocation columns and the window may change after issue; who/what/why is immutable history.
CREATE FUNCTION iam.role_grant_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.person_id <> OLD.person_id OR NEW.role <> OLD.role OR NEW.issued_by <> OLD.issued_by
       OR NEW.reason <> OLD.reason OR NEW.society_id <> OLD.society_id OR NEW.scope <> OLD.scope
       OR NEW.issued_at <> OLD.issued_at THEN
        RAISE EXCEPTION 'role grants are immutable except for revocation' USING ERRCODE = '23514';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
        RAISE EXCEPTION 'a revoked grant stays revoked' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam.role_grant_immutable() FROM PUBLIC;
CREATE TRIGGER role_grants_immutable BEFORE UPDATE ON role_grants
    FOR EACH ROW EXECUTE FUNCTION iam.role_grant_immutable();
