-- 0133 identity: memberships, verification cases, committee holds (society-owned, RLS) + the global access index.
-- REQ: IAM-01 (memberships carry type, unit, dates, verification status, evidence), IAM-05 (owner-tenant dispute is a
--      review state, never an automatic deactivation), IAM-07 (household joining states, reasons visible to the
--      applicant, appeals reviewed by someone other than the original decision-maker), IAM-12 (owner confirmation;
--      committee hold with logged reason, visible to owner and tenant, with appeal), INV-04 (ownership, occupancy,
--      billing liability and voting entitlement are SEPARATE columns/relationships, never one "role").
--
-- Units live in the organisation module (migrations 0100-0129). Until the composite foreign key
-- (society_id, unit_id) -> units(society_id, id) is added (migration 0190) a membership's unit is an unchecked uuid.

-- ---------------------------------------------------------------------------------------------
-- Global projection used by the grant resolver. A person's grants span societies, but every society table is
-- FORCE-RLS on app.society_id, so "which societies am I in?" cannot be asked of the tables themselves. Row triggers
-- on memberships and role_grants (SECURITY DEFINER, not executable by the runtime roles) maintain this index in the
-- SAME transaction as the change. No runtime role has any table privilege on it; iam.effective_grants() and
-- iam.access_overview() read it for the context person only.
-- ---------------------------------------------------------------------------------------------
CREATE TABLE iam.person_access_index (
    source_kind text NOT NULL CHECK (source_kind IN ('membership', 'role_grant')),
    source_id uuid NOT NULL,
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    society_ref uuid NOT NULL,
    unit_ref uuid,
    role text NOT NULL CHECK (role ~ '^[a-z][a-z0-9_]{0,63}$'),
    membership_kind text,
    verification text,
    effective boolean NOT NULL,
    not_before timestamptz,
    expires_at timestamptz,
    scope jsonb,
    swept_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source_kind, source_id)
);
CREATE INDEX person_access_index_person_idx ON iam.person_access_index (person_id);
REVOKE ALL ON TABLE iam.person_access_index FROM PUBLIC, dwaar_app, dwaar_worker;

-- Which roles are elevated (MFA, IAM-03). dwaar_api.modules.identity.matrix.ELEVATED_ROLES must equal this list
-- (tests/integration/identity/test_matrix_data.py compares them).
CREATE FUNCTION iam.is_elevated_role(p_role text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path = pg_catalog
AS $$ SELECT p_role = ANY (ARRAY['secretary', 'treasurer', 'committee', 'estate_mgr', 'guard_sup', 'auditor',
                                'org_admin', 'plat_support']) $$;
REVOKE ALL ON FUNCTION iam.is_elevated_role(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.is_elevated_role(text) TO dwaar_app, dwaar_worker;

-- Effective role of a membership. Ownership and occupancy are independent facts (INV-04): an owner who does not
-- live in the unit is a non-resident owner.
CREATE FUNCTION iam.membership_role(p_kind text, p_lives boolean) RETURNS text LANGUAGE sql IMMUTABLE SET search_path = pg_catalog
AS $$ SELECT CASE p_kind WHEN 'owner' THEN CASE WHEN p_lives THEN 'owner_occ' ELSE 'owner_nr' END
                         WHEN 'joint_owner' THEN CASE WHEN p_lives THEN 'owner_occ' ELSE 'owner_nr' END
                         WHEN 'tenant' THEN 'tenant' WHEN 'family' THEN 'family' ELSE 'staff' END $$;
REVOKE ALL ON FUNCTION iam.membership_role(text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.membership_role(text, boolean) TO dwaar_app, dwaar_worker;

-- ---------------------------------------------------------------------------------------------
-- memberships
-- ---------------------------------------------------------------------------------------------
CREATE TABLE memberships (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL,
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    unit_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('owner', 'joint_owner', 'tenant', 'family', 'staff')),
    effective_from date NOT NULL DEFAULT ((now() AT TIME ZONE 'Asia/Kolkata')::date),
    effective_to date,
    -- pending|verified|rejected|disputed are the PRD states; 'reverification' is added for IAM-11 (a number change
    -- or recycle). Only verified and disputed memberships carry grants: a dispute never removes occupancy (IAM-05).
    verification text NOT NULL DEFAULT 'pending'
        CHECK (verification IN ('pending', 'verified', 'rejected', 'disputed', 'reverification')),
    evidence_ref text CHECK (evidence_ref IS NULL OR char_length(evidence_ref) <= 300),
    is_primary_approver boolean NOT NULL DEFAULT false,
    lives_in_unit boolean NOT NULL DEFAULT true,       -- occupancy (independent of ownership)
    billing_liable boolean NOT NULL DEFAULT false,     -- liability (recorded here, owned by finance)
    voting_entitled boolean NOT NULL DEFAULT false,    -- statutory voting (owned by governance)
    owner_decision text CHECK (owner_decision IN ('confirmed', 'disputed')),
    owner_decision_by uuid REFERENCES iam.persons (id),
    owner_decision_at timestamptz,
    owner_decision_reason text CHECK (owner_decision_reason IS NULL OR char_length(owner_decision_reason) <= 500),
    created_by uuid NOT NULL REFERENCES iam.persons (id),
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT memberships_dates_check CHECK (effective_to IS NULL OR effective_to >= effective_from),
    CONSTRAINT memberships_society_id_key UNIQUE (society_id, id)
);
-- One live claim per (person, unit, kind). A rejected claim does not block a fresh one; an ended one neither.
CREATE UNIQUE INDEX memberships_live_claim_uq ON memberships (society_id, person_id, unit_id, kind)
    WHERE verification <> 'rejected' AND effective_to IS NULL;
CREATE INDEX memberships_unit_idx ON memberships (society_id, unit_id);
CREATE INDEX memberships_person_idx ON memberships (person_id);
SELECT dwaar_enable_society_rls('memberships', 'SELECT, INSERT, UPDATE', 'SELECT');

-- ---------------------------------------------------------------------------------------------
-- verification cases (IAM-07)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE verification_cases (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('ownership_claim', 'tenant_onboarding', 'household_join', 'staff_onboarding',
                                       'reverification', 'dispute')),
    state text NOT NULL DEFAULT 'requested' CHECK (state IN
        ('requested', 'evidence_pending', 'society_review', 'verified', 'rejected', 'appealed', 'inactive')),
    requested_by uuid NOT NULL REFERENCES iam.persons (id),
    reviewer_id uuid REFERENCES iam.persons (id),       -- the decision-maker of the last decision
    reason text CHECK (reason IS NULL OR char_length(reason) <= 500),   -- visible to the applicant
    evidence_ref text CHECK (evidence_ref IS NULL OR char_length(evidence_ref) <= 300),
    appeal_of uuid,
    decided_at timestamptz,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT verification_cases_society_id_key UNIQUE (society_id, id),
    CONSTRAINT verification_cases_membership_fk FOREIGN KEY (society_id, membership_id)
        REFERENCES memberships (society_id, id),
    CONSTRAINT verification_cases_appeal_fk FOREIGN KEY (society_id, appeal_of)
        REFERENCES verification_cases (society_id, id),
    CONSTRAINT verification_cases_not_own_reviewer CHECK (reviewer_id IS NULL OR reviewer_id <> requested_by),
    CONSTRAINT verification_cases_appeal_state CHECK (appeal_of IS NULL OR state IN ('appealed', 'verified', 'rejected'))
);
CREATE INDEX verification_cases_membership_idx ON verification_cases (society_id, membership_id);
SELECT dwaar_enable_society_rls('verification_cases', 'SELECT, INSERT, UPDATE', 'SELECT');

-- An appeal must be decided by someone other than the person who made the decision it appeals (IAM-07). Enforced
-- here as well as in the service, so no code path (and no future module) can skip it.
CREATE FUNCTION iam.verification_appeal_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE v_prev uuid;
BEGIN
    IF NEW.appeal_of IS NOT NULL AND NEW.reviewer_id IS NOT NULL THEN
        SELECT c.reviewer_id INTO v_prev FROM public.verification_cases c
        WHERE c.society_id = NEW.society_id AND c.id = NEW.appeal_of;
        IF v_prev IS NOT NULL AND v_prev = NEW.reviewer_id THEN
            RAISE EXCEPTION 'an appeal must be reviewed by someone other than the original decision-maker'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION iam.verification_appeal_guard() FROM PUBLIC;
CREATE TRIGGER verification_cases_appeal_guard BEFORE INSERT OR UPDATE ON verification_cases
    FOR EACH ROW EXECUTE FUNCTION iam.verification_appeal_guard();

-- ---------------------------------------------------------------------------------------------
-- committee holds (IAM-12)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE membership_holds (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'appealed', 'released', 'upheld')),
    placed_by uuid NOT NULL REFERENCES iam.persons (id),
    reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 10 AND 500),   -- logged and visible to owner and tenant
    placed_at timestamptz NOT NULL DEFAULT now(),
    appeal_by uuid REFERENCES iam.persons (id),
    appeal_reason text CHECK (appeal_reason IS NULL OR char_length(appeal_reason) BETWEEN 10 AND 500),
    appealed_at timestamptz,
    decided_by uuid REFERENCES iam.persons (id),
    decision_reason text CHECK (decision_reason IS NULL OR char_length(decision_reason) <= 500),
    decided_at timestamptz,
    version integer NOT NULL DEFAULT 1,
    CONSTRAINT membership_holds_society_id_key UNIQUE (society_id, id),
    CONSTRAINT membership_holds_membership_fk FOREIGN KEY (society_id, membership_id)
        REFERENCES memberships (society_id, id),
    CONSTRAINT membership_holds_decider_differs CHECK (decided_by IS NULL OR decided_by <> placed_by)
);
CREATE UNIQUE INDEX membership_holds_one_open_uq ON membership_holds (society_id, membership_id)
    WHERE state IN ('active', 'appealed');
SELECT dwaar_enable_society_rls('membership_holds', 'SELECT, INSERT, UPDATE', 'SELECT');

-- ---------------------------------------------------------------------------------------------
-- index maintenance for memberships (role_grants does the same in 0134)
-- ---------------------------------------------------------------------------------------------
CREATE FUNCTION iam.index_membership() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
BEGIN
    INSERT INTO iam.person_access_index AS i (source_kind, source_id, person_id, society_ref, unit_ref, role,
        membership_kind, verification, effective, not_before, expires_at, updated_at)
    VALUES ('membership', NEW.id, NEW.person_id, NEW.society_id, NEW.unit_id,
            iam.membership_role(NEW.kind, NEW.lives_in_unit), NEW.kind, NEW.verification,
            NEW.verification IN ('verified', 'disputed'),
            (NEW.effective_from::timestamp AT TIME ZONE 'Asia/Kolkata'),
            CASE WHEN NEW.effective_to IS NULL THEN NULL
                 ELSE ((NEW.effective_to + 1)::timestamp AT TIME ZONE 'Asia/Kolkata') END, now())
    ON CONFLICT (source_kind, source_id) DO UPDATE SET
        role = EXCLUDED.role, membership_kind = EXCLUDED.membership_kind, verification = EXCLUDED.verification,
        effective = EXCLUDED.effective, not_before = EXCLUDED.not_before, expires_at = EXCLUDED.expires_at,
        unit_ref = EXCLUDED.unit_ref, swept_at = NULL, updated_at = now();
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION iam.index_membership() FROM PUBLIC;
CREATE TRIGGER memberships_index AFTER INSERT OR UPDATE ON memberships
    FOR EACH ROW EXECUTE FUNCTION iam.index_membership();
