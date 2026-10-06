-- 0430 staff: consent receipts, the staff register, per-household engagements, attendance observations with appended corrections, and
-- payroll adjustments that need household approval.
-- REQ: STAFF-01 (one staff person, SEPARATE engagements per household, valid hours; guards see only currently authorised destinations),
--      STAFF-02 (attendance is an observation; corrections are APPENDED with who, why and when; payroll adjustments need household
--      approval), STAFF-03 (ending one engagement never touches another), STAFF-04 (consent captured in the staff member's language BEFORE any
--      data capture; no global blacklist: nothing in this schema is shared across societies or households), STAFF-05 (check-in by code
--      or card; NO face-matching column exists, by design), PRIV-03/PRIV-04 (data minimisation: ID numbers only masked, police verification as
--      a STATUS only), INV-01 (RLS), ARCH-01 (composite FKs), DB-02 (append-only history), PRD 8.2 (staff, staff_engagements, attendance_events).

-- ---------------------------------------------------------------------------------------------
-- staff_consents: the consent_receipt record. It exists BEFORE the staff row (the staff row requires one).
-- ---------------------------------------------------------------------------------------------
CREATE TABLE staff_consents (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    language text NOT NULL CHECK (language IN ('en', 'hi', 'mr', 'kn')),
    notice_version text NOT NULL CHECK (char_length(btrim(notice_version)) BETWEEN 1 AND 50),
    channel text NOT NULL CHECK (channel IN ('assisted_tablet', 'ivr_assisted')),
    purposes text[] NOT NULL CHECK (cardinality(purposes) BETWEEN 1 AND 5
        AND purposes <@ ARRAY['engagement_record', 'attendance', 'id_capture', 'photo', 'police_verification_status']::text[]),
    -- PRIV-03: a guard tap is NOT consent. The staff member's own affirmative action (and the notice being read aloud) are recorded.
    staff_action_recorded boolean NOT NULL CHECK (staff_action_recorded),
    notice_read_aloud boolean NOT NULL DEFAULT false,
    captured_by uuid NOT NULL REFERENCES iam.persons (id),
    given_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- IVR assist is M2: only the labelled simulator can record that channel
    simulation boolean NOT NULL DEFAULT false,
    withdrawn_at timestamptz,
    withdrawn_by uuid REFERENCES iam.persons (id),
    withdrawn_reason text CHECK (withdrawn_reason IS NULL OR char_length(withdrawn_reason) <= 500),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    retention_class text NOT NULL DEFAULT 'CONSENT' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT staff_consents_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT staff_consents_ivr_is_simulated CHECK (channel = 'assisted_tablet' OR simulation),
    CONSTRAINT staff_consents_withdrawal_shape CHECK ((withdrawn_at IS NULL) = (withdrawn_by IS NULL))
);
SELECT dwaar_enable_society_rls('staff_consents', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (withdrawn_at, withdrawn_by, withdrawn_reason, version) ON TABLE staff_consents TO dwaar_app;

-- ---------------------------------------------------------------------------------------------
-- staff
-- ---------------------------------------------------------------------------------------------
CREATE TABLE staff (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    -- the society's own record of the name (the global iam.persons row is reachable only through reviewed definers)
    display_name text NOT NULL CHECK (char_length(btrim(display_name)) BETWEEN 1 AND 120),
    staff_ref text NOT NULL CHECK (staff_ref ~ '^[A-Z2-7]{10}$'),
    staff_type text NOT NULL CHECK (staff_type IN ('domestic_help', 'cook', 'driver', 'nanny', 'gardener', 'caretaker', 'other')),
    consent_id uuid NOT NULL,
    photo_ref text CHECK (photo_ref IS NULL OR char_length(photo_ref) <= 300),
    -- PRIV-04: an ID number is NEVER stored; only the kind and a masked display value (Aadhaar: last 4 digits)
    id_doc_kind text CHECK (id_doc_kind IN ('aadhaar', 'driving_licence', 'voter_id', 'other')),
    id_doc_masked text CHECK (id_doc_masked IS NULL OR id_doc_masked ~ '^(X{4} )+[0-9A-Za-z]{4}$'),
    -- a STATUS only: no certificate, no document, no police record
    police_verification_status text NOT NULL DEFAULT 'not_recorded'
        CHECK (police_verification_status IN ('not_recorded', 'requested', 'verified', 'not_verified', 'expired')),
    police_verification_recorded_at timestamptz,
    credential_code_hash text,
    credential_card_hash text,
    credential_issued_at timestamptz,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by uuid NOT NULL REFERENCES iam.persons (id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'STAFF' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT staff_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT staff_person_uq UNIQUE (society_id, person_id),
    CONSTRAINT staff_ref_uq UNIQUE (society_id, staff_ref),
    CONSTRAINT staff_consent_uq UNIQUE (society_id, consent_id),
    CONSTRAINT staff_code_uq UNIQUE (society_id, credential_code_hash),
    CONSTRAINT staff_card_uq UNIQUE (society_id, credential_card_hash),
    CONSTRAINT staff_consent_fk FOREIGN KEY (society_id, consent_id) REFERENCES staff_consents (society_id, id),
    CONSTRAINT staff_id_doc_pair CHECK ((id_doc_kind IS NULL) = (id_doc_masked IS NULL))
);
SELECT dwaar_enable_society_rls('staff', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (display_name, photo_ref, id_doc_kind, id_doc_masked, police_verification_status, police_verification_recorded_at,
              credential_code_hash, credential_card_hash, credential_issued_at, status, staff_type, version)
    ON TABLE staff TO dwaar_app;

-- ---------------------------------------------------------------------------------------------
-- staff_engagements: one row per (staff person, household). Ending one never touches another (STAFF-03).
-- ---------------------------------------------------------------------------------------------
CREATE TABLE staff_engagements (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    staff_id uuid NOT NULL,
    unit_id uuid NOT NULL,
    duty text NOT NULL CHECK (char_length(btrim(duty)) BETWEEN 1 AND 60),
    -- valid hours: {"days": ["mon", ...], "from": "07:00", "to": "11:00"} in Asia/Kolkata (validated by the service)
    schedule jsonb NOT NULL CHECK (jsonb_typeof(schedule) = 'object' AND pg_column_size(schedule) <= 1024),
    effective_from date NOT NULL DEFAULT ((now() AT TIME ZONE 'Asia/Kolkata')::date),
    effective_to date,
    ended_at timestamptz,
    ended_by uuid REFERENCES iam.persons (id),
    end_reason text CHECK (end_reason IS NULL OR char_length(btrim(end_reason)) BETWEEN 5 AND 500),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by uuid NOT NULL REFERENCES iam.persons (id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'STAFF' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT staff_engagements_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT staff_engagements_staff_fk FOREIGN KEY (society_id, staff_id) REFERENCES staff (society_id, id),
    CONSTRAINT staff_engagements_unit_fk FOREIGN KEY (society_id, unit_id) REFERENCES units (society_id, id),
    CONSTRAINT staff_engagements_dates CHECK (effective_to IS NULL OR effective_to >= effective_from),
    CONSTRAINT staff_engagements_end_shape CHECK (
        (ended_at IS NULL) = (ended_by IS NULL) AND (ended_at IS NULL) = (end_reason IS NULL)),
    -- two live engagements of the same person in the same household cannot overlap in time
    CONSTRAINT staff_engagements_no_overlap EXCLUDE USING gist (
        society_id WITH =, staff_id WITH =, unit_id WITH =,
        daterange(effective_from, effective_to, '[]') WITH &&) WHERE (ended_at IS NULL)
);
CREATE INDEX staff_engagements_unit_idx ON staff_engagements (society_id, unit_id, created_at DESC, id DESC);
CREATE INDEX staff_engagements_staff_idx ON staff_engagements (society_id, staff_id);
SELECT dwaar_enable_society_rls('staff_engagements', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (duty, schedule, effective_to, ended_at, ended_by, end_reason, version) ON TABLE staff_engagements TO dwaar_app;

-- ---------------------------------------------------------------------------------------------
-- attendance_events (an OBSERVATION: it never creates or removes permission) and appended corrections
-- ---------------------------------------------------------------------------------------------
CREATE TABLE attendance_events (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    staff_id uuid NOT NULL,
    engagement_id uuid,
    direction text NOT NULL CHECK (direction IN ('in', 'out')),
    credential_kind text NOT NULL CHECK (credential_kind IN ('code', 'card', 'manual_by_guard')),
    device_id uuid,
    seq bigint CHECK (seq IS NULL OR seq >= 0),
    client_event_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    recorded_by uuid NOT NULL REFERENCES iam.persons (id),
    authorised_now boolean NOT NULL,
    CONSTRAINT attendance_events_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT attendance_events_client_uq UNIQUE (society_id, client_event_id),
    CONSTRAINT attendance_events_device_seq_uq UNIQUE (society_id, device_id, seq),
    CONSTRAINT attendance_events_staff_fk FOREIGN KEY (society_id, staff_id) REFERENCES staff (society_id, id),
    CONSTRAINT attendance_events_engagement_fk FOREIGN KEY (society_id, engagement_id) REFERENCES staff_engagements (society_id, id),
    CONSTRAINT attendance_events_device_fk FOREIGN KEY (society_id, device_id) REFERENCES devices (society_id, id)
);
CREATE INDEX attendance_events_staff_idx ON attendance_events (society_id, staff_id, occurred_at DESC, id DESC);
CREATE INDEX attendance_events_engagement_idx ON attendance_events (society_id, engagement_id, occurred_at DESC, id DESC);
SELECT dwaar_enable_society_rls('attendance_events', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('attendance_events');

CREATE TABLE attendance_corrections (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    attendance_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('void', 'amend_time', 'amend_direction')),
    new_occurred_at timestamptz,
    new_direction text CHECK (new_direction IN ('in', 'out')),
    reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 5 AND 500),
    corrected_by uuid NOT NULL REFERENCES iam.persons (id),
    corrector_role text NOT NULL CHECK (corrector_role ~ '^[a-z][a-z0-9_]{0,63}$'),
    at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT attendance_corrections_attendance_fk FOREIGN KEY (society_id, attendance_id)
        REFERENCES attendance_events (society_id, id),
    CONSTRAINT attendance_corrections_shape CHECK (
        (kind = 'void' AND new_occurred_at IS NULL AND new_direction IS NULL)
        OR (kind = 'amend_time' AND new_occurred_at IS NOT NULL AND new_direction IS NULL)
        OR (kind = 'amend_direction' AND new_direction IS NOT NULL AND new_occurred_at IS NULL))
);
CREATE INDEX attendance_corrections_idx ON attendance_corrections (society_id, attendance_id, at);
SELECT dwaar_enable_society_rls('attendance_corrections', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('attendance_corrections');

-- ---------------------------------------------------------------------------------------------
-- payroll_adjustments: money in integer paise (INV-02); a household must approve (STAFF-02)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE payroll_adjustments (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    engagement_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('bonus', 'deduction', 'advance_recovery', 'attendance_credit')),
    amount_paise bigint NOT NULL CHECK (amount_paise > 0 AND amount_paise <= 100000000),
    period text NOT NULL CHECK (period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
    reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 5 AND 500),
    state text NOT NULL DEFAULT 'proposed' CHECK (state IN ('proposed', 'approved', 'rejected')),
    proposed_by uuid NOT NULL REFERENCES iam.persons (id),
    proposer_role text NOT NULL CHECK (proposer_role ~ '^[a-z][a-z0-9_]{0,63}$'),
    proposed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    decided_by uuid REFERENCES iam.persons (id),
    decided_at timestamptz,
    decision_note text CHECK (decision_note IS NULL OR char_length(decision_note) <= 500),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    retention_class text NOT NULL DEFAULT 'STAFF' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT payroll_adjustments_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT payroll_adjustments_engagement_fk FOREIGN KEY (society_id, engagement_id) REFERENCES staff_engagements (society_id, id),
    CONSTRAINT payroll_adjustments_decision_shape CHECK (
        (state = 'proposed') = (decided_by IS NULL AND decided_at IS NULL))
);
CREATE INDEX payroll_adjustments_engagement_idx ON payroll_adjustments (society_id, engagement_id, proposed_at DESC, id DESC);
SELECT dwaar_enable_society_rls('payroll_adjustments', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (state, decided_by, decided_at, decision_note, version) ON TABLE payroll_adjustments TO dwaar_app;
