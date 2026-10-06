-- 0460 shifts: guard profiles (language), practice-mode training records, guard shifts, start/end checklists, handovers with their
-- acknowledgements and the supervisor override that dies with the shift.
-- REQ: SHIFT-01 (start checklist; end checklist counting parcels and unresolved inside records; BOTH guards or the supervisor acknowledge; a
--      missing next guard escalates and NEVER locks the kiosk), SHIFT-02 (deterministic open-items list, always shown below the summary),
--      UX-08 (guard language per guard, stored on the guard profile), UX-09 (practice-mode training completion per guard per scenario type),
--      INV-08 (essential egress is never blocked: nothing here is read by the gate path), Appendix C (supervisor override valid until
--      shift end or earlier), INV-01 (RLS), ARCH-01, DB-02, PRD 8.2 (shift_handovers).

CREATE TABLE guard_profiles (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    -- UX-08: English, Hindi, Marathi at M1; Kannada at M2 (the service refuses it until then)
    language text NOT NULL CHECK (language IN ('en', 'hi', 'mr')),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    updated_by uuid REFERENCES iam.persons (id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT guard_profiles_person_uq UNIQUE (society_id, person_id)
);
SELECT dwaar_enable_society_rls('guard_profiles', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (language, version, updated_by, updated_at) ON TABLE guard_profiles TO dwaar_app;

-- UX-09: practice mode only (dummy units); no client work here. One row per completion, the latest per scenario type is the record.
CREATE TABLE guard_training_completions (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    scenario_type text NOT NULL CHECK (scenario_type IN
        ('guest_entry', 'delivery_entry', 'service_entry', 'cab_entry', 'staff_checkin', 'parcel_receive', 'parcel_pickup',
         'emergency_entry', 'shift_handover', 'incident_report')),
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    language text NOT NULL CHECK (language IN ('en', 'hi', 'mr')),
    practice_mode boolean NOT NULL DEFAULT true CHECK (practice_mode),
    recorded_by uuid NOT NULL REFERENCES iam.persons (id)
);
CREATE INDEX guard_training_person_idx ON guard_training_completions (society_id, person_id, scenario_type, completed_at DESC);
SELECT dwaar_enable_society_rls('guard_training_completions', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('guard_training_completions');

CREATE TABLE shifts (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    gate_id uuid NOT NULL,
    guard_id uuid NOT NULL REFERENCES iam.persons (id),
    planned_start timestamptz NOT NULL,
    planned_end timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'scheduled' CHECK (state IN ('scheduled', 'active', 'ended')),
    started_at timestamptz,
    started_by uuid REFERENCES iam.persons (id),
    ended_at timestamptz,
    ended_by uuid REFERENCES iam.persons (id),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by uuid NOT NULL REFERENCES iam.persons (id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT shifts_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT shifts_gate_fk FOREIGN KEY (society_id, gate_id) REFERENCES gates (society_id, id),
    CONSTRAINT shifts_window CHECK (planned_end > planned_start AND planned_end - planned_start <= interval '24 hours'),
    CONSTRAINT shifts_state_shape CHECK (
        (state = 'scheduled' AND started_at IS NULL AND ended_at IS NULL)
        OR (state = 'active' AND started_at IS NOT NULL AND ended_at IS NULL)
        OR (state = 'ended' AND started_at IS NOT NULL AND ended_at IS NOT NULL))
);
-- a guard is on duty in ONE active shift at a time
CREATE UNIQUE INDEX shifts_one_active_per_guard_uq ON shifts (society_id, guard_id) WHERE state = 'active';
CREATE INDEX shifts_gate_idx ON shifts (society_id, gate_id, planned_start DESC, id DESC);
CREATE INDEX shifts_guard_idx ON shifts (society_id, guard_id, planned_start DESC, id DESC);
SELECT dwaar_enable_society_rls('shifts', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (state, started_at, started_by, ended_at, ended_by, version) ON TABLE shifts TO dwaar_app;

CREATE TABLE shift_checklists (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    shift_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('start', 'end')),
    items jsonb NOT NULL CHECK (jsonb_typeof(items) = 'array' AND pg_column_size(items) <= 32768),
    completed_by uuid NOT NULL REFERENCES iam.persons (id),
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT shift_checklists_once_uq UNIQUE (society_id, shift_id, kind),
    CONSTRAINT shift_checklists_shift_fk FOREIGN KEY (society_id, shift_id) REFERENCES shifts (society_id, id)
);
SELECT dwaar_enable_society_rls('shift_checklists', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('shift_checklists');

CREATE TABLE shift_handovers (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    gate_id uuid NOT NULL,
    outgoing_shift_id uuid NOT NULL,
    incoming_shift_id uuid,
    outgoing_guard uuid NOT NULL REFERENCES iam.persons (id),
    incoming_guard uuid REFERENCES iam.persons (id),
    -- SHIFT-02: the deterministic list of open items. A summary (AI-G08, later) can only ever be shown ABOVE it.
    open_items jsonb NOT NULL CHECK (jsonb_typeof(open_items) = 'array' AND pg_column_size(open_items) <= 65536),
    summary_text text CHECK (summary_text IS NULL OR char_length(summary_text) <= 4000),
    summary_source text CHECK (summary_source IN ('ai_gateway', 'manual')),
    summary_language text CHECK (summary_language IN ('en', 'hi', 'mr')),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'acknowledged', 'escalated')),
    outgoing_ack_at timestamptz,
    incoming_ack_at timestamptz,
    supervisor_ack_at timestamptz,
    supervisor_ack_by uuid REFERENCES iam.persons (id),
    escalated_at timestamptz,
    escalation_reason text CHECK (escalation_reason IS NULL OR escalation_reason ~ '^[a-z0-9_]{3,60}$'),
    signed_at timestamptz,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT shift_handovers_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT shift_handovers_outgoing_uq UNIQUE (society_id, outgoing_shift_id),
    CONSTRAINT shift_handovers_gate_fk FOREIGN KEY (society_id, gate_id) REFERENCES gates (society_id, id),
    CONSTRAINT shift_handovers_outgoing_fk FOREIGN KEY (society_id, outgoing_shift_id) REFERENCES shifts (society_id, id),
    CONSTRAINT shift_handovers_incoming_fk FOREIGN KEY (society_id, incoming_shift_id) REFERENCES shifts (society_id, id),
    CONSTRAINT shift_handovers_summary_pair CHECK ((summary_text IS NULL) = (summary_source IS NULL)),
    CONSTRAINT shift_handovers_supervisor_pair CHECK ((supervisor_ack_at IS NULL) = (supervisor_ack_by IS NULL)),
    -- SHIFT-01: acknowledged means BOTH guards, or the supervisor
    CONSTRAINT shift_handovers_ack_shape CHECK (
        (state = 'acknowledged') = (signed_at IS NOT NULL)
        AND (state <> 'acknowledged'
             OR supervisor_ack_at IS NOT NULL
             OR (outgoing_ack_at IS NOT NULL AND incoming_ack_at IS NOT NULL))),
    CONSTRAINT shift_handovers_escalated_shape CHECK (state <> 'escalated' OR escalated_at IS NOT NULL)
);
CREATE INDEX shift_handovers_gate_idx ON shift_handovers (society_id, gate_id, created_at DESC, id DESC);
CREATE INDEX shift_handovers_state_idx ON shift_handovers (society_id, state, created_at);
SELECT dwaar_enable_society_rls('shift_handovers', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (incoming_shift_id, incoming_guard, summary_text, summary_source, summary_language, state, outgoing_ack_at,
              incoming_ack_at, supervisor_ack_at, supervisor_ack_by, escalated_at, escalation_reason, signed_at, version)
    ON TABLE shift_handovers TO dwaar_app;
GRANT UPDATE (state, escalated_at, escalation_reason, version) ON TABLE shift_handovers TO dwaar_worker;

-- Appendix C: a supervisor override is valid until the shift ends or earlier. valid_until is capped to the shift's planned end by the
-- service; the shift ending (or the override being revoked) makes it inactive regardless of valid_until.
CREATE TABLE shift_overrides (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    shift_id uuid NOT NULL,
    gate_id uuid NOT NULL,
    granted_by uuid NOT NULL REFERENCES iam.persons (id),
    reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 5 AND 500),
    granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    valid_until timestamptz NOT NULL,
    revoked_at timestamptz,
    revoke_reason text CHECK (revoke_reason IS NULL OR revoke_reason ~ '^[a-z0-9_]{3,60}$'),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CONSTRAINT shift_overrides_window CHECK (valid_until > granted_at),
    CONSTRAINT shift_overrides_shift_fk FOREIGN KEY (society_id, shift_id) REFERENCES shifts (society_id, id),
    CONSTRAINT shift_overrides_gate_fk FOREIGN KEY (society_id, gate_id) REFERENCES gates (society_id, id),
    CONSTRAINT shift_overrides_revoked_shape CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE INDEX shift_overrides_shift_idx ON shift_overrides (society_id, shift_id, granted_at DESC);
SELECT dwaar_enable_society_rls('shift_overrides', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (revoked_at, revoke_reason, version) ON TABLE shift_overrides TO dwaar_app, dwaar_worker;
