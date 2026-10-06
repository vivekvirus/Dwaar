-- 0530 helpdesk configuration: SLA targets, business calendar, emergency procedures (OPS-01, OPS-09, INV-10).
-- REQ: OPS-01 (acknowledgement and resolution clocks run on the society business calendar), OPS-04 (feedback window default
--      48 h, reopen window default 7 days), OPS-02 (similarity threshold for duplicate PROPOSALS), OPS-09 (a configurable
--      emergency-procedure record per society and hazard), INV-10 (law and policy are configuration, never hard-coded),
--      ARCH-01/INV-01 (society_id, RLS in the same migration).
--
-- One settings row per society, created lazily by the module with the PILOT DEFAULTS of PRD 9.7 (emergency 2-minute
-- acknowledgement, urgent 15 minutes, normal 4 working hours, resolution e.g. 2 working days). Every number is
-- configuration (the sla document says "pilot_default" until the society changes it); nothing here promises a rescue.

CREATE TABLE helpdesk_settings (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    timezone text NOT NULL DEFAULT 'Asia/Kolkata' CHECK (char_length(timezone) BETWEEN 3 AND 64),
    working_days smallint[] NOT NULL DEFAULT '{1,2,3,4,5,6}'
        CHECK (cardinality(working_days) BETWEEN 1 AND 7 AND working_days <@ ARRAY[1, 2, 3, 4, 5, 6, 7]::smallint[]),
    opens_at time NOT NULL DEFAULT '09:00',
    closes_at time NOT NULL DEFAULT '18:00',
    holidays date[] NOT NULL DEFAULT '{}' CHECK (cardinality(holidays) <= 400),
    sla jsonb NOT NULL CHECK (jsonb_typeof(sla) = 'object' AND pg_column_size(sla) <= 4096),
    sla_source text NOT NULL DEFAULT 'pilot_default' CHECK (sla_source IN ('pilot_default', 'society_configured')),
    feedback_window_hours integer NOT NULL DEFAULT 48 CHECK (feedback_window_hours BETWEEN 1 AND 720),
    reopen_window_days integer NOT NULL DEFAULT 7 CHECK (reopen_window_days BETWEEN 1 AND 90),
    duplicate_similarity numeric(3, 2) NOT NULL DEFAULT 0.45 CHECK (duplicate_similarity BETWEEN 0.10 AND 1.00),
    next_ticket_no integer NOT NULL DEFAULT 1 CHECK (next_ticket_no >= 1),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    updated_by uuid REFERENCES iam.persons (id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT helpdesk_settings_society_uq UNIQUE (society_id),
    CONSTRAINT helpdesk_settings_hours CHECK (closes_at > opens_at)
);
SELECT dwaar_enable_society_rls('helpdesk_settings', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (timezone, working_days, opens_at, closes_at, holidays, sla, sla_source, feedback_window_hours,
              reopen_window_days, duplicate_similarity, next_ticket_no, version, updated_by, updated_at)
    ON TABLE helpdesk_settings TO dwaar_app;

-- OPS-09: what residents and staff see IMMEDIATELY when an unsafe lift / electrical / gas / fire observation is raised.
-- The society writes its own procedure and accountable contacts; the platform never authors repair instructions.
CREATE TABLE emergency_procedures (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    hazard text NOT NULL CHECK (hazard IN ('lift', 'electrical', 'gas', 'fire', 'general')),
    headline text NOT NULL CHECK (char_length(btrim(headline)) BETWEEN 3 AND 200),
    steps text NOT NULL CHECK (char_length(btrim(steps)) BETWEEN 3 AND 2000),
    contacts jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(contacts) = 'array' AND jsonb_array_length(contacts) <= 12 AND pg_column_size(contacts) <= 4096),
    qualified_contractor text CHECK (qualified_contractor IS NULL OR char_length(qualified_contractor) BETWEEN 2 AND 200),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    updated_by uuid REFERENCES iam.persons (id),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT emergency_procedures_society_hazard_uq UNIQUE (society_id, hazard)
);
SELECT dwaar_enable_society_rls('emergency_procedures', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (headline, steps, contacts, qualified_contractor, version, updated_by, updated_at)
    ON TABLE emergency_procedures TO dwaar_app;
