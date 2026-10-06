-- 0301 standing rules per household (GATE-14): e.g. food delivery after 10 PM is left at the gate; a milk vendor is allowed daily 6 to 7 AM.
-- REQ: GATE-14 (standing rules per household evaluated LOCALLY by the edge policy; published in the signed snapshot), INV-03 (a rule
--      pre-authorises a category inside a window, never a person, and never replaces guard confirmation), INV-01 (RLS), INV-10 (the
--      allowed shapes are data, validated by the service), PRD 8.2.
CREATE TABLE standing_rules (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    unit_id uuid NOT NULL,
    rule_kind text NOT NULL CHECK (rule_kind IN ('leave_at_gate', 'allow_window')),
    params jsonb NOT NULL CHECK (jsonb_typeof(params) = 'object' AND pg_column_size(params) <= 2048),
    effective_from date NOT NULL DEFAULT ((now() AT TIME ZONE 'Asia/Kolkata')::date),
    effective_to date,
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'ended')),
    created_by uuid NOT NULL REFERENCES iam.persons (id),
    ended_by uuid REFERENCES iam.persons (id),
    ended_at timestamptz,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'VIS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT standing_rules_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT standing_rules_unit_fk FOREIGN KEY (society_id, unit_id) REFERENCES units (society_id, id),
    CONSTRAINT standing_rules_dates_check CHECK (effective_to IS NULL OR effective_to >= effective_from),
    CONSTRAINT standing_rules_ended_shape CHECK ((state = 'ended') = (ended_at IS NOT NULL AND ended_by IS NOT NULL))
);
CREATE INDEX standing_rules_unit_idx ON standing_rules (society_id, unit_id, state);
SELECT dwaar_enable_society_rls('standing_rules', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (state, effective_to, ended_by, ended_at, version) ON TABLE standing_rules TO dwaar_app;
