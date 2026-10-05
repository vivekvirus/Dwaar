-- 0205 gate exceptions (PRD 9.2 Exception: open -> supervisor_review -> resolved / escalated; GATE-07, GATE-11).
-- REQ: GATE-07 (emergency or manual entry needs a defined local authority and a reason, audited: nothing is an
--      invisible bypass), GATE-11 (an overstay produces an exception), PRD 9.2 (an exception records reason, actor,
--      evidence and whether entry happened), PRD 8.2 (exceptions).

CREATE TABLE exceptions (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    kind text NOT NULL CHECK (kind IN
        ('overstay', 'unauthorised_entry', 'exit_unknown', 'exit_without_entry', 'emergency_entry', 'manual_entry', 'other')),
    visit_id uuid,
    reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 5 AND 500),
    actor_id uuid REFERENCES iam.persons (id),
    raised_by_system boolean NOT NULL DEFAULT false,
    evidence_ref text CHECK (evidence_ref IS NULL OR char_length(evidence_ref) <= 300),
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(evidence) = 'object' AND pg_column_size(evidence) <= 4096),
    entry_happened boolean,                                  -- NULL = not known
    state text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'supervisor_review', 'resolved', 'escalated')),
    reviewed_by uuid REFERENCES iam.persons (id),
    resolved_by uuid REFERENCES iam.persons (id),
    resolved_at timestamptz,
    resolution_note text CHECK (resolution_note IS NULL OR char_length(resolution_note) <= 500),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'VIS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT exceptions_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT exceptions_visit_fk FOREIGN KEY (society_id, visit_id) REFERENCES visits (society_id, id),
    CONSTRAINT exceptions_actor_known CHECK (actor_id IS NOT NULL OR raised_by_system),
    CONSTRAINT exceptions_resolved_shape CHECK (
        (state = 'resolved') = (resolved_by IS NOT NULL AND resolved_at IS NOT NULL AND resolution_note IS NOT NULL))
);
-- one overstay exception per visit: the detection job can run any number of times
CREATE UNIQUE INDEX exceptions_one_overstay_uq ON exceptions (society_id, visit_id) WHERE kind = 'overstay';
CREATE INDEX exceptions_state_idx ON exceptions (society_id, state, created_at DESC, id DESC);
SELECT dwaar_enable_society_rls('exceptions', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (state, reviewed_by, resolved_by, resolved_at, resolution_note, version)
    ON TABLE exceptions TO dwaar_app, dwaar_worker;
GRANT INSERT ON TABLE exceptions TO dwaar_worker;
