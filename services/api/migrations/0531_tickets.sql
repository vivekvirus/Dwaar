-- 0531 tickets (OPS-01..OPS-04, OPS-09, UX-07, PRD 8.2 tickets).
-- REQ: OPS-01 (state machine draft -> submitted -> triaged -> assigned -> in_progress -> awaiting_material /
--      awaiting_resident -> resolved -> closed, with reopen and cancel; acknowledgement and resolution clocks),
--      OPS-02 (scope private household / block / society), OPS-04 (closure by confirmation or feedback window; reopen
--      keeps the ORIGINAL clocks), OPS-09 (hazard kind, contractor routing), UX-07 (category 'support_privacy'),
--      PRD 8.2 (unit_id null, scope, category, priority, state, assignee_id, sla_ack_by, sla_fix_by, parent_ticket_id,
--      ai_meta), ARCH-01 (composite FKs make cross-society references impossible), INV-01 (RLS), INV-07.
--
-- Ticket text is untrusted data. It is never copied into audit rows or outbox payloads by the module (ids and states only).

CREATE TABLE tickets (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    ticket_no integer NOT NULL CHECK (ticket_no >= 1),
    unit_id uuid,
    block_id uuid,
    scope text NOT NULL CHECK (scope IN ('private', 'block', 'society')),
    category text NOT NULL CHECK (category IN (
        'plumbing', 'electrical', 'lift', 'gas', 'fire_safety', 'cleaning', 'security', 'parking', 'noise',
        'common_area', 'water_supply', 'garden', 'pest', 'civil', 'other', 'support_privacy')),
    priority text NOT NULL CHECK (priority IN ('emergency', 'urgent', 'normal', 'low')),
    state text NOT NULL DEFAULT 'draft' CHECK (state IN (
        'draft', 'submitted', 'triaged', 'assigned', 'in_progress', 'awaiting_material', 'awaiting_resident',
        'resolved', 'closed', 'cancelled')),
    title text NOT NULL CHECK (char_length(btrim(title)) BETWEEN 3 AND 200),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 4000),
    photo_refs text[] NOT NULL DEFAULT '{}' CHECK (cardinality(photo_refs) <= 6),
    raised_by uuid NOT NULL REFERENCES iam.persons (id),
    raised_channel text NOT NULL DEFAULT 'form'
        CHECK (raised_channel IN ('form', 'guard', 'manager', 'support', 'ai_intake')),
    assignee_id uuid REFERENCES iam.persons (id),
    contractor_name text CHECK (contractor_name IS NULL OR char_length(btrim(contractor_name)) BETWEEN 2 AND 200),
    routing text NOT NULL DEFAULT 'staff' CHECK (routing IN ('staff', 'qualified_contractor')),
    beyond_staff_competence boolean NOT NULL DEFAULT false,
    hazard_kind text CHECK (hazard_kind IS NULL OR hazard_kind IN ('lift', 'electrical', 'gas', 'fire')),
    hazard_rule text CHECK (hazard_rule IS NULL OR char_length(hazard_rule) <= 60),
    sla_started_at timestamptz,
    sla_ack_by timestamptz,
    sla_fix_by timestamptz,
    ack_at timestamptz,
    ack_by uuid REFERENCES iam.persons (id),
    sla_paused_since timestamptz,
    submitted_at timestamptz,
    resolved_at timestamptz,
    feedback_due_at timestamptz,
    closed_at timestamptz,
    closed_basis text CHECK (closed_basis IN ('resident_confirmed', 'feedback_window_elapsed', 'manager_closed', 'merged')),
    reopen_count integer NOT NULL DEFAULT 0 CHECK (reopen_count >= 0),
    reopened_at timestamptz,
    parent_ticket_id uuid,
    merged_at timestamptz,
    ai_meta jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(ai_meta) = 'object' AND pg_column_size(ai_meta) <= 8192),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'OPS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT tickets_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT tickets_society_no_uq UNIQUE (society_id, ticket_no),
    CONSTRAINT tickets_unit_fk FOREIGN KEY (society_id, unit_id) REFERENCES units (society_id, id),
    CONSTRAINT tickets_block_fk FOREIGN KEY (society_id, block_id) REFERENCES blocks (society_id, id),
    CONSTRAINT tickets_parent_fk FOREIGN KEY (society_id, parent_ticket_id) REFERENCES tickets (society_id, id),
    CONSTRAINT tickets_scope_shape CHECK (
        (scope = 'private' AND unit_id IS NOT NULL AND block_id IS NULL)
        OR (scope = 'block' AND block_id IS NOT NULL AND unit_id IS NULL)
        OR (scope = 'society' AND block_id IS NULL AND unit_id IS NULL)),
    -- a draft has no clock; a submitted ticket always has both targets and a start
    CONSTRAINT tickets_draft_shape CHECK (
        (state = 'draft' AND submitted_at IS NULL AND sla_started_at IS NULL)
        OR (state <> 'draft' AND submitted_at IS NOT NULL)),
    CONSTRAINT tickets_clock_shape CHECK (
        state IN ('draft', 'cancelled')
        OR (sla_started_at IS NOT NULL AND sla_ack_by IS NOT NULL AND sla_fix_by IS NOT NULL)),
    CONSTRAINT tickets_closed_shape CHECK ((state = 'closed') = (closed_at IS NOT NULL)),
    CONSTRAINT tickets_contractor_shape CHECK (routing = 'staff' OR contractor_name IS NOT NULL OR assignee_id IS NULL),
    -- the support/privacy channel is always a private, household-level ticket (UX-07)
    CONSTRAINT tickets_support_private CHECK (category <> 'support_privacy' OR scope = 'private'),
    CONSTRAINT tickets_no_self_parent CHECK (parent_ticket_id IS NULL OR parent_ticket_id <> id)
);
CREATE INDEX tickets_state_idx ON tickets (society_id, state, created_at DESC, id DESC);
CREATE INDEX tickets_created_idx ON tickets (society_id, created_at DESC, id DESC);
CREATE INDEX tickets_unit_idx ON tickets (society_id, unit_id, created_at DESC, id DESC) WHERE unit_id IS NOT NULL;
CREATE INDEX tickets_block_idx ON tickets (society_id, block_id, created_at DESC, id DESC) WHERE block_id IS NOT NULL;
CREATE INDEX tickets_raised_idx ON tickets (society_id, raised_by, created_at DESC, id DESC);
CREATE INDEX tickets_due_idx ON tickets (society_id, state, feedback_due_at) WHERE state = 'resolved';
CREATE INDEX tickets_sla_idx ON tickets (society_id, sla_ack_by, sla_fix_by)
    WHERE state NOT IN ('draft', 'resolved', 'closed', 'cancelled');
-- OPS-02: deterministic duplicate PROPOSALS (pg_trgm), same scope only; the application never compares across households.
CREATE INDEX tickets_text_trgm_idx ON tickets USING gin ((lower(title || ' ' || description)) gin_trgm_ops);

SELECT dwaar_enable_society_rls('tickets', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (category, priority, state, assignee_id, contractor_name, routing, beyond_staff_competence, hazard_kind,
              hazard_rule, sla_started_at, sla_ack_by, sla_fix_by, ack_at, ack_by, sla_paused_since, submitted_at,
              resolved_at, feedback_due_at, closed_at, closed_basis, reopen_count, reopened_at, parent_ticket_id,
              merged_at, ai_meta, photo_refs, version, updated_at)
    ON TABLE tickets TO dwaar_app, dwaar_worker;
