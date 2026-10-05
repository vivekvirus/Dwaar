-- 0203 approval requests and decisions (GATE-02, GATE-03, PRD 9.2 Approval request state machine, PRD 12.3).
-- REQ: GATE-02 (unannounced visitor: destination confirmed, visitor notice and consent recorded, request expires after
--      the society policy, never an auto-admission), GATE-03 (a denied or expired request cannot be resurrected by a
--      stale approval: the decision is a compare-and-swap on state and version), PRD 9.2 (pending -> approved / denied /
--      expired / cancelled; the first valid decision wins; a later reversal is a NEW event), PRD 8.2 (UNIQUE one valid
--      first decision per request), INV-03 (no auto-allow on timeout), INV-07.
--
-- The decision is two writes in one transaction: a conditional UPDATE of approval_requests (state 'pending', version
-- and expiry checked in the WHERE clause) and the INSERT of the winning decision. The partial unique index below
-- is the second, independent guard: even a buggy writer cannot record two valid first decisions.

CREATE TABLE approval_requests (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    unit_id uuid NOT NULL,
    visit_id uuid NOT NULL,
    gate_id uuid,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'denied', 'expired', 'cancelled')),
    expires_at timestamptz NOT NULL,
    cascade jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(cascade) = 'object' AND pg_column_size(cascade) <= 8192),
    destination_confirmed boolean NOT NULL DEFAULT false,
    requested_by uuid NOT NULL REFERENCES iam.persons (id),
    decision_id uuid,
    closed_at timestamptz,
    closed_reason text CHECK (closed_reason IS NULL OR char_length(closed_reason) <= 100),
    permission_expires_at timestamptz,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'VIS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT approval_requests_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT approval_requests_unit_fk FOREIGN KEY (society_id, unit_id) REFERENCES units (society_id, id),
    CONSTRAINT approval_requests_visit_fk FOREIGN KEY (society_id, visit_id) REFERENCES visits (society_id, id),
    CONSTRAINT approval_requests_gate_fk FOREIGN KEY (society_id, gate_id) REFERENCES gates (society_id, id),
    CONSTRAINT approval_requests_closed_shape CHECK ((state = 'pending') = (closed_at IS NULL)),
    -- an approval always carries the decision and the permission window; nothing else ever does
    CONSTRAINT approval_requests_permission_shape CHECK (
        (state = 'approved' AND decision_id IS NOT NULL AND permission_expires_at IS NOT NULL)
        OR (state <> 'approved' AND permission_expires_at IS NULL))
);
CREATE INDEX approval_requests_unit_idx ON approval_requests (society_id, unit_id, state, created_at DESC, id DESC);
CREATE INDEX approval_requests_visit_idx ON approval_requests (society_id, visit_id);
CREATE INDEX approval_requests_due_idx ON approval_requests (society_id, expires_at) WHERE state = 'pending';
SELECT dwaar_enable_society_rls('approval_requests', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (state, decision_id, closed_at, closed_reason, permission_expires_at, version)
    ON TABLE approval_requests TO dwaar_app, dwaar_worker;

CREATE TABLE approval_decisions (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    request_id uuid NOT NULL,
    decided_by uuid NOT NULL REFERENCES iam.persons (id),
    decider_role text NOT NULL CHECK (decider_role ~ '^[a-z][a-z0-9_]{0,63}$'),
    decision text NOT NULL CHECK (decision IN ('approve', 'deny', 'reverse')),
    channel text NOT NULL DEFAULT 'app' CHECK (channel IN ('app', 'ivr', 'whatsapp', 'sms', 'guard_assisted')),
    client_action_id uuid NOT NULL,
    valid boolean NOT NULL,                         -- true only for the first decision (approve / deny); a reversal is a new, non-first event
    request_version integer NOT NULL CHECK (request_version >= 2),   -- the request's version AFTER this decision
    reverses_decision_id uuid,
    reason text CHECK (reason IS NULL OR char_length(reason) <= 500),
    decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'VIS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT approval_decisions_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT approval_decisions_request_fk FOREIGN KEY (society_id, request_id)
        REFERENCES approval_requests (society_id, id),
    CONSTRAINT approval_decisions_reverses_fk FOREIGN KEY (society_id, reverses_decision_id)
        REFERENCES approval_decisions (society_id, id),
    CONSTRAINT approval_decisions_action_uq UNIQUE (society_id, request_id, decided_by, client_action_id),
    CONSTRAINT approval_decisions_valid_shape CHECK (
        (decision IN ('approve', 'deny') AND valid AND reverses_decision_id IS NULL)
        OR (decision = 'reverse' AND NOT valid AND reverses_decision_id IS NOT NULL))
);
-- PRD 8.2: unique (request_id) for the first valid decision
CREATE UNIQUE INDEX approval_decisions_first_valid_uq ON approval_decisions (society_id, request_id) WHERE valid;
SELECT dwaar_enable_society_rls('approval_decisions', 'SELECT, INSERT', 'SELECT');
-- history: a decision is never rewritten
SELECT dwaar_make_append_only('approval_decisions');

-- The winning decision is written after the compare-and-swap that points at it: deferred.
ALTER TABLE approval_requests
    ADD CONSTRAINT approval_requests_decision_fk FOREIGN KEY (society_id, decision_id)
        REFERENCES approval_decisions (society_id, id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE visit_stops
    ADD CONSTRAINT visit_stops_request_fk FOREIGN KEY (society_id, approval_request_id)
        REFERENCES approval_requests (society_id, id) DEFERRABLE INITIALLY DEFERRED;
