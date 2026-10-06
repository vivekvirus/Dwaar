-- 0532 ticket history: events, priority history, SLA pause log, SLA breaches, duplicate links (OPS-01, OPS-02, OPS-04).
-- REQ: OPS-01 (priority history immutable with the approver recorded; pause reason and approver, immutable pause history;
--      changing priority later cannot erase a breach), OPS-04 (reopen keeps the ORIGINAL history), OPS-02 (links PROPOSE
--      only; a link can never join tickets of different scope or different private households), DB-02 (append-only),
--      ARCH-01, INV-01.

CREATE TABLE ticket_events (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    ticket_id uuid NOT NULL,
    seq integer NOT NULL CHECK (seq >= 1),
    kind text NOT NULL CHECK (kind IN (
        'created', 'submitted', 'acknowledged', 'triaged', 'assigned', 'state_changed', 'priority_changed', 'paused',
        'resumed', 'resolved', 'closed', 'reopened', 'cancelled', 'merged', 'duplicate_proposed', 'sla_breached', 'note')),
    from_state text,
    to_state text,
    actor_id uuid REFERENCES iam.persons (id),
    actor_role text NOT NULL CHECK (actor_role ~ '^[a-z][a-z0-9_]{0,63}$'),
    note text CHECK (note IS NULL OR char_length(note) <= 1000),
    data jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(data) = 'object' AND pg_column_size(data) <= 2048),
    at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ticket_events_ticket_fk FOREIGN KEY (society_id, ticket_id) REFERENCES tickets (society_id, id),
    CONSTRAINT ticket_events_seq_uq UNIQUE (society_id, ticket_id, seq)
);
SELECT dwaar_enable_society_rls('ticket_events', 'SELECT, INSERT', 'SELECT, INSERT');
SELECT dwaar_make_append_only('ticket_events');

-- Every priority a ticket ever had, who set it, who approved it, and the targets that priority implied (computed from the
-- ORIGINAL clock start, pauses excluded). Later rows never rewrite earlier ones.
CREATE TABLE ticket_priority_history (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    ticket_id uuid NOT NULL,
    seq integer NOT NULL CHECK (seq >= 1),
    priority text NOT NULL CHECK (priority IN ('emergency', 'urgent', 'normal', 'low')),
    previous_priority text CHECK (previous_priority IS NULL OR previous_priority IN ('emergency', 'urgent', 'normal', 'low')),
    set_by uuid REFERENCES iam.persons (id),
    set_role text NOT NULL CHECK (set_role ~ '^[a-z][a-z0-9_]{0,63}$'),
    approver_id uuid REFERENCES iam.persons (id),
    rule text NOT NULL CHECK (rule IN ('initial', 'hazard_rule', 'manual', 'triage')),
    reason text CHECK (reason IS NULL OR char_length(reason) <= 500),
    ack_due_at timestamptz,
    fix_due_at timestamptz,
    at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ticket_priority_history_ticket_fk FOREIGN KEY (society_id, ticket_id) REFERENCES tickets (society_id, id),
    CONSTRAINT ticket_priority_history_seq_uq UNIQUE (society_id, ticket_id, seq)
);
SELECT dwaar_enable_society_rls('ticket_priority_history', 'SELECT, INSERT', 'SELECT, INSERT');
SELECT dwaar_make_append_only('ticket_priority_history');

-- SLA pauses: a pause row, later a resume row. Never updated or deleted.
CREATE TABLE ticket_sla_log (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    ticket_id uuid NOT NULL,
    seq integer NOT NULL CHECK (seq >= 1),
    kind text NOT NULL CHECK (kind IN ('pause', 'resume')),
    reason text NOT NULL CHECK (reason IN ('awaiting_resident', 'awaiting_material')),
    actor_id uuid REFERENCES iam.persons (id),
    approver_id uuid REFERENCES iam.persons (id),
    credited_seconds bigint CHECK (credited_seconds IS NULL OR credited_seconds >= 0),
    fix_due_before timestamptz,
    fix_due_after timestamptz,
    at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ticket_sla_log_ticket_fk FOREIGN KEY (society_id, ticket_id) REFERENCES tickets (society_id, id),
    CONSTRAINT ticket_sla_log_seq_uq UNIQUE (society_id, ticket_id, seq),
    -- OPS-01: a pause always names who approved it
    CONSTRAINT ticket_sla_log_pause_approver CHECK (kind <> 'pause' OR approver_id IS NOT NULL)
);
SELECT dwaar_enable_society_rls('ticket_sla_log', 'SELECT, INSERT', 'SELECT, INSERT');
SELECT dwaar_make_append_only('ticket_sla_log');

-- A breach, once recorded, stays: it is keyed by (ticket, clock), not by priority.
CREATE TABLE ticket_sla_breaches (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    ticket_id uuid NOT NULL,
    clock text NOT NULL CHECK (clock IN ('acknowledgement', 'resolution')),
    due_at timestamptz NOT NULL,
    priority_at_breach text NOT NULL CHECK (priority_at_breach IN ('emergency', 'urgent', 'normal', 'low')),
    basis text NOT NULL CHECK (basis IN ('sweep', 'before_change', 'met_late')),
    recorded_by uuid REFERENCES iam.persons (id),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ticket_sla_breaches_ticket_fk FOREIGN KEY (society_id, ticket_id) REFERENCES tickets (society_id, id),
    CONSTRAINT ticket_sla_breaches_clock_uq UNIQUE (society_id, ticket_id, clock)
);
SELECT dwaar_enable_society_rls('ticket_sla_breaches', 'SELECT, INSERT', 'SELECT, INSERT');
SELECT dwaar_make_append_only('ticket_sla_breaches');

-- OPS-02: proposed / accepted / rejected duplicate links.
CREATE TABLE ticket_links (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    ticket_id uuid NOT NULL,
    linked_ticket_id uuid NOT NULL,
    state text NOT NULL DEFAULT 'proposed' CHECK (state IN ('proposed', 'merged', 'rejected')),
    similarity numeric(4, 3) CHECK (similarity IS NULL OR similarity BETWEEN 0 AND 1),
    method text NOT NULL CHECK (method IN ('trigram', 'manual', 'ai_grouping')),
    proposed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    decided_by uuid REFERENCES iam.persons (id),
    decided_at timestamptz,
    CONSTRAINT ticket_links_ticket_fk FOREIGN KEY (society_id, ticket_id) REFERENCES tickets (society_id, id),
    CONSTRAINT ticket_links_linked_fk FOREIGN KEY (society_id, linked_ticket_id) REFERENCES tickets (society_id, id),
    CONSTRAINT ticket_links_pair_uq UNIQUE (society_id, ticket_id, linked_ticket_id),
    CONSTRAINT ticket_links_distinct CHECK (ticket_id <> linked_ticket_id)
);
CREATE INDEX ticket_links_linked_idx ON ticket_links (society_id, linked_ticket_id);
SELECT dwaar_enable_society_rls('ticket_links', 'SELECT, INSERT', 'SELECT, INSERT');
GRANT UPDATE (state, decided_by, decided_at) ON TABLE ticket_links TO dwaar_app;

-- Defence in depth for OPS-02: whatever the application does, a link (proposed by a model, a rule or a person) can only
-- join tickets of the SAME scope, and private tickets only inside the SAME household unit; block tickets inside the SAME block.
CREATE FUNCTION ticket_links_same_scope_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE a record; b record;
BEGIN
    SELECT scope, unit_id, block_id INTO a FROM tickets WHERE society_id = NEW.society_id AND id = NEW.ticket_id;
    SELECT scope, unit_id, block_id INTO b FROM tickets WHERE society_id = NEW.society_id AND id = NEW.linked_ticket_id;
    IF a.scope IS DISTINCT FROM b.scope
       OR (a.scope = 'private' AND a.unit_id IS DISTINCT FROM b.unit_id)
       OR (a.scope = 'block' AND a.block_id IS DISTINCT FROM b.block_id) THEN
        RAISE EXCEPTION 'ticket link across scope or household is not allowed' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER ticket_links_same_scope BEFORE INSERT ON ticket_links
    FOR EACH ROW EXECUTE FUNCTION ticket_links_same_scope_guard();

-- The same rule for a merge (tickets.parent_ticket_id): a ticket can only be merged into one of the same scope / household / block.
CREATE FUNCTION tickets_parent_scope_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE p record;
BEGIN
    IF NEW.parent_ticket_id IS NULL THEN RETURN NEW; END IF;
    SELECT scope, unit_id, block_id INTO p FROM tickets WHERE society_id = NEW.society_id AND id = NEW.parent_ticket_id;
    IF p.scope IS DISTINCT FROM NEW.scope
       OR (NEW.scope = 'private' AND p.unit_id IS DISTINCT FROM NEW.unit_id)
       OR (NEW.scope = 'block' AND p.block_id IS DISTINCT FROM NEW.block_id) THEN
        RAISE EXCEPTION 'ticket merge across scope or household is not allowed' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER tickets_parent_scope BEFORE INSERT OR UPDATE OF parent_ticket_id ON tickets
    FOR EACH ROW EXECUTE FUNCTION tickets_parent_scope_guard();
