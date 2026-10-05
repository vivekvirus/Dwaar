-- 0204 access events: the append-only record of PHYSICAL observations (entries and exits).
-- REQ: INV-07 / GATE-05 (observed movement is its own record: an observation never creates or widens permission),
--      PRD 9.3 (the gate is authoritative for physical observations; append-only; deduplicate and flag, never overwrite),
--      DB-02 (access_events reject UPDATE and DELETE for the application role), PRD 8.2 (unique (device_id, seq);
--      unique (event_id)), PRD 12.3 (event fields), GATE-07 (decision_source supervisor_override is recorded).
--
-- Deviation from PRD 8.2 (recorded in ADR-0013): event_id uniqueness is per society (society_id, event_id). A global unique
-- index on a tenant table answers "does this event id exist elsewhere?" to every caller (ADR-0004); UUIDv7 ids do not
-- collide in practice, so nothing is lost.

CREATE TABLE access_events (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    device_id uuid NOT NULL,
    seq bigint NOT NULL CHECK (seq >= 0),
    event_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type IN ('EntryObserved', 'ExitObserved')),
    gate_id uuid NOT NULL,
    lane_id uuid,
    visit_id uuid,
    credential_kind text NOT NULL CHECK (credential_kind IN ('qr', 'code', 'guard_assisted', 'resident_app', 'rfid', 'anpr', 'none')),
    decision_source text NOT NULL CHECK (decision_source IN
        ('cached_policy', 'resident_app', 'ivr', 'guard_assisted', 'supervisor_override', 'rfid', 'anpr')),
    policy_version bigint CHECK (policy_version IS NULL OR policy_version >= 0),
    occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    clock_uncertainty_ms integer NOT NULL DEFAULT 0 CHECK (clock_uncertainty_ms BETWEEN 0 AND 86400000),
    payload_hash text NOT NULL CHECK (payload_hash ~ '^sha256:[0-9a-f]{64}$'),
    signature text CHECK (signature IS NULL OR signature ~ '^ed25519:[A-Za-z0-9_-]{86}$'),   -- edge signature (slice 3); NULL for guard-app entries
    payload jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(payload) = 'object' AND pg_column_size(payload) <= 4096),
    recorded_by uuid REFERENCES iam.persons (id),
    retention_class text NOT NULL DEFAULT 'VIS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT access_events_device_seq_uq UNIQUE (society_id, device_id, seq),
    CONSTRAINT access_events_event_uq UNIQUE (society_id, event_id),
    CONSTRAINT access_events_device_fk FOREIGN KEY (society_id, device_id) REFERENCES devices (society_id, id),
    CONSTRAINT access_events_gate_fk FOREIGN KEY (society_id, gate_id) REFERENCES gates (society_id, id),
    CONSTRAINT access_events_lane_fk FOREIGN KEY (society_id, lane_id) REFERENCES lanes (society_id, id),
    CONSTRAINT access_events_visit_fk FOREIGN KEY (society_id, visit_id) REFERENCES visits (society_id, id)
);
CREATE INDEX access_events_visit_idx ON access_events (society_id, visit_id, occurred_at);
CREATE INDEX access_events_gate_idx ON access_events (society_id, gate_id, occurred_at DESC);
SELECT dwaar_enable_society_rls('access_events', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('access_events');
