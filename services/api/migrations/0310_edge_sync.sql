-- 0310 edge sync: the per-device cursor, the ledger of processed edge events and the quarantine.
-- REQ: EDGE-03 (<= 500 events or 1 MB per batch; per-event outcome, highest contiguous acknowledged sequence, gaps, policy cursor; a bad
--      event is quarantined without blocking later events), EDGE-07 (verify -> reject wrong society/schema -> deduplicate (device_id, seq)
--      and event_id -> enforce transition -> commit record, audit and outbox atomically; invalid transitions go to the exception queue;
--      physical entries are never silently discarded), EDGE-05 (clock uncertainty recorded, timestamps never rewritten), OBS-02 (sync age,
--      policy age), PRD 9.3 (append-only observations, preserve both observations on conflict), DB-02, INV-01.
--
-- edge_events is the idempotency ledger: one row per processed event, unique (device, seq) AND (society, event_id). The physical record
-- itself is access_events (slice 2, append-only). edge_quarantine keeps what could not be processed, bounded and masked; a quarantined seq
-- still counts as DISPOSED for acknowledgement (docs/contracts/edge-sync.md 4.3) so one bad event never freezes the cursor.

CREATE TABLE edge_device_state (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    device_id uuid NOT NULL,
    highest_contiguous_seq bigint NOT NULL DEFAULT 0 CHECK (highest_contiguous_seq >= 0),
    max_seq_seen bigint NOT NULL DEFAULT 0 CHECK (max_seq_seen >= 0),
    last_batch_at timestamptz,
    last_sync_at timestamptz,
    batches_total bigint NOT NULL DEFAULT 0 CHECK (batches_total >= 0),
    events_total bigint NOT NULL DEFAULT 0 CHECK (events_total >= 0),
    quarantined_total bigint NOT NULL DEFAULT 0 CHECK (quarantined_total >= 0),
    policy_seq_applied bigint NOT NULL DEFAULT 0 CHECK (policy_seq_applied >= 0),
    last_policy_poll_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT edge_device_state_device_uq UNIQUE (society_id, device_id),
    CONSTRAINT edge_device_state_device_fk FOREIGN KEY (society_id, device_id) REFERENCES devices (society_id, id)
);
SELECT dwaar_enable_society_rls('edge_device_state', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (highest_contiguous_seq, max_seq_seen, last_batch_at, last_sync_at, batches_total, events_total,
              quarantined_total, policy_seq_applied, last_policy_poll_at) ON TABLE edge_device_state TO dwaar_app;

CREATE TABLE edge_events (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    device_id uuid NOT NULL,
    seq bigint NOT NULL CHECK (seq >= 0 AND seq <= 4611686018427387904),
    event_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type ~ '^[A-Za-z][A-Za-z0-9_.]{0,99}$'),
    entity_id uuid NOT NULL,
    entity_version integer NOT NULL CHECK (entity_version >= 0),
    policy_version bigint NOT NULL CHECK (policy_version >= 0),
    status text NOT NULL CHECK (status IN ('accepted', 'rejected_transition')),
    reason text CHECK (reason IS NULL OR reason ~ '^[a-z0-9_]{3,60}$'),
    projected boolean NOT NULL DEFAULT false,          -- true when the event changed a visit
    occurred_at timestamptz NOT NULL,                  -- exactly as the device stated it: never rewritten (EDGE-05)
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    clock_uncertainty_ms integer NOT NULL CHECK (clock_uncertainty_ms BETWEEN 0 AND 86400000),
    clock_flag text CHECK (clock_flag IS NULL OR clock_flag IN ('future', 'stale', 'uncertain')),
    payload_hash text NOT NULL CHECK (payload_hash ~ '^sha256:[0-9a-f]{64}$'),
    access_event_id uuid,                              -- the append-only observation (access_events.id), when there is one
    exception_id uuid,
    retention_class text NOT NULL DEFAULT 'VIS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT edge_events_device_seq_uq UNIQUE (society_id, device_id, seq),
    CONSTRAINT edge_events_event_uq UNIQUE (society_id, event_id),
    CONSTRAINT edge_events_device_fk FOREIGN KEY (society_id, device_id) REFERENCES devices (society_id, id),
    CONSTRAINT edge_events_exception_fk FOREIGN KEY (society_id, exception_id) REFERENCES exceptions (society_id, id)
);
CREATE INDEX edge_events_received_idx ON edge_events (society_id, device_id, received_at DESC);
SELECT dwaar_enable_society_rls('edge_events', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('edge_events');

CREATE TABLE edge_quarantine (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    device_id uuid NOT NULL,                           -- the AUTHENTICATED device that delivered it
    seq bigint CHECK (seq IS NULL OR (seq >= 0 AND seq <= 4611686018427387904)),
    event_id uuid,
    event_type text CHECK (event_type IS NULL OR char_length(event_type) <= 100),
    reason text NOT NULL CHECK (reason ~ '^[a-z0-9_]{3,60}$'),
    claimed_society_id uuid,                           -- evidence for wrong_society; deliberately NOT a foreign key
    raw jsonb NOT NULL CHECK (jsonb_typeof(raw) = 'object' AND pg_column_size(raw) <= 12288),   -- bounded, masked copy
    raw_sha256 text NOT NULL CHECK (raw_sha256 ~ '^[0-9a-f]{64}$'),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    exception_id uuid,
    retention_class text NOT NULL DEFAULT 'VIS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT edge_quarantine_device_raw_uq UNIQUE (society_id, device_id, raw_sha256),
    CONSTRAINT edge_quarantine_device_fk FOREIGN KEY (society_id, device_id) REFERENCES devices (society_id, id),
    CONSTRAINT edge_quarantine_exception_fk FOREIGN KEY (society_id, exception_id) REFERENCES exceptions (society_id, id)
);
CREATE INDEX edge_quarantine_seq_idx ON edge_quarantine (society_id, device_id, seq) WHERE seq IS NOT NULL;
CREATE INDEX edge_quarantine_received_idx ON edge_quarantine (society_id, received_at DESC, id DESC);
SELECT dwaar_enable_society_rls('edge_quarantine', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('edge_quarantine');
