-- 0200 gates, lanes, devices (basic enrolment record + public key) and the per-society gate policy.
-- REQ: SOC-05 (subset: a device is enrolled by request and activated only by a DIFFERENT, authorised person),
--      GATE-11 (overstay thresholds are configuration), GATE-01 (revocation is versioned: the society-wide monotonic
--      counter lives here), D-13/D-15 (approval expiry is configuration within pack bounds), ARCH-01 (composite FKs),
--      INV-01 (RLS), PRD 8.2 (gates, lanes, devices).
--
-- Certificates (cert_fingerprint is filled by slice 3), controllers and policy snapshots are NOT part of this migration.
-- A device belongs to exactly one society (society_id NOT NULL); the same public key may not enrol twice INSIDE a society.
-- Uniqueness is deliberately per society: a global unique key would answer "is this key enrolled somewhere else?" to any
-- caller (ADR-0004: global unique indexes on tenant tables are existence oracles).

CREATE TABLE gates (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    name text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 100),
    kind text NOT NULL CHECK (kind IN ('vehicle', 'pedestrian', 'mixed')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid REFERENCES iam.persons (id),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT gates_society_id_uq UNIQUE (society_id, id)
);
CREATE UNIQUE INDEX gates_society_name_ci_uq ON gates (society_id, lower(btrim(name)));
SELECT dwaar_enable_society_rls('gates', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (name, kind, status, version) ON TABLE gates TO dwaar_app;

CREATE TABLE lanes (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    gate_id uuid NOT NULL,
    label text NOT NULL CHECK (char_length(btrim(label)) BETWEEN 1 AND 100),
    direction text NOT NULL CHECK (direction IN ('in', 'out', 'both')),
    controller_id uuid,                      -- controllers arrive with the barrier adapter (M1, slice 3)
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid REFERENCES iam.persons (id),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT lanes_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT lanes_gate_fk FOREIGN KEY (society_id, gate_id) REFERENCES gates (society_id, id)
);
CREATE UNIQUE INDEX lanes_gate_label_ci_uq ON lanes (society_id, gate_id, lower(btrim(label)));
SELECT dwaar_enable_society_rls('lanes', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (label, direction, status, version) ON TABLE lanes TO dwaar_app;

CREATE TABLE devices (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    kind text NOT NULL CHECK (kind IN ('terminal', 'gateway', 'reader', 'camera', 'relay', 'meter_gw')),
    name text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 100),
    gate_id uuid,
    state text NOT NULL DEFAULT 'pending_approval'
        CHECK (state IN ('pending_approval', 'active', 'rejected', 'revoked')),
    public_key text NOT NULL CHECK (public_key ~ '^[A-Za-z0-9_-]{43}$'),     -- Ed25519, 32 bytes, base64url without padding
    key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    cert_fingerprint text,                                                    -- slice 3 (device certificates)
    firmware text CHECK (firmware IS NULL OR char_length(firmware) <= 100),
    capabilities jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(capabilities) = 'object' AND pg_column_size(capabilities) <= 4096),
    simulation boolean NOT NULL DEFAULT false,
    last_seen_at timestamptz,
    requested_by uuid NOT NULL REFERENCES iam.persons (id),
    decided_by uuid REFERENCES iam.persons (id),
    decided_at timestamptz,
    decision_reason text CHECK (decision_reason IS NULL OR char_length(decision_reason) <= 500),
    revoked_by uuid REFERENCES iam.persons (id),
    revoked_at timestamptz,
    revoke_reason text CHECK (revoke_reason IS NULL OR char_length(revoke_reason) <= 500),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'CRED' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT devices_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT devices_society_key_uq UNIQUE (society_id, key_id),
    CONSTRAINT devices_gate_fk FOREIGN KEY (society_id, gate_id) REFERENCES gates (society_id, id),
    -- maker != checker, in the database as well as in the service (SOC-05, IAM-03)
    CONSTRAINT devices_maker_checker CHECK (decided_by IS NULL OR decided_by <> requested_by),
    CONSTRAINT devices_decision_shape CHECK (
        (state = 'pending_approval' AND decided_by IS NULL AND decided_at IS NULL)
        OR (state IN ('active', 'rejected', 'revoked') AND decided_by IS NOT NULL AND decided_at IS NOT NULL)),
    CONSTRAINT devices_revocation_shape CHECK ((state = 'revoked') = (revoked_by IS NOT NULL AND revoked_at IS NOT NULL))
);
CREATE INDEX devices_gate_idx ON devices (society_id, gate_id);
SELECT dwaar_enable_society_rls('devices', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (state, decided_by, decided_at, decision_reason, revoked_by, revoked_at, revoke_reason, last_seen_at,
              firmware, cert_fingerprint, version)
    ON TABLE devices TO dwaar_app;

-- One row per society, created lazily (defaults apply while there is none). Operational defaults, not statutory
-- (PRD 9.2 "Defaults"): the approval expiry is validated against the cascade pack bounds by the service, the overstay
-- thresholds are overrides on top of code defaults (delivery 20 minutes, service 2-8 hours, GATE-11).
CREATE TABLE gate_policies (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    approval_expiry_seconds integer NOT NULL DEFAULT 90 CHECK (approval_expiry_seconds BETWEEN 10 AND 3600),
    permission_validity_minutes integer NOT NULL DEFAULT 30 CHECK (permission_validity_minutes BETWEEN 1 AND 1440),
    override_validity_minutes integer NOT NULL DEFAULT 240 CHECK (override_validity_minutes BETWEEN 1 AND 1440),
    overstay_minutes jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(overstay_minutes) = 'object' AND pg_column_size(overstay_minutes) <= 1024),
    -- GATE-01: the society-wide, monotonic revocation counter. An invitation revoked at counter N carries
    -- revoked_version = N; the next signed policy snapshot publishes the highest N.
    revocation_version bigint NOT NULL DEFAULT 0 CHECK (revocation_version >= 0),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    updated_by uuid REFERENCES iam.persons (id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT gate_policies_society_uq UNIQUE (society_id)
);
SELECT dwaar_enable_society_rls('gate_policies', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (approval_expiry_seconds, permission_validity_minutes, override_validity_minutes, overstay_minutes,
              revocation_version, version, updated_by)
    ON TABLE gate_policies TO dwaar_app;
