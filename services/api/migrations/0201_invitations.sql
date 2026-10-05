-- 0201 invitations (GATE-01, GATE-08): host-issued passes with explicit windows, a signed QR and an optional 6-digit code.
-- REQ: GATE-01 (purpose, host and unit, people count, gate, validity window, max uses, optional vehicle; the signed QR
--      carries opaque ids, expiry and a nonce; 6-digit codes are hashed, rate-limited and bounded by uses and windows),
--      GATE-08 (a phone-free pass: the visitor contact token is optional), PRD 9.2 (Invitation draft -> active ->
--      consumed / expired / revoked; revocation is versioned; recurring visits have explicit windows, never a
--      permanent OTP), PRD 8.2, GATE-13/PRD 7.4 (no raw phone anywhere: only a keyed hash, the visitor contact token).
--
-- "Never a permanent OTP" is a database fact: every window is at most 7 days, the whole pass spans at most 366 days,
-- and max_uses is finite (<= 100).

CREATE TABLE invitations (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    host_person_id uuid NOT NULL REFERENCES iam.persons (id),
    unit_id uuid NOT NULL,
    kind text NOT NULL DEFAULT 'guest' CHECK (kind IN ('guest', 'delivery', 'service', 'cab', 'staff', 'vendor')),
    purpose text NOT NULL CHECK (char_length(btrim(purpose)) BETWEEN 1 AND 200),
    visitor_alias text CHECK (visitor_alias IS NULL OR char_length(btrim(visitor_alias)) BETWEEN 1 AND 100),
    visitor_contact_token text,                  -- keyed hash of the visitor number; NEVER the number (GATE-13)
    people_count integer NOT NULL CHECK (people_count BETWEEN 1 AND 50),
    gate_id uuid,
    window_start timestamptz NOT NULL,           -- earliest window start
    window_end timestamptz NOT NULL,             -- latest window end = the pass expiry
    max_uses integer NOT NULL CHECK (max_uses BETWEEN 1 AND 100),
    uses integer NOT NULL DEFAULT 0,
    vehicle_plate text CHECK (vehicle_plate IS NULL OR char_length(vehicle_plate) BETWEEN 3 AND 20),
    expected_minutes integer CHECK (expected_minutes IS NULL OR expected_minutes BETWEEN 5 AND 480),
    token_nonce text NOT NULL CHECK (char_length(token_nonce) BETWEEN 8 AND 64),
    code_hash text,                              -- keyed hash of the 6-digit code; the code itself is shown once
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('draft', 'active', 'consumed', 'expired', 'revoked')),
    revoked_version bigint NOT NULL DEFAULT 0 CHECK (revoked_version >= 0),
    revoked_at timestamptz,
    revoked_by uuid REFERENCES iam.persons (id),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid NOT NULL REFERENCES iam.persons (id),
    retention_class text NOT NULL DEFAULT 'VIS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT invitations_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT invitations_unit_fk FOREIGN KEY (society_id, unit_id) REFERENCES units (society_id, id),
    CONSTRAINT invitations_gate_fk FOREIGN KEY (society_id, gate_id) REFERENCES gates (society_id, id),
    CONSTRAINT invitations_window_check CHECK (window_end > window_start AND window_end - window_start <= interval '366 days'),
    CONSTRAINT invitations_uses_check CHECK (uses >= 0 AND uses <= max_uses),
    CONSTRAINT invitations_revocation_shape CHECK (
        (state = 'revoked') = (revoked_version > 0 AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL))
);
CREATE INDEX invitations_unit_idx ON invitations (society_id, unit_id, state);
SELECT dwaar_enable_society_rls('invitations', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (uses, state, revoked_version, revoked_at, revoked_by, version) ON TABLE invitations TO dwaar_app;

-- Explicit validity windows (a recurring visit is a LIST of windows, never an open-ended code).
CREATE TABLE invitation_windows (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    invitation_id uuid NOT NULL,
    seq integer NOT NULL CHECK (seq >= 1),
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    CONSTRAINT invitation_windows_order CHECK (window_end > window_start),
    CONSTRAINT invitation_windows_length CHECK (window_end - window_start <= interval '7 days'),
    CONSTRAINT invitation_windows_seq_uq UNIQUE (society_id, invitation_id, seq),
    CONSTRAINT invitation_windows_invitation_fk FOREIGN KEY (society_id, invitation_id)
        REFERENCES invitations (society_id, id)
);
SELECT dwaar_enable_society_rls('invitation_windows', 'SELECT, INSERT', 'SELECT');
