-- 0202 visits and visit stops (GATE-04, GATE-05, INV-07).
-- REQ: GATE-04 (one visit, independent visit stops: approving one stop never authorises another), GATE-05 (exit may be
--      scanned, observed or reconciled as unknown; an exact exit time is never manufactured; inside counts carry a
--      confidence indicator), INV-07 (authorised, entered and exited are different facts: permission, observed
--      movement and destination stops are separate records), PRD 9.2 (Visit requested -> authorised -> inside ->
--      exited; authorised -> cancelled / expired), PRD 8.2, GATE-13 (only a keyed hash of the visitor number).
--
-- exited_at is the OBSERVED exit instant. A visit reconciled as unknown has exit_basis = 'reconciled_unknown' and
-- exited_at NULL (the CHECKs below make a fabricated exit time impossible); exit_reconciled_at records when somebody
-- reconciled it.

CREATE TABLE visits (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    kind text NOT NULL CHECK (kind IN ('guest', 'delivery', 'service', 'cab', 'staff', 'vendor')),
    state text NOT NULL DEFAULT 'requested'
        CHECK (state IN ('requested', 'authorised', 'inside', 'exited', 'cancelled', 'expired')),
    visitor_alias text NOT NULL CHECK (char_length(btrim(visitor_alias)) BETWEEN 1 AND 100),
    visitor_contact_token text,
    photo_ref text CHECK (photo_ref IS NULL OR char_length(photo_ref) <= 300),
    invitation_id uuid,
    gate_id uuid,
    people_count integer NOT NULL DEFAULT 1 CHECK (people_count BETWEEN 1 AND 50),
    vehicle_plate text CHECK (vehicle_plate IS NULL OR char_length(vehicle_plate) BETWEEN 3 AND 20),
    expected_minutes integer CHECK (expected_minutes IS NULL OR expected_minutes BETWEEN 5 AND 480),
    authorisation_source text CHECK (authorisation_source IN ('household_approval', 'invitation', 'supervisor_override')),
    authorised_at timestamptz,
    authorised_until timestamptz,
    entered_at timestamptz,
    exited_at timestamptz,
    exit_basis text CHECK (exit_basis IN ('scanned', 'observed', 'reconciled_unknown')),
    exit_reconciled_at timestamptz,
    confidence_inside text NOT NULL DEFAULT 'none' CHECK (confidence_inside IN ('none', 'observed', 'stale', 'unknown')),
    closed_reason text CHECK (closed_reason IS NULL OR char_length(closed_reason) <= 100),
    notice_version text CHECK (notice_version IS NULL OR char_length(notice_version) <= 50),
    notice_language text CHECK (notice_language IS NULL OR notice_language IN ('en', 'hi', 'mr', 'kn')),
    consent_recorded boolean NOT NULL DEFAULT false,
    created_by uuid NOT NULL REFERENCES iam.persons (id),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'VIS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT visits_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT visits_invitation_fk FOREIGN KEY (society_id, invitation_id) REFERENCES invitations (society_id, id),
    CONSTRAINT visits_gate_fk FOREIGN KEY (society_id, gate_id) REFERENCES gates (society_id, id),
    CONSTRAINT visits_authorised_has_time CHECK (state NOT IN ('authorised', 'inside') OR authorised_at IS NOT NULL),
    CONSTRAINT visits_inside_has_entry CHECK (state <> 'inside' OR entered_at IS NOT NULL),
    CONSTRAINT visits_exit_shape CHECK ((state = 'exited') = (exit_basis IS NOT NULL)),
    CONSTRAINT visits_never_manufacture_exit CHECK (
        (exit_basis IN ('scanned', 'observed') AND exited_at IS NOT NULL)
        OR (exit_basis = 'reconciled_unknown' AND exited_at IS NULL AND exit_reconciled_at IS NOT NULL)
        OR (exit_basis IS NULL AND exited_at IS NULL)),
    CONSTRAINT visits_confidence_matches_state CHECK (
        (state = 'inside' AND confidence_inside IN ('observed', 'stale'))
        OR (state = 'exited' AND confidence_inside IN ('none', 'unknown'))
        OR (state NOT IN ('inside', 'exited') AND confidence_inside = 'none'))
);
CREATE INDEX visits_state_idx ON visits (society_id, state, created_at DESC, id DESC);
CREATE INDEX visits_created_idx ON visits (society_id, created_at DESC, id DESC);
CREATE INDEX visits_invitation_idx ON visits (society_id, invitation_id);
SELECT dwaar_enable_society_rls('visits', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (state, authorisation_source, authorised_at, authorised_until, entered_at, exited_at, exit_basis,
              exit_reconciled_at, confidence_inside, closed_reason, version)
    ON TABLE visits TO dwaar_app, dwaar_worker;

-- A visit has one stop per destination unit. Approving a stop authorises THAT stop only (GATE-04).
CREATE TABLE visit_stops (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    visit_id uuid NOT NULL,
    unit_id uuid NOT NULL,
    seq integer NOT NULL CHECK (seq BETWEEN 1 AND 20),
    authorised boolean NOT NULL DEFAULT false,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'authorised', 'denied', 'expired', 'cancelled')),
    approval_request_id uuid,
    closed_reason text CHECK (closed_reason IS NULL OR char_length(closed_reason) <= 100),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'VIS' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT visit_stops_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT visit_stops_visit_fk FOREIGN KEY (society_id, visit_id) REFERENCES visits (society_id, id),
    CONSTRAINT visit_stops_unit_fk FOREIGN KEY (society_id, unit_id) REFERENCES units (society_id, id),
    CONSTRAINT visit_stops_unit_uq UNIQUE (society_id, visit_id, unit_id),
    CONSTRAINT visit_stops_seq_uq UNIQUE (society_id, visit_id, seq),
    CONSTRAINT visit_stops_authorised_matches_state CHECK (authorised = (state = 'authorised'))
);
CREATE INDEX visit_stops_unit_idx ON visit_stops (society_id, unit_id, visit_id);
CREATE UNIQUE INDEX visit_stops_request_uq ON visit_stops (society_id, approval_request_id) WHERE approval_request_id IS NOT NULL;
SELECT dwaar_enable_society_rls('visit_stops', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (authorised, state, approval_request_id, closed_reason) ON TABLE visit_stops TO dwaar_app, dwaar_worker;
