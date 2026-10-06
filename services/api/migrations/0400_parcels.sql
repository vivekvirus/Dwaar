-- 0400 parcels: expected / received / stored / collected parcels, the append-only custody chain, pickup attempts, external courier
-- observations, reminders and custody reports.
-- REQ: PAR-01 (delivery entries tagged by brand; resident pre-approval by brand and time window), PAR-02 (states, carrier reference, receiving
--      guard, bin code, time, optional minimally framed photo), PAR-03 (leave-at-gate consent explicit and revocable before custody; pickup by a
--      single-use token), PAR-04 (a courier's "delivered" claim is an EXTERNAL observation, never custody), PAR-05 (reminders at 24 h and 48 h,
--      custody report reconciling the physical count), INV-07 (received / stored / collected are distinct, truthful states), INV-01 (RLS),
--      ARCH-01 (composite FKs), DB-02 (custody history is append-only), PRD 8.2 (parcels, custody_transfers).
--
-- "Exactly one current custodian": custody_transfers is a CHAIN. Each row names its predecessor (prev_seq) and the pair
-- (parcel, prev_seq) is unique, so two concurrent hand-overs from the same predecessor cannot both commit (the loser fails the unique
-- index); a trigger additionally requires from_party to equal the predecessor's to_party. parcels.custodian / custody_seq are the
-- denormalised head of that chain, moved by a compare-and-swap in the same transaction.

CREATE TABLE parcels (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    unit_id uuid NOT NULL,
    brand text NOT NULL CHECK (char_length(btrim(brand)) BETWEEN 1 AND 60),
    brand_key text GENERATED ALWAYS AS (lower(btrim(brand))) STORED,
    carrier text CHECK (carrier IS NULL OR char_length(btrim(carrier)) BETWEEN 1 AND 60),
    carrier_ref text CHECK (carrier_ref IS NULL OR char_length(btrim(carrier_ref)) BETWEEN 1 AND 100),
    state text NOT NULL DEFAULT 'expected' CHECK (state IN
        ('expected', 'received_at_gate', 'stored', 'pickup_pending', 'collected', 'refused', 'returned', 'lost_exception', 'cancelled')),
    -- PAR-01: the resident's pre-approval (brand + time window). No order contents, no screenshot (PAR-08).
    expected_from timestamptz,
    expected_until timestamptz,
    expected_by uuid REFERENCES iam.persons (id),
    matched_expectation boolean NOT NULL DEFAULT false,
    -- PAR-02: receipt at the gate
    gate_id uuid,
    received_at timestamptz,
    received_by uuid REFERENCES iam.persons (id),
    bin_code text CHECK (bin_code IS NULL OR bin_code ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$'),
    stored_at timestamptz,
    photo_ref text CHECK (photo_ref IS NULL OR char_length(photo_ref) <= 300),
    -- PAR-03: leave-at-gate consent (explicit, revocable BEFORE custody)
    leave_at_gate_consent_at timestamptz,
    leave_at_gate_consent_by uuid REFERENCES iam.persons (id),
    leave_at_gate_revoked_at timestamptz,
    left_at_gate boolean NOT NULL DEFAULT false,
    -- PAR-03: single-use pickup token (only its hash is stored; the token is shown once)
    pickup_token_hash text,
    pickup_token_issued_at timestamptz,
    pickup_token_expires_at timestamptz,
    pickup_token_issued_by uuid REFERENCES iam.persons (id),
    pickup_pending_at timestamptz,
    collected_at timestamptz,
    collected_by_kind text CHECK (collected_by_kind IN ('recipient', 'delegate', 'supervised_alternate')),
    collected_by_person uuid REFERENCES iam.persons (id),
    collected_via text CHECK (collected_via IN ('token', 'alternate_proof')),
    resolved_at timestamptz,
    resolution_note text CHECK (resolution_note IS NULL OR char_length(resolution_note) <= 500),
    custody_seq integer NOT NULL DEFAULT 0 CHECK (custody_seq >= 0),
    custodian text CHECK (custodian IS NULL OR custodian ~ '^(guard|storage|resident|delegate|carrier|lost)(:[A-Za-z0-9._ -]{1,64})?$'),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by uuid NOT NULL REFERENCES iam.persons (id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT parcels_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT parcels_unit_fk FOREIGN KEY (society_id, unit_id) REFERENCES units (society_id, id),
    CONSTRAINT parcels_gate_fk FOREIGN KEY (society_id, gate_id) REFERENCES gates (society_id, id),
    CONSTRAINT parcels_window_check CHECK (expected_from IS NULL OR expected_until IS NULL OR expected_until > expected_from),
    CONSTRAINT parcels_expected_shape CHECK (state <> 'expected' OR (custodian IS NULL AND custody_seq = 0 AND received_at IS NULL)),
    CONSTRAINT parcels_received_shape CHECK (
        state IN ('expected', 'cancelled') OR (received_at IS NOT NULL AND received_by IS NOT NULL AND custody_seq >= 1 AND custodian IS NOT NULL)),
    CONSTRAINT parcels_collected_shape CHECK (
        (state = 'collected') = (collected_at IS NOT NULL AND collected_by_kind IS NOT NULL AND collected_via IS NOT NULL)),
    CONSTRAINT parcels_stored_has_bin CHECK (state NOT IN ('stored', 'pickup_pending') OR bin_code IS NOT NULL),
    CONSTRAINT parcels_consent_revocation CHECK (leave_at_gate_revoked_at IS NULL OR leave_at_gate_consent_at IS NOT NULL),
    CONSTRAINT parcels_token_shape CHECK (
        pickup_token_hash IS NULL OR (pickup_token_issued_at IS NOT NULL AND pickup_token_expires_at IS NOT NULL))
);
CREATE INDEX parcels_unit_state_idx ON parcels (society_id, unit_id, state, created_at DESC, id DESC);
CREATE INDEX parcels_state_idx ON parcels (society_id, state, created_at DESC, id DESC);
CREATE INDEX parcels_expectation_match_idx ON parcels (society_id, unit_id, brand_key) WHERE state = 'expected';
SELECT dwaar_enable_society_rls('parcels', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (state, expected_from, expected_until, matched_expectation, gate_id, received_at, received_by, carrier, carrier_ref,
              bin_code, stored_at, photo_ref, leave_at_gate_consent_at, leave_at_gate_consent_by, leave_at_gate_revoked_at,
              left_at_gate, pickup_token_hash, pickup_token_issued_at, pickup_token_expires_at, pickup_token_issued_by,
              pickup_pending_at, collected_at, collected_by_kind, collected_by_person, collected_via, resolved_at,
              resolution_note, custody_seq, custodian, version)
    ON TABLE parcels TO dwaar_app;

-- ---------------------------------------------------------------------------------------------
-- custody_transfers: the append-only chain (PRD 8.2)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE custody_transfers (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    parcel_id uuid NOT NULL,
    seq integer NOT NULL CHECK (seq >= 1),
    prev_seq integer,
    from_party text NOT NULL CHECK (from_party ~ '^(courier|guard|storage|resident|delegate|carrier|lost)(:[A-Za-z0-9._ -]{1,64})?$'),
    to_party text NOT NULL CHECK (to_party ~ '^(guard|storage|resident|delegate|carrier|lost)(:[A-Za-z0-9._ -]{1,64})?$'),
    at timestamptz NOT NULL DEFAULT clock_timestamp(),
    reason text NOT NULL CHECK (reason IN ('received', 'stored', 'collected', 'returned', 'lost', 'refused_held')),
    evidence_ref text CHECK (evidence_ref IS NULL OR char_length(evidence_ref) <= 300),
    actor_id uuid REFERENCES iam.persons (id),
    CONSTRAINT custody_transfers_parcel_seq_uq UNIQUE (society_id, parcel_id, seq),
    -- one successor per predecessor: the chain cannot fork, so there is exactly one current custodian
    CONSTRAINT custody_transfers_single_successor_uq UNIQUE (society_id, parcel_id, prev_seq),
    CONSTRAINT custody_transfers_chain_shape CHECK ((seq = 1 AND prev_seq IS NULL) OR (seq > 1 AND prev_seq = seq - 1)),
    CONSTRAINT custody_transfers_parcel_fk FOREIGN KEY (society_id, parcel_id) REFERENCES parcels (society_id, id),
    CONSTRAINT custody_transfers_prev_fk FOREIGN KEY (society_id, parcel_id, prev_seq)
        REFERENCES custody_transfers (society_id, parcel_id, seq)
);
CREATE INDEX custody_transfers_parcel_idx ON custody_transfers (society_id, parcel_id, seq);

CREATE FUNCTION parcels_custody_chain_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_to text;
BEGIN
    IF NEW.seq > 1 THEN
        SELECT t.to_party INTO v_to FROM public.custody_transfers t
        WHERE t.society_id = NEW.society_id AND t.parcel_id = NEW.parcel_id AND t.seq = NEW.prev_seq;
        IF v_to IS DISTINCT FROM NEW.from_party THEN
            RAISE EXCEPTION 'custody chain broken: from_party must be the current custodian'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER custody_transfers_chain BEFORE INSERT ON custody_transfers
    FOR EACH ROW EXECUTE FUNCTION parcels_custody_chain_guard();
SELECT dwaar_enable_society_rls('custody_transfers', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('custody_transfers');

-- ---------------------------------------------------------------------------------------------
-- parcel_pickup_attempts: EVERY attempt, granted or denied, append-only (AT-13: custody history intact)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE parcel_pickup_attempts (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    parcel_id uuid NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('granted', 'denied')),
    reason text NOT NULL CHECK (reason ~ '^[a-z0-9_]{3,60}$'),
    method text NOT NULL CHECK (method IN ('token', 'alternate_proof', 'none')),
    actor_id uuid REFERENCES iam.persons (id),
    at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT parcel_pickup_attempts_parcel_fk FOREIGN KEY (society_id, parcel_id) REFERENCES parcels (society_id, id)
);
CREATE INDEX parcel_pickup_attempts_parcel_idx ON parcel_pickup_attempts (society_id, parcel_id, at);
SELECT dwaar_enable_society_rls('parcel_pickup_attempts', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('parcel_pickup_attempts');

-- ---------------------------------------------------------------------------------------------
-- courier_observations: what a courier CLAIMS (PAR-04). Never custody; never a state change.
-- ---------------------------------------------------------------------------------------------
CREATE TABLE courier_observations (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    parcel_id uuid NOT NULL,
    source text NOT NULL CHECK (source IN ('courier_app', 'courier_sms', 'courier_call', 'rider_statement', 'other')),
    claim text NOT NULL CHECK (claim IN ('out_for_delivery', 'attempted', 'delivered')),
    claimed_at timestamptz NOT NULL,
    external_ref text CHECK (external_ref IS NULL OR char_length(external_ref) <= 100),
    external boolean NOT NULL DEFAULT true CHECK (external),
    recorded_by uuid REFERENCES iam.persons (id),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT courier_observations_parcel_fk FOREIGN KEY (society_id, parcel_id) REFERENCES parcels (society_id, id)
);
CREATE INDEX courier_observations_parcel_idx ON courier_observations (society_id, parcel_id, claimed_at);
SELECT dwaar_enable_society_rls('courier_observations', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('courier_observations');

-- ---------------------------------------------------------------------------------------------
-- parcel_reminders: one row per (parcel, kind): the unique key makes the reminder job idempotent (PAR-05)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE parcel_reminders (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    parcel_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('h24', 'h48')),
    due_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT parcel_reminders_once_uq UNIQUE (society_id, parcel_id, kind),
    CONSTRAINT parcel_reminders_parcel_fk FOREIGN KEY (society_id, parcel_id) REFERENCES parcels (society_id, id)
);
SELECT dwaar_enable_society_rls('parcel_reminders', 'SELECT, INSERT', 'SELECT, INSERT');
SELECT dwaar_make_append_only('parcel_reminders');

-- ---------------------------------------------------------------------------------------------
-- parcel_custody_reports: the guard's physical count against the system count (PAR-05)
-- ---------------------------------------------------------------------------------------------
CREATE TABLE parcel_custody_reports (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    gate_id uuid,
    counted_by uuid NOT NULL REFERENCES iam.persons (id),
    physical_count integer NOT NULL CHECK (physical_count >= 0 AND physical_count <= 100000),
    system_count integer NOT NULL CHECK (system_count >= 0),
    discrepancy integer GENERATED ALWAYS AS (physical_count - system_count) STORED,
    details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object' AND pg_column_size(details) <= 65536),
    note text CHECK (note IS NULL OR char_length(note) <= 500),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT parcel_custody_reports_gate_fk FOREIGN KEY (society_id, gate_id) REFERENCES gates (society_id, id)
);
CREATE INDEX parcel_custody_reports_idx ON parcel_custody_reports (society_id, created_at DESC, id DESC);
SELECT dwaar_enable_society_rls('parcel_custody_reports', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('parcel_custody_reports');
