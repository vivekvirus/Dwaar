-- 0300 edge policy: signed, monotonically versioned policy snapshots and the opaque resident credential references.
-- REQ: EDGE-04 (signed snapshots carry sequence, issue time, validity, issuer key id and a data-minimisation manifest; applied atomically;
--      rollback rejected), GATE-06 (credentials validated locally against status, gate, time, policy age and revocation version),
--      PRD 8.2 policy_snapshots(seq bigint, issued_at, valid_until, issuer_key_id, manifest jsonb, signature) unique (society_id, seq),
--      PRD 9.3 authority split (the cloud is authoritative for roles and revocations, issued as signed monotonic snapshots),
--      PRD 12.4 (PolicyPublished), DB-02 (append-only), INV-01 (RLS in the same migration), EDGE-10 (tombstones).
--
-- policy_snapshots is history: the application role can only INSERT. seq is gapless per society and enforced by a trigger, so a
-- publisher bug cannot produce a rollback or a hole. The signature covers the canonical JSON of the snapshot without it
-- (dwaar_common canonical rules); the row keeps the manifest exactly as signed.

CREATE TABLE policy_snapshots (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    seq bigint NOT NULL CHECK (seq >= 1),
    schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version >= 1),
    issued_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    issuer_key_id text NOT NULL CHECK (issuer_key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
    reason text NOT NULL CHECK (reason IN ('initial', 'changed', 'refresh', 'key_rotation', 'forced')),
    manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
    signature text NOT NULL CHECK (signature ~ '^ed25519:[A-Za-z0-9_-]{86}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'CRED' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT policy_snapshots_society_seq_uq UNIQUE (society_id, seq),
    CONSTRAINT policy_snapshots_validity_check CHECK (valid_until > issued_at)
);
SELECT dwaar_enable_society_rls('policy_snapshots', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('policy_snapshots');

-- seq must be exactly the previous seq + 1 (1 for the first). Concurrent publishers serialise on the publisher's advisory lock;
-- this trigger is the database-side guarantee that a snapshot can never be older than, or skip over, another one.
CREATE FUNCTION edge_policy_seq_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE v_prev bigint;
BEGIN
    SELECT coalesce(max(seq), 0) INTO v_prev FROM public.policy_snapshots WHERE society_id = NEW.society_id;
    IF NEW.seq <> v_prev + 1 THEN
        RAISE EXCEPTION 'policy_snapshots.seq must be % (monotonic, gapless)', v_prev + 1 USING ERRCODE = 'DW002';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER policy_snapshots_seq_guard BEFORE INSERT ON policy_snapshots
    FOR EACH ROW EXECUTE FUNCTION edge_policy_seq_guard();
CREATE INDEX policy_snapshots_latest_idx ON policy_snapshots (society_id, seq DESC);

-- Opaque credential references of residents (EDGE-04 data minimisation: the edge never sees a phone, a name or a membership id).
-- One row per (membership, generation). A membership that stops being effective is marked revoked with the next value of the society's
-- monotonic revocation counter (gate_policies.revocation_version, the same counter as invitation revocations); when it becomes effective
-- again it gets a NEW generation and therefore a NEW credential_ref, so "newest known deny" can never lock out a re-verified resident
-- nor resurrect a revoked reference.
CREATE TABLE edge_credential_refs (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    membership_id uuid NOT NULL,
    generation integer NOT NULL DEFAULT 0 CHECK (generation >= 0),
    credential_ref text NOT NULL CHECK (credential_ref ~ '^cr_[A-Za-z0-9_-]{16,64}$'),
    person_ref text NOT NULL CHECK (person_ref ~ '^pr_[A-Za-z0-9_-]{16,64}$'),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    revocation_version bigint CHECK (revocation_version IS NULL OR revocation_version >= 1),
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'CRED' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT edge_credential_refs_membership_fk FOREIGN KEY (society_id, membership_id)
        REFERENCES memberships (society_id, id),
    CONSTRAINT edge_credential_refs_ref_uq UNIQUE (society_id, credential_ref),
    CONSTRAINT edge_credential_refs_generation_uq UNIQUE (society_id, membership_id, generation),
    CONSTRAINT edge_credential_refs_revocation_shape CHECK (
        (state = 'revoked') = (revocation_version IS NOT NULL AND revoked_at IS NOT NULL))
);
CREATE INDEX edge_credential_refs_membership_idx ON edge_credential_refs (society_id, membership_id, generation DESC);
SELECT dwaar_enable_society_rls('edge_credential_refs', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (state, revocation_version, revoked_at) ON TABLE edge_credential_refs TO dwaar_app;
