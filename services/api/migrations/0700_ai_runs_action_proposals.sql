-- 0700 AI audit: ai_runs and action_proposals (PRD 8.2, AI-SYS-01, AI-SYS-04, INV-06).
-- REQ: AI-SYS-01 (record model and version, prompt template version, authorised source ids, schema version, latency, cost and outcome;
--      NEVER raw private prompts: this table has NO text column that could hold a prompt, only a salted-free sha256 of the redacted input,
--      counts of redacted items and diagnostic CODES), AI-SYS-04 (action proposal: id, actor and scope, intent, target ids and versions,
--      allowed command, validated payload, evidence, missing fields, risk class, expiry, estimated effect; confirmation binds to the payload
--      hash), PRD 10.2 (class X is FORBIDDEN: it cannot even be stored), INV-06 (AI proposes, deterministic services execute), INV-01 (RLS),
--      ARCH-01 (composite FK), NFR-13 (latency is measured), INV-12 (claims only from measurements: simulation is recorded per run).
--
-- Database-side guards that hold even if application code is wrong:
--   * action_proposals.risk_class admits only A, B, C: a class X proposal is a constraint violation;
--   * the command name must not start with a forbidden domain (gate, payment, vote, journal, tax, export, rights, fine, service, access,
--     bill, settlement, ledger): money, gate, votes and personal-data export can never be a stored AI command;
--   * the stored proposal is IMMUTABLE except for its decision columns (column-level UPDATE grant), and a decided proposal can never change
--     state again (trigger): a confirmed proposal cannot be re-opened and a rejected one cannot be confirmed.

CREATE TABLE ai_runs (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    actor_id uuid NOT NULL REFERENCES iam.persons (id),
    actor_role text NOT NULL CHECK (actor_role ~ '^[a-z][a-z0-9_]{0,63}$'),
    feature_id text NOT NULL CHECK (feature_id ~ '^AI-[A-Z][0-9]{2}$'),
    purpose text NOT NULL CHECK (purpose ~ '^[a-z][a-z0-9_]{0,63}$'),
    provider text NOT NULL CHECK (char_length(provider) BETWEEN 1 AND 60),
    model text NOT NULL CHECK (char_length(model) BETWEEN 1 AND 100),
    simulation boolean NOT NULL,                          -- true = a labelled simulator answered: nothing about model quality may be inferred
    model_called boolean NOT NULL,                        -- counts against the per-society budget
    prompt_version text NOT NULL CHECK (char_length(prompt_version) BETWEEN 1 AND 100),
    schema_version text NOT NULL CHECK (char_length(schema_version) BETWEEN 1 AND 40),
    source_ids uuid[] NOT NULL DEFAULT '{}',
    latency_ms integer NOT NULL CHECK (latency_ms >= 0),
    cost_paise bigint NOT NULL DEFAULT 0 CHECK (cost_paise >= 0),   -- integer paise (INV-02)
    input_tokens integer NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens integer NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    status text NOT NULL CHECK (status IN ('ok', 'unavailable', 'rejected')),
    reason text CHECK (reason IS NULL OR char_length(reason) <= 100),
    outcome text CHECK (outcome IS NULL OR outcome IN ('accepted', 'edited', 'rejected', 'abstained', 'failed')),  -- NULL = not decided yet
    input_hash text CHECK (input_hash IS NULL OR input_hash ~ '^sha256:[0-9a-f]{64}$'),   -- of the REDACTED input; the input itself is never stored
    redaction_counts jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(redaction_counts) = 'object'),
    diagnostics jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(diagnostics) = 'array' AND pg_column_size(diagnostics) <= 8192),  -- codes only
    proposal_id uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    decided_at timestamptz,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT ai_runs_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT ai_runs_simulation_cost CHECK (NOT simulation OR cost_paise = 0)
);
CREATE INDEX ai_runs_society_created_idx ON ai_runs (society_id, created_at DESC, id DESC);
CREATE INDEX ai_runs_budget_idx ON ai_runs (society_id, feature_id, created_at) WHERE model_called;
SELECT dwaar_enable_society_rls('ai_runs', 'SELECT, INSERT', 'SELECT');
-- only the OUTCOME can change after the fact (the user's decision), never what the model did
GRANT UPDATE (outcome, decided_at, proposal_id, version) ON TABLE ai_runs TO dwaar_app;

CREATE TABLE action_proposals (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    ai_run_id uuid NOT NULL,
    actor_id uuid NOT NULL REFERENCES iam.persons (id),
    actor_role text NOT NULL CHECK (actor_role ~ '^[a-z][a-z0-9_]{0,63}$'),   -- the role the proposal was made under (AT-26)
    feature_id text NOT NULL CHECK (feature_id ~ '^AI-[A-Z][0-9]{2}$'),
    intent text NOT NULL CHECK (intent ~ '^[a-z][a-z0-9_]{0,63}$'),
    command text NOT NULL CHECK (command ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),
    risk_class text NOT NULL CHECK (risk_class IN ('A', 'B', 'C')),         -- class X can never be stored
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND pg_column_size(payload) <= 65536),
    payload_hash text NOT NULL CHECK (payload_hash ~ '^sha256:[0-9a-f]{64}$'),
    target_ids uuid[] NOT NULL DEFAULT '{}',
    target_versions integer[] NOT NULL DEFAULT '{}',
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(evidence) = 'array'),
    missing_fields text[] NOT NULL DEFAULT '{}',
    estimated_effect text CHECK (estimated_effect IS NULL OR char_length(estimated_effect) <= 400),
    labels jsonb NOT NULL CHECK (jsonb_typeof(labels) = 'object'),
    expires_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'proposed' CHECK (state IN ('proposed', 'confirmed', 'rejected', 'expired', 'failed')),
    confirmed_by uuid REFERENCES iam.persons (id),
    confirmed_role text CHECK (confirmed_role IS NULL OR confirmed_role ~ '^[a-z][a-z0-9_]{0,63}$'),
    confirmed_at timestamptz,
    edited boolean NOT NULL DEFAULT false,
    final_payload jsonb CHECK (final_payload IS NULL OR jsonb_typeof(final_payload) = 'object'),   -- what actually executed (after validated edits)
    result jsonb CHECK (result IS NULL OR jsonb_typeof(result) = 'object'),                        -- the deterministic receipt
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    retention_class text NOT NULL DEFAULT 'RES' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT action_proposals_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT action_proposals_run_fk FOREIGN KEY (society_id, ai_run_id) REFERENCES ai_runs (society_id, id),
    CONSTRAINT action_proposals_run_uq UNIQUE (society_id, ai_run_id),
    CONSTRAINT action_proposals_targets_shape CHECK (cardinality(target_ids) = cardinality(target_versions)),
    CONSTRAINT action_proposals_no_forbidden_domain CHECK (
        command !~ '^(gate|payment|vote|journal|tax|export|rights|fine|service|access|bill|settlement|ledger)\.'),
    CONSTRAINT action_proposals_decision_shape CHECK (
        (state = 'confirmed') = (confirmed_at IS NOT NULL AND confirmed_by IS NOT NULL AND confirmed_role IS NOT NULL AND result IS NOT NULL))
);
CREATE INDEX action_proposals_actor_idx ON action_proposals (society_id, actor_id, created_at DESC, id DESC);
CREATE INDEX action_proposals_open_idx ON action_proposals (society_id, expires_at) WHERE state = 'proposed';
SELECT dwaar_enable_society_rls('action_proposals', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (state, confirmed_by, confirmed_role, confirmed_at, edited, final_payload, result, version)
    ON TABLE action_proposals TO dwaar_app;

-- a decided proposal is final: no re-opening, no second decision (AT-26: a stale proposal is replaced by a NEW one)
CREATE FUNCTION action_proposals_decided_is_final() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF OLD.state <> 'proposed' THEN
        RAISE EXCEPTION 'action proposal % is already %', OLD.id, OLD.state USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION action_proposals_decided_is_final() FROM PUBLIC;
CREATE TRIGGER action_proposals_decided_is_final BEFORE UPDATE ON action_proposals
    FOR EACH ROW EXECUTE FUNCTION action_proposals_decided_is_final();
