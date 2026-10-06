-- 0701 AI drafts (the self-contained result of a confirmed draft) and user feedback that feeds evaluation.
-- REQ: AI-SYS-08 ('what will be saved'; an easy correction route), AI-SYS-07 / PRD 12.1 (POST /v1/ai/feedback: run id, outcome, correction ->
--      stored, feeds evaluation), G6/PRIV-14 (the correction text is REDACTED before storage), INV-01, PRIV-15 (AI payloads inherit retention).
--
-- ai_drafts are PRIVATE to their owner inside the society: a RESTRICTIVE policy on app.person_id sits next to the society policy, so even a
-- query that forgets the owner filter returns only the caller's own drafts.

CREATE TABLE ai_drafts (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    owner_id uuid NOT NULL REFERENCES iam.persons (id),
    kind text NOT NULL CHECK (kind IN ('translation', 'poll_wording', 'notice_draft', 'complaint', 'triage', 'handover')),
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    content jsonb NOT NULL CHECK (jsonb_typeof(content) = 'object' AND pg_column_size(content) <= 65536),
    source_proposal_id uuid NOT NULL,
    status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'discarded')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    retention_class text NOT NULL DEFAULT 'RES' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT ai_drafts_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT ai_drafts_proposal_fk FOREIGN KEY (society_id, source_proposal_id) REFERENCES action_proposals (society_id, id),
    CONSTRAINT ai_drafts_proposal_uq UNIQUE (society_id, source_proposal_id)
);
CREATE INDEX ai_drafts_owner_idx ON ai_drafts (society_id, owner_id, created_at DESC, id DESC);
SELECT dwaar_enable_society_rls('ai_drafts', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (status, version) ON TABLE ai_drafts TO dwaar_app;
CREATE POLICY ai_drafts_owner_only ON ai_drafts AS RESTRICTIVE FOR ALL
    USING (owner_id = nullif(current_setting('app.person_id', true), '')::uuid)
    WITH CHECK (owner_id = nullif(current_setting('app.person_id', true), '')::uuid);

CREATE TABLE ai_feedback (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    ai_run_id uuid NOT NULL,
    actor_id uuid NOT NULL REFERENCES iam.persons (id),
    outcome text NOT NULL CHECK (outcome IN ('accepted', 'edited', 'rejected')),
    correction_redacted text CHECK (correction_redacted IS NULL OR char_length(correction_redacted) <= 2000),   -- identifiers tokenised, irreversibly
    redaction_counts jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(redaction_counts) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT ai_feedback_run_fk FOREIGN KEY (society_id, ai_run_id) REFERENCES ai_runs (society_id, id),
    CONSTRAINT ai_feedback_one_per_actor UNIQUE (society_id, ai_run_id, actor_id)
);
SELECT dwaar_enable_society_rls('ai_feedback', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('ai_feedback');
