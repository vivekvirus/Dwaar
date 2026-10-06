-- 0562 opinion polls (COM-06 ONLY).
-- REQ: COM-06 (clearly labelled NON-BINDING opinion polls, owners-only option, result visibility rules, neutral-wording
--      check hook for AI-C12), D-24 / GOV-01 (binding votes are M2 governance behind an approved legal pack: nothing here
--      can represent one: is_binding is CHECKed false and there is no ballot, quorum or resolution column), INV-10, ARCH-01.

CREATE TABLE polls (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    question text NOT NULL CHECK (char_length(btrim(question)) BETWEEN 5 AND 300),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
    eligibility text NOT NULL DEFAULT 'all_members' CHECK (eligibility IN ('all_members', 'owners_only')),
    result_visibility text NOT NULL DEFAULT 'after_close' CHECK (result_visibility IN ('live', 'after_close', 'managers_only')),
    state text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'open', 'closed')),
    is_binding boolean NOT NULL DEFAULT false CHECK (NOT is_binding),
    label_key text NOT NULL DEFAULT 'community.poll.non_binding' CHECK (label_key = 'community.poll.non_binding'),
    opens_at timestamptz,
    closes_at timestamptz,
    neutrality_status text NOT NULL DEFAULT 'not_run' CHECK (neutrality_status IN ('not_run', 'clean', 'flagged', 'overridden')),
    neutrality_report jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(neutrality_report) = 'object' AND pg_column_size(neutrality_report) <= 4096),
    neutrality_override_reason text CHECK (neutrality_override_reason IS NULL OR char_length(neutrality_override_reason) <= 500),
    created_by uuid NOT NULL REFERENCES iam.persons (id),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'COM' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT polls_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT polls_window CHECK (closes_at IS NULL OR opens_at IS NULL OR closes_at > opens_at),
    CONSTRAINT polls_open_shape CHECK (state = 'draft' OR opens_at IS NOT NULL)
);
CREATE INDEX polls_state_idx ON polls (society_id, state, created_at DESC, id DESC);

CREATE TABLE poll_options (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    poll_id uuid NOT NULL,
    position integer NOT NULL CHECK (position BETWEEN 1 AND 12),
    label text NOT NULL CHECK (char_length(btrim(label)) BETWEEN 1 AND 200),
    CONSTRAINT poll_options_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT poll_options_poll_fk FOREIGN KEY (society_id, poll_id) REFERENCES polls (society_id, id),
    CONSTRAINT poll_options_position_uq UNIQUE (society_id, poll_id, position)
);

CREATE TABLE poll_responses (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    poll_id uuid NOT NULL,
    option_id uuid NOT NULL,
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    unit_id uuid,
    at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT poll_responses_poll_fk FOREIGN KEY (society_id, poll_id) REFERENCES polls (society_id, id),
    CONSTRAINT poll_responses_option_fk FOREIGN KEY (society_id, option_id) REFERENCES poll_options (society_id, id),
    CONSTRAINT poll_responses_unit_fk FOREIGN KEY (society_id, unit_id) REFERENCES units (society_id, id),
    CONSTRAINT poll_responses_once_uq UNIQUE (society_id, poll_id, person_id)
);
CREATE INDEX poll_responses_poll_idx ON poll_responses (society_id, poll_id, option_id);

SELECT dwaar_enable_society_rls('polls', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (question, description, eligibility, result_visibility, state, opens_at, closes_at, neutrality_status,
              neutrality_report, neutrality_override_reason, version, updated_at) ON TABLE polls TO dwaar_app;
SELECT dwaar_enable_society_rls('poll_options', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_enable_society_rls('poll_responses', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('poll_responses');
