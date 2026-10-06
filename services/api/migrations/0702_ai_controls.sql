-- 0702 per-society AI kill switch and per-feature controls (AI-SYS-06, ARCH-05).
-- REQ: AI-SYS-06 (per-society kill switch and per-feature rollback WITHOUT an app update), ARCH-05 (per-society feature flags and AI budgets),
--      AT-29. The daily budget itself is society_quotas.ai_requests_per_day (organisation module; default 0 = AI off); this module adds the
--      switches and an optional per-feature daily limit. Changes are audited and emit an outbox event through the application.

CREATE TABLE ai_society_controls (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    kill_switch boolean NOT NULL DEFAULT false,
    reason text CHECK (reason IS NULL OR char_length(reason) <= 300),
    updated_by uuid REFERENCES iam.persons (id),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT ai_society_controls_society_uq UNIQUE (society_id)
);
SELECT dwaar_enable_society_rls('ai_society_controls', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (kill_switch, reason, updated_by, updated_at, version) ON TABLE ai_society_controls TO dwaar_app;

CREATE TABLE ai_feature_controls (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    feature_id text NOT NULL CHECK (feature_id ~ '^AI-[A-Z][0-9]{2}$'),
    state text NOT NULL DEFAULT 'enabled' CHECK (state IN ('enabled', 'disabled')),
    prompt_version_pin text CHECK (prompt_version_pin IS NULL OR prompt_version_pin ~ '^v[0-9]{1,4}$'),   -- rollback to a prior prompt, no deploy
    daily_limit integer CHECK (daily_limit IS NULL OR daily_limit BETWEEN 0 AND 1000000),
    reason text CHECK (reason IS NULL OR char_length(reason) <= 300),
    updated_by uuid REFERENCES iam.persons (id),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT ai_feature_controls_uq UNIQUE (society_id, feature_id)
);
SELECT dwaar_enable_society_rls('ai_feature_controls', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (state, prompt_version_pin, daily_limit, reason, updated_by, updated_at, version)
    ON TABLE ai_feature_controls TO dwaar_app;
