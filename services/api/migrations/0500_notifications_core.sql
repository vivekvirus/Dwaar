-- 0500 notifications and calling: templates, preferences, household settings, device push tokens, cascades, notifications,
-- delivery-attempt log, proxy call sessions, budgets and counters, device health, processed-event ledger (PRD 9.4).
-- REQ: NOTIF-01 (five categories; security and emergency can never carry promotional content: a CHECK, not a convention),
--      NOTIF-02 (created -> provider_accepted -> app_received -> displayed -> actioned -> expired; acceptance by a provider is
--      NOT delivery), NOTIF-03 / AT-40 (one cascade per request and attempt; ONE primary and ONE alternate call, enforced by
--      unique indexes), NOTIF-04 (stale actions invalidated), NOTIF-05 (immutable request id), NOTIF-06 / NOTIF-07 (device health
--      by phone model and OS), NOTIF-09 (lock-screen identity is opt-in), CALL-01 (TTL-bound sessions, outcome and duration,
--      NO audio recording), CALL-02 (DLT header and template id, whitelisted URL), IAM-11 (push tokens revoked), INV-01, INV-03,
--      INV-07, PRD 12.4.
--
-- Every table is society-owned: society_id NOT NULL, composite foreign keys against cross-society references (ARCH-01),
-- ENABLE + FORCE ROW LEVEL SECURITY in this same migration (dwaar_enable_society_rls). The worker role gets exactly the
-- writes the cascade needs; history tables (delivery attempts, health reports, processed events) are append-only.

-- ---------------------------------------------------------------------------------------------------------------- templates
CREATE TABLE notification_templates (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    template_key text NOT NULL CHECK (template_key ~ '^[a-z][a-z0-9_.]{1,80}$'),
    category text NOT NULL CHECK (category IN ('security_approval', 'emergency', 'finance', 'service_ticket', 'community_digest')),
    channel text NOT NULL CHECK (channel IN ('push', 'ivr_call', 'sms', 'whatsapp')),
    language text NOT NULL CHECK (language IN ('en', 'hi', 'mr')),
    content_class text NOT NULL DEFAULT 'transactional' CHECK (content_class IN ('transactional', 'service', 'promotional')),
    -- the i18n key (namespace "notifications") of the body: copy lives in packages/i18n, never in a table
    body_key text NOT NULL CHECK (body_key ~ '^[a-z][a-z0-9_.]{1,100}$'),
    -- CALL-02: SMS only through a DLT-registered header and template; NULL = placeholder, NOT sendable
    dlt_header text CHECK (dlt_header IS NULL OR dlt_header ~ '^[A-Z]{6}$'),
    dlt_template_id text CHECK (dlt_template_id IS NULL OR dlt_template_id ~ '^[0-9]{8,30}$'),
    whitelisted_url text CHECK (whitelisted_url IS NULL OR whitelisted_url ~ '^https://[a-z0-9.-]{3,100}(/[A-Za-z0-9._~/-]{0,100})?$'),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
    created_by uuid REFERENCES iam.persons (id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CONSTRAINT notification_templates_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT notification_templates_key_uq UNIQUE (society_id, template_key, channel, language),
    -- NOTIF-01: the security and emergency channels never carry ads, launches or unrelated content
    CONSTRAINT notification_templates_security_clean CHECK (
        category NOT IN ('security_approval', 'emergency') OR content_class = 'transactional')
);
SELECT dwaar_enable_society_rls('notification_templates', 'SELECT, INSERT', 'SELECT');
-- retiring a template and the registration of its DLT header / template id (the placeholder gets its real ids) are the only edits
GRANT UPDATE (status, dlt_header, dlt_template_id, version) ON TABLE notification_templates TO dwaar_app;

-- ---------------------------------------------------------------------------------------------------------------- preferences
CREATE TABLE notification_preferences (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    -- NOTIF-09: the lock screen shows neither visitor identity nor unit unless the resident opted in
    show_identity_on_lockscreen boolean NOT NULL DEFAULT false,
    whatsapp_opt_in boolean NOT NULL DEFAULT false,
    sms_opt_in boolean NOT NULL DEFAULT false,
    language text NOT NULL DEFAULT 'en' CHECK (language IN ('en', 'hi', 'mr')),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CONSTRAINT notification_preferences_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT notification_preferences_person_uq UNIQUE (society_id, person_id)
);
SELECT dwaar_enable_society_rls('notification_preferences', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (show_identity_on_lockscreen, whatsapp_opt_in, sms_opt_in, language, updated_at, version)
    ON TABLE notification_preferences TO dwaar_app;

CREATE TABLE unit_notification_settings (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    unit_id uuid NOT NULL,
    primary_person_id uuid REFERENCES iam.persons (id),
    approver_person_ids uuid[] NOT NULL DEFAULT '{}'::uuid[] CHECK (cardinality(approver_person_ids) <= 6),
    alternate_person_id uuid REFERENCES iam.persons (id),
    -- AT-11: the fallback the household configured when the app cannot be reached: a masked call, or the intercom
    fallback_mode text NOT NULL DEFAULT 'call' CHECK (fallback_mode IN ('call', 'intercom')),
    updated_by uuid REFERENCES iam.persons (id),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CONSTRAINT unit_notification_settings_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT unit_notification_settings_unit_uq UNIQUE (society_id, unit_id),
    CONSTRAINT unit_notification_settings_unit_fk FOREIGN KEY (society_id, unit_id) REFERENCES units (society_id, id),
    CONSTRAINT unit_notification_settings_alt_differs CHECK (alternate_person_id IS NULL OR alternate_person_id IS DISTINCT FROM primary_person_id)
);
SELECT dwaar_enable_society_rls('unit_notification_settings', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (primary_person_id, approver_person_ids, alternate_person_id, fallback_mode, updated_by, updated_at, version)
    ON TABLE unit_notification_settings TO dwaar_app;

-- ---------------------------------------------------------------------------------------------------------------- push tokens
-- FCM / APNs are SIMULATED (D-21 vendors TBD): only a hash and a short reference are kept. A real adapter needs the token itself,
-- envelope-encrypted like the vault; that is not built and is listed in ADR-0020.
CREATE TABLE device_push_tokens (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    platform text NOT NULL CHECK (platform IN ('fcm', 'apns')),
    token_hash text NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    token_ref text NOT NULL CHECK (char_length(token_ref) BETWEEN 4 AND 40),
    device_label text CHECK (device_label IS NULL OR char_length(device_label) <= 80),
    phone_model text CHECK (phone_model IS NULL OR char_length(phone_model) <= 80),
    manufacturer text CHECK (manufacturer IS NULL OR char_length(manufacturer) <= 40),
    os_name text CHECK (os_name IS NULL OR char_length(os_name) <= 40),
    os_version text CHECK (os_version IS NULL OR char_length(os_version) <= 40),
    app_version text CHECK (app_version IS NULL OR char_length(app_version) <= 40),
    notification_permission text NOT NULL DEFAULT 'unknown' CHECK (notification_permission IN ('granted', 'denied', 'unknown')),
    simulation boolean NOT NULL DEFAULT true,
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    revoked_reason text CHECK (revoked_reason IS NULL OR char_length(revoked_reason) <= 100),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CONSTRAINT device_push_tokens_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT device_push_tokens_revoked_shape CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
);
CREATE UNIQUE INDEX device_push_tokens_active_uq ON device_push_tokens (society_id, token_hash) WHERE revoked_at IS NULL;
CREATE INDEX device_push_tokens_person_idx ON device_push_tokens (society_id, person_id) WHERE revoked_at IS NULL;
SELECT dwaar_enable_society_rls('device_push_tokens', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (notification_permission, last_seen_at, phone_model, manufacturer, os_name, os_version, app_version, revoked_at,
              revoked_reason, version) ON TABLE device_push_tokens TO dwaar_app;
GRANT UPDATE (revoked_at, revoked_reason, version) ON TABLE device_push_tokens TO dwaar_worker;

-- ---------------------------------------------------------------------------------------------------------------- cascades
CREATE TABLE notification_cascades (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    request_id uuid NOT NULL,
    unit_id uuid NOT NULL,
    attempt_no integer NOT NULL DEFAULT 1 CHECK (attempt_no BETWEEN 1 AND 5),
    -- t = 0 of this attempt (attempt 1: the request's creation time) and the request's expiry (never extended here)
    started_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    plan jsonb NOT NULL CHECK (jsonb_typeof(plan) = 'object' AND pg_column_size(plan) <= 8192),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'decided', 'expired', 'cancelled', 'superseded')),
    started_by uuid REFERENCES iam.persons (id),
    ended_at timestamptz,
    ended_reason text CHECK (ended_reason IS NULL OR char_length(ended_reason) <= 100),
    guard_options jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(guard_options) = 'array'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CONSTRAINT notification_cascades_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT notification_cascades_attempt_uq UNIQUE (society_id, request_id, attempt_no),
    CONSTRAINT notification_cascades_request_fk FOREIGN KEY (society_id, request_id) REFERENCES approval_requests (society_id, id),
    CONSTRAINT notification_cascades_unit_fk FOREIGN KEY (society_id, unit_id) REFERENCES units (society_id, id),
    CONSTRAINT notification_cascades_ended_shape CHECK ((state = 'active') = (ended_at IS NULL)),
    -- attempts after the first are started by a supervisor, by a named person
    CONSTRAINT notification_cascades_attempt_owner CHECK (attempt_no = 1 OR started_by IS NOT NULL)
);
-- only one attempt of a request may be live at a time
CREATE UNIQUE INDEX notification_cascades_one_active_uq ON notification_cascades (society_id, request_id) WHERE state = 'active';
CREATE INDEX notification_cascades_active_idx ON notification_cascades (society_id, started_at) WHERE state = 'active';
SELECT dwaar_enable_society_rls('notification_cascades', 'SELECT, INSERT', 'SELECT, INSERT');
GRANT UPDATE (state, ended_at, ended_reason, guard_options, version) ON TABLE notification_cascades TO dwaar_app, dwaar_worker;

-- ---------------------------------------------------------------------------------------------------------------- notifications
CREATE TABLE notifications (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    cascade_id uuid,
    request_id uuid,
    attempt_no integer CHECK (attempt_no IS NULL OR attempt_no >= 1),
    category text NOT NULL CHECK (category IN ('security_approval', 'emergency', 'finance', 'service_ticket', 'community_digest')),
    channel text NOT NULL CHECK (channel IN ('push', 'ivr_call', 'sms', 'whatsapp')),
    content_class text NOT NULL DEFAULT 'transactional' CHECK (content_class IN ('transactional', 'service', 'promotional')),
    template_key text CHECK (template_key IS NULL OR char_length(template_key) <= 90),
    cascade_step integer CHECK (cascade_step IS NULL OR cascade_step BETWEEN 1 AND 5),
    recipient_role text NOT NULL CHECK (recipient_role IN ('primary', 'alternate', 'approver', 'opted_in', 'resident')),
    recipient_person_id uuid NOT NULL REFERENCES iam.persons (id),
    token_id uuid,
    dedupe_key text NOT NULL CHECK (char_length(dedupe_key) BETWEEN 8 AND 300),
    -- NOTIF-02 states, exactly; failure and cancellation are explained by the two reason columns, never by a seventh state
    state text NOT NULL DEFAULT 'created'
        CHECK (state IN ('created', 'provider_accepted', 'app_received', 'displayed', 'actioned', 'expired')),
    failure_reason text CHECK (failure_reason IS NULL OR failure_reason ~ '^[a-z][a-z0-9_]{1,60}$'),
    closed_reason text CHECK (closed_reason IS NULL OR closed_reason ~ '^[a-z][a-z0-9_]{1,60}$'),
    provider text CHECK (provider IS NULL OR provider ~ '^[a-z][a-z0-9_]{1,40}$'),
    provider_ref text CHECK (provider_ref IS NULL OR char_length(provider_ref) <= 120),
    simulation boolean NOT NULL DEFAULT true,
    lockscreen_identity boolean NOT NULL DEFAULT false,   -- NOTIF-09: whether the lock-screen text carried identity (opt-in only)
    phone_model text CHECK (phone_model IS NULL OR char_length(phone_model) <= 80),
    manufacturer text CHECK (manufacturer IS NULL OR char_length(manufacturer) <= 40),
    os_name text CHECK (os_name IS NULL OR char_length(os_name) <= 40),
    os_version text CHECK (os_version IS NULL OR char_length(os_version) <= 40),
    action text CHECK (action IS NULL OR action IN ('approve', 'deny', 'talk_to_guard')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    sent_at timestamptz,
    provider_accepted_at timestamptz,
    app_received_at timestamptz,
    displayed_at timestamptz,
    actioned_at timestamptz,
    expired_at timestamptz,
    invalidated_at timestamptz,
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CONSTRAINT notifications_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT notifications_dedupe_uq UNIQUE (society_id, dedupe_key),
    CONSTRAINT notifications_cascade_fk FOREIGN KEY (society_id, cascade_id) REFERENCES notification_cascades (society_id, id),
    CONSTRAINT notifications_request_fk FOREIGN KEY (society_id, request_id) REFERENCES approval_requests (society_id, id),
    CONSTRAINT notifications_token_fk FOREIGN KEY (society_id, token_id) REFERENCES device_push_tokens (society_id, id),
    -- NOTIF-01: nothing promotional on the security or emergency channels, whatever a caller does
    CONSTRAINT notifications_security_clean CHECK (
        category NOT IN ('security_approval', 'emergency') OR content_class = 'transactional'),
    -- NOTIF-02: a state is only claimed with its timestamp (provider acceptance is never delivery)
    CONSTRAINT notifications_state_evidence CHECK (
        (state <> 'provider_accepted' OR provider_accepted_at IS NOT NULL)
        AND (state <> 'app_received' OR app_received_at IS NOT NULL)
        AND (state <> 'displayed' OR (app_received_at IS NOT NULL AND displayed_at IS NOT NULL))
        AND (state <> 'actioned' OR actioned_at IS NOT NULL)
        AND (state <> 'expired' OR expired_at IS NOT NULL)),
    CONSTRAINT notifications_request_shape CHECK ((request_id IS NULL) = (cascade_id IS NULL))
);
CREATE INDEX notifications_person_idx ON notifications (society_id, recipient_person_id, created_at DESC, id DESC);
CREATE INDEX notifications_request_idx ON notifications (society_id, request_id, created_at);
CREATE INDEX notifications_open_idx ON notifications (society_id, request_id) WHERE state NOT IN ('actioned', 'expired');
-- AT-40 / NOTIF-03: at most ONE primary and ONE alternate CALL per request and attempt (a supervisor's new attempt is a new attempt_no)
CREATE UNIQUE INDEX notifications_one_call_per_role_uq ON notifications (society_id, request_id, attempt_no, recipient_role)
    WHERE channel = 'ivr_call' AND recipient_role IN ('primary', 'alternate');
SELECT dwaar_enable_society_rls('notifications', 'SELECT, INSERT', 'SELECT, INSERT');
GRANT UPDATE (state, failure_reason, closed_reason, provider, provider_ref, simulation, template_key, content_class,
              lockscreen_identity, sent_at, provider_accepted_at, app_received_at, displayed_at, actioned_at, expired_at,
              invalidated_at, action, token_id, phone_model, manufacturer, os_name, os_version, version)
    ON TABLE notifications TO dwaar_app, dwaar_worker;

-- Append-only log of what providers and devices reported, in the order we RECORDED it. Duplicate provider callbacks are
-- absorbed by the partial unique index (same provider event id = same fact, recorded once).
CREATE TABLE notification_attempts (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    notification_id uuid NOT NULL,
    source text NOT NULL CHECK (source IN ('provider', 'device', 'system')),
    event text NOT NULL CHECK (event ~ '^[a-z][a-z0-9_]{1,40}$'),
    provider_event_id text CHECK (provider_event_id IS NULL OR char_length(provider_event_id) <= 120),
    observed_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    detail jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object' AND pg_column_size(detail) <= 4096),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT notification_attempts_notification_fk FOREIGN KEY (society_id, notification_id) REFERENCES notifications (society_id, id)
);
CREATE UNIQUE INDEX notification_attempts_event_uq ON notification_attempts (society_id, notification_id, source, provider_event_id)
    WHERE provider_event_id IS NOT NULL;
CREATE INDEX notification_attempts_notification_idx ON notification_attempts (society_id, notification_id, recorded_at, id);
SELECT dwaar_enable_society_rls('notification_attempts', 'SELECT, INSERT', 'SELECT, INSERT');
SELECT dwaar_make_append_only('notification_attempts');

-- ---------------------------------------------------------------------------------------------------------------- proxy calls
CREATE TABLE proxy_call_sessions (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    request_id uuid NOT NULL,
    notification_id uuid,
    purpose text NOT NULL CHECK (purpose IN ('cascade_ivr', 'guard_call')),
    initiated_by uuid REFERENCES iam.persons (id),
    initiator_role text NOT NULL CHECK (initiator_role ~ '^[a-z][a-z0-9_]{0,63}$'),
    callee_person_id uuid NOT NULL REFERENCES iam.persons (id),
    -- what the caller may see: never a number (GATE-13, CALL-01)
    masked_label text NOT NULL CHECK (char_length(masked_label) BETWEEN 1 AND 80),
    contact_ref text NOT NULL CHECK (char_length(contact_ref) BETWEEN 8 AND 120),
    ttl_expires_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'created' CHECK (state IN ('created', 'dialing', 'completed', 'failed', 'expired')),
    dial_outcome text CHECK (dial_outcome IS NULL OR dial_outcome IN ('answered', 'no_answer', 'busy', 'failed', 'rejected', 'cancelled')),
    dtmf_digit text CHECK (dtmf_digit IS NULL OR dtmf_digit ~ '^[0-9*#]$'),
    duration_seconds integer CHECK (duration_seconds IS NULL OR duration_seconds BETWEEN 0 AND 7200),
    provider text CHECK (provider IS NULL OR provider ~ '^[a-z][a-z0-9_]{1,40}$'),
    provider_ref text CHECK (provider_ref IS NULL OR char_length(provider_ref) <= 120),
    simulation boolean NOT NULL DEFAULT true,
    -- CALL-01: dial outcome and duration are logged, audio is NOT recorded unless a separate lawful use is approved
    -- (such an approval would be its own migration and decision record); until then the column cannot become true.
    recording_enabled boolean NOT NULL DEFAULT false CHECK (recording_enabled = false),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CONSTRAINT proxy_call_sessions_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT proxy_call_sessions_request_fk FOREIGN KEY (society_id, request_id) REFERENCES approval_requests (society_id, id),
    CONSTRAINT proxy_call_sessions_notification_fk FOREIGN KEY (society_id, notification_id) REFERENCES notifications (society_id, id),
    CONSTRAINT proxy_call_sessions_ttl_shape CHECK (ttl_expires_at > created_at),
    CONSTRAINT proxy_call_sessions_done_shape CHECK (
        (state IN ('completed', 'failed', 'expired')) = (completed_at IS NOT NULL))
);
CREATE INDEX proxy_call_sessions_request_idx ON proxy_call_sessions (society_id, request_id, created_at);
CREATE UNIQUE INDEX proxy_call_sessions_notification_uq ON proxy_call_sessions (society_id, notification_id) WHERE notification_id IS NOT NULL;
SELECT dwaar_enable_society_rls('proxy_call_sessions', 'SELECT, INSERT', 'SELECT, INSERT');
GRANT UPDATE (state, dial_outcome, dtmf_digit, duration_seconds, provider, provider_ref, completed_at, version)
    ON TABLE proxy_call_sessions TO dwaar_app, dwaar_worker;

-- ---------------------------------------------------------------------------------------------------------------- budgets
CREATE TABLE notification_budgets (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    monthly_notification_cap integer NOT NULL DEFAULT 30000 CHECK (monthly_notification_cap BETWEEN 0 AND 10000000),
    monthly_call_cap integer NOT NULL DEFAULT 3000 CHECK (monthly_call_cap BETWEEN 0 AND 1000000),
    monthly_sms_cap integer NOT NULL DEFAULT 3000 CHECK (monthly_sms_cap BETWEEN 0 AND 1000000),
    updated_by uuid REFERENCES iam.persons (id),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CONSTRAINT notification_budgets_society_uq UNIQUE (society_id)
);
SELECT dwaar_enable_society_rls('notification_budgets', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (monthly_notification_cap, monthly_call_cap, monthly_sms_cap, updated_by, updated_at, version)
    ON TABLE notification_budgets TO dwaar_app;

CREATE TABLE notification_counters (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    period text NOT NULL CHECK (period ~ '^[0-9]{4}-[0-9]{2}$'),
    kind text NOT NULL CHECK (kind IN ('notification', 'call', 'sms', 'over_budget', 'budget_blocked')),
    n bigint NOT NULL DEFAULT 0 CHECK (n >= 0),
    CONSTRAINT notification_counters_uq UNIQUE (society_id, period, kind)
);
SELECT dwaar_enable_society_rls('notification_counters', 'SELECT, INSERT', 'SELECT, INSERT');
GRANT UPDATE (n) ON TABLE notification_counters TO dwaar_app, dwaar_worker;

-- ---------------------------------------------------------------------------------------------------------------- device health
CREATE TABLE device_health_reports (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    token_id uuid,
    manufacturer text NOT NULL CHECK (manufacturer IN ('xiaomi', 'oppo', 'vivo', 'samsung', 'apple', 'other')),
    phone_model text CHECK (phone_model IS NULL OR char_length(phone_model) <= 80),
    os_name text CHECK (os_name IS NULL OR char_length(os_name) <= 40),
    os_version text CHECK (os_version IS NULL OR char_length(os_version) <= 40),
    notification_permission text NOT NULL CHECK (notification_permission IN ('granted', 'denied', 'unknown')),
    battery_optimisation text NOT NULL DEFAULT 'unknown' CHECK (battery_optimisation IN ('unrestricted', 'optimised', 'unknown')),
    focus_mode_blocks text NOT NULL DEFAULT 'unknown' CHECK (focus_mode_blocks IN ('yes', 'no', 'unknown')),
    test_push text NOT NULL DEFAULT 'not_run' CHECK (test_push IN ('received', 'not_received', 'not_run')),
    -- what the diagnostic concluded: never "delivery is guaranteed"
    verdict text NOT NULL CHECK (verdict IN ('needs_attention', 'no_problem_found', 'cannot_tell')),
    simulation boolean NOT NULL DEFAULT false,
    reported_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT device_health_reports_token_fk FOREIGN KEY (society_id, token_id) REFERENCES device_push_tokens (society_id, id)
);
CREATE INDEX device_health_reports_person_idx ON device_health_reports (society_id, person_id, reported_at DESC);
SELECT dwaar_enable_society_rls('device_health_reports', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_make_append_only('device_health_reports');

-- ---------------------------------------------------------------------------------------------------------------- processed events
-- The outbox consumer's ledger: an event is handled at most once per society even when it is delivered twice or the job restarts.
-- (A cursor on event ids would skip an event whose transaction committed late; a ledger cannot.)
CREATE TABLE notification_processed_events (
    society_id uuid NOT NULL REFERENCES societies (id),
    event_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type ~ '^[A-Za-z][A-Za-z0-9_.]{0,99}$'),
    outcome text NOT NULL DEFAULT 'handled' CHECK (outcome ~ '^[a-z][a-z0-9_]{0,60}$'),
    processed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (society_id, event_id)
);
SELECT dwaar_enable_society_rls('notification_processed_events', 'SELECT', 'SELECT, INSERT');
SELECT dwaar_make_append_only('notification_processed_events');
