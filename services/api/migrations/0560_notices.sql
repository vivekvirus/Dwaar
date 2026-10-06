-- 0560 notices (COM-01, COM-02, COM-03, COM-05, PRD 8.2 notices / notice_versions).
-- REQ: COM-01 (draft -> approved -> scheduled/published -> superseded/archived; recipient scope; delivery attempts and
--      read acknowledgements as records; revisions create new versions), COM-02 (translations always show the original;
--      legally or safety-significant translations need recorded human review), COM-03 (AI-drafted notices require human
--      approval: drafted_by_ai forces the approval step), COM-05 (emergency channel; never carries ads: no sponsor field
--      exists and the emergency body refuses links), INV-05 (no commercial content), ARCH-01, INV-01.
--
-- A notice is the thread; each REVISION is a notice_versions row. Once a revision is approved its content never changes
-- (trigger below); a published revision is immutable and is only ever superseded by a newer published revision.

CREATE TABLE notices (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    kind text NOT NULL CHECK (kind IN ('general', 'legal', 'safety', 'emergency')),
    audience jsonb NOT NULL CHECK (jsonb_typeof(audience) = 'object' AND pg_column_size(audience) <= 8192),
    audience_scope text NOT NULL CHECK (audience_scope IN ('society', 'block', 'unit', 'role')),
    audience_block_ids uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(audience_block_ids) <= 200),
    audience_unit_ids uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(audience_unit_ids) <= 500),
    audience_roles text[] NOT NULL DEFAULT '{}' CHECK (cardinality(audience_roles) <= 20),
    state text NOT NULL DEFAULT 'draft'
        CHECK (state IN ('draft', 'approved', 'scheduled', 'published', 'superseded', 'archived')),
    target_languages text[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(target_languages) <= 4 AND target_languages <@ ARRAY['en', 'hi', 'mr', 'kn']::text[]),
    latest_revision integer NOT NULL DEFAULT 1 CHECK (latest_revision >= 1),
    current_version_id uuid,
    superseded_by uuid,
    created_by uuid NOT NULL REFERENCES iam.persons (id),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    archived_at timestamptz,
    retention_class text NOT NULL DEFAULT 'COM' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT notices_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT notices_audience_shape CHECK (
        (audience_scope = 'society' AND cardinality(audience_block_ids) = 0 AND cardinality(audience_unit_ids) = 0
            AND cardinality(audience_roles) = 0)
        OR (audience_scope = 'block' AND cardinality(audience_block_ids) > 0)
        OR (audience_scope = 'unit' AND cardinality(audience_unit_ids) > 0)
        OR (audience_scope = 'role' AND cardinality(audience_roles) > 0)),
    CONSTRAINT notices_superseded_shape CHECK ((state = 'superseded') = (superseded_by IS NOT NULL)),
    CONSTRAINT notices_superseded_fk FOREIGN KEY (society_id, superseded_by) REFERENCES notices (society_id, id)
);
CREATE INDEX notices_state_idx ON notices (society_id, state, created_at DESC, id DESC);
CREATE INDEX notices_kind_idx ON notices (society_id, kind, created_at DESC, id DESC);

CREATE TABLE notice_versions (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    notice_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision >= 1),
    language text NOT NULL CHECK (language IN ('en', 'hi', 'mr', 'kn')),
    title text NOT NULL CHECK (char_length(btrim(title)) BETWEEN 3 AND 200),
    body text NOT NULL CHECK (char_length(btrim(body)) BETWEEN 3 AND 20000),
    content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    state text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'approved', 'scheduled', 'published', 'superseded')),
    drafted_by_ai boolean NOT NULL DEFAULT false,
    ai_run_ref text CHECK (ai_run_ref IS NULL OR char_length(ai_run_ref) <= 100),
    created_by uuid NOT NULL REFERENCES iam.persons (id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    approved_by uuid REFERENCES iam.persons (id),
    approved_at timestamptz,
    publish_at timestamptz,
    published_at timestamptz,
    CONSTRAINT notice_versions_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT notice_versions_notice_fk FOREIGN KEY (society_id, notice_id) REFERENCES notices (society_id, id),
    CONSTRAINT notice_versions_revision_uq UNIQUE (society_id, notice_id, revision),
    -- COM-03: anything past draft carries a human approver; an AI draft can never skip that step
    CONSTRAINT notice_versions_approved_shape CHECK (
        state = 'draft' OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)),
    CONSTRAINT notice_versions_ai_needs_human CHECK (
        NOT drafted_by_ai OR state = 'draft' OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)),
    CONSTRAINT notice_versions_scheduled_shape CHECK (state <> 'scheduled' OR publish_at IS NOT NULL),
    CONSTRAINT notice_versions_published_shape CHECK (
        (state IN ('published', 'superseded')) = (published_at IS NOT NULL))
);
CREATE INDEX notice_versions_notice_idx ON notice_versions (society_id, notice_id, revision DESC);
CREATE INDEX notice_versions_due_idx ON notice_versions (society_id, publish_at) WHERE state = 'scheduled';
ALTER TABLE notices ADD CONSTRAINT notices_current_version_fk
    FOREIGN KEY (society_id, current_version_id) REFERENCES notice_versions (society_id, id) DEFERRABLE INITIALLY DEFERRED;

-- COM-01: a revision past draft is IMMUTABLE; states only move forward.
CREATE FUNCTION notice_versions_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF OLD.state <> 'draft' AND (
        NEW.notice_id IS DISTINCT FROM OLD.notice_id OR NEW.revision IS DISTINCT FROM OLD.revision
        OR NEW.language IS DISTINCT FROM OLD.language OR NEW.title IS DISTINCT FROM OLD.title
        OR NEW.body IS DISTINCT FROM OLD.body OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
        OR NEW.drafted_by_ai IS DISTINCT FROM OLD.drafted_by_ai OR NEW.ai_run_ref IS DISTINCT FROM OLD.ai_run_ref
        OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
        OR NEW.approved_at IS DISTINCT FROM OLD.approved_at
        OR (OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at)) THEN
        RAISE EXCEPTION 'notice version % is immutable once approved', OLD.id USING ERRCODE = 'DW002';
    END IF;
    IF NEW.state <> OLD.state AND NOT (
        (OLD.state = 'draft' AND NEW.state = 'approved')
        OR (OLD.state = 'approved' AND NEW.state IN ('scheduled', 'published'))
        OR (OLD.state = 'scheduled' AND NEW.state = 'published')
        OR (OLD.state = 'published' AND NEW.state = 'superseded')) THEN
        RAISE EXCEPTION 'notice version state % -> % is not allowed', OLD.state, NEW.state USING ERRCODE = 'DW002';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER notice_versions_immutable BEFORE UPDATE ON notice_versions
    FOR EACH ROW EXECUTE FUNCTION notice_versions_immutable();

-- COM-02: a translation always sits next to the original. Review state is recorded; a reviewed text cannot be edited.
CREATE TABLE notice_translations (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    notice_id uuid NOT NULL,
    notice_version_id uuid NOT NULL,
    language text NOT NULL CHECK (language IN ('en', 'hi', 'mr', 'kn')),
    title text NOT NULL CHECK (char_length(btrim(title)) BETWEEN 3 AND 200),
    body text NOT NULL CHECK (char_length(btrim(body)) BETWEEN 3 AND 20000),
    origin text NOT NULL CHECK (origin IN ('human', 'machine_draft')),
    drafted_by_ai boolean NOT NULL DEFAULT false,
    ai_run_ref text CHECK (ai_run_ref IS NULL OR char_length(ai_run_ref) <= 100),
    translated_by uuid REFERENCES iam.persons (id),
    review_state text NOT NULL DEFAULT 'unreviewed' CHECK (review_state IN ('unreviewed', 'reviewed', 'rejected')),
    reviewed_by uuid REFERENCES iam.persons (id),
    reviewed_at timestamptz,
    review_note text CHECK (review_note IS NULL OR char_length(review_note) <= 500),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT notice_translations_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT notice_translations_version_fk FOREIGN KEY (society_id, notice_version_id)
        REFERENCES notice_versions (society_id, id),
    CONSTRAINT notice_translations_lang_uq UNIQUE (society_id, notice_version_id, language),
    CONSTRAINT notice_translations_origin_shape CHECK (
        (origin = 'human' AND translated_by IS NOT NULL) OR (origin = 'machine_draft' AND drafted_by_ai)),
    CONSTRAINT notice_translations_review_shape CHECK (
        (review_state = 'unreviewed' AND reviewed_by IS NULL AND reviewed_at IS NULL)
        OR (review_state IN ('reviewed', 'rejected') AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL))
);
CREATE INDEX notice_translations_notice_idx ON notice_translations (society_id, notice_id);

CREATE FUNCTION notice_translations_reviewed_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF OLD.review_state = 'reviewed' AND (
        NEW.title IS DISTINCT FROM OLD.title OR NEW.body IS DISTINCT FROM OLD.body
        OR NEW.language IS DISTINCT FROM OLD.language OR NEW.review_state IS DISTINCT FROM OLD.review_state
        OR NEW.reviewed_by IS DISTINCT FROM OLD.reviewed_by) THEN
        RAISE EXCEPTION 'a reviewed translation is immutable' USING ERRCODE = 'DW002';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER notice_translations_reviewed_immutable BEFORE UPDATE ON notice_translations
    FOR EACH ROW EXECUTE FUNCTION notice_translations_reviewed_immutable();

-- COM-01: delivery ATTEMPTS are records (the notifications module appends them; this module never dispatches).
CREATE TABLE notice_deliveries (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    notice_version_id uuid NOT NULL,
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    channel text NOT NULL CHECK (channel IN ('app_push', 'sms', 'whatsapp', 'email', 'voice', 'emergency', 'notice_board', 'manual')),
    status text NOT NULL CHECK (status IN ('queued', 'sent', 'delivered', 'failed', 'skipped')),
    attempt integer NOT NULL DEFAULT 1 CHECK (attempt >= 1),
    provider_ref text CHECK (provider_ref IS NULL OR char_length(provider_ref) <= 200),
    detail text CHECK (detail IS NULL OR char_length(detail) <= 300),
    simulation boolean NOT NULL DEFAULT false,
    at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT notice_deliveries_version_fk FOREIGN KEY (society_id, notice_version_id)
        REFERENCES notice_versions (society_id, id)
);
CREATE INDEX notice_deliveries_version_idx ON notice_deliveries (society_id, notice_version_id, at DESC, id DESC);
SELECT dwaar_enable_society_rls('notice_deliveries', 'SELECT, INSERT', 'SELECT, INSERT');
SELECT dwaar_make_append_only('notice_deliveries');

-- COM-01: read and acknowledgement receipts (one of each kind per person per revision).
CREATE TABLE notice_receipts (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    notice_version_id uuid NOT NULL,
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    kind text NOT NULL CHECK (kind IN ('read', 'acknowledged')),
    at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT notice_receipts_version_fk FOREIGN KEY (society_id, notice_version_id)
        REFERENCES notice_versions (society_id, id),
    CONSTRAINT notice_receipts_once_uq UNIQUE (society_id, notice_version_id, person_id, kind)
);
SELECT dwaar_enable_society_rls('notice_receipts', 'SELECT, INSERT', 'SELECT, INSERT');
SELECT dwaar_make_append_only('notice_receipts');

SELECT dwaar_enable_society_rls('notices', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (audience, audience_scope, audience_block_ids, audience_unit_ids, audience_roles, state, target_languages,
              latest_revision, current_version_id, superseded_by, version, updated_at, archived_at)
    ON TABLE notices TO dwaar_app, dwaar_worker;
SELECT dwaar_enable_society_rls('notice_versions', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (title, body, language, content_hash, state, approved_by, approved_at, publish_at, published_at)
    ON TABLE notice_versions TO dwaar_app, dwaar_worker;
SELECT dwaar_enable_society_rls('notice_translations', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (title, body, origin, drafted_by_ai, ai_run_ref, translated_by, review_state, reviewed_by, reviewed_at,
              review_note, version)
    ON TABLE notice_translations TO dwaar_app;

-- COM-05 / INV-05: the emergency channel carries no links and is never AI-drafted (structural; ad detection is NOT claimed).
CREATE FUNCTION notice_versions_emergency_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE v_kind text;
BEGIN
    SELECT kind INTO v_kind FROM notices WHERE society_id = NEW.society_id AND id = NEW.notice_id;
    IF v_kind = 'emergency' AND (NEW.drafted_by_ai
        OR (NEW.title || ' ' || NEW.body) ~* '(https?://|www\.|\.(com|in|net|org)(/|\s|$))') THEN
        RAISE EXCEPTION 'emergency broadcasts carry no links and are never AI-drafted' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER notice_versions_emergency BEFORE INSERT OR UPDATE OF title, body ON notice_versions
    FOR EACH ROW EXECUTE FUNCTION notice_versions_emergency_guard();
