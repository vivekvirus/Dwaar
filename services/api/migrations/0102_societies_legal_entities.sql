-- 0102 organisation: societies, legal_entities (PRD 8.2), per-society feature flags and budgets (ARCH-05).
-- REQ: SOC-01, ARCH-01 (composite FKs: no cross-society reference), ARCH-03/INV-01 (RLS), ARCH-05 (per-society
--      feature flags, AI/rate budgets and queue quotas), INV-04 (billing/legal entity explicitly linked),
--      PRD 7.4 (encrypted ID numbers), PRD 8.2 common columns.
--
-- `societies` has no society column in the PRD, but it IS the tenant root. It carries
--     society_id uuid GENERATED ALWAYS AS (id) STORED
-- so the standard helper applies and the policy reads `society_id = app.society_id`, i.e. a society context may
-- see exactly its OWN row and no other. Inserting a society needs the context of the NEW id (the API allocates
-- the id first, then opens the transaction with that context); the creator cannot see or write another society.
--
-- legal_entities belong to exactly one society (carry society_id). societies.legal_entity_id and
-- legal_entities.society_id reference each other through DEFERRABLE FKs so both rows are created in one
-- transaction; the composite FK (id, legal_entity_id) -> legal_entities (society_id, id) makes it impossible to
-- link a society to another society's legal entity (ARCH-01).
--
-- PAN/TAN/GSTIN: only AES-GCM envelope ciphertext (`*_enc`, dwaar_common.crypto) and a masked display form
-- (`*_masked`, never the full value) are stored. GSTIN is `gstin_enc` here (PRD 8.2 lists a plain `gstin`; the task
-- and PRD 7.4 require ID numbers to be encrypted, the stricter reading wins; see ADR-0010).

CREATE TABLE societies (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid GENERATED ALWAYS AS (id) STORED,
    org_id uuid REFERENCES orgs (id),
    name text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 200),
    legal_entity_id uuid NOT NULL,
    legal_pack_id uuid NOT NULL REFERENCES legal_packs (id),
    tax_pack_id uuid REFERENCES tax_packs (id),
    city text NOT NULL CHECK (char_length(btrim(city)) BETWEEN 1 AND 100),
    state text NOT NULL CHECK (char_length(btrim(state)) BETWEEN 1 AND 100),
    timezone text NOT NULL DEFAULT 'Asia/Kolkata' CHECK (char_length(timezone) BETWEEN 1 AND 64),
    settings jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(settings) = 'object' AND pg_column_size(settings) <= 16384),
    ai_budget_paise bigint NOT NULL DEFAULT 0 CHECK (ai_budget_paise >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'archived')),
    retention_class text NOT NULL DEFAULT 'RES' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid
);
CREATE INDEX societies_org_idx ON societies (org_id) WHERE org_id IS NOT NULL;

CREATE TABLE legal_entities (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id) DEFERRABLE INITIALLY DEFERRED,
    name text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 200),
    entity_type text NOT NULL CHECK (entity_type IN ('chs', 'apartment_assoc', 'society_reg', 'company')),
    registration_no text NOT NULL CHECK (char_length(btrim(registration_no)) BETWEEN 1 AND 100),
    pan_enc text,
    pan_masked text,
    tan_enc text,
    tan_masked text,
    gstin_enc text,
    gstin_masked text,
    gst_registered boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    retention_class text NOT NULL DEFAULT 'FIN' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT legal_entities_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT legal_entities_pan_pair CHECK ((pan_enc IS NULL) = (pan_masked IS NULL)),
    CONSTRAINT legal_entities_tan_pair CHECK ((tan_enc IS NULL) = (tan_masked IS NULL)),
    CONSTRAINT legal_entities_gstin_pair CHECK ((gstin_enc IS NULL) = (gstin_masked IS NULL)),
    CONSTRAINT legal_entities_gst_flag CHECK (gstin_enc IS NULL OR gst_registered)
);

ALTER TABLE societies
    ADD CONSTRAINT societies_legal_entity_fk FOREIGN KEY (id, legal_entity_id)
        REFERENCES legal_entities (society_id, id) DEFERRABLE INITIALLY DEFERRED;

SELECT dwaar_enable_society_rls('societies', 'SELECT, INSERT', 'SELECT');
SELECT dwaar_enable_society_rls('legal_entities', 'SELECT, INSERT', 'SELECT');
-- Column-level UPDATE only (a table-level UPDATE privilege would let the role take any table lock, ADR-0004).
GRANT UPDATE (name, legal_pack_id, tax_pack_id, city, state, timezone, settings, ai_budget_paise, version, status)
    ON TABLE societies TO dwaar_app;
GRANT UPDATE (name, registration_no, version, status) ON TABLE legal_entities TO dwaar_app;

-- ---------------------------------------------------------------------------------------------
-- ARCH-05: per-society feature flags and resource budgets, so one township cannot exhaust shared resources.
-- ---------------------------------------------------------------------------------------------
CREATE TABLE society_feature_flags (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    flag_key text NOT NULL CHECK (flag_key ~ '^[a-z][a-z0-9_]{1,62}$'),
    enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT society_feature_flags_key_uq UNIQUE (society_id, flag_key)
);
SELECT dwaar_enable_society_rls('society_feature_flags', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (enabled, version, status) ON TABLE society_feature_flags TO dwaar_app;

CREATE TABLE society_quotas (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    rate_per_minute integer NOT NULL DEFAULT 600 CHECK (rate_per_minute BETWEEN 1 AND 100000),
    rate_burst integer NOT NULL DEFAULT 120 CHECK (rate_burst BETWEEN 1 AND 100000),
    queue_quota integer NOT NULL DEFAULT 1000 CHECK (queue_quota BETWEEN 0 AND 10000000),
    ai_requests_per_day integer NOT NULL DEFAULT 0 CHECK (ai_requests_per_day BETWEEN 0 AND 1000000),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT society_quotas_society_uq UNIQUE (society_id)
);
SELECT dwaar_enable_society_rls('society_quotas', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (rate_per_minute, rate_burst, queue_quota, ai_requests_per_day, version)
    ON TABLE society_quotas TO dwaar_app;
