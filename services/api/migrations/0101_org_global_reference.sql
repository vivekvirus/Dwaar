-- 0101 organisation: global (non-society) reference data: orgs, legal_packs, tax_packs.
-- REQ: SOC-01 (legal pack and tax pack selection), INV-10 (law is configuration; packs are versioned rows loaded
--      from packages/legal-packs and packages/tax-packs BY CODE, never hard-coded here), GOV-01 / D-24 (binding
--      governance stays disabled until a pack is approved), PRD 8.1 (Organisation aggregate), PRD 8.2.
--
-- These three tables have NO society_id: they are platform-level. The runtime roles get NO table privileges at all
-- (the catalog guard test treats any reachable table without society_id as a violation). The API reads them only
-- through the narrow catalog views below (owner-owned views run with the owner's rights, expose reference data only,
-- and need no SECURITY DEFINER function), and the pack loader (dwaar_api.modules.organisation.packs)
-- writes them as dwaar_owner. Approval (approved_by/approved_at, status 'approved') is evidence entered by operations
-- tooling, never by the API role and never taken from a file claim (ADR-0007 decision 9).

CREATE TABLE orgs (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    name text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 200),
    kind text NOT NULL CHECK (kind IN ('fm', 'builder')),
    settings jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(settings) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid,
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    retention_class text NOT NULL DEFAULT 'RES' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid
);

CREATE TABLE legal_packs (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    pack_key text NOT NULL CHECK (pack_key ~ '^[a-z0-9][a-z0-9._-]{0,99}$'),
    jurisdiction text NOT NULL CHECK (char_length(jurisdiction) BETWEEN 1 AND 40),
    entity_type text NOT NULL CHECK (entity_type IN ('chs', 'apartment_assoc', 'society_reg', 'company', 'any')),
    version text NOT NULL CHECK (char_length(version) BETWEEN 1 AND 40),
    title text NOT NULL DEFAULT '',
    pack_status text NOT NULL CHECK (pack_status IN ('draft', 'unapproved', 'approved', 'retired')),
    enabled boolean NOT NULL DEFAULT true,
    rules jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(rules) = 'object'),
    legal_sources jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(legal_sources) = 'array'),
    content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
    approved_by text,
    approved_at timestamptz,
    effective_from date NOT NULL,
    effective_to date,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid,
    version_no integer NOT NULL DEFAULT 1 CHECK (version_no >= 1),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT legal_packs_key_version_uq UNIQUE (pack_key, version),
    CONSTRAINT legal_packs_effective_range CHECK (effective_to IS NULL OR effective_to >= effective_from),
    -- GOV-01: approval is all-or-nothing evidence; only an approved pack has an approver.
    CONSTRAINT legal_packs_approval_evidence CHECK (
        (pack_status = 'approved') = (approved_by IS NOT NULL AND approved_at IS NOT NULL)
        AND (approved_by IS NULL) = (approved_at IS NULL))
);
COMMENT ON COLUMN legal_packs.version IS 'Pack version string from the pack file (PRD 8.2 name). The common row version is version_no.';
COMMENT ON COLUMN legal_packs.pack_status IS 'Pack lifecycle: draft | unapproved | approved | retired. (Common column status = active|archived row state.)';

CREATE TABLE tax_packs (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    pack_key text NOT NULL CHECK (pack_key ~ '^[a-z0-9][a-z0-9._-]{0,99}$'),
    pack_type text NOT NULL CHECK (pack_type IN ('tds', 'gst-rwa', 'gst-einvoice', 'fee-schedule')),
    version text NOT NULL CHECK (char_length(version) BETWEEN 1 AND 40),
    title text NOT NULL DEFAULT '',
    pack_status text NOT NULL CHECK (pack_status IN ('draft', 'unapproved', 'approved', 'retired')),
    enabled boolean NOT NULL DEFAULT true,
    content jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(content) = 'object'),
    content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
    approved_by text,
    approved_at timestamptz,
    effective_from date NOT NULL,
    effective_to date,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_by uuid,
    version_no integer NOT NULL DEFAULT 1 CHECK (version_no >= 1),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    retention_class text NOT NULL DEFAULT 'LOG' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT tax_packs_key_version_uq UNIQUE (pack_key, version),
    CONSTRAINT tax_packs_effective_range CHECK (effective_to IS NULL OR effective_to >= effective_from),
    CONSTRAINT tax_packs_approval_evidence CHECK (
        (pack_status = 'approved') = (approved_by IS NOT NULL AND approved_at IS NOT NULL)
        AND (approved_by IS NULL) = (approved_at IS NULL))
);

REVOKE ALL ON TABLE orgs, legal_packs, tax_packs FROM PUBLIC, dwaar_app, dwaar_worker;

-- ---------------------------------------------------------------------------------------------
-- Narrow read views for the runtime roles. Reference data only: no names of orgs, no pack rules or content.
-- ---------------------------------------------------------------------------------------------
CREATE VIEW org_catalog AS
    SELECT id, status FROM orgs;

-- binding_allowed (D-24, GOV-01): approved WITH evidence, enabled and inside its effective range today (IST).
CREATE VIEW legal_pack_catalog AS
    SELECT p.id, p.pack_key, p.jurisdiction, p.entity_type, p.version, p.title, p.pack_status, p.enabled,
           (p.pack_status = 'approved' AND p.approved_by IS NOT NULL AND p.approved_at IS NOT NULL) AS approved,
           (p.pack_status = 'approved' AND p.approved_by IS NOT NULL AND p.approved_at IS NOT NULL AND p.enabled
            AND p.status = 'active'
            AND (now() AT TIME ZONE 'Asia/Kolkata')::date >= p.effective_from
            AND (p.effective_to IS NULL OR (now() AT TIME ZONE 'Asia/Kolkata')::date <= p.effective_to))
               AS binding_allowed,
           p.effective_from, p.effective_to
    FROM legal_packs p;

CREATE VIEW tax_pack_catalog AS
    SELECT p.id, p.pack_key, p.pack_type, p.version, p.title, p.pack_status, p.enabled,
           (p.pack_status = 'approved' AND p.approved_by IS NOT NULL AND p.approved_at IS NOT NULL) AS approved,
           p.effective_from, p.effective_to
    FROM tax_packs p;

REVOKE ALL ON org_catalog, legal_pack_catalog, tax_pack_catalog FROM PUBLIC;
GRANT SELECT ON org_catalog, legal_pack_catalog, tax_pack_catalog TO dwaar_app, dwaar_worker;
