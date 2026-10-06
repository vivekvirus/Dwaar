-- 0561 document vault (COM-04, SEC-03, SEC-04).
-- REQ: COM-04 (versions, effective dates, authority, access levels; published versions immutable; sha256 recorded),
--      SEC-03 (uploads type- and size-validated and malware-scanned: a version can only be published when scan_state is
--      'clean'; the scanner fails closed), SEC-04 (object keys are unguessable and live outside this table's API surface;
--      downloads are signed, short-lived URLs issued after a current access check), INV-01, ARCH-01.

CREATE TABLE documents (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    doc_type text NOT NULL CHECK (doc_type IN ('bye_laws', 'minutes', 'audit_report', 'circular', 'policy', 'other')),
    title text NOT NULL CHECK (char_length(btrim(title)) BETWEEN 3 AND 200),
    authority text NOT NULL CHECK (char_length(btrim(authority)) BETWEEN 2 AND 200),
    access_level text NOT NULL CHECK (access_level IN ('all_residents', 'owners', 'committee', 'managers')),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'archived')),
    current_version_id uuid,
    created_by uuid NOT NULL REFERENCES iam.persons (id),
    version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retention_class text NOT NULL DEFAULT 'DOC' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    CONSTRAINT documents_society_id_uq UNIQUE (society_id, id)
);
CREATE INDEX documents_type_idx ON documents (society_id, doc_type, created_at DESC, id DESC);

CREATE TABLE document_versions (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL REFERENCES societies (id),
    document_id uuid NOT NULL,
    version_no integer NOT NULL CHECK (version_no >= 1),
    state text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'published', 'superseded', 'withdrawn')),
    effective_from date NOT NULL,
    authority text NOT NULL CHECK (char_length(btrim(authority)) BETWEEN 2 AND 200),
    change_note text CHECK (change_note IS NULL OR char_length(change_note) <= 500),
    original_filename text CHECK (original_filename IS NULL OR char_length(original_filename) BETWEEN 1 AND 200),
    media_type text CHECK (media_type IS NULL OR media_type IN (
        'application/pdf', 'image/png', 'image/jpeg', 'text/plain', 'text/csv')),
    size_bytes bigint CHECK (size_bytes IS NULL OR size_bytes BETWEEN 1 AND 52428800),
    sha256 text CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
    object_key text CHECK (object_key IS NULL OR object_key ~ '^[A-Za-z0-9_-]{32,128}$'),
    storage_simulation boolean NOT NULL DEFAULT false,
    scan_state text NOT NULL DEFAULT 'none' CHECK (scan_state IN ('none', 'clean', 'infected', 'unavailable')),
    scanner text CHECK (scanner IS NULL OR char_length(scanner) <= 60),
    scanner_simulation boolean NOT NULL DEFAULT false,
    scanned_at timestamptz,
    created_by uuid NOT NULL REFERENCES iam.persons (id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    published_by uuid REFERENCES iam.persons (id),
    published_at timestamptz,
    withdrawn_at timestamptz,
    withdraw_reason text CHECK (withdraw_reason IS NULL OR char_length(withdraw_reason) <= 500),
    CONSTRAINT document_versions_society_id_uq UNIQUE (society_id, id),
    CONSTRAINT document_versions_document_fk FOREIGN KEY (society_id, document_id) REFERENCES documents (society_id, id),
    CONSTRAINT document_versions_no_uq UNIQUE (society_id, document_id, version_no),
    CONSTRAINT document_versions_file_shape CHECK (
        (object_key IS NULL AND sha256 IS NULL AND size_bytes IS NULL AND media_type IS NULL)
        OR (object_key IS NOT NULL AND sha256 IS NOT NULL AND size_bytes IS NOT NULL AND media_type IS NOT NULL)),
    -- SEC-03: nothing is published that is not a stored, hashed, CLEAN-scanned file
    CONSTRAINT document_versions_published_shape CHECK (
        state NOT IN ('published', 'superseded') OR
        (object_key IS NOT NULL AND scan_state = 'clean' AND published_by IS NOT NULL AND published_at IS NOT NULL))
);
CREATE INDEX document_versions_doc_idx ON document_versions (society_id, document_id, version_no DESC);
ALTER TABLE documents ADD CONSTRAINT documents_current_version_fk
    FOREIGN KEY (society_id, current_version_id) REFERENCES document_versions (society_id, id) DEFERRABLE INITIALLY DEFERRED;

-- COM-04: published versions are immutable (file, hash, dates, authority); states only move forward.
CREATE FUNCTION document_versions_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF OLD.state <> 'draft' AND (
        NEW.document_id IS DISTINCT FROM OLD.document_id OR NEW.version_no IS DISTINCT FROM OLD.version_no
        OR NEW.effective_from IS DISTINCT FROM OLD.effective_from OR NEW.authority IS DISTINCT FROM OLD.authority
        OR NEW.original_filename IS DISTINCT FROM OLD.original_filename OR NEW.media_type IS DISTINCT FROM OLD.media_type
        OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes OR NEW.sha256 IS DISTINCT FROM OLD.sha256
        OR NEW.object_key IS DISTINCT FROM OLD.object_key OR NEW.created_by IS DISTINCT FROM OLD.created_by
        OR NEW.published_by IS DISTINCT FROM OLD.published_by OR NEW.published_at IS DISTINCT FROM OLD.published_at) THEN
        RAISE EXCEPTION 'document version % is immutable once published', OLD.id USING ERRCODE = 'DW002';
    END IF;
    IF NEW.state <> OLD.state AND NOT (
        (OLD.state = 'draft' AND NEW.state = 'published')
        OR (OLD.state = 'published' AND NEW.state IN ('superseded', 'withdrawn'))
        OR (OLD.state = 'superseded' AND NEW.state = 'withdrawn')) THEN
        RAISE EXCEPTION 'document version state % -> % is not allowed', OLD.state, NEW.state USING ERRCODE = 'DW002';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER document_versions_immutable BEFORE UPDATE ON document_versions
    FOR EACH ROW EXECUTE FUNCTION document_versions_immutable();

SELECT dwaar_enable_society_rls('documents', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (title, authority, access_level, state, current_version_id, version, updated_at) ON TABLE documents TO dwaar_app;
SELECT dwaar_enable_society_rls('document_versions', 'SELECT, INSERT', 'SELECT');
GRANT UPDATE (state, effective_from, authority, change_note, original_filename, media_type, size_bytes, sha256, object_key,
              storage_simulation, scan_state, scanner, scanner_simulation, scanned_at, published_by, published_at,
              withdrawn_at, withdraw_reason)
    ON TABLE document_versions TO dwaar_app;
