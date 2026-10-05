-- 0130 identity: global persons + encrypted vault (schema "iam").
-- REQ: ARCH-02 (one global persons identity; personal identity details in an encrypted vault separated from
--      operational identifiers), IAM-01, IAM-06, IAM-11, PRD 8.2 (persons, person_vault), INV-04.
--
-- WHY A SCHEMA. persons, the vault, OTP challenges, sessions and MFA factors are GLOBAL (a person belongs to many
-- societies), so they cannot carry society_id + RLS. They live in schema "iam" and the runtime roles hold NO
-- table privilege there at all: the only way in is a small set of reviewed SECURITY DEFINER functions
-- (iam.*), each of which checks the transaction context (app.person_id / app.society_id) itself. The catalog
-- guard (tests/security/test_core_rls_isolation.py) therefore sees nothing reachable, and
-- tests/security/test_identity_definers.py is the equivalent of the "reviewed definers" test for this schema
-- (the core test only scans schema public).
CREATE SCHEMA iam AUTHORIZATION dwaar_owner;
REVOKE ALL ON SCHEMA iam FROM PUBLIC;
GRANT USAGE ON SCHEMA iam TO dwaar_app, dwaar_worker;

CREATE TABLE iam.persons (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    display_name text NOT NULL CHECK (char_length(btrim(display_name)) BETWEEN 1 AND 120),
    preferred_language text NOT NULL DEFAULT 'en' CHECK (preferred_language IN ('en', 'hi', 'mr', 'kn')),
    -- keyed salted HMAC of the E.164 number (dwaar_common.crypto.keyed_hash, purpose phone_token). Phone is never a key.
    phone_token text NOT NULL CONSTRAINT persons_phone_token_key UNIQUE CHECK (char_length(phone_token) BETWEEN 8 AND 200),
    is_minor boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'phone_released')),
    phone_verified_at timestamptz,
    phone_released_at timestamptz,
    version integer NOT NULL DEFAULT 1,
    retention_class text NOT NULL DEFAULT 'RES' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam.person_vault (
    person_id uuid PRIMARY KEY REFERENCES iam.persons (id),
    phone_enc text NOT NULL,          -- AES-GCM envelope (dwaar_common.crypto.EnvelopeCipher), AAD binds person and field
    email_enc text,
    id_doc_masked text,               -- masked display value only; the number itself is never stored in the clear
    retention_class text NOT NULL DEFAULT 'RES' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    updated_at timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON TABLE iam.persons, iam.person_vault FROM PUBLIC, dwaar_app, dwaar_worker;

-- Context helpers (SECURITY INVOKER: they only read the transaction-local settings).
CREATE FUNCTION iam.ctx_person() RETURNS uuid LANGUAGE sql STABLE SET search_path = pg_catalog
AS $$ SELECT nullif(current_setting('app.person_id', true), '')::uuid $$;
CREATE FUNCTION iam.ctx_society() RETURNS uuid LANGUAGE sql STABLE SET search_path = pg_catalog
AS $$ SELECT nullif(current_setting('app.society_id', true), '')::uuid $$;
CREATE FUNCTION iam.ctx_role() RETURNS text LANGUAGE sql STABLE SET search_path = pg_catalog
AS $$ SELECT nullif(current_setting('app.actor_role', true), '') $$;
REVOKE ALL ON FUNCTION iam.ctx_person(), iam.ctx_society(), iam.ctx_role() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.ctx_person(), iam.ctx_society(), iam.ctx_role() TO dwaar_app, dwaar_worker;

-- A person for a phone token, created if missing and WITHOUT claiming the number is proven (secretary-created
-- stubs: membership invitations, staff grants). Returns the person id; the caller cannot tell whether it existed.
CREATE FUNCTION iam.ensure_person(p_person_id uuid, p_phone_token text, p_phone_enc text, p_display_name text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
DECLARE v_id uuid;
BEGIN
    SELECT p.id INTO v_id FROM iam.persons p WHERE p.phone_token = p_phone_token;
    IF FOUND THEN RETURN v_id; END IF;
    INSERT INTO iam.persons (id, display_name, phone_token)
    VALUES (p_person_id, left(coalesce(nullif(btrim(p_display_name), ''), 'Resident'), 120), p_phone_token);
    INSERT INTO iam.person_vault (person_id, phone_enc) VALUES (p_person_id, p_phone_enc);
    RETURN p_person_id;
END $$;
