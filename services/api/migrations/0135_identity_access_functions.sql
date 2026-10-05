-- 0135 identity: the reviewed SQL surface over the global tables (schema "iam").
-- REQ: IAM-02, IAM-08 (current grants re-read from the database on every request; revoked sessions stop at once),
--      IAM-11 (number change), ARCH-02 (vault reachable only on a designed path), INV-01.
--
-- Every function is SECURITY DEFINER with a pinned search_path, REVOKEd from PUBLIC, and gates itself on the
-- transaction context that only the API's authorisation layer sets (ADR-0011). The vault returns CIPHERTEXT, and only
-- to (a) the person it belongs to, or (b) a secretary acting in a society where that person has a membership or
-- grant. A person with no relationship to the caller's society is invisible: no row, not an error.

-- Everything the resolver needs, for the context person only. Triggers the elevation sweep first, so an expired
-- or revoked elevated grant has already revoked its MFA-elevated sessions by the time access is decided.
CREATE FUNCTION iam.sweep_person(p_person uuid) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
DECLARE v_n integer := 0;
BEGIN
    IF EXISTS (SELECT 1 FROM iam.person_access_index i WHERE i.person_id = p_person AND i.source_kind = 'role_grant'
               AND iam.is_elevated_role(i.role) AND i.swept_at IS NULL AND (i.expires_at <= now() OR NOT i.effective)) THEN
        UPDATE iam.person_access_index i SET swept_at = now()
        WHERE i.person_id = p_person AND i.source_kind = 'role_grant' AND iam.is_elevated_role(i.role)
          AND i.swept_at IS NULL AND (i.expires_at <= now() OR NOT i.effective);
        IF NOT EXISTS (SELECT 1 FROM iam.person_access_index i WHERE i.person_id = p_person AND iam.is_elevated_role(i.role)
                       AND i.effective AND (i.not_before IS NULL OR i.not_before <= now())
                       AND (i.expires_at IS NULL OR i.expires_at > now())) THEN
            UPDATE iam.refresh_tokens SET revoked_at = now() WHERE revoked_at IS NULL AND session_id IN
                (SELECT id FROM iam.auth_sessions WHERE person_id = p_person AND revoked_at IS NULL AND mfa_verified_at IS NOT NULL);
            UPDATE iam.auth_sessions SET revoked_at = now(), revoked_reason = 'privilege_expired'
            WHERE person_id = p_person AND revoked_at IS NULL AND mfa_verified_at IS NOT NULL;
            GET DIAGNOSTICS v_n = ROW_COUNT;
        END IF;
    END IF;
    RETURN v_n;
END $$;

-- Housekeeping for the worker: the same sweep for every person with a pending expiry.
CREATE FUNCTION iam.sweep_expired_grants() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
DECLARE v_p uuid; v_n integer := 0;
BEGIN
    FOR v_p IN SELECT DISTINCT i.person_id FROM iam.person_access_index i
               WHERE i.source_kind = 'role_grant' AND iam.is_elevated_role(i.role) AND i.swept_at IS NULL
                 AND (i.expires_at <= now() OR NOT i.effective) LOOP
        v_n := v_n + iam.sweep_person(v_p);
    END LOOP;
    RETURN v_n;
END $$;

CREATE FUNCTION iam.effective_grants(p_person uuid)
RETURNS TABLE (source_kind text, source_id uuid, role text, society_ref uuid, unit_ref uuid, not_before timestamptz,
               expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
#variable_conflict use_column
BEGIN
    IF p_person IS DISTINCT FROM iam.ctx_person() THEN RETURN; END IF;
    PERFORM iam.sweep_person(p_person);
    RETURN QUERY
    SELECT i.source_kind, i.source_id, i.role, i.society_ref, i.unit_ref, i.not_before, i.expires_at
    FROM iam.person_access_index i JOIN iam.persons p ON p.id = i.person_id AND p.status = 'active'
    WHERE i.person_id = p_person AND i.effective
      AND (i.not_before IS NULL OR i.not_before <= now()) AND (i.expires_at IS NULL OR i.expires_at > now());
END $$;

-- Every relationship of the context person, effective or not (GET /v1/me, society discovery for applicants).
CREATE FUNCTION iam.access_overview(p_person uuid)
RETURNS TABLE (source_kind text, source_id uuid, role text, society_ref uuid, unit_ref uuid, membership_kind text,
               verification text, effective boolean, not_before timestamptz, expires_at timestamptz)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, iam, public AS $$
    SELECT i.source_kind, i.source_id, i.role, i.society_ref, i.unit_ref, i.membership_kind, i.verification,
           i.effective AND (i.not_before IS NULL OR i.not_before <= now()) AND (i.expires_at IS NULL OR i.expires_at > now()),
           i.not_before, i.expires_at
    FROM iam.person_access_index i
    WHERE i.person_id = p_person AND p_person = iam.ctx_person()
    ORDER BY i.society_ref, i.source_kind, i.source_id
$$;

-- The society (and unit) a membership id belongs to. Only the context person may ask; the caller then proves
-- standing through the resolver, so an unknown id and an id the caller has no standing in look the same.
CREATE FUNCTION iam.locate_membership(p_membership uuid)
RETURNS TABLE (society_ref uuid, unit_ref uuid)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, iam, public AS $$
    SELECT i.society_ref, i.unit_ref FROM iam.person_access_index i
    WHERE i.source_kind = 'membership' AND i.source_id = p_membership AND iam.ctx_person() IS NOT NULL
$$;

-- Display data of a person, only for the person themself or in a society where they have a relationship.
CREATE FUNCTION iam.society_people(p_ids uuid[])
RETURNS TABLE (id uuid, display_name text, preferred_language text, is_minor boolean)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, iam, public AS $$
    SELECT p.id, p.display_name, p.preferred_language, p.is_minor FROM iam.persons p
    WHERE p.id = ANY (p_ids) AND (p.id = iam.ctx_person() OR (iam.ctx_society() IS NOT NULL AND EXISTS
          (SELECT 1 FROM iam.person_access_index i WHERE i.person_id = p.id AND i.society_ref = iam.ctx_society())))
$$;

CREATE FUNCTION iam.person_profile(p_person uuid)
RETURNS TABLE (id uuid, display_name text, preferred_language text, is_minor boolean, status text, phone_verified_at timestamptz)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, iam, public AS $$
    SELECT p.id, p.display_name, p.preferred_language, p.is_minor, p.status, p.phone_verified_at
    FROM iam.persons p WHERE p.id = p_person AND p.id = iam.ctx_person()
$$;

CREATE FUNCTION iam.update_profile(p_person uuid, p_display_name text, p_language text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
BEGIN
    IF p_person IS DISTINCT FROM iam.ctx_person() THEN RETURN false; END IF;
    UPDATE iam.persons SET display_name = coalesce(p_display_name, display_name),
           preferred_language = coalesce(p_language, preferred_language), updated_at = now(), version = version + 1
    WHERE id = p_person;
    RETURN FOUND;
END $$;

-- The vault: ciphertext only, on a designed path only.
CREATE FUNCTION iam.vault_get(p_person uuid)
RETURNS TABLE (person_id uuid, phone_enc text, email_enc text, id_doc_masked text)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, iam, public AS $$
    SELECT v.person_id, v.phone_enc, v.email_enc, v.id_doc_masked FROM iam.person_vault v
    WHERE v.person_id = p_person AND (
        p_person = iam.ctx_person()
        OR (iam.ctx_role() = 'secretary' AND iam.ctx_society() IS NOT NULL AND EXISTS
            (SELECT 1 FROM iam.person_access_index i WHERE i.person_id = p_person AND i.society_ref = iam.ctx_society())))
$$;

CREATE FUNCTION iam.vault_put(p_person uuid, p_email_enc text, p_id_doc_masked text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
BEGIN
    IF p_person IS DISTINCT FROM iam.ctx_person() THEN RETURN false; END IF;
    UPDATE iam.person_vault SET email_enc = coalesce(p_email_enc, email_enc),
           id_doc_masked = coalesce(p_id_doc_masked, id_doc_masked), updated_at = now()
    WHERE person_id = p_person;
    RETURN FOUND;
END $$;

-- IAM-11: a number change. Needs a just-consumed phone_change OTP for the NEW number issued to this person. Old
-- sessions (all of them, including the current one) are revoked; the caller re-opens memberships for verification.
-- Result: ok | conflict (the new number belongs to someone else) | invalid.
CREATE FUNCTION iam.change_phone(p_person uuid, p_challenge uuid, p_new_token text, p_new_phone_enc text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
DECLARE v_ok boolean;
BEGIN
    IF p_person IS DISTINCT FROM iam.ctx_person() THEN RETURN 'invalid'; END IF;
    SELECT true INTO v_ok FROM iam.otp_challenges c
    WHERE c.id = p_challenge AND c.purpose = 'phone_change' AND c.person_id = p_person AND c.phone_token = p_new_token
      AND c.consumed_at > now() - interval '2 minutes' AND c.session_issued_at IS NULL FOR UPDATE;
    IF v_ok IS NOT TRUE THEN RETURN 'invalid'; END IF;
    IF EXISTS (SELECT 1 FROM iam.persons p WHERE p.phone_token = p_new_token AND p.id <> p_person) THEN RETURN 'conflict'; END IF;
    UPDATE iam.otp_challenges SET session_issued_at = now() WHERE id = p_challenge;
    UPDATE iam.persons SET phone_token = p_new_token, phone_verified_at = now(), updated_at = now(), version = version + 1
    WHERE id = p_person;
    UPDATE iam.person_vault SET phone_enc = p_new_phone_enc, updated_at = now() WHERE person_id = p_person;
    PERFORM iam.revoke_all_sessions_internal(p_person, 'phone_changed');
    RETURN 'ok';
END $$;

-- Session liveness, asked on EVERY authenticated request by the SessionStore. Revocation is immediate: the check is a
-- row lookup, not a token claim. The elevation sweep runs here too, so an expired privilege revokes its
-- MFA-elevated sessions before the request that notices it is served.
CREATE FUNCTION iam.session_is_active(p_session uuid, p_person uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
BEGIN
    PERFORM iam.sweep_person(p_person);
    RETURN EXISTS (SELECT 1 FROM iam.auth_sessions s JOIN iam.persons p ON p.id = s.person_id
                   WHERE s.id = p_session AND s.person_id = p_person AND s.revoked_at IS NULL
                     AND s.expires_at > now() AND p.status = 'active');
END $$;

REVOKE ALL ON FUNCTION iam.sweep_person(uuid), iam.sweep_expired_grants(), iam.effective_grants(uuid),
    iam.access_overview(uuid), iam.locate_membership(uuid), iam.society_people(uuid[]), iam.person_profile(uuid),
    iam.update_profile(uuid, text, text), iam.vault_get(uuid), iam.vault_put(uuid, text, text),
    iam.change_phone(uuid, uuid, text, text), iam.session_is_active(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.effective_grants(uuid), iam.access_overview(uuid), iam.locate_membership(uuid),
    iam.society_people(uuid[]), iam.person_profile(uuid), iam.update_profile(uuid, text, text), iam.vault_get(uuid),
    iam.vault_put(uuid, text, text), iam.change_phone(uuid, uuid, text, text), iam.session_is_active(uuid, uuid)
    TO dwaar_app;
GRANT EXECUTE ON FUNCTION iam.sweep_expired_grants() TO dwaar_worker, dwaar_app;
