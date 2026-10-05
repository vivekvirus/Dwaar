-- 0132 identity: sessions/devices, rotating refresh tokens with reuse detection, MFA factors (schema "iam").
-- REQ: IAM-08 (short-lived access tokens, rotating refresh tokens, device and session list, revocation),
--      IAM-03 (MFA for elevated roles), IAM-11 (a number change or recycle revokes old sessions), IAM-14.
--
-- auth_sessions is the server-side truth the SessionStore consults on EVERY request: revoking a row makes the
-- access token unusable at once, whatever its exp. A refresh token is single-use; presenting a used or revoked
-- one is theft evidence and revokes the whole session (the "family").
CREATE TABLE iam.auth_sessions (
    id uuid PRIMARY KEY,
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    device_id text NOT NULL CHECK (char_length(device_id) BETWEEN 1 AND 128),
    device_label text NOT NULL DEFAULT 'Unknown device' CHECK (char_length(device_label) BETWEEN 1 AND 120),
    platform text CHECK (platform IS NULL OR char_length(platform) <= 32),
    login_challenge_id uuid UNIQUE REFERENCES iam.otp_challenges (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    mfa_verified_at timestamptz,
    revoked_at timestamptz,
    revoked_reason text CHECK (revoked_reason IS NULL OR char_length(revoked_reason) <= 64)
);
CREATE INDEX auth_sessions_person_idx ON iam.auth_sessions (person_id) WHERE revoked_at IS NULL;

CREATE TABLE iam.refresh_tokens (
    id uuid PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES iam.auth_sessions (id),
    token_hash text NOT NULL CONSTRAINT refresh_tokens_hash_key UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    parent_id uuid REFERENCES iam.refresh_tokens (id),
    issued_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX refresh_tokens_session_idx ON iam.refresh_tokens (session_id);

CREATE TABLE iam.mfa_factors (
    id uuid PRIMARY KEY,
    person_id uuid NOT NULL REFERENCES iam.persons (id),
    kind text NOT NULL CHECK (kind IN ('totp')),
    secret_enc text NOT NULL,
    confirmed_at timestamptz,
    last_used_step bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE UNIQUE INDEX mfa_factors_one_live_idx ON iam.mfa_factors (person_id, kind) WHERE revoked_at IS NULL;
REVOKE ALL ON TABLE iam.auth_sessions, iam.refresh_tokens, iam.mfa_factors FROM PUBLIC, dwaar_app, dwaar_worker;

-- Internal helper (not executable by the runtime roles): revoke every live session of a person.
CREATE FUNCTION iam.revoke_all_sessions_internal(p_person uuid, p_reason text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
DECLARE v_n integer;
BEGIN
    UPDATE iam.refresh_tokens SET revoked_at = now()
    WHERE revoked_at IS NULL AND session_id IN (SELECT id FROM iam.auth_sessions WHERE person_id = p_person AND revoked_at IS NULL);
    UPDATE iam.auth_sessions SET revoked_at = now(), revoked_reason = p_reason
    WHERE person_id = p_person AND revoked_at IS NULL;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n;
END $$;
REVOKE ALL ON FUNCTION iam.revoke_all_sessions_internal(uuid, text) FROM PUBLIC;

-- Login: the person for a verified number.
--  * unknown number            -> new person, no memberships.
--  * known and recently used   -> that person.
--  * known but DORMANT longer than p_dormancy -> the number may have been recycled by the carrier (IAM-11): the old
--    person keeps their memberships but loses the number (token released, sessions revoked) and the new holder gets
--    a NEW person with nothing. Memberships are never inherited through a phone number.
CREATE FUNCTION iam.login_person(
    p_person_id uuid, p_phone_token text, p_phone_enc text, p_display_name text, p_dormancy interval)
RETURNS TABLE (person_id uuid, created boolean, recycled boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
#variable_conflict use_column
DECLARE v record; v_recycled boolean := false;
BEGIN
    SELECT p.id, p.phone_verified_at, p.status INTO v FROM iam.persons p WHERE p.phone_token = p_phone_token FOR UPDATE;
    IF FOUND THEN
        IF v.phone_verified_at IS NOT NULL AND v.phone_verified_at < now() - p_dormancy THEN
            UPDATE iam.persons SET phone_token = 'released:' || v.id::text, status = 'phone_released',
                   phone_released_at = now(), updated_at = now(), version = version + 1 WHERE id = v.id;
            v_recycled := true;
            
            PERFORM iam.revoke_all_sessions_internal(v.id, 'phone_recycled');
        ELSE
            UPDATE iam.persons SET phone_verified_at = now(), updated_at = now() WHERE id = v.id;
            RETURN QUERY SELECT v.id, false, false;
            RETURN;
        END IF;
    END IF;
    INSERT INTO iam.persons (id, display_name, phone_token, phone_verified_at)
    VALUES (p_person_id, left(coalesce(nullif(btrim(p_display_name), ''), 'Resident'), 120), p_phone_token, now());
    INSERT INTO iam.person_vault (person_id, phone_enc) VALUES (p_person_id, p_phone_enc);
    RETURN QUERY SELECT p_person_id, true, v_recycled;
END $$;
REVOKE ALL ON FUNCTION iam.login_person(uuid, text, text, text, interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.login_person(uuid, text, text, text, interval) TO dwaar_app;

-- Session creation needs PROOF of a just-consumed login OTP for THIS person's number: nobody can mint a session for an
-- arbitrary person id, even with SQL access as dwaar_app, without a live consumed challenge.
CREATE FUNCTION iam.session_create(
    p_session uuid, p_person uuid, p_challenge uuid, p_device_id text, p_label text, p_platform text,
    p_refresh_id uuid, p_refresh_hash text, p_ttl_seconds integer, p_max_sessions integer)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
DECLARE v_ok boolean;
BEGIN
    SELECT true INTO v_ok FROM iam.otp_challenges c JOIN iam.persons p ON p.phone_token = c.phone_token
    WHERE c.id = p_challenge AND c.purpose = 'login' AND c.consumed_at > now() - interval '2 minutes'
      AND c.session_issued_at IS NULL AND p.id = p_person AND p.status = 'active' FOR UPDATE OF c;
    IF v_ok IS NOT TRUE THEN
        RAISE EXCEPTION 'session_create: no valid login proof' USING ERRCODE = '42501';
    END IF;
    UPDATE iam.otp_challenges SET session_issued_at = now() WHERE id = p_challenge;
    INSERT INTO iam.auth_sessions (id, person_id, device_id, device_label, platform, login_challenge_id, expires_at)
    VALUES (p_session, p_person, p_device_id, p_label, p_platform, p_challenge, now() + make_interval(secs => p_ttl_seconds));
    INSERT INTO iam.refresh_tokens (id, session_id, token_hash, expires_at)
    VALUES (p_refresh_id, p_session, p_refresh_hash, now() + make_interval(secs => p_ttl_seconds));
    -- bounded device list: the oldest sessions beyond the cap are revoked
    UPDATE iam.auth_sessions SET revoked_at = now(), revoked_reason = 'device_limit'
    WHERE id IN (SELECT id FROM iam.auth_sessions WHERE person_id = p_person AND revoked_at IS NULL
                 ORDER BY last_seen_at DESC OFFSET p_max_sessions);
END $$;

-- Rotation. outcome: ok | invalid | reuse. A used or revoked token = reuse: the whole session is revoked and the
-- caller must treat it as a possible theft. The revocation commits even though the API then answers 401.
CREATE FUNCTION iam.session_rotate(p_old_hash text, p_new_id uuid, p_new_hash text, p_ttl_seconds integer)
RETURNS TABLE (outcome text, session_id uuid, person_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
#variable_conflict use_column
DECLARE v record;
BEGIN
    SELECT t.id, t.session_id, t.used_at, t.revoked_at, t.expires_at, s.person_id, s.revoked_at AS s_revoked,
           s.expires_at AS s_expires, p.status
    INTO v FROM iam.refresh_tokens t JOIN iam.auth_sessions s ON s.id = t.session_id
         JOIN iam.persons p ON p.id = s.person_id
    WHERE t.token_hash = p_old_hash FOR UPDATE OF t;
    IF NOT FOUND THEN RETURN QUERY SELECT 'invalid'::text, NULL::uuid, NULL::uuid; RETURN; END IF;
    IF v.s_revoked IS NOT NULL OR v.status <> 'active' THEN
        RETURN QUERY SELECT 'invalid'::text, NULL::uuid, NULL::uuid; RETURN;
    END IF;
    IF v.used_at IS NOT NULL OR v.revoked_at IS NOT NULL THEN
        UPDATE iam.refresh_tokens SET revoked_at = now() WHERE session_id = v.session_id AND revoked_at IS NULL;
        UPDATE iam.auth_sessions SET revoked_at = now(), revoked_reason = 'refresh_reuse' WHERE id = v.session_id;
        RETURN QUERY SELECT 'reuse'::text, v.session_id, v.person_id; RETURN;
    END IF;
    IF v.expires_at <= now() OR v.s_expires <= now() THEN
        RETURN QUERY SELECT 'invalid'::text, NULL::uuid, NULL::uuid; RETURN;
    END IF;
    UPDATE iam.refresh_tokens SET used_at = now() WHERE id = v.id;
    INSERT INTO iam.refresh_tokens (id, session_id, token_hash, parent_id, expires_at)
    VALUES (p_new_id, v.session_id, p_new_hash, v.id, least(v.s_expires, now() + make_interval(secs => p_ttl_seconds)));
    UPDATE iam.auth_sessions SET last_seen_at = now() WHERE id = v.session_id;
    RETURN QUERY SELECT 'ok'::text, v.session_id, v.person_id;
END $$;

-- Device/session list of the authenticated person (the context person only).
CREATE FUNCTION iam.session_list(p_person uuid)
RETURNS TABLE (id uuid, device_id text, device_label text, platform text, created_at timestamptz,
               last_seen_at timestamptz, expires_at timestamptz, mfa_verified_at timestamptz)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, iam, public AS $$
    SELECT s.id, s.device_id, s.device_label, s.platform, s.created_at, s.last_seen_at, s.expires_at, s.mfa_verified_at
    FROM iam.auth_sessions s
    WHERE s.person_id = p_person AND p_person = iam.ctx_person() AND s.revoked_at IS NULL AND s.expires_at > now()
    ORDER BY s.last_seen_at DESC
$$;

CREATE FUNCTION iam.session_revoke(p_person uuid, p_session uuid, p_reason text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
BEGIN
    IF p_person IS DISTINCT FROM iam.ctx_person() THEN RETURN false; END IF;
    UPDATE iam.refresh_tokens SET revoked_at = now() WHERE session_id = p_session AND revoked_at IS NULL
        AND session_id IN (SELECT id FROM iam.auth_sessions WHERE person_id = p_person);
    UPDATE iam.auth_sessions SET revoked_at = now(), revoked_reason = left(p_reason, 64)
    WHERE id = p_session AND person_id = p_person AND revoked_at IS NULL;
    RETURN FOUND;
END $$;

CREATE FUNCTION iam.session_revoke_others(p_person uuid, p_keep uuid, p_reason text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
DECLARE v_n integer;
BEGIN
    IF p_person IS DISTINCT FROM iam.ctx_person() THEN RETURN 0; END IF;
    UPDATE iam.refresh_tokens SET revoked_at = now() WHERE revoked_at IS NULL
        AND session_id IN (SELECT id FROM iam.auth_sessions WHERE person_id = p_person AND id <> p_keep AND revoked_at IS NULL);
    UPDATE iam.auth_sessions SET revoked_at = now(), revoked_reason = left(p_reason, 64)
    WHERE person_id = p_person AND id <> p_keep AND revoked_at IS NULL;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n;
END $$;

-- MFA (TOTP) factor handling: the secret is stored encrypted; only the context person reaches it.
CREATE FUNCTION iam.mfa_enrol(p_person uuid, p_factor uuid, p_secret_enc text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
BEGIN
    IF p_person IS DISTINCT FROM iam.ctx_person() THEN RETURN false; END IF;
    IF EXISTS (SELECT 1 FROM iam.mfa_factors WHERE person_id = p_person AND kind = 'totp' AND revoked_at IS NULL
               AND confirmed_at IS NOT NULL) THEN
        RETURN false;   -- a confirmed factor is never silently replaced
    END IF;
    UPDATE iam.mfa_factors SET revoked_at = now() WHERE person_id = p_person AND kind = 'totp' AND revoked_at IS NULL;
    INSERT INTO iam.mfa_factors (id, person_id, kind, secret_enc) VALUES (p_factor, p_person, 'totp', p_secret_enc);
    RETURN true;
END $$;

CREATE FUNCTION iam.mfa_get(p_person uuid)
RETURNS TABLE (id uuid, secret_enc text, confirmed_at timestamptz, last_used_step bigint)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, iam, public AS $$
    SELECT f.id, f.secret_enc, f.confirmed_at, f.last_used_step FROM iam.mfa_factors f
    WHERE f.person_id = p_person AND p_person = iam.ctx_person() AND f.kind = 'totp' AND f.revoked_at IS NULL
$$;

-- Accept a TOTP step exactly once (replay of the same code, or an older one, is refused).
CREATE FUNCTION iam.mfa_use_step(p_person uuid, p_factor uuid, p_step bigint, p_confirm boolean) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
BEGIN
    IF p_person IS DISTINCT FROM iam.ctx_person() THEN RETURN false; END IF;
    UPDATE iam.mfa_factors SET last_used_step = p_step,
           confirmed_at = CASE WHEN p_confirm THEN coalesce(confirmed_at, now()) ELSE confirmed_at END
    WHERE id = p_factor AND person_id = p_person AND revoked_at IS NULL AND last_used_step < p_step
      AND (p_confirm OR confirmed_at IS NOT NULL);
    RETURN FOUND;
END $$;

CREATE FUNCTION iam.session_mark_mfa(p_person uuid, p_session uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
BEGIN
    IF p_person IS DISTINCT FROM iam.ctx_person() THEN RETURN false; END IF;
    UPDATE iam.auth_sessions SET mfa_verified_at = now()
    WHERE id = p_session AND person_id = p_person AND revoked_at IS NULL;
    RETURN FOUND;
END $$;

CREATE FUNCTION iam.session_mfa_fresh(p_person uuid, p_session uuid, p_ttl_seconds integer) RETURNS boolean
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, iam, public AS $$
    SELECT coalesce((SELECT s.mfa_verified_at > now() - make_interval(secs => p_ttl_seconds)
                     FROM iam.auth_sessions s
                     WHERE s.id = p_session AND s.person_id = p_person AND s.revoked_at IS NULL), false)
$$;

REVOKE ALL ON FUNCTION iam.session_create(uuid, uuid, uuid, text, text, text, uuid, text, integer, integer),
    iam.session_rotate(text, uuid, text, integer), iam.session_list(uuid), iam.session_revoke(uuid, uuid, text),
    iam.session_revoke_others(uuid, uuid, text), iam.mfa_enrol(uuid, uuid, text), iam.mfa_get(uuid),
    iam.mfa_use_step(uuid, uuid, bigint, boolean), iam.session_mark_mfa(uuid, uuid),
    iam.session_mfa_fresh(uuid, uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.session_create(uuid, uuid, uuid, text, text, text, uuid, text, integer, integer),
    iam.session_rotate(text, uuid, text, integer), iam.session_list(uuid), iam.session_revoke(uuid, uuid, text),
    iam.session_revoke_others(uuid, uuid, text), iam.mfa_enrol(uuid, uuid, text), iam.mfa_get(uuid),
    iam.mfa_use_step(uuid, uuid, bigint, boolean), iam.session_mark_mfa(uuid, uuid),
    iam.session_mfa_fresh(uuid, uuid, integer) TO dwaar_app;
