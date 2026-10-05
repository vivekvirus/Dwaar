-- 0131 identity: phone OTP challenges and simulated DLT delivery (schema "iam").
-- REQ: IAM-06 (phone OTP with rate limits, expiry and abuse protection, DLT-approved templates; OTP proves control
--      of a number, not ownership; plaintext OTPs never stored or logged), SEC-05 (enumeration protection).
--
-- * otp_challenges stores only a keyed HASH of the code (HMAC over phone token, challenge id and code) plus an
--   attempt counter and an expiry. The code itself is never stored here.
-- * otp_deliveries is the delivery queue (the "outbox message" of an unauthenticated flow: core outbox rows are
--   society-owned and an OTP request has no society). The message payload (recipient + code + DLT template
--   parameters) is envelope-ENCRYPTED, bound by AAD to the delivery id, and cleared as soon as the challenge is
--   consumed, superseded or expired. In the labelled simulator the payload is readable only by the dev-only
--   endpoint; a real SMS provider adapter is blocked-external (needs a DLT principal entity id + template ids).
CREATE TABLE iam.otp_challenges (
    id uuid PRIMARY KEY,
    phone_token text NOT NULL,
    purpose text NOT NULL CHECK (purpose IN ('login', 'phone_change')),
    person_id uuid REFERENCES iam.persons (id),     -- phone_change: the authenticated person asking
    code_hash text NOT NULL CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 10),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    session_issued_at timestamptz,
    superseded_at timestamptz,
    retention_class text NOT NULL DEFAULT 'CRED' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX otp_challenges_lookup_idx ON iam.otp_challenges (phone_token, purpose, created_at DESC);

CREATE TABLE iam.otp_deliveries (
    id uuid PRIMARY KEY,
    challenge_id uuid NOT NULL REFERENCES iam.otp_challenges (id),
    channel text NOT NULL DEFAULT 'sms' CHECK (channel IN ('sms')),
    template_id text NOT NULL CHECK (char_length(template_id) BETWEEN 1 AND 64),
    recipient_token text NOT NULL,
    payload_enc text,
    state text NOT NULL CHECK (state IN ('pending', 'simulated_sent', 'sent', 'failed', 'purged')),
    simulation boolean NOT NULL,
    retention_class text NOT NULL DEFAULT 'CRED' CHECK (retention_class ~ '^[A-Z][A-Z0-9]{1,15}$'),
    legal_hold_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz
);
CREATE INDEX otp_deliveries_recipient_idx ON iam.otp_deliveries (recipient_token, created_at DESC);
REVOKE ALL ON TABLE iam.otp_challenges, iam.otp_deliveries FROM PUBLIC, dwaar_app, dwaar_worker;

-- Clear the encrypted payload of every delivery whose challenge is consumed, superseded or expired.
CREATE FUNCTION iam.otp_purge_expired() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
DECLARE v_n integer;
BEGIN
    UPDATE iam.otp_deliveries d SET payload_enc = NULL, state = 'purged'
    FROM iam.otp_challenges c
    WHERE c.id = d.challenge_id AND d.payload_enc IS NOT NULL
      AND (c.consumed_at IS NOT NULL OR c.superseded_at IS NOT NULL OR c.expires_at <= now());
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n;
END $$;

CREATE FUNCTION iam.otp_issue(
    p_id uuid, p_phone_token text, p_purpose text, p_person uuid, p_code_hash text, p_ttl_seconds integer,
    p_max_attempts integer, p_delivery_id uuid, p_template text, p_payload_enc text, p_simulation boolean)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
BEGIN
    IF p_purpose = 'phone_change' AND (p_person IS NULL OR p_person IS DISTINCT FROM iam.ctx_person()) THEN
        RAISE EXCEPTION 'otp_issue: phone_change needs the authenticated person' USING ERRCODE = '42501';
    END IF;
    UPDATE iam.otp_challenges SET superseded_at = now()
    WHERE phone_token = p_phone_token AND purpose = p_purpose AND consumed_at IS NULL AND superseded_at IS NULL;
    PERFORM iam.otp_purge_expired();
    INSERT INTO iam.otp_challenges (id, phone_token, purpose, person_id, code_hash, max_attempts, expires_at)
    VALUES (p_id, p_phone_token, p_purpose, p_person, p_code_hash, p_max_attempts,
            now() + make_interval(secs => p_ttl_seconds));
    INSERT INTO iam.otp_deliveries (id, challenge_id, template_id, recipient_token, payload_enc, state, simulation)
    VALUES (p_delivery_id, p_id, p_template, p_phone_token, p_payload_enc,
            CASE WHEN p_simulation THEN 'simulated_sent' ELSE 'pending' END, p_simulation);
    RETURN p_id;
END $$;

-- One verification attempt: the counter moves BEFORE the comparison (the caller compares the hash), so a crash or a
-- parallel guess cannot buy extra tries. Status: ok | none | expired | locked.
CREATE FUNCTION iam.otp_attempt(p_phone_token text, p_purpose text)
RETURNS TABLE (challenge_id uuid, code_hash text, status text, person_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
#variable_conflict use_column
DECLARE c record;
BEGIN
    SELECT o.* INTO c FROM iam.otp_challenges o
    WHERE o.phone_token = p_phone_token AND o.purpose = p_purpose AND o.consumed_at IS NULL AND o.superseded_at IS NULL
    ORDER BY o.created_at DESC LIMIT 1 FOR UPDATE;
    IF NOT FOUND THEN RETURN QUERY SELECT NULL::uuid, ''::text, 'none'::text, NULL::uuid; RETURN; END IF;
    IF c.expires_at <= now() THEN RETURN QUERY SELECT c.id, ''::text, 'expired'::text, NULL::uuid; RETURN; END IF;
    IF c.attempts >= c.max_attempts THEN RETURN QUERY SELECT c.id, ''::text, 'locked'::text, NULL::uuid; RETURN; END IF;
    UPDATE iam.otp_challenges SET attempts = attempts + 1 WHERE id = c.id;
    RETURN QUERY SELECT c.id, c.code_hash, 'ok'::text, c.person_id;
END $$;

-- Atomic single use: the first caller wins, a replay of the same code finds nothing.
CREATE FUNCTION iam.otp_consume(p_challenge_id uuid)
RETURNS TABLE (phone_token text, purpose text, person_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, iam, public AS $$
#variable_conflict use_column
BEGIN
    RETURN QUERY
    UPDATE iam.otp_challenges o SET consumed_at = now()
    WHERE o.id = p_challenge_id AND o.consumed_at IS NULL AND o.superseded_at IS NULL AND o.expires_at > now()
    RETURNING o.phone_token, o.purpose, o.person_id;
    PERFORM iam.otp_purge_expired();
END $$;

-- Dev-only reader of the labelled simulator: returns the encrypted payload of the newest live delivery for a number.
-- The API only mounts the endpoint when simulators are allowed (local/test); the payload is ciphertext either way.
CREATE FUNCTION iam.dev_otp_latest(p_phone_token text)
RETURNS TABLE (delivery_id uuid, payload_enc text, template_id text, created_at timestamptz)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path = pg_catalog, iam, public AS $$
    SELECT d.id, d.payload_enc, d.template_id, d.created_at
    FROM iam.otp_deliveries d JOIN iam.otp_challenges c ON c.id = d.challenge_id
    WHERE d.recipient_token = p_phone_token AND d.simulation AND d.payload_enc IS NOT NULL
      AND c.consumed_at IS NULL AND c.superseded_at IS NULL AND c.expires_at > now()
    ORDER BY d.created_at DESC LIMIT 1
$$;

REVOKE ALL ON FUNCTION iam.otp_purge_expired(), iam.dev_otp_latest(text), iam.otp_consume(uuid),
    iam.otp_attempt(text, text),
    iam.otp_issue(uuid, text, text, uuid, text, integer, integer, uuid, text, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION iam.otp_purge_expired() TO dwaar_app, dwaar_worker;
GRANT EXECUTE ON FUNCTION iam.dev_otp_latest(text), iam.otp_consume(uuid), iam.otp_attempt(text, text),
    iam.otp_issue(uuid, text, text, uuid, text, integer, integer, uuid, text, text, boolean) TO dwaar_app;
GRANT EXECUTE ON FUNCTION iam.ensure_person(uuid, text, text, text) TO dwaar_app;
REVOKE ALL ON FUNCTION iam.ensure_person(uuid, text, text, text) FROM PUBLIC;
