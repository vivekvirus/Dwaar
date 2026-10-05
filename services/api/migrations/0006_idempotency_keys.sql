-- 0006 platform core: idempotency_keys.
-- REQ: INV-02 (retries cannot duplicate), PRD 7.4 / 12 (Idempotency-Key bound to actor, society, endpoint
--      and request hash; same key + different payload => 409 duplicate_payload_mismatch).
--
-- The claim row is written in the SAME transaction as the domain change and the stored response
-- (dwaar_api.core.idempotency), so a crash leaves no half-claimed key: either the whole request
-- committed and the key replays its response, or nothing exists. 'in_progress' therefore only exists
-- inside the owning transaction; concurrent identical requests block on the unique index and then replay.
CREATE TABLE idempotency_keys (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    society_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    key text NOT NULL CHECK (char_length(key) BETWEEN 8 AND 128),
    endpoint text NOT NULL CHECK (char_length(endpoint) BETWEEN 1 AND 300),
    request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
    state text NOT NULL DEFAULT 'in_progress' CHECK (state IN ('in_progress', 'completed')),
    response_status integer CHECK (response_status BETWEEN 100 AND 599),
    response_body jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    expires_at timestamptz NOT NULL,
    CONSTRAINT idempotency_keys_scope_key UNIQUE (society_id, actor_id, key),
    CONSTRAINT idempotency_keys_completed_has_response CHECK (
        state <> 'completed' OR (response_status IS NOT NULL AND response_body IS NOT NULL AND completed_at IS NOT NULL))
);
CREATE INDEX idempotency_keys_expiry_idx ON idempotency_keys (expires_at);

SELECT dwaar_enable_society_rls('idempotency_keys', 'SELECT, INSERT, UPDATE', 'SELECT, DELETE');

-- Expired-key cleanup is a platform job that runs across societies: worker only, expired rows only.
CREATE POLICY idempotency_keys_expired_select ON idempotency_keys FOR SELECT TO dwaar_worker
    USING (expires_at < now());
CREATE POLICY idempotency_keys_expired_delete ON idempotency_keys FOR DELETE TO dwaar_worker
    USING (expires_at < now());

COMMENT ON TABLE idempotency_keys IS 'Stored canonical responses for Idempotency-Key replay; short retention (expires_at).';
