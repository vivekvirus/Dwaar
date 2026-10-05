-- 0007 platform core: Postgres token bucket for OTP and API rate limiting.
-- REQ: IAM-06 (OTP rate limits and abuse protection), ARCH-05 (rate budgets), PRD 12.2 (429 with retry info).
-- Keys are opaque strings chosen by the caller, for example 'otp:phone:<keyed-hash>' or
-- 'api:<society-token>:<route>'. Never put raw phone numbers or tokens in a key.
-- No society_id column: buckets are platform-level counters; there is nothing tenant-readable in them.
CREATE TABLE rate_limit_buckets (
    key text PRIMARY KEY CHECK (char_length(key) BETWEEN 1 AND 200),
    tokens double precision NOT NULL CHECK (tokens >= 0),
    updated_at timestamptz NOT NULL
);
CREATE INDEX rate_limit_buckets_updated_idx ON rate_limit_buckets (updated_at);

REVOKE ALL ON TABLE rate_limit_buckets FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE rate_limit_buckets TO dwaar_app, dwaar_worker;

-- dwaar_rate_limit_take: refill by elapsed time, take p_cost tokens if available. A denied attempt does not
-- burn tokens. The row lock serialises concurrent callers for the same key.
CREATE FUNCTION dwaar_rate_limit_take(
    p_key text,
    p_capacity integer,
    p_refill_per_second double precision,
    p_cost integer DEFAULT 1
) RETURNS TABLE (allowed boolean, remaining double precision, retry_after_ms integer)
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_now timestamptz := clock_timestamp();
    v_tokens double precision;
    v_updated timestamptz;
    v_allowed boolean;
    v_retry integer := 0;
BEGIN
    IF p_capacity < 1 OR p_refill_per_second <= 0 OR p_cost < 1 OR p_cost > p_capacity THEN
        RAISE EXCEPTION 'dwaar_rate_limit_take: invalid bucket parameters';
    END IF;
    INSERT INTO rate_limit_buckets (key, tokens, updated_at)
    VALUES (p_key, p_capacity, v_now)
    ON CONFLICT (key) DO NOTHING;

    SELECT b.tokens, b.updated_at INTO v_tokens, v_updated
    FROM rate_limit_buckets b WHERE b.key = p_key FOR UPDATE;

    v_tokens := least(p_capacity::double precision,
                      v_tokens + greatest(0, extract(epoch FROM (v_now - v_updated))) * p_refill_per_second);
    IF v_tokens >= p_cost THEN
        v_tokens := v_tokens - p_cost;
        v_allowed := true;
    ELSE
        v_allowed := false;
        v_retry := ceil((p_cost - v_tokens) / p_refill_per_second * 1000)::integer;
    END IF;
    UPDATE rate_limit_buckets b SET tokens = v_tokens, updated_at = v_now WHERE b.key = p_key;
    RETURN QUERY SELECT v_allowed, v_tokens, v_retry;
END
$$;

REVOKE ALL ON FUNCTION dwaar_rate_limit_take(text, integer, double precision, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dwaar_rate_limit_take(text, integer, double precision, integer) TO dwaar_app, dwaar_worker;
