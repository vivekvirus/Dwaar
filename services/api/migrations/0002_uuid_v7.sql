-- 0002 platform core: uuid_generate_v7().
-- REQ: D-10 / PRD 7.4 (UUIDv7 identifiers). 48-bit unix-ms timestamp, version 7, RFC 4122 variant,
-- 74 random bits taken from gen_random_uuid() (a CSPRNG v4 uuid). Time-ordered to the millisecond;
-- ordering inside the same millisecond is random. Application code normally generates ids with
-- dwaar_common.ids.uuid7() (monotonic); this function is the database-side default.
CREATE FUNCTION uuid_generate_v7() RETURNS uuid
LANGUAGE sql VOLATILE PARALLEL SAFE
AS $$
    SELECT encode(
        set_bit(
            set_bit(
                overlay(
                    uuid_send(gen_random_uuid())
                    PLACING substring(int8send((extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3)
                    FROM 1 FOR 6
                ),
                52, 1),
            53, 1),
        'hex')::uuid
$$;

COMMENT ON FUNCTION uuid_generate_v7() IS 'UUIDv7 (unix-ms timestamp + random). Database-side default for id columns.';
