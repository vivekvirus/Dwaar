-- 0010 platform core: the worker role may INSERT outbox rows (a background job is a writer of domain events too).
-- REQ: PRD 12.4 (a domain mutation, its audit row and its outbox row commit in ONE transaction: a job that mutates a society, such as the
--      edge policy publisher or the visits expiry sweep, must be able to write the outbox row of its own mutation), INV-01, DB-02.
--
-- Until now only dwaar_app could INSERT into outbox (0008, F08), so every job had to run as the API role. Narrow by construction:
--   * column-scoped like the API role: the delivery columns (published_at, attempts, next_attempt_at, last_error) are NOT insertable, an
--     event always starts undelivered;
--   * the society policy `dwaar_society_isolation` (FOR ALL, no role list) applies to dwaar_worker as well: an INSERT needs
--     app.society_id = the row's society_id, so a job writes into the society whose context it set and into no other, and without a
--     context it writes nothing;
--   * no UPDATE beyond the relay's delivery columns, no DELETE, no TRUNCATE (the history guard and 0005 stay as they are).
GRANT INSERT (event_id, schema_version, society_id, aggregate_type, aggregate_id, aggregate_version,
              event_type, occurred_at, actor_ref, correlation_id, causation_id, payload, payload_hash,
              retention_class)
    ON TABLE outbox TO dwaar_worker;
