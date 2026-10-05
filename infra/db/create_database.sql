-- Create (if missing) and prepare one Dwaar database. Idempotent.
--
-- Run as a superuser AFTER bootstrap_roles.sql:
--   psql -X -v ON_ERROR_STOP=1 -v dbname=dwaar -f create_database.sql
--
-- Steps (the "DB-level grants pattern" used by dev, docker and the test harness):
--   1. database owned by dwaar_owner
--   2. PUBLIC loses all database privileges; only the three Dwaar roles may CONNECT
--   3. trusted extensions pgcrypto, pg_trgm, btree_gist created by the superuser here, so
--      migrations (run as dwaar_owner, a non-superuser) never need elevated rights
--   4. schema public: PUBLIC cannot CREATE; app and worker may USE it but not create objects
-- pgvector is NOT created here (not installed locally; M2 AI retrieval only).

\set ON_ERROR_STOP on
SET client_min_messages = warning;

SELECT format('CREATE DATABASE %I OWNER dwaar_owner ENCODING ''UTF8'' LC_COLLATE ''C'' LC_CTYPE ''C.UTF-8'' TEMPLATE template0', :'dbname')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'dbname')
\gexec

SELECT format('ALTER DATABASE %I OWNER TO dwaar_owner', :'dbname') \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'dbname') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO dwaar_owner, dwaar_app, dwaar_worker', :'dbname') \gexec

\connect :dbname
SET client_min_messages = warning;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gist;

ALTER SCHEMA public OWNER TO dwaar_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM dwaar_app, dwaar_worker;
GRANT USAGE ON SCHEMA public TO dwaar_owner, dwaar_app, dwaar_worker;
