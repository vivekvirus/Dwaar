-- Dwaar database roles. Idempotent; safe to re-run (it also re-applies attributes and passwords).
--
-- Run as a PostgreSQL superuser, once per cluster, with passwords supplied as psql variables:
--   psql -X -v ON_ERROR_STOP=1 -v owner_pw=... -v app_pw=... -v worker_pw=... -f bootstrap_roles.sql
--
-- dwaar_owner  owns every schema object and runs migrations (never used by the API at runtime)
-- dwaar_app    the API role: NOSUPERUSER NOBYPASSRLS NOCREATEDB, no DDL, table grants come from
--              each migration (no UPDATE/DELETE on append-only tables)
-- dwaar_worker background jobs: narrowly granted, sets per-society context for society data
--
-- Roles are cluster-wide. Database-level grants live in create_database.sql.

\set ON_ERROR_STOP on
SET client_min_messages = warning;

SELECT format(
    'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT',
    r.name)
FROM (VALUES ('dwaar_owner'), ('dwaar_app'), ('dwaar_worker')) AS r(name)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r.name)
\gexec

-- Re-assert the attributes on every run so drift is corrected, not preserved.
ALTER ROLE dwaar_owner  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE dwaar_app    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE dwaar_worker NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

SELECT format('ALTER ROLE dwaar_owner  PASSWORD %L', :'owner_pw')  \gexec
SELECT format('ALTER ROLE dwaar_app    PASSWORD %L', :'app_pw')    \gexec
SELECT format('ALTER ROLE dwaar_worker PASSWORD %L', :'worker_pw') \gexec

-- The app and worker roles must never be able to become the owner (no-op unless drifted).
SELECT format('REVOKE dwaar_owner FROM %I', r)
FROM unnest(ARRAY['dwaar_app', 'dwaar_worker']) AS r
WHERE pg_has_role(r, 'dwaar_owner', 'MEMBER')
\gexec
