-- 0001 platform core: extensions.
-- REQ: ADR-0002 (trusted extensions only). pgvector is intentionally absent (M2 AI retrieval).
-- infra/db/create_database.sql already creates these as a superuser; IF NOT EXISTS keeps this
-- migration valid on managed databases where only the database owner may create trusted extensions.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gist;
