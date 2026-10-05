#!/usr/bin/env bash
# Runs once when the postgres container initialises an empty data directory.
# Creates the Dwaar roles and database exactly as tools/dev/pg.sh does (same SQL files).
set -euo pipefail

psql -X -v ON_ERROR_STOP=1 --username postgres --dbname postgres \
  -v owner_pw="${DWAAR_DB_OWNER_PASSWORD:?}" \
  -v app_pw="${DWAAR_DB_APP_PASSWORD:?}" \
  -v worker_pw="${DWAAR_DB_WORKER_PASSWORD:?}" \
  -f /dwaar-db/bootstrap_roles.sql

psql -X -v ON_ERROR_STOP=1 --username postgres --dbname postgres \
  -v dbname="${DWAAR_DB_NAME:-dwaar}" \
  -f /dwaar-db/create_database.sql
