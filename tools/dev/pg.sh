#!/usr/bin/env bash
# Persistent local PostgreSQL 16 dev cluster under .local/pg (git-ignored).
#
#   tools/dev/pg.sh up        init (first time) + start + roles + database   (make db-up)
#   tools/dev/pg.sh down      stop                                           (make db-down)
#   tools/dev/pg.sh reset     drop and recreate the dev database (empty)     (make db-reset)
#   tools/dev/pg.sh status | psql [args] | url [owner|app|worker|admin] | logs | destroy
#
# Port: DWAAR_PG_PORT (default 55432). Auth: trust on 127.0.0.1 only. When run as root the
# server runs as the `postgres` OS user via runuser (PostgreSQL refuses to run as root).
# Data is NOT crash-safe (fsync off): this is a disposable development database.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Merge .env.example < .env < environment (stdlib only, no venv needed).
eval "$(python3 "$ROOT/tools/dev/devenv.py" shell)"

PORT="${DWAAR_PG_PORT:-55432}"
DBNAME="${DWAAR_DB_NAME:-dwaar}"
PGROOT="${DWAAR_PG_ROOT:-$ROOT/.local/pg}"
DATA="$PGROOT/data"
RUN="$PGROOT/run"
LOGDIR="$PGROOT/log"
LOGFILE="$LOGDIR/postgres.log"

die() { echo "pg.sh: $*" >&2; exit 1; }

pg_bin_dir() {
  if [ -n "${DWAAR_PG_BIN:-}" ]; then echo "$DWAAR_PG_BIN"; return; fi
  local d
  for d in /usr/lib/postgresql/16/bin $(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -rV); do
    [ -x "$d/initdb" ] && { echo "$d"; return; }
  done
  command -v initdb >/dev/null 2>&1 && { dirname "$(command -v initdb)"; return; }
  die "PostgreSQL binaries not found (set DWAAR_PG_BIN)"
}
BIN="$(pg_bin_dir)"
PSQL="$BIN/psql"; [ -x "$PSQL" ] || PSQL="$(command -v psql || true)"
[ -n "$PSQL" ] || die "psql not found"

as_pg() {
  if [ "$(id -u)" = "0" ]; then
    command -v runuser >/dev/null || die "running as root requires runuser"
    runuser -u postgres -- "$@"
  else
    "$@"
  fi
}

admin_psql() { "$PSQL" -X -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$PORT" -U postgres "$@"; }

is_running() { as_pg "$BIN/pg_ctl" -D "$DATA" status >/dev/null 2>&1; }

init_cluster() {
  [ -f "$DATA/PG_VERSION" ] && return 0
  echo "initialising cluster in $PGROOT (port $PORT)"
  mkdir -p "$PGROOT"; chmod 755 "$PGROOT"
  mkdir -p "$DATA" "$RUN" "$LOGDIR"
  if [ "$(id -u)" = "0" ]; then chown postgres:postgres "$DATA" "$RUN" "$LOGDIR"; fi
  chmod 700 "$DATA"
  as_pg "$BIN/initdb" -D "$DATA" -A trust -U postgres -E UTF8 --locale=C.UTF-8 --no-sync >/dev/null \
    || as_pg "$BIN/initdb" -D "$DATA" -A trust -U postgres -E UTF8 --no-locale --no-sync >/dev/null \
    || die "initdb failed"
}

start_cluster() {
  if is_running; then echo "already running on port $PORT"; return 0; fi
  as_pg "$BIN/pg_ctl" -D "$DATA" -l "$LOGFILE" -w -t 60 \
    -o "-p $PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories=$RUN -c fsync=off -c synchronous_commit=off -c full_page_writes=off -c timezone=UTC -c log_timezone=UTC" \
    start >/dev/null </dev/null || { tail -n 20 "$LOGFILE" >&2 || true; die "pg_ctl start failed"; }
}

provision() {
  admin_psql -d postgres \
    -v owner_pw="${DWAAR_DB_OWNER_PASSWORD:?DWAAR_DB_OWNER_PASSWORD not set}" \
    -v app_pw="${DWAAR_DB_APP_PASSWORD:?DWAAR_DB_APP_PASSWORD not set}" \
    -v worker_pw="${DWAAR_DB_WORKER_PASSWORD:?DWAAR_DB_WORKER_PASSWORD not set}" \
    -f "$ROOT/infra/db/bootstrap_roles.sql"
  admin_psql -d postgres -v dbname="$DBNAME" -f "$ROOT/infra/db/create_database.sql"
}

url() {
  case "${1:-owner}" in
    owner)  echo "postgresql://dwaar_owner:${DWAAR_DB_OWNER_PASSWORD}@127.0.0.1:$PORT/$DBNAME" ;;
    app)    echo "postgresql://dwaar_app:${DWAAR_DB_APP_PASSWORD}@127.0.0.1:$PORT/$DBNAME" ;;
    worker) echo "postgresql://dwaar_worker:${DWAAR_DB_WORKER_PASSWORD}@127.0.0.1:$PORT/$DBNAME" ;;
    admin)  echo "postgresql://postgres@127.0.0.1:$PORT/postgres" ;;
    *) die "url: owner|app|worker|admin" ;;
  esac
}

cmd="${1:-help}"; shift || true
case "$cmd" in
  up)
    init_cluster; start_cluster; provision
    echo "PostgreSQL ready: $(url app | sed -E 's#(://[^:]+):[^@]*@#\1:***@#')"
    ;;
  down)
    if [ -f "$DATA/PG_VERSION" ] && is_running; then
      as_pg "$BIN/pg_ctl" -D "$DATA" -m fast -w -t 30 stop >/dev/null </dev/null && echo "stopped"
    else
      echo "not running"
    fi
    ;;
  status)
    if [ -f "$DATA/PG_VERSION" ] && is_running; then echo "running on port $PORT"; else echo "stopped"; exit 3; fi
    ;;
  reset)
    init_cluster; start_cluster
    admin_psql -d postgres -v dbname="$DBNAME" <<'SQL'
\set ON_ERROR_STOP on
SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', :'dbname') \gexec
SQL
    provision
    echo "database $DBNAME recreated (empty). Run: make migrate"
    ;;
  psql)
    admin_psql -d "${PGDATABASE:-$DBNAME}" "$@"
    ;;
  url) url "${1:-owner}" ;;
  logs) tail -n "${1:-50}" "$LOGFILE" ;;
  destroy)
    if [ -f "$DATA/PG_VERSION" ] && is_running; then
      as_pg "$BIN/pg_ctl" -D "$DATA" -m immediate -w -t 30 stop >/dev/null </dev/null || true
    fi
    rm -rf "$PGROOT"; echo "removed $PGROOT"
    ;;
  *)
    sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    [ "$cmd" = "help" ] || exit 2
    ;;
esac
