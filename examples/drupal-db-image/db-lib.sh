#!/usr/bin/env bash
# Shared helpers for the disposable database used by sanitise.sh and verify.sh.
set -euo pipefail
DB_IMAGE="${DB_IMAGE:-mariadb:11.4}"
DB_CONTAINER=""
cleanup_db() {
  if [[ -n "$DB_CONTAINER" ]]; then docker rm -fv "$DB_CONTAINER" >/dev/null 2>&1 || true; fi
}
trap cleanup_db EXIT
start_db() {
  local name
  name="db-snapshot-${GITHUB_RUN_ID:-local}-$$-${RANDOM}"
  DB_CONTAINER="$name"
  # No published ports, no network, anonymous data volume removed on exit.
  docker run --rm -d --name "$DB_CONTAINER" --network none \
    -e MARIADB_ROOT_PASSWORD=temporary-local-only -e MARIADB_DATABASE=drupal \
    "$DB_IMAGE" >/dev/null
  local attempt
  for ((attempt=1; attempt<=90; attempt++)); do
    if docker exec "$DB_CONTAINER" mariadb -uroot -ptemporary-local-only drupal -e 'SELECT 1' >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo 'Disposable database failed to start.' >&2
  return 1
}
db_sql() { docker exec -i "$DB_CONTAINER" mariadb -uroot -ptemporary-local-only drupal "$@"; }
db_query() { db_sql --batch --skip-column-names -e "$1"; }
import_dump() {
  gzip -t "$1"
  # MariaDB can echo rejected SQL, and dumps can contain SELECT statements.
  # Never let source data reach the CI log, including on import failures.
  if ! gzip -dc "$1" 2>/dev/null | db_sql >/dev/null 2>&1; then
    echo 'Database import failed; inspect only in an approved private environment.' >&2
    return 1
  fi
}
require_tables() {
  local count
  count=$(db_query "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name IN ('users_field_data','config','key_value')")
  [[ "$count" == 3 ]] || { echo 'Required Drupal tables are missing.' >&2; return 1; }
}
