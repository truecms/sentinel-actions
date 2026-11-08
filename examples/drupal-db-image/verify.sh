#!/usr/bin/env bash
# Usage: verify.sh sanitized.sql.gz. Restores a fresh isolated DB and checks it.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=examples/drupal-db-image/db-lib.sh
source "$script_dir/db-lib.sh"
[[ $# == 1 && -s "$1" ]] || { echo 'Expected a sanitised dump.' >&2; exit 1; }
site_hook="$script_dir/site-verify.sh"
[[ -x "$site_hook" ]] || { echo 'Missing executable site-verify.sh; site-specific checks are required.' >&2; exit 1; }
start_db
import_dump "$1"
require_tables
bad=$(db_query "SELECT COUNT(*) FROM users_field_data WHERE NOT (status <=> 0) OR NOT (pass <=> '!disabled!') OR (uid > 0 AND (NOT (name <=> CONCAT('user_',uid)) OR NOT (mail <=> CONCAT('user+',uid,'@example.invalid')) OR NOT (init <=> CONCAT('user+',uid,'@example.invalid')))) OR (uid=0 AND (NOT (name <=> '') OR NOT (mail <=> '') OR NOT (init <=> '')))")
[[ "$bad" == 0 ]] || { echo 'Baseline user sanitisation check failed.' >&2; exit 1; }
tables=$(db_query "SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND (LEFT(table_name,6)='cache_' OR table_name IN ('cachetags','sessions','watchdog','dblog','batch','flood','queue','semaphore','key_value_expire'))")
while IFS= read -r table; do
  [[ -z "$table" ]] && continue
  [[ "$table" =~ ^[a-zA-Z0-9_]+$ ]] || { echo 'Unsafe table name.' >&2; exit 1; }
  count=$(db_query "SELECT COUNT(*) FROM \`$table\`")
  [[ "$count" == 0 ]] || { echo "Runtime table $table is not empty." >&2; exit 1; }
done <<< "$tables"
if ! "$site_hook" "$DB_CONTAINER" >/dev/null 2>&1; then
  echo 'Site-specific verification failed.' >&2
  exit 1
fi
