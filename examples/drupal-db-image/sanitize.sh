#!/usr/bin/env bash
# Usage: sanitize.sh raw.sql.gz sanitized.sql.gz. Only touches a disposable DB.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=examples/drupal-db-image/db-lib.sh
source "$script_dir/db-lib.sh"
[[ $# == 2 && -s "$1" && "$1" != "$2" && ! -e "$2" && ! -L "$2" ]] || { echo 'Expected an input and a new output dump path.' >&2; exit 1; }
umask 077
set -o noclobber
site_hook="$script_dir/site-sanitize.sh"
[[ -x "$site_hook" ]] || { echo 'Missing executable site-sanitize.sh; site-specific scrubbing is required.' >&2; exit 1; }
start_db
import_dump "$1"
require_tables
# Lock accounts, remove identifying core fields and invalidate password hashes.
db_sql <<'SQL'
UPDATE users_field_data SET name=IF(uid=0,'',CONCAT('user_',uid)),
  mail=IF(uid=0,'',CONCAT('user+',uid,'@example.invalid')),
  init=IF(uid=0,'',CONCAT('user+',uid,'@example.invalid')),
  pass='!disabled!', status=0;
SQL
# Empty common ephemeral tables. Other tables and files require site-specific handling.
tables=$(db_query "SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND (LEFT(table_name,6)='cache_' OR table_name IN ('cachetags','sessions','watchdog','dblog','batch','flood','queue','semaphore','key_value_expire'))")
while IFS= read -r table; do
  [[ -z "$table" ]] && continue
  [[ "$table" =~ ^[a-zA-Z0-9_]+$ ]] || { echo 'Unsafe table name.' >&2; exit 1; }
  db_sql -e "TRUNCATE TABLE \`$table\`"
done <<< "$tables"
if ! "$site_hook" "$DB_CONTAINER" >/dev/null 2>&1; then
  echo 'Site-specific sanitisation failed.' >&2
  exit 1
fi
docker exec "$DB_CONTAINER" mariadb-dump -uroot -ptemporary-local-only --single-transaction --skip-add-locks drupal | gzip -c > "$2"
gzip -t "$2"
