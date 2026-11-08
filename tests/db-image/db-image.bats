#!/usr/bin/env bats

setup() {
  export ROOT_DIR="$BATS_TEST_DIRNAME/../.."
  export WORK_DIR="$BATS_TEST_TMPDIR/work"
  mkdir -p "$WORK_DIR"
  cp "$ROOT_DIR"/examples/drupal-db-image/*.sh "$WORK_DIR/"
  cat > "$WORK_DIR/raw.sql" <<'SQL'
CREATE TABLE users_field_data (uid INT, name VARCHAR(60), mail VARCHAR(254), init VARCHAR(254), pass VARCHAR(255), status INT);
INSERT INTO users_field_data VALUES (0,'','','','',0), (1,'Alice','alice@example.com','alice@example.com','hash',1);
CREATE TABLE config (name VARCHAR(60));
CREATE TABLE key_value (name VARCHAR(60));
CREATE TABLE sessions (sid VARCHAR(60));
INSERT INTO sessions VALUES ('sensitive');
CREATE TABLE site_private (secret VARCHAR(60));
INSERT INTO site_private VALUES ('secret');
SELECT 'SYNTHETIC_SELECT_SECRET';
SQL
  gzip -c "$WORK_DIR/raw.sql" > "$WORK_DIR/raw.sql.gz"
}

@test "baseline and project hooks sanitise then verify a fresh restore" {
  cat > "$WORK_DIR/site-sanitize.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
docker exec "$1" mariadb -uroot -ptemporary-local-only drupal -e 'TRUNCATE TABLE site_private'
SH
  cat > "$WORK_DIR/site-verify.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
count=$(docker exec "$1" mariadb -uroot -ptemporary-local-only --skip-column-names drupal -e 'SELECT COUNT(*) FROM site_private')
[[ "$count" == 0 ]]
SH
  chmod +x "$WORK_DIR/site-sanitize.sh" "$WORK_DIR/site-verify.sh"
  run "$WORK_DIR/sanitize.sh" "$WORK_DIR/raw.sql.gz" "$WORK_DIR/clean.sql.gz"
  if [ "$status" -ne 0 ]; then echo "$output"; fi
  [ "$status" -eq 0 ]
  [[ "$output" != *'SYNTHETIC_SELECT_SECRET'* ]]
  run "$WORK_DIR/verify.sh" "$WORK_DIR/clean.sql.gz"
  if [ "$status" -ne 0 ]; then echo "$output"; fi
  [ "$status" -eq 0 ]
  run "$WORK_DIR/verify.sh" "$WORK_DIR/raw.sql.gz"
  [ "$status" -ne 0 ]
}

@test "unconfigured site hook fails closed" {
  run "$WORK_DIR/sanitize.sh" "$WORK_DIR/raw.sql.gz" "$WORK_DIR/clean.sql.gz"
  [ "$status" -ne 0 ]
  [ ! -s "$WORK_DIR/clean.sql.gz" ]
}

@test "failed import never prints source values to logs" {
  printf "INSERT INTO missing_table VALUES ('SYNTHETIC_PRIVATE_EMAIL@example.invalid');\n" | gzip -c > "$WORK_DIR/bad.sql.gz"
  run "$WORK_DIR/sanitize.sh" "$WORK_DIR/bad.sql.gz" "$WORK_DIR/clean.sql.gz"
  [ "$status" -ne 0 ]
  [[ "$output" == *'Database import failed'* ]]
  [[ "$output" != *'SYNTHETIC_PRIVATE_EMAIL'* ]]
  [ ! -s "$WORK_DIR/clean.sql.gz" ]
}

@test "Platform export passes context, produces gzip and fails on CLI errors" {
  mkdir -p "$WORK_DIR/bin"
  cat > "$WORK_DIR/bin/platform" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "${PLATFORMSH_CLI_TOKEN:-}" == test-secret ]]
[[ "$1" == db:dump ]]
shift
while (($#)); do
  if [[ "$1" == --file ]]; then printf 'SELECT 1;' | gzip -c > "$2"; exit 0; fi
  shift
done
exit 1
SH
  chmod +x "$WORK_DIR/bin/platform"
  export PATH="$WORK_DIR/bin:$PATH" PLATFORMSH_CLI_TOKEN=test-secret PLATFORM_PROJECT_ID=test-project PLATFORM_ENVIRONMENT=test
  run "$WORK_DIR/export-platform.sh" "$WORK_DIR/platform.sql.gz"
  [ "$status" -eq 0 ]
  gzip -t "$WORK_DIR/platform.sql.gz"
  printf '#!/usr/bin/env bash\nexit 7\n' > "$WORK_DIR/bin/platform"
  run "$WORK_DIR/export-platform.sh" "$WORK_DIR/fail.sql.gz"
  [ "$status" -ne 0 ]
}

@test "Upsun uses its own token and executable" {
  mkdir -p "$WORK_DIR/bin"
  cat > "$WORK_DIR/bin/upsun" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "${UPSUN_CLI_TOKEN:-}" == upsun-secret ]]
[[ "$1" == db:dump ]]
while (($#)); do
  if [[ "$1" == --file ]]; then printf 'SELECT 1;' | gzip -c > "$2"; exit 0; fi
  shift
done
exit 1
SH
  chmod +x "$WORK_DIR/bin/upsun"
  export PATH="$WORK_DIR/bin:$PATH" DB_EXPORT_SOURCE=upsun UPSUN_CLI_TOKEN=upsun-secret PLATFORM_PROJECT_ID=test-project PLATFORM_ENVIRONMENT=test
  run "$WORK_DIR/export-platform.sh" "$WORK_DIR/upsun.sql.gz"
  [ "$status" -eq 0 ]
  gzip -t "$WORK_DIR/upsun.sql.gz"
}

@test "Quant download accepts gzip or SQL and rejects non-HTTPS" {
  mkdir -p "$WORK_DIR/bin"
  cat > "$WORK_DIR/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
while (($#)); do
  if [[ "$1" == --output ]]; then cp "$QUANT_FIXTURE" "$2"; exit 0; fi
  shift
done
exit 1
SH
  chmod +x "$WORK_DIR/bin/curl"
  export PATH="$WORK_DIR/bin:$PATH" BACKUP_URL=https://example.invalid/signed QUANT_FIXTURE="$WORK_DIR/raw.sql.gz"
  run "$WORK_DIR/export-quant.sh" "$WORK_DIR/quant-gzip.sql.gz"
  [ "$status" -eq 0 ]
  gzip -t "$WORK_DIR/quant-gzip.sql.gz"
  export QUANT_FIXTURE="$WORK_DIR/raw.sql"
  run "$WORK_DIR/export-quant.sh" "$WORK_DIR/quant-plain.sql.gz"
  [ "$status" -eq 0 ]
  gzip -t "$WORK_DIR/quant-plain.sql.gz"
  export BACKUP_URL=http://example.invalid/signed
  run "$WORK_DIR/export-quant.sh" "$WORK_DIR/refused.sql.gz"
  [ "$status" -ne 0 ]
}
