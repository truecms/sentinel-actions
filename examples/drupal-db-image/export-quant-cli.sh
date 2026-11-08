#!/usr/bin/env bash
# Local, already-authenticated Quant CLI: download one specified completed backup.
# For unattended GitHub runs use the backup action in db-image-refresh.yml.
set -euo pipefail
: "${QUANT_ORGANIZATION:?}" "${QUANT_APPLICATION:?}" "${QUANT_ENVIRONMENT:?}" "${QUANT_BACKUP_ID:?}"
[[ $# == 1 && "$QUANT_BACKUP_ID" != latest && "$QUANT_BACKUP_ID" =~ ^[a-zA-Z0-9][a-zA-Z0-9._:-]*$ ]] || { echo 'Specify an output and exact backup ID.' >&2; exit 1; }
[[ ! -e "$1" && ! -L "$1" ]] || { echo 'Output already exists.' >&2; exit 1; }
command -v quant-cloud >/dev/null || { echo 'Quant Cloud CLI is required.' >&2; exit 1; }
umask 077
set -o noclobber
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/quant-db-export.XXXXXXXX")
trap 'rm -rf -- "$temp_dir"' EXIT
if ! quant-cloud backup download "$QUANT_BACKUP_ID" --org "$QUANT_ORGANIZATION" \
  --app "$QUANT_APPLICATION" --env "$QUANT_ENVIRONMENT" --type database \
  --output "$temp_dir" >/dev/null 2>&1; then
  echo 'Quant backup download failed.' >&2
  exit 1
fi
shopt -s nullglob
files=("$temp_dir"/*)
[[ ${#files[@]} == 1 && -f "${files[0]}" && -s "${files[0]}" ]] || { echo 'Expected exactly one non-empty Quant backup file.' >&2; exit 1; }
if gzip -t "${files[0]}" >/dev/null 2>&1; then
  cat -- "${files[0]}" > "$1"
else
  gzip -c "${files[0]}" > "$1"
fi
gzip -t "$1"
