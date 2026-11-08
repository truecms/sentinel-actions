#!/usr/bin/env bash
# Download the signed URL returned for the exact newly-created Quant backup.
set -euo pipefail
: "${BACKUP_URL:?Quant backup download URL is required}"
[[ $# == 1 && "$BACKUP_URL" == https://* ]] || { echo 'Expected an HTTPS backup URL and an output path.' >&2; exit 1; }
raw="$1.download"
trap 'rm -f "$raw"' EXIT
# The URL is a credential: never print it, and avoid curl progress output.
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --retry 3 --url "$BACKUP_URL" --output "$raw"
test -s "$raw"
if gzip -t "$raw" >/dev/null 2>&1; then
  mv "$raw" "$1"
else
  gzip -c "$raw" > "$1"
fi
test -s "$1"
gzip -t "$1"
