#!/usr/bin/env bash
# Usage: export-platform.sh OUTPUT.gz; token stays in the CLI environment.
set -euo pipefail
: "${PLATFORM_PROJECT_ID:?}" "${PLATFORM_ENVIRONMENT:?}"
[[ $# == 1 ]] || { echo 'Expected output path.' >&2; exit 1; }
case "${DB_EXPORT_SOURCE:-platform}" in
  platform) : "${PLATFORMSH_CLI_TOKEN:?Set PLATFORM_API_TOKEN as a GitHub secret}"; cli=platform ;;
  upsun) : "${UPSUN_CLI_TOKEN:?Set UPSUN_API_TOKEN as a GitHub secret}"; cli=upsun ;;
  *) echo 'Unsupported hosting CLI.' >&2; exit 1 ;;
esac
args=(-p "$PLATFORM_PROJECT_ID" -e "$PLATFORM_ENVIRONMENT")
[[ -z "${PLATFORM_APPLICATION:-}" ]] || args+=(-A "$PLATFORM_APPLICATION")
[[ -z "${PLATFORM_RELATIONSHIP:-}" ]] || args+=(-r "$PLATFORM_RELATIONSHIP")
"$cli" db:dump "${args[@]}" --file "$1" --gzip --no-interaction --yes
test -s "$1"
gzip -t "$1"
