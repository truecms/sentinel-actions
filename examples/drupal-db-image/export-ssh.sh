#!/usr/bin/env bash
# Copy to .github/db-image/export.sh; replace the remote command for your host.
set -euo pipefail
: "${HOST_TARGET:?Set repository variable DB_EXPORT_SSH_TARGET}"
: "${DB_SSH_KEY_FILE:?}" "${DB_KNOWN_HOSTS_FILE:?}"
# The remote account must be read-only and restricted to the approved export.
# Replace this command with your host's supported database-export command.
ssh -i "$DB_SSH_KEY_FILE" -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$DB_KNOWN_HOSTS_FILE" \
  "$HOST_TARGET" 'drush sql:dump' | gzip -c > "$1"
