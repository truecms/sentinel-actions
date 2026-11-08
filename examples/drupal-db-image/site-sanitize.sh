#!/usr/bin/env bash
# Replace this fail-closed example with project-specific scrubbing.
# Argument 1 is the isolated MariaDB container name. Never connect to production.
# Example only, after confirming the table exists and is safe to empty:
# docker exec "$1" mariadb -uroot -ptemporary-local-only drupal \
#   -e 'TRUNCATE TABLE webform_submission_data'
# Review all custom content and other tables before removing the failure below.
echo 'Implement and review project-specific sanitisation before publishing.' >&2
exit 1
